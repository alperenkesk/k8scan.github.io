"""
Scan routes.

POST /api/v1/scans/upload          – upload Helm chart & queue scan
GET  /api/v1/scans/{scan_id}       – get scan status + findings
GET  /api/v1/scans                 – list user's scans
GET  /api/v1/scans/{scan_id}/report?format=html|json – download report
DELETE /api/v1/scans/{scan_id}     – delete scan
"""
import html as html_module
import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import (
    APIRouter, BackgroundTasks, Depends, File, Form,
    HTTPException, Request, UploadFile, status,
)
from fastapi.responses import HTMLResponse, JSONResponse, Response
from pydantic import BaseModel
from slowapi import Limiter
from slowapi.util import get_remote_address
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.config import get_settings
from backend.database import get_db
from backend.models import Finding, Scan, User
from backend.scanner import scan_chart

router   = APIRouter(prefix="/api/v1/scans", tags=["scans"])
limiter  = Limiter(key_func=get_remote_address)
settings = get_settings()

ALLOWED_EXTENSIONS = {".tgz", ".tar.gz", ".zip", ".yaml", ".yml", ".json"}
SEVERITY_ORDER     = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _check_quota(user: User, db: Session) -> None:
    from backend.models import Scan as ScanModel
    quota    = settings.PLAN_QUOTAS.get(user.plan, 3)
    now      = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    used     = db.query(ScanModel).filter(
        ScanModel.user_id == user.id,
        ScanModel.created_at >= month_start,
    ).count()
    if used >= quota:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Monthly scan quota ({quota}) reached. Upgrade your plan for more scans.",
        )


def _safe_filename(name: str) -> str:
    """Sanitize filename – allow only alphanum, dash, dot, underscore."""
    import re
    return re.sub(r"[^A-Za-z0-9._\-]", "_", name)[:255]


def _get_scan_or_404(scan_id: str, user_id: str, db: Session) -> Scan:
    scan = db.query(Scan).filter_by(id=scan_id, user_id=user_id).first()
    if not scan:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Scan not found.")
    return scan


# ── Background scanning task ─────────────────────────────────────────────────

def _run_scan(
    scan_id: str,
    file_data: bytes,
    filename: str,
    min_severity: str,
    values_dict: dict | None = None,
) -> None:
    from backend.database import SessionLocal
    db = SessionLocal()
    try:
        scan = db.query(Scan).filter_by(id=scan_id).first()
        if not scan:
            return

        scan.status     = "running"
        scan.started_at = datetime.now(timezone.utc)
        db.commit()

        result = scan_chart(file_data, filename, min_severity, values_dict)

        if result.error:
            scan.status        = "failed"
            scan.error_message = result.error
        else:
            min_rank = SEVERITY_ORDER.get(min_severity, 1)
            filtered = [f for f in result.findings if SEVERITY_ORDER.get(f.severity, 0) >= min_rank]

            scan.status          = "completed"
            scan.risk_score      = result.risk_score
            scan.findings_count  = len(filtered)
            scan.completed_at    = datetime.now(timezone.utc)

            for f in filtered:
                db.add(Finding(
                    scan_id=scan_id,
                    severity=f.severity,
                    title=f.title,
                    description=f.description,
                    location=f.location,
                    remediation=f.remediation,
                    poc_command=f.poc_command,
                    cvss_score=f.cvss_score,
                    cve_id=f.cve_id,
                    check_id=f.check_id,
                ))

        # Delete uploaded file after scanning
        if scan.file_path and os.path.exists(scan.file_path):
            try:
                os.remove(scan.file_path)
            except OSError:
                pass
        scan.file_path = None
        db.commit()

    except Exception as e:
        try:
            scan = db.query(Scan).filter_by(id=scan_id).first()
            if scan:
                scan.status        = "failed"
                scan.error_message = str(e)
                db.commit()
        except Exception:
            pass
    finally:
        db.close()


# ── Routes ────────────────────────────────────────────────────────────────────

@router.post("/upload", status_code=status.HTTP_201_CREATED)
@limiter.limit("30/minute")
async def upload_chart(
    request: Request,
    background_tasks: BackgroundTasks,
    file: UploadFile = File(...),
    label: str = Form(default=""),
    min_severity: str = Form(default="MEDIUM"),
    values_file: Optional[UploadFile] = File(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    # Quota check
    _check_quota(current_user, db)

    # Validate severity
    if min_severity not in SEVERITY_ORDER:
        min_severity = "MEDIUM"

    # Validate file extension (defense against MIME spoofing – check name only,
    # we never execute the file so extension is sufficient)
    original_name = _safe_filename(file.filename or "chart.yaml")
    ext_lower     = "." + ".".join(original_name.split(".")[1:]).lower() if "." in original_name else ""
    if not any(original_name.lower().endswith(e) for e in ALLOWED_EXTENSIONS):
        raise HTTPException(
            status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
            detail="Unsupported file type. Allowed: .tgz, .tar.gz, .zip, .yaml, .yml, .json",
        )

    # Read file data with size guard
    file_data = await file.read(settings.MAX_UPLOAD_BYTES + 1)
    if len(file_data) > settings.MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=f"File too large. Maximum size is {settings.MAX_UPLOAD_BYTES // 1_048_576} MB.",
        )

    # Parse optional values file
    values_dict: dict | None = None
    if values_file and values_file.filename:
        vals_ext = (values_file.filename or "").lower().rsplit(".", 1)[-1]
        if vals_ext not in ("yaml", "yml"):
            raise HTTPException(
                status_code=status.HTTP_415_UNSUPPORTED_MEDIA_TYPE,
                detail="Values file must be a .yaml or .yml file.",
            )
        vals_data = await values_file.read(1 * 1024 * 1024 + 1)  # 1 MB limit
        if len(vals_data) > 1 * 1024 * 1024:
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                detail="Values file too large. Maximum size is 1 MB.",
            )
        try:
            import yaml as _yaml
            parsed = _yaml.safe_load(vals_data.decode("utf-8", errors="ignore"))
            if isinstance(parsed, dict):
                values_dict = parsed
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Values file is not valid YAML.",
            )

    chart_name = label.strip()[:80] if label.strip() else original_name

    scan = Scan(
        user_id=current_user.id,
        chart_name=chart_name,
        label=label.strip()[:80] or None,
        original_filename=original_name,
        file_size=len(file_data),
        min_severity=min_severity,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    # Run scan in background (in-memory, no disk write needed)
    background_tasks.add_task(_run_scan, scan.id, file_data, original_name, min_severity, values_dict)

    return {"scan_id": scan.id, "status": "pending"}


@router.get("")
async def list_scans(
    skip: int = 0,
    limit: int = 20,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    skip  = max(skip, 0)
    limit = min(max(limit, 1), 100)
    scans = (
        db.query(Scan)
        .filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .offset(skip)
        .limit(limit)
        .all()
    )
    return [_scan_summary(s) for s in scans]


@router.get("/{scan_id}")
async def get_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _get_scan_or_404(scan_id, current_user.id, db)
    findings = (
        db.query(Finding)
        .filter_by(scan_id=scan.id)
        .order_by(Finding.created_at)
        .all()
    )
    return {
        **_scan_summary(scan),
        "findings": [_finding_dict(f) for f in findings],
    }


@router.get("/{scan_id}/report")
async def download_report(
    scan_id: str,
    format: str = "html",
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _get_scan_or_404(scan_id, current_user.id, db)
    if scan.status != "completed":
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Scan not complete yet.")

    findings = db.query(Finding).filter_by(scan_id=scan.id).all()

    if format == "json":
        payload = {
            **_scan_summary(scan),
            "findings": [_finding_dict(f) for f in findings],
        }
        return Response(
            content=json.dumps(payload, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="k8scan-{scan_id[:8]}.json"'},
        )

    # HTML report
    html_content = _build_html_report(scan, findings)
    return HTMLResponse(
        content=html_content,
        headers={"Content-Disposition": f'attachment; filename="k8scan-{scan_id[:8]}.html"'},
    )


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: str,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    scan = _get_scan_or_404(scan_id, current_user.id, db)
    if scan.file_path and os.path.exists(scan.file_path):
        try:
            os.remove(scan.file_path)
        except OSError:
            pass
    db.delete(scan)
    db.commit()


# ── Serializers ───────────────────────────────────────────────────────────────

def _scan_summary(scan: Scan) -> dict:
    return {
        "id":               scan.id,
        "chart_name":       scan.chart_name,
        "label":            scan.label,
        "original_filename": scan.original_filename,
        "file_size":        scan.file_size,
        "file_size_display": scan.file_size_display,
        "min_severity":     scan.min_severity,
        "status":           scan.status,
        "risk_score":       scan.risk_score,
        "findings_count":   scan.findings_count,
        "error_message":    scan.error_message,
        "started_at":       scan.started_at.isoformat() if scan.started_at else None,
        "completed_at":     scan.completed_at.isoformat() if scan.completed_at else None,
        "created_at":       scan.created_at.isoformat(),
    }


def _finding_dict(f: Finding) -> dict:
    return {
        "id":          f.id,
        "severity":    f.severity,
        "title":       f.title,
        "description": f.description,
        "location":    f.location,
        "remediation": f.remediation,
        "poc_command": f.poc_command,
        "cvss_score":  f.cvss_score,
        "cve_id":      f.cve_id,
        "check_id":    f.check_id,
    }


# ── HTML Report Builder ───────────────────────────────────────────────────────

def _build_html_report(scan: Scan, findings: list[Finding]) -> str:
    sev_colors = {
        "CRITICAL": ("#f87171", "#1f0a0a"),
        "HIGH":     ("#fb923c", "#1f0f05"),
        "MEDIUM":   ("#facc15", "#1f1a05"),
        "LOW":      ("#a3e635", "#111806"),
    }
    counts = {s: sum(1 for f in findings if f.severity == s) for s in sev_colors}

    def esc(v: str | None) -> str:
        # quote=True escapes both " and & < > but NOT single quotes by default.
        # We replace ' manually to be safe in any HTML attribute context.
        return html_module.escape(str(v or ""), quote=True).replace("'", "&#x27;")

    rows = ""
    for f in findings:
        color, bg = sev_colors.get(f.severity, ("#9ca3af", "#111"))
        poc_block = ""
        if f.poc_command:
            poc_block = f"""
            <details style="margin-top:10px">
              <summary style="color:#fb923c;cursor:pointer;font-size:12px;font-weight:700">⚠ Proof-of-Concept Command (authorized testing only)</summary>
              <pre style="background:#0a0a0a;border:1px solid #333;border-radius:6px;padding:10px;margin-top:6px;font-size:12px;color:#fb923c;overflow-x:auto;white-space:pre-wrap">{esc(f.poc_command)}</pre>
            </details>"""
        rows += f"""
        <details style="background:#18181b;border:1px solid #27272a;border-radius:10px;margin-bottom:10px;overflow:hidden">
          <summary style="padding:14px 18px;cursor:pointer;display:flex;align-items:center;gap:12px;list-style:none">
            <span style="background:{bg};color:{color};border:1px solid {color}40;font-size:11px;font-weight:800;padding:3px 10px;border-radius:999px;white-space:nowrap">{esc(f.severity)}</span>
            <span style="color:#fff;font-weight:600;flex:1">{esc(f.title)}</span>
            <span style="color:#52525b;font-size:11px">{esc(f.location or '')}</span>
          </summary>
          <div style="padding:14px 18px 18px;border-top:1px solid #27272a">
            <p style="color:#a1a1aa;font-size:14px;line-height:1.6;margin:0 0 10px">{esc(f.description)}</p>
            {f'<p style="color:#6ee7b7;font-size:13px"><strong>Remediation:</strong> {esc(f.remediation)}</p>' if f.remediation else ''}
            {poc_block}
            {f'<p style="color:#52525b;font-size:12px;margin-top:8px">CVSS: <strong style="color:#d4d4d8">{f.cvss_score}</strong>{f"  ·  CVE: <a href='https://nvd.nist.gov/vuln/detail/{esc(f.cve_id)}' style='color:#10b981'>{esc(f.cve_id)}</a>" if f.cve_id else ""}</p>' if f.cvss_score else ''}
          </div>
        </details>"""

    score = scan.risk_score or 0
    score_color = "#f87171" if score >= 70 else "#facc15" if score >= 40 else "#10b981"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>k8scan Report – {esc(scan.chart_name)}</title>
  <style>
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ background:#09090b; color:#a1a1aa; font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif; padding:32px 16px; }}
    .container {{ max-width:900px; margin:0 auto; }}
    h1 {{ color:#fff; font-size:24px; font-weight:800; }}
    .meta {{ font-size:13px; color:#52525b; margin-top:4px; }}
    .cards {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(130px,1fr)); gap:12px; margin:24px 0; }}
    .card {{ background:#18181b; border:1px solid #27272a; border-radius:10px; padding:16px; text-align:center; }}
    .card p {{ font-size:11px; text-transform:uppercase; letter-spacing:.05em; color:#71717a; margin-bottom:6px; }}
    .card strong {{ font-size:28px; font-weight:800; }}
    details summary::-webkit-details-marker {{ display:none; }}
  </style>
</head>
<body>
<div class="container">
  <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px;margin-bottom:24px">
    <div>
      <h1>k8<span style="color:#10b981">scan</span> Security Report</h1>
      <p class="meta">{esc(scan.chart_name)} &bull; {scan.completed_at.strftime('%Y-%m-%d %H:%M UTC') if scan.completed_at else 'N/A'}</p>
    </div>
  </div>
  <div class="cards">
    <div class="card"><p>Risk Score</p><strong style="color:{score_color}">{score}</strong></div>
    <div class="card"><p>Critical</p><strong style="color:#f87171">{counts['CRITICAL']}</strong></div>
    <div class="card"><p>High</p><strong style="color:#fb923c">{counts['HIGH']}</strong></div>
    <div class="card"><p>Medium</p><strong style="color:#facc15">{counts['MEDIUM']}</strong></div>
    <div class="card"><p>Low</p><strong style="color:#a3e635">{counts['LOW']}</strong></div>
  </div>
  <h2 style="color:#fff;font-size:16px;font-weight:700;margin-bottom:14px">Findings</h2>
  {rows if rows else '<p style="color:#52525b;text-align:center;padding:40px 0">No findings at the selected severity threshold.</p>'}
  <p style="text-align:center;font-size:11px;color:#3f3f46;margin-top:32px">Generated by k8scan &bull; For authorized security testing only</p>
</div>
</body>
</html>"""
