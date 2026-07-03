"""
Dashboard summary route.

GET /api/v1/dashboard
"""
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from backend.auth import get_current_user
from backend.config import get_settings
from backend.database import get_db
from backend.models import Finding, Scan, User

router   = APIRouter(prefix="/api/v1", tags=["dashboard"])
settings = get_settings()


@router.get("/dashboard")
async def get_dashboard(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    now         = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    quota       = settings.PLAN_QUOTAS.get(current_user.plan, 3)

    total_scans = db.query(Scan).filter_by(user_id=current_user.id).count()
    scans_this_month = db.query(Scan).filter(
        Scan.user_id == current_user.id,
        Scan.created_at >= month_start,
    ).count()

    critical_count = (
        db.query(Finding)
        .join(Scan, Scan.id == Finding.scan_id)
        .filter(Scan.user_id == current_user.id, Finding.severity == "CRITICAL")
        .count()
    )

    avg_score_row = (
        db.query(func.avg(Scan.risk_score))
        .filter(Scan.user_id == current_user.id, Scan.status == "completed")
        .scalar()
    )
    avg_risk_score = round(avg_score_row) if avg_score_row is not None else None

    recent_scans = (
        db.query(Scan)
        .filter_by(user_id=current_user.id)
        .order_by(Scan.created_at.desc())
        .limit(10)
        .all()
    )

    remaining   = max(0, quota - scans_this_month)
    quota_pct   = min(100, round((scans_this_month / quota) * 100)) if quota else 0

    return {
        "user": {
            "id":           current_user.id,
            "full_name":    current_user.full_name,
            "email":        current_user.email,
            "plan":         current_user.plan,
            "plan_display": current_user.plan_display,
        },
        "stats": {
            "total_scans":     total_scans,
            "critical_count":  critical_count,
            "avg_risk_score":  avg_risk_score,
        },
        "quota": {
            "used":      scans_this_month,
            "limit":     quota,
            "remaining": remaining,
            "pct":       quota_pct,
        },
        "recent_scans": [
            {
                "id":          s.id,
                "chart_name":  s.chart_name,
                "status":      s.status,
                "risk_score":  s.risk_score,
                "created_at":  s.created_at.isoformat(),
            }
            for s in recent_scans
        ],
    }
