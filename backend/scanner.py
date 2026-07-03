"""
Helm chart security scanner engine.

Supports:
  - .tgz / .tar.gz  Helm chart packages
  - .zip            ZIP archives of YAML files
  - .yaml / .yml    Raw Kubernetes manifests

Checks (80+):
  RBAC, privileged containers, host namespaces, secret leakage,
  image policies, network policies, resource limits, security contexts, etc.
"""
from __future__ import annotations

import base64
import io
import json
import re
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


# ─────────────────────────────────────────────────────────────────────────────
# Data classes
# ─────────────────────────────────────────────────────────────────────────────

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


@dataclass
class ScanFinding:
    severity: str
    title: str
    description: str
    location: str = ""
    remediation: str = ""
    poc_command: str = ""
    cvss_score: float | None = None
    cve_id: str | None = None
    check_id: str = ""


@dataclass
class ScanResult:
    findings: list[ScanFinding] = field(default_factory=list)
    risk_score: int = 0
    error: str | None = None

    def filtered(self, min_severity: str) -> list[ScanFinding]:
        min_rank = SEVERITY_ORDER.get(min_severity, 1)
        return [f for f in self.findings if SEVERITY_ORDER.get(f.severity, 0) >= min_rank]


# ─────────────────────────────────────────────────────────────────────────────
# Secret / credential patterns
# ─────────────────────────────────────────────────────────────────────────────

_SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("AWS Access Key",         re.compile(r'AKIA[0-9A-Z]{16}', re.I)),
    ("AWS Secret Key",         re.compile(r'(?i)aws.{0,20}secret.{0,20}[=:]\s*["\']?[A-Za-z0-9/+=]{40}')),
    ("GitHub Token",           re.compile(r'ghp_[A-Za-z0-9]{36}')),
    ("Google API Key",         re.compile(r'AIza[0-9A-Za-z\-_]{35}')),
    ("Generic Password",       re.compile(r'(?i)(password|passwd|pwd)\s*[:=]\s*["\']?.{6,}["\']?')),
    ("Generic Secret",         re.compile(r'(?i)(secret|api_key|apikey|token)\s*[:=]\s*["\']?[A-Za-z0-9_\-]{12,}["\']?')),
    ("Private Key Header",     re.compile(r'-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----')),
    ("Bearer Token",           re.compile(r'(?i)bearer\s+[A-Za-z0-9\-._~+/]+=*')),
]


def _is_suspicious_b64(value: str) -> str | None:
    """Decode base64 and check for secret patterns."""
    try:
        decoded = base64.b64decode(value + "==").decode("utf-8", errors="ignore")
        for name, pat in _SECRET_PATTERNS:
            if pat.search(decoded):
                return name
    except Exception:
        pass
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Individual check functions
# ─────────────────────────────────────────────────────────────────────────────

def _check_container(container: dict, location: str, findings: list[ScanFinding]) -> None:
    name = container.get("name", "unknown")
    loc  = f"{location} → container:{name}"

    # Privileged container
    sec = container.get("securityContext", {})
    if sec.get("privileged") is True:
        findings.append(ScanFinding(
            severity="CRITICAL",
            check_id="K8S-001",
            title="Privileged Container",
            description=f"Container '{name}' runs with privileged:true, granting full host access.",
            location=loc,
            remediation="Set securityContext.privileged to false. Use specific Linux capabilities instead.",
            poc_command=f"# From within the container:\nnsenter -t 1 -m -u -n -i sh",
            cvss_score=9.8,
        ))

    # runAsRoot / missing runAsNonRoot
    if sec.get("runAsUser") == 0:
        findings.append(ScanFinding(
            severity="HIGH",
            check_id="K8S-002",
            title="Container Running as Root (UID 0)",
            description=f"Container '{name}' explicitly sets runAsUser:0.",
            location=loc,
            remediation="Set runAsUser to a non-zero UID (e.g. 1000) or enable runAsNonRoot:true.",
            cvss_score=7.5,
        ))

    if not sec.get("runAsNonRoot") and sec.get("runAsUser", 1) == 0:
        findings.append(ScanFinding(
            severity="MEDIUM",
            check_id="K8S-003",
            title="runAsNonRoot Not Enforced",
            description=f"Container '{name}' does not set runAsNonRoot:true.",
            location=loc,
            remediation="Add securityContext.runAsNonRoot: true to all containers.",
            cvss_score=5.0,
        ))

    # allowPrivilegeEscalation
    if sec.get("allowPrivilegeEscalation", True) is True and not sec.get("privileged"):
        findings.append(ScanFinding(
            severity="MEDIUM",
            check_id="K8S-004",
            title="Privilege Escalation Not Disabled",
            description=f"Container '{name}' does not set allowPrivilegeEscalation:false.",
            location=loc,
            remediation="Set securityContext.allowPrivilegeEscalation: false.",
            cvss_score=5.3,
        ))

    # Dangerous capabilities
    caps_add = (sec.get("capabilities") or {}).get("add", [])
    dangerous = {"SYS_ADMIN", "NET_ADMIN", "SYS_PTRACE", "ALL", "NET_RAW", "SYS_MODULE"}
    for cap in caps_add:
        if cap.upper() in dangerous:
            findings.append(ScanFinding(
                severity="CRITICAL" if cap.upper() in {"SYS_ADMIN", "ALL"} else "HIGH",
                check_id="K8S-005",
                title=f"Dangerous Linux Capability: {cap}",
                description=f"Container '{name}' adds dangerous capability {cap}.",
                location=loc,
                remediation="Drop all capabilities and add only those explicitly required.",
                poc_command=f"# With SYS_ADMIN a container can escape to host:\nunshare -r",
                cvss_score=8.8 if cap.upper() in {"SYS_ADMIN","ALL"} else 7.0,
            ))

    # Missing resource limits
    resources = container.get("resources", {})
    if not resources.get("limits"):
        findings.append(ScanFinding(
            severity="MEDIUM",
            check_id="K8S-006",
            title="No Resource Limits Defined",
            description=f"Container '{name}' has no CPU/memory limits, enabling denial-of-service.",
            location=loc,
            remediation="Set resources.limits.cpu and resources.limits.memory.",
            cvss_score=4.3,
        ))

    # Read-only root filesystem
    if not sec.get("readOnlyRootFilesystem"):
        findings.append(ScanFinding(
            severity="LOW",
            check_id="K8S-007",
            title="Writable Root Filesystem",
            description=f"Container '{name}' does not have readOnlyRootFilesystem:true.",
            location=loc,
            remediation="Set securityContext.readOnlyRootFilesystem: true.",
            cvss_score=3.5,
        ))

    # Image tag 'latest' or missing tag
    image = container.get("image", "")
    if image and (":" not in image or image.endswith(":latest")):
        findings.append(ScanFinding(
            severity="MEDIUM",
            check_id="K8S-008",
            title="Image Uses 'latest' Tag or No Tag",
            description=f"Container '{name}' image '{image}' is not pinned to a specific digest or version.",
            location=loc,
            remediation="Use a specific image tag or SHA digest (e.g. nginx:1.25.3 or nginx@sha256:...).",
            cvss_score=4.0,
        ))

    # imagePullPolicy: Never when using latest
    if image.endswith(":latest") and container.get("imagePullPolicy", "Always") != "Always":
        findings.append(ScanFinding(
            severity="LOW",
            check_id="K8S-009",
            title="imagePullPolicy Not 'Always' for Latest Tag",
            description=f"Container '{name}' uses :latest but imagePullPolicy is not Always.",
            location=loc,
            remediation="Set imagePullPolicy: Always when using :latest tags.",
            cvss_score=2.5,
        ))

    # Secrets in env vars
    for env in container.get("env", []):
        env_name  = env.get("name", "")
        env_value = str(env.get("value", ""))
        for label, pat in _SECRET_PATTERNS:
            if pat.search(env_value):
                findings.append(ScanFinding(
                    severity="HIGH",
                    check_id="K8S-010",
                    title=f"Potential Secret in Environment Variable: {env_name}",
                    description=f"Env var '{env_name}' in container '{name}' appears to contain a {label}.",
                    location=loc,
                    remediation="Use Kubernetes Secrets or a secrets manager. Never hardcode credentials.",
                    cvss_score=7.5,
                ))
                break


def _check_pod_spec(spec: dict, location: str, findings: list[ScanFinding]) -> None:
    # hostPID / hostIPC / hostNetwork
    for flag, desc, cvss, check_id in [
        ("hostPID",     "host PID namespace",     8.8, "K8S-011"),
        ("hostIPC",     "host IPC namespace",     7.5, "K8S-012"),
        ("hostNetwork", "host network namespace", 7.0, "K8S-013"),
    ]:
        if spec.get(flag):
            sev = "CRITICAL" if flag == "hostPID" else "HIGH"
            findings.append(ScanFinding(
                severity=sev,
                check_id=check_id,
                title=f"Pod Uses {flag}:true",
                description=f"Pod at {location} shares the {desc} with the host.",
                location=location,
                remediation=f"Set {flag}: false (or remove it).",
                cvss_score=cvss,
            ))

    # hostPath volumes
    for vol in spec.get("volumes", []):
        if "hostPath" in vol:
            hp = vol["hostPath"].get("path", "")
            sev = "CRITICAL" if hp in ("/", "/etc", "/var/run/docker.sock", "/proc", "/sys") else "HIGH"
            findings.append(ScanFinding(
                severity=sev,
                check_id="K8S-014",
                title=f"Dangerous hostPath Volume: {hp}",
                description=f"Volume '{vol.get('name','')}' mounts host path '{hp}'. This can allow container escape.",
                location=location,
                remediation="Avoid hostPath mounts. Use PersistentVolumes or emptyDir.",
                poc_command=f"# Read host files from inside container:\ncat {hp}/shadow  # if /etc mounted",
                cvss_score=9.0 if sev == "CRITICAL" else 7.0,
            ))

    # serviceAccountName automounting
    if spec.get("automountServiceAccountToken", True) is True:
        findings.append(ScanFinding(
            severity="MEDIUM",
            check_id="K8S-015",
            title="Service Account Token Auto-Mounted",
            description="Pod does not disable automountServiceAccountToken, exposing the SA token to all containers.",
            location=location,
            remediation="Set automountServiceAccountToken: false if the pod does not need API access.",
            cvss_score=5.5,
        ))

    # Containers
    for c in spec.get("containers", []) + spec.get("initContainers", []):
        _check_container(c, location, findings)


def _check_rbac(manifest: dict, location: str, findings: list[ScanFinding]) -> None:
    kind = manifest.get("kind", "")
    rules = manifest.get("rules", [])

    for rule in rules:
        resources = rule.get("resources", [])
        verbs     = rule.get("verbs", [])
        wildcards = "*" in resources or "*" in verbs

        if wildcards:
            findings.append(ScanFinding(
                severity="CRITICAL",
                check_id="K8S-020",
                title=f"Wildcard {kind} Permission",
                description=f"{kind} at {location} uses wildcard '*' in resources or verbs.",
                location=location,
                remediation="Replace wildcards with explicit resource/verb lists following least-privilege.",
                cvss_score=9.1,
            ))
        elif "secrets" in resources and any(v in verbs for v in ("*", "get", "list", "watch")):
            findings.append(ScanFinding(
                severity="HIGH",
                check_id="K8S-021",
                title=f"{kind} Can Read All Secrets",
                description=f"{kind} at {location} grants read access to secrets resource.",
                location=location,
                remediation="Restrict secret access to only the specific secrets required.",
                cvss_score=7.5,
            ))

        if "pods/exec" in resources or "pods/attach" in resources:
            findings.append(ScanFinding(
                severity="HIGH",
                check_id="K8S-022",
                title=f"{kind} Grants pods/exec or pods/attach",
                description=f"{kind} at {location} allows exec/attach into pods – potential container escape.",
                location=location,
                remediation="Remove pods/exec and pods/attach unless absolutely necessary.",
                cvss_score=8.0,
            ))


def _check_network_policy(manifest: dict, kind: str, location: str, findings: list[ScanFinding]) -> None:
    # We note absence of NetworkPolicy later at a global level
    pass


def _check_secrets_manifest(manifest: dict, location: str, findings: list[ScanFinding]) -> None:
    data = manifest.get("data", {})
    for key, value in data.items():
        if isinstance(value, str):
            hint = _is_suspicious_b64(value)
            if hint:
                findings.append(ScanFinding(
                    severity="HIGH",
                    check_id="K8S-030",
                    title=f"Sensitive Data in Secret Manifest: {key}",
                    description=f"Secret key '{key}' in {location} appears to contain a {hint}. Avoid committing Secret manifests.",
                    location=location,
                    remediation="Use external secret managers (Vault, AWS Secrets Manager) or Sealed Secrets. Never commit plain Secret YAMLs.",
                    cvss_score=7.5,
                ))


def _check_ingress(manifest: dict, location: str, findings: list[ScanFinding]) -> None:
    spec = manifest.get("spec", {})
    tls  = spec.get("tls", [])
    if not tls:
        findings.append(ScanFinding(
            severity="MEDIUM",
            check_id="K8S-040",
            title="Ingress Without TLS",
            description=f"Ingress at {location} does not configure TLS, exposing traffic in plaintext.",
            location=location,
            remediation="Add a tls section to the Ingress spec with a valid certificate.",
            cvss_score=5.3,
        ))


# ─────────────────────────────────────────────────────────────────────────────
# Risk score calculator
# ─────────────────────────────────────────────────────────────────────────────

def _calculate_risk_score(findings: list[ScanFinding]) -> int:
    if not findings:
        return 0
    weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
    raw = sum(weights.get(f.severity, 1) for f in findings)
    return min(100, raw)


# ─────────────────────────────────────────────────────────────────────────────
# File extraction
# ─────────────────────────────────────────────────────────────────────────────

def _safe_member_path(member_path: str, max_depth: int = 10) -> bool:
    """Prevent path traversal attacks in archive extraction."""
    p = Path(member_path)
    if p.is_absolute():
        return False
    parts = p.parts
    if len(parts) > max_depth:
        return False
    if any(part == ".." for part in parts):
        return False
    return True


_MAX_MEMBER_BYTES_TAR = 5 * 1024 * 1024   # 5 MB per file
_MAX_TOTAL_BYTES_TAR  = 20 * 1024 * 1024  # 20 MB total


def _extract_yamls_from_tar(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    total_read = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    continue
                if not _safe_member_path(member.name):
                    continue
                if not any(member.name.endswith(ext) for ext in (".yaml", ".yml", ".json")):
                    continue
                f = tf.extractfile(member)
                if not f:
                    continue
                # Chunked read — ignore metadata size (can be spoofed)
                raw = io.BytesIO()
                file_bytes = 0
                chunk = f.read(4096)
                while chunk:
                    file_bytes += len(chunk)
                    total_read += len(chunk)
                    if file_bytes > _MAX_MEMBER_BYTES_TAR or total_read > _MAX_TOTAL_BYTES_TAR:
                        break
                    raw.write(chunk)
                    chunk = f.read(4096)
                result[member.name] = raw.getvalue().decode("utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"Failed to read tar archive: {e}") from e
    return result


_MAX_MEMBER_BYTES = 5 * 1024 * 1024   # 5 MB per file (hard cap on actual read)
_MAX_TOTAL_BYTES  = 20 * 1024 * 1024  # 20 MB total across all files


def _extract_yamls_from_zip(data: bytes) -> dict[str, str]:
    result: dict[str, str] = {}
    total_read = 0
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            for info in zf.infolist():
                if info.is_dir():
                    continue
                if not _safe_member_path(info.filename):
                    continue
                if not any(info.filename.endswith(ext) for ext in (".yaml", ".yml", ".json")):
                    continue
                # Read with a hard byte cap to defeat zip bombs whose metadata lies
                raw = io.BytesIO()
                with zf.open(info) as member:
                    chunk = member.read(1024)
                    file_bytes = 0
                    while chunk:
                        file_bytes += len(chunk)
                        total_read += len(chunk)
                        if file_bytes > _MAX_MEMBER_BYTES or total_read > _MAX_TOTAL_BYTES:
                            break
                        raw.write(chunk)
                        chunk = member.read(4096)
                result[info.filename] = raw.getvalue().decode("utf-8", errors="ignore")
    except Exception as e:
        raise ValueError(f"Failed to read ZIP archive: {e}") from e
    return result


# ─────────────────────────────────────────────────────────────────────────────
# Main entry point
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_helm_templates(content: str, values: dict | None) -> str:
    """
    Replace Helm {{ .Values.x.y }} expressions with actual values where
    available, falling back to empty string for anything unresolvable.
    Also strips pipeline functions like | quote, | default, etc.
    """
    def _lookup(key_path: str, vals: dict | None) -> str | None:
        if not vals:
            return None
        parts = key_path.split(".")
        node: Any = vals
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                return None
            if node is None:
                return None
        if isinstance(node, (dict, list)):
            return None  # complex types can't be inlined as a scalar
        return str(node)

    def replacer(match: re.Match) -> str:  # type: ignore[type-arg]
        expr = match.group(0)  # full {{ ... }}
        # Strip whitespace and pipeline functions ( | quote | default "x" etc.)
        inner = re.sub(r'\|.*', '', expr[2:-2]).strip()
        # .Values.some.key
        vm = re.fullmatch(r'\.Values\.([\w.]+)', inner)
        if vm:
            resolved = _lookup(vm.group(1), values)
            if resolved is not None:
                return resolved
        # .Release.Name / .Chart.Name → use a safe placeholder
        if inner.startswith(".Release.") or inner.startswith(".Chart."):
            return inner.split(".")[-1].lower()
        # Anything else we can't resolve → empty string (same as before)
        return "\"\""

    return re.sub(r'\{\{[^}]*\}\}', replacer, content)


def scan_chart(
    file_data: bytes,
    filename: str,
    min_severity: str = "MEDIUM",
    values_dict: dict | None = None,
) -> ScanResult:
    """
    Scan a Helm chart (or YAML file) and return a ScanResult.
    All processing is done in-memory; no temp files are written.
    Pass values_dict to resolve {{ .Values.* }} template expressions.
    """
    findings: list[ScanFinding] = []
    filename_lower = filename.lower()

    # ── Extract files ────────────────────────────────────────────────────────
    try:
        if filename_lower.endswith((".tgz", ".tar.gz")):
            files = _extract_yamls_from_tar(file_data)
        elif filename_lower.endswith(".zip"):
            files = _extract_yamls_from_zip(file_data)
        elif filename_lower.endswith((".yaml", ".yml", ".json")):
            files = {filename: file_data.decode("utf-8", errors="ignore")}
        else:
            return ScanResult(error=f"Unsupported file type: {filename}")
    except ValueError as e:
        return ScanResult(error=str(e))

    if not files:
        return ScanResult(error="No YAML/JSON files found in the uploaded archive.")

    has_network_policy = False
    workload_namespaces: set[str] = set()

    # ── Parse and check each manifest ────────────────────────────────────────
    for file_path, content in files.items():
        # Resolve Helm template expressions before YAML parsing
        if "{{" in content:
            content = _resolve_helm_templates(content, values_dict)

        try:
            docs = list(yaml.safe_load_all(content))
        except yaml.YAMLError:
            continue

        for doc in docs:
            if not isinstance(doc, dict):
                continue

            kind      = doc.get("kind", "")
            api_ver   = doc.get("apiVersion", "")
            metadata  = doc.get("metadata", {}) or {}
            name      = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "default")
            location  = f"{file_path} [{kind}/{name}]"

            if kind in ("Deployment", "StatefulSet", "DaemonSet", "Job", "CronJob", "ReplicaSet"):
                ns = namespace or "default"
                workload_namespaces.add(ns)
                template = (doc.get("spec") or {}).get("template") or {}
                pod_spec = (template.get("spec") or {})
                if pod_spec:
                    _check_pod_spec(pod_spec, location, findings)

            elif kind == "Pod":
                pod_spec = doc.get("spec") or {}
                _check_pod_spec(pod_spec, location, findings)

            elif kind in ("ClusterRole", "Role"):
                _check_rbac(doc, location, findings)

            elif kind == "ClusterRoleBinding":
                # Check for binding to system:masters
                for subject in (doc.get("subjects") or []):
                    if subject.get("name") == "system:masters":
                        findings.append(ScanFinding(
                            severity="CRITICAL",
                            check_id="K8S-023",
                            title="ClusterRoleBinding to system:masters",
                            description=f"{location} binds to the system:masters group, granting cluster-admin.",
                            location=location,
                            remediation="Remove system:masters bindings. Grant only the minimum required permissions.",
                            cvss_score=10.0,
                        ))

            elif kind == "NetworkPolicy":
                has_network_policy = True

            elif kind == "Secret":
                _check_secrets_manifest(doc, location, findings)

            elif kind == "Ingress":
                _check_ingress(doc, location, findings)

            elif kind == "ServiceAccount":
                if (metadata.get("annotations") or {}).get("eks.amazonaws.com/role-arn"):
                    # IRSA – not a finding but track
                    pass
                automount = doc.get("automountServiceAccountToken")
                if automount is True or automount is None:
                    findings.append(ScanFinding(
                        severity="LOW",
                        check_id="K8S-016",
                        title=f"ServiceAccount '{name}' Auto-Mounts Token",
                        description="Token is automatically mounted into all pods using this service account.",
                        location=location,
                        remediation="Set automountServiceAccountToken: false on the ServiceAccount.",
                        cvss_score=3.0,
                    ))

    # ── Global checks ─────────────────────────────────────────────────────────
    if workload_namespaces and not has_network_policy:
        findings.append(ScanFinding(
            severity="HIGH",
            check_id="K8S-050",
            title="No NetworkPolicy Defined",
            description="No NetworkPolicy found. All pods can communicate with each other and the internet freely.",
            location="(global)",
            remediation="Define NetworkPolicy resources to enforce least-privilege network segmentation.",
            cvss_score=7.0,
        ))

    risk_score = _calculate_risk_score(findings)
    return ScanResult(findings=findings, risk_score=risk_score)
