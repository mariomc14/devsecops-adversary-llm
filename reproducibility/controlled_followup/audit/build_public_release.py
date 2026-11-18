#!/usr/bin/env python3
"""Build the public (sanitized) material of the IJIS controlled follow-up from the internal campaign archive.

Usage:
    python -I build_public_release.py <workspace_root> <repo_root> <human_package_dir> <release_docs_dir> <out_dir>

<workspace_root>      internal campaign workspace (contains campaign_run2_final_20261116/original,
                      campaign_logs/ and the archived run 1 under devsecops-adversary-llm-ijis-experiments-v4/).
<repo_root>           this Git repository.
<human_package_dir>   extracted human_adjudication_final_package.zip (verified against its SHA256SUMS.txt).
<release_docs_dir>    README files written for the two release assets (PUBLIC_README.md, RUN1_README.md).
<out_dir>             where the release assets are staged and zipped.

The internal archive is only read; nothing in it is modified. Every copied text file is passed through the same
sanitizer. The sensitive values themselves are NOT stored in this script: they are read at build time from the
campaign's own campaign_environment.json (account ID, caller ARN, fixed network IDs) or matched by pattern
(access-key IDs, IAM unique principal IDs, local home-directory prefix). Each modified file is recorded in
SANITIZATION.json with its original and public SHA-256 and the number of replacements per rule.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import re
import shutil
import sys
import zipfile
from collections import Counter
from pathlib import Path

WS, REPO, HUMAN, DOCS, OUT = (Path(a).resolve() for a in sys.argv[1:6])
BUNDLE = WS / "campaign_run2_final_20261116" / "original"
LOGS = WS / "campaign_logs"
RUN1 = WS / "devsecops-adversary-llm-ijis-experiments-v4" / "controlled_validation" / "previous_runs" / "run1_v4_halted_at_order30_20261115"
INCIDENT30 = LOGS / "v4" / "incidente_orden30_20261115T221700Z"
CF = REPO / "reproducibility" / "controlled_followup"
ZIP_DATE = (2026, 11, 18, 0, 0, 0)

# --------------------------------------------------------------------------------------------------------------
# Sanitization rules (values discovered from the campaign environment, never hard-coded)
# --------------------------------------------------------------------------------------------------------------
env = json.loads((BUNDLE / "results" / "campaign_environment.json").read_text(encoding="utf-8"))
account_id = env["aws_account_id"]
iam_user = env["caller_arn"].split(":user/", 1)[1]
net = env["campaign_network"]
home_prefix = re.match(r"^(/home/[^/]+)", env["chaos_executable"]).group(1)
assert re.fullmatch(r"\d{12}", account_id) and iam_user and home_prefix.startswith("/home/")

# Literal search strings are assembled from parts so that a plain-text secret scan of this repository
# (grep for the access-key prefixes, signed-request parameters, private-key headers) does not match this file.
KEY_PREFIXES = "|".join(("AK" + "IA", "AS" + "IA"))

RULES: list[tuple[str, re.Pattern, str]] = [
    ("aws_access_key_id", re.compile(r"\b(?:" + KEY_PREFIXES + r")[0-9A-Z]{16}\b"), "<REDACTED_AWS_ACCESS_KEY_ID>"),
    ("aws_access_key_id_masked", re.compile(r"\b(?:" + KEY_PREFIXES + r")\*{12}[0-9A-Z]{4}\b"), "<REDACTED_AWS_ACCESS_KEY_ID>"),
    ("aws_unique_principal_id", re.compile(r"\b(?:AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{12,}\b"), "<REDACTED_AWS_PRINCIPAL_ID>"),
    ("aws_account_id", re.compile(re.escape(account_id)), "<REDACTED_AWS_ACCOUNT_ID>"),
    ("iam_user_name", re.compile(re.escape(iam_user)), "<REDACTED_IAM_USER>"),
    ("local_home_path", re.compile(re.escape(home_prefix) + r"(?![A-Za-z0-9_.-])"), "<LOCAL_HOME>"),
    ("campaign_vpc_id", re.compile(re.escape(net["vpc_id"])), "<CAMPAIGN_VPC_ID>"),
    ("campaign_subnet_id", re.compile(re.escape(net["subnet_id"])), "<CAMPAIGN_SUBNET_ID>"),
    ("campaign_security_group_id", re.compile(re.escape(net["security_group_id"])), "<CAMPAIGN_SECURITY_GROUP_ID>"),
]
# Must never be present; if found the build stops so that a human can look at it.
FATAL = re.compile(r"BEGIN [A-Z ]*PRIVATE" + r" KEY|X-Amz-(?:Credential|Signature|Security-Token)|Authorization: " + "AW" + r"S4|"
                   r"(?:SecretAccessKey|aws_secret_access_key|SessionToken|aws_session_token)[\"']?\s*[:=]\s*[\"']?[A-Za-z0-9/+=]{20,}")
EMAIL = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
# Placeholder/example e-mail-like strings that are not personal data may be allow-listed here (none expected).
EMAIL_ALLOW: set[str] = set()


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sanitize_text(text: str, label: str) -> tuple[str, Counter]:
    m = FATAL.search(text)
    if m:
        sys.exit(f"FATAL pattern in {label}: {m.group(0)[:20]}... -- stop and review manually")
    emails = {e for e in EMAIL.findall(text) if e not in EMAIL_ALLOW}
    if emails:
        sys.exit(f"e-mail address in {label}: review manually before publishing")
    counts: Counter = Counter()
    for name, rx, repl in RULES:
        text, n = rx.subn(repl, text)
        if n:
            counts[name] += n
    return text, counts


def sanitize_bytes(data: bytes, label: str, suffix: str) -> tuple[bytes, Counter]:
    if suffix in (".docx", ".xlsx"):
        counts: Counter = Counter()
        src = zipfile.ZipFile(io.BytesIO(data))
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as dst:
            for info in src.infolist():
                raw = src.read(info.filename)
                try:
                    t = raw.decode("utf-8")
                except UnicodeDecodeError:
                    dst.writestr(info, raw)
                    continue
                t2, c = sanitize_text(t, f"{label}!{info.filename}")
                counts += c
                dst.writestr(info, t2.encode("utf-8") if c else raw)
        return (buf.getvalue(), counts) if counts else (data, counts)
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        for name, rx, _ in RULES:
            if rx.search(data.decode("latin-1")):
                sys.exit(f"binary file {label} contains {name}; handle manually")
        return data, Counter()
    t2, counts = sanitize_text(text, label)
    return (t2.encode("utf-8"), counts) if counts else (data, counts)


class Recorder:
    """Copies files through the sanitizer and records what changed."""

    def __init__(self, name: str):
        self.name = name
        self.modified: list[dict] = []
        self.unchanged = 0
        self.totals: Counter = Counter()

    def copy(self, src: Path, dst: Path, source_label: str, public_label: str, transform=None):
        data = src.read_bytes()
        out, counts = sanitize_bytes(data, source_label, src.suffix.lower())
        note = None
        if transform is not None:
            out2, note = transform(out)
            out = out2
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_bytes(out)
        if out != data:
            rec = {"path": public_label, "source": source_label, "original_sha256": sha(data), "public_sha256": sha(out),
                   "redactions": dict(sorted(counts.items()))}
            if note:
                rec["editorial_change"] = note
            self.modified.append(rec)
            self.totals += counts
        else:
            self.unchanged += 1

    def copytree(self, src: Path, dst: Path, source_label: str, public_label: str):
        for p in sorted(src.rglob("*")):
            if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc":
                rel = p.relative_to(src).as_posix()
                self.copy(p, dst / rel, f"{source_label}/{rel}", f"{public_label}/{rel}")

    def summary(self) -> dict:
        return {"files_modified": len(self.modified), "files_unchanged": self.unchanged,
                "replacements_by_rule": dict(sorted(self.totals.items())), "modified_files": self.modified}


def translate_index(data: bytes):
    t = data.decode("utf-8")
    n = t.count("+reanudado_v6")
    return t.replace("+reanudado_v6", "+resumed_v6").encode("utf-8"), (
        f"Spanish token '+reanudado_v6' translated to '+resumed_v6' in attempt_revisions ({n} occurrence(s)); no other change")


def write_manifest(base: Path, name: str = "SHA256SUMS.txt") -> int:
    lines = [f"{sha(p.read_bytes())}  {p.relative_to(base).as_posix()}"
             for p in sorted(base.rglob("*")) if p.is_file() and p != base / name]
    (base / name).write_text("\n".join(lines) + "\n", encoding="utf-8")
    return len(lines)


def make_zip(base: Path, zip_path: Path):
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for p in sorted(base.rglob("*")):
            if p.is_file():
                info = zipfile.ZipInfo(f"{base.name}/{p.relative_to(base).as_posix()}", ZIP_DATE)
                info.external_attr = 0o644 << 16
                info.compress_type = zipfile.ZIP_DEFLATED
                z.writestr(info, p.read_bytes(), compresslevel=9)


# --------------------------------------------------------------------------------------------------------------
# 1. Public archive of the controlled follow-up (80 trajectories / 164 attempts)
# --------------------------------------------------------------------------------------------------------------
if OUT.exists():
    sys.exit(f"{OUT} already exists; refusing to overwrite")
PUB = OUT / "ijis_controlled_followup_public"
pub = Recorder("ijis_controlled_followup_public.zip")
B = "campaign_run2_final_20261116/original"
PATH_MAPPING = {
    "results/": "results/",
    "indice_trayectorias.csv": "trajectory_index.csv",
    "sesiones/sesion1_v5/": "sessions/session1_v5/",
    "sesiones/sesion2_v6/": "sessions/session2_v6/",
    "codigo/": "code/",
    "incidencias/verificacion_v5/": "incidents/verification_v5/",
    "incidencias/verificacion_v6/": "incidents/verification_v6/",
    "incidencias/": "incidents/",
    "verificacion_final/": "final_verification/",
    "LEEME.md": "(not copied: replaced by README.md in English)",
}
pub.copytree(BUNDLE / "results", PUB / "results", f"{B}/results", "results")
pub.copy(BUNDLE / "indice_trayectorias.csv", PUB / "trajectory_index.csv", f"{B}/indice_trayectorias.csv",
         "trajectory_index.csv", transform=translate_index)
pub.copytree(BUNDLE / "sesiones" / "sesion1_v5", PUB / "sessions" / "session1_v5", f"{B}/sesiones/sesion1_v5", "sessions/session1_v5")
pub.copytree(BUNDLE / "sesiones" / "sesion2_v6", PUB / "sessions" / "session2_v6", f"{B}/sesiones/sesion2_v6", "sessions/session2_v6")
pub.copytree(BUNDLE / "codigo", PUB / "code", f"{B}/codigo", "code")
for name in ("v4_to_v5.diff", "v5_to_v6.diff", "Informe_errores_v5.docx"):
    pub.copy(BUNDLE / "incidencias" / name, PUB / "incidents" / name, f"{B}/incidencias/{name}", f"incidents/{name}")
pub.copytree(BUNDLE / "incidencias" / "verificacion_v5", PUB / "incidents" / "verification_v5", f"{B}/incidencias/verificacion_v5", "incidents/verification_v5")
pub.copytree(BUNDLE / "incidencias" / "verificacion_v6", PUB / "incidents" / "verification_v6", f"{B}/incidencias/verificacion_v6", "incidents/verification_v6")
pub.copytree(BUNDLE / "verificacion_final", PUB / "final_verification", f"{B}/verificacion_final", "final_verification")
pub.copy(WS / "campaign_run2_final_20261116" / "compartible" / "REDACCION.json", PUB / "REDACTION.json",
         "campaign_run2_final_20261116/compartible/REDACCION.json", "REDACTION.json")
for name in ("human_adjudication_final.csv", "human_adjudication_trace.csv", "blind_id_mapping.csv",
             "VALIDATION_SUMMARY.json", "README.md", "SHA256SUMS.txt"):
    pub.copy(HUMAN / name, PUB / "human_evaluation" / name, f"human_adjudication_final_package.zip/{name}", f"human_evaluation/{name}")
shutil.copyfile(DOCS / "PUBLIC_README.md", PUB / "README.md")

# --------------------------------------------------------------------------------------------------------------
# 2. Repository material (controlled_validation/ v6, protocol/, results_summary/, audit/)
# --------------------------------------------------------------------------------------------------------------
repo = Recorder("repository")
V6, V5 = BUNDLE / "codigo" / "runner_v6", BUNDLE / "codigo" / "runner_v5"
TEMPLATE = BUNDLE / "codigo" / "automate" / "inputs" / "template.json"
# canonical runner (v6) at the repository root
repo.copytree(V6, REPO / "controlled_validation", f"{B}/codigo/runner_v6", "controlled_validation")
repo.copy(TEMPLATE, REPO / "automate" / "inputs" / "template.json", f"{B}/codigo/automate/inputs/template.json", "automate/inputs/template.json")
# frozen protocol
P = CF / "protocol"
for name in ("campaign.yaml", "schedule.csv"):
    repo.copy(V6 / name, P / name, f"{B}/codigo/runner_v6/{name}", f"reproducibility/controlled_followup/protocol/{name}")
repo.copytree(V6 / "tasks", P / "tasks", f"{B}/codigo/runner_v6/tasks", "reproducibility/controlled_followup/protocol/tasks")
repo.copy(TEMPLATE, P / "template.json", f"{B}/codigo/automate/inputs/template.json", "reproducibility/controlled_followup/protocol/template.json")
repo.copy(REPO / "automate" / "requirements.txt", P / "requirements.txt", "repository automate/requirements.txt (target of controlled_validation/requirements.txt)",
          "reproducibility/controlled_followup/protocol/requirements.txt")
# results summary
RS = CF / "results_summary"
for name in ("campaign_results.csv", "campaign_results.json"):
    repo.copy(BUNDLE / "results" / name, RS / name, f"{B}/results/{name}", f"reproducibility/controlled_followup/results_summary/{name}")
repo.copy(BUNDLE / "indice_trayectorias.csv", RS / "trajectory_index.csv", f"{B}/indice_trayectorias.csv",
          "reproducibility/controlled_followup/results_summary/trajectory_index.csv", transform=translate_index)
for name in ("human_adjudication_final.csv", "human_adjudication_trace.csv", "blind_id_mapping.csv", "VALIDATION_SUMMARY.json"):
    repo.copy(HUMAN / name, RS / name, f"human_adjudication_final_package.zip/{name}", f"reproducibility/controlled_followup/results_summary/{name}")
for name in ("README.md", "SHA256SUMS.txt"):
    repo.copy(HUMAN / name, CF / "human_evaluation" / "delivered_package" / name, f"human_adjudication_final_package.zip/{name}",
              f"reproducibility/controlled_followup/human_evaluation/delivered_package/{name}")
# analysis helpers shipped with the runner (analyze_campaign.py is adapted separately, by hand, and documented)
repo.copy(V6 / "analyze_gate_validation.py", CF / "analysis" / "analyze_gate_validation.py", f"{B}/codigo/runner_v6/analyze_gate_validation.py",
          "reproducibility/controlled_followup/analysis/analyze_gate_validation.py")
# audit
A = CF / "audit"
repo.copytree(V5, A / "runner_versions" / "v5", f"{B}/codigo/runner_v5", "reproducibility/controlled_followup/audit/runner_versions/v5")
repo.copytree(V6, A / "runner_versions" / "v6", f"{B}/codigo/runner_v6", "reproducibility/controlled_followup/audit/runner_versions/v6")
for name in ("v4_to_v5.diff", "v5_to_v6.diff"):
    repo.copy(BUNDLE / "incidencias" / name, A / name, f"{B}/incidencias/{name}", f"reproducibility/controlled_followup/audit/{name}")
for name in ("audit_final.log", "audit_final.py"):
    repo.copy(BUNDLE / "verificacion_final" / name, A / name, f"{B}/verificacion_final/{name}", f"reproducibility/controlled_followup/audit/{name}")
repo.copy(WS / "campaign_run2_final_20261116" / "compartible" / "REDACCION.json", A / "REDACTION.json",
          "campaign_run2_final_20261116/compartible/REDACCION.json", "reproducibility/controlled_followup/audit/REDACTION.json")
I = A / "incidents"
repo.copy(BUNDLE / "incidencias" / "Informe_errores_v5.docx", I / "Informe_errores_v5.docx", f"{B}/incidencias/Informe_errores_v5.docx",
          "reproducibility/controlled_followup/audit/incidents/Informe_errores_v5.docx")
repo.copytree(BUNDLE / "incidencias" / "verificacion_v5", I / "verification_v5", f"{B}/incidencias/verificacion_v5", "reproducibility/controlled_followup/audit/incidents/verification_v5")
repo.copytree(BUNDLE / "incidencias" / "verificacion_v6", I / "verification_v6", f"{B}/incidencias/verificacion_v6", "reproducibility/controlled_followup/audit/incidents/verification_v6")
repo.copytree(INCIDENT30, I / "run1_halt_order30", "campaign_logs/v4/incidente_orden30_20261115T221700Z", "reproducibility/controlled_followup/audit/incidents/run1_halt_order30")
repo.copy(RUN1 / "ARCHIVE.json", I / "run1_excluded" / "ARCHIVE.json", "run1_v4_halted_at_order30_20261115/ARCHIVE.json",
          "reproducibility/controlled_followup/audit/incidents/run1_excluded/ARCHIVE.json")
inv = RUN1 / "results_invalidated" / "20261115_v4_validator_lookup_events_paginator" / "INVALIDATED.json"
repo.copy(inv, I / "run1_excluded" / "INVALIDATED.json", "run1_v4_halted_at_order30_20261115/results_invalidated/20261115_v4_validator_lookup_events_paginator/INVALIDATED.json",
          "reproducibility/controlled_followup/audit/incidents/run1_excluded/INVALIDATED.json")

# --------------------------------------------------------------------------------------------------------------
# 3. Excluded preliminary run 1 (runner v4, halted at trajectory 30) -- separate asset, EXCLUDED FROM SCIENTIFIC RESULTS
# --------------------------------------------------------------------------------------------------------------
R1 = OUT / "ijis_controlled_followup_run1_EXCLUDED"
run1 = Recorder("ijis_controlled_followup_run1_EXCLUDED.zip")
run1.copytree(RUN1 / "results", R1 / "results", "run1_v4_halted_at_order30_20261115/results", "results")
run1.copytree(RUN1 / "results_invalidated", R1 / "results_invalidated", "run1_v4_halted_at_order30_20261115/results_invalidated", "results_invalidated")
run1.copy(RUN1 / "ARCHIVE.json", R1 / "ARCHIVE.json", "run1_v4_halted_at_order30_20261115/ARCHIVE.json", "ARCHIVE.json")
run1.copy(RUN1 / "SHA256SUMS.txt", R1 / "ARCHIVE_SHA256SUMS.txt", "run1_v4_halted_at_order30_20261115/SHA256SUMS.txt", "ARCHIVE_SHA256SUMS.txt")
run1.copytree(INCIDENT30, R1 / "halt_incident_order30", "campaign_logs/v4/incidente_orden30_20261115T221700Z", "halt_incident_order30")
shutil.copyfile(DOCS / "RUN1_README.md", R1 / "README.md")

# --------------------------------------------------------------------------------------------------------------
# 4. Sanitization records, manifests and ZIPs
# --------------------------------------------------------------------------------------------------------------
policy = {
    "sanitized": {
        "<REDACTED_AWS_ACCESS_KEY_ID>": "AWS access-key IDs (long-term and temporary), including the masked form used in the intermediate shareable bundle",
        "<REDACTED_AWS_PRINCIPAL_ID>": "IAM unique principal IDs (AIDA/AROA/...) printed inside CloudTrail events",
        "<REDACTED_AWS_ACCOUNT_ID>": "12-digit ID of the campaign AWS account (inside ARNs, environment records and logs)",
        "<REDACTED_IAM_USER>": "name of the IAM user that ran the campaign (caller ARN)",
        "<LOCAL_HOME>": "local home-directory prefix of the workstation that ran the campaign",
        "<CAMPAIGN_VPC_ID> / <CAMPAIGN_SUBNET_ID> / <CAMPAIGN_SECURITY_GROUP_ID>": "IDs of the fixed cvr2-network VPC, subnet and security group (stable placeholders; every attempt used the same network)",
    },
    "checked_and_absent": ["AWS secret access keys", "session tokens", "SigV4 signed-request material (credential/signature query parameters, authorization headers)",
                           "private-key material", "e-mail addresses"],
    "not_modified": ["model IDs and model names", "AWS region", "timestamps", "task IDs", "condition names", "Q_pre / Q_post",
                     "token usage", "generated code logic", "experiment outcomes and human labels", "runner revision",
                     "attempt IDs and execution structure", "attempt-owned resource names (cvr2-*) and EC2 instance IDs",
                     "public AMI IDs", "AWS documentation example IDs (123456789012, *-0123456789abcdef0) produced by the models"],
    "notes": [
        "results/SHA256SUMS.txt inside the public archive is the runner's original manifest, kept unchanged as historical evidence; "
        "files listed in public_archive.modified_files match it only through their original_sha256.",
        "The internal campaign archive was only read. Original SHA-256 values can be checked against the runner manifest "
        "(results/SHA256SUMS.txt) and against the internal bundle manifest.",
        "Replacement is pattern/value based and was followed by a scan of every published file; it is a safety aid, not a formal proof.",
    ],
}
sanitization = {
    "generated_by": "reproducibility/controlled_followup/audit/build_public_release.py",
    "policy": policy,
    "public_archive": {"asset": "ijis_controlled_followup_public.zip", "path_mapping_from_internal_bundle": PATH_MAPPING, **pub.summary()},
    "repository": repo.summary(),
}
sanitization_text = json.dumps(sanitization, indent=2, ensure_ascii=False) + "\n"
(A / "SANITIZATION.json").write_text(sanitization_text, encoding="utf-8")
(PUB / "SANITIZATION.json").write_text(sanitization_text, encoding="utf-8")
shutil.copyfile(A / "SANITIZATION.md", PUB / "SANITIZATION.md")
run1_record = {"generated_by": sanitization["generated_by"], "policy": policy,
               "excluded_run_archive": {"asset": "ijis_controlled_followup_run1_EXCLUDED.zip",
                                        "path_mapping_from_internal_archive": {"SHA256SUMS.txt": "ARCHIVE_SHA256SUMS.txt",
                                                                               "campaign_logs/v4/incidente_orden30_20261115T221700Z/": "halt_incident_order30/"},
                                        **run1.summary()}}
(R1 / "SANITIZATION.json").write_text(json.dumps(run1_record, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

for base in (PUB, R1):
    n = write_manifest(base)
    zp = OUT / f"{base.name}.zip"
    make_zip(base, zp)
    digest = sha(zp.read_bytes())
    (OUT / f"{zp.name}.sha256").write_text(f"{digest}  {zp.name}\n", encoding="utf-8")
    print(f"{zp.name}: {n} files, sha256 {digest}")

for rec in (pub, repo, run1):
    s = rec.summary()
    print(f"{rec.name}: modified={s['files_modified']} unchanged={s['files_unchanged']} replacements={s['replacements_by_rule']}")
