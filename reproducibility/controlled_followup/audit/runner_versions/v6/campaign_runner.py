#!/usr/bin/env python3
"""Prospective controlled validation campaign for the IJIS Reviewer-2 follow-up.

This runner intentionally does not modify or depend on the interactive orchestration
state in automate/sce_automation_api.py. It freezes the follow-up protocol in a
configuration file and preserves every attempt in an immutable directory.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

import boto3
import yaml
from botocore.config import Config as BotoConfig
from botocore.exceptions import BotoCoreError, ClientError, WaiterError


ROOT = Path(__file__).resolve().parent
RESULTS_DIR = ROOT / "results"
TASK_DIR = ROOT / "tasks"
TEMPLATE_PATH = ROOT.parent / "automate" / "inputs" / "template.json"
ENVIRONMENT_FILE = RESULTS_DIR / "campaign_environment.json"
RESULTS_CSV = RESULTS_DIR / "campaign_results.csv"
RESULTS_JSON = RESULTS_DIR / "campaign_results.json"
ADJUDICATION_CSV = RESULTS_DIR / "human_adjudication.csv"
SHA_FILE = RESULTS_DIR / "SHA256SUMS.txt"
INFRASTRUCTURE_FILE = RESULTS_DIR / "campaign_infrastructure.json"
NETWORK_STACK_NAME = "cvr2-network"

CONDITION_LABELS = {
    "chaos_adt_feedback": "Chaos ADT + Q_pre gate + feedback",
    "chaos_adt_no_feedback": "Chaos ADT + Q_pre gate + no-feedback regeneration",
    "conventional_adt_feedback": "Conventional ADT + feedback",
    "direct_sce_feedback": "Direct LLM-to-SCE + feedback",
}

CONDITION_CODES = {
    "chaos_adt_feedback": "caf",
    "chaos_adt_no_feedback": "can",
    "conventional_adt_feedback": "cad",
    "direct_sce_feedback": "dir",
}

MODEL_CODES = {"haiku-4.5": "h45", "sonnet-4.6": "s46"}

TERMINAL_QPOST = "terminal_qpost"


@dataclass
class AttemptResult:
    order: int
    repetition: int
    task: str
    model: str
    condition: str
    attempt: int
    status: str
    q_pre: Optional[float] = None
    q_post: Optional[float] = None
    executed: bool = False
    chaos_return_code: Optional[int] = None
    chaos_timed_out: bool = False
    input_tokens_generation: Optional[int] = None
    output_tokens_generation: Optional[int] = None
    input_tokens_qpre: Optional[int] = None
    output_tokens_qpre: Optional[int] = None
    input_tokens_qpost: Optional[int] = None
    output_tokens_qpost: Optional[int] = None
    attempt_dir: str = ""
    notes: str = ""
    # v4 audit counters, derived from attempt_events.jsonl when the status is written.
    resume_count: int = 0
    model_call_retries: int = 0
    infrastructure_errors: int = 0


def read_yaml(path: Path) -> Dict[str, Any]:
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def dump_json(path: Path, obj: Any) -> None:
    path.write_text(json.dumps(obj, indent=2, ensure_ascii=False, default=str), encoding="utf-8")


RUNNER_REVISION = "v6-artifact-order-json-guard"
ATTEMPT_EVENTS_FILE = "attempt_events.jsonl"


def utc_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def utc_stamp() -> str:
    return time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())


def append_attempt_event(attempt_dir: Path, event: str, **details: Any) -> None:
    """Append one record to the attempt's append-only audit trail.

    The file is only ever opened in append mode, so resumes, retried Bedrock calls,
    infrastructure errors and halts accumulate instead of overwriting each other.
    """
    record = {"timestamp": utc_now(), "event": event, **details}
    with (attempt_dir / ATTEMPT_EVENTS_FILE).open("a", encoding="utf-8") as f:
        f.write(json.dumps(record, ensure_ascii=False, default=str) + "\n")
        f.flush()
        os.fsync(f.fileno())


def read_attempt_events(attempt_dir: Path) -> List[Dict[str, Any]]:
    path = attempt_dir / ATTEMPT_EVENTS_FILE
    if not path.exists():
        return []
    events: List[Dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            events.append({"event": "unparseable_event_line", "raw": line})
    return events


def _read_json_or_none(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def begin_model_call(attempt_dir: Path, stage: str, model_id: str) -> bool:
    """Mark the start of a Bedrock call for `stage` ("generation", "qpre" or "qpost").

    Returns False when the previous call of this stage started but left neither a
    response nor a failure record (the process died mid-call). Its outcome is unknown,
    so the caller must halt instead of re-sampling the model.

    A failure record only clears the call it belongs to. Before a retry, the previous
    started/failed records are copied to the audit trail and the failure record is
    removed, so an interruption of the retry itself is detected as ambiguous. (In v3
    the stale failure record masked it and the model was silently called again.)
    """
    started = attempt_dir / f"{stage}_call_started.json"
    failed = attempt_dir / f"{stage}_call_failed.json"
    if started.exists() and not failed.exists():
        return False
    if failed.exists():
        append_attempt_event(attempt_dir, f"{stage}_call_retry",
                             previous_call_started=_read_json_or_none(started),
                             previous_call_failed=_read_json_or_none(failed))
    # Write the new start marker before removing the old failure record: if the process
    # dies in between, both exist and the next resume correctly treats it as a retry of
    # a call that was never sent.
    dump_json(started, {"timestamp": utc_now(), "model_id": model_id})
    failed.unlink(missing_ok=True)
    append_attempt_event(attempt_dir, f"{stage}_call_started", model_id=model_id)
    return True


def record_model_call_failure(attempt_dir: Path, stage: str, exc: BaseException) -> None:
    dump_json(attempt_dir / f"{stage}_call_failed.json", {"timestamp": utc_now(), "error": repr(exc)})
    append_attempt_event(attempt_dir, f"{stage}_call_failed", error=repr(exc))


def sanitize(value: str) -> str:
    """Return a CloudFormation-safe token (letters/numbers/hyphens only)."""
    value = value.replace("_", "-")
    return re.sub(r"[^A-Za-z0-9-]+", "-", value).strip("-").lower()


def score_from_text(text: str, metric: str) -> Optional[float]:
    patterns = [
        rf"(?im)^\s*{re.escape(metric)}\s*=\s*(\d{{1,3}}(?:\.\d+)?)\s*$",
        rf"\*\*\s*{re.escape(metric)}\s*=\s*(\d{{1,3}}(?:\.\d+)?)\s*\*\*",
        rf"{re.escape(metric)}\s*=\s*(\d{{1,3}}(?:\.\d+)?)",
    ]
    for pattern in patterns:
        matches = list(re.finditer(pattern, text, re.IGNORECASE | re.MULTILINE))
        if matches:
            value = float(matches[-1].group(1))
            if 0 <= value <= 100:
                return value
    return None


def _first_fenced_match(text: str, languages: Iterable[str], pos: int = 0) -> Optional["re.Match[str]"]:
    for language in languages:
        pattern = re.compile(rf"```{language}\s*\n(.*?)```", re.IGNORECASE | re.DOTALL)
        match = pattern.search(text, pos)
        if match:
            return match
    return None


def extract_fenced(text: str, languages: Iterable[str]) -> Optional[str]:
    match = _first_fenced_match(text, languages)
    return match.group(1).strip() + "\n" if match else None


def extract_generation_artifacts(text: str) -> Tuple[Optional[str], Optional[str]]:
    """Return the (Python, JSON) artifacts of a generation response.

    v6: the generation prompt asks for "exactly two fenced artifacts, first Python
    and then JSON". The Python artifact is the first Python block (as in v5). The
    JSON artifact is the first JSON block that starts after that Python block; only
    if there is none does it fall back to the first JSON block of the response (the
    v5 rule). A JSON snippet quoted in the explanation before the code is therefore
    not taken as the Chaos Toolkit manifest. For every response whose blocks follow
    the requested order, the result is identical to v5.
    """
    py_match = _first_fenced_match(text, ["python", "py"])
    py = py_match.group(1).strip() + "\n" if py_match else None
    js = None
    if py_match is not None:
        js_match = _first_fenced_match(text, ["json"], py_match.end())
        if js_match:
            js = js_match.group(1).strip() + "\n"
    if js is None:
        js = extract_fenced(text, ["json"])
    return py, js


def executable_source_without_docstrings(tree: ast.AST) -> str:
    """Return executable Python source without comments/docstrings for marker checks.

    Comments are absent from the AST. Leading string expressions used as
    module/function/class docstrings are removed before unparsing. String literals
    that are actual executable data (for example a CloudFormation template body)
    are intentionally preserved.
    """
    class StripDocstrings(ast.NodeTransformer):
        @staticmethod
        def _strip(body: List[ast.stmt]) -> List[ast.stmt]:
            if (body and isinstance(body[0], ast.Expr) and
                    isinstance(body[0].value, ast.Constant) and
                    isinstance(body[0].value.value, str)):
                return body[1:]
            return body

        def visit_Module(self, node: ast.Module) -> ast.AST:
            node.body = self._strip(node.body)
            return self.generic_visit(node)

        def visit_FunctionDef(self, node: ast.FunctionDef) -> ast.AST:
            node.body = self._strip(node.body)
            return self.generic_visit(node)

        def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> ast.AST:
            node.body = self._strip(node.body)
            return self.generic_visit(node)

        def visit_ClassDef(self, node: ast.ClassDef) -> ast.AST:
            node.body = self._strip(node.body)
            return self.generic_visit(node)

    cleaned = StripDocstrings().visit(tree)
    ast.fix_missing_locations(cleaned)
    return ast.unparse(cleaned)


def load_schedule(path: Path) -> List[Dict[str, Any]]:
    with path.open(newline="", encoding="utf-8") as f:
        rows = list(csv.DictReader(f))
    for row in rows:
        row["order"] = int(row["order"])
        row["repetition"] = int(row["repetition"])
    return rows


def format_task_semantics(task: Dict[str, Any]) -> str:
    return f"""TASK: {task['display_name']}
Attack node(s): {', '.join(task['attack_nodes'])}
Attack name: {task['attack']['name']}
Attack action: {task['attack']['action']}
Attack description: {task['attack']['description']}
Defensive control: {task['defense']['name']}
Defense classification: {task['defense']['classification']}
Defense description: {task['defense']['description']}
Experimental question: {task['probe']['question']}
Required evidence: {task['probe']['expected_evidence']}"""


def representation_for(task: Dict[str, Any], condition: str) -> str:
    common = format_task_semantics(task)
    if condition in {"chaos_adt_feedback", "chaos_adt_no_feedback"}:
        return f"""CHAOS-ADT REPRESENTATION
The task is represented as an Attack-Defense structure with an explicit first-class Chaos Node.
- Attack Node(s): {', '.join(task['attack_nodes'])} — {task['attack']['name']}
- Defense Node: {task['defense']['name']} ({task['defense']['classification']})
- Chaos Node / SCE Node: {task['sce_node']}
- Validation relation: the Chaos Node explicitly links the attack action, the corresponding defense, and the SCE probe that empirically exercises that relationship.

{common}"""
    if condition == "conventional_adt_feedback":
        return f"""CONVENTIONAL ADT REPRESENTATION
The same security semantics are provided as a conventional Attack-Defense representation. There is NO explicit Chaos Node and NO experiment-admission gate in this baseline.
- Attack Node(s): {', '.join(task['attack_nodes'])} — {task['attack']['name']}
- Defense Node: {task['defense']['name']} ({task['defense']['classification']})
The SCE artifact must be derived from this attack-defense relationship.

{common}"""
    if condition == "direct_sce_feedback":
        return f"""DIRECT LLM-TO-SCE REPRESENTATION
Generate the SCE experiment directly from the security task below. There is NO ADT, NO explicit Chaos Node, and NO semantic experiment-admission gate in this baseline.

{common}"""
    raise ValueError(f"Unknown condition: {condition}")


def feedback_context(previous: Optional[Dict[str, str]], condition: str) -> str:
    if not previous or condition == "chaos_adt_no_feedback":
        return ""
    chunks = ["\nPREVIOUS-ATTEMPT MATERIAL FOR ITERATIVE REFINEMENT:"]
    if previous.get("python"):
        chunks.append("\nPrevious Python candidate:\n```python\n" + previous["python"] + "\n```")
    if previous.get("json"):
        chunks.append("\nPrevious Chaos Toolkit manifest:\n```json\n" + previous["json"] + "\n```")
    if previous.get("qpre"):
        chunks.append("\nPrevious semantic pre-execution evaluation:\n" + previous["qpre"])
    if previous.get("execution"):
        chunks.append("\nPrevious execution evidence:\n```text\n" + previous["execution"] + "\n```")
    if previous.get("qpost"):
        chunks.append("\nPrevious post-execution operational-evaluability report:\n" + previous["qpost"])
    chunks.append(
        "\nUse the previous-attempt material only to correct the next candidate. "
        "Do not claim that an issue is fixed unless the new implementation actually changes it."
    )
    return "\n".join(chunks)


def generation_prompt(task: Dict[str, Any], condition: str, template_json: str,
                      attempt_prefix: str, previous: Optional[Dict[str, str]],
                      network: Dict[str, str]) -> str:
    rep = representation_for(task, condition)
    fb = feedback_context(previous, condition)
    return f"""You are generating one Security Chaos Engineering experiment for a controlled academic validation campaign in a dedicated AWS test account.

{rep}

CONTROLLED CAMPAIGN ENVIRONMENT
- AWS region: us-east-1
- Credentials are supplied through the standard AWS credential chain / AWS CLI profile.
- The account is a dedicated research test account.
- Run only against resources created for THIS attempt.
- Attempt identifier/prefix: {attempt_prefix}
- A fixed campaign network has already been provisioned and MUST be reused by every condition:
  - VPC ID: {network['vpc_id']}
  - Subnet ID: {network['subnet_id']}
  - Security Group ID: {network['security_group_id']}

COMMON TECHNICAL AND SAFETY REQUIREMENTS — APPLY TO EVERY EXPERIMENTAL CONDITION
1. Return exactly two fenced artifacts, first Python and then JSON.
2. Python must define: steady_state(), attack(), hypothesis_verification(), rollback().
3. Use real boto3 AWS API calls; no mocks or hard-coded success values. Comments may describe simulated/adversarial roles, but executable behavior must use real AWS APIs.
4. Use region us-east-1 explicitly for AWS clients/resources.
5. ALL temporary per-attempt infrastructure must be provisioned through ONE CloudFormation stack whose name begins exactly with `{attempt_prefix}-` followed by a timestamp. The fixed campaign VPC/subnet/security group above are pre-existing controlled infrastructure and must be referenced, NOT recreated or deleted.
6. The attempt stack may create only resources needed for the current task (for example EC2/IAM resources). Do not create VPCs, subnets, security groups, CloudTrail trails, AWS Config recorders/rules, EventBridge rules, CloudWatch log groups, or S3 telemetry buckets.
7. Attack actions may operate only on resources provisioned by that attempt's CloudFormation stack.
8. Tag resources/stack with Campaign=review2-controlled-validation-v2 and Attempt={attempt_prefix} whenever supported.
9. rollback() must delete the attempt stack and wait for DELETE_COMPLETE. Always tolerate an already-absent stack. Never delete the fixed campaign network.
10. Implement bounded polling with time.monotonic() for AWS eventual consistency; never rely on a single fixed short sleep followed by one probe.
11. hypothesis_verification() must derive its result from real AWS-side evidence tied to the CURRENT attempt/resource and must return False when evidence is unavailable.
12. For CN2-D specifically, use CloudTrail Event History via boto3 cloudtrail.lookup_events(). Do NOT create a CloudTrail trail, S3 bucket, AWS Config resource, EventBridge rule, or CloudWatch telemetry resource. Match EventName=ModifyInstanceMetadataOptions and then parse each event's CloudTrailEvent JSON to verify the current attempt-owned EC2 instance ID, the relevant weakening parameters, and an event time within the current attempt window. Historical evidence from previous repetitions must never satisfy the probe.
13. No organization-wide changes, no cross-account actions, no modification/deletion of pre-existing resources, and no shell commands from the generated Python.
14. Do not create long-lived access keys/users. Prefer temporary role/session credentials where credentials are needed.

EXPERIMENT FLOW
- steady_state(): create the unique per-attempt CloudFormation stack using the fixed campaign subnet/security-group IDs and wait for CREATE_COMPLETE.
- attack(): execute the specified real attack/API action against attempt-owned resources and return verifiable evidence/success state.
- hypothesis_verification(): establish whether the specified defensive behavior/evidence can be observed for this attempt.
- rollback(): remove only the per-attempt stack and wait for deletion.

CHAOS TOOLKIT TEMPLATE
Use this structure and replace placeholders. Keep method order steady_state -> attack; the campaign executes with --hypothesis-strategy=after-method-only.
```json
{template_json}
```

The JSON provider module path may use a placeholder; the campaign runner will replace it with an immutable attempt-specific module name before execution.
{fb}
"""


def qpre_prompt(task: Dict[str, Any], python_code: str, manifest: str, threshold: int) -> str:
    rep = representation_for(task, "chaos_adt_feedback")
    return f"""# PRE-EXECUTION SEMANTIC QUALITY EVALUATION

This is the semantic admission gate used by the proposed Chaos-ADT workflow. Evaluate BEFORE AWS execution.

## CHAOS-ADT TASK
{rep}

## GENERATED MANIFEST
```json
{manifest}
```

## GENERATED PYTHON
```python
{python_code}
```

Score exactly these factors:
- f1 ACTION ↔ Attack correspondence: 0=no correspondence, 50=partial, 100=full same tactic/technique with sound implementation.
- f2 Defense ↔ Defense correspondence: 0=no correspondence, 50=partial correspondence, 100=full correspondence with sound implementation.
- f3 PROBE ↔ defensive-intent correspondence: 0=no correspondence, 100=full correspondence.

Compute Q_pre = 0.40*f1 + 0.30*f2 + 0.30*f3.
Admission threshold = {threshold}.

Your final report MUST contain a standalone line exactly `Q_pre = XX.XX` and then either `DECISION: AUTHORIZE` or `DECISION: REJECT`.
Explain each factor sufficiently for later human audit.
"""


def qpost_prompt(task: Dict[str, Any], execution_log: str, threshold: int) -> str:
    return f"""# POST-EXECUTION OPERATIONAL-EVALUABILITY ASSESSMENT

The purpose of this score is ONLY to decide whether another automated refinement attempt is needed. It is NOT a measure of security effectiveness and is NOT the primary scientific validity label.

Task: {task['display_name']}
Attack node(s): {', '.join(task['attack_nodes'])}
Probe type: {task['probe_type']}

EXECUTION EVIDENCE
```text
{execution_log}
```

Score:
- f1 ACTION evidence: 0 if the action produced no verifiable evidence of execution; 100 if verifiable evidence establishes what happened.
- f2 PROBE evidence: 0 if the probe produced no verifiable defensive outcome/evidence; 100 if the defensive outcome can be established from runtime evidence, whether effective or ineffective.

Compute Q_post = 0.50*f1 + 0.50*f2.
Operational stopping threshold = {threshold}.

Your final report MUST contain a standalone line exactly `Q_post = XX.XX`.
Do NOT infer that Q_post=100 means that the defense was effective; it only means the experiment is operationally evaluable.
"""


class CampaignRunner:
    def __init__(self, config_path: Path, profile: str, force: bool = False):
        self.config_path = config_path.resolve()
        self.cfg = read_yaml(self.config_path)
        self.profile = profile
        self.force = force
        self.region = self.cfg["aws"]["region"]
        self.session = boto3.Session(profile_name=profile, region_name=self.region)
        boto_cfg = BotoConfig(read_timeout=3600, connect_timeout=30,
                              retries={"max_attempts": 3, "mode": "standard"})
        self.bedrock = self.session.client("bedrock-runtime", config=boto_cfg)
        self.sts = self.session.client("sts")
        self.cfn = self.session.client("cloudformation")
        self.cloudtrail = self.session.client("cloudtrail")
        self.template = TEMPLATE_PATH.read_text(encoding="utf-8")
        self.tasks = {task_id: read_yaml(TASK_DIR / f"{task_id}.yaml") for task_id in self.cfg["tasks"]}
        self.schedule = load_schedule(ROOT / "schedule.csv")
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        self.environment: Dict[str, Any] = {}
        self.all_results: List[AttemptResult] = []

    def _campaign_network_outputs(self) -> Optional[Dict[str, str]]:
        try:
            response = self.cfn.describe_stacks(StackName=NETWORK_STACK_NAME)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ValidationError":
                return None
            raise
        stack = response["Stacks"][0]
        if stack.get("StackStatus") != "CREATE_COMPLETE":
            return None
        outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
        required = {"VpcId", "SubnetId", "SecurityGroupId"}
        if not required.issubset(outputs):
            return None
        return {
            "vpc_id": outputs["VpcId"],
            "subnet_id": outputs["SubnetId"],
            "security_group_id": outputs["SecurityGroupId"],
            "stack_name": NETWORK_STACK_NAME,
        }

    def prepare_infrastructure(self) -> Dict[str, str]:
        existing = self._campaign_network_outputs()
        if existing:
            dump_json(INFRASTRUCTURE_FILE, existing)
            return existing
        template = {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Fixed network for IJIS Reviewer-2 controlled validation",
            "Resources": {
                "Vpc": {
                    "Type": "AWS::EC2::VPC",
                    "Properties": {
                        "CidrBlock": self.cfg["infrastructure"]["vpc_cidr"],
                        "EnableDnsSupport": True,
                        "EnableDnsHostnames": True,
                        "Tags": [
                            {"Key": "Name", "Value": "cvr2-network"},
                            {"Key": "Campaign", "Value": self.cfg["campaign_id"]},
                        ],
                    },
                },
                "Subnet": {
                    "Type": "AWS::EC2::Subnet",
                    "Properties": {
                        "VpcId": {"Ref": "Vpc"},
                        "CidrBlock": self.cfg["infrastructure"]["subnet_cidr"],
                        "MapPublicIpOnLaunch": False,
                        "Tags": [
                            {"Key": "Name", "Value": "cvr2-subnet"},
                            {"Key": "Campaign", "Value": self.cfg["campaign_id"]},
                        ],
                    },
                },
                "SecurityGroup": {
                    "Type": "AWS::EC2::SecurityGroup",
                    "Properties": {
                        "GroupDescription": "Controlled validation default SG",
                        "VpcId": {"Ref": "Vpc"},
                        "SecurityGroupEgress": [
                            {"IpProtocol": "-1", "CidrIp": "0.0.0.0/0"}
                        ],
                        "Tags": [
                            {"Key": "Name", "Value": "cvr2-sg"},
                            {"Key": "Campaign", "Value": self.cfg["campaign_id"]},
                        ],
                    },
                },
            },
            "Outputs": {
                "VpcId": {"Value": {"Ref": "Vpc"}},
                "SubnetId": {"Value": {"Ref": "Subnet"}},
                "SecurityGroupId": {"Value": {"Ref": "SecurityGroup"}},
            },
        }
        self.cfn.create_stack(
            StackName=NETWORK_STACK_NAME,
            TemplateBody=json.dumps(template),
            Tags=[{"Key": "Campaign", "Value": self.cfg["campaign_id"]}],
        )
        waiter = self.cfn.get_waiter("stack_create_complete")
        waiter.wait(StackName=NETWORK_STACK_NAME, WaiterConfig={"Delay": 10, "MaxAttempts": 90})
        outputs = self._campaign_network_outputs()
        if not outputs:
            raise RuntimeError("Campaign network stack was created but required outputs are unavailable")
        dump_json(INFRASTRUCTURE_FILE, outputs)
        return outputs

    def cleanup_infrastructure(self) -> None:
        try:
            self.cfn.delete_stack(StackName=NETWORK_STACK_NAME)
            waiter = self.cfn.get_waiter("stack_delete_complete")
            waiter.wait(StackName=NETWORK_STACK_NAME, WaiterConfig={"Delay": 10, "MaxAttempts": 90})
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "ValidationError":
                raise
        INFRASTRUCTURE_FILE.unlink(missing_ok=True)

    def preflight(self, invoke_models: bool = True) -> Dict[str, Any]:
        identity = self.sts.get_caller_identity()
        account_id = identity["Account"]
        arn = identity["Arn"]
        expected = self.cfg["aws"].get("expected_account_id")
        if expected and str(expected) != str(account_id):
            raise RuntimeError(f"AWS account mismatch: expected {expected}, resolved {account_id}")

        if ENVIRONMENT_FILE.exists():
            old = json.loads(ENVIRONMENT_FILE.read_text(encoding="utf-8"))
            old_account = old.get("aws_account_id")
            if old_account and old_account != account_id:
                raise RuntimeError(
                    f"Campaign was previously bound to AWS account {old_account}; current account is {account_id}."
                )

        chaos = shutil.which("chaos")
        if not chaos:
            raise RuntimeError("Chaos Toolkit executable 'chaos' not found in PATH")

        spec = importlib.util.find_spec("chaosaws.ec2")
        if spec is None or not spec.submodule_search_locations:
            raise RuntimeError("Python package chaosaws.ec2 is not available in this environment")
        module_dir = Path(next(iter(spec.submodule_search_locations))).resolve()

        model_checks: Dict[str, Any] = {}
        model_failures: List[str] = []
        if invoke_models:
            for label, model_id in self.cfg["models"].items():
                try:
                    response = self.bedrock.converse(
                        modelId=model_id,
                        messages=[{"role": "user", "content": [{"text": "Reply with exactly OK"}]}],
                        inferenceConfig={"maxTokens": 8, "temperature": 0},
                    )
                    model_checks[label] = {
                        "status": "OK",
                        "model_id": model_id,
                        "response": response.get("output", {}).get("message", {}).get("content", [{}])[0].get("text", ""),
                        "usage": response.get("usage", {}),
                    }
                except Exception as exc:
                    model_checks[label] = {"status": "FAIL", "model_id": model_id, "error": repr(exc)}
                    model_failures.append(label)

        network = self._campaign_network_outputs()
        legacy_warnings: List[str] = []
        try:
            active_statuses = ["CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_IN_PROGRESS",
                               "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED"]
            response = self.cfn.list_stacks(StackStatusFilter=active_statuses)
            old = [x for x in response.get("StackSummaries", []) if x.get("StackName", "").startswith("sce-")]
            if old:
                legacy_warnings.append(f"Found {len(old)} historical sce-* CloudFormation stacks; they are not touched by this campaign")
        except Exception as exc:
            legacy_warnings.append(f"Could not enumerate historical stacks: {exc!r}")
        try:
            trails = [t for t in self.cloudtrail.list_trails().get("Trails", [])
                      if t.get("Name", "").startswith("sce-")]
            if trails:
                legacy_warnings.append(f"Found {len(trails)} historical sce-* CloudTrail trails; CN2-D uses Event History scoped to current attempt and does not create/use these trails")
        except Exception as exc:
            legacy_warnings.append(f"Could not enumerate CloudTrail trails: {exc!r}")

        ready = not model_failures and network is not None
        self.environment = {
            "campaign_id": self.cfg["campaign_id"],
            "runner_revision": RUNNER_REVISION,
            "aws_account_id": account_id,
            "caller_arn": arn,
            "aws_region": self.region,
            "aws_profile_name": self.profile,
            "chaos_executable": chaos,
            "chaosaws_ec2_module_dir": str(module_dir),
            "model_checks": model_checks,
            "campaign_network": network,
            "legacy_resource_warnings": legacy_warnings,
            "ready_for_run": ready,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "python": sys.version,
        }
        dump_json(ENVIRONMENT_FILE, self.environment)
        return self.environment

    def call_bedrock(self, prompt: str, model_id: str, max_tokens: Optional[int] = None,
                     temperature: Optional[float] = None) -> Tuple[str, Dict[str, Any]]:
        inf = {
            "maxTokens": max_tokens if max_tokens is not None else self.cfg["inference"]["max_tokens"],
            "temperature": temperature if temperature is not None else self.cfg["inference"]["temperature"],
        }
        response = self.bedrock.converse(
            modelId=model_id,
            messages=[{"role": "user", "content": [{"text": prompt}]}],
            inferenceConfig=inf,
        )
        text = response["output"]["message"]["content"][0]["text"]
        metadata = {
            "model_id": model_id,
            "inference_config": inf,
            "usage": response.get("usage", {}),
            "stop_reason": response.get("stopReason"),
            "response_metadata": response.get("ResponseMetadata", {}),
        }
        return text, metadata

    @staticmethod
    def rewrite_manifest_modules(manifest_text: str, module_name: str) -> str:
        manifest = json.loads(manifest_text)

        def walk(obj: Any) -> None:
            if isinstance(obj, dict):
                provider = obj.get("provider")
                if isinstance(provider, dict) and provider.get("type") == "python":
                    provider["module"] = f"chaosaws.ec2.{module_name}"
                for value in obj.values():
                    walk(value)
            elif isinstance(obj, list):
                for value in obj:
                    walk(value)

        walk(manifest)
        return json.dumps(manifest, indent=2, ensure_ascii=False) + "\n"

    @classmethod
    def safe_rewrite_manifest_modules(cls, manifest_text: str, module_name: str) -> Tuple[str, Optional[str]]:
        """v6: like rewrite_manifest_modules, but an unparseable manifest is returned
        unchanged together with the parse error instead of raising."""
        try:
            return cls.rewrite_manifest_modules(manifest_text, module_name), None
        except (ValueError, RecursionError) as exc:
            return manifest_text, repr(exc)

    def technical_validate(self, python_code: str, manifest_text: str,
                           attempt_prefix: str, module_name: str,
                           task: Dict[str, Any], network: Dict[str, str]) -> Dict[str, Any]:
        errors: List[str] = []
        warnings: List[str] = []
        tree = None
        try:
            tree = ast.parse(python_code)
        except SyntaxError as exc:
            errors.append(f"Python syntax error: {exc}")

        try:
            manifest = json.loads(manifest_text)
        except json.JSONDecodeError as exc:
            manifest = None
            errors.append(f"JSON parse error: {exc}")

        functions = set()
        calls: List[str] = []
        # v5: boto3 operations invoked through a paginator, e.g. client.get_paginator("lookup_events").
        # A paginator issues exactly the same API operation (CloudTrail LookupEvents) page by page.
        paginated_operations: set = set()
        if tree is not None:
            functions = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}
            for node in ast.walk(tree):
                if isinstance(node, ast.Call):
                    fn = node.func
                    if isinstance(fn, ast.Attribute):
                        calls.append(fn.attr)
                        if (fn.attr == "get_paginator" and node.args
                                and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
                            paginated_operations.add(node.args[0].value)
                    elif isinstance(fn, ast.Name):
                        calls.append(fn.id)

        required = {"steady_state", "attack", "hypothesis_verification", "rollback"}
        missing = required - functions
        if missing:
            errors.append(f"Missing required functions: {sorted(missing)}")

        lower = python_code.lower()
        executable_lower = executable_source_without_docstrings(tree).lower() if tree is not None else lower
        # Hard text-marker checks apply only to executable code/data. Comments and
        # docstrings remain archived for audit but cannot cause technical rejection.
        for bad in ["your-account-id", "your_account_id", "replace_me", "changeme"]:
            if bad in executable_lower:
                errors.append(f"Unresolved configuration marker found in executable code/data: {bad}")
        for marker in ["todo", "simulated", "placeholder", "mock aws"]:
            if marker in lower:
                warnings.append(f"Text marker present and retained for audit (not an automatic rejection): {marker}")

        if attempt_prefix not in python_code:
            errors.append(f"Attempt-specific CloudFormation prefix {attempt_prefix!r} is not embedded in Python source")
        if "us-east-1" not in python_code:
            errors.append("Python source does not explicitly contain region us-east-1")
        if "create_stack" not in calls:
            errors.append("No CloudFormation create_stack call found")
        if "delete_stack" not in calls:
            errors.append("No CloudFormation delete_stack call found in rollback path")
        if "subprocess" in executable_lower or "os.system" in executable_lower:
            errors.append("Generated Python uses shell/subprocess execution")

        for key in ["subnet_id", "security_group_id"]:
            if network[key] not in python_code:
                errors.append(f"Generated Python does not reference fixed campaign {key}: {network[key]}")

        # The fixed network is campaign-level infrastructure; attempt templates must not
        # create/delete network resources or telemetry infrastructure.
        forbidden_template_markers = [
            "aws::ec2::vpc", "aws::ec2::subnet", "aws::ec2::securitygroup",
            "aws::cloudtrail::trail", "aws::config::", "aws::events::rule",
            "aws::logs::loggroup", "aws::s3::bucket", "aws::guardduty::detector",
            "aws::iam::user", "aws::iam::accesskey",
        ]
        # `(?!::)`: `AWS::EC2::VPC::Id`, `AWS::EC2::Subnet::Id` and `AWS::EC2::SecurityGroup::Id`
        # are CloudFormation parameter types that REFERENCE the existing fixed campaign network,
        # which is exactly what the prompt asks for. They create nothing and must not be rejected.
        # Resource types that merely start with a marker (e.g. AWS::EC2::SecurityGroupIngress,
        # AWS::S3::BucketPolicy) are still rejected, as in v3.
        for marker in forbidden_template_markers:
            if re.search(re.escape(marker) + r"(?!::)", executable_lower):
                errors.append(f"Per-attempt template contains forbidden campaign-level resource: {marker}")

        forbidden_direct_resource_calls = {
            "run_instances", "create_role", "create_user", "create_access_key",
            "create_vpc", "create_subnet", "create_security_group", "create_bucket",
            "create_trail", "put_configuration_recorder", "put_delivery_channel",
            "delete_role", "delete_user", "delete_access_key", "delete_vpc",
            "delete_subnet", "delete_security_group", "delete_bucket", "delete_trail",
            "terminate_instances",
        }
        direct = sorted(set(calls) & forbidden_direct_resource_calls)
        if direct:
            errors.append(
                "Direct resource creation/deletion API calls found; per-attempt temporary infrastructure must be CloudFormation-owned: "
                + ", ".join(direct)
            )

        if task.get("task_id") == "cn2_d":
            # v4 accepted only a direct `.lookup_events(...)` call and rejected the equivalent
            # `get_paginator("lookup_events")`, which calls the same CloudTrail LookupEvents API.
            if "lookup_events" not in calls and "lookup_events" not in paginated_operations:
                errors.append("CN2-D must use CloudTrail Event History via lookup_events()")
            if "create_trail" in calls or "aws::cloudtrail::trail" in executable_lower:
                errors.append("CN2-D must not create a CloudTrail trail")

        if manifest is not None:
            providers: List[Dict[str, Any]] = []
            def collect(obj: Any) -> None:
                if isinstance(obj, dict):
                    if isinstance(obj.get("provider"), dict):
                        providers.append(obj["provider"])
                    for v in obj.values():
                        collect(v)
                elif isinstance(obj, list):
                    for v in obj:
                        collect(v)
            collect(manifest)
            expected_module = f"chaosaws.ec2.{module_name}"
            wrong = [p.get("module") for p in providers if p.get("type") == "python" and p.get("module") != expected_module]
            if wrong:
                errors.append(f"Unexpected provider module(s): {wrong}")
            funcs = {p.get("func") for p in providers if p.get("type") == "python"}
            if not {"steady_state", "attack", "hypothesis_verification", "rollback"}.issubset(funcs):
                errors.append(f"Manifest does not reference all required functions; found {sorted(f for f in funcs if f)}")

        return {"passed": not errors, "errors": errors, "warnings": warnings, "observed_calls": sorted(set(calls)),
                "observed_paginated_operations": sorted(paginated_operations)}

    def install_module(self, source: Path, module_name: str) -> Path:
        spec = importlib.util.find_spec("chaosaws.ec2")
        if spec is None or not spec.submodule_search_locations:
            raise RuntimeError("chaosaws.ec2 package not found")
        module_dir = Path(next(iter(spec.submodule_search_locations))).resolve()
        dest = module_dir / f"{module_name}.py"
        shutil.copy2(source, dest)
        return dest

    # v5: an AWS input-validation rejection, e.g. "1 validation error detected: Value at 'roleName' failed to
    # satisfy constraint: Member must have length less than or equal to 64". The service rejects such a
    # request before acting on it, so a resource whose creation AND deletion were both rejected this way
    # was never created. CloudFormation nevertheless keeps the stack in DELETE_FAILED because it re-sends
    # the same invalid identifier on every delete attempt.
    _AWS_INPUT_VALIDATION_ERROR = re.compile(
        r"validation error detected: Value at '[^']+' failed to satisfy constraint", re.IGNORECASE)

    def _wait_stack_deleted(self, name: str) -> None:
        waiter = self.cfn.get_waiter("stack_delete_complete")
        max_attempts = max(1, int(self.cfg["execution"]["cleanup_wait_seconds"] / self.cfg["execution"]["cleanup_poll_seconds"]))
        waiter.wait(StackName=name, WaiterConfig={
            "Delay": self.cfg["execution"]["cleanup_poll_seconds"],
            "MaxAttempts": max_attempts,
        })

    def _never_created_delete_failures(self, stack_name: str) -> Optional[List[Dict[str, Any]]]:
        """Return the DELETE_FAILED resources of a DELETE_FAILED stack only if ALL of them were provably never
        created; otherwise None (the caller then halts as before). A resource qualifies only if it never
        reached any *_COMPLETE state and every CREATE_FAILED and DELETE_FAILED event it has is an AWS
        input-validation rejection. Retaining such a resource leaves nothing behind in the account."""
        stacks = self.cfn.describe_stacks(StackName=stack_name).get("Stacks", [])
        if not stacks or stacks[0].get("StackStatus") != "DELETE_FAILED":
            return None
        resources = self.cfn.describe_stack_resources(StackName=stack_name).get("StackResources", [])
        failed = [r for r in resources if r.get("ResourceStatus") == "DELETE_FAILED"]
        if not failed:
            return None
        history: Dict[str, List[Dict[str, Any]]] = {}
        for page in self.cfn.get_paginator("describe_stack_events").paginate(StackName=stack_name):
            for event in page.get("StackEvents", []):
                history.setdefault(event.get("LogicalResourceId", ""), []).append(event)
        qualified: List[Dict[str, Any]] = []
        for resource in failed:
            events = history.get(resource["LogicalResourceId"], [])
            ever_complete = any(str(e.get("ResourceStatus", "")).endswith("_COMPLETE") for e in events)
            create_failed = [e for e in events if e.get("ResourceStatus") == "CREATE_FAILED"]
            delete_failed = [e for e in events if e.get("ResourceStatus") == "DELETE_FAILED"]
            if ever_complete or not create_failed or not delete_failed:
                return None
            if not all(self._AWS_INPUT_VALIDATION_ERROR.search(e.get("ResourceStatusReason") or "")
                       for e in create_failed + delete_failed):
                return None
            qualified.append({
                "logical_id": resource["LogicalResourceId"],
                "type": resource.get("ResourceType"),
                "physical_id": resource.get("PhysicalResourceId"),
                "create_failed_reason": create_failed[-1].get("ResourceStatusReason"),
                "delete_failed_reason": delete_failed[0].get("ResourceStatusReason"),
            })
        return qualified

    def cleanup_stacks(self, prefix: str, report_path: Path, attempt_dir: Optional[Path] = None) -> Dict[str, Any]:
        active_statuses = [
            "CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_IN_PROGRESS",
            "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED",
            "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_COMPLETE",
            "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS", "UPDATE_ROLLBACK_FAILED",
            "UPDATE_ROLLBACK_COMPLETE_CLEANUP_IN_PROGRESS", "UPDATE_ROLLBACK_COMPLETE",
            "IMPORT_IN_PROGRESS", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_IN_PROGRESS",
            "IMPORT_ROLLBACK_FAILED", "IMPORT_ROLLBACK_COMPLETE",
        ]
        found: List[Dict[str, Any]] = []
        token = None
        try:
            while True:
                kwargs = {"StackStatusFilter": active_statuses}
                if token: kwargs["NextToken"] = token
                response = self.cfn.list_stacks(**kwargs)
                for summary in response.get("StackSummaries", []):
                    if summary.get("StackName", "").startswith(prefix):
                        found.append({"name": summary["StackName"], "status": summary["StackStatus"]})
                token = response.get("NextToken")
                if not token: break

            actions = []
            for stack in found:
                name, status = stack["name"], stack["status"]
                if status != "DELETE_IN_PROGRESS":
                    self.cfn.delete_stack(StackName=name)
                    actions.append({"name": name, "action": "delete_stack_requested", "prior_status": status})
                else:
                    actions.append({"name": name, "action": "already_deleting", "prior_status": status})
                try:
                    self._wait_stack_deleted(name)
                except WaiterError as wait_exc:
                    try:
                        retained = self._never_created_delete_failures(name)
                    except (ClientError, BotoCoreError):
                        retained = None
                    if not retained:
                        raise wait_exc
                    self.cfn.delete_stack(StackName=name, RetainResources=[r["logical_id"] for r in retained])
                    actions.append({"name": name, "action": "delete_stack_retaining_never_created_resources",
                                    "first_delete_error": repr(wait_exc), "retained": retained})
                    self._wait_stack_deleted(name)
            report = {"prefix": prefix, "found": found, "actions": actions, "clean": True}
            retained_all = [r for a in actions for r in a.get("retained", [])]
            if retained_all:
                report["retained_never_created"] = retained_all
                if attempt_dir is not None:
                    append_attempt_event(attempt_dir, "cleanup_retained_never_created_resources",
                                         report=report_path.name, resources=retained_all)
        except Exception as exc:
            report = {"prefix": prefix, "found": found, "clean": False, "error": repr(exc)}
        dump_json(report_path, report)
        return report

    def assert_no_campaign_leftovers(self) -> None:
        prefix = "cvr2-"
        active_statuses = ["CREATE_IN_PROGRESS", "CREATE_FAILED", "CREATE_COMPLETE", "ROLLBACK_IN_PROGRESS",
                           "ROLLBACK_FAILED", "ROLLBACK_COMPLETE", "DELETE_IN_PROGRESS", "DELETE_FAILED",
                           "UPDATE_IN_PROGRESS", "UPDATE_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_IN_PROGRESS",
                           "UPDATE_ROLLBACK_FAILED", "UPDATE_ROLLBACK_COMPLETE"]
        leftovers: List[Dict[str, Any]] = []
        token = None
        while True:
            kwargs = {"StackStatusFilter": active_statuses}
            if token:
                kwargs["NextToken"] = token
            response = self.cfn.list_stacks(**kwargs)
            leftovers.extend([s for s in response.get("StackSummaries", [])
                              if s.get("StackName", "").startswith(prefix)
                              and s.get("StackName") != NETWORK_STACK_NAME])
            token = response.get("NextToken")
            if not token:
                break
        if leftovers:
            names = [f"{s['StackName']} ({s['StackStatus']})" for s in leftovers]
            raise RuntimeError("Controlled-campaign per-attempt CloudFormation leftovers exist before starting/resuming: " + "; ".join(names))

    def run_chaos(self, manifest_path: Path, attempt_dir: Path) -> Tuple[int, str, List[str], bool]:
        cmd = ["chaos", "run", str(manifest_path), "--hypothesis-strategy=after-method-only"]
        env = os.environ.copy()
        env["AWS_PROFILE"] = self.profile
        env["AWS_DEFAULT_REGION"] = self.region
        env["AWS_REGION"] = self.region
        timeout = int(self.cfg["execution"].get("chaos_timeout_seconds", 1800))
        timed_out = False
        try:
            result = subprocess.run(cmd, cwd=attempt_dir, env=env, capture_output=True, text=True, timeout=timeout)
            rc, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as exc:
            timed_out = True
            rc = 124
            stdout = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            stderr = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            stderr += f"\nCHAOS TIMEOUT: exceeded {timeout} seconds; process terminated by campaign runner.\n"
        log = (
            f"COMMAND: {' '.join(cmd)}\n"
            f"TIMEOUT_SECONDS: {timeout}\n"
            f"TIMED_OUT: {timed_out}\n\n"
            f"STDOUT:\n{stdout}\n\n"
            f"STDERR:\n{stderr}\n\n"
            f"RETURN CODE: {rc}\n"
        )
        (attempt_dir / "execution.log").write_text(log, encoding="utf-8")
        (attempt_dir / "chaos_command.txt").write_text(" ".join(cmd) + "\n", encoding="utf-8")
        journals = [str(p.name) for p in attempt_dir.glob("journal*.json")]
        return rc, log, journals, timed_out

    def trajectory_dir(self, row: Dict[str, Any]) -> Path:
        return RESULTS_DIR / row["task"] / row["model"] / row["condition"] / f"rep_{row['repetition']:02d}"

    def trajectory_done(self, path: Path) -> bool:
        status = path / "trajectory_status.json"
        if not status.exists(): return False
        data = json.loads(status.read_text(encoding="utf-8"))
        return bool(data.get("completed"))

    def run_trajectory(self, row: Dict[str, Any]) -> List[AttemptResult]:
        task = self.tasks[row["task"]]
        model_id = self.cfg["models"][row["model"]]
        condition = row["condition"]
        network = self._campaign_network_outputs()
        if not network:
            raise RuntimeError("Fixed campaign network is not prepared; run --prepare-infrastructure first")
        trajectory = self.trajectory_dir(row)
        trajectory.mkdir(parents=True, exist_ok=True)
        if self.trajectory_done(trajectory):
            print(f"SKIP completed trajectory: {trajectory.relative_to(ROOT)}")
            return []

        previous: Optional[Dict[str, str]] = None
        trajectory_results: List[AttemptResult] = []
        terminal = False
        completed_statuses = {"technical_rejected", "gate_rejected", "gate_evaluation_error", "qpost_evaluation_error", "qpost_insufficient", TERMINAL_QPOST}

        def reconstruct_previous(attempt_dir: Path) -> Optional[Dict[str, str]]:
            if condition == "chaos_adt_no_feedback":
                return None
            data: Dict[str, str] = {}
            py_files = list(attempt_dir.glob("cvr2_*.py"))
            js_files = list(attempt_dir.glob("cvr2_*.json"))
            if py_files:
                data["python"] = py_files[0].read_text(encoding="utf-8")
            if js_files:
                data["json"] = js_files[0].read_text(encoding="utf-8")
            for key, name in [("qpre", "qpre_report.md"), ("execution", "execution.log"), ("qpost", "qpost_report.md")]:
                f = attempt_dir / name
                if f.exists():
                    data[key] = f.read_text(encoding="utf-8")
            return data or None

        for attempt in range(1, self.cfg["max_attempts"] + 1):
            attempt_dir = trajectory / f"attempt_{attempt:02d}"
            status_file = attempt_dir / "attempt_status.json"
            resuming_attempt = False
            prior_status: Optional[str] = None
            if attempt_dir.exists() and any(attempt_dir.iterdir()):
                if status_file.exists():
                    existing = json.loads(status_file.read_text(encoding="utf-8"))
                    status = existing.get("status")
                    prior_status = status
                    if status in completed_statuses:
                        existing.setdefault("chaos_timed_out", False)
                        existing_result = AttemptResult(**existing)
                        trajectory_results.append(existing_result)
                        previous = reconstruct_previous(attempt_dir)
                        if status == TERMINAL_QPOST:
                            terminal = True
                            break
                        continue
                # V3: never rename/re-sample an attempt that may already contain a
                # Bedrock candidate. Resume deterministically from archived files.
                resuming_attempt = True
                print(f"RESUME existing attempt without re-sampling -> {attempt_dir.relative_to(ROOT)}")

            attempt_dir.mkdir(parents=True, exist_ok=True)
            if resuming_attempt:
                append_attempt_event(attempt_dir, "attempt_resumed", prior_status=prior_status,
                                     runner_revision=RUNNER_REVISION)
            prefix = f"cvr2-{sanitize(row['task'])}-{MODEL_CODES[row['model']]}-{CONDITION_CODES[condition]}-r{row['repetition']:02d}-a{attempt:02d}"
            module_name = prefix.replace("-", "_")
            result = AttemptResult(
                order=row["order"], repetition=row["repetition"], task=row["task"], model=row["model"],
                condition=condition, attempt=attempt, status="started", attempt_dir=str(attempt_dir.relative_to(ROOT))
            )
            try:
                prompt = generation_prompt(task, condition, self.template, prefix, previous, network)
                prompt_path = attempt_dir / "generation_prompt.txt"
                response_path = attempt_dir / "generation_response.txt"
                response_meta_path = attempt_dir / "generation_response_metadata.json"

                if not prompt_path.exists():
                    prompt_path.write_text(prompt, encoding="utf-8")
                if previous and condition != "chaos_adt_no_feedback":
                    if not (attempt_dir / "feedback_manifest.json").exists():
                        dump_json(attempt_dir / "feedback_manifest.json", {"included": list(previous.keys())})
                    if not (attempt_dir / "feedback_supplied.txt").exists():
                        (attempt_dir / "feedback_supplied.txt").write_text(feedback_context(previous, condition), encoding="utf-8")
                elif not (attempt_dir / "feedback_manifest.json").exists():
                    dump_json(attempt_dir / "feedback_manifest.json", {"included": []})

                if response_path.exists():
                    response_text = response_path.read_text(encoding="utf-8")
                    meta = json.loads(response_meta_path.read_text(encoding="utf-8")) if response_meta_path.exists() else {}
                    print(f"REUSE archived Bedrock candidate for {attempt_dir.relative_to(ROOT)}")
                    if resuming_attempt:
                        append_attempt_event(attempt_dir, "archived_candidate_reused")
                else:
                    if not begin_model_call(attempt_dir, "generation", model_id):
                        result.status = "ambiguous_generation_state"
                        result.notes = "Generation call started but no response/failure record exists; manual adjudication required before any re-sampling"
                        raise RuntimeError(result.notes)
                    try:
                        response_text, meta = self.call_bedrock(prompt_path.read_text(encoding="utf-8"), model_id)
                    except (ClientError, BotoCoreError) as exc:
                        record_model_call_failure(attempt_dir, "generation", exc)
                        raise
                    response_path.write_text(response_text, encoding="utf-8")
                    dump_json(response_meta_path, meta)
                    append_attempt_event(attempt_dir, "generation_call_completed")
                result.input_tokens_generation = meta.get("usage", {}).get("inputTokens")
                result.output_tokens_generation = meta.get("usage", {}).get("outputTokens")

                py_files_existing = list(attempt_dir.glob("cvr2_*.py"))
                js_files_existing = list(attempt_dir.glob("cvr2_*.json"))
                extracted_py, extracted_js = extract_generation_artifacts(response_text)
                py = py_files_existing[0].read_text(encoding="utf-8") if py_files_existing else extracted_py
                js = js_files_existing[0].read_text(encoding="utf-8") if js_files_existing else extracted_js
                if not py or not js:
                    result.status = "technical_rejected"
                    result.notes = "Could not extract both Python and JSON fenced artifacts"
                    dump_json(attempt_dir / "technical_validation.json", {"passed": False, "errors": [result.notes]})
                    previous = None if condition == "chaos_adt_no_feedback" else {"python": py or "", "json": js or ""}
                    trajectory_results.append(result)
                    continue

                py_path = attempt_dir / f"{module_name}.py"
                json_path = attempt_dir / f"{module_name}.json"
                if not py_path.exists():
                    py_path.write_text(py, encoding="utf-8")
                else:
                    py = py_path.read_text(encoding="utf-8")
                if not json_path.exists():
                    js, rewrite_error = self.safe_rewrite_manifest_modules(js, module_name)
                    if rewrite_error:
                        # v6: an unparseable manifest is a technical rejection of the
                        # candidate (technical_validate reports the JSON parse error),
                        # never a campaign halt. The extracted text is kept verbatim.
                        append_attempt_event(attempt_dir, "manifest_unparseable_kept_verbatim", error=rewrite_error)
                    json_path.write_text(js, encoding="utf-8")
                else:
                    js = json_path.read_text(encoding="utf-8")

                validation = self.technical_validate(py, js, prefix, module_name, task, network)
                dump_json(attempt_dir / "technical_validation.json", validation)
                if not validation["passed"]:
                    result.status = "technical_rejected"
                    result.notes = "; ".join(validation["errors"])
                    previous = None if condition == "chaos_adt_no_feedback" else {"python": py, "json": js}
                    trajectory_results.append(result)
                    continue

                qpre_text = ""
                if condition in {"chaos_adt_feedback", "chaos_adt_no_feedback"}:
                    qp = qpre_prompt(task, py, js, self.cfg["thresholds"]["q_pre"])
                    qpre_prompt_path = attempt_dir / "qpre_prompt.txt"
                    qpre_report_path = attempt_dir / "qpre_report.md"
                    qpre_meta_path = attempt_dir / "qpre_response_metadata.json"
                    if not qpre_prompt_path.exists():
                        qpre_prompt_path.write_text(qp, encoding="utf-8")
                    if qpre_report_path.exists():
                        qpre_text = qpre_report_path.read_text(encoding="utf-8")
                        qpre_meta = json.loads(qpre_meta_path.read_text(encoding="utf-8")) if qpre_meta_path.exists() else {}
                    else:
                        if not begin_model_call(attempt_dir, "qpre", model_id):
                            result.status = "ambiguous_qpre_state"
                            result.notes = "Q_pre call started but no response/failure record exists; evaluator will not be re-sampled automatically"
                            raise RuntimeError(result.notes)
                        try:
                            qpre_text, qpre_meta = self.call_bedrock(qpre_prompt_path.read_text(encoding="utf-8"), model_id)
                        except (ClientError, BotoCoreError) as exc:
                            record_model_call_failure(attempt_dir, "qpre", exc)
                            raise
                        qpre_report_path.write_text(qpre_text, encoding="utf-8")
                        dump_json(qpre_meta_path, qpre_meta)
                        append_attempt_event(attempt_dir, "qpre_call_completed")
                    result.input_tokens_qpre = qpre_meta.get("usage", {}).get("inputTokens")
                    result.output_tokens_qpre = qpre_meta.get("usage", {}).get("outputTokens")
                    result.q_pre = score_from_text(qpre_text, "Q_pre")
                    if result.q_pre is None:
                        result.status = "gate_evaluation_error"
                        result.notes = "Stored Q_pre response is not parseable; preserved without re-querying the evaluator"
                        previous = None if condition == "chaos_adt_no_feedback" else {"python": py, "json": js, "qpre": qpre_text}
                        trajectory_results.append(result)
                        continue
                    if result.q_pre < self.cfg["thresholds"]["q_pre"]:
                        result.status = "gate_rejected"
                        previous = None if condition == "chaos_adt_no_feedback" else {"python": py, "json": js, "qpre": qpre_text}
                        trajectory_results.append(result)
                        continue

                execution_log_path = attempt_dir / "execution.log"
                execution_artifacts_path = attempt_dir / "execution_artifacts.json"
                if resuming_attempt and not execution_log_path.exists():
                    stamp = utc_stamp()
                    # Preserve files left by an interrupted Chaos run before the frozen candidate is
                    # executed again in the same directory, so they are not appended to or overwritten.
                    partial = [p for p in attempt_dir.iterdir() if p.is_file() and (
                        p.name == "chaostoolkit.log" or (p.name.startswith("journal") and p.suffix == ".json"))]
                    preserved_dir = None
                    if partial:
                        preserved_dir = attempt_dir / f"interrupted_execution_{stamp}"
                        preserved_dir.mkdir()
                        for p in partial:
                            p.rename(preserved_dir / p.name)
                    cleanup_report_name = f"resume_pre_execution_cleanup_report_{stamp}.json"
                    resume_cleanup = self.cleanup_stacks(prefix, attempt_dir / cleanup_report_name, attempt_dir)
                    append_attempt_event(attempt_dir, "resume_pre_execution_cleanup",
                                         clean=bool(resume_cleanup.get("clean")), report=cleanup_report_name,
                                         preserved_partial_execution_files=[p.name for p in partial],
                                         preserved_to=preserved_dir.name if preserved_dir else None)
                    if not resume_cleanup.get("clean"):
                        result.status = "infrastructure_cleanup_error"
                        result.notes = resume_cleanup.get("error", "Unresolved cleanup before resuming archived candidate")
                        trajectory_results.append(result)
                        raise RuntimeError(f"Cannot safely resume archived candidate for {prefix}: unresolved AWS leftovers")
                if execution_log_path.exists():
                    execution_log = execution_log_path.read_text(encoding="utf-8")
                    artifacts = json.loads(execution_artifacts_path.read_text(encoding="utf-8")) if execution_artifacts_path.exists() else {}
                    journals = artifacts.get("journals", [])
                    timed_out = bool(artifacts.get("timed_out", False))
                    result.chaos_return_code = artifacts.get("return_code")
                    result.chaos_timed_out = timed_out
                    result.executed = True
                    print(f"REUSE archived Chaos execution for {attempt_dir.relative_to(ROOT)}")
                    if resuming_attempt:
                        append_attempt_event(attempt_dir, "archived_execution_reused")
                else:
                    installed = self.install_module(py_path, module_name)
                    dump_json(attempt_dir / "installed_module.json", {"path": str(installed)})
                    result.executed = True
                    append_attempt_event(attempt_dir, "chaos_execution_started")
                    try:
                        rc, execution_log, journals, timed_out = self.run_chaos(json_path, attempt_dir)
                        result.chaos_return_code = rc
                        result.chaos_timed_out = timed_out
                        dump_json(execution_artifacts_path, {"journals": journals, "timed_out": timed_out, "return_code": rc})
                        append_attempt_event(attempt_dir, "chaos_execution_finished", return_code=rc, timed_out=timed_out)
                    finally:
                        try:
                            installed.unlink(missing_ok=True)
                        except Exception:
                            pass

                # v5: a previous cleanup report of this attempt (e.g. an unresolved cleanup that halted the
                # campaign) is preserved under a timestamped name instead of being overwritten on resume.
                cleanup_report_path = attempt_dir / "cleanup_report.json"
                if cleanup_report_path.exists():
                    preserved_report = attempt_dir / f"cleanup_report_superseded_{utc_stamp()}.json"
                    cleanup_report_path.rename(preserved_report)
                    append_attempt_event(attempt_dir, "previous_cleanup_report_preserved", preserved_as=preserved_report.name)
                cleanup = self.cleanup_stacks(prefix, cleanup_report_path, attempt_dir)
                if not cleanup.get("clean"):
                    result.status = "infrastructure_cleanup_error"
                    result.notes = cleanup.get("error", "Unresolved cleanup")
                    trajectory_results.append(result)
                    raise RuntimeError(f"Unresolved cleanup for {prefix}; campaign halted")

                qpp = qpost_prompt(task, execution_log, self.cfg["thresholds"]["q_post"])
                qpost_prompt_path = attempt_dir / "qpost_prompt.txt"
                qpost_report_path = attempt_dir / "qpost_report.md"
                qpost_meta_path = attempt_dir / "qpost_response_metadata.json"
                if not qpost_prompt_path.exists():
                    qpost_prompt_path.write_text(qpp, encoding="utf-8")
                if qpost_report_path.exists():
                    qpost_text = qpost_report_path.read_text(encoding="utf-8")
                    qpost_meta = json.loads(qpost_meta_path.read_text(encoding="utf-8")) if qpost_meta_path.exists() else {}
                else:
                    if not begin_model_call(attempt_dir, "qpost", model_id):
                        result.status = "ambiguous_qpost_state"
                        result.notes = "Q_post call started but no response/failure record exists; evaluator will not be re-sampled automatically"
                        raise RuntimeError(result.notes)
                    try:
                        qpost_text, qpost_meta = self.call_bedrock(qpost_prompt_path.read_text(encoding="utf-8"), model_id)
                    except (ClientError, BotoCoreError) as exc:
                        record_model_call_failure(attempt_dir, "qpost", exc)
                        raise
                    qpost_report_path.write_text(qpost_text, encoding="utf-8")
                    dump_json(qpost_meta_path, qpost_meta)
                    append_attempt_event(attempt_dir, "qpost_call_completed")
                result.input_tokens_qpost = qpost_meta.get("usage", {}).get("inputTokens")
                result.output_tokens_qpost = qpost_meta.get("usage", {}).get("outputTokens")
                result.q_post = score_from_text(qpost_text, "Q_post")
                if result.q_post is None:
                    result.status = "qpost_evaluation_error"
                    result.notes = "Stored Q_post response is not parseable; preserved without re-querying the evaluator"
                    previous = None if condition == "chaos_adt_no_feedback" else {
                        "python": py, "json": js, **({"qpre": qpre_text} if qpre_text else {}),
                        "execution": execution_log, "qpost": qpost_text,
                    }
                    trajectory_results.append(result)
                    continue

                if result.q_post >= self.cfg["thresholds"]["q_post"]:
                    result.status = TERMINAL_QPOST
                    terminal = True
                else:
                    result.status = "qpost_insufficient"

                previous = None if condition == "chaos_adt_no_feedback" else {
                    "python": py, "json": js, **({"qpre": qpre_text} if qpre_text else {}),
                    "execution": execution_log, "qpost": qpost_text,
                }
                trajectory_results.append(result)
                if terminal:
                    break

            except (ClientError, BotoCoreError) as exc:
                result.status = "infrastructure_error"
                result.notes = repr(exc)
                # Latest error kept in this file (now timestamped); the full history of every
                # infrastructure error in this attempt is in attempt_events.jsonl.
                dump_json(attempt_dir / "infrastructure_error.json", {"timestamp": utc_now(), "error": repr(exc)})
                append_attempt_event(attempt_dir, "infrastructure_error", error=repr(exc))
                if not trajectory_results or trajectory_results[-1] is not result:
                    trajectory_results.append(result)
                raise
            except BaseException as exc:
                # Halts (ambiguous state, unresolved cleanup), unexpected exceptions and
                # KeyboardInterrupt are recorded before propagating. Behaviour is unchanged.
                append_attempt_event(attempt_dir, "attempt_halted", status=result.status, error=repr(exc))
                raise
            finally:
                events = read_attempt_events(attempt_dir)
                result.resume_count = sum(e.get("event") == "attempt_resumed" for e in events)
                result.model_call_retries = sum(str(e.get("event", "")).endswith("_call_retry") for e in events)
                result.infrastructure_errors = sum(e.get("event") == "infrastructure_error" for e in events)
                dump_json(attempt_dir / "attempt_status.json", asdict(result))

        dump_json(trajectory / "trajectory_status.json", {
            "completed": True,
            "terminal_qpost_reached": terminal,
            "attempts_used": len([r for r in trajectory_results if r.status in completed_statuses]),
            "results": [asdict(r) for r in trajectory_results],
            "runner_revision": RUNNER_REVISION,
        })
        return trajectory_results

    def collect_results(self) -> List[Dict[str, Any]]:
        rows=[]
        for path in RESULTS_DIR.rglob("attempt_status.json"):
            try: rows.append(json.loads(path.read_text(encoding="utf-8")))
            except Exception: pass
        rows.sort(key=lambda x: (x.get("order",9999), x.get("attempt",9999)))
        return rows

    def write_aggregate_outputs(self) -> None:
        rows = self.collect_results()
        dump_json(RESULTS_JSON, rows)
        fields = list(asdict(AttemptResult(0,0,"","","",0,"")).keys())
        with RESULTS_CSV.open("w", newline="", encoding="utf-8") as f:
            w=csv.DictWriter(f, fieldnames=fields)
            w.writeheader()
            for row in rows: w.writerow({k: row.get(k) for k in fields})

        # One blank adjudication row per generated attempt. This makes the expert-adjudicated
        # "VALID within budget" endpoint independent of the automated Q_post stopping score.
        adjudication_rows=[]
        for row in rows:
            adjudication_rows.append({
                "order": row["order"], "repetition": row["repetition"], "task": row["task"],
                "model": row["model"], "condition": row["condition"], "attempt": row["attempt"],
                "technical_status": row["status"], "q_pre": row.get("q_pre"), "q_post": row.get("q_post"),
                "executed": row.get("executed"),
                "rater1_experiment_outcome": "", "rater2_experiment_outcome": "",
                "adjudicated_experiment_outcome": "", "adjudicated_security_outcome": "", "notes": "",
            })
        adj_fields=list(adjudication_rows[0].keys()) if adjudication_rows else [
            "order","repetition","task","model","condition","attempt","technical_status","q_pre","q_post","executed",
            "rater1_experiment_outcome","rater2_experiment_outcome",
            "adjudicated_experiment_outcome","adjudicated_security_outcome","notes"
        ]
        with ADJUDICATION_CSV.open("w",newline="",encoding="utf-8") as f:
            w=csv.DictWriter(f, fieldnames=adj_fields); w.writeheader(); w.writerows(adjudication_rows)
        self.write_sha256_manifest()

    def write_sha256_manifest(self) -> None:
        lines=[]
        for path in sorted(RESULTS_DIR.rglob("*")):
            if not path.is_file() or path == SHA_FILE: continue
            h=hashlib.sha256()
            with path.open("rb") as f:
                for chunk in iter(lambda:f.read(1024*1024),b""): h.update(chunk)
            lines.append(f"{h.hexdigest()}  {path.relative_to(RESULTS_DIR)}")
        SHA_FILE.write_text("\n".join(lines)+("\n" if lines else ""),encoding="utf-8")

    def run(self) -> None:
        env = self.preflight(invoke_models=True)
        if not env.get("ready_for_run"):
            raise RuntimeError("Preflight is not ready for run; inspect model checks and prepare the fixed campaign infrastructure")
        self.assert_no_campaign_leftovers()
        for row in self.schedule:
            print(f"\n=== {row['order']:02d}/80 | rep={row['repetition']} task={row['task']} model={row['model']} condition={row['condition']} ===")
            try:
                results=self.run_trajectory(row)
                self.all_results.extend(results)
                self.write_aggregate_outputs()
            except Exception:
                self.write_aggregate_outputs()
                raise
        self.write_aggregate_outputs()


def validate_static_files(config_path: Path) -> None:
    cfg=read_yaml(config_path)
    schedule=load_schedule(ROOT/"schedule.csv")
    expected=cfg["repetitions"]*len(cfg["tasks"])*len(cfg["models"])*len(cfg["conditions"])
    if len(schedule)!=expected:
        raise RuntimeError(f"schedule.csv has {len(schedule)} rows; expected {expected}")
    keys={(r["repetition"],r["task"],r["model"],r["condition"]) for r in schedule}
    if len(keys)!=expected:
        raise RuntimeError("schedule.csv contains duplicate/missing experimental cells")
    unknown_models=sorted({r["model"] for r in schedule}-set(cfg["models"]))
    unknown_tasks=sorted({r["task"] for r in schedule}-set(cfg["tasks"]))
    unknown_conditions=sorted({r["condition"] for r in schedule}-set(cfg["conditions"]))
    if unknown_models or unknown_tasks or unknown_conditions:
        raise RuntimeError(f"schedule.csv references unknown values: models={unknown_models}, tasks={unknown_tasks}, conditions={unknown_conditions}")
    for task_id in cfg["tasks"]:
        task=read_yaml(TASK_DIR/f"{task_id}.yaml")
        for field in ["task_id","sce_node","probe_type","attack_nodes","attack","defense","probe"]:
            if field not in task: raise RuntimeError(f"Task {task_id} missing field {field}")
    json.loads(TEMPLATE_PATH.read_text(encoding="utf-8"))
    print(f"Static validation OK: {expected} predetermined trajectories, {cfg['max_attempts']} attempts max each")


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config",type=Path,default=ROOT/"campaign.yaml")
    parser.add_argument("--aws-profile",default=None,help="Local AWS CLI profile name (never committed)")
    parser.add_argument("--preflight",action="store_true",help="Run non-destructive environment/model checks")
    parser.add_argument("--prepare-infrastructure",action="store_true",help="Create/reuse the fixed campaign VPC/subnet/security group")
    parser.add_argument("--cleanup-infrastructure",action="store_true",help="Delete the fixed campaign network stack after the campaign")
    parser.add_argument("--static-check",action="store_true",help="Validate config/tasks/schedule without AWS")
    parser.add_argument("--run",action="store_true",help="Execute the scientific campaign")
    args=parser.parse_args()

    validate_static_files(args.config)
    if args.static_check and not (args.preflight or args.prepare_infrastructure or args.cleanup_infrastructure or args.run):
        return 0
    if not args.aws_profile:
        parser.error("--aws-profile is required for AWS operations")

    runner=CampaignRunner(args.config,args.aws_profile,force=False)
    if args.prepare_infrastructure:
        outputs = runner.prepare_infrastructure()
        print("Fixed campaign infrastructure ready:")
        print(json.dumps(outputs,indent=2))
        return 0
    if args.cleanup_infrastructure:
        runner.cleanup_infrastructure()
        print("Fixed campaign infrastructure deleted (or was already absent).")
        return 0
    if args.preflight and not args.run:
        env=runner.preflight(invoke_models=True)
        for label, check in env.get("model_checks", {}).items():
            if check.get("status") == "OK":
                print(f"[OK]   {label}: {check.get('model_id')}")
            else:
                print(f"[FAIL] {label}: {check.get('model_id')} -> {check.get('error')}")
        for warning in env.get("legacy_resource_warnings", []):
            print(f"[WARN] {warning}")
        if env.get("campaign_network"):
            print("[OK]   fixed campaign network is ready")
        else:
            print("[NEED] fixed campaign network is absent; run --prepare-infrastructure before --run")
        print(json.dumps(env,indent=2,default=str))
        return 0 if env.get("ready_for_run") else 2
    if args.run:
        runner.run(); return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
