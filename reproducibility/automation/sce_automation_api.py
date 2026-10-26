#!/usr/bin/env python3
"""
SCE Automation with Amazon Bedrock API Integration
"""

import json
import os
import sys
import time
import subprocess
from typing import Dict, List, Optional
import yaml
import re

try:
    import boto3
except ImportError:
    subprocess.check_call([sys.executable, "-m", "pip", "install", "boto3"])
    import boto3

from botocore.config import Config

AVAILABLE_MODELS = [
    # Haiku
    "us.anthropic.claude-3-5-haiku-20241022-v1:0",
    "us.anthropic.claude-haiku-4-5-20251001-v1:0",
    # Sonnet
    "us.anthropic.claude-3-5-sonnet-20241022-v2:0",
    "us.anthropic.claude-3-7-sonnet-20250219-v1:0",
    "us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    "us.anthropic.claude-sonnet-4-6",
    # Opus
    "us.anthropic.claude-opus-4-5-20251101-v1:0",
    "us.anthropic.claude-opus-4-6-v1",
]


def _select_model(prompt_label: str) -> str:
    """Present numbered model options and return the selected model ID."""
    print(f"\n🤖 Select model for {prompt_label}:")
    for i, model in enumerate(AVAILABLE_MODELS, 1):
        print(f"  {i}. {model}")
    while True:
        choice = input("> ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(AVAILABLE_MODELS):
            selected = AVAILABLE_MODELS[int(choice) - 1]
            print(f"✅ Selected: {selected}")
            return selected
        print(f"⚠️  Please enter a number between 1 and {len(AVAILABLE_MODELS)}")


class SCEAutomationAPI:
    def __init__(self):
        self.workspace_path = os.path.join(os.getcwd())
        bedrock_config = Config(
            read_timeout=3600,
            connect_timeout=30,
            retries={"max_attempts": 3, "mode": "standard"},
        )
        self.bedrock = boto3.client('bedrock-runtime', config=bedrock_config)
        self.conversation_history = []
        self.tracking_table: List[Dict] = []
        self.model_tree: Optional[str] = None
        self.model_experiment: Optional[str] = None

    # ─────────────────────────────────────────────────────────────────────────
    # Tracking helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _tracking_add(self, experiment: str, loop: int,
                      q_pre: Optional[float], q_post: Optional[float],
                      model: Optional[str] = None) -> None:
        self.tracking_table.append({
            "experiment": experiment,
            "loop":       loop,
            "q_pre":      q_pre,
            "q_post":     q_post,
            "model":      model or "N/A",
        })

    def _tracking_print(self) -> None:
        if not self.tracking_table:
            print("\n📋 No experiments were tracked in this session.")
            return

        col_exp   = max(len(r["experiment"]) for r in self.tracking_table)
        col_exp   = max(col_exp, len("Experimento"))
        col_loop  = max(len(str(r["loop"])) for r in self.tracking_table)
        col_loop  = max(col_loop, len("# Loop"))
        col_pre   = len("Q_pre")
        col_post  = len("Q_post")
        col_model = max(len(r.get("model", "N/A")) for r in self.tracking_table)
        col_model = max(col_model, len("Modelo"))

        sep  = (f"+{'-'*(col_exp+2)}+{'-'*(col_loop+2)}"
                f"+{'-'*(col_pre+2)}+{'-'*(col_post+2)}+{'-'*(col_model+2)}+")
        head = (f"| {'Experimento':<{col_exp}} "
                f"| {'# Loop':>{col_loop}} "
                f"| {'Q_pre':>{col_pre}} "
                f"| {'Q_post':>{col_post}} "
                f"| {'Modelo':<{col_model}} |")

        print("\n" + "="*70)
        print("📋  CUADRO DE SEGUIMIENTO DE EXPERIMENTOS SCE")
        print("="*70)
        print(sep)
        print(head)
        print(sep)
        for r in self.tracking_table:
            q_pre_s  = f"{r['q_pre']:.2f}"  if r["q_pre"]  is not None else "N/A"
            q_post_s = f"{r['q_post']:.2f}" if r["q_post"] is not None else "N/A"
            model_s  = r.get("model", "N/A")
            print(f"| {r['experiment']:<{col_exp}} "
                  f"| {r['loop']:>{col_loop}} "
                  f"| {q_pre_s:>{col_pre}} "
                  f"| {q_post_s:>{col_post}} "
                  f"| {model_s:<{col_model}} |")
        print(sep)
        print()

    def _build_session_block(self) -> str:
        """Build the markdown block for the current session only."""
        session_ts = time.strftime('%Y-%m-%d %H:%M:%S')
        lines = [
            f"### 🗓️ Session: {session_ts}",
            "",
            "| Experimento | # Loop | Q_pre | Q_post | Modelo |",
            "|---|---|---|---|---|",
        ]
        for r in self.tracking_table:
            q_pre_s  = f"{r['q_pre']:.2f}"  if r["q_pre"]  is not None else "N/A"
            q_post_s = f"{r['q_post']:.2f}" if r["q_post"] is not None else "N/A"
            lines.append(
                f"| {r['experiment']} | {r['loop']} | {q_pre_s} "
                f"| {q_post_s} | {r.get('model', 'N/A')} |"
            )
        return "\n".join(lines)

    def _tracking_save_md(self) -> None:
        if not self.tracking_table:
            return

        filepath = os.path.join(self.workspace_path, "tracking_summary.md")
        session_block = self._build_session_block()

        # ── Ask whether to append to an existing file ────────────────────────
        if os.path.exists(filepath):
            print(f"\n📋 Found existing tracking_summary.md.")
            print("   Append this session's results to it? (y/n):")
            choice = input("> ").strip().lower()
            if choice == 'y':
                try:
                    separator = (
                        "\n\n---\n\n"
                        "<!-- ════════════════════ NEW EXECUTION ════════════════════ -->\n\n"
                    )
                    with open(filepath, 'a', encoding='utf-8') as f:
                        f.write(separator + session_block + "\n")
                    print(f"✅ Session appended to: {filepath}")
                except Exception as e:
                    print(f"⚠️ Could not append to tracking summary: {e}")
                return  # done — don't overwrite

        # ── No existing file (or user chose not to append) — write fresh ─────
        header = "\n".join([
            "# SCE Experiment Tracking Summary",
            "",
            "## Legend",
            "- **Q_pre**: Pre-execution quality score (0–100)",
            "- **Q_post**: Post-execution quality score (0–100)",
            "- **Modelo**: Model used to generate the experiment",
            "- **N/A**: Score not available",
            "",
        ])
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(header + session_block + "\n")
            print(f"✅ Tracking summary saved to: {filepath}")
        except Exception as e:
            print(f"⚠️ Could not save tracking summary: {e}")

    # ─────────────────────────────────────────────────────────────────────────
    # Score extraction
    # ─────────────────────────────────────────────────────────────────────────

    def _extract_score(self, text: str, metric: str) -> Optional[float]:
        pattern_full = (
            rf'{re.escape(metric)}\s*='
            r'(?:[^=\n]+=\s*)'
            r'(\d{1,3}(?:\.\d+)?)'
        )
        m = re.search(pattern_full, text, re.IGNORECASE)
        if m:
            v = float(m.group(1))
            if 0 <= v <= 100:
                return v

        pattern_bold = rf'\*\*\s*{re.escape(metric)}\s*=\s*(\d{{1,3}}(?:\.\d+)?)\s*\*\*'
        m = re.search(pattern_bold, text, re.IGNORECASE)
        if m:
            v = float(m.group(1))
            if 0 <= v <= 100:
                return v

        pattern_simple = rf'{re.escape(metric)}\s*=\s*(\d{{1,3}}(?:\.\d+)?)'
        for m in re.finditer(pattern_simple, text, re.IGNORECASE):
            v = float(m.group(1))
            if 1 <= v <= 100:
                return v

        lines = text.splitlines()
        for i, line in enumerate(lines):
            if re.search(rf'\b{re.escape(metric)}\b', line, re.IGNORECASE):
                for candidate in lines[i:i+3]:
                    nums = re.findall(r'\b(\d{1,3}(?:\.\d+)?)\b', candidate)
                    for n in nums:
                        v = float(n)
                        if 1 <= v <= 100:
                            return v
        return None

    # ─────────────────────────────────────────────────────────────────────────

    def _sanitize_name(self, name: str) -> str:
        return re.sub(r'[^\w\-_]', '_', name.lower()).strip('_')

    def _load_yaml(self, yaml_path: str) -> Dict:
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                self.yaml = yaml.safe_load(f)
                return self.yaml
        except Exception as e:
            print(f"❌ Error loading yaml file: {e}")
            return None  # type: ignore

    def _load_file(self, template_path: str) -> str:
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"❌ Error loading file {template_path}: {e}")
            return None  # type: ignore

    def _extract_yaml_from_response(self, response_text: str) -> bool:
        try:
            yaml_start = response_text.find("attack:")
            if yaml_start == -1:
                return False
            yaml_content = response_text[yaml_start:]
            lines = yaml_content.split('\n')
            yaml_lines = []
            for line in lines:
                stripped = line.strip()
                if (stripped and not line.startswith((' ', '\t')) and ':' not in line and
                        not stripped.startswith(('-', 'attack', 'steps', 'stride_goal'))):
                    break
                yaml_lines.append(line)
            clean_yaml = '\n'.join(yaml_lines).strip()
            filepath = os.path.join(self.workspace_path, "attacks.yaml")
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(clean_yaml)
            return True
        except Exception as e:
            print(f"❌ Save error: {e}")
            return False  # type: ignore

    def _build_mission_prompt(self) -> str:
        if not self.yaml:
            return None  # type: ignore
        config = self.yaml
        overview = "\n".join([f"- {desc}" for desc in config['mission_overview']['description']])
        threats = "\n".join([
            f"- {threat['name']}: {threat['description']}"
            for threat in config['primary_threat_categories']
        ])
        technologies = "\n".join([
            f"- {tech['name']}: {tech['purpose']}"
            for tech in config['core_technologies']
        ])
        safeguards = "\n".join([
            f"{i+1}. **{safeguard['name']}**: {safeguard['description']}"
            for i, safeguard in enumerate(config['safeguard_logic'])
        ])
        return f"""Analyze the following scenario from mission configuration:

**Mission Overview**
{overview}

**Primary Threat Categories**
{threats}

**Core Technologies**
{technologies}

**Safeguard Logic**
{safeguards}

"""

    def _build_attack_prompt(self, threat_intelligence: str) -> str:
        if not hasattr(self, 'attack_template'):
            return None  # type: ignore
        return f"""Please populate the template using it strictly as a schema, not as content. Complete every applicable field in the template with information specific to the following attack:
            THREAT INTELLIGENCE:
            {threat_intelligence}

            TEMPLATE TO POPULATE:
            {self.attack_template}

            Instructions:
            - Preserve the structure, section order, and field names exactly as they appear in the template.
            - Replace all placeholder or example text with concrete details for this attack only
            - If a field is not applicable or the information is unavailable, leave the field present and explicitly mark it as N/A rather than deleting it.
            - Use clear, concise, technically accurate language suitable for threat modeling and repeatable testing.

            Return the completed content in yaml format, ready to be stored as an attack record."""

    def _build_attack_defense_tree_prompt(self, attacks_yaml: str, structure_dot: str) -> str:
        return f"""Imagine you are a lead cyber-defense analyst tasked with turning raw intelligence into actionable insight for senior leadership and incident-response teams. Under this premise:

    - Start from the detailed scenario and safeguard logic classes (Preventive, Detective, Reactive) you have already defined and stored.
    - Scrutinize the attacks described in the attached file @attacks.yaml.
    - Consider, integrate, and visualize possible countermeasures for that scenario using the previously defined safeguard logic.
    - Follow the hierarchy, connectors and colors defined in the attached file @structure.dot as your base template.

    Your assignment is to:

    1. Build the attack-defense tree
    - Construct an attack-defense tree that, from root to attack goal, explicitly shows every command, dependency, result and TTP from @attacks.yaml
    - Adapt each attack to the specifics of the described scenario (mission, tech stack, environment), while preserving the original steps and intent

    2. Map each attack step to safeguard logic
    - For every attack step, map zero or more safeguards using the three pre-defined safeguard logic classes (Preventive, Detective, Reactive)
    - It is acceptable for an attack step to have no safeguard if none is relevant; explicitly modeling "no action taken" is allowed and may itself be considered a countermeasure choice.
    - For each mapped safeguard, clearly indicate whether it Prevents, Detects, or Reacts according to the definitions above.

    3. Add a chaos node for each attack step (Security Chaos Engineering)
    - Preventive probe: How the countermeasure is expected to block the action.
    - Detective probe: How the countermeasure is expected to detect the action.
    - Reactive probe: How the countermeasure is expected to respond.

    4. Produce the final DOT representation
    - Label each node has a unique identifier using hierarchical numbering.
    - Output the final result in DOT format, ready for rendering, using the hierarchy, connectors, and color conventions defined in @structure.dot.
    - Generate a Graphviz DOT graph using HTML-like labels (label=<...>). For any character that should appear as literal text inside the label, always escape &, <, >, and " as &amp;, &lt;, &gt;, and &quot;. Ensure each HTML-like label is a single, well-formed block with balanced HTML tags and no extra > characters outside the opening label=< and the closing > of the label. Validate the opening and closing tags inside each label before returning the code.

    @attacks.yaml:
    {attacks_yaml}

    @structure.dot:
    {structure_dot}
    """

    def _build_sce_experiment_prompt(self, sce_node: str, probe_type: str, attack_nodes: str,
                                     template_json: str,
                                     previous_log: Optional[str] = None,
                                     previous_metrics_report: Optional[str] = None,
                                     previous_post_metrics_report: Optional[str] = None) -> str:
        log_context = ""
        if previous_log:
            log_context = f"""
PREVIOUS EXECUTION LOG:
The following log contains information from a previous execution of this experiment. Use this information to:
- Fix any errors or issues that occurred
- Improve the implementation based on lessons learned
- Adjust timeouts, retries, or resource configurations
- Enhance error handling and edge cases

{previous_log}

"""
        metrics_context = ""
        if previous_metrics_report:
            metrics_context = f"""
PREVIOUS PRE-EXECUTION METRICS REPORT:
The following report contains a quality evaluation from a previous iteration of this experiment. Use this information to:
- Address any quality issues identified (low f1, f2, or f3 scores)
- Improve correspondence between ADT specification and implementation
- Enhance code quality, documentation, and error handling
- Ensure the implementation fully matches the defensive intent

{previous_metrics_report}

"""
        post_metrics_context = ""
        if previous_post_metrics_report:
            post_metrics_context = f"""
PREVIOUS POST-EXECUTION METRICS REPORT:
The following report contains a post-execution quality evaluation from a previous run of this experiment. Use this information to:
- Improve ACTION effectiveness and observability (if f1 score was low)
- Enhance PROBE verification and evidence collection (if f2 score was low)
- Ensure both ACTION and PROBE produce verifiable results
- Add better logging, metrics, and observability to the experiment

{previous_post_metrics_report}

"""
        return f"""Input:

- SCE Experiment node: {sce_node}
- Type of probe: {probe_type}
- Attack Node/s: {attack_nodes}
{log_context}{metrics_context}{post_metrics_context}
Goal: Generate an end-to-end Security Chaos Engineering unit test that validates exactly this one probe, by:
- Translating each associated attack step into real, scoped AWS API calls against only the resources created by the experiment
- Implementing the probe's security intent (Preventive / Detective / Reactive) as an AWS-native control
- Verifying programmatically that this control behaves as described in the probe's label and classification

Environment:
- The script runs authenticated against a REAL dedicated AWS test account
- Active credentials are already configured via the default credential chain (~/.aws/credentials)
- The account is isolated and intended exclusively for security chaos experiments — it is safe to create, modify, and delete real AWS resources
- There are no pre-existing IAM roles, policies, buckets, parameters, alarms, etc.

CRITICAL EXECUTION REQUIREMENTS — non-negotiable:
- Every boto3 call MUST be a real API call against the live AWS account; do NOT simulate, mock, print-only, or stub any AWS interaction
- Do NOT use placeholder values such as "your-account-id", "your-region", "SIMULATED", or "TODO"
- attack() MUST actually execute the attack action and capture a real AWS API response as evidence (ARN, resource ID, HTTP status, etc.)
- hypothesis_verification() MUST query real AWS resources (CloudWatch, Config, IAM, S3, etc.) and derive its True/False result exclusively from actual API responses — a hardcoded return value is INVALID
- Any function that returns a result without having made at least one real AWS API call is INVALID and will be rejected

Deliverables (return two artifacts):
Produce exactly two files, in this order:
1. Python script implementing the experiment logic
2. JSON experiment manifest for the chaostoolkit runner, following the structure of @template.json:
    - Replace [SCE_NODE] with: {self._sanitize_name(sce_node)}
    - Replace [PROBE_TYPE] with: {self._sanitize_name(probe_type)}
    - Keep "chaosaws.ec2" prefix fixed in all module paths
    - DO NOT include a "secrets" section — credentials are discovered automatically

Script structure (must follow this exact flow):
Self-contained: no CLI arguments, no external config files. Use only the standard library unless unavoidable; install boto3 at runtime if needed. Implement bounded retries/backoff with time.monotonic() for eventual consistency. Log every error encountered.

1. steady_state()
- Generate a unique timestamp suffix with int(time.time()) for the stack name (e.g. "sce-experiment-1703123456")
- Deploy a CloudFormation stack that provisions only the AWS resources required for this attack step
- Handle pre-existing stacks gracefully (log warning and continue)
- Wait for CREATE_COMPLETE before proceeding; use retries/backoff
- Tag the stack and all resources with the experiment name and timestamp

2. attack() -> bool
- Execute each attack step against resources created in steady_state() — real API calls only
- Return True if the attack was carried out and produced verifiable AWS-side evidence, False otherwise

3. hypothesis_verification() -> bool
- Query real AWS resources to determine whether the control worked as expected
- Return True only if the API responses confirm the expected defensive behavior
- Return False (never raise) if the control did not behave as expected or evidence is missing

4. rollback()
- Delete the CloudFormation stack by its timestamped name and wait for DELETE_COMPLETE
- Tolerate "stack does not exist" errors gracefully
- Always attempt rollback even if earlier phases failed (use try/finally)

@template.json (update the placeholders):
{template_json}
"""

    def _build_metrics_prompt(self, dot_content: str, json_content: str, py_content: str,
                               sce_node: str, probe_type: str, attack_nodes: str,
                               threshold: int = 80) -> str:
        return f"""# PRE-EXECUTION QUALITY EVALUATION

You are tasked with evaluating the quality of a Security Chaos Engineering (SCE) experiment BEFORE execution.

## EXPERIMENT CONTEXT
- **SCE Node**: {sce_node}
- **Probe Type**: {probe_type}
- **Attack Nodes**: {attack_nodes}

## INPUT ARTIFACTS

### 1. ATTACK-DEFENSE TREE (ADT) - DOT FILE:
```dot
{dot_content}
```

### 2. EXPERIMENT MANIFEST - JSON FILE:
```json
{json_content}
```

### 3. EXPERIMENT IMPLEMENTATION - PYTHON FILE:
```python
{py_content}
```

## EVALUATION TASK

Evaluate the correspondence between the ADT specification and the SCE experiment implementation using three quality factors:

### **Factor 1 (f1): ACTION ↔ Attack Correspondence**
- **0 points**: No correspondence
- **50 points**: Partial alignment - same tactic but different technique
- **100 points**: Full correspondence (same tactic AND technique, high implementation quality)

### **Factor 2 (f2): Defense ↔ Defense Correspondence**
- **0 points**: No correspondence
- **50 points**: Corresponds to the defense node in ADT
- **100 points**: Full correspondence plus high-quality code

### **Factor 3 (f3): PROBE ↔ Defensive Intent Correspondence**
- **0 points**: PROBE does not correspond to defensive intent
- **100 points**: PROBE fully corresponds to defensive intent

## COMPUTATION

**Q_pre = 0.40 × f1 + 0.30 × f2 + 0.30 × f3**

**Execution Threshold**: τ = {threshold}
- If Q_pre < {threshold} → **STOP**
- If Q_pre ≥ {threshold} → **AUTHORIZE**

## OUTPUT FORMAT

IMPORTANT: In the FINAL SCORE CALCULATION section you MUST write the result on its own line
in exactly this format (replace XX.XX with the actual number):
Q_pre = XX.XX

```markdown
# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: {sce_node}
- **Probe Type**: {probe_type}
- **Attack Nodes**: {attack_nodes}
- **Evaluation Date**: [Current timestamp]

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: [0 | 50 | 100]
**Justification**: [Detailed explanation]

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: [0 | 50 | 100]
**Justification**: [Detailed explanation]

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: [0 | 100]
**Justification**: [Detailed explanation]

---

## FINAL SCORE CALCULATION

**Q_pre = 0.40 × [f1] + 0.30 × [f2] + 0.30 × [f3]**
Q_pre = XX.XX

**Threshold**: {threshold}
**Result**: Q_pre [>=|<] {threshold}

## DECISION

**[AUTHORIZE EXECUTION | STOP - QUALITY INSUFFICIENT]**

[If STOP, provide specific recommendations for improvement]

---

## Recommendations

[Specific suggestions to improve scores if Q_pre < {threshold}]
```
"""

    def _build_metrics_post_prompt(self, output_log: str, sce_node: str, probe_type: str,
                                   attack_nodes: str, threshold_post: int = 100) -> str:
        return f"""# POST-EXECUTION QUALITY EVALUATION

You are an **expert in experimental cybersecurity**, specialized in **attack-defense trees** and in the evaluation of **Security Chaos Engineering (SCE)** experiments.

## EXPERIMENT CONTEXT
- **SCE Node**: {sce_node}
- **Probe Type**: {probe_type}
- **Attack Nodes**: {attack_nodes}

## EXECUTION OUTPUT LOG

```
{output_log}
```

## EVALUATION TASK

### **Factor 1 (f1): Effectiveness of the ACTION**
- **0 points**: ACTION did not return verifiable evidence of execution
- **100 points**: ACTION returned verifiable evidence of attack execution

### **Factor 2 (f2): PROBE Capability**
- **0 points**: PROBE did not return a verifiable result
- **100 points**: PROBE returned verifiable evidence of defense behavior

## COMPUTATION

**Q_post = 0.50 × f1 + 0.50 × f2**

**Threshold**: τ_post = {threshold_post}
- If Q_post < {threshold_post} → **INVALID**
- If Q_post ≥ {threshold_post} → **VALID**

## OUTPUT FORMAT

IMPORTANT: In the FINAL SCORE CALCULATION section you MUST write the result on its own line
in exactly this format (replace XX.XX with the actual number):
Q_post = XX.XX

```markdown
# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: {sce_node}
- **Probe Type**: {probe_type}
- **Attack Nodes**: {attack_nodes}
- **Evaluation Date**: [Current timestamp]

## Factor 1: Effectiveness of the ACTION
**Score**: [0 | 100]
**Log Excerpts**: [Relevant excerpts]
**Justification**: [Detailed explanation]

---

## Factor 2: PROBE Capability
**Score**: [0 | 100]
**Log Excerpts**: [Relevant excerpts]
**Justification**: [Detailed explanation]

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × [f1] + 0.50 × [f2]**
Q_post = XX.XX

**Threshold**: {threshold_post}
**Result**: Q_post [>=|<] {threshold_post}

## DECISION

**[VALID EXECUTION | INVALID EXECUTION]**

---

## Recommendations

[Suggestions for improving experiment execution or observability if Q_post < threshold]
```
"""

    def _save_sce_experiment_output(self, response_text: str, sce_node: str, probe_type: str) -> bool:
        try:
            safe_sce_node   = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)

            experiments_dir   = os.path.join(self.workspace_path, "experiments")
            experiment_subdir = os.path.join(experiments_dir, f"{safe_sce_node}_{safe_probe_type}")
            os.makedirs(experiment_subdir, exist_ok=True)

            # ── Python block — tolerant search ───────────────────────────────
            python_content = None
            for py_tag in ["```python", "```Python", "```py"]:
                idx = response_text.find(py_tag)
                if idx != -1:
                    start = idx + len(py_tag)
                    end   = response_text.find("```", start)
                    if end != -1:
                        python_content = response_text[start:end].strip()
                        break

            if python_content:
                python_filename = f"{safe_sce_node}_{safe_probe_type}.py"
                python_filepath = os.path.join(experiment_subdir, python_filename)
                with open(python_filepath, 'w', encoding='utf-8') as f:
                    f.write(python_content)
                print(f"✅ Python script saved to: {python_filepath}")

                try:
                    import chaosaws.ec2
                    chaosaws_path     = chaosaws.ec2.__path__[0]
                    chaosaws_filepath = os.path.join(chaosaws_path, python_filename)
                    with open(chaosaws_filepath, 'w', encoding='utf-8') as f:
                        f.write(python_content)
                    print(f"✅ Python script copied to chaosaws: {chaosaws_filepath}")
                except ImportError:
                    print("⚠️ chaosaws.ec2 not found, skipping copy to chaosaws directory")
                except Exception as e:
                    print(f"⚠️ Could not copy to chaosaws directory: {e}")
            else:
                print("⚠️  No se encontró bloque ```python en la respuesta del modelo")

            # ── JSON block — tolerant search ─────────────────────────────────
            json_content = None
            for json_tag in ["```json", "```JSON"]:
                idx = response_text.find(json_tag)
                if idx != -1:
                    start = idx + len(json_tag)
                    end   = response_text.find("```", start)
                    if end != -1:
                        json_content = response_text[start:end].strip()
                        break

            if json_content:
                json_filepath = os.path.join(experiment_subdir,
                                             f"{safe_sce_node}_{safe_probe_type}.json")
                with open(json_filepath, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                print(f"✅ JSON manifest saved to: {json_filepath}")
                return True

            # ── Neither block found — save raw response for diagnosis ─────────
            print("⚠️  No se encontró bloque ```json en la respuesta del modelo")
            raw_path = os.path.join(experiment_subdir,
                                    f"{safe_sce_node}_{safe_probe_type}_raw_response.txt")
            with open(raw_path, 'w', encoding='utf-8') as f:
                f.write(response_text)
            print(f"📄 Respuesta cruda guardada en: {raw_path}")
            print("   Revisa ese archivo para ver qué devolvió el modelo.")
            return False

        except Exception as e:
            print(f"❌ Error saving SCE experiment files: {e}")
            return False

    def _save_metrics_report(self, response_text: str, sce_node: str, probe_type: str):
        try:
            safe_sce_node   = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)

            report_subdir = os.path.join(self.workspace_path, "reports",
                                         f"{safe_sce_node}_{safe_probe_type}")
            os.makedirs(report_subdir, exist_ok=True)

            report_start = response_text.find("```markdown")
            if report_start != -1:
                report_start += 11
                report_end   = response_text.find("```", report_start)
                report_content = (response_text[report_start:report_end].strip()
                                  if report_end != -1 else response_text[report_start:].strip())
            else:
                idx = response_text.find("# PRE-EXECUTION QUALITY EVALUATION REPORT")
                report_content = (response_text[idx:].strip()
                                  if idx != -1 else response_text.strip())

            report_filepath = os.path.join(report_subdir,
                                           f"pre_execution_report_{safe_sce_node}_{safe_probe_type}.md")
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"✅ Pre-execution report saved to: {report_filepath}")

            q_pre_score = self._extract_score(response_text, "Q_pre")
            if q_pre_score is None:
                q_pre_score = self._extract_score(report_content, "Q_pre")

            if q_pre_score is not None:
                print(f"📊 Quality Score (Q_pre): {q_pre_score:.2f}/100")
            else:
                print("⚠️ Could not extract Q_pre score from report")

            decision_match = re.search(
                r'\*\*\[(AUTHORIZE EXECUTION|STOP[^\]]*)\]\*\*', report_content)
            if decision_match:
                decision = decision_match.group(1)
                if "AUTHORIZE" in decision:
                    print(f"✅ Decision: {decision}")
                else:
                    print(f"⚠️ Decision: {decision}")
                    print("   Experiment quality below threshold. Review report for recommendations.")

            return True, q_pre_score
        except Exception as e:
            print(f"❌ Error saving metrics report: {e}")
            return False, None

    def _save_metrics_post_report(self, response_text: str, sce_node: str, probe_type: str):
        try:
            safe_sce_node   = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)

            report_subdir = os.path.join(self.workspace_path, "reports",
                                         f"{safe_sce_node}_{safe_probe_type}")
            os.makedirs(report_subdir, exist_ok=True)

            report_start = response_text.find("```markdown")
            if report_start != -1:
                report_start += 11
                report_end   = response_text.find("```", report_start)
                report_content = (response_text[report_start:report_end].strip()
                                  if report_end != -1 else response_text[report_start:].strip())
            else:
                idx = response_text.find("# POST-EXECUTION QUALITY EVALUATION REPORT")
                report_content = (response_text[idx:].strip()
                                  if idx != -1 else response_text.strip())

            report_filepath = os.path.join(report_subdir,
                                           f"post_execution_report_{safe_sce_node}_{safe_probe_type}.md")
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"✅ Post-execution report saved to: {report_filepath}")

            q_post_score = self._extract_score(response_text, "Q_post")
            if q_post_score is None:
                q_post_score = self._extract_score(report_content, "Q_post")

            if q_post_score is not None:
                print(f"📊 Post-Execution Quality Score (Q_post): {q_post_score:.2f}/100")
            else:
                print("⚠️ Could not extract Q_post score from report")

            decision_match = re.search(
                r'\*\*\[(VALID EXECUTION|INVALID EXECUTION)\]\*\*', report_content)
            if decision_match:
                decision = decision_match.group(1)
                if "VALID" in decision and "INVALID" not in decision:
                    print(f"✅ Decision: {decision}")
                else:
                    print(f"⚠️ Decision: {decision}")
                    print("   Experiment execution results not reliable. Review report for details.")

            return True, q_post_score
        except Exception as e:
            print(f"❌ Error saving post-execution metrics report: {e}")
            return False, None

    def _save_dot_output(self, response_text: str) -> bool:
        try:
            dot_start = response_text.find("```dot")
            if dot_start == -1:
                dot_start = response_text.find("digraph")
            else:
                dot_start += 6

            dot_end = response_text.find("```", dot_start)
            if dot_end == -1:
                dot_end = len(response_text)

            if dot_start != -1:
                dot_content = response_text[dot_start:dot_end].strip()
                filepath = os.path.join(self.workspace_path, "attack_defense_tree.dot")
                with open(filepath, 'w', encoding='utf-8') as f:
                    f.write(dot_content)
                print(f"✅ DOT file saved to: {filepath}")
                return True
            else:
                print("❌ No DOT content found in response")
                return False
        except Exception as e:
            print(f"❌ Error saving DOT file: {e}")
            return False

    def _call_amazon_q(self, prompt: str, use_context: bool = True,
                       model_id: Optional[str] = None) -> str:
        try:
            if use_context and self.conversation_history:
                context = "\n\n".join([
                    f"Previous: {item['prompt']}\nResponse: {item['response']}"
                    for item in self.conversation_history
                ])
                full_prompt = f"{context}\n\nCurrent: {prompt}"
            else:
                full_prompt = prompt

            effective_model = model_id or self.model_experiment or AVAILABLE_MODELS[0]

            response = self.bedrock.converse(
                modelId=effective_model,
                messages=[{
                    "role": "user",
                    "content": [{"text": full_prompt}]
                }],
                inferenceConfig={
                    "maxTokens": 8192,
                    "temperature": 1,
                },
            )

            print(f"Input tokens: {response['usage']['inputTokens']}")
            response_text = response["output"]["message"]["content"][0]["text"]

            if use_context:
                self.conversation_history.append({
                    'prompt': prompt,
                    'response': response_text
                })

            return response_text

        except Exception as e:
            print(f"❌ API Error: {e}")
            return None  # type: ignore

    # ─────────────────────────────────────────────────────────────────────────
    # Main orchestrator
    # ─────────────────────────────────────────────────────────────────────────

    def run_automated_conversation(self, start_mode: str,
                                   existing_dot: Optional[str] = None,
                                   mission_yaml: Optional[str] = None,
                                   threat_intelligence: Optional[str] = None,
                                   attack_yaml: Optional[str] = None,
                                   structure_dot: Optional[str] = None):
        """
        start_mode:
          'full'     — stages 1-2-3 (build tree from scratch) then experiments
          'from_dot' — skip stages 1-2-3, load existing .dot, go straight to experiments
        """
        print("🚀 Starting Automated SCE Conversation")

        # ── Model selection ──────────────────────────────────────────────────
        if start_mode == 'full':
            self.model_tree       = _select_model("Attack-Defense Tree generation")
            self.model_experiment = _select_model("SCE Experiment generation")
        else:
            # Tree model only needed if a rebuild is triggered later via regen option
            print("\n💡 Starting from existing .dot — tree model only needed if you later "
                  "choose to rebuild the tree.")
            self.model_tree       = _select_model("Attack-Defense Tree (rebuild only)")
            self.model_experiment = _select_model("SCE Experiment generation")

        print(f"\n📌 Tree model      : {self.model_tree}")
        print(f"📌 Experiment model: {self.model_experiment}")

        # ── Stage 3 helper ───────────────────────────────────────────────────
        def run_stage3() -> bool:
            if not structure_dot:
                print("❌ structure.dot path not available — cannot rebuild tree")
                return False
            print(f"\n🌳 Stage 3: Building attack-defense tree...")
            attacks_yaml_path    = os.path.join(self.workspace_path, "attacks.yaml")
            attacks_yaml_content = self._load_file(attacks_yaml_path)
            if not attacks_yaml_content:
                print("❌ Failed to load attacks.yaml file")
                return False
            structure_dot_content = self._load_file(structure_dot)
            if not structure_dot_content:
                print("❌ Failed to load structure.dot file")
                return False
            tree_prompt     = self._build_attack_defense_tree_prompt(attacks_yaml_content,
                                                                     structure_dot_content)
            stage3_response = self._call_amazon_q(tree_prompt, use_context=True,
                                                  model_id=self.model_tree)
            if not stage3_response:
                print("❌ Failed to generate attack-defense tree")
                return False
            if not self._save_dot_output(stage3_response):
                print("❌ Failed to save DOT output")
                return False
            print("✅ Attack-defense tree generated and saved as DOT file")
            return True

        # ── Entry point branching ────────────────────────────────────────────
        if start_mode == 'from_dot':
            dest_dot    = os.path.join(self.workspace_path, "attack_defense_tree.dot")
            dot_content = self._load_file(existing_dot)
            if not dot_content:
                print(f"❌ Could not load existing .dot file: {existing_dot}")
                return
            # Only copy if source and dest differ
            if os.path.abspath(existing_dot) != os.path.abspath(dest_dot):
                with open(dest_dot, 'w', encoding='utf-8') as f:
                    f.write(dot_content)
            print(f"✅ Loaded existing ADT from: {existing_dot}")
            print("   Skipping Stages 1-2-3 (mission analysis, attack YAML, tree generation)")

        else:
            # full mode — stages 1, 2, 3
            print(f"\n📁 Loading mission configuration from {mission_yaml}...")
            if not self._load_yaml(mission_yaml):
                print("❌ Failed to load mission configuration")
                return

            print("📋 Stage 1: Analyzing mission from YAML configuration...")
            mission_prompt = self._build_mission_prompt()
            if not mission_prompt:
                print("❌ Failed to build mission prompt")
                return

            stage1_response = self._call_amazon_q(mission_prompt, use_context=True,
                                                  model_id=self.model_tree)
            if not stage1_response:
                print("❌ Failed to get mission analysis")
                return
            print("✅ Mission analysis completed")

            print(f"\n📁 Loading attack template from {attack_yaml}...")
            self.attack_template = self._load_yaml(attack_yaml)
            if not self.attack_template:
                print("❌ Failed to load attack template")
                return

            print("🎯 Stage 2: Generating attack YAML from threat intelligence...")
            attack_prompt = self._build_attack_prompt(threat_intelligence)
            if not attack_prompt:
                print("❌ Failed to build attack prompt")
                return

            stage2_response = self._call_amazon_q(attack_prompt, False, model_id=self.model_tree)
            if not stage2_response:
                print("❌ Failed to generate attack content")
                return

            if not self._extract_yaml_from_response(stage2_response):
                print("❌ Failed to save attack file")
                return
            print("✅ Attack YAML generated and saved")

            if not run_stage3():
                return

        # ── Quality thresholds ───────────────────────────────────────────────
        print("\n📊 Enter quality threshold for pre-execution metrics (0-100, default=80):")
        threshold_input = input("> ").strip()
        try:
            quality_threshold = int(threshold_input) if threshold_input else 80
            quality_threshold = quality_threshold if 0 <= quality_threshold <= 100 else 80
        except ValueError:
            quality_threshold = 80
        print(f"✅ Pre-execution quality threshold: {quality_threshold}")

        print("\n📊 Enter quality threshold for post-execution metrics (0-100, default=100):")
        threshold_post_input = input("> ").strip()
        try:
            quality_threshold_post = int(threshold_post_input) if threshold_post_input else 100
            quality_threshold_post = (quality_threshold_post
                                      if 0 <= quality_threshold_post <= 100 else 100)
        except ValueError:
            quality_threshold_post = 100
        print(f"✅ Post-execution quality threshold: {quality_threshold_post}")

        # ── Experiment loop ──────────────────────────────────────────────────
        current_sce_node      : Optional[str] = None
        current_probe_type    : Optional[str] = None
        current_attack_nodes  : Optional[str] = None
        current_template_json : Optional[str] = None
        same_experiment       : bool           = False

        while True:
            loop_number = len(self.tracking_table) + 1
            print(f"\n{'─'*60}")
            print(f"🔁 Loop #{loop_number}")
            print(f"{'─'*60}")

            print("\n🧪 Stage 4: Generating SCE experiments...")

            if not same_experiment:
                print("\n🧪 Enter SCE Node name:")
                current_sce_node = input("> ")
                print("\n🔍 Enter Probe Type (Preventive/Detective/Reactive):")
                current_probe_type = input("> ")
                print("\n🎯 Enter Attack Nodes:")
                current_attack_nodes = input("> ")
                print("\n📋 Enter Template JSON filename:")
                current_template_json = input("> ")
            else:
                print(f"\n🔁 Regenerating same experiment:")
                print(f"   SCE Node    : {current_sce_node}")
                print(f"   Probe Type  : {current_probe_type}")
                print(f"   Attack Nodes: {current_attack_nodes}")
                print(f"   Template    : {current_template_json}")

            same_experiment = False

            sce_node      = current_sce_node
            probe_type    = current_probe_type
            attack_nodes  = current_attack_nodes
            template_json = current_template_json

            template_json_content = self._load_file(template_json)
            if not template_json_content:
                print("❌ Failed to load template.json")
                experiment_name = (f"{self._sanitize_name(sce_node)}_"
                                   f"{self._sanitize_name(probe_type)}")
                self._tracking_add(experiment_name, loop_number, None, None, self.model_experiment)
                continue

            safe_sce_node   = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)
            experiment_name = f"{safe_sce_node}_{safe_probe_type}"

            experiment_subdir        = os.path.join(self.workspace_path, "experiments", experiment_name)
            report_subdir            = os.path.join(self.workspace_path, "reports", experiment_name)
            log_path                 = os.path.join(experiment_subdir, f"output_{experiment_name}.log")
            metrics_report_path      = os.path.join(report_subdir, f"pre_execution_report_{experiment_name}.md")
            post_metrics_report_path = os.path.join(report_subdir, f"post_execution_report_{experiment_name}.md")

            previous_log = None
            if os.path.exists(log_path):
                print(f"\n📝 Found existing execution log: output_{experiment_name}.log")
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        previous_log = f.read()
                    print(f"✅ Loaded previous execution log ({len(previous_log)} chars)")
                except Exception as e:
                    print(f"⚠️ Could not read log file: {e}")
            else:
                print("\n💡 No previous execution log found")

            previous_metrics_report = None
            if os.path.exists(metrics_report_path):
                print("📊 Found existing pre-metrics report")
                try:
                    with open(metrics_report_path, 'r', encoding='utf-8') as f:
                        previous_metrics_report = f.read()
                    print(f"✅ Loaded previous pre-metrics report ({len(previous_metrics_report)} chars)")
                except Exception as e:
                    print(f"⚠️ Could not read metrics report: {e}")
            else:
                print("💡 No previous pre-metrics report found")

            previous_post_metrics_report = None
            if os.path.exists(post_metrics_report_path):
                print("📊 Found existing post-metrics report")
                try:
                    with open(post_metrics_report_path, 'r', encoding='utf-8') as f:
                        previous_post_metrics_report = f.read()
                    print(f"✅ Loaded previous post-metrics report ({len(previous_post_metrics_report)} chars)")
                except Exception as e:
                    print(f"⚠️ Could not read post-metrics report: {e}")
            else:
                print("💡 No previous post-metrics report found")

            if not any([previous_log, previous_metrics_report, previous_post_metrics_report]):
                print("   Generating experiment from scratch.")

            sce_prompt = self._build_sce_experiment_prompt(
                sce_node, probe_type, attack_nodes, template_json_content,
                previous_log, previous_metrics_report, previous_post_metrics_report
            )
            sce_response = self._call_amazon_q(sce_prompt, use_context=False,
                                               model_id=self.model_experiment)
            if not sce_response:
                print("❌ Failed to generate SCE experiment")
                self._tracking_add(experiment_name, loop_number, None, None, self.model_experiment)
                continue

            if not self._save_sce_experiment_output(sce_response, sce_node, probe_type):
                print("❌ Failed to save SCE experiment files")
                self._tracking_add(experiment_name, loop_number, None, None, self.model_experiment)
                continue
            print("✅ SCE experiment generated and saved")

            print("\n📊 Evaluating pre-execution quality metrics...")
            dot_filepath  = os.path.join(self.workspace_path, "attack_defense_tree.dot")
            dot_content   = self._load_file(dot_filepath) or "# DOT file not available"
            json_filepath = os.path.join(experiment_subdir, f"{experiment_name}.json")
            json_content  = self._load_file(json_filepath) or "{}"
            py_filepath   = os.path.join(experiment_subdir, f"{experiment_name}.py")
            py_content    = self._load_file(py_filepath) or "# Python file not available"

            metrics_prompt   = self._build_metrics_prompt(
                dot_content, json_content, py_content,
                sce_node, probe_type, attack_nodes, quality_threshold
            )
            metrics_response = self._call_amazon_q(metrics_prompt, use_context=False,
                                                   model_id=self.model_experiment)

            q_pre_score = None
            if metrics_response:
                save_ok, q_pre_score = self._save_metrics_report(metrics_response, sce_node, probe_type)
                if save_ok:
                    print("✅ Pre-execution quality evaluation completed")
                else:
                    print("⚠️ Metrics evaluation completed but report save failed")
            else:
                print("⚠️ Failed to generate metrics evaluation")

            tracking_row: Dict = {
                "experiment": experiment_name,
                "loop":       loop_number,
                "q_pre":      q_pre_score,
                "q_post":     None,
                "model":      self.model_experiment,
            }
            self.tracking_table.append(tracking_row)

            q_post_score = None

            if q_pre_score is not None and q_pre_score >= quality_threshold:
                print(f"\n✅ Quality threshold met (Q_pre={q_pre_score:.2f} >= {quality_threshold})")
                print("🚀 Execute this experiment now? (y/n):")
                execute_response = input("> ").strip().lower()

                if execute_response == 'y':
                    json_filename = f"{experiment_name}.json"
                    json_filepath = os.path.join(experiment_subdir, json_filename)
                    log_filepath  = os.path.join(experiment_subdir, f"output_{experiment_name}.log")

                    print(f"\n▶️ Executing: chaos run {json_filename}")
                    print(f"📝 Output will be saved to: output_{experiment_name}.log")
                    print("=" * 60)

                    execution_successful = False
                    try:
                        result = subprocess.run(
                            ['chaos', 'run', json_filepath,
                             '--hypothesis-strategy=after-method-only'],
                            cwd=experiment_subdir,
                            capture_output=True,
                            text=True
                        )
                        combined_output = (f"STDOUT:\n{result.stdout}\n\n"
                                           f"STDERR:\n{result.stderr}\n\n"
                                           f"RETURN CODE: {result.returncode}")
                        with open(log_filepath, 'w', encoding='utf-8') as f:
                            f.write(combined_output)

                        print(result.stdout)
                        if result.stderr:
                            print("Errors/Warnings:")
                            print(result.stderr)

                        print("=" * 60)
                        if result.returncode == 0:
                            print("✅ Experiment execution completed successfully")
                        else:
                            print(f"⚠️ Experiment finished with return code: {result.returncode}")
                        print(f"✅ Execution log saved to: {log_filepath}")
                        execution_successful = True

                    except FileNotFoundError:
                        print("❌ 'chaos' command not found.")
                        print("   pip install chaostoolkit chaostoolkit-aws")
                    except Exception as e:
                        print(f"❌ Error executing experiment: {e}")

                    if execution_successful and os.path.exists(log_filepath):
                        print("\n📊 Evaluating post-execution quality metrics...")
                        output_log = self._load_file(log_filepath)
                        if output_log:
                            metrics_post_prompt = self._build_metrics_post_prompt(
                                output_log, sce_node, probe_type,
                                attack_nodes, quality_threshold_post
                            )
                            metrics_post_response = self._call_amazon_q(
                                metrics_post_prompt, use_context=False,
                                model_id=self.model_experiment)

                            if metrics_post_response:
                                save_ok, q_post_score = self._save_metrics_post_report(
                                    metrics_post_response, sce_node, probe_type)
                                if save_ok:
                                    print("✅ Post-execution quality evaluation completed")
                                    tracking_row["q_post"] = q_post_score
                                else:
                                    print("⚠️ Post-execution evaluation completed but report save failed")

                                if q_post_score is not None and q_post_score < quality_threshold_post:
                                    print(f"\n⚠️ Post-execution threshold not met "
                                          f"(Q_post={q_post_score:.2f} < {quality_threshold_post})")

                                    print(f"\n🔁 Regenerate the same experiment ({experiment_name})? (y/n):")
                                    regen_response = input("> ").strip().lower()

                                    if regen_response == 'y':
                                        print("\n📐 Regenerate from:")
                                        print("  1. Attack-Defense Tree (rebuild tree then experiment)")
                                        print("  2. Experiment only (use existing tree + logs)")
                                        regen_mode = input("> ").strip()

                                        if regen_mode == '1':
                                            # If in from_dot mode, structure_dot may be None
                                            if not structure_dot:
                                                print("\n⚠️  Tree rebuild requires structure.dot.")
                                                print("   Enter path to structure.dot (or press Enter to skip):")
                                                provided = input("> ").strip()
                                                if provided:
                                                    structure_dot = provided
                                                else:
                                                    print("❌ No structure.dot provided — falling back to experiment-only regen.")
                                                    same_experiment = True
                                                    continue
                                            print("\n🌳 Rebuilding Attack-Defense Tree...")
                                            if not run_stage3():
                                                print("❌ Tree rebuild failed; regenerating experiment only...")
                                            print("\n📊 Update pre-execution threshold? "
                                                  f"(current={quality_threshold}, press Enter to keep):")
                                            t_in = input("> ").strip()
                                            if t_in.isdigit():
                                                quality_threshold = max(0, min(100, int(t_in)))
                                                print(f"✅ New pre-execution threshold: {quality_threshold}")
                                            print("\n📊 Update post-execution threshold? "
                                                  f"(current={quality_threshold_post}, press Enter to keep):")
                                            t_in = input("> ").strip()
                                            if t_in.isdigit():
                                                quality_threshold_post = max(0, min(100, int(t_in)))
                                                print(f"✅ New post-execution threshold: {quality_threshold_post}")
                                            same_experiment = True
                                            continue
                                        else:
                                            print("\n🔁 Regenerating experiment from existing tree and logs...")
                                            same_experiment = True
                                            continue
                            else:
                                print("⚠️ Failed to generate post-execution metrics evaluation")
                else:
                    print("💡 Experiment not executed. Run manually with:")
                    print(f"   chaos run {experiment_name}.json "
                          f"> output_{experiment_name}.log 2>&1")

            elif q_pre_score is not None:
                print(f"\n⚠️ Quality threshold not met "
                      f"(Q_pre={q_pre_score:.2f} < {quality_threshold})")
                print("   Review the pre-execution report for recommendations.")
            else:
                print("\n💡 No quality score available for execution decision.")

            print("\n🔄 Generate a different SCE experiment? (y/n):")
            continue_response = input("> ").strip().lower()
            if continue_response != 'y':
                break

        self._tracking_print()
        self._tracking_save_md()
        print("🎉 All SCE experiments completed!")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def test_bedrock_connection() -> bool:
    print("🧪 Testing Bedrock Connection")
    print("=" * 40)

    print("\n1️⃣ Checking AWS credentials...")
    try:
        session     = boto3.Session()
        credentials = session.get_credentials()
        if credentials is None:
            print("❌ No AWS credentials found")
            return False
        print(f"✅ Credentials found for region: {session.region_name or 'default'}")
    except Exception as e:
        print(f"❌ Credential error: {e}")
        return False

    print("\n2️⃣ Creating Bedrock client...")
    try:
        bedrock = boto3.client('bedrock-runtime')
        print("✅ Bedrock client created successfully")
    except Exception as e:
        print(f"❌ Client creation failed: {e}")
        return False

    print("\n3️⃣ Testing model access...")
    try:
        bedrock_models   = boto3.client('bedrock')
        models           = bedrock_models.list_foundation_models()
        available_models = [m['modelId'] for m in models['modelSummaries']]
        print(f"✅ Found {len(available_models)} available models")
    except Exception as e:
        print(f"⚠️ Could not list models: {e}")

    print("\n4️⃣ Testing model invocation...")
    try:
        response = bedrock.invoke_model(
            modelId='amazon.titan-text-express-v1',
            body=json.dumps({
                'inputText': 'Hello, this is a test. Respond with "Test successful".',
                'textGenerationConfig': {'maxTokenCount': 50, 'temperature': 0.1}
            })
        )
        result      = json.loads(response['body'].read())
        output_text = result['results'][0]['outputText']
        print("✅ Model invocation successful")
        print(f"📝 Response: {output_text.strip()[:100]}...")
        return True
    except Exception as e:
        print(f"❌ Model invocation failed: {e}")
        return False


def interactive_input() -> Dict:
    """
    Ask for start mode first, then collect only what is needed for that mode.
    Returns a dict that unpacks directly into run_automated_conversation().
    """
    print("🤖 ADTs and Experiments Automation")
    print("====================================\n")

    print("📐 Select start mode:")
    print("  1. Full pipeline  — build tree from mission/threat intelligence, then experiments")
    print("  2. From .dot file — load existing attack-defense tree, go straight to experiments")
    while True:
        mode_choice = input("> ").strip()
        if mode_choice in ('1', '2'):
            break
        print("⚠️  Please enter 1 or 2")

    if mode_choice == '2':
        print("\n🌳 Enter path to existing Attack-Defense Tree (.dot) file:")
        existing_dot = input("> ").strip()
        return {
            'start_mode':          'from_dot',
            'existing_dot':        existing_dot,
            'mission_yaml':        None,
            'threat_intelligence': None,
            'attack_yaml':         None,
            'structure_dot':       None,
        }

    # Full pipeline
    print("\n📋 Enter Mission (YAML) filename:")
    mission_yaml = input("> ")

    print("\n🎯 Threat Intelligence (end with single quote ' on new line):")
    ti_lines = []
    while True:
        line = input()
        if line.strip() == "'":
            break
        ti_lines.append(line)
    threat_intelligence = '\n'.join(ti_lines)

    print("\n📝 Enter Attack Template (YAML) filename:")
    attack_yaml = input("> ")

    print("\n🌳 Enter Structure (DOT) filename:")
    structure_dot = input("> ")

    return {
        'start_mode':          'full',
        'existing_dot':        None,
        'mission_yaml':        mission_yaml,
        'threat_intelligence': threat_intelligence,
        'attack_yaml':         attack_yaml,
        'structure_dot':       structure_dot,
    }


def main():
    inputs = interactive_input()
    automation = SCEAutomationAPI()
    automation.run_automated_conversation(**inputs)


def run_test():
    print("🚀 Running Tests")
    print("=" * 30)
    connection_ok = test_bedrock_connection()
    if connection_ok:
        print("\n🎉 All tests passed!")
    else:
        print("\n❌ Some tests failed.")
    return connection_ok


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_test()
    else:
        main()