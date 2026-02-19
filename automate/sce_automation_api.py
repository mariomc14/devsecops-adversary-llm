#!/usr/bin/env python3
"""
SCE Automation with Amazon Q API Integration
"""

import json
import os
from pickle import FALSE
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

import tiktoken

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

        # ── CHANGE 1: tracking table ──────────────────────────────────────────
        # Each entry: {experiment, loop, q_pre, q_post}
        self.tracking_table: List[Dict] = []

    # ─────────────────────────────────────────────────────────────────────────
    # Tracking helpers
    # ─────────────────────────────────────────────────────────────────────────

    def _tracking_add(self, experiment: str, loop: int,
                      q_pre: Optional[float], q_post: Optional[float]) -> None:
        """Append one row to the tracking table."""
        self.tracking_table.append({
            "experiment": experiment,
            "loop":       loop,
            "q_pre":      q_pre,
            "q_post":     q_post,
        })

    def _tracking_print(self) -> None:
        """Pretty-print the tracking table to stdout."""
        if not self.tracking_table:
            print("\n📋 No experiments were tracked in this session.")
            return

        col_exp  = max(len(r["experiment"]) for r in self.tracking_table)
        col_exp  = max(col_exp, len("Experimento"))
        col_loop = max(len(str(r["loop"])) for r in self.tracking_table)
        col_loop = max(col_loop, len("# Loop"))
        col_pre  = len("Q_pre")
        col_post = len("Q_post")

        sep  = f"+{'-'*(col_exp+2)}+{'-'*(col_loop+2)}+{'-'*(col_pre+2)}+{'-'*(col_post+2)}+"
        head = (f"| {'Experimento':<{col_exp}} "
                f"| {'# Loop':>{col_loop}} "
                f"| {'Q_pre':>{col_pre}} "
                f"| {'Q_post':>{col_post}} |")

        print("\n" + "="*60)
        print("📋  CUADRO DE SEGUIMIENTO DE EXPERIMENTOS SCE")
        print("="*60)
        print(sep)
        print(head)
        print(sep)
        for r in self.tracking_table:
            q_pre_s  = f"{r['q_pre']:.2f}"  if r["q_pre"]  is not None else "N/A"
            q_post_s = f"{r['q_post']:.2f}" if r["q_post"] is not None else "N/A"
            print(f"| {r['experiment']:<{col_exp}} "
                  f"| {r['loop']:>{col_loop}} "
                  f"| {q_pre_s:>{col_pre}} "
                  f"| {q_post_s:>{col_post}} |")
        print(sep)
        print()

    # ─────────────────────────────────────────────────────────────────────────

    def _sanitize_name(self, name: str) -> str:
        """Sanitize name for safe filename usage"""
        return re.sub(r'[^\w\-_]', '_', name.lower()).strip('_')

    def _count_tokens(self, text: str) -> int:
        """Count tokens using tiktoken"""
        encoding = tiktoken.get_encoding("cl100k_base")
        return len(encoding.encode(text))

    def _load_yaml(self, yaml_path: str) -> Dict:
        """Load mission configuration from YAML file"""
        try:
            with open(yaml_path, 'r', encoding='utf-8') as f:
                self.yaml = yaml.safe_load(f)
                return self.yaml
        except Exception as e:
            print(f"❌ Error loading yaml file: {e}")
            return None # type: ignore
        
    def _load_file(self, template_path: str) -> str:
        """Load files as raw text"""
        try:
            with open(template_path, 'r', encoding='utf-8') as f:
                return f.read()
        except Exception as e:
            print(f"❌ Error loading attack template: {e}")
            return None # type: ignore
        
    def _extract_yaml_from_response(self, response_text: str) -> bool:
        try:
            """Extract clean YAML content from LLM response"""
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
            return False # type: ignore

    def _build_mission_prompt(self) -> str:
        """Build mission analysis prompt from YAML configuration"""
        if not self.yaml:
            return None # type:ignore
            
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
            return None # type: ignore
            
        return f"""Please populate the template using it strictly as a schema, not as content. Complete every applicable field in the template with information specific to the following attack:
            THREAT INTELLIGENCE:
            {threat_intelligence}

            TEMPLATE TO POPULATE:
            {self.attack_template}

            Instructions:
            - Preserve the structure, section order, and field names exactly as they appear in the template.
            - Replace all placeholder or example text with concrete details for this attack only
            - If a field is not applicable or the information is unavailable, leave the field present and explicitly mark it as N/A rather than deleting it.
            - Use clear, concise, technically accurate language suitable for threat modeling and repeteable testing.
            
            Return the completed content in yaml format, ready to be stored as an attack record."""

    def _build_attack_defense_tree_prompt(self, attacks_yaml: str, structure_dot: str) -> str:
        """Build the attack-defense tree generation prompt"""
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
        """Build SCE experiment generation prompt"""
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
Goal: Generate an end-to-end Security Chaos Engineering unit test that validates exactly this one probe, by.
- Translating each associated attack step into safe, scoped AWS actions against only the resources created by the experiment
- Implementing the probe's security intent (Preventive / Detective / Reactive as an AWS-native control in the experiment)
- Verifying, programatically, that this control behaves as described in the probe's label and classification.

Environment:
- The script runs in a real but completely clean AWS account (no existing IAM roles, policies, buckets, parameters, alarms, etc)

Deliverables (return two artifacts):
Produce exactly two files, in this order:
1. Python script implementing the experiment logic
2. JSON experiment manifest for the chaostoolkit runner, it must follow the structure of the file @template.json, replace:
    - [SCE_NODE] with: {self._sanitize_name(sce_node)}
    - [PROBE_TYPE] with: {self._sanitize_name(probe_type)}
    - Keep "chaosaws.ec2" prefix fixed in all module paths
    - DO NOT include a "secrets" section - AWS credentials will be automatically discovered from the standard credential chain (~/.aws/credentials)

Script structure (must follow this flow):
The script is self-contained: no CLI arguments, no external config files, no pre-existing AWS resources. Use only the standard library unless unavoidable; if needed, install boto3 at runtime programmatically and keep the footprint minimal. Implement basic retries/backoff for eventual consistency using time.monotonic(). All functions take no parameters. Finally, log every error encountered.

1. Preparation block (executes on import/run)
- Function: steady_state()
- Generate a unique timestamp suffix using int(time.time()) to append to stack name (e.g., "sce-experiment-1703123456")
- Use AWS CloudFormation to provision everything the test needs:
    - Create a CloudFormation template defining only the AWS resources required for the specified attack step
    - Deploy the stack with timestamped name to avoid conflicts
    - Generate any sample data needed and set environment variables or acquire temporary tokens if required
    - Handle stack conflicts gracefully: if stack already exists, log warning and continue
- Reliability: add bounded retries/backoff for stack creation completion, IAM policy propagation, etc.
- Tagging: tag the CloudFormation stack and all resources with experiment tag and timestamp
- Wait until CloudFormation complete execution to continue with the experiment

2. attack() -> bool: Execute the provided attack step in order and only those steps, operating strictly on resources created in steady_state()
3. hypothesis_verification() -> bool: Verify countermeasure based on probe type from the SCE experiment node.
4. rollback(): Complete teardown using CloudFormation:
- Delete the CloudFormation stack created in steady_state() using the timestamped stack name
- Wait for stack deletion to complete with proper error handling
- Be safe and tolerant: catch stack not found errors and proceed
- The test function must always attempt rollback, even on failure (e.g., try/finally)
- If execution is halted midway, stack deletion will still clean up all resources automatically

@template.json (update the placeholders):
{template_json}
"""

    def _build_metrics_prompt(self, dot_content: str, json_content: str, py_content: str,
                               sce_node: str, probe_type: str, attack_nodes: str,
                               threshold: int = 80) -> str:
        """Build pre-execution quality evaluation prompt"""
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

**Q_pre = 0.40 × f1 + 0.30 × f2 + 0.30 × f3**
**Q_pre = 0.40 × [f1] + 0.30 × [f2] + 0.30 × [f3]**
**Q_pre = [calculated value]**

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
        """Build post-execution quality evaluation prompt"""
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

**Q_post = 0.50 × f1 + 0.50 × f2**
**Q_post = 0.50 × [f1] + 0.50 × [f2]**
**Q_post = [calculated value]**

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
        """Extract and save Python script and JSON manifest from response"""
        try:
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)

            # Create experiments directory structure
            experiments_dir = os.path.join(self.workspace_path, "experiments")
            experiment_subdir = os.path.join(experiments_dir, f"{safe_sce_node}_{safe_probe_type}")
            os.makedirs(experiment_subdir, exist_ok=True)

            # Extract Python script
            python_start = response_text.find("```python")
            if python_start != -1:
                python_start += 9
                python_end = response_text.find("```", python_start)
                if python_end != -1:
                    python_content = response_text[python_start:python_end].strip()
                    python_filename = f"{safe_sce_node}_{safe_probe_type}.py"
                    python_filepath = os.path.join(experiment_subdir, python_filename)
                    with open(python_filepath, 'w', encoding='utf-8') as f:
                        f.write(python_content)
                    print(f"✅ Python script saved to: {python_filepath}")

                    try:
                        import chaosaws.ec2
                        chaosaws_path = chaosaws.ec2.__path__[0]
                        chaosaws_filepath = os.path.join(chaosaws_path, python_filename)
                        with open(chaosaws_filepath, 'w', encoding='utf-8') as f:
                            f.write(python_content)
                        print(f"✅ Python script copied to chaosaws: {chaosaws_filepath}")
                    except ImportError:
                        print(f"⚠️ chaosaws.ec2 not found, skipping copy to chaosaws directory")
                    except Exception as e:
                        print(f"⚠️ Could not copy to chaosaws directory: {e}")

            # Extract JSON manifest
            json_start = response_text.find("```json")
            if json_start != -1:
                json_start += 7
                json_end = response_text.find("```", json_start)
                if json_end != -1:
                    json_content = response_text[json_start:json_end].strip()
                    json_filepath = os.path.join(experiment_subdir,
                                                 f"{safe_sce_node}_{safe_probe_type}.json")
                    with open(json_filepath, 'w', encoding='utf-8') as f:
                        f.write(json_content)
                    print(f"✅ JSON manifest saved to: {json_filepath}")
                    return True

            return False
        except Exception as e:
            print(f"❌ Error saving SCE experiment files: {e}")
            return False

    def _save_metrics_report(self, response_text: str, sce_node: str, probe_type: str):
        """Extract and save pre-execution metrics report. Returns (success, q_pre_score)."""
        try:
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)

            reports_dir = os.path.join(self.workspace_path, "reports")
            report_subdir = os.path.join(reports_dir, f"{safe_sce_node}_{safe_probe_type}")
            os.makedirs(report_subdir, exist_ok=True)

            report_start = response_text.find("```markdown")
            if report_start != -1:
                report_start += 11
                report_end = response_text.find("```", report_start)
                report_content = (response_text[report_start:report_end].strip()
                                  if report_end != -1 else response_text[report_start:].strip())
            else:
                report_start = response_text.find("# PRE-EXECUTION QUALITY EVALUATION REPORT")
                report_content = (response_text[report_start:].strip()
                                  if report_start != -1 else response_text.strip())

            report_filename = f"pre_execution_report_{safe_sce_node}_{safe_probe_type}.md"
            report_filepath = os.path.join(report_subdir, report_filename)
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"✅ Pre-execution report saved to: {report_filepath}")

            q_pre_patterns = [
                r'Q_pre\s*=\s*0\.40\s*×\s*\d+\s*\+\s*0\.30\s*×\s*\d+\s*\+\s*0\.30\s*×\s*\d+\s*=\s*([0-9.]+)',
                r'\*\*Q_pre\s*=\s*([0-9.]+)\*\*',
                r'Q_pre\s*=\s*\*\*([0-9.]+)\*\*',
                r'calculated value\]:\s*\*\*([0-9.]+)\*\*',
                r'Q_pre.*?=.*?([0-9]{2,3}\.[0-9]{2})\s*(?:\n|$|<|>|\*)',
            ]
            q_pre_score = None
            for pattern in q_pre_patterns:
                m = re.search(pattern, report_content, re.MULTILINE | re.DOTALL)
                if m:
                    try:
                        v = float(m.group(1))
                        if 0 <= v <= 100 and v not in (0.40, 0.30):
                            q_pre_score = v
                            break
                    except (ValueError, IndexError):
                        continue

            if q_pre_score is not None:
                print(f"📊 Quality Score (Q_pre): {q_pre_score:.2f}/100")
            else:
                print("⚠️ Could not extract Q_pre score from report")

            decision_match = re.search(r'\*\*\[(AUTHORIZE EXECUTION|STOP[^\]]*)\]\*\*', report_content)
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
        """Extract and save post-execution metrics report. Returns (success, q_post_score)."""
        try:
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)

            reports_dir = os.path.join(self.workspace_path, "reports")
            report_subdir = os.path.join(reports_dir, f"{safe_sce_node}_{safe_probe_type}")
            os.makedirs(report_subdir, exist_ok=True)

            report_start = response_text.find("```markdown")
            if report_start != -1:
                report_start += 11
                report_end = response_text.find("```", report_start)
                report_content = (response_text[report_start:report_end].strip()
                                  if report_end != -1 else response_text[report_start:].strip())
            else:
                report_start = response_text.find("# POST-EXECUTION QUALITY EVALUATION REPORT")
                report_content = (response_text[report_start:].strip()
                                  if report_start != -1 else response_text.strip())

            report_filename = f"post_execution_report_{safe_sce_node}_{safe_probe_type}.md"
            report_filepath = os.path.join(report_subdir, report_filename)
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            print(f"✅ Post-execution report saved to: {report_filepath}")

            q_post_patterns = [
                r'Q_post\s*=\s*0\.50\s*×\s*\d+\s*\+\s*0\.50\s*×\s*\d+\s*=\s*([0-9.]+)',
                r'\*\*Q_post\s*=\s*([0-9.]+)\*\*',
                r'Q_post\s*=\s*\*\*([0-9.]+)\*\*',
                r'calculated value\]:\s*\*\*([0-9.]+)\*\*',
                r'Q_post.*?=.*?([0-9]{1,3}\.?[0-9]{0,2})\s*(?:\n|$|<|>|\*)',
            ]
            q_post_score = None
            for pattern in q_post_patterns:
                m = re.search(pattern, report_content, re.MULTILINE | re.DOTALL)
                if m:
                    try:
                        v = float(m.group(1))
                        if 0 <= v <= 100 and v != 0.50:
                            q_post_score = v
                            break
                    except (ValueError, IndexError):
                        continue

            if q_post_score is not None:
                print(f"📊 Post-Execution Quality Score (Q_post): {q_post_score:.2f}/100")
            else:
                print("⚠️ Could not extract Q_post score from report")

            decision_match = re.search(r'\*\*\[(VALID EXECUTION|INVALID EXECUTION)\]\*\*',
                                       report_content)
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
        """Extract and save DOT content from response"""
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

    def _call_amazon_q(self, prompt: str, use_context: bool = True) -> str:
        """Call Amazon Bedrock API with prompt and conversation context"""
        try:
            if use_context and self.conversation_history:
                context = "\n\n".join([
                    f"Previous: {item['prompt']}\nResponse: {item['response']}"
                    for item in self.conversation_history
                ])
                full_prompt = f"{context}\n\nCurrent: {prompt}"
            else:
                full_prompt = prompt

            response = self.bedrock.converse(
                modelId="global.anthropic.claude-haiku-4-5-20251001-v1:0",
                messages=[{
                    "role": "user",
                    "content": [{"text": full_prompt}]
                }],
                inferenceConfig={
                    "maxTokens": 64000,
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
            return None # type: ignore

    # ─────────────────────────────────────────────────────────────────────────
    # Main orchestrator
    # ─────────────────────────────────────────────────────────────────────────

    def run_automated_conversation(self, mission_yaml: str, threat_intelligence: str,
                                   attack_yaml: str, structure_dot: str):
        """Run automated conversation with Amazon Q"""

        print("🚀 Starting Automated SCE Conversation with Amazon Q")

        # ── Stage 1: Mission analysis ─────────────────────────────────────────
        print(f"\n📁 Loading mission configuration from {mission_yaml}...")
        if not self._load_yaml(mission_yaml):
            print("❌ Failed to load mission configuration")
            return

        print("📋 Stage 1: Analyzing mission from YAML configuration...")
        mission_prompt = self._build_mission_prompt()
        if not mission_prompt:
            print("❌ Failed to build mission prompt")
            return

        stage1_response = self._call_amazon_q(mission_prompt, use_context=True)
        if not stage1_response:
            print("❌ Failed to get mission analysis")
            return
        print("✅ Mission analysis completed")

        # ── Stage 2: Attack YAML ──────────────────────────────────────────────
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

        stage2_response = self._call_amazon_q(attack_prompt, False)
        if not stage2_response:
            print("❌ Failed to generate attack content")
            return

        if not self._extract_yaml_from_response(stage2_response):
            print("❌ Failed to save attack file")
            return
        print("✅ Attack YAML generated and saved")

        # ── Stage 3: Attack-Defense Tree (runs ONCE, outside the loop) ────────
        print(f"\n🌳 Stage 3: Building attack-defense tree with safeguard logic...")

        attacks_yaml_path = os.path.join(self.workspace_path, "attacks.yaml")
        attacks_yaml_content = self._load_file(attacks_yaml_path)
        if not attacks_yaml_content:
            print("❌ Failed to load attacks.yaml file")
            return

        structure_dot_content = self._load_file(structure_dot)
        if not structure_dot_content:
            print("❌ Failed to load structure.dot file")
            return

        tree_prompt = self._build_attack_defense_tree_prompt(attacks_yaml_content,
                                                             structure_dot_content)
        stage3_response = self._call_amazon_q(tree_prompt, use_context=True)
        if not stage3_response:
            print("❌ Failed to generate attack-defense tree")
            return

        if not self._save_dot_output(stage3_response):
            print("❌ Failed to save DOT output")
            return
        print("✅ Attack-defense tree generated and saved as DOT file")

        # ── Quality thresholds (asked once before the loop) ───────────────────
        print("\n📊 Enter quality threshold for pre-execution metrics (0-100, default=80):")
        threshold_input = input("> ").strip()
        try:
            quality_threshold = int(threshold_input) if threshold_input else 80
            quality_threshold = quality_threshold if 0 <= quality_threshold <= 100 else 80
        except ValueError:
            quality_threshold = 80
        print(f"✅ Pre-execution quality threshold set to: {quality_threshold}")

        print("\n📊 Enter quality threshold for post-execution metrics (0-100, default=100):")
        threshold_post_input = input("> ").strip()
        try:
            quality_threshold_post = int(threshold_post_input) if threshold_post_input else 100
            quality_threshold_post = (quality_threshold_post
                                      if 0 <= quality_threshold_post <= 100 else 100)
        except ValueError:
            quality_threshold_post = 100
        print(f"✅ Post-execution quality threshold set to: {quality_threshold_post}")

        # ── Stage 4: Experiment loop ──────────────────────────────────────────
        # CHANGE 2: loop starts from experiment generation, NOT from ADT generation
        print("\n🧪 Stage 4: Generating SCE experiments...")

        while True:
            # ── CHANGE 1: increment loop counter per experiment ───────────────
            loop_number = len(self.tracking_table) + 1
            print(f"\n{'─'*60}")
            print(f"🔁 Loop #{loop_number}")
            print(f"{'─'*60}")

            # Collect inputs
            print("\n🧪 Enter SCE Node name:")
            sce_node = input("> ")

            print("\n🔍 Enter Probe Type (Preventive/Detective/Reactive):")
            probe_type = input("> ")

            print("\n🎯 Enter Attack Nodes:")
            attack_nodes = input("> ")

            print("\n📋 Enter Template JSON filename:")
            template_json = input("> ")

            template_json_content = self._load_file(template_json)
            if not template_json_content:
                print("❌ Failed to load template.json")
                # Register failed loop with no scores
                experiment_name = f"{self._sanitize_name(sce_node)}_{self._sanitize_name(probe_type)}"
                self._tracking_add(experiment_name, loop_number, None, None)
                continue

            safe_sce_node  = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)
            experiment_name = f"{safe_sce_node}_{safe_probe_type}"

            # ── Load previous artifacts if they exist ─────────────────────────
            experiments_dir  = os.path.join(self.workspace_path, "experiments")
            experiment_subdir = os.path.join(experiments_dir, experiment_name)
            reports_dir      = os.path.join(self.workspace_path, "reports")
            report_subdir    = os.path.join(reports_dir, experiment_name)

            log_path = os.path.join(experiment_subdir,
                                    f"output_{experiment_name}.log")
            metrics_report_path = os.path.join(report_subdir,
                                               f"pre_execution_report_{experiment_name}.md")
            post_metrics_report_path = os.path.join(report_subdir,
                                                    f"post_execution_report_{experiment_name}.md")

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
                print(f"\n💡 No previous execution log found")

            previous_metrics_report = None
            if os.path.exists(metrics_report_path):
                print(f"📊 Found existing pre-metrics report")
                try:
                    with open(metrics_report_path, 'r', encoding='utf-8') as f:
                        previous_metrics_report = f.read()
                    print(f"✅ Loaded previous pre-metrics report ({len(previous_metrics_report)} chars)")
                except Exception as e:
                    print(f"⚠️ Could not read metrics report: {e}")
            else:
                print(f"💡 No previous pre-metrics report found")

            previous_post_metrics_report = None
            if os.path.exists(post_metrics_report_path):
                print(f"📊 Found existing post-metrics report")
                try:
                    with open(post_metrics_report_path, 'r', encoding='utf-8') as f:
                        previous_post_metrics_report = f.read()
                    print(f"✅ Loaded previous post-metrics report ({len(previous_post_metrics_report)} chars)")
                except Exception as e:
                    print(f"⚠️ Could not read post-metrics report: {e}")
            else:
                print(f"💡 No previous post-metrics report found")

            if not any([previous_log, previous_metrics_report, previous_post_metrics_report]):
                print("   Generating experiment from scratch.")

            # ── Generate experiment ───────────────────────────────────────────
            sce_prompt = self._build_sce_experiment_prompt(
                sce_node, probe_type, attack_nodes, template_json_content,
                previous_log, previous_metrics_report, previous_post_metrics_report
            )
            sce_response = self._call_amazon_q(sce_prompt, use_context=True)
            if not sce_response:
                print("❌ Failed to generate SCE experiment")
                self._tracking_add(experiment_name, loop_number, None, None)
                continue

            if not self._save_sce_experiment_output(sce_response, sce_node, probe_type):
                print("❌ Failed to save SCE experiment files")
                self._tracking_add(experiment_name, loop_number, None, None)
                continue
            print("✅ SCE experiment generated and saved")

            # ── Pre-execution quality evaluation ─────────────────────────────
            print("\n📊 Evaluating pre-execution quality metrics...")

            dot_filepath = os.path.join(self.workspace_path, "attack_defense_tree.dot")
            dot_content  = self._load_file(dot_filepath) or "# DOT file not available"

            json_filepath = os.path.join(experiment_subdir, f"{experiment_name}.json")
            json_content  = self._load_file(json_filepath) or "{}"

            py_filepath = os.path.join(experiment_subdir, f"{experiment_name}.py")
            py_content  = self._load_file(py_filepath) or "# Python file not available"

            metrics_prompt   = self._build_metrics_prompt(
                dot_content, json_content, py_content,
                sce_node, probe_type, attack_nodes, quality_threshold
            )
            metrics_response = self._call_amazon_q(metrics_prompt, use_context=False)

            q_pre_score = None
            if metrics_response:
                save_ok, q_pre_score = self._save_metrics_report(
                    metrics_response, sce_node, probe_type)
                if save_ok:
                    print("✅ Pre-execution quality evaluation completed")
                else:
                    print("⚠️ Metrics evaluation completed but report save failed")
            else:
                print("⚠️ Failed to generate metrics evaluation")

            # ── CHANGE 1: register row (q_post filled later if executed) ─────
            # We add a mutable dict so we can update q_post in place
            tracking_row: Dict = {
                "experiment": experiment_name,
                "loop":       loop_number,
                "q_pre":      q_pre_score,
                "q_post":     None,
            }
            self.tracking_table.append(tracking_row)

            # ── Execution decision ────────────────────────────────────────────
            q_post_score = None

            if q_pre_score is not None and q_pre_score >= quality_threshold:
                print(f"\n✅ Quality threshold met (Q_pre={q_pre_score:.2f} >= {quality_threshold})")
                print("🚀 Execute this experiment now? (y/n):")
                execute_response = input("> ").strip().lower()

                if execute_response == 'y':
                    json_filename = f"{experiment_name}.json"
                    json_filepath = os.path.join(experiment_subdir, json_filename)
                    log_filepath  = os.path.join(experiment_subdir,
                                                 f"output_{experiment_name}.log")

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

                    # ── Post-execution quality evaluation ─────────────────────
                    if execution_successful and os.path.exists(log_filepath):
                        print("\n📊 Evaluating post-execution quality metrics...")
                        output_log = self._load_file(log_filepath)
                        if output_log:
                            metrics_post_prompt = self._build_metrics_post_prompt(
                                output_log, sce_node, probe_type,
                                attack_nodes, quality_threshold_post
                            )
                            metrics_post_response = self._call_amazon_q(
                                metrics_post_prompt, use_context=False)

                            if metrics_post_response:
                                save_ok, q_post_score = self._save_metrics_post_report(
                                    metrics_post_response, sce_node, probe_type)
                                if save_ok:
                                    print("✅ Post-execution quality evaluation completed")
                                    # ── CHANGE 1: update q_post in tracking row ──
                                    tracking_row["q_post"] = q_post_score
                                else:
                                    print("⚠️ Post-execution evaluation completed but report save failed")

                                # ── CHANGE 1: register in tracking regardless of threshold ──
                                if q_post_score is not None and q_post_score < quality_threshold_post:
                                    print(f"\n⚠️ Post-execution threshold not met "
                                          f"(Q_post={q_post_score:.2f} < {quality_threshold_post})")
                                    print("   Review the post-execution report before re-running.")
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

            # ── Continue? ─────────────────────────────────────────────────────
            print("\n🔄 Generate another SCE experiment? (y/n):")
            continue_response = input("> ").strip().lower()
            if continue_response != 'y':
                break
            # CHANGE 2: if continuing, the loop goes back to experiment generation,
            # NOT to ADT generation — the while True already achieves this.

        # ── CHANGE 3: present tracking table at the end ───────────────────────
        self._tracking_print()
        print("🎉 All SCE experiments completed!")


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def test_bedrock_connection() -> bool:
    print("🧪 Testing Bedrock Connection")
    print("=" * 40)

    print("\n1️⃣ Checking AWS credentials...")
    try:
        session = boto3.Session()
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
        bedrock_models = boto3.client('bedrock')
        models = bedrock_models.list_foundation_models()
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
        result = json.loads(response['body'].read())
        output_text = result['results'][0]['outputText']
        print("✅ Model invocation successful")
        print(f"📝 Response: {output_text.strip()[:100]}...")
        return True
    except Exception as e:
        print(f"❌ Model invocation failed: {e}")
        return False


def interactive_input():
    print("🤖 ADTs and Experiments Automation")
    print("====================================\n")

    print("📋 Enter Mission (YAML) filename:")
    mission_yaml = input("> ")

    print("\n🎯 Threat Intelligence (end with single quote ' on new line):")
    threat_intelligence_lines = []
    while True:
        line = input()
        if line.strip() == "'":
            break
        threat_intelligence_lines.append(line)
    threat_intelligence = '\n'.join(threat_intelligence_lines)

    print("\n📝 Enter Attack Template (YAML) filename:")
    attack_yaml = input("> ")

    print("\n🌳 Enter Structure (DOT) filename:")
    structure_dot = input("> ")

    return mission_yaml, threat_intelligence, attack_yaml, structure_dot


def main():
    mission_yaml, threat_intelligence, attack_yaml, structure_dot = interactive_input()
    automation = SCEAutomationAPI()
    automation.run_automated_conversation(mission_yaml, threat_intelligence,
                                         attack_yaml, structure_dot)


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