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

    def _sanitize_name(self, name: str) -> str:
        """Sanitize name for safe filename usage"""
        return re.sub(r'[^\w\-_]', '_', name.lower()).strip('_')


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
            # Find the start of the YAML (after "attack:")
            yaml_start = response_text.find("attack:")
            if yaml_start == -1:
                return False  # Return as-is if no clear YAML found
            
            # Extract from "attack:" onwards
            yaml_content = response_text[yaml_start:]
            
            # Remove any trailing explanation text after the YAML
            lines = yaml_content.split('\n')
            yaml_lines = []
            
            for line in lines:
                stripped = line.strip()
                # Stop if line doesn't look like YAML structure
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
        
        # Build mission overview
        overview = "\n".join([f"- {desc}" for desc in config['mission_overview']['description']])
        
        # Build threat categories
        threats = "\n".join([
            f"- {threat['name']}: {threat['description']}" 
            for threat in config['primary_threat_categories']
        ])
        
        # Build core technologies
        technologies = "\n".join([
            f"- {tech['name']}: {tech['purpose']}" 
            for tech in config['core_technologies']
        ])
        
        # Build safeguard definitions
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
    - Generate a Graphviz DOT graph using HTML-like labels label=<...> (do not add an extra > at the end), always escape & < > \" as &amp; &lt; &gt; &quot; when they appear as literal text, and validate the </> balance in each label before returning the code.

    @attacks.yaml:
    {attacks_yaml}

    @structure.dot:
    {structure_dot}
    """

    def _build_sce_experiment_prompt(self, sce_node : str, probe_type : str, attack_nodes : str, template_json: str, previous_log: Optional[str] = None, previous_metrics_report: Optional[str] = None, previous_post_metrics_report: Optional[str] = None) -> str:
        """Build SCE experiment generation prompt"""
        
        # Build additional context from previous log if available
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
        
        # Build additional context from previous metrics report if available
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
        
        # Build additional context from previous post-execution metrics report if available
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
- The script runs in a real but completely clean AWS account (no existing IAM roles, policies, buckets, parameters, alarms, etc)-
- Standard AWS credentials are already available via environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, etc.). Use AWS_REGION if present; otherwise default to us-east-1.

Deliverables (return two artifacts):
Produce exactly two files, in this order:
1. Python script implementing the experiment logic
2. JSON experiment manifest for the chaostoolkit runner, it must follow the structure of the file @template.json, replace:
    - [SCE_NODE] with: {self._sanitize_name(sce_node)}
    - [PROBE_TYPE] with: {self._sanitize_name(probe_type)}
    - Keep "chaosaws.ec2" prefix fixed in all module paths

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
    
    def _build_metrics_prompt(self, dot_content: str, json_content: str, py_content: str, sce_node: str, probe_type: str, attack_nodes: str, threshold: int = 80) -> str:
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
Evaluate the degree of correspondence between the attack node defined in the ADT and the implementation of the ACTION in the SCE experiment.

**Scoring Criteria:**
- **0 points**: No correspondence between ADT attack node and implemented ACTION
- **50 points**: Partial alignment - same tactic but different technique
- **100 points**: Full correspondence with:
  - Same tactic AND technique as ADT
  - High implementation quality: well-defined methods, arguments, inputs/outputs
  - Proper documentation
  - Error handling implemented

**Your analysis for f1:**
1. Identify the attack node(s) in the ADT
2. Identify the ACTION implementation in the Python code (typically in the `attack()` function)
3. Compare tactic and technique alignment
4. Assess implementation quality (documentation, error handling, code structure)
5. Assign score: 0, 50, or 100

### **Factor 2 (f2): Defense ↔ Defense Correspondence**
Evaluate the correspondence between the defense node defined in the ADT and its implementation in the SCE experiment.

**Scoring Criteria:**
- **0 points**: No correspondence between ADT defense node and implemented defense
- **50 points**: Corresponds to the defense node in ADT
- **100 points**: Full correspondence plus high-quality code:
  - Matches ADT defense specification
  - Well-documented (method purpose, arguments, I/O clearly explained)
  - Validated error handling
  - Robust implementation

**Your analysis for f2:**
1. Identify the defense/safeguard node(s) in the ADT
2. Identify the defense implementation in the Python code (typically in CloudFormation template or steady_state())
3. Verify correspondence with ADT specification
4. Assess code quality (documentation, error handling)
5. Assign score: 0, 50, or 100

### **Factor 3 (f3): PROBE ↔ Defensive Intent Correspondence**
Measure whether the purpose of the defense node in the ADT is correctly reflected in the implementation of the PROBE in the SCE experiment.

**Scoring Criteria:**
- **0 points**: PROBE does not correspond to defensive intent from ADT
- **100 points**: PROBE fully corresponds to defensive intent - what the PROBE observes matches exactly what the defense should achieve

**Your analysis for f3:**
1. Identify the defensive intent/purpose in the ADT (what the defense is supposed to do)
2. Identify the PROBE implementation (typically in `hypothesis_verification()` function)
3. Verify that the PROBE correctly validates the defensive intent
4. Assign score: 0 or 100

## COMPUTATION

Calculate the pre-execution quality score:

**Q_pre = 0.40 × f1 + 0.30 × f2 + 0.30 × f3**

Where:
- f1, f2 ∈ {{0, 50, 100}}
- f3 ∈ {{0, 100}}
- 0 ≤ Q_pre ≤ 100

**Execution Threshold**: τ = {threshold}

**Decision Rule**:
- If Q_pre < {threshold} → **STOP** - Experiment quality insufficient for execution
- If Q_pre ≥ {threshold} → **AUTHORIZE** - Experiment approved for execution

## OUTPUT FORMAT

Produce a detailed evaluation report in the following structure:

```markdown
# PRE-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: {sce_node}
- **Probe Type**: {probe_type}
- **Attack Nodes**: {attack_nodes}
- **Evaluation Date**: [Current timestamp]

## Factor 1: ACTION ↔ Attack Correspondence
**Score**: [0 | 50 | 100]

**Analysis**:
- Attack node in ADT: [description]
- ACTION implementation: [description]
- Tactic alignment: [Yes/No/Partial]
- Technique alignment: [Yes/No]
- Implementation quality: [assessment]

**Justification**: [Detailed explanation of why this score was assigned]

---

## Factor 2: Defense ↔ Defense Correspondence
**Score**: [0 | 50 | 100]

**Analysis**:
- Defense node in ADT: [description]
- Defense implementation: [description]
- Correspondence: [Yes/No/Partial]
- Code quality: [assessment]
- Documentation: [assessment]
- Error handling: [assessment]

**Justification**: [Detailed explanation of why this score was assigned]

---

## Factor 3: PROBE ↔ Defensive Intent Correspondence
**Score**: [0 | 100]

**Analysis**:
- Defensive intent in ADT: [description]
- PROBE implementation: [description]
- Intent correspondence: [Yes/No]

**Justification**: [Detailed explanation of why this score was assigned]

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

## Detailed Observations

[Any additional observations, warnings, or recommendations]

## Recommendations

[Specific suggestions to improve scores if Q_pre < 80]
```

**IMPORTANT**: Be thorough and precise in your analysis. Examine the actual code, the ADT structure, and the JSON manifest carefully. Provide specific examples and quotes from the artifacts to justify your scores."""

    def _build_metrics_post_prompt(self, output_log: str, sce_node: str, probe_type: str, attack_nodes: str, threshold_post: int = 100) -> str:
        """Build post-execution quality evaluation prompt"""
        return f"""# POST-EXECUTION QUALITY EVALUATION

You are an **expert in experimental cybersecurity**, specialized in **attack-defense trees** and in the evaluation of **Security Chaos Engineering (SCE)** experiments.

Your task is to rigorously evaluate the **post-execution quality** of an SCE experiment after the execution of the **ACTION** and the **PROBE**, taking into account the execution output log.

## EXPERIMENT CONTEXT
- **SCE Node**: {sce_node}
- **Probe Type**: {probe_type}
- **Attack Nodes**: {attack_nodes}

## EXECUTION OUTPUT LOG

```
{output_log}
```

## EVALUATION TASK

The post-execution metrics focus on verifying the **correctness, observability, and reliability** of the results produced during the experiment. These metrics evaluate both the capability of the ACTION to execute the attack and the capability of the PROBE to verify and report the consequences of that attack.

Evaluate the following factors **after the execution of the experiment**:

---

### **Factor 1 (f1): Effectiveness of the ACTION in Executing the Attack**

Evaluate whether the **ACTION** produced a result that clearly indicates that the attack was executed and whether such evidence is **verifiable** within the context of the SCE experiment.

**Scoring Criteria:**
- **0 points**: The ACTION did not return a result indicating that the attack was executed
- **100 points**: The ACTION returned a verifiable result with evidence of attack execution (success or failure)

**Your analysis for f1:**
1. Review the execution output log
2. Identify evidence that the ACTION was executed (e.g., AWS API calls, resource modifications, command outputs)
3. Determine if the attack execution can be verified from the log
4. Look for clear indicators of success or failure
5. Assign score: 0 or 100

**Justification**: Provide specific log excerpts that demonstrate attack execution

---

### **Factor 2 (f2): PROBE Capability to Verify and Report the Attack Outcome**

Evaluate the capacity of the **PROBE** to verify and report the outcome of the attack. This includes determining whether the PROBE produced **reliable and verifiable evidence** that reflects the system's defensive behavior.

Examples of evidence include (but are not limited to):
- Logs
- Alerts
- Metrics
- Other measurable indicators

**Scoring Criteria:**
- **0 points**: The PROBE did not return a verifiable result
- **100 points**: The PROBE returned a verifiable result with evidence of defense behavior

**Your analysis for f2:**
1. Review the execution output log
2. Identify PROBE verification results (hypothesis validation, defensive mechanism checks)
3. Look for evidence of defense behavior (blocked attack, detected attack, alert triggered, etc.)
4. Determine if the PROBE produced reliable and verifiable evidence
5. Assign score: 0 or 100

**Justification**: Provide specific log excerpts showing PROBE verification and defense evidence

---

## POST-EXECUTION QUALITY METRIC CALCULATION

Calculate the post-execution quality score:

**Q_post = 0.50 × f1 + 0.50 × f2**

Where:
- f1, f2 ∈ {{0, 100}}
- 0 ≤ Q_post ≤ 100

**Execution Validation Threshold**: τ_post = {threshold_post}

**Decision Rule**:
- If Q_post < {threshold_post} → **INVALID** - Experiment results not reliable
- If Q_post ≥ {threshold_post} → **VALID** - Experiment results are reliable

---

## OUTPUT FORMAT

Produce a detailed evaluation report in the following structure:

```markdown
# POST-EXECUTION QUALITY EVALUATION REPORT

## Experiment Information
- **SCE Node**: {sce_node}
- **Probe Type**: {probe_type}
- **Attack Nodes**: {attack_nodes}
- **Evaluation Date**: [Current timestamp]

## Factor 1: Effectiveness of the ACTION in Executing the Attack
**Score**: [0 | 100]

**Analysis**:
- Evidence of ACTION execution: [description]
- Attack indicators found: [list specific log entries]
- Verification status: [Verifiable | Not Verifiable]

**Log Excerpts**:
```
[Relevant excerpts from output log showing ACTION execution]
```

**Justification**: [Detailed explanation of why this score was assigned]

---

## Factor 2: PROBE Capability to Verify and Report the Attack Outcome
**Score**: [0 | 100]

**Analysis**:
- PROBE verification results: [description]
- Defense behavior evidence: [description]
- Observable indicators: [logs, alerts, metrics found]
- Reliability assessment: [assessment]

**Log Excerpts**:
```
[Relevant excerpts from output log showing PROBE verification]
```

**Justification**: [Detailed explanation of why this score was assigned]

---

## FINAL SCORE CALCULATION

**Q_post = 0.50 × f1 + 0.50 × f2**
**Q_post = 0.50 × [f1] + 0.50 × [f2]**
**Q_post = [calculated value]**

**Threshold**: {threshold_post}
**Result**: Q_post [>=|<] {threshold_post}

## DECISION

**[VALID EXECUTION | INVALID EXECUTION]**

[If INVALID, explain what evidence was missing or insufficient]

---

## Detailed Observations

[Any additional observations about the experiment execution]

## Recommendations

[Suggestions for improving experiment execution or observability if Q_post < threshold]
```

**IMPORTANT**: Be thorough and precise. Examine the actual log output carefully. Quote specific lines from the log to support your scores. If evidence is ambiguous or missing, explain what would be needed for a higher score.
"""

    def _save_sce_experiment_output(self, response_text: str, sce_node : str, probe_type : str) -> bool:
        """Extract and save Python script and JSON manifest from response"""
        try:
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)

            # Extract Python script
            python_start = response_text.find("```python")
            if python_start != -1:
                python_start += 9
                python_end = response_text.find("```", python_start)
                if python_end != -1:
                    python_content = response_text[python_start:python_end].strip()
                    python_filename = f"{safe_sce_node}_{safe_probe_type}.py"
                    python_filepath = os.path.join(self.workspace_path, python_filename)
                    
                    # Save to workspace
                    with open(python_filepath, 'w', encoding='utf-8') as f:
                        f.write(python_content)
                    print(f"✅ Python script saved to: {python_filepath}")
                    
                    # Copy to chaosaws.ec2 directory
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
                    json_filepath = os.path.join(self.workspace_path, f"{safe_sce_node}_{safe_probe_type}.json")
                    with open(json_filepath, 'w', encoding='utf-8') as f:
                        f.write(json_content)
                    print(f"✅ JSON manifest saved to: {json_filepath}")
                    return True
            
            return False
        except Exception as e:
            print(f"❌ Error saving SCE experiment files: {e}")
            return False   

    def _save_metrics_report(self, response_text: str, sce_node: str, probe_type: str) -> bool:
        """Extract and save metrics evaluation report from response"""
        try:
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)
            
            # Try to find markdown code block first
            report_start = response_text.find("```markdown")
            if report_start != -1:
                report_start += 11  # Skip ```markdown
                report_end = response_text.find("```", report_start)
                if report_end != -1:
                    report_content = response_text[report_start:report_end].strip()
                else:
                    # If no closing ```, take everything after ```markdown
                    report_content = response_text[report_start:].strip()
            else:
                # If no markdown block, look for the report starting with "# PRE-EXECUTION"
                report_start = response_text.find("# PRE-EXECUTION QUALITY EVALUATION REPORT")
                if report_start != -1:
                    report_content = response_text[report_start:].strip()
                else:
                    # Use the entire response as the report
                    report_content = response_text.strip()
            
            # Save the report with new naming convention
            report_filename = f"pre_execution_report_{safe_sce_node}_{safe_probe_type}.md"
            report_filepath = os.path.join(self.workspace_path, report_filename)
            
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            print(f"✅ Pre-execution report saved to: {report_filepath}")
            
            # Try to extract Q_pre score and decision
            # Look for the final calculated value, not the formula coefficients
            # Pattern matches lines like: "**Q_pre = 85.00**" or "Q_pre = 85.00" or just the final calculated value
            q_pre_patterns = [
                r'Q_pre\s*=\s*0\.40\s*×\s*\d+\s*\+\s*0\.30\s*×\s*\d+\s*\+\s*0\.30\s*×\s*\d+\s*=\s*([0-9.]+)',  # Full calculation
                r'\*\*Q_pre\s*=\s*([0-9.]+)\*\*',  # Bold final value
                r'Q_pre\s*=\s*\*\*([0-9.]+)\*\*',  # Value in bold
                r'calculated value\]:\s*\*\*([0-9.]+)\*\*',  # [calculated value]: **XX**
                r'Q_pre.*?=.*?([0-9]{2,3}\.[0-9]{2})\s*(?:\n|$|<|>|\*)',  # General pattern looking for 2-3 digit decimal
            ]
            
            q_pre_score = None
            for pattern in q_pre_patterns:
                q_pre_match = re.search(pattern, report_content, re.MULTILINE | re.DOTALL)
                if q_pre_match:
                    try:
                        extracted_value = float(q_pre_match.group(1))
                        # Validate it's a reasonable score (0-100)
                        if 0 <= extracted_value <= 100 and extracted_value != 0.40 and extracted_value != 0.30:
                            q_pre_score = extracted_value
                            break
                    except (ValueError, IndexError):
                        continue
            
            if q_pre_score is not None:
                print(f"📊 Quality Score (Q_pre): {q_pre_score:.2f}/100")
            else:
                print("⚠️ Could not extract Q_pre score from report")
            
            # Extract decision
            decision_match = re.search(r'\*\*\[(AUTHORIZE EXECUTION|STOP[^\]]*)\]\*\*', report_content)
            
            if decision_match:
                decision = decision_match.group(1)
                if "AUTHORIZE" in decision:
                    print(f"✅ Decision: {decision}")
                else:
                    print(f"⚠️ Decision: {decision}")
                    print("   Experiment quality below threshold. Review report for recommendations.")
            
            return True, q_pre_score  # Return both success status and score
            
        except Exception as e:
            print(f"❌ Error saving metrics report: {e}")
            return False, None

    def _save_metrics_post_report(self, response_text: str, sce_node: str, probe_type: str) -> tuple:
        """Extract and save post-execution metrics evaluation report from response"""
        try:
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)
            
            # Try to find markdown code block first
            report_start = response_text.find("```markdown")
            if report_start != -1:
                report_start += 11  # Skip ```markdown
                report_end = response_text.find("```", report_start)
                if report_end != -1:
                    report_content = response_text[report_start:report_end].strip()
                else:
                    report_content = response_text[report_start:].strip()
            else:
                # Look for the report starting with "# POST-EXECUTION"
                report_start = response_text.find("# POST-EXECUTION QUALITY EVALUATION REPORT")
                if report_start != -1:
                    report_content = response_text[report_start:].strip()
                else:
                    report_content = response_text.strip()
            
            # Save the report
            report_filename = f"post_execution_report_{safe_sce_node}_{safe_probe_type}.md"
            report_filepath = os.path.join(self.workspace_path, report_filename)
            
            with open(report_filepath, 'w', encoding='utf-8') as f:
                f.write(report_content)
            
            print(f"✅ Post-execution report saved to: {report_filepath}")
            
            # Try to extract Q_post score and decision
            # Look for patterns specific to Q_post
            q_post_patterns = [
                r'Q_post\s*=\s*0\.50\s*×\s*\d+\s*\+\s*0\.50\s*×\s*\d+\s*=\s*([0-9.]+)',  # Full calculation
                r'\*\*Q_post\s*=\s*([0-9.]+)\*\*',  # Bold final value
                r'Q_post\s*=\s*\*\*([0-9.]+)\*\*',  # Value in bold
                r'calculated value\]:\s*\*\*([0-9.]+)\*\*',  # [calculated value]: **XX**
                r'Q_post.*?=.*?([0-9]{1,3}\.?[0-9]{0,2})\s*(?:\n|$|<|>|\*)',  # General pattern
            ]
            
            q_post_score = None
            for pattern in q_post_patterns:
                q_post_match = re.search(pattern, report_content, re.MULTILINE | re.DOTALL)
                if q_post_match:
                    try:
                        extracted_value = float(q_post_match.group(1))
                        # Validate it's a reasonable score (0-100)
                        if 0 <= extracted_value <= 100 and extracted_value != 0.50:
                            q_post_score = extracted_value
                            break
                    except (ValueError, IndexError):
                        continue
            
            if q_post_score is not None:
                print(f"📊 Post-Execution Quality Score (Q_post): {q_post_score:.2f}/100")
            else:
                print("⚠️ Could not extract Q_post score from report")
            
            # Extract decision
            decision_match = re.search(r'\*\*\[(VALID EXECUTION|INVALID EXECUTION)\]\*\*', report_content)
            
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
            # Find DOT content between ```dot and ```
            dot_start = response_text.find("```dot")
            if dot_start == -1:
                dot_start = response_text.find("digraph")
            else:
                dot_start += 6  # Skip ```dot
                
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
        """Call Amazon Q API with prompt and conversation context"""
        try:
            # Build full prompt with complete context if requested
            if use_context and self.conversation_history:
                context = "\n\n".join([f"Previous: {item['prompt']}\nResponse: {item['response']}" for item in self.conversation_history])
                full_prompt = f"{context}\n\nCurrent: {prompt}"
            else:
                full_prompt = prompt
            
            response = self.bedrock.converse(
                modelId="global.anthropic.claude-opus-4-5-20251101-v1:0",
                messages=[
                    {
                        "role" : "user",
                        "content" : [
                            {
                                "text" : full_prompt
                            }
                        ]
                    }
                ],
                inferenceConfig={
                    "maxTokens" : 64000,
                    "temperature" : 0.1,
                },
            )

            response_text = response["output"]["message"]["content"][0]["text"] 

            """response = self.bedrock.invoke_model(
                modelId='global.anthropic.claude-sonnet-4-5-20250929-v1:0',
                body=json.dumps({
                    'anthropic_version': 'bedrock-2023-05-31',
                    'max_tokens': 64000,
                    'temperature': 0.1,
                    'messages': [
                        {
                            'role': 'user',
                            'content': full_prompt
                        }
                    ]
                }) 
            )
            
            result = json.loads(response['body'].read())
            response_text = result['content'][0]['text']"""
            
            if use_context:
                # Store in conversation history
                self.conversation_history.append({
                    'prompt': prompt,
                    'response': response_text
                })
            
            return response_text
            
        except Exception as e:
            print(f"❌ API Error: {e}")
            return None # type: ignore


    def run_automated_conversation(self, mission_yaml: str, threat_intelligence: str, 
                                 attack_yaml: str, structure_dot: str):
        """Run automated conversation with Amazon Q"""
        
        print("🚀 Starting Automated SCE Conversation with Amazon Q")
        
        # Stage 1: Analyze Mission
        print(f"\n📁 Loading mission configuration from {mission_yaml}...")
        if not self._load_yaml(mission_yaml):
            print("❌ Failed to load mission configuration")
            return
        
        # Stage 1: Analyze Mission from YAML
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
        
        # Stage 2: Generate Attack YAML
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
        
        # Stage 3: Build Attack-Defense Tree
        print(f"\n🌳 Stage 3: Building attack-defense tree with safeguard logic...")
        
        # Load attacks.yaml and structure.dot files
        attacks_yaml_path = os.path.join(self.workspace_path, "attacks.yaml")
        attacks_yaml_content = self._load_file(attacks_yaml_path)
        if not attacks_yaml_content:
            print("❌ Failed to load attacks.yaml file")
            return
        
        structure_dot_content = self._load_file(structure_dot)
        if not structure_dot_content:
            print("❌ Failed to load structure.dot file")
            return
        
        # Build attack-defense tree prompt
        tree_prompt = self._build_attack_defense_tree_prompt(attacks_yaml_content, structure_dot_content)
        
        stage3_response = self._call_amazon_q(tree_prompt, use_context=True)
        
        if not stage3_response:
            print("❌ Failed to generate attack-defense tree")
            return
        
        if not self._save_dot_output(stage3_response):
            print("❌ Failed to save DOT output")
            return
            
        print("✅ Attack-defense tree generated and saved as DOT file")

        # Stage 4: Generate SCE experiments (loop)
        print("\n🧪 Stage 4: Generating SCE experiments...")
        
        # Ask for quality thresholds once at the beginning
        print("\n📊 Enter quality threshold for pre-execution metrics (0-100, default=80):")
        threshold_input = input("> ").strip()
        try:
            quality_threshold = int(threshold_input) if threshold_input else 80
            if quality_threshold < 0 or quality_threshold > 100:
                print("⚠️ Invalid threshold. Using default: 80")
                quality_threshold = 80
            else:
                print(f"✅ Pre-execution quality threshold set to: {quality_threshold}")
        except ValueError:
            print("⚠️ Invalid input. Using default threshold: 80")
            quality_threshold = 80
        
        print("\n📊 Enter quality threshold for post-execution metrics (0-100, default=100):")
        threshold_post_input = input("> ").strip()
        try:
            quality_threshold_post = int(threshold_post_input) if threshold_post_input else 100
            if quality_threshold_post < 0 or quality_threshold_post > 100:
                print("⚠️ Invalid threshold. Using default: 100")
                quality_threshold_post = 100
            else:
                print(f"✅ Post-execution quality threshold set to: {quality_threshold_post}")
        except ValueError:
            print("⚠️ Invalid input. Using default threshold: 100")
            quality_threshold_post = 100
                
        while True:
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
                continue
            
            # Check for existing log file
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)
            log_filename = f"last_report_{safe_sce_node}_{safe_probe_type}.log"
            log_path = os.path.join(self.workspace_path, log_filename)
            
            previous_log = None
            if os.path.exists(log_path):
                print(f"\n📝 Found existing execution log: {log_filename}")
                print("   This log will be used to improve the experiment generation.")
                try:
                    with open(log_path, 'r', encoding='utf-8') as f:
                        previous_log = f.read()
                    print(f"✅ Loaded previous execution log ({len(previous_log)} characters)")
                except Exception as e:
                    print(f"⚠️ Could not read log file: {e}")
                    previous_log = None
            else:
                print(f"\n💡 No previous execution log found ({log_filename})")
            
            # Check for existing pre-execution metrics report
            metrics_report_filename = f"pre_execution_report_{safe_sce_node}_{safe_probe_type}.md"
            metrics_report_path = os.path.join(self.workspace_path, metrics_report_filename)
            
            previous_metrics_report = None
            if os.path.exists(metrics_report_path):
                print(f"\n📊 Found existing pre-metrics report: {metrics_report_filename}")
                print("   This report will be used to improve quality scores.")
                try:
                    with open(metrics_report_path, 'r', encoding='utf-8') as f:
                        previous_metrics_report = f.read()
                    print(f"✅ Loaded previous metrics report ({len(previous_metrics_report)} characters)")
                except Exception as e:
                    print(f"⚠️ Could not read metrics report: {e}")
                    previous_metrics_report = None
            else:
                print(f"💡 No previous pre-metrics report found ({metrics_report_filename})")
            
            # Check for existing post-execution metrics report
            post_metrics_report_filename = f"post_execution_report_{safe_sce_node}_{safe_probe_type}.md"
            post_metrics_report_path = os.path.join(self.workspace_path, post_metrics_report_filename)
            
            previous_post_metrics_report = None
            if os.path.exists(post_metrics_report_path):
                print(f"\n📊 Found existing post-metrics report: {post_metrics_report_filename}")
                print("   This report will be used to improve experiment observability.")
                try:
                    with open(post_metrics_report_path, 'r', encoding='utf-8') as f:
                        previous_post_metrics_report = f.read()
                    print(f"✅ Loaded previous post-metrics report ({len(previous_post_metrics_report)} characters)")
                except Exception as e:
                    print(f"⚠️ Could not read post-metrics report: {e}")
                    previous_post_metrics_report = None
            else:
                print(f"💡 No previous post-metrics report found ({post_metrics_report_filename})")
            
            if not previous_log and not previous_metrics_report and not previous_post_metrics_report:
                print("   Generating experiment from scratch.")
            
            sce_prompt = self._build_sce_experiment_prompt(sce_node, probe_type, attack_nodes, template_json_content, previous_log, previous_metrics_report, previous_post_metrics_report)
            
            sce_response = self._call_amazon_q(sce_prompt, use_context=True)
            
            if not sce_response:
                print("❌ Failed to generate SCE experiment")
                continue
            
            if not self._save_sce_experiment_output(sce_response, sce_node, probe_type):
                print("❌ Failed to save SCE experiment files")
                continue
                
            print("✅ SCE experiment generated and saved")
            
            # Stage 4b: Pre-execution quality evaluation
            print("\n📊 Evaluating pre-execution quality metrics...")
            
            # Load the generated files for evaluation
            safe_sce_node = self._sanitize_name(sce_node)
            safe_probe_type = self._sanitize_name(probe_type)
            
            # Load DOT file (attack_defense_tree.dot)
            dot_filepath = os.path.join(self.workspace_path, "attack_defense_tree.dot")
            dot_content = self._load_file(dot_filepath)
            if not dot_content:
                print("⚠️ Could not load DOT file for metrics evaluation")
                dot_content = "# DOT file not available"
            
            # Load JSON file (experiment manifest)
            json_filepath = os.path.join(self.workspace_path, f"{safe_sce_node}_{safe_probe_type}.json")
            json_content = self._load_file(json_filepath)
            if not json_content:
                print("⚠️ Could not load JSON file for metrics evaluation")
                json_content = "{}"
            
            # Load Python file (experiment implementation)
            py_filepath = os.path.join(self.workspace_path, f"{safe_sce_node}_{safe_probe_type}.py")
            py_content = self._load_file(py_filepath)
            if not py_content:
                print("⚠️ Could not load Python file for metrics evaluation")
                py_content = "# Python file not available"
            
            # Build metrics evaluation prompt with dynamic threshold
            metrics_prompt = self._build_metrics_prompt(dot_content, json_content, py_content, sce_node, probe_type, attack_nodes, quality_threshold)
            
            # Call LLM for metrics evaluation
            metrics_response = self._call_amazon_q(metrics_prompt, use_context=False)
            
            q_pre_score = None
            if metrics_response:
                save_success, q_pre_score = self._save_metrics_report(metrics_response, sce_node, probe_type)
                if save_success:
                    print("✅ Pre-execution quality evaluation completed")
                else:
                    print("⚠️ Metrics evaluation completed but report save failed")
            else:
                print("⚠️ Failed to generate metrics evaluation")
            
            # Always ask if user wants to generate another experiment (independent of threshold)
            print("\n🔄 Generate another SCE experiment? (y/n):")
            continue_response = input("> ").strip().lower()
            
            if continue_response != 'y':
                # User doesn't want to generate another experiment
                # Check if quality threshold was met and ask about execution
                if q_pre_score is not None and q_pre_score >= quality_threshold:
                    print(f"\n✅ Quality threshold met (Q_pre={q_pre_score:.2f} >= {quality_threshold})")
                    print(f"🚀 Execute this experiment now? (y/n):")
                    execute_response = input("> ").strip().lower()
                    
                    if execute_response == 'y':
                        json_filename = f"{safe_sce_node}_{safe_probe_type}.json"
                        json_filepath = os.path.join(self.workspace_path, json_filename)
                        log_filename = f"output_{safe_sce_node}_{safe_probe_type}.log"
                        log_filepath = os.path.join(self.workspace_path, log_filename)
                        
                        print(f"\n▶️ Executing: chaos run {json_filename}")
                        print(f"📝 Output will be saved to: {log_filename}")
                        print("=" * 60)
                        
                        execution_successful = False
                        try:
                            import subprocess
                            result = subprocess.run(
                                ['chaos', 'run', json_filepath],
                                cwd=self.workspace_path,
                                capture_output=True,
                                text=True
                            )
                            
                            # Save output to log file
                            combined_output = f"STDOUT:\n{result.stdout}\n\nSTDERR:\n{result.stderr}\n\nRETURN CODE: {result.returncode}"
                            with open(log_filepath, 'w', encoding='utf-8') as f:
                                f.write(combined_output)
                            
                            print(result.stdout)
                            if result.stderr:
                                print("Errors/Warnings:")
                                print(result.stderr)
                            
                            if result.returncode == 0:
                                print("=" * 60)
                                print("✅ Experiment execution completed successfully")
                                print(f"✅ Execution log saved to: {log_filepath}")
                                execution_successful = True
                            else:
                                print("=" * 60)
                                print(f"⚠️ Experiment execution finished with return code: {result.returncode}")
                                print(f"✅ Execution log saved to: {log_filepath}")
                                execution_successful = True  # Still evaluate even if return code != 0
                                
                        except FileNotFoundError:
                            print("❌ 'chaos' command not found. Please install chaostoolkit:")
                            print("   pip install chaostoolkit chaostoolkit-aws")
                        except Exception as e:
                            print(f"❌ Error executing experiment: {e}")
                        
                        # Post-execution quality evaluation
                        if execution_successful and os.path.exists(log_filepath):
                            print("\n📊 Evaluating post-execution quality metrics...")
                            
                            # Load the execution log
                            output_log = self._load_file(log_filepath)
                            if output_log:
                                # Build post-execution metrics prompt
                                metrics_post_prompt = self._build_metrics_post_prompt(
                                    output_log, sce_node, probe_type, attack_nodes, quality_threshold_post
                                )
                                
                                # Call LLM for post-execution evaluation
                                metrics_post_response = self._call_amazon_q(metrics_post_prompt, use_context=False)
                                
                                if metrics_post_response:
                                    save_success, q_post_score = self._save_metrics_post_report(
                                        metrics_post_response, sce_node, probe_type
                                    )
                                    if save_success:
                                        print("✅ Post-execution quality evaluation completed")
                                    else:
                                        print("⚠️ Post-execution evaluation completed but report save failed")
                                else:
                                    print("⚠️ Failed to generate post-execution metrics evaluation")
                            else:
                                print("⚠️ Could not load execution log for post-evaluation")
                    else:
                        print("💡 Experiment not executed. You can run it manually with:")
                        print(f"   chaos run {safe_sce_node}_{safe_probe_type}.json > output_{safe_sce_node}_{safe_probe_type}.log 2>&1")
                
                elif q_pre_score is not None and q_pre_score < quality_threshold:
                    print(f"\n⚠️ Quality threshold not met (Q_pre={q_pre_score:.2f} < {quality_threshold})")
                    print("   Review the pre-execution report for recommendations before executing.")
                else:
                    print("\n💡 No quality score available for execution decision.")
                
                break
            
            # If continuing, ask if they want to include the current reports
            print("\n📊 Include the pre-execution report from this experiment in the next generation? (y/n):")
            include_pre_report = input("> ").strip().lower()
            
            if include_pre_report == 'y':
                print("✅ The pre-execution report will be available for the next experiment generation.")
            else:
                print("💡 The next experiment will be generated without the pre-execution report.")
            
            # Also ask about post-execution report if it exists
            post_report_exists = os.path.exists(os.path.join(self.workspace_path, f"post_execution_report_{safe_sce_node}_{safe_probe_type}.md"))
            if post_report_exists:
                print("\n📊 Include the post-execution report from this experiment in the next generation? (y/n):")
                include_post_report = input("> ").strip().lower()
                
                if include_post_report == 'y':
                    print("✅ The post-execution report will be available for the next experiment generation.")
                else:
                    print("💡 The next experiment will be generated without the post-execution report.")

        print("🎉 All SCE experiments completed!")



def test_bedrock_connection() -> bool:
    """Comprehensive test of Bedrock connection and functionality"""
    print("🧪 Testing Bedrock Connection")
    print("=" * 40)
    
    # Test 1: AWS Credentials
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
    
    # Test 2: Bedrock Client
    print("\n2️⃣ Creating Bedrock client...")
    try:
        bedrock = boto3.client('bedrock-runtime')
        print("✅ Bedrock client created successfully")
    except Exception as e:
        print(f"❌ Client creation failed: {e}")
        return False
    
    # Test 3: Model Access
    print("\n3️⃣ Testing model access...")
    try:
        bedrock_models = boto3.client('bedrock')
        models = bedrock_models.list_foundation_models()
        available_models = [m['modelId'] for m in models['modelSummaries']]
        print(f"✅ Found {len(available_models)} available models")
        
        if 'amazon.titan-text-express-v1' in available_models:
            print("✅ Titan Text Express model is available")
        else:
            print("⚠️ Titan Text Express not found in available models")
            print("Available models:", available_models[:3])
    except Exception as e:
        print(f"⚠️ Could not list models: {e}")
    
    # Test 4: Simple Model Invocation
    print("\n4️⃣ Testing model invocation...")
    try:
        response = bedrock.invoke_model(
            modelId='amazon.titan-text-express-v1',
            body=json.dumps({
                'inputText': 'Hello, this is a test. Respond with "Test successful".',
                'textGenerationConfig': {
                    'maxTokenCount': 50,
                    'temperature': 0.1
                }
            })
        )
        
        result = json.loads(response['body'].read())
        output_text = result['results'][0]['outputText']
        
        print("✅ Model invocation successful")
        print(f"📝 Response: {output_text.strip()[:100]}...")
        return True
        
    except Exception as e:
        print(f"❌ Model invocation failed: {e}")
        print("\n💡 Possible solutions:")
        print("   - Check model access in Bedrock console")
        print("   - Verify IAM permissions for bedrock:InvokeModel")
        print("   - Ensure you're in a supported region")
        return False

def interactive_input():
    """Get inputs interactively from user"""
    print("🤖 SCE API Automation with Amazon Q")
    print("====================================")
    print("")
    
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
    automation.run_automated_conversation(mission_yaml, threat_intelligence, attack_yaml, structure_dot)

def run_test():
    print("🚀 Running Tests")
    print("=" * 30)
    
    # Test 1: Connection
    print("\n1️⃣ Testing connection...")
    connection_ok = test_bedrock_connection()
    
    if not connection_ok:
        print("❌ Connection failed. Cannot proceed with file tests.")
        return False
    
    if connection_ok:
        print("\n🎉 All tests passed!")
        return True
    else:
        print("\n❌ Some tests failed. Check the output above.")
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--test":
        run_test()
    else:
        main()