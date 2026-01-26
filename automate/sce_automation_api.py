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
            
        return f"""Please populate the template using the threat intelligence information provided.

            THREAT INTELLIGENCE:
            {threat_intelligence}

            TEMPLATE TO POPULATE:
            {self.attack_template}

            Instructions:
            - Use the threat intelligence to fill all template fields
            - Keep the exact template structure
            - Return the completed YAML in your response"""

    def _build_attack_defense_tree_prompt(self, attacks_yaml: str, structure_dot: str) -> str:
        """Build the attack-defense tree generation prompt"""
        return f"""Imagine you are a lead cyber-defense analyst tasked with turning raw intelligence into actionable insight for senior leadership and incident-response teams. Under this premise:

    - Start from the detailed scenario and safeguard logic classes (Preventive, Detective, Reactive) you have already defined and stored.
    - Scrutinize the attacks described in the attached file attacks.md.
    - Consider, integrate, and visualize possible countermeasures for that scenario using the previously defined safeguard logic.
    - Follow the hierarchy, connectors and colors defined in the attached file structure.dot as your base template.

    Your assignment is to:

    1. Build the attack-defense tree
    - Construct an attack-defense tree that, from root to attack goal, explicitly shows every command, dependency, result and TTP from attacks.md
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
    - Group the resulting attack–defense tree into numeric branches (for example: branch 1.x, 2.x, etc.) that reflect distinct attack paths and their associated safeguards.
    - Output the final result in DOT format, ready for rendering, using the hierarchy, connectors, and color conventions defined in structure.dot.
    - Ensure all special characters are properly escaped as in standard HTML to avoid rendering problems in downstream visualization tools.

    ATTACKS FILE CONTENT:
    {attacks_yaml}

    STRUCTURE DOT TEMPLATE:
    {structure_dot}
    """

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
            
            response = self.bedrock.invoke_model(
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
            response_text = result['content'][0]['text']
            
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