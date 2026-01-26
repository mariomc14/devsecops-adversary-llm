#!/bin/bash

# SCE API Automation Interactive Runner

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

echo "🤖 SCE API Automation with Amazon Q"
echo "===================================="
echo ""

# Check AWS credentials
if [[ -z "$AWS_ACCESS_KEY_ID" || -z "$AWS_SECRET_ACCESS_KEY" ]]; then
    echo "⚠️  AWS credentials not found in environment"
    echo "Please set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY"
    exit 1
fi

echo "📋 Enter Mission & Tech Stack:"
read -p "> " MISSION_TEXT

echo ""
echo "🎯 Enter Threat Intelligence:"
read -p "> " THREAT_INTEL

echo ""
echo "📄 Enter Attack Template PDF filename:"
read -p "> " ATTACK_TEMPLATE_PDF

echo ""
echo "🌳 Enter Structure DOT filename:"
read -p "> " STRUCTURE_DOT

echo ""
read -p "🧪 Generate SCE unit tests? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    EXTRA_ARGS="--with-tests"
else
    EXTRA_ARGS=""
fi

echo ""
echo "🚀 Starting API Automation..."
echo ""

python3 sce_automation_api.py "$MISSION_TEXT" "$THREAT_INTEL" "$ATTACK_TEMPLATE_PDF" "$STRUCTURE_DOT" $EXTRA_ARGS

echo ""
echo "✅ API Automation complete!"