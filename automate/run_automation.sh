#!/bin/bash

# SCE Automation Interactive Runner Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if ! command -v python3 &> /dev/null; then
    echo "❌ Python 3 is required but not installed"
    exit 1
fi

echo "🚀 SCE Automation Interactive Setup"
echo "====================================="
echo ""

echo "📋 Enter Mission & Tech Stack description:"
read -p "> " MISSION_TEXT

echo ""
echo "🎯 Enter Threat Intelligence description:"
read -p "> " THREAT_INTEL_TEXT

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
echo "🚀 Starting SCE Automation"
echo "📋 Mission & Tech Stack: $MISSION_TEXT"
echo "🎯 Threat Intelligence: $THREAT_INTEL_TEXT"
echo "📄 Attack Template PDF: $ATTACK_TEMPLATE_PDF"
echo "🌳 Structure DOT: $STRUCTURE_DOT"
echo ""

python3 sce_automation.py "$MISSION_TEXT" "$THREAT_INTEL_TEXT" "$ATTACK_TEMPLATE_PDF" "$STRUCTURE_DOT" $EXTRA_ARGS

echo ""
echo "✅ Automation complete!"
echo "📁 Check the generated prompt files in: $SCRIPT_DIR"