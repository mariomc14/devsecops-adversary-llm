#!/bin/bash

if [ $# -eq 0 ] || [[ ! $1 == *.json ]]; then
    echo "Error: Must specify a .json experiment as argument"
    echo "Usage: $0 experiment.json"
    exit 1
fi

# Check for active virtual environment and exit with error
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Error: Virtual environment is active: $VIRTUAL_ENV"
    echo "Please deactivate it before running this script"
    exit 1
fi


# Check if venv exists
if [ ! -d "chaostk" ]; then
    echo "Creating venv..."
    python3 -m venv chaostk
    source chaostk/bin/activate
    
    # Install dependencies from requirements.txt
    pip install -r requirements.txt
else
    echo "Existing venv, activating..."
    source chaostk/bin/activate
fi

# Obtain the path for chaosaws/ec2 module
MODULE_PATH=$(python3 -c "import chaosaws.ec2; print(chaosaws.ec2.__path__[0])")

# Extract filename without extension and copy corresponding Python file
EXPERIMENT_NAME=$(basename "$1" .json)
cp "$EXPERIMENT_NAME.py" "$MODULE_PATH/"

chaos run $1 --hypothesis-strategy=after-method-only
