#!/bin/bash

if [ $# -eq 0 ] || [[ ! $1 == *.json ]]; then
    echo "Error: Must specify a .json experiment as argument"
    echo "Usage: $0 experiment.json"
    exit 1
fi


# Check if venv exists
if [ ! -d "chaostk" ]; then
    echo "Creating venv..."
    python3 -m venv chaostk
    source chaostk/bin/activate
    
    # Instalar dependencias desde requirements.txt
    pip install -r ../requirements.txt
else
    echo "Existing venv, activating..."
    source chaostk/bin/activate
fi

# Obtener la ruta del módulo chaosaws/ec2
MODULE_PATH=$(python3 -c "import chaosaws.ec2; print(chaosaws.ec2.__path__[0])")

# Copiar los archivos al directorio del módulo
cp probes/probes.py "$MODULE_PATH/"
cp actions/actions.py "$MODULE_PATH/"

chaos run $1
