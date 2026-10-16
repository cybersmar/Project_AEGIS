import paramiko
import os
import sys

# --- Configuration (Environment Variables) ---
# O formato é: os.getenv("NOME_DA_VARIAVEL", "valor_por_defeito_opcional")

HOST = os.getenv("TAILSCALE_IP")
PORT = int(os.getenv("SSH_PORT", 2222))  # Por defeito 2222
USER = os.getenv("SSH_USER", "ubuntu")   # Por defeito ubuntu
KEY_FILE = os.getenv("SSH_KEY_PATH", "/app/data/istecaws.pem")
LOCAL_LOG_PATH = os.getenv("LOCAL_LOG_PATH", "/app/data/cowrie.json")

def fetch_logs():
    # Validação de Segurança: Impedir execução cega
    if not HOST:
        print("❌ ERRO CRÍTICO: A variável TAILSCALE_IP não está configurada.")
        sys.exit(1)

    print(f"Connecting to AWS {HOST}:{PORT} via Tailscale VPN...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    
    try:
        # 1. Drive through the tunnel
        ssh.connect(hostname=HOST, port=PORT, username=USER, key_filename=KEY_FILE)
        print("Extracting JSON logs from the honeypot container...")
        
        # 2. Tell AWS to extract the log file from the honeypot and print it out
        command = "sudo docker cp cowrie:/cowrie/cowrie-git/var/log/cowrie/cowrie.json /tmp/cowrie.json && cat /tmp/cowrie.json"
        stdin, stdout, stderr = ssh.exec_command(command)
        
        # 3. Read the data
        log_data = stdout.read().decode('utf-8')
        
        # 4. Save it locally for ELK
        if log_data:
            with open(LOCAL_LOG_PATH, "w") as f:
                f.write(log_data)
            print(f"Success! Threat data securely downloaded to {LOCAL_LOG_PATH}.")
        else:
            print("No data found. Error:", stderr.read().decode('utf-8'))
            
    except Exception as e:
        print(f"Connection failed: {e}")
    finally:
        ssh.close()

if __name__ == "__main__":
    fetch_logs()