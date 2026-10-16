from flask import Flask, request
import paramiko
import os
import sys
from dotenv import load_dotenv

# Carregar variáveis de ambiente (útil se correres fora do Docker na fase de testes)
load_dotenv("/app/data/.env")

# --- Configuration (Environment Variables) ---
HOST = os.getenv("TAILSCALE_IP")
PORT = int(os.getenv("SSH_PORT"))
USER = os.getenv("SSH_USER")
KEY_FILE = os.getenv("SSH_KEY_PATH")

app = Flask(__name__)

# Validação de Segurança no arranque do serviço
if not HOST or not KEY_FILE:
    print("❌ ERRO CRÍTICO: As credenciais SSH/Tailscale não estão configuradas no .env.")
    sys.exit(1)

@app.route('/ban')
def ban_ip():
    ip = request.args.get('ip')
    if not ip:
        return "No IP provided", 400

    print(f"Target locked: Initiating ban for IP {ip}...")

    try:
        # Load your AWS Zero-Trust Key
        key = paramiko.RSAKey.from_private_key_file(KEY_FILE)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Connect to the AWS server via the Tailscale VPN backdoor
        client.connect(hostname=HOST, port=PORT, username=USER, pkey=key)
        
        # Docker bypasses standard UFW firewalls, so we must add the drop rule 
        # directly to the DOCKER-USER iptables chain to ensure the IP is blocked.
        command = f"sudo iptables -I DOCKER-USER -s {ip} -j DROP"
        stdin, stdout, stderr = client.exec_command(command)
        
        error = stderr.read().decode()
        if error:
            client.close()
            return f"❌ ERROR from AWS Firewall: {error}", 500
            
        client.close()
        return f"✅ SUCCESS: IP {ip} has been permanently banned at the AWS Firewall level.", 200

    except Exception as e:
        return f"❌ SYSTEM FAILURE: {str(e)}", 500

if __name__ == '__main__':
    # Listen on all interfaces inside the container, but Docker will restrict it to localhost
    app.run(host='0.0.0.0', port=5000)