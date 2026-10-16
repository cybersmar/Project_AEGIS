import json
import requests
import os
import sys
import re

# --- Configuration (Environment Variables) ---
API_KEY = os.getenv("OTX_API_KEY")
INPUT_FILE = os.getenv("INPUT_LOG_PATH", "/app/data/cowrie.json")
OUTPUT_FILE = os.getenv("OUTPUT_LOG_PATH", "/app/data/cowrie_enriched.json")
BASE_URL = "https://otx.alienvault.com/api/v1/indicators/IPv4/{}/general"
LLAMA_API_URL = "http://host.docker.internal:11434/api/generate" # Endpoint do LLM Local

# --- Nova Função do Agente MITRE ---
def get_mitre_mapping(command):
    prompt = f"""You are a Cyber Threat Intelligence Analyst mapping Linux honeypot commands to MITRE ATT&CK.
RULES: Return ONLY valid JSON. All strings in double quotes. No extra text.

CHEATSHEET:
- Download files (wget, curl) -> Tactic: "Command and Control", ID: "T1105", Name: "Ingress Tool Transfer"
- Check passwords (cat /etc/passwd) -> Tactic: "Credential Access", ID: "T1003.008", Name: "OS Credential Dumping"
- Check current user (whoami, id) -> Tactic: "Discovery", ID: "T1033", Name: "System Owner/User Discovery"
- System info (uname, cat /proc/cpuinfo) -> Tactic: "Discovery", ID: "T1082", Name: "System Information Discovery"
- Clear logs (rm, history -c) -> Tactic: "Defense Evasion", ID: "T1070", Name: "Indicator Removal"
- Normal session close (exit, logout) -> Tactic: "None", ID: "None", Name: "Session Exit"

Command: {command}
JSON Output:"""

    payload = {
        "model": "qwen2.5:14b",
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0}
    }
    
    try:
        # Aumentei o timeout para 30s. A primeira vez que o modelo acorda, pode demorar!
        response = requests.post(LLAMA_API_URL, json=payload, timeout=30)
        
        if response.status_code == 200:
            raw_text = response.json().get("response", "").strip()
            
            # 🐞 MODO DEBUG: Imprime o que a IA disse realmente
            print(f"\n[DEBUG LLAMA] Resposta Bruta:\n{raw_text}\n")
            
            # 🛡️ MODO BLINDADO: Regex para extrair apenas o conteúdo entre { e }
            match = re.search(r'\{.*\}', raw_text, re.DOTALL)
            if match:
                clean_json = match.group(0)
                return json.loads(clean_json)
            else:
                print("⚠️ A IA não gerou nenhum bloco de JSON válido.")
                
    except Exception as e:
        print(f"⚠️ Erro ao processar IA: {e}")
        
    return {"tactic": "Unknown", "technique_id": "Unknown", "technique_name": "Unknown"}


# --- Lógica Principal de Enriquecimento ---
def enrich_data():
    if not API_KEY:
        print("❌ ERRO CRÍTICO: A variável OTX_API_KEY não está configurada.")
        sys.exit(1)

    HEADERS = {"X-OTX-API-KEY": API_KEY}
    
    ip_cache = {}
    mitre_cache = {} # NOVO: Cache para não perguntar o mesmo comando 2x ao Llama!
    
    enriched_logs = []
    
    print("🚀 Starting AlienVault OTX & Llama 3 MITRE Enrichment...")
    
    if not os.path.exists(INPUT_FILE):
        print(f"No {INPUT_FILE} found. Exiting.")
        return
        
    with open(INPUT_FILE, "r") as f:
        for line in f:
            try:
                event = json.loads(line.strip())
                
                # ==========================================
                # 1. ENRIQUECIMENTO ALIENVAULT (IP)
                # ==========================================
                ip = event.get("src_ip")
                if ip and "otx_pulse_count" not in event:
                    if ip not in ip_cache:
                        print(f"🌍 Investigating IP via AlienVault: {ip}...")
                        try:
                            response = requests.get(BASE_URL.format(ip), headers=HEADERS, timeout=5)
                            if response.status_code == 200:
                                data = response.json()
                                ip_cache[ip] = data.get("pulse_info", {}).get("count", 0)
                            else:
                                ip_cache[ip] = 0 
                        except Exception as e:
                            ip_cache[ip] = 0
                            
                    event["otx_pulse_count"] = ip_cache[ip]
                    
                    if ip_cache[ip] == 0:
                        event["risk_level"] = "Low (Clean)"
                    elif ip_cache[ip] < 5:
                        event["risk_level"] = "Medium (Suspicious)"
                    else:
                        event["risk_level"] = "High (Known Botnet)"

                # ==========================================
                # 2. ENRIQUECIMENTO LLAMA 3 (MITRE ATT&CK)
                # ==========================================
                # 1º Passo: Garantir que este evento é um registo de comando
                if event.get("eventid") == "cowrie.command.input":
                    # 2º Passo: Extrair a string do comando usando a chave correta 'input'
                    command_input = event.get("input") 
                    
                    if command_input:
                        if command_input not in mitre_cache:
                            print(f"🧠 Asking Llama 3 to analyze: {command_input[:40]}...")
                            mitre_cache[command_input] = get_mitre_mapping(command_input)
                        
                        # Vai buscar o resultado ao cache e injeta no evento
                        mitre_data = mitre_cache[command_input]
                        event["mitre_tactic"] = mitre_data.get("tactic", "Unknown")
                        event["mitre_technique_id"] = mitre_data.get("technique_id", "Unknown")
                        event["mitre_technique_name"] = mitre_data.get("technique_name", "Unknown")

                enriched_logs.append(event)
                
            except Exception as e:
                continue
                
    with open(OUTPUT_FILE, "w") as f:
        for log in enriched_logs:
            f.write(json.dumps(log) + "\n")
            
    print(f"\n✅ Enrichment Complete! Processed {len(enriched_logs)} events.")
    print(f"📊 IP Cache Size: {len(ip_cache)} | MITRE Cache Size: {len(mitre_cache)}")

if __name__ == "__main__":
    enrich_data()
