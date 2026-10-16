import pandas as pd
import json
import re
import requests
import os
import sys
from dotenv import load_dotenv
load_dotenv(override=True)
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate

# --- Inicialização Segura de Variáveis de Ambiente ---
# Carrega o .env logo no início para garantir que as variáveis estão disponíveis
load_dotenv("/app/data/.env")

API_GATEWAY_URL = os.getenv("API_GATEWAY_URL","https://qe9lgwkza3.execute-api.eu-central-1.amazonaws.com/default/soc-active-response-api")
SOAR_API_KEY = os.getenv("SOAR_API_KEY")
DATA_FILE = os.getenv("CLUSTERED_LOG_PATH", "/app/data/cowrie_clustered.json")

def run_direct_agent():
    # Validação de Segurança
    if not API_GATEWAY_URL or not SOAR_API_KEY:
        print("❌ ERRO CRÍTICO: As variáveis da API AWS SOAR não estão configuradas no .env.")
        sys.exit(1)

    print("📊 Waking up the Custom Data Science Agent (Direct Execution)...")
    
    # 1. Load the Data
    data = []
    try:
        with open(DATA_FILE, "r") as f:
            for line in f:
                try:
                    data.append(json.loads(line.strip()))
                except:
                    continue
    except FileNotFoundError:
        print(f"❌ ERRO: Ficheiro de dados não encontrado em {DATA_FILE}")
        sys.exit(1)

    df = pd.DataFrame(data)
    print(f"✅ Loaded {len(df)} threat events into memory.")
    
    # 2. Connect the Brain
    llm = OllamaLLM(model="llama3", base_url="http://host.docker.internal:11434", temperature=0)
    
    # 3. The Custom System Prompt
    template = """You are a Senior Data Scientist. 
    You have a Pandas DataFrame named 'df'.
    The DataFrame has these columns: {columns}
    
    Write the exact Python Pandas code to answer the Commander's question.
    RULES:
    1. Return ONLY the raw python code. No explanations. No markdown formatting.
    2. The code must be a single line.
    3. SAFE ARRAYS: Never use .index[0] or [0]. Always use .head(1) to get the top result to avoid out-of-bounds errors.
    4. DATA DICTIONARY: The 'risk_level' column contains EXACT strings. You must use these exact strings in your filters:
       - "High (Known Botnet)"
       - "Medium (Suspicious)"
       - "Low (Noise)"
       
    Commander's Question: {question}
    Raw Python Code:"""
    
    prompt = PromptTemplate(input_variables=["columns", "question"], template=template)
    
    # Create the pipeline: Prompt -> LLM
    chain = prompt | llm
    
    print("\n✅ Agent Online! Type 'exit' to quit.")
    
    # 4. The Execution Loop with Human-in-the-Loop (HITL) SOAR
    while True:
        question = input("\nCommander 🕵️‍♂️: ")
        if question.lower() == 'exit':
            break
            
        try:
            print("Translating question to Python...")
            raw_code = chain.invoke({"columns": list(df.columns), "question": question}).strip()
            clean_code = raw_code.replace("```python", "").replace("```", "").strip()
            
            # Execute the mathematical search
            result = eval(clean_code)
            print(f"\nAgent 🤖: \n{result}")
            
            # --- THE SAFETY CATCH (HITL) ---
            # Use Regex to scan the AI's answer to see if an IP address is in it
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            found_ips = ip_pattern.findall(str(result))
            
            if found_ips:
                # Grab the first IP it found
                target_ip = found_ips[0] 
                print(f"\n⚠️ SECURITY ALERT: I identified a Threat Actor IP ({target_ip}) in my findings.")
                
                # Ask the human for permission
                auth = input(f"Do you authorize AWS to drop a Network ACL block on {target_ip}? (yes/no): ")
                
                if auth.lower() == 'yes':
                    print("🚀 Authorization accepted. Firing SOAR payload to AWS API Gateway...")
                    
                    # Attach the badge to the header
                    headers = {
                        "x-api-key": SOAR_API_KEY,
                        "Content-Type": "application/json"
                    }
                    
                    # Pull the trigger!
                    payload = {"ip_address": target_ip}
                    response = requests.post(API_GATEWAY_URL, json=payload, headers=headers)
                    
                    print(f"☁️ AWS Firewall Response: {response.status_code} - {response.text}")
                else:
                    print("🛑 Safety catch engaged. Block aborted by Commander.")
                    
        except Exception as e:
            print(f"\nAgent 🤖: I hit an error processing that request: {e}")

if __name__ == "__main__":
    run_direct_agent()