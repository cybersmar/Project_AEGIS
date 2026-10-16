import json
from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate

def run_mitre_agent():
    print("🧠 Waking up the MITRE ATT&CK AI Agent...")

    # 1. Conectar ao "Cérebro" (Llama 3 local)
    # Mantemos a temperature=0 para evitar que a IA invente técnicas que não existem no MITRE
    llm = OllamaLLM(model="llama3", base_url="http://localhost:11434", temperature = 0)

# 2. Engenharia do Prompt (Few-Shot Prompting)
    template = """You are a Senior Cyber Threat Intelligence (CTI) Analyst expert in the MITRE ATT&CK framework.
Your task is to analyze the following shell command executed by an attacker on a compromised Linux system.

Map the command to the most relevant MITRE ATT&CK Tactic and Technique.

RULES:
1. Return ONLY a valid JSON object. No markdown, no explanations before or after.
2. ALL string values, including the technique_id, MUST be enclosed in double quotes.
3. Use the exact keys: "tactic", "technique_id", "technique_name", and "confidence".

EXAMPLE:
Attacker Command: cat /etc/passwd; cat /etc/shadow
JSON Output:
{{
    "tactic": "Credential Access",
    "technique_id": "T1003.008",
    "technique_name": "OS Credential Dumping: /etc/passwd and /etc/shadow",
    "confidence": "High"
}}

Attacker Command: {command}

JSON Output:"""

    prompt = PromptTemplate(input_variables=["command"], template=template)
    
    # Criar o pipeline
    chain = prompt | llm

    print("\n🕵️ Agent Online! Insere o comando capturado (ou 'exit' para sair).")

    # 3. O Loop de Teste Interativo
    while True:
        attacker_cmd = input("\nComando do Atacante: ")
        
        if attacker_cmd.lower() == 'exit':
            break
            
        print("A processar a inteligência...")
        
        try:
            # Invocar o LLM
            raw_response = chain.invoke({"command": attacker_cmd}).strip()
            
            # Tentar limpar qualquer lixo que a IA possa ter adicionado acidentalmente
            clean_json = raw_response.replace("```json", "").replace("```", "").strip()
            
            # Converter o texto da IA num dicionário Python real
            mitre_mapping = json.loads(clean_json)
            
            print("\n✅ MITRE Mapping Completo:")
            print(json.dumps(mitre_mapping, indent=4))
            
        except json.JSONDecodeError:
            print("\n❌ Erro: O Agente não devolveu um JSON válido. Resposta em bruto:")
            print(raw_response)
        except Exception as e:
            print(f"\n❌ Erro inesperado: {e}")

if __name__ == "__main__":
    run_mitre_agent()