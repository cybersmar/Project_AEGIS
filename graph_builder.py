import json
from neo4j import GraphDatabase

# Connect to the Neo4j container via Docker's internal host routing
URI = "bolt://host.docker.internal:7687"
AUTH = ("neo4j", "Palantir123!")

def build_ontology():
    print("Connecting to Neo4j Ontology Database...")
    driver = GraphDatabase.driver(URI, auth=AUTH)
    
    with driver.session() as session:
        
        logins_count = 0
        commands_count = 0
        
        with open("/app/data/cowrie_enriched.json", "r") as f:
            for line in f:
                try:
                    event = json.loads(line.strip())
                    event_id = event.get("eventid")
                    ip = event.get("src_ip", "Unknown")
                    risk = event.get("risk_level", "Unknown")
                    
                    # ==========================================
                    # RAMIFICAÇÃO 1: TENTATIVAS DE LOGIN FALSAS
                    # ==========================================
                    if event_id == "cowrie.login.failed":
                        username = event.get("username", "Unknown")
                        password_attempt = event.get("password", "Unknown")
                        
                        query_login = """
                        MERGE (attacker:IP {address: $ip})
                        ON CREATE SET attacker.risk_level = $risk
                        
                        MERGE (cred:Credential {combo: $username + ':' + $password})
                        MERGE (target:Server {name: "AWS-Honeypot"})
                        
                        MERGE (attacker)-[:TARGETED]->(target)
                        MERGE (attacker)-[:USED_CREDENTIAL]->(cred)
                        """
                        session.run(query_login, ip=ip, username=username, password=password_attempt, risk=risk)
                        logins_count += 1
                        
                    # ==========================================
                    # RAMIFICAÇÃO 2: COMANDOS E MITRE ATT&CK
                    # ==========================================
                    elif event_id == "cowrie.command.input" and event.get("input"):
                        command = event.get("input")
                        tactic = event.get("mitre_tactic", "Unknown")
                        tech_id = event.get("mitre_technique_id", "Unknown")
                        tech_name = event.get("mitre_technique_name", "Unknown")
                        
                        
                        query_mitre = """
                        MERGE (attacker:IP {address: $ip})
                        ON CREATE SET attacker.risk_level = $risk
                        
                        // 🔗 A CORREÇÃO ESTÁ AQUI: Ancorar o atacante ao servidor!
                        MERGE (target:Server {name: "AWS-Honeypot"})
                        MERGE (attacker)-[:TARGETED]->(target)
                        
                        MERGE (cmd:Command {input: $command})
                        MERGE (attacker)-[:EXECUTED]->(cmd)
                        
                        // Criar os nós do MITRE apenas se a IA tiver identificado uma técnica válida
                        FOREACH (_ IN CASE WHEN $tech_id <> 'Unknown' AND $tech_id <> 'None' THEN [1] ELSE [] END |
                            MERGE (tech:Technique {id: $tech_id})
                            ON CREATE SET tech.name = $tech_name
                            
                            MERGE (tac:Tactic {name: $tactic})
                            
                            MERGE (cmd)-[:MAPS_TO]->(tech)
                            MERGE (tech)-[:BELONGS_TO]->(tac)
                        )
                        """
                        session.run(query_mitre, ip=ip, risk=risk, command=command, 
                                    tactic=tactic, tech_id=tech_id, tech_name=tech_name)
                        commands_count += 1
                        
                except Exception as e:
                    print(f"Erro ao processar linha: {e}")
                    continue
                    
    driver.close()
    print(f"✅ Ingestão Concluída com Sucesso!")
    print(f"📊 Resumo: {logins_count} Logins mapeados | {commands_count} Comandos (MITRE) mapeados.")

if __name__ == "__main__":
    build_ontology()