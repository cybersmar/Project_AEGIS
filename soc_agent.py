from langchain_ollama import OllamaLLM
from langchain_core.prompts import PromptTemplate
from langchain_neo4j import Neo4jGraph, GraphCypherQAChain

def run_agent():
    print("🤖 Waking up Hardened Local SOC Analyst Agent (Llama 3)...")

    # 1. Connect to your local Neo4j Knowledge Graph
    graph = Neo4jGraph(
        url="bolt://host.docker.internal:7687", 
        username="neo4j", 
        password="Palantir123!"
    )

    # 2. Connect to your local Ollama Brain using the new, updated class
    llm = OllamaLLM(model="llama3", base_url="http://host.docker.internal:11434")

    # 3. The "System Prompt" to enforce strict Cypher rules
    cypher_template = """Task: Generate a Cypher statement to query a graph database.
    Strict Instructions:
    1. Use only the provided relationship types and properties in the schema.
    2. NEVER use SIZE() to count relationships. Always use standard COUNT() aggregation. 
       Example: MATCH (a)-[r]->(b) RETURN b.name, COUNT(a) ORDER BY COUNT(a) DESC
    3. The risk_level property for high risk is exactly "High (Known Botnet)".
    4. The risk_level property for medium risk is exactly "Medium (Suspicious)".
    
    Schema:
    {schema}
    
    Question: {question}
    Cypher query:"""
    
    cypher_prompt = PromptTemplate(
        input_variables=["schema", "question"], 
        template=cypher_template
    )

    # 4. Create the LangChain Agent
    agent = GraphCypherQAChain.from_llm(
        llm=llm,
        graph=graph,
        verbose=True,
        cypher_prompt=cypher_prompt,
        allow_dangerous_requests=True 
    )

    print("\n✅ Agent Online! Type 'exit' to quit.")
    
    # 5. The Interactive Loop
    while True:
        question = input("\nCommander 🕵️‍♂️: ")
        if question.lower() == 'exit':
            break
            
        try:
            print("Thinking...")
            response = agent.invoke({"query": question})
            print(f"\nAgent 🤖: {response['result']}")
        except Exception as e:
            print(f"\nAgent 🤖: I encountered an error checking the database: {e}")

if __name__ == "__main__":
    run_agent()