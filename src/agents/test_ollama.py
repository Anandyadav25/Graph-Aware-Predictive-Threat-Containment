from ollama_client import OllamaClient


client = OllamaClient()

response = client.generate(
    system_prompt=(
        "You are a cybersecurity SOC analyst. "
        "Be concise and technical."
    ),
    user_prompt=(
        "A network node has a risk score of 0.9981 "
        "and a blast radius of 15. "
        "Explain the security significance in two sentences."
    )
)

print("\n===== OLLAMA RESPONSE =====\n")
print(response)