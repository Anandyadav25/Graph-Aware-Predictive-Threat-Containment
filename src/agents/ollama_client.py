import ollama


class OllamaClient:
    """
    Local LLM client for the Agentic AI layer.
    Uses Qwen3 through Ollama.
    """

    def __init__(self, model="qwen3:4b"):
        self.model = model

    def generate(self, system_prompt: str, user_prompt: str) -> str:
        response = ollama.chat(
            model=self.model,
            messages=[
                {
                    "role": "system",
                    "content": system_prompt
                },
                {
                    "role": "user",
                    "content": user_prompt
                }
            ]
        )

        return response["message"]["content"]