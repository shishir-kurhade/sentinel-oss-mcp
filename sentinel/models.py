# sentinel/models.py

import os
from google import genai
from google.genai import types

class GeminiClient:
    def __init__(self, model_name="gemini-2.5-flash-lite"):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise ValueError("GOOGLE_API_KEY environment variable is not set.")
        self.client = genai.Client(api_key=self.api_key)
        self.model_name = model_name

    async def generate(self, prompt: str, system_instruction: str = None) -> str:
        config = types.GenerateContentConfig(
            system_instruction=system_instruction,
            temperature=0.0,
        )
        response = await self.client.aio.models.generate_content(
            model=self.model_name,
            contents=prompt,
            config=config,
        )
        return response.text
