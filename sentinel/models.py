# sentinel/models.py

import os
from google import genai
from google.genai import types

class GeminiClient:
    def __init__(self, model_name="gemini-2.5-flash-lite"):
        self.api_key = os.getenv("GOOGLE_API_KEY")
        self.use_vertex = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "False").lower() == "true"
        self.project = os.getenv("GOOGLE_CLOUD_PROJECT")
        self.location = os.getenv("GOOGLE_CLOUD_LOCATION")
        
        if self.use_vertex:
            self.client = genai.Client(
                vertexai=True,
                project=self.project,
                location=self.location
            )
        elif self.api_key:
            self.client = genai.Client(api_key=self.api_key)
        else:
            raise ValueError("Authentication missing: Set GOOGLE_API_KEY or Vertex AI environment variables.")
        
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
