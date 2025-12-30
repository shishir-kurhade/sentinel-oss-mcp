# sentinel/cache.py

import lancedb
import pandas as pd
import asyncio
from sentinel.constants import SEMANTIC_CACHE

class VectorCache:
    def __init__(self, db_path=".sentinel_cache", client=None):
        self.db_path = db_path
        self.client = client
        self.db = lancedb.connect(db_path)
        self.table_name = "malicious_prompts"
        self._initialized = False

    async def ensure_initialized(self):
        """Ensures the table exists and is seeded with initial data."""
        if self._initialized:
            return
            
        if self.table_name not in self.db.table_names():
            await self._initialize_table()
        self._initialized = True

    async def _initialize_table(self):
        """Creates the table and seeds it with SEMANTIC_CACHE data."""
        data = []
        for prompt, meta in SEMANTIC_CACHE.items():
            vector = await self.client.embed(prompt)
            data.append({
                "vector": vector,
                "text": prompt,
                "reason": meta["reason"]
            })
        
        if not data:
            # Create dummy data to establish schema if SEMANTIC_CACHE is empty
            data = [{
                "vector": [0.0] * 768,
                "text": "dummy",
                "reason": "dummy"
            }]
            
        df = pd.DataFrame(data)
        self.db.create_table(self.table_name, data=df, mode="overwrite")

    async def add_prompt(self, text: str, reason: str):
        await self.ensure_initialized()
        vector = await self.client.embed(text)
        table = self.db.open_table(self.table_name)
        table.add([{"vector": vector, "text": text, "reason": reason}])

    async def search(self, text: str, threshold: float = 0.80) -> dict:
        """
        Search for semantically similar prompts.
        Returns a dict with 'action': 'BLOCK' if a match is found above the threshold.
        """
        await self.ensure_initialized()
        vector = await self.client.embed(text)
        table = self.db.open_table(self.table_name)
        
        # Search using cosine similarity (lancedb returns distance)
        # distance = 1 - similarity for cosine
        results = table.search(vector).metric("cosine").limit(1).to_pandas()
        
        if not results.empty:
            distance = results.iloc[0]['_distance']
            similarity = 1 - distance
            
            if similarity >= threshold:
                return {
                    "action": "BLOCK",
                    "reason": results.iloc[0]['reason'],
                    "similarity": float(similarity),
                    "layer": "Semantic Cache (Vector)"
                }
            return {"action": "ALLOW", "similarity": float(similarity)}
        
        return {"action": "ALLOW", "similarity": 0.0}
