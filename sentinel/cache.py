# Copyright 2025 Sentinel MCP Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# sentinel/cache.py

import lancedb
import pandas as pd
import asyncio
from datetime import datetime
from sentinel.constants import SEMANTIC_CACHE

class VectorCache:
    def __init__(self, db_path=".sentinel_cache", client=None):
        self.db_path = db_path
        self.client = client
        self.db = lancedb.connect(db_path)
        self.table_name = "malicious_prompts"
        self.audit_table_name = "audit_logs"
        self._initialized = False
        self._lock = asyncio.Lock()

    async def ensure_initialized(self):
        """Ensures tables exist and are seeded with initial data."""
        async with self._lock:
            if self._initialized:
                return
                
            if self.table_name not in self.db.table_names():
                await self._initialize_table()
            
            if self.audit_table_name not in self.db.table_names():
                self._initialize_audit_table()
                
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

    def _initialize_audit_table(self):
        """Creates the audit logs table with the appropriate schema."""
        # Using a dummy row to define schema for LanceDB
        dummy_data = [{
            "timestamp": "2024-01-01T00:00:00",
            "prompt": "dummy",
            "verdict": "ALLOW",
            "reason": "dummy",
            "layer": "Final",
            "latency_ms": 0.0,
            "similarity": 0.0,
            "constitution": "banking"
        }]
        df = pd.DataFrame(dummy_data)
        self.db.create_table(self.audit_table_name, data=df, mode="overwrite")

    async def log_audit(self, data: dict):
        """Records an interaction in the audit_logs table."""
        await self.ensure_initialized()
        table = self.db.open_table(self.audit_table_name)
        table.add([data])
        # Force table to be available for search immediately
        # LanceDB local storage is quite fast, but we'll ensure we re-open if needed.

    def get_recent_logs(self, limit: int = 50):
        """Returns the most recent audit logs."""
        table = self.db.open_table(self.audit_table_name)
        # to_pandas() is sometimes flaky in constrained environments
        # Fallback to search().to_list()
        try:
            df = table.to_pandas()
            if df.empty:
                return []
            df = df[df['prompt'] != "dummy"]
        except Exception:
            data = table.search().limit(limit).to_list()
            df = pd.DataFrame(data)
            if df.empty:
                return []
            df = df[df['prompt'] != "dummy"]
            
        if df.empty:
            return []
            
        df = df.sort_values(by="timestamp", ascending=False).head(limit)
        return df.to_dict(orient="records")

    def get_analytics_summary(self):
        """Returns aggregate security statistics."""
        table = self.db.open_table(self.audit_table_name)
        try:
            df = table.to_pandas()
        except Exception:
            df = pd.DataFrame(table.search().limit(1000).to_list())
        
        # Filter out dummy
        df = df[df['prompt'] != "dummy"] if not df.empty else df
        
        if df.empty:
            return {
                "total_prompts": 0, 
                "blocked_prompts": 0,
                "block_rate": 0.0, 
                "avg_latency_ms": 0.0,
                "top_layer": "N/A"
            }
            
        total = len(df)
        blocks = len(df[df['verdict'] == "BLOCK"])
        
        return {
            "total_prompts": total,
            "blocked_prompts": blocks,
            "block_rate": round(blocks / total, 2) if total > 0 else 0,
            "avg_latency_ms": round(df['latency_ms'].mean(), 2),
            "top_layer": df[df['verdict'] == "BLOCK"]['layer'].mode().iloc[0] if blocks > 0 else "N/A",
            "last_updated": datetime.now().isoformat()
        }
