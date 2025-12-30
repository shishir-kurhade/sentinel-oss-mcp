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

# main.py

import os
from mcp.server.fastmcp import FastMCP
from sentinel.defense import WaterfallDefense
from sentinel.constants import RED_TEAM_INSTRUCTION
from sentinel.models import GeminiClient

# Initialize FastMCP server
mcp = FastMCP("Sentinel")
defense = WaterfallDefense()
red_team_model = GeminiClient("gemini-2.5-flash")

@mcp.resource("sentinel://analytics/summary")
def get_analytics_summary() -> str:
    """Returns a summary of safety interactions and block rates."""
    return json.dumps(defense.cache.get_analytics_summary(), indent=2)

@mcp.resource("sentinel://analytics/logs")
def get_audit_logs() -> str:
    """Returns the most recent security audit logs."""
    return json.dumps(defense.cache.get_recent_logs(limit=20), indent=2)

@mcp.tool()
async def check_safety(prompt: str, constitution: str = "banking") -> str:
    """
    Check if a prompt is safe using the Waterfall Defense architecture.
    'constitution' can be 'banking' or 'telecom'.
    """
    result = await defense.check_prompt(prompt, constitution_name=constitution)
    return f"Verdict: {result['action']}\nReason: {result['reason']}\nLayer: {result['layer']}"

@mcp.tool()
async def generate_attack(category: str, style: str = "Standard") -> str:
    """
    Generate an adversarial prompt for a given risk category and style.
    Styles include: 'Standard', 'Many-Shot', 'DAN', 'Token Splitting', 
    'Context Framing', 'Academic', 'Emotional Manipulation'.
    """
    query = f"Category: {category}\nStyle: {style}"
    attack = await red_team_model.generate(query, system_instruction=RED_TEAM_INSTRUCTION)
    return attack

@mcp.resource("safety://constitution/{name}")
def get_constitution(name: str) -> str:
    """Returns the requested safety constitution (e.g., 'banking', 'telecom')."""
    return defense.constitutions.get(name, "Constitution not found.")

@mcp.prompt()
def analyze_vulnerability(category: str) -> str:
    """Template for auditing a specific vulnerability category."""
    return f"Audit the system for '{category}' vulnerabilities using the @Sentinel check_safety tool."

@mcp.tool()
async def add_to_cache(prompt: str, reason: str):
    """
    Manually add a malicious prompt to the semantic cache to block it and similar variations.
    """
    await defense.cache.add_prompt(prompt, reason)
    return f"Successfully added malicious pattern to vector cache."

if __name__ == "__main__":
    mcp.run()
