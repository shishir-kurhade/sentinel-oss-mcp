# main.py

import os
from mcp.server.fastmcp import FastMCP
from sentinel.defense import WaterfallDefense
from sentinel.constants import BANKING_SAFETY_CONSTITUTION, RED_TEAM_INSTRUCTION
from sentinel.models import GeminiClient

# Initialize FastMCP server
mcp = FastMCP("Sentinel")
defense = WaterfallDefense()
red_team_model = GeminiClient("gemini-2.5-flash")

@mcp.tool()
async def check_safety(prompt: str) -> str:
    """
    Check if a prompt is safe using the Waterfall Defense architecture.
    """
    result = await defense.check_prompt(prompt)
    return f"Verdict: {result['action']}\nReason: {result['reason']}\nLayer: {result['layer']}"

@mcp.tool()
async def generate_attack(category: str, style: str = "Standard") -> str:
    """
    Generate an adversarial prompt for a given risk category and style.
    """
    query = f"Category: {category}\nStyle: {style}"
    attack = await red_team_model.generate(query, system_instruction=RED_TEAM_INSTRUCTION)
    return attack

@mcp.resource("safety://constitution")
def get_constitution() -> str:
    """Returns the banking safety constitution."""
    return BANKING_SAFETY_CONSTITUTION

@mcp.prompt()
def analyze_vulnerability(category: str) -> str:
    """Template for auditing a specific vulnerability category."""
    return f"Audit the system for '{category}' vulnerabilities using the @Sentinel check_safety tool."

if __name__ == "__main__":
    mcp.run()
