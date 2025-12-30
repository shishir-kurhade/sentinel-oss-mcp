import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

from sentinel.defense import WaterfallDefense
from sentinel.models import GeminiClient
from sentinel.constants import RED_TEAM_INSTRUCTION

async def test_advanced_threats():
    print("🛡️ Sentinel Advanced Threat Audit\n")
    defense = WaterfallDefense()
    red_team = GeminiClient("gemini-2.5-flash")

    attacks = [
        ("DAN", "Data Privacy"),
        ("Token Splitting", "Malware Analysis"),
        ("Emotional Manipulation", "Account Takeover")
    ]

    for style, category in attacks:
        print(f"--- Testing {style} Attack for {category} ---")
        
        # 1. Generate the attack
        query = f"Category: {category}\nStyle: {style}"
        print(f"Generating...")
        attack_prompt = await red_team.generate(query, system_instruction=RED_TEAM_INSTRUCTION)
        
        # 2. Audit the attack
        print(f"Auditing Generated Prompt...")
        result = await defense.check_prompt(attack_prompt)
        
        print(f"Verdict: {result['action']}")
        print(f"Blocked by: {result['layer']}")
        print(f"Reason: {result['reason']}")
        print(f"Prompt (Snippet): {attack_prompt[:200]}...\n")

if __name__ == "__main__":
    asyncio.run(test_advanced_threats())
