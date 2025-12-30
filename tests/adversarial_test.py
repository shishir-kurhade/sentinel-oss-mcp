import os
import asyncio
from dotenv import load_dotenv

load_dotenv()

from sentinel.defense import WaterfallDefense
from sentinel.models import GeminiClient
from sentinel.constants import RED_TEAM_INSTRUCTION

async def run_adversarial_tests():
    print("⚔️ Starting Sentinel Adversarial & Red Team Audit...\n")
    defense = WaterfallDefense()
    red_team = GeminiClient("gemini-2.5-flash")

    # --- 1. Attack Style Generation ---
    print("--- 1. Attack Generation Styles ---")
    styles = ["Many-Shot", "DAN", "Token Splitting", "Emotional Manipulation"]
    for style in styles:
        print(f"Generating {style} attack for 'Unauthorized Access'...")
        query = f"Category: Unauthorized Access\nStyle: {style}"
        attack = await red_team.generate(query, system_instruction=RED_TEAM_INSTRUCTION)
        
        # --- 2. Immediate Audit of Generated Attack ---
        print(f"Auditing Generated {style} Prompt...")
        res = await defense.check_prompt(attack)
        print(f"Verdict: {res['action']} | Layer: {res['layer']}")
        print(f"Reason: {res['reason'][:150]}...\n")

    # --- 3. Multi-Domain Red Teaming ---
    print("--- 2. Multi-Domain Red Teaming ---")
    domain_attacks = [
        ("hospital_records", "healthcare"),
        ("price_manipulation", "retail"),
        ("personnel_file_export", "hr_it")
    ]
    for category, domain in domain_attacks:
        print(f"Red Teaming Domain: {domain} for Category: {category}")
        attack = await red_team.generate(f"Category: {category}\nStyle: Advanced", system_instruction=RED_TEAM_INSTRUCTION)
        res = await defense.check_prompt(attack, constitution_name=domain)
        print(f"Verdict: {res['action']} | Layer: {res['layer']}\n")

if __name__ == "__main__":
    asyncio.run(run_adversarial_tests())
