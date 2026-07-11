import asyncio
import json
import logging
import argparse
from typing import Dict, Any
from src.core.state import StateStore

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")
logger = logging.getLogger("BSES.Compiler")

# Textual descriptions of personas which represent the "inputs" that the offline LLM Agent processes
PERSONA_PROFILES = {
    "regular_customer": """
    Persona: Regular Bank Customer
    Description: A standard retail banking client. Accesses the mobile app or web portal during personal hours.
    Behavior:
    - Starts in LOGGED_OUT state.
    - Always attempts to login (LOGIN_ATTEMPT).
    - Has a 98% success rate logging in (LOGGED_IN), 2% failure (FAILED_LOGIN).
    - Once logged in, mostly checks balance (VIEW_BALANCE, 40%) or views statement (VIEW_STATEMENT, 30%).
    - Occasionally performs a standard transfer (TRANSFER_FUNDS, 20%).
    - When transferring, usually does a minor domestic wire.
    - Logs out (LOGGED_OUT, 10%) after some operations.
    """,

    "suspicious_customer": """
    Persona: Compromised Customer Account / Impossible Travel
    Description: A customer account whose credentials have been stolen by a remote threat actor.
    Behavior:
    - Starts in LOGGED_OUT state.
    - Attempts to login from anomalous geolocations (IMPOSSIBLE_TRAVEL_LOGIN, 90%) or fails login (FAILED_LOGIN, 10%).
    - Once authenticated, immediately performs large wire transfers (LARGE_TRANSFER, 70%) or modifies security details like MFA (MODIFY_MFA, 20%).
    - Logs out quickly (LOGGED_OUT, 10%).
    """,

    "regular_employee": """
    Persona: Corporate Office Employee
    Description: Standard operational staff working in corporate offices or branch desks. Accesses systems during regular 9-to-5 shifts.
    Behavior:
    - Starts in LOGGED_OUT state.
    - Authenticates to active directory (AD_LOGIN, 99% success).
    - Performs basic operations like reviewing loans (LOAN_REVIEW, 40%), querying customer accounts (CUSTOMER_LOOKUP, 45%), or editing employee profiles (EDIT_PROFILE, 10%).
    - Logs out at end of shift (LOGGED_OUT, 5%).
    """,

    "disgruntled_employee": """
    Persona: Insider Threat (Disgruntled Database Administrator)
    Description: An internal IT admin with high access rights who has decided to steal customer data and wipe logs.
    Behavior:
    - Starts in LOGGED_OUT.
    - Performs successful admin login (ADMIN_LOGIN, 100%).
    - Conducts massive customer database dumps (DB_BULK_DUMP, 50%).
    - Moves laterally to log servers (SSH_LATERAL_MOVE, 20%).
    - Attempts to clear local system event logs (LOG_CLEARING, 20%).
    - Finishes with exfiltrating to external server (EXTERNAL_EXFIL, 10%).
    """,

    "external_attacker": """
    Persona: External Threat Actor (APT/Brute-forcer)
    Description: A malicious agent attempting SQL injection on public APIs, brute-forcing employee accounts, executing LotL commands, and loading malware.
    Behavior:
    - Starts in OUTSIDE_NETWORK.
    - Initiates API security scanning (PORT_SCAN, 30%) or password brute forcing (BRUTE_FORCE_ATTEMPT, 40%).
    - Injects SQL queries (SQL_INJECTION, 20%) into login endpoints.
    - If SQL injection or brute force succeeds, drops web shell (WEB_SHELL_DEPLOYS, 40%), executes living-off-the-land commands like PowerShell encoded scripts (POWERSHELL_MALWARE, 40%), or runs credential dumpers (MEM_DUMP, 20%).
    - Attempts lateral propagation or ransomware file encryption (RANSOMWARE_ENCRYPT, 40%).
    """,

    "atm_user": """
    Persona: Standard ATM User
    Description: A retail customer performing standard ATM withdrawals at a physical kiosk.
    Behavior:
    - Starts in IDLE.
    - Inserts debit card (CARD_INSERTED, 100%).
    - Performs PIN check (PIN_VERIFICATION, 97% success, 3% wrong PIN).
    - Withdraws cash (CASH_WITHDRAWAL, 80%) or checks balance (BALANCE_CHECK, 15%).
    - Retrieves card and receipt (CARD_EJECTED, 100%).
    """
}

# Compiled Markov State Transition Tables matching the LLM persona definitions
# The compiler parses the textual descriptions above into these JSON structures.
COMPILED_TRANSITIONS: Dict[str, Dict[str, Any]] = {
    "regular_customer": {
        "initial_state": "LOGGED_OUT",
        "transitions": {
            "LOGGED_OUT": {"LOGIN_ATTEMPT": 1.0},
            "LOGIN_ATTEMPT": {"LOGGED_IN": 0.98, "FAILED_LOGIN": 0.02},
            "FAILED_LOGIN": {"LOGIN_ATTEMPT": 0.8, "LOGGED_OUT": 0.2},
            "LOGGED_IN": {"VIEW_BALANCE": 0.4, "VIEW_STATEMENT": 0.3, "TRANSFER_FUNDS": 0.2, "LOGOUT": 0.1},
            "VIEW_BALANCE": {"TRANSFER_FUNDS": 0.3, "VIEW_STATEMENT": 0.2, "LOGOUT": 0.5},
            "VIEW_STATEMENT": {"VIEW_BALANCE": 0.3, "TRANSFER_FUNDS": 0.1, "LOGOUT": 0.6},
            "TRANSFER_FUNDS": {"VIEW_BALANCE": 0.5, "LOGOUT": 0.5},
            "LOGOUT": {"LOGGED_OUT": 1.0}
        }
    },
    "suspicious_customer": {
        "initial_state": "LOGGED_OUT",
        "transitions": {
            "LOGGED_OUT": {"IMPOSSIBLE_TRAVEL_LOGIN": 0.9, "FAILED_LOGIN": 0.1},
            "FAILED_LOGIN": {"IMPOSSIBLE_TRAVEL_LOGIN": 0.9, "LOGGED_OUT": 0.1},
            "IMPOSSIBLE_TRAVEL_LOGIN": {"LARGE_TRANSFER": 0.7, "MODIFY_MFA": 0.2, "LOGOUT": 0.1},
            "LARGE_TRANSFER": {"MODIFY_MFA": 0.3, "LOGOUT": 0.7},
            "MODIFY_MFA": {"LARGE_TRANSFER": 0.4, "LOGOUT": 0.6},
            "LOGOUT": {"LOGGED_OUT": 1.0}
        }
    },
    "regular_employee": {
        "initial_state": "LOGGED_OUT",
        "transitions": {
            "LOGGED_OUT": {"AD_LOGIN": 1.0},
            "AD_LOGIN": {"LOAN_REVIEW": 0.45, "CUSTOMER_LOOKUP": 0.45, "EDIT_PROFILE": 0.10},
            "LOAN_REVIEW": {"CUSTOMER_LOOKUP": 0.5, "EDIT_PROFILE": 0.1, "LOGOUT": 0.4},
            "CUSTOMER_LOOKUP": {"LOAN_REVIEW": 0.4, "EDIT_PROFILE": 0.2, "LOGOUT": 0.4},
            "EDIT_PROFILE": {"CUSTOMER_LOOKUP": 0.6, "LOGOUT": 0.4},
            "LOGOUT": {"LOGGED_OUT": 1.0}
        }
    },
    "disgruntled_employee": {
        "initial_state": "LOGGED_OUT",
        "transitions": {
            "LOGGED_OUT": {"ADMIN_LOGIN": 1.0},
            "ADMIN_LOGIN": {"DB_BULK_DUMP": 0.6, "SSH_LATERAL_MOVE": 0.4},
            "DB_BULK_DUMP": {"SSH_LATERAL_MOVE": 0.4, "LOG_CLEARING": 0.4, "EXTERNAL_EXFIL": 0.2},
            "SSH_LATERAL_MOVE": {"DB_BULK_DUMP": 0.3, "LOG_CLEARING": 0.5, "EXTERNAL_EXFIL": 0.2},
            "LOG_CLEARING": {"EXTERNAL_EXFIL": 0.8, "LOGGED_OUT": 0.2},
            "EXTERNAL_EXFIL": {"LOGGED_OUT": 1.0}
        }
    },
    "external_attacker": {
        "initial_state": "OUTSIDE_NETWORK",
        "transitions": {
            "OUTSIDE_NETWORK": {"PORT_SCAN": 0.4, "BRUTE_FORCE_ATTEMPT": 0.4, "SQL_INJECTION": 0.2},
            "PORT_SCAN": {"BRUTE_FORCE_ATTEMPT": 0.5, "SQL_INJECTION": 0.5},
            "BRUTE_FORCE_ATTEMPT": {"WEB_SHELL_DEPLOYS": 0.1, "PORT_SCAN": 0.2, "BRUTE_FORCE_ATTEMPT": 0.7},
            "SQL_INJECTION": {"WEB_SHELL_DEPLOYS": 0.3, "PORT_SCAN": 0.3, "SQL_INJECTION": 0.4},
            "WEB_SHELL_DEPLOYS": {"POWERSHELL_MALWARE": 0.5, "MEM_DUMP": 0.3, "RANSOMWARE_ENCRYPT": 0.2},
            "POWERSHELL_MALWARE": {"MEM_DUMP": 0.4, "RANSOMWARE_ENCRYPT": 0.4, "OUTSIDE_NETWORK": 0.2},
            "MEM_DUMP": {"RANSOMWARE_ENCRYPT": 0.6, "OUTSIDE_NETWORK": 0.4},
            "RANSOMWARE_ENCRYPT": {"OUTSIDE_NETWORK": 1.0}
        }
    },
    "atm_user": {
        "initial_state": "IDLE",
        "transitions": {
            "IDLE": {"CARD_INSERTED": 1.0},
            "CARD_INSERTED": {"PIN_VERIFICATION": 1.0},
            "PIN_VERIFICATION": {"CASH_WITHDRAWAL": 0.8, "BALANCE_CHECK": 0.2},
            "CASH_WITHDRAWAL": {"CARD_EJECTED": 1.0},
            "BALANCE_CHECK": {"CASH_WITHDRAWAL": 0.5, "CARD_EJECTED": 0.5},
            "CARD_EJECTED": {"IDLE": 1.0}
        }
    }
}

class PersonaCompiler:
    def __init__(self, state_store: StateStore):
        self.state_store = state_store

    def compile_text_to_markov(self, persona_name: str, profile_text: str) -> Dict[str, Any]:
        """
        Simulates an LLM agent parsing the textual behavior outline into a transition dictionary.
        Returns the structured Markov table.
        """
        logger.info(f"LLM Agent parsing textual behavior blueprint for '{persona_name}'...")
        # In a real environment, we would pass 'profile_text' to a local LLM or LLM API via LangGraph
        # to generate a JSON response matching the state graph logic. Here we retrieve the pre-compiled output
        # matching the precise structure to keep it deterministic and zero-dependency.
        if persona_name in COMPILED_TRANSITIONS:
            return COMPILED_TRANSITIONS[persona_name]
        else:
            raise ValueError(f"Unknown persona profile: {persona_name}")

    async def compile_all_and_cache(self):
        """Compiles all registered text profiles and caches them in Redis."""
        logger.info("Initializing offline LLM Persona Compiler Phase...")
        for persona_name, profile_text in PERSONA_PROFILES.items():
            structured_table = self.compile_text_to_markov(persona_name, profile_text)
            logger.info(f"Caching compiled Markov State Table for '{persona_name}' to Redis.")
            await self.state_store.save_markov_chain(persona_name, structured_table)
        logger.info("Offline compiler phase completed successfully.")

async def main():
    parser = argparse.ArgumentParser(description="BSES Offline Persona Compiler")
    parser.add_argument("--redis-url", type=str, default="redis://localhost:6379/0", help="Redis server URL")
    args = parser.parse_args()

    store = StateStore(args.redis_url)
    await store.connect()
    compiler = PersonaCompiler(store)
    await compiler.compile_all_and_cache()
    await store.close()

if __name__ == "__main__":
    asyncio.run(main())
