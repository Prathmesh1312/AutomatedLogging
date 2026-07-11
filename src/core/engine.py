import asyncio
import time
import random
import uuid
import logging
import yaml
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from src.generators.ecs_formatter import (
    ECSLog, Event, Source, Destination, User, Device, Process,
    ParentProcess, Url, Http, HttpRequest, HttpResponse, Database,
    SimulatorContext, OsInfo, Geo, GeoLocation
)
from src.core.state import StateStore
from src.agents.state_machine import StateMachine

logger = logging.getLogger("BSES.Engine")

class SimulationEngine:
    def __init__(
        self,
        infra_config_path: str,
        attack_db_path: str,
        state_store: StateStore,
        emitters: List[Any],
        target_eps: int = 1000,
        attack_rate: float = 0.05
    ):
        self.infra_config_path = infra_config_path
        self.attack_db_path = attack_db_path
        self.state_store = state_store
        self.emitters = emitters
        self.target_eps = target_eps
        self.attack_rate = attack_rate

        self.infra: Dict[str, Any] = {}
        self.attack_db: Dict[str, Any] = {}
        self.state_machines: Dict[str, StateMachine] = {}

        # Entity pools
        self.customers: List[Dict[str, Any]] = []
        self.employees: List[Dict[str, Any]] = []
        self.atms: List[Dict[str, Any]] = []
        
        # Runtime lists/pools
        self.running = False
        self.paused = False
        self.manual_attack_queue: asyncio.Queue = asyncio.Queue()
        self.log_callback = None
        self.total_generated_count = 0
        self.realized_eps = 0.0
        self._stats_events_generated = 0
        self._stats_start_time = 0.0

    async def load_configurations(self):
        """Loads topology yaml and attack json."""
        logger.info(f"Loading infrastructure from {self.infra_config_path}")
        with open(self.infra_config_path, 'r') as f:
            self.infra = yaml.safe_load(f)

        logger.info(f"Loading attack database from {self.attack_db_path}")
        with open(self.attack_db_path, 'r') as f:
            self.attack_db = json.load(f)

    async def initialize_state_machines(self):
        """Fetches Markov chain matrices cached in Redis (or fallback)."""
        logger.info("Initializing state machine definitions from cache...")
        personas = [
            "regular_customer", "suspicious_customer", "regular_employee",
            "disgruntled_employee", "external_attacker", "atm_user"
        ]
        for persona in personas:
            chain = await self.state_store.get_markov_chain(persona)
            if not chain:
                # If compiler has not run, load placeholder/default transition table directly
                from src.agents.compiler import COMPILED_TRANSITIONS
                logger.warning(f"Markov matrix for '{persona}' not found in state store. Using hardcoded defaults.")
                chain = COMPILED_TRANSITIONS.get(persona, {})
            self.state_machines[persona] = StateMachine(persona, chain)

    def build_entity_pools(self):
        """Populates retail customers, corporate staff, and network elements."""
        logger.info("Building entity IP pools, devices, and profile definitions...")
        
        # 1. Customers
        os_options = ["Android", "iOS", "Windows", "macOS"]
        browsers = ["Chrome Mobile", "Safari Mobile", "Chrome", "Safari", "Firefox"]
        cities = [
            {"city": "Mumbai", "country": "IN", "lat": 19.076, "lon": 72.877},
            {"city": "Delhi", "country": "IN", "lat": 28.7041, "lon": 77.1025},
            {"city": "Bangalore", "country": "IN", "lat": 12.9716, "lon": 77.5946},
            {"city": "Chennai", "country": "IN", "lat": 13.0827, "lon": 80.2707}
        ]

        for i in range(500):
            c_id = f"C{100000 + i}"
            username = f"cust_{c_id.lower()}"
            city_choice = random.choice(cities)
            self.customers.append({
                "id": c_id,
                "name": username,
                "persona": "regular_customer",
                "current_state": "LOGGED_OUT",
                "session_id": None,
                "ip": f"192.168.10.{random.randint(10, 250)}", # User client IP
                "geo": city_choice,
                "device": {
                    "id": str(uuid.uuid4())[:18],
                    "model": random.choice(["iPhone 14", "Galaxy S23", "Pixel 7", "Generic PC"]),
                    "os": random.choice(os_options),
                    "browser": random.choice(browsers)
                }
            })

        # 2. Employees
        departments = ["Loans", "Operations", "Finance", "IT_Support", "Compliance"]
        roles_map = {
            "Loans": "Loan Officer",
            "Operations": "Tellers",
            "Finance": "Wire Operator",
            "IT_Support": "System Admin",
            "Compliance": "Compliance Auditor"
        }
        for i in range(50):
            e_id = f"EMP{200 + i}"
            dept = random.choice(departments)
            role = roles_map[dept]
            username = f"emp_{e_id.lower()}"
            self.employees.append({
                "id": e_id,
                "name": username,
                "persona": "regular_employee",
                "current_state": "LOGGED_OUT",
                "session_id": None,
                "department": dept,
                "role": role,
                "ip": f"10.100.10.{100 + i}", # HQ Subnet
                "mac": f"00:50:56:d5:e6:{10 + i:02x}",
                "device": {
                    "id": f"WRK-{e_id}",
                    "model": "Optiplex Workstation",
                    "os": "Windows 11 Enterprise",
                    "browser": "Edge"
                }
            })

        # 3. ATMs (based on branch subnet layout)
        branch_count = self.infra.get("branches", {}).get("count", 20)
        atms_per_branch = self.infra.get("branches", {}).get("atms_per_branch", 5)
        for b in range(1, branch_count + 1):
            for a in range(1, atms_per_branch + 1):
                atm_id = f"ATM-B{b:02d}-N{a:02d}"
                # Branch subnets e.g. 10.200.branch_id.x
                self.atms.append({
                    "id": atm_id,
                    "name": f"atm_node_{b}_{a}",
                    "persona": "atm_user",
                    "current_state": "IDLE",
                    "branch_id": b,
                    "ip": f"10.200.{b}.{100 + a}",
                    "mac": f"00:0c:29:{b:02d}:a0:{a:02d}",
                    "device": {
                        "id": atm_id,
                        "model": "NCR SelfServ ATM",
                        "os": "Windows 10 IoT",
                        "browser": "ATMClientApp"
                    }
                })

    async def advance_entity(self, entity: Dict[str, Any]) -> Optional[ECSLog]:
        """Advances state machine of a single entity and generates the corresponding ECS log."""
        persona = entity["persona"]
        state_machine = self.state_machines.get(persona)
        if not state_machine:
            return None

        current_state = entity["current_state"]
        next_state = state_machine.get_next_state(current_state)
        entity["current_state"] = next_state

        # Session lifecycle updates
        if next_state in ["LOGGED_OUT", "LOGOUT", "IDLE"]:
            if entity.get("session_id"):
                await self.state_store.delete_session(entity["session_id"])
                entity["session_id"] = None
        elif current_state in ["LOGGED_OUT", "IDLE"] and next_state not in ["FAILED_LOGIN"]:
            entity["session_id"] = str(uuid.uuid4())
            session_data = {
                "user": entity["name"],
                "ip": entity["ip"],
                "login_time": datetime.now(timezone.utc).isoformat()
            }
            await self.state_store.save_session(entity["session_id"], session_data)

        # Build ECS Log
        return await self._map_state_to_ecs(entity, current_state, next_state)

    async def _map_state_to_ecs(self, entity: Dict[str, Any], prev_state: str, state: str) -> ECSLog:
        now = datetime.now(timezone.utc)
        
        # Standard default elements
        ecs_log = ECSLog(
            timestamp=now,
            event=Event(action="state-transition", category=["process"], outcome="success"),
            simulator=SimulatorContext(
                attack=False,
                entity_type="system",
                persona=entity["persona"],
                session_id=entity.get("session_id")
            ),
            message=f"Entity transitioned from {prev_state} to {state}"
        )

        persona = entity["persona"]
        
        # User details if present
        if "name" in entity:
            roles = [entity.get("role")] if "role" in entity else ["customer"]
            ecs_log.user = User(id=entity.get("id"), name=entity["name"], roles=roles)

        # Device details if present
        if "device" in entity:
            dev = entity["device"]
            ecs_log.device = Device(
                id=dev["id"],
                model=dev["model"],
                os=OsInfo(name=dev["os"])
            )

        # Assign entity category mapping
        if persona in ["regular_customer", "suspicious_customer"]:
            ecs_log.simulator.entity_type = "customer"
        elif persona in ["regular_employee", "disgruntled_employee"]:
            ecs_log.simulator.entity_type = "employee"
        elif persona == "atm_user":
            ecs_log.simulator.entity_type = "atm"
        elif persona == "external_attacker":
            ecs_log.simulator.entity_type = "external"

        # --- MAP SPECIFIC STATES TO DETAILED LOG FIELDS ---

        # 1. Normal User / Customer States
        if state == "LOGIN_ATTEMPT":
            ecs_log.event = Event(category=["authentication"], action="user-login-attempt", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"User {entity['name']} initiated web login attempt"
            
        elif state == "LOGGED_IN":
            ecs_log.event = Event(category=["authentication"], action="user-login", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"User {entity['name']} successfully authenticated (Session: {entity.get('session_id')})"

        elif state == "FAILED_LOGIN":
            ecs_log.event = Event(category=["authentication"], action="user-login", outcome="failure", reason="Invalid password")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"User {entity['name']} failed authentication: Invalid password credentials"

        elif state == "VIEW_BALANCE":
            ecs_log.event = Event(category=["web"], action="api-query", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="10.100.1.10", port=443) # API gateway
            ecs_log.url = Url(path="/api/v1/accounts/balance", original="https://api.apexbank.com/api/v1/accounts/balance")
            ecs_log.http = Http(request=HttpRequest(method="GET"), response=HttpResponse(status_code=200))
            ecs_log.message = f"User {entity['name']} queried account balance"

        elif state == "VIEW_STATEMENT":
            ecs_log.event = Event(category=["web"], action="api-query", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="10.100.1.10", port=443)
            ecs_log.url = Url(path="/api/v1/accounts/statement", original="https://api.apexbank.com/api/v1/accounts/statement")
            ecs_log.http = Http(request=HttpRequest(method="GET"), response=HttpResponse(status_code=200))
            ecs_log.message = f"User {entity['name']} generated account transaction statement"

        elif state == "TRANSFER_FUNDS":
            amount = random.randint(100, 5000)
            ecs_log.event = Event(category=["transaction"], action="fund-transfer", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="10.100.1.10", port=443)
            ecs_log.database = Database(query=f"INSERT INTO transactions (amount, currency) VALUES ({amount}, 'INR')", instance="db-main-primary")
            ecs_log.message = f"Customer transfer of INR {amount} completed successfully."

        # 2. Impossible Travel (Threat state)
        elif state == "IMPOSSIBLE_TRAVEL_LOGIN":
            # Fetch last location
            last_loc = await self.state_store.get_user_location(entity["name"])
            
            # Draw target location from attack database
            locs = self.attack_db["attacks"]["impossible_travel"]["locations"]
            new_loc = random.choice(locs)
            
            # Build geo data
            ecs_log.source = Source(
                ip=f"185.220.101.{random.randint(2, 254)}",  # Tor exit IP simulation
                geo=Geo(
                    city_name=new_loc["city"],
                    country_iso_code=new_loc["country"],
                    location=GeoLocation(lat=new_loc["lat"], lon=new_loc["lon"])
                )
            )
            
            ecs_log.event = Event(category=["authentication"], action="user-login", outcome="success")
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = self.attack_db["attacks"]["impossible_travel"]["mitre_id"]
            ecs_log.simulator.attack_name = self.attack_db["attacks"]["impossible_travel"]["name"]
            ecs_log.simulator.risk_level = "high"
            
            # Save location in state manager
            await self.state_store.update_user_location(entity["name"], {
                "city": new_loc["city"], "country": new_loc["country"],
                "lat": new_loc["lat"], "lon": new_loc["lon"], "timestamp": now.isoformat()
            })

            if last_loc:
                ecs_log.message = (
                    f"CRITICAL: Login for {entity['name']} from {new_loc['city']} ({new_loc['country']}) "
                    f"detected shortly after login from {last_loc['city']} ({last_loc['country']}). Impossible Travel alert!"
                )
            else:
                # Seed first location if empty
                ecs_log.message = f"Login for {entity['name']} from anomalous remote location: {new_loc['city']} ({new_loc['country']})"
                
        elif state == "LARGE_TRANSFER":
            amount = random.randint(500000, 2000000)
            ecs_log.event = Event(category=["transaction"], action="fund-transfer-anomalous", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1567" # Exfiltration / Fraudulent transfer
            ecs_log.simulator.attack_name = "Anomalous Large Fund Transfer"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"ALERT: High value transfer of INR {amount} requested by account {entity['name']} from untrusted IP."

        elif state == "MODIFY_MFA":
            ecs_log.event = Event(category=["iam"], action="mfa-disable", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1556.006" # Modify authentication process
            ecs_log.simulator.attack_name = "MFA Device Modification"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"CRITICAL: Multi-Factor Authentication device list updated for user {entity['name']}."

        # 3. Employee / Corporate States
        elif state == "AD_LOGIN":
            ecs_log.event = Event(category=["authentication"], action="ad-auth", outcome="success")
            ecs_log.source = Source(ip=entity["ip"], mac=entity.get("mac"))
            ecs_log.destination = Destination(ip="10.100.10.10") # AD domain controller
            ecs_log.message = f"Active Directory authentication successful for user {entity['name']} on {entity['device']['id']}"

        elif state == "LOAN_REVIEW":
            ecs_log.event = Event(category=["app"], action="document-access", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"Employee {entity['name']} loaded loan application metadata in CreditDecisionPortal"

        elif state == "CUSTOMER_LOOKUP":
            ecs_log.event = Event(category=["database"], action="query", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.database = Database(query="SELECT * FROM customers WHERE id = ?", instance="db-main-replica", user=entity["name"])
            ecs_log.message = f"Customer database lookup initiated by employee {entity['name']}"

        elif state == "EDIT_PROFILE":
            ecs_log.event = Event(category=["database"], action="update", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.database = Database(query="UPDATE employee_profiles SET last_active = ?", instance="db-main-primary", user=entity["name"])
            ecs_log.message = f"Employee {entity['name']} updated internal workstation session parameter"

        # 4. Disgruntled Employee (Insider Threat States)
        elif state == "ADMIN_LOGIN":
            ecs_log.event = Event(category=["authentication"], action="elevated-login", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="10.100.10.10")
            ecs_log.message = f"Administrator session initiated by {entity['name']} (Privileges: Domain Admin)"

        elif state == "DB_BULK_DUMP":
            q = random.choice(self.attack_db["attacks"]["data_exfiltration"]["queries"])
            ecs_log.event = Event(category=["database"], action="dump-query", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="10.100.2.20") # DB IP
            ecs_log.database = Database(query=q, instance="db-main-primary", user=entity["name"])
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1114.002"
            ecs_log.simulator.attack_name = "Insider Threat Database Dump"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"SQL AUDIT ALERT: User '{entity['name']}' executed bulk dump query targeting customer records. Query: {q}"

        elif state == "SSH_LATERAL_MOVE":
            ecs_log.event = Event(category=["network"], action="ssh-lateral", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="10.100.2.30", port=22) # DW
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1021.004"
            ecs_log.simulator.attack_name = "Lateral Movement via SSH"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"SSH lateral connection established from {entity['ip']} to Core Database server 10.100.2.30"

        elif state == "LOG_CLEARING":
            cmd = "wevtutil.exe cl Security"
            ecs_log.event = Event(category=["process"], action="process-execution", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.process = Process(name="wevtutil.exe", command_line=cmd, pid=random.randint(1000, 9999))
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1070.001"
            ecs_log.simulator.attack_name = "Indicator Removal on Host: Clear Windows Event Logs"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"Process started on {entity['device']['id']}: wevtutil.exe. Action: Event log deletion."

        elif state == "EXTERNAL_EXFIL":
            target_url = random.choice(self.attack_db["attacks"]["data_exfiltration"]["exfil_endpoints"])
            ecs_log.event = Event(category=["network"], action="outbound-exfil", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="198.51.100.42", port=8080)
            ecs_log.url = Url(original=target_url)
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = self.attack_db["attacks"]["data_exfiltration"]["mitre_id"]
            ecs_log.simulator.attack_name = self.attack_db["attacks"]["data_exfiltration"]["name"]
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"DATA EXFILTRATION WARNING: Exfiltrated ZIP archive (1.2 GB) via HTTP POST payload target: {target_url}"

        # 5. External Attacker (APT/Brute-force states)
        elif state == "PORT_SCAN":
            target_ip = random.choice(["10.100.1.10", "10.100.1.11"]) # Public gateways
            ecs_log.event = Event(category=["network"], action="port-scan-detect", outcome="failure")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip=target_ip, port=22)
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1046"
            ecs_log.simulator.attack_name = "Network Service Scanning"
            ecs_log.simulator.risk_level = "medium"
            ecs_log.message = f"FIREWALL: Denied connection from external IP {entity['ip']} to local subnet on SSH port 22."

        elif state == "BRUTE_FORCE_ATTEMPT":
            target_user = random.choice(self.attack_db["attacks"]["brute_force"]["username_pool"])
            ecs_log.event = Event(category=["authentication"], action="user-login", outcome="failure", reason="Authentication lock threshold exceeded")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.user = User(name=target_user)
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = self.attack_db["attacks"]["brute_force"]["mitre_id"]
            ecs_log.simulator.attack_name = self.attack_db["attacks"]["brute_force"]["name"]
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"SECURITY ALERT: Account brute-force attempt blocked for login user {target_user} from IP {entity['ip']}."

        elif state == "SQL_INJECTION":
            payload = random.choice(self.attack_db["attacks"]["sql_injection"]["payloads"])
            endpoint = random.choice(self.attack_db["attacks"]["sql_injection"]["endpoints"])
            ecs_log.event = Event(category=["web"], action="http-request", outcome="failure")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.destination = Destination(ip="10.100.1.10", port=443)
            ecs_log.url = Url(path=endpoint)
            ecs_log.http = Http(request=HttpRequest(method="POST"), response=HttpResponse(status_code=500))
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = self.attack_db["attacks"]["sql_injection"]["mitre_id"]
            ecs_log.simulator.attack_name = self.attack_db["attacks"]["sql_injection"]["name"]
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"WAF SHIELD: SQL Injection query detected and sanitized in body parameter: query={payload}"

        elif state == "WEB_SHELL_DEPLOYS":
            ecs_log.event = Event(category=["process"], action="process-execution", outcome="success")
            ecs_log.source = Source(ip="10.100.1.10") # Deployed on web API GW
            ecs_log.process = Process(
                name="cmd.exe",
                command_line="cmd.exe /c echo <%@ Page Language=\"JScript\"%><%eval(Request.Item[\"cmd\"],\"unsafe\");%> > c:\\inetpub\\wwwroot\\shell.aspx",
                pid=random.randint(5000, 9999)
            )
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1505.003"
            ecs_log.simulator.attack_name = "Server Software Component: Web Shell"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"Threat intelligence alert: Web shell creation signature detected in local IIS directories on api-gw-01"

        elif state == "POWERSHELL_MALWARE":
            cmd = random.choice(self.attack_db["attacks"]["lotl_malware"]["commands"])
            ecs_log.event = Event(category=["process"], action="process-execution", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.process = Process(
                name="powershell.exe",
                command_line=cmd,
                pid=random.randint(1000, 9999),
                parent=ParentProcess(name="cmd.exe", pid=random.randint(1000, 9999))
            )
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = self.attack_db["attacks"]["lotl_malware"]["mitre_id"]
            ecs_log.simulator.attack_name = self.attack_db["attacks"]["lotl_malware"]["name"]
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"ENDPOINT MONITOR: Suspicious PowerShell process launched with encoded string arguments: {cmd[:60]}..."

        elif state == "MEM_DUMP":
            cmd = "reg.exe save HKLM\\SAM C:\\temp\\sam.hive & reg.exe save HKLM\\SYSTEM C:\\temp\\system.hive"
            ecs_log.event = Event(category=["process"], action="process-execution", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.process = Process(name="reg.exe", command_line=cmd, pid=random.randint(1000, 9999))
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1003.002"
            ecs_log.simulator.attack_name = "OS Credential Dumping: Security Account Manager"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"Process spawned (reg.exe) attempting to backup registry hives containing local passwords/hashes."

        elif state == "RANSOMWARE_ENCRYPT":
            cmd = "vssadmin.exe delete shadows /all /quiet"
            ecs_log.event = Event(category=["process"], action="process-execution", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.process = Process(name="vssadmin.exe", command_line=cmd, pid=random.randint(1000, 9999))
            ecs_log.simulator.attack = True
            ecs_log.simulator.mitre_id = "T1490"
            ecs_log.simulator.attack_name = "Inhibit System Recovery"
            ecs_log.simulator.risk_level = "high"
            ecs_log.message = f"CRITICAL: Ransomware alert: Deleting local volume shadow backup storage. Command: {cmd}"

        # 6. ATM states
        elif state == "CARD_INSERTED":
            ecs_log.event = Event(category=["hardware"], action="atm-card-inserted", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"ATM hardware: Card read succeeded at terminal {entity['id']}"

        elif state == "PIN_VERIFICATION":
            ecs_log.event = Event(category=["authentication"], action="atm-pin-verified", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"ATM session PIN confirmation success on node {entity['id']}"

        elif state == "CASH_WITHDRAWAL":
            amount = random.choice([2000, 5000, 10000, 20000])
            ecs_log.event = Event(category=["transaction"], action="atm-cash-dispensed", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"ATM Transaction: Dispensed cash payout INR {amount} from kiosk {entity['id']}"

        elif state == "CARD_EJECTED":
            ecs_log.event = Event(category=["hardware"], action="atm-card-ejected", outcome="success")
            ecs_log.source = Source(ip=entity["ip"])
            ecs_log.message = f"ATM kiosk {entity['id']}: Session finished, debit card ejected."

        # Setup base IP attributes if source IP was set but destination IP is missing
        if ecs_log.source and not ecs_log.destination:
            # Default to destination API gateway/internal routers
            ecs_log.destination = Destination(ip="10.100.1.1")

        return ecs_log

    async def start(self):
        """Starts the simulator main scheduling loop."""
        self.running = True
        self._stats_events_generated = 0
        self._stats_start_time = time.time()
        logger.info(f"Starting simulation core at target {self.target_eps} EPS...")

        # Setup entity reference lists
        all_normal_entities = self.customers + self.employees + self.atms
        
        # Attack entities pool (simulating threat actors in the background)
        attack_entities = []
        attacker_ips = [
            "45.227.254.10", "185.220.101.42", "203.0.113.195", "198.51.100.99"
        ]
        for i, ip in enumerate(attacker_ips):
            attack_entities.append({
                "id": f"ATTACKER-{i}",
                "name": f"external_threat_{i}",
                "persona": "external_attacker",
                "current_state": "OUTSIDE_NETWORK",
                "ip": ip,
                "device": {
                    "id": f"ATTACK-HOST-{i}",
                    "model": "Kali Linux VPS",
                    "os": "Linux x86_64",
                    "browser": "Nmap/Go-Buster"
                }
            })
            
        # Also assign malicious/insider persona occasionally to employees or suspicious flows
        compromised_customers = self.customers[:50]  # First 50 customers can suffer credential compromise
        disgruntled_employees = self.employees[:5]   # First 5 employees are potential insider threats

        # Target ticks per second (e.g. 50 ticks, meaning each tick runs every 20ms)
        ticks_per_second = 50
        tick_interval = 1.0 / ticks_per_second

        logger.info(f"Main Loop: Dynamic scheduler configured. Target: {self.target_eps} EPS.")

        while self.running:
            if self.paused:
                await asyncio.sleep(0.1)
                continue

            tick_start = time.time()

            # Process manual threat injections
            while not self.manual_attack_queue.empty():
                try:
                    attack_type = self.manual_attack_queue.get_nowait()
                    entity = None
                    if attack_type == "sql_injection":
                        entity = random.choice(attack_entities)
                        entity["current_state"] = "SQL_INJECTION"
                    elif attack_type == "brute_force":
                        entity = random.choice(attack_entities)
                        entity["current_state"] = "BRUTE_FORCE_ATTEMPT"
                    elif attack_type == "powershell_malware":
                        entity = random.choice(attack_entities)
                        entity["current_state"] = "POWERSHELL_MALWARE"
                    elif attack_type == "ransomware":
                        entity = random.choice(attack_entities)
                        entity["current_state"] = "RANSOMWARE_ENCRYPT"
                    elif attack_type == "insider_dump":
                        entity = random.choice(disgruntled_employees)
                        entity["persona"] = "disgruntled_employee"
                        entity["current_state"] = "DB_BULK_DUMP"
                    elif attack_type == "impossible_travel":
                        entity = random.choice(compromised_customers)
                        entity["persona"] = "suspicious_customer"
                        entity["current_state"] = "IMPOSSIBLE_TRAVEL_LOGIN"

                    if entity:
                        log = await self._map_state_to_ecs(entity, "START_MANUAL", entity["current_state"])
                        if log:
                            json_str = log.to_json()
                            for emitter in self.emitters:
                                try:
                                    res = emitter.emit(json_str)
                                    if asyncio.iscoroutine(res):
                                        asyncio.create_task(res)
                                except Exception as e:
                                    logger.error(f"Error emitting manual log: {e}")
                            if self.log_callback:
                                self.log_callback(json_str)
                            self._stats_events_generated += 1
                            self.total_generated_count += 1
                    self.manual_attack_queue.task_done()
                except Exception as ex:
                    logger.error(f"Failed to process manual attack: {ex}")

            # Calculate events per tick dynamically to support runtime EPS changes
            events_per_tick = max(1, int(self.target_eps / ticks_per_second))
            
            # Accumulate batch lists to emit
            tasks = []
            
            # Select entities for this tick
            for _ in range(events_per_tick):
                # Check if we should inject an attack event
                if random.random() < self.attack_rate:
                    # Select attack category
                    attack_type = random.choice(["external", "insider", "compromise"])
                    if attack_type == "external":
                        entity = random.choice(attack_entities)
                    elif attack_type == "insider":
                        entity = random.choice(disgruntled_employees)
                        entity["persona"] = "disgruntled_employee"
                    else:
                        entity = random.choice(compromised_customers)
                        entity["persona"] = "suspicious_customer"
                else:
                    # Normal event
                    entity = random.choice(all_normal_entities)
                    if entity["id"].startswith("C"):
                        entity["persona"] = "regular_customer"
                    elif entity["id"].startswith("EMP"):
                        entity["persona"] = "regular_employee"

                # Schedule the async transition update
                tasks.append(self.advance_entity(entity))

            # Run transitions concurrently
            logs = await asyncio.gather(*tasks)

            # Emit serialized events non-blockingly
            for log in logs:
                if log:
                    json_str = log.to_json()
                    # Feed to all output emitters (Syslog, Kafka, stdout)
                    for emitter in self.emitters:
                        try:
                            res = emitter.emit(json_str)
                            if asyncio.iscoroutine(res):
                                asyncio.create_task(res)
                        except Exception as e:
                            logger.error(f"Error emitting log: {e}")
                    
                    if self.log_callback:
                        self.log_callback(json_str)
                    
                    self._stats_events_generated += 1
                    self.total_generated_count += 1

            # Periodically output statistics (every 5 seconds)
            elapsed = time.time() - self._stats_start_time
            if elapsed >= 5.0:
                self.realized_eps = self._stats_events_generated / elapsed
                logger.info(f"Simulating... Total Events: {self.total_generated_count} | Realized EPS: {self.realized_eps:.2f}")
                self._stats_events_generated = 0
                self._stats_start_time = time.time()

            # Non-blocking tick alignment
            tick_duration = time.time() - tick_start
            sleep_time = tick_interval - tick_duration
            if sleep_time > 0:
                await asyncio.sleep(sleep_time)
            else:
                await asyncio.sleep(0.001)

    def stop(self):
        self.running = False
        logger.info("Simulation engine stopping.")
