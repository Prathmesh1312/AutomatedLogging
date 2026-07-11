import os
import json
import yaml
import asyncio
import logging
from typing import List, Dict, Any
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException, Body
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

logger = logging.getLogger("BSES.WebApp")

# Global reference to engine, set during startup
engine_ref: Any = None
active_websockets: List[WebSocket] = []

app = FastAPI(title="BSES Management Portal")

class ControlRequest(BaseModel):
    paused: bool
    eps: int
    attack_rate: float

# Helper async sender
async def broadcast_log_to_ws(ws: WebSocket, msg: str):
    try:
        await ws.send_text(msg)
    except Exception:
        if ws in active_websockets:
            active_websockets.remove(ws)

def setup_websocket_callback(engine):
    """Hooks engine's log generator to push logs directly to websocket clients."""
    global engine_ref
    engine_ref = engine
    
    def log_callback(json_str: str):
        for ws in list(active_websockets):
            # Spawn non-blocking send task in current event loop
            asyncio.create_task(broadcast_log_to_ws(ws, json_str))
            
    engine.log_callback = log_callback

# --- API ENDPOINTS ---

@app.get("/api/status")
async def get_status():
    if not engine_ref:
        raise HTTPException(status_code=503, detail="Simulation engine not initialized.")
    return {
        "running": engine_ref.running,
        "paused": engine_ref.paused,
        "target_eps": engine_ref.target_eps,
        "attack_rate": engine_ref.attack_rate,
        "total_events": engine_ref.total_generated_count,
        "realized_eps": round(engine_ref.realized_eps, 2),
        "active_entities": {
            "customers": len(engine_ref.customers),
            "employees": len(engine_ref.employees),
            "atms": len(engine_ref.atms)
        }
    }

@app.post("/api/control")
async def update_control(req: ControlRequest):
    if not engine_ref:
        raise HTTPException(status_code=503, detail="Simulation engine not initialized.")
    
    engine_ref.paused = req.paused
    engine_ref.target_eps = max(1, req.eps)
    engine_ref.attack_rate = max(0.0, min(1.0, req.attack_rate))
    
    logger.info(f"Updated controls via API: Paused={engine_ref.paused}, EPS={engine_ref.target_eps}, AttackRate={engine_ref.attack_rate}")
    return {"status": "success", "config": req}

@app.get("/api/config/infrastructure")
async def get_infra_config():
    if not engine_ref:
        raise HTTPException(status_code=503, detail="Simulation engine not initialized.")
    try:
        with open(engine_ref.infra_config_path, "r") as f:
            content = f.read()
        return {"yaml": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read infrastructure config: {e}")

@app.post("/api/config/infrastructure")
async def save_infra_config(payload: Dict[str, str] = Body(...)):
    if not engine_ref:
        raise HTTPException(status_code=503, detail="Simulation engine not initialized.")
    content = payload.get("yaml", "")
    try:
        # Validate syntax
        yaml.safe_load(content)
        # Write to file
        with open(engine_ref.infra_config_path, "w") as f:
            f.write(content)
        # Hot-reload configurations
        await engine_ref.load_configurations()
        engine_ref.build_entity_pools()
        return {"status": "success", "message": "Infrastructure configuration reloaded successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML config format: {e}")

@app.get("/api/config/attack_db")
async def get_attack_config():
    if not engine_ref:
        raise HTTPException(status_code=503, detail="Simulation engine not initialized.")
    try:
        with open(engine_ref.attack_db_path, "r") as f:
            content = f.read()
        return {"json": content}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to read attack database config: {e}")

@app.post("/api/config/attack_db")
async def save_attack_config(payload: Dict[str, str] = Body(...)):
    if not engine_ref:
        raise HTTPException(status_code=503, detail="Simulation engine not initialized.")
    content = payload.get("json", "")
    try:
        # Validate syntax
        json_data = json.loads(content)
        # Write to file
        with open(engine_ref.attack_db_path, "w") as f:
            f.write(content)
        # Hot-reload
        await engine_ref.load_configurations()
        await engine_ref.initialize_state_machines()
        return {"status": "success", "message": "Attack database reloaded successfully."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON format: {e}")

@app.post("/api/trigger")
async def trigger_manual_attack(payload: Dict[str, str] = Body(...)):
    if not engine_ref:
        raise HTTPException(status_code=503, detail="Simulation engine not initialized.")
    
    attack_type = payload.get("type", "")
    valid_types = ["sql_injection", "brute_force", "powershell_malware", "ransomware", "insider_dump", "impossible_travel"]
    if attack_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"Invalid attack type. Choose from: {valid_types}")

    await engine_ref.manual_attack_queue.put(attack_type)
    logger.info(f"Enqueued manual threat execution: {attack_type}")
    return {"status": "success", "message": f"Threat scenario '{attack_type}' enqueued for immediate execution."}

# --- WEBSOCKET ENDPOINT ---

@app.websocket("/api/logs/stream")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_websockets.append(websocket)
    logger.info(f"New Websocket client subscriber connected. Current count: {len(active_websockets)}")
    try:
        while True:
            # Keep socket alive and check for client close
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        logger.info("Websocket client unsubscribed.")
    finally:
        if websocket in active_websockets:
            active_websockets.remove(websocket)

# --- STATIC FILES ROUTING ---

@app.get("/", response_class=HTMLResponse)
async def get_index():
    static_index = os.path.join("static", "index.html")
    if os.path.exists(static_index):
        with open(static_index, "r") as f:
            return f.read()
    else:
        return "<h3>BSES Portal Interface Not Found. Make sure static files are in 'static/' directory.</h3>"

app.mount("/static", StaticFiles(directory="static"), name="static")
