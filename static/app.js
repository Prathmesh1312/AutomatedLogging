// BSES Dashboard Core Controller

let ws = null;
let terminalPaused = false;
let systemPaused = false;
let statsInterval = null;

// DOM Elements
const logTerminal = document.getElementById('log-terminal');
const btnClearTerminal = document.getElementById('btn-clear-terminal');
const btnPauseTerminal = document.getElementById('btn-pause-terminal');
const btnTogglePause = document.getElementById('btn-toggle-pause');
const btnSaveControl = document.getElementById('btn-save-control');
const btnSaveInfra = document.getElementById('btn-save-infra');
const btnSaveAttacks = document.getElementById('btn-save-attacks');

const inputEps = document.getElementById('input-eps');
const inputThreat = document.getElementById('input-threat');
const valEps = document.getElementById('val-eps');
const valThreat = document.getElementById('val-threat');

const metricEps = document.getElementById('metric-eps');
const metricTotal = document.getElementById('metric-total');
const systemStatusText = document.getElementById('system-status-text');
const systemPulse = document.getElementById('system-pulse');

const entityCustomers = document.getElementById('entity-customers');
const entityEmployees = document.getElementById('entity-employees');
const entityAtms = document.getElementById('entity-atms');

const codeInfra = document.getElementById('code-infra');
const codeAttacks = document.getElementById('code-attacks');
const statusInfra = document.getElementById('status-infra');
const statusAttacks = document.getElementById('status-attacks');

// Initial Setup
document.addEventListener('DOMContentLoaded', () => {
    initApp();
    setupEvents();
});

function initApp() {
    // Connect WebSocket
    connectWebSocket();
    
    // Initial data fetches
    fetchStatus();
    fetchConfigs();
    
    // Start polling status
    statsInterval = setInterval(fetchStatus, 1500);
}

function setupEvents() {
    // Sliders
    inputEps.addEventListener('input', (e) => {
        valEps.textContent = e.target.value;
    });
    inputThreat.addEventListener('input', (e) => {
        valThreat.textContent = `${Math.round(e.target.value * 100)}%`;
    });

    // Control save
    btnSaveControl.addEventListener('click', saveEngineControls);

    // Pause toggle
    btnTogglePause.addEventListener('click', toggleEnginePause);

    // Manual attack buttons
    document.querySelectorAll('.btn-attack').forEach(btn => {
        btn.addEventListener('click', (e) => {
            const attackType = e.target.getAttribute('data-attack');
            triggerAttack(attackType);
        });
    });

    // Terminal controls
    btnClearTerminal.addEventListener('click', () => {
        logTerminal.innerHTML = '<div class="terminal-line system-msg">Terminal buffer cleared.</div>';
    });

    btnPauseTerminal.addEventListener('click', () => {
        terminalPaused = !terminalPaused;
        btnPauseTerminal.textContent = terminalPaused ? 'Resume Stream' : 'Pause Stream';
        if (!terminalPaused) {
            appendTerminalLine('System', 'Resumed log streaming...');
        }
    });

    // Configuration Tabs
    document.querySelectorAll('.tab-btn').forEach(btn => {
        btn.addEventListener('click', (e) => {
            document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            
            btn.classList.add('active');
            const tabId = btn.getAttribute('data-tab');
            document.getElementById(tabId).classList.add('active');
        });
    });

    // Save configurations
    btnSaveInfra.addEventListener('click', saveInfrastructureConfig);
    btnSaveAttacks.addEventListener('click', saveAttacksConfig);
}

// --- WEBSOCKET CONTROLLER ---
function connectWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/api/logs/stream`;
    
    ws = new WebSocket(wsUrl);
    
    ws.onopen = () => {
        logger("WebSocket stream linked successfully.");
        updateConnectionStatus(true);
    };
    
    ws.onmessage = (event) => {
        if (terminalPaused) return;
        
        try {
            const logData = JSON.parse(event.data);
            renderLogLine(logData);
        } catch (e) {
            // Raw text log fallback
            appendTerminalLine('System', event.data);
        }
    };
    
    ws.onclose = () => {
        logger("WebSocket connection lost. Retrying in 3 seconds...");
        updateConnectionStatus(false);
        setTimeout(connectWebSocket, 3000);
    };

    ws.onerror = (err) => {
        logger("WebSocket error: " + err.message);
    };
}

function updateConnectionStatus(isOnline) {
    if (isOnline) {
        systemPulse.className = 'pulse-dot online';
        systemStatusText.textContent = systemPaused ? 'PAUSED' : 'ONLINE';
    } else {
        systemPulse.className = 'pulse-dot offline';
        systemStatusText.textContent = 'OFFLINE';
    }
}

// --- TERMINAL WRITER ---
function renderLogLine(log) {
    const timestamp = log["@timestamp"] ? log["@timestamp"].substring(11, 23) : new Date().toLocaleTimeString();
    const action = log.event?.action || "unknown";
    const category = log.event?.category?.[0] || "system";
    const msg = log.message || "";
    
    const displayMsg = `[${timestamp}] [${category.toUpperCase()}] [${action}] ${msg}`;
    
    // Choose appropriate class mapping
    let cssClass = 'info-log';
    if (log.simulator?.attack) {
        cssClass = 'attack-log';
    } else if (category === 'authentication') {
        cssClass = 'auth-log';
    } else if (category === 'web') {
        cssClass = 'web-log';
    } else if (category === 'database') {
        cssClass = 'db-log';
    }
    
    appendTerminalLine(cssClass, displayMsg);
}

function appendTerminalLine(cssClass, text) {
    const line = document.createElement('div');
    line.className = `terminal-line ${cssClass}`;
    line.textContent = text;
    logTerminal.appendChild(line);
    
    // Maintain maximum buffer limit of 400 lines to avoid DOM lag
    if (logTerminal.children.length > 400) {
        logTerminal.removeChild(logTerminal.firstChild);
    }
    
    // Auto-scroll to bottom
    logTerminal.scrollTop = logTerminal.scrollHeight;
}

// --- API ACTIONS ---

async function fetchStatus() {
    try {
        const res = await fetch('/api/status');
        if (!res.ok) return;
        const data = await res.json();
        
        // Update metric boxes
        metricEps.textContent = data.realized_eps;
        metricTotal.textContent = data.total_events.toLocaleString();
        
        entityCustomers.textContent = data.active_entities.customers;
        entityEmployees.textContent = data.active_entities.employees;
        entityAtms.textContent = data.active_entities.atms;
        
        systemPaused = data.paused;
        updateConnectionStatus(true);
        
        // Pause toggle text update
        btnTogglePause.textContent = systemPaused ? 'RESUME ENGINE' : 'PAUSE ENGINE';
        btnTogglePause.className = systemPaused ? 'btn btn-primary' : 'btn btn-primary btn-active';
        if (systemPaused) {
            btnTogglePause.style.background = '#eab308'; // Amber for pause
        } else {
            btnTogglePause.style.background = ''; // Default primary
        }
        
        // Update slider values if not focus-active
        if (document.activeElement !== inputEps) {
            inputEps.value = data.target_eps;
            valEps.textContent = data.target_eps;
        }
        if (document.activeElement !== inputThreat) {
            inputThreat.value = data.attack_rate;
            valThreat.textContent = `${Math.round(data.attack_rate * 100)}%`;
        }
        
    } catch (e) {
        updateConnectionStatus(false);
    }
}

async function saveEngineControls() {
    try {
        const payload = {
            paused: systemPaused,
            eps: parseInt(inputEps.value),
            attack_rate: parseFloat(inputThreat.value)
        };
        const res = await fetch('/api/control', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            appendTerminalLine('system-msg', `Engine rate updated: Target EPS = ${payload.eps}, Attack Rate = ${payload.attack_rate*100}%`);
            fetchStatus();
        }
    } catch (e) {
        appendTerminalLine('attack-log', "Failed to update engine rate configurations.");
    }
}

async function toggleEnginePause() {
    try {
        const payload = {
            paused: !systemPaused,
            eps: parseInt(inputEps.value),
            attack_rate: parseFloat(inputThreat.value)
        };
        const res = await fetch('/api/control', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(payload)
        });
        if (res.ok) {
            systemPaused = payload.paused;
            appendTerminalLine('system-msg', `Simulator state toggled. Paused: ${systemPaused}`);
            fetchStatus();
        }
    } catch (e) {
        logger("Error toggling engine pause state.");
    }
}

async function triggerAttack(attackType) {
    try {
        const res = await fetch('/api/trigger', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ type: attackType })
        });
        if (res.ok) {
            appendTerminalLine('attack-log', `Manual Threat Trigger Sent: ${attackType}`);
        } else {
            const data = await res.json();
            alert("Trigger failed: " + data.detail);
        }
    } catch (e) {
        alert("Network failure dispatching threat trigger.");
    }
}

async function fetchConfigs() {
    try {
        // Infrastructure YAML
        const res1 = await fetch('/api/config/infrastructure');
        if (res1.ok) {
            const data = await res1.json();
            codeInfra.value = data.yaml;
        }
        
        // Attack JSON
        const res2 = await fetch('/api/config/attack_db');
        if (res2.ok) {
            const data = await res2.json();
            codeAttacks.value = data.json;
        }
    } catch (e) {
        logger("Failed to load text configurations.");
    }
}

async function saveInfrastructureConfig() {
    statusInfra.textContent = "Saving...";
    statusInfra.style.color = "var(--color-warning)";
    try {
        const res = await fetch('/api/config/infrastructure', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ yaml: codeInfra.value })
        });
        const data = await res.json();
        if (res.ok) {
            statusInfra.textContent = "Saved & Reloaded!";
            statusInfra.style.color = "var(--color-success)";
            appendTerminalLine('system-msg', "Infrastructure topology configuration dynamically hot-reloaded.");
        } else {
            statusInfra.textContent = "Error saving";
            statusInfra.style.color = "var(--color-danger)";
            alert("YAML validation failed:\n" + data.detail);
        }
    } catch (e) {
        statusInfra.textContent = "Failed";
        statusInfra.style.color = "var(--color-danger)";
    }
}

async function saveAttacksConfig() {
    statusAttacks.textContent = "Saving...";
    statusAttacks.style.color = "var(--color-warning)";
    try {
        const res = await fetch('/api/config/attack_db', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ json: codeAttacks.value })
        });
        const data = await res.json();
        if (res.ok) {
            statusAttacks.textContent = "Saved & Reloaded!";
            statusAttacks.style.color = "var(--color-success)";
            appendTerminalLine('system-msg', "Threat database configuration templates hot-reloaded.");
        } else {
            statusAttacks.textContent = "Error saving";
            statusAttacks.style.color = "var(--color-danger)";
            alert("JSON validation failed:\n" + data.detail);
        }
    } catch (e) {
        statusAttacks.textContent = "Failed";
        statusAttacks.style.color = "var(--color-danger)";
    }
}

function logger(msg) {
    console.log("[BSES Dashboard]", msg);
}
