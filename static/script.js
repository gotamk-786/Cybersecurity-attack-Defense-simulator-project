// ====== DOM REFERENCES ======
const graphElement = document.getElementById("graph");
const statusBanner = document.getElementById("statusBanner");
const alertCountEl = document.getElementById("alert-count");
const timelineEl = document.getElementById("alertTimeline");
const packetBody = document.getElementById("pktBody");
const lastPacketBody = document.getElementById("lastPacketBody");
const throughputEl = document.getElementById("pps");
const lastEventEl = document.getElementById("last-event");
const consoleLine = document.getElementById("consoleLine");
const attackLed = document.getElementById("attack-led");
const graphDataElement = document.getElementById("graph-data");
const attackBtn = document.getElementById("attackBtn");
const attackStatus = document.getElementById("attack-status");
const modeModal = document.getElementById("trafficModeModal");
const modeStartBtn = document.getElementById("modeStartBtn");
const modeCancelBtn = document.getElementById("modeCancelBtn");
const urlInput = document.getElementById("urlInput");
const urlError = document.getElementById("urlError");
const urlBanner = document.getElementById("urlBanner");
const startBtn = document.getElementById("modeStartBtn");

// ====== DATA STORAGE ======
let timeData = [];
let normalData = [];
let maliciousData = [];
let blockedData = [];
let t = 0;
let lastStats = { normal: 0, malicious: 0, blocked: 0, load: 0, total: 0 };
let lastUpdateTime = Date.now();
let activeAlerts = 0;

// ====== GRAPH INITIALIZATION ======
const layout = {
    title: {
        text: "CYBER THREAT TELEMETRY (LIVE)",
        font: { color: "cyan", size: 22, family: "Consolas" }
    },
    paper_bgcolor: "rgba(0,0,0,0)",
    plot_bgcolor: "rgba(0,0,0,0)",
    xaxis: {
        title: "Time (s)",
        color: "cyan",
        gridcolor: "rgba(0,255,255,0.1)",
        zerolinecolor: "rgba(0,255,255,0.4)"
    },
    yaxis: {
        title: "Packets",
        color: "lime",
        gridcolor: "rgba(0,255,0,0.1)",
        zerolinecolor: "rgba(0,255,0,0.4)"
    },
    showlegend: true,
    legend: { font: { color: "cyan" }, x: 1, y: 1 },
    margin: { t: 50 }
};

const normalTrace = {
    x: [],
    y: [],
    mode: "lines",
    name: "Normal Packets",
    line: { color: "lime", width: 3, shape: "spline" }
};

const maliciousTrace = {
    x: [],
    y: [],
    mode: "lines",
    name: "Malicious Packets",
    line: { color: "red", width: 4, shape: "spline" }
};

const blockedTrace = {
    x: [],
    y: [],
    mode: "lines",
    name: "Blocked Packets",
    line: { color: "yellow", width: 3, dash: "dot", shape: "spline" }
};

// ignore server-seeded graph; we start fresh each load

let plotlyReady = false;

function initPlotlyChart() {
    if (!window.Plotly || !graphElement) {
        console.warn("Plotly still unavailable; graph updates paused.");
        return;
    }
    Plotly.newPlot(graphElement, [normalTrace, maliciousTrace, blockedTrace], layout);
    plotlyReady = true;
}

function ensurePlotlyLoaded() {
    if (window.Plotly) {
        initPlotlyChart();
        return;
    }
    console.warn("Plotly not found. Attempting fallback load...");
    const fallback = document.createElement("script");
    fallback.src = "https://cdn.plot.ly/plotly-2.32.0.min.js";
    fallback.onload = initPlotlyChart;
    fallback.onerror = () => console.error("Failed to load Plotly from CDN.");
    document.head.appendChild(fallback);
}

ensurePlotlyLoaded();

// ====== UTILS ======
function setBanner(state, message) {
    statusBanner.textContent = message;
    statusBanner.classList.remove("status-ok", "status-alert");
    statusBanner.classList.add(state === "alert" ? "status-alert" : "status-ok");
}

function setConsoleText(text) {
    if (consoleLine) {
        consoleLine.textContent = `> ${text}`;
    }
}

function setAttackLed(active) {
    if (!attackLed) return;
    attackLed.classList.toggle("active", !!active);
}

function logTimelineEvent(message) {
    if (!timelineEl) return;
    const li = document.createElement("li");
    const timestamp = new Date().toLocaleTimeString();
    li.textContent = `[${timestamp}] ${message}`;
    timelineEl.prepend(li);

    while (timelineEl.children.length > 8) {
        timelineEl.removeChild(timelineEl.lastChild);
    }
    setConsoleText(message);
}
window.logTimelineEvent = logTimelineEvent;
window.setAttackLed = setAttackLed;
window.setConsoleText = setConsoleText;
window.attachAttackHandler = attachAttackHandler;
window.startMode = startMode;
window.hideModeModal = hideModeModal;
window.showModeModal = showModeModal;
window.closeModal = hideModeModal;
window.closeModal = closeModal;

function setUrlBanner(url) {
    if (!urlBanner) return;
    if (url) {
        urlBanner.textContent = `URL Traffic Mode Active: ${url}`;
        urlBanner.classList.add("show");
        urlBanner.classList.remove("hidden");
    } else {
        urlBanner.classList.remove("show");
        urlBanner.classList.add("hidden");
        urlBanner.textContent = "URL Traffic Mode Active";
    }
}

function updateAlertCount(count) {
    alertCountEl.textContent = count;
}

function formatTitle(obj) {
    try {
        return JSON.stringify(obj).replace(/"/g, "&quot;");
    } catch {
        return "";
    }
}

function updateLastPacket(packets) {
    if (!lastPacketBody) return;
    if (!packets.length) {
        lastPacketBody.innerHTML = "<p>No packets captured yet.</p>";
        return;
    }
    const latest = packets[packets.length - 1];
    const timestamp = new Date(latest.timestamp * 1000).toLocaleString();
    lastPacketBody.innerHTML = `
        <ul>
            <li><strong>Timestamp:</strong> ${timestamp}</li>
            <li><strong>IP:</strong> ${latest.ip}</li>
            <li><strong>Port:</strong> ${latest.port}</li>
        </ul>
        <pre>${latest.raw || "(empty payload)"}</pre>
    `;
}

function updatePacketLog(packets) {
    if (!packetBody) return;
    const rows = packets
        .slice()
        .reverse()
        .map(p => `
            <tr title="${formatTitle(p)}">
                <td>${new Date(p.timestamp * 1000).toLocaleTimeString()}</td>
                <td>${p.ip}</td>
                <td>${p.port}</td>
                <td>${p.raw}</td>
            </tr>`)
        .join("");
    packetBody.innerHTML = rows;
    updateLastPacket(packets);
}

// ====== GRAPH LIVE UPDATE FUNCTION ======
function updateGraph(stats) {
    t += 1;
    timeData.push(t);
    normalData.push(stats.normal);
    maliciousData.push(stats.malicious);
    blockedData.push(stats.blocked);

    if (plotlyReady && window.Plotly && graphElement) {
        Plotly.update(graphElement, {
            x: [timeData, timeData, timeData],
            y: [normalData, maliciousData, blockedData]
        });
    }

    if (stats.malicious > 0) {
        graphElement.style.boxShadow = "0 0 25px red, 0 0 50px red";
        setTimeout(() => {
            graphElement.style.boxShadow = "0 0 15px cyan";
        }, 300);
    }
}

// ====== LIVE UPDATES ======
function updateStats() {
    fetch('/api/stats')
        .then(response => response.json())
        .then(data => {
            document.getElementById('normal').innerText = data.normal;
            document.getElementById('malicious').innerText = data.malicious;
            document.getElementById('blocked').innerText = data.blocked;
            document.getElementById('load').innerText = data.load + "%";

            const now = Date.now();
            const deltaTime = Math.max((now - lastUpdateTime) / 1000, 0.1);
            const totalPackets = data.normal + data.malicious + data.blocked;
            const deltaPackets = totalPackets - lastStats.total;
            throughputEl.textContent = Math.max(deltaPackets / deltaTime, 0).toFixed(1);

            let eventText = "Awaiting traffic...";
            if (data.malicious > lastStats.malicious) {
                eventText = "Malicious activity detected!";
            } else if (data.blocked > lastStats.blocked) {
                eventText = "Firewall blocked hostile traffic.";
            } else if (data.load > lastStats.load) {
                eventText = "IDS load rising.";
            } else if (deltaPackets > 0) {
                eventText = "Traffic flowing.";
            }
            lastEventEl.textContent = eventText;

            if (data.load > lastStats.load) {
                setBanner("alert", `IDS alert! Load spike (${data.load}%)`);
                logTimelineEvent(`IDS alert triggered (load ${data.load}%).`);
            } else if (data.load > 0) {
                setBanner("alert", `IDS alert active (${data.load}%)`);
            } else if (totalPackets === 0) {
                setBanner("ok", "System idle. Awaiting traffic...");
            } else {
                setBanner("ok", "Monitoring traffic.");
            }

            activeAlerts = data.load;
            updateAlertCount(activeAlerts);
            updateGraph(data);

            lastStats = { ...data, total: totalPackets };
            lastUpdateTime = now;
        })
        .catch(err => console.error("Stats Error:", err))
        .finally(() => setTimeout(updateStats, 900));
}

function loadPackets() {
    fetch("/api/packets")
        .then(r => r.json())
        .then(updatePacketLog)
        .catch(err => console.error("Packet log error:", err))
        .finally(() => setTimeout(loadPackets, 750));
}

function showModeModal() {
    if (!modeModal) return;
    setStartDisabled(false);
    modeModal.classList.add("active");
    modeModal.style.display = "flex";
    document.body.classList.add("modal-open");
}

function hideModeModal() {
    if (!modeModal) return;
    modeModal.classList.remove("active");
    modeModal.style.display = "none";
    document.body.classList.remove("modal-open");
    if (urlError) urlError.textContent = "";
}

function closeModal() {
    hideModeModal();
}

function setStartDisabled(disabled) {
    if (!startBtn) return;
    startBtn.disabled = !!disabled;
    startBtn.classList.toggle("disabled", !!disabled);
}

function startAttackSimulation() {
    console.log("Starting dynamic attack...");
    setStartDisabled(true);
    if (attackStatus) attackStatus.textContent = "Launching simulated attack...";
    setAttackLed(true);
    setConsoleText("Launching simulated attack...");
    setUrlBanner(null);

    fetch('/start_attack', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            if (attackStatus) attackStatus.textContent = data.status || "Attack started!";
            setConsoleText(data.status || "Attack started!");
            logTimelineEvent("User triggered dynamic attack simulation.");
        })
        .catch(err => {
            if (attackStatus) attackStatus.textContent = "Failed to start attack.";
            setConsoleText("Attack trigger failed.");
            console.error("Attack trigger error:", err);
            setBanner("alert", "Dynamic attack failed to start.");
        })
        .finally(() => {
            setStartDisabled(false);
            setTimeout(() => setAttackLed(false), 1200);
        });
}

function triggerUrlCapture(url) {
    console.log("Starting URL capture for", url);
    setStartDisabled(true);
    if (attackStatus) attackStatus.textContent = "Capturing URL traffic...";
    setAttackLed(true);
    setConsoleText(`Capturing traffic from ${url} ...`);
    setBanner("ok", `URL capture started for ${url}`);

    fetch('/scan_url', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url })
    })
        .then(r => r.json())
        .then(res => {
            if (res.error) {
                setBanner("alert", `URL capture failed: ${res.error}`);
                setConsoleText(`URL capture failed: ${res.error}`);
                logTimelineEvent(`URL capture failed: ${res.error}`);
                return;
            }
            setUrlBanner(url);
            if (attackStatus) attackStatus.textContent = `URL traffic captured (${res.code})`;
            logTimelineEvent(`Captured URL traffic from ${url} (status ${res.code})`);
            setConsoleText(`URL capture complete: ${url}`);
        })
        .catch(err => {
            setBanner("alert", "URL capture failed (network/timeout)");
            setConsoleText("URL capture failed.");
            logTimelineEvent("URL capture failed (network/timeout)");
            console.error("URL capture error:", err);
        })
        .finally(() => {
            setTimeout(() => setAttackLed(false), 1000);
            setStartDisabled(false);
        });
}

function startMode() {
    const selected = document.querySelector('input[name="mode"]:checked') ||
        document.querySelector('input[name="traffic-mode"]:checked');
    const mode = selected ? selected.value : "dynamic";
    if (urlError) urlError.textContent = "";
    console.log("Mode selected:", mode);

    if (mode === "url") {
        const url = (urlInput?.value || "").trim();
        if (!url) {
            setBanner("alert", "Enter a URL to capture.");
            setConsoleText("URL capture aborted: missing URL.");
            return;
        }
        hideModeModal(); // close immediately
        triggerUrlCapture(url);
    } else {
        hideModeModal(); // close immediately
        startAttackSimulation();
    }
}

function attachAttackHandler() {
    if (attackBtn) attackBtn.addEventListener("click", showModeModal);
    if (modeStartBtn) modeStartBtn.addEventListener("click", startMode);
    if (modeCancelBtn) modeCancelBtn.addEventListener("click", hideModeModal);
    if (modeModal) {
        modeModal.addEventListener("click", (e) => {
            if (e.target === modeModal) hideModeModal();
        });
    }
}

function initializeDashboard() {
    fetch('/api/reset', { method: 'POST' })
        .catch(err => console.error("Reset Error:", err))
        .finally(() => {
            // local reset
            timeData = [];
            normalData = [];
            maliciousData = [];
            blockedData = [];
            t = 0;
            lastStats = { normal: 0, malicious: 0, blocked: 0, load: 0, total: 0 };
            lastUpdateTime = Date.now();
            updateStats();
            loadPackets();
        });
}

initializeDashboard();
// Ensure handlers are attached even if DOMContentLoaded hook is missed
attachAttackHandler();
