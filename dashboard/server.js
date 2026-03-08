/**
 * server.js
 * ---------
 * Entry point for the attack dashboard backend.
 */

const http    = require("http");
const express = require("express");
const cors    = require("cors");
const path    = require("path");
const { WebSocketServer } = require("ws");

const eventBus        = require("./eventBus.js");
const { startParser } = require("./parser.js");

const PORT = process.env.PORT || 3000;
const OLLAMA_URL = process.env.OLLAMA_URL || "http://localhost:11434/api/generate";
const MODEL = "llama3.1";

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();
app.use(cors());
app.use(express.json());

app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// ---------------------------------------------------------------------------
// THE NEW AI ENDPOINT (/analyze)
// ---------------------------------------------------------------------------
app.post("/analyze", async (req, res) => {
  const sessionData = req.body;
  if (!sessionData || !sessionData.session_id) {
    return res.status(400).json({ error: "Invalid session data provided." });
  }

  const sessId = sessionData.session_id;
  const srcIp = sessionData.source_ip;
  
  // Build the chronological story for the AI
  let narrative = `Session ID: ${sessId}\nSource IP: ${srcIp}\nSession Start: ${sessionData.start_time}\nSession End: ${sessionData.end_time}\nTotal Events: ${sessionData.total_events}\nTimeline:\n`;
  
  (sessionData.timeline || []).forEach(event => {
    if (event.action.includes("login")) {
      narrative += `- Login ${event.status}: ${event.username || 'N/A'} / ${event.password || 'N/A'}\n`;
    } else if (event.action.includes("command.input")) {
      narrative += `- Executed Command: '${event.command}'\n`;
    } else if (event.action.includes("file_download")) {
      narrative += `- Downloaded File from: ${event.url}\n`;
    }
  });

  const prompt = `
  You are an expert SOC Analyst analyzing a complete honeypot session timeline.
  Event Details:
  ${narrative}

  Task 1: Classify the attacker into EXACTLY ONE of these Personas:
  - Automated Bot (Machine speed, rapid brute-forcing, instant execution of wget/curl scripts)
  - Script Kiddie (Human speed, basic noisy commands like 'whoami', 'ls', manual exploration)
  - Advanced Threat (Stealthy, complex encoded payloads, clearing logs, privilege escalation)

  Task 2: Write a highly descriptive, 2-3 sentence technical summary of the ENTIRE session.

  OUTPUT RULE: You must output ONLY valid JSON. Do not include markdown backticks.
  Format exactly like this:
  {
    "persona": "Persona Name",
    "summary": "Your highly descriptive session summary here"
  }
  `;

  console.log(`\n[*] Requesting AI analysis for session ${sessId}...`);

  try {
    // Native Node.js fetch to Ollama
    const response = await fetch(OLLAMA_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model: MODEL, prompt: prompt, stream: false })
    });

    if (!response.ok) throw new Error(`Ollama HTTP Error: ${response.status}`);
    
    const rawData = await response.json();
    const cleanStr = rawData.response.replace(/```json/g, "").replace(/```/g, "").trim();
    
    const aiData = JSON.parse(cleanStr);
    console.log(`[+] AI Classification: ${aiData.persona}`);
    res.json(aiData);

  } catch (error) {
    console.error("[-] AI Analysis failed:", error.message);
    res.json({ persona: "Unknown", summary: "Failed to reach local Ollama AI or parse response." });
  }
});

// ---------------------------------------------------------------------------
// SERVE FRONTEND
// ---------------------------------------------------------------------------
const distPath = path.join(__dirname, "..", "dist");
app.use(express.static(distPath));
app.get("/{*path}", (req, res) => res.sendFile(path.join(distPath, "index.html")));

// ---------------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------------
const server = http.createServer(app);
const wss = new WebSocketServer({ server });
const clients = new Set();

wss.on("connection", (ws, req) => {
  clients.add(ws);
  ws.on("close", () => clients.delete(ws));
  ws.on("error", () => clients.delete(ws));
});

// Helper to broadcast strongly typed messages
function broadcast(type, data) {
  if (clients.size === 0) return;
  const payload = JSON.stringify({ type, data });
  for (const ws of clients) {
    if (ws.readyState === ws.OPEN) ws.send(payload);
  }
}

// Listen to the EventBus
eventBus.on("live_log", (log) => broadcast("live_log", log));
eventBus.on("session_completed", (session) => broadcast("session_completed", session));

server.listen(PORT, () => {
  console.log(`[server] Running on port ${PORT}`);
  startParser();
});