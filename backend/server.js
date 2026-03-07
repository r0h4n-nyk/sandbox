/**
 * server.js
 * ---------
 * Entry point for the attack dashboard backend.
 */

const http    = require("http");
const express = require("express");
const cors    = require("cors");
const path    = require("path"); // Added for file paths
const { WebSocketServer } = require("ws");

const eventBus        = require("./eventBus.js");
const { startParser } = require("./parser.js");

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

app.use(cors());
app.use(express.json());

/**
 * GET /health
 */
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// ---------------------------------------------------------------------------
// SERVE FRONTEND (The missing piece)
// ---------------------------------------------------------------------------

// Since server.js is in /backend, we go up one level to find /dist
const distPath = path.join(__dirname, "..", "dist");

// 1. Serve static files (js, css, images)
app.use(express.static(distPath));

// 2. Handle SPA routing (redirect all other GETs to index.html)
// This ensures that if you refresh the page on a sub-route, it won't 404.
app.get("*", (req, res) => {
  res.sendFile(path.join(distPath, "index.html"));
});

// ---------------------------------------------------------------------------
// HTTP server (shared by Express and WebSocket)
// ---------------------------------------------------------------------------

const server = http.createServer(app);

// ---------------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------------

const wss = new WebSocketServer({ server });
const clients = new Set();

wss.on("connection", (ws, req) => {
  const clientIp = req.socket.remoteAddress;
  clients.add(ws);
  console.log(`[ws] Connected: ${clientIp} — Total: ${clients.size}`);

  ws.on("close", () => {
    clients.delete(ws);
    console.log(`[ws] Disconnected: ${clientIp} — Total: ${clients.size}`);
  });

  ws.on("error", (err) => {
    console.error(`[ws] Error (${clientIp}):`, err.message);
    clients.delete(ws);
  });
});

// ---------------------------------------------------------------------------
// Broadcast attack events
// ---------------------------------------------------------------------------

eventBus.on("attack_event", (event) => {
  if (clients.size === 0) return;
  const payload = JSON.stringify(event);
  for (const ws of clients) {
    if (ws.readyState === ws.OPEN) {
      ws.send(payload);
    }
  }
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

server.listen(PORT, () => {
  console.log(`[server] Running on port ${PORT}`);
  console.log(`[server] Serving static files from: ${distPath}`);
  startParser();
});