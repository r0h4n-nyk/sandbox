/**
 * server.js
 * ---------
 * Entry point for the attack dashboard backend.
 *
 * Responsibilities:
 *   - Serve an Express HTTP server with CORS and a /health endpoint.
 *   - Run a WebSocket server (ws) on the same port.
 *   - Maintain the set of connected dashboard clients.
 *   - Subscribe to "attack_event" on the event bus and broadcast each
 *     event as a JSON string to every live client.
 *   - Boot the parser (tail-file watcher) so log monitoring starts
 *     automatically on server launch.
 *
 * Port: 3000 (override with PORT env var)
 */

const http    = require("http");
const express = require("express");
const cors    = require("cors");
const { WebSocketServer } = require("ws");

const eventBus        = require("./eventBus.js");
const { startParser } = require("./parser.js");   // <-- starts the log watcher

const PORT = process.env.PORT || 3000;

// ---------------------------------------------------------------------------
// Express app
// ---------------------------------------------------------------------------

const app = express();

// Allow all origins so the React dashboard can connect from any host.
app.use(cors());

// Parse JSON request bodies (useful for future REST endpoints).
app.use(express.json());

/**
 * GET /health
 * Simple liveness check used by load balancers / monitoring tools.
 */
app.get("/health", (_req, res) => {
  res.json({ status: "ok" });
});

// ---------------------------------------------------------------------------
// HTTP server (shared by Express and WebSocket)
// ---------------------------------------------------------------------------

const server = http.createServer(app);

// ---------------------------------------------------------------------------
// WebSocket server
// ---------------------------------------------------------------------------

const wss = new WebSocketServer({ server });

/**
 * Active client set.
 * Using a Set allows O(1) add/delete and easy iteration for broadcasts.
 */
const clients = new Set();

wss.on("connection", (ws, req) => {
  const clientIp = req.socket.remoteAddress;

  // Track the new client.
  clients.add(ws);
  console.log(
    `[ws] WebSocket client connected: ${clientIp} — total clients: ${clients.size}`
  );

  // ── Client disconnect ───────────────────────────────────────────────────
  ws.on("close", () => {
    clients.delete(ws);
    console.log(
      `[ws] WebSocket client disconnected: ${clientIp} — total clients: ${clients.size}`
    );
  });

  // ── Client-level errors — remove without crashing the server ───────────
  ws.on("error", (err) => {
    console.error(`[ws] Client error (${clientIp}):`, err.message);
    clients.delete(ws);
  });
});

// ---------------------------------------------------------------------------
// Broadcast attack events
// ---------------------------------------------------------------------------

/**
 * Whenever the parser validates a new event, broadcast it as a JSON string
 * to every currently connected WebSocket client.
 *
 * Clients that have closed between the last check and now are silently
 * skipped — readyState guards against mid-broadcast disconnects.
 */
eventBus.on("attack_event", (event) => {
  // Skip serialization entirely if nobody is listening.
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
  console.log(`[server] Attack dashboard backend running on port ${PORT}`);
  // Boot the log watcher — must come after the event bus listener above
  // so no events are missed between startup and the first broadcast.
  startParser();
});