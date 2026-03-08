/**
 * parser.js
 * ---------
 * Watches cowrie.json for new attacks.
 * Task 1: Instantly emits raw logs for the GeoIP Map.
 * Task 2: Buffers logs into Sessions and emits them when closed.
 */

const fs       = require("fs");
const path     = require("path");
const eventBus = require("./eventBus");
const { normalizeCowrieEvent } = require("./schema");

const LOG_PATH = process.env.LOG_PATH || "cowrie.json";
const COMPLETED_SESSIONS_FILE = path.join(__dirname, "completed_sessions.json");
const POLL_INTERVAL = Number(process.env.POLL_INTERVAL_MS) || 500;

// RAM Buffer for active attack sessions
const activeSessions = new Map();

async function processLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return;

  let raw;
  try {
    raw = JSON.parse(trimmed);
  } catch { return; }

  // TASK 1: INSTANT GEO-IP ROUTING
  // Emit immediately so the React map can plot the red dot
  eventBus.emit("live_log", raw);

  // TASK 2: SESSION BUFFERING
  const sessionId = raw.session;
  if (!sessionId) return;

  const eventId = raw.eventid || "";
  const timestamp = raw.timestamp;

  // Initialize new session
  if (!activeSessions.has(sessionId)) {
    activeSessions.set(sessionId, {
      session_id: sessionId,
      source_ip: raw.src_ip || "Unknown",
      start_time: timestamp,
      end_time: timestamp,
      total_events: 0,
      timeline: []
    });
  }

  const session = activeSessions.get(sessionId);
  session.end_time = timestamp;
  session.total_events += 1;

  // Normalize the raw log into our clean timeline format
  const cleanEvent = normalizeCowrieEvent(raw);
  if (cleanEvent) {
    session.timeline.push(cleanEvent);
  }

  // TRIGGER: SESSION CLOSES
  if (eventId === "cowrie.session.closed") {
    const completedSession = activeSessions.get(sessionId);
    activeSessions.delete(sessionId);

    // Save to disk for persistence
    fs.appendFile(COMPLETED_SESSIONS_FILE, JSON.stringify(completedSession) + "\n", (err) => {
      if (err) console.error("[parser] Failed to save session:", err);
    });

    // Notify the dashboard
    console.log(`\n[*] Session ${sessionId} closed! Emitting to dashboard...`);
    eventBus.emit("session_completed", completedSession);
  }
}

function splitLines(text) {
  const parts = text.split(/\r?\n/);
  const remainder = parts.pop();
  return { lines: parts, remainder };
}

function startParser() {
  let fileOffset = 0;
  let lineBuffer = "";
  let initialised = false;

  console.log(`[parser] Watching ${LOG_PATH} for new events...`);

  const poll = async () => {
    try {
      let stat;
      try { stat = await fs.promises.stat(LOG_PATH); } 
      catch (err) { if (err.code === "ENOENT") return; throw err; }

      const fileSize = stat.size;

      if (!initialised) {
        fileOffset = fileSize;
        initialised = true;
        console.log(`[parser] Skipping existing content. Starting at byte ${fileOffset}`);
        return;
      }

      if (fileSize < fileOffset) { fileOffset = 0; lineBuffer = ""; }
      if (fileSize === fileOffset) return;

      const length = fileSize - fileOffset;
      const buf = Buffer.alloc(length);
      const fh = await fs.promises.open(LOG_PATH, "r");
      
      try {
        const { bytesRead } = await fh.read(buf, 0, length, fileOffset);
        fileOffset += bytesRead;
      } finally { await fh.close(); }

      const text = lineBuffer + buf.toString("utf8");
      const { lines, remainder } = splitLines(text);
      lineBuffer = remainder;

      for (const line of lines) { await processLine(line); }

    } catch (err) { console.error("[parser] Poll error:", err.message); }
  };

  setInterval(poll, POLL_INTERVAL);
}

module.exports = { startParser };