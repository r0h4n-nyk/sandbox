/**
 * parser.js
 * ---------
 * Watches attacks.log for newly appended NDJSON lines using tail-file.
 *
 * Pipeline per line:
 *   1. JSON.parse()        — handles raw string from log file
 *   2. validateEvent()     — checks raw shape with Zod
 *   3. normalizeEvent()    — remaps spaced keys → clean snake_case shape
 *   4. eventBus.emit()     — forwards normalized event to server.js
 *
 * Malformed or invalid lines are logged and skipped.
 * The watcher never crashes on bad input.
 */

const TailFile = require("tail-file");
const eventBus = require("./eventBus");
const { validateEvent, normalizeEvent } = require("./schema");

// Allow the log path to be overridden via environment variable.
const LOG_PATH = process.env.LOG_PATH || "attacks.log";

// ---------------------------------------------------------------------------
// startParser
// ---------------------------------------------------------------------------

/**
 * Starts the tail-file watcher.
 * Called once by server.js on startup.
 */
function startParser() {
  const tail = new TailFile(LOG_PATH, {
    startPos:     "end",   // Only process lines appended after startup.
    pollInterval: 250,     // 250 ms poll — low latency, negligible CPU.
  });

  // ── New line handler ──────────────────────────────────────────────────────
  tail.on("line", (line) => {
    const trimmed = line.trim();

    // Skip blank lines that may appear between log writes.
    if (!trimmed) return;

    // Step 1: Parse JSON ---------------------------------------------------
    let raw;
    try {
      raw = JSON.parse(trimmed);
    } catch {
      console.error(
        "[parser] Invalid JSON — skipping line:",
        trimmed.slice(0, 120)
      );
      return;
    }

    // Step 2: Validate raw shape -------------------------------------------
    const result = validateEvent(raw);

    if (!result.success) {
      console.error(
        "[parser] Invalid event detected:",
        result.error.flatten()
      );
      return;
    }

    // Step 3: Normalize to clean broadcast shape ---------------------------
    const normalized = normalizeEvent(result.data);

    // Step 4: Emit onto the bus --------------------------------------------
    eventBus.emit("attack_event", normalized);
  });

  // ── Error handler ─────────────────────────────────────────────────────────
  tail.on("error", (err) => {
    console.error("[parser] Tail error:", err.message);
  });

  // ── Start watching ────────────────────────────────────────────────────────
  try {
    tail.start();
    console.log("Watching attacks.log for new events...");
    } catch (err) {
    console.error("[parser] Failed to start tail watcher:", err.message);
    }
}

module.exports = { startParser };