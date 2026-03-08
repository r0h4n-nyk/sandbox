/**
 * parser.js
 * ---------
 * Watches attacks.log for newly appended NDJSON lines using a manual
 * fs.stat + fs.read polling loop.
 *
 * WHY NOT tail-file?
 *   tail-file relies on fs.watch / inotify to detect changes. On cloud
 *   environments (AWS EFS, GCP Filestore, Docker volumes, any NFS mount)
 *   inotify events are NEVER fired for remotely-written files, so updates
 *   are silently missed. Pure stat-polling works on every filesystem.
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

const fs       = require("fs");
const eventBus = require("./eventBus");
const { validateEvent, normalizeEvent } = require("./schema");

// Allow the log path to be overridden via environment variable.
const LOG_PATH     = process.env.LOG_PATH     || "attacks.log";
// Poll interval in ms. 500 ms is a good balance for cloud; lower if needed.
const POLL_INTERVAL = Number(process.env.POLL_INTERVAL_MS) || 500;

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/**
 * Process a single raw text line through the full validation + emit pipeline.
 * @param {string} line
 */
function processLine(line) {
  const trimmed = line.trim();
  if (!trimmed) return; // skip blank lines between log writes

  // Step 1: Parse JSON -------------------------------------------------------
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

  // Step 2: Validate raw shape -----------------------------------------------
  const result = validateEvent(raw);
  if (!result.success) {
    console.error("[parser] Invalid event detected:", result.error.flatten());
    return;
  }

  // Step 3: Normalize to clean broadcast shape --------------------------------
  const normalized = normalizeEvent(result.data);

  // Step 4: Emit onto the bus -------------------------------------------------
  eventBus.emit("attack_event", normalized);
}

/**
 * Splits a buffer into complete lines and a leftover tail.
 * Handles \r\n and \n line endings.
 *
 * @param {string} text
 * @returns {{ lines: string[], remainder: string }}
 */
function splitLines(text) {
  const parts = text.split(/\r?\n/);
  // The last element is either "" (text ended with newline) or a partial line.
  const remainder = parts.pop();
  return { lines: parts, remainder };
}

// ---------------------------------------------------------------------------
// startParser
// ---------------------------------------------------------------------------

/**
 * Starts a polling loop that tails LOG_PATH by tracking byte offset.
 * Works on local disks, NFS, Docker volumes, AWS EFS, GCP Filestore, etc.
 * Called once by server.js on startup.
 */
function startParser() {
  // Byte offset of the next unread byte in the file.
  let fileOffset = 0;
  // Carry-over text from the last read that didn't end with a newline.
  let lineBuffer  = "";
  // Whether we have already seeked to the end on first open.
  let initialised = false;

  console.log(`[parser] Watching ${LOG_PATH} for new events (poll every ${POLL_INTERVAL} ms)…`);

  const poll = async () => {
    try {
      // ------------------------------------------------------------------
      // 1. stat the file to get current size
      // ------------------------------------------------------------------
      let stat;
      try {
        stat = await fs.promises.stat(LOG_PATH);
      } catch (err) {
        // File doesn't exist yet — wait for it to appear.
        if (err.code === "ENOENT") return;
        throw err;
      }

      const fileSize = stat.size;

      // ------------------------------------------------------------------
      // 2. On the very first successful stat, seek to EOF so we only
      //    process lines appended AFTER the server started.
      // ------------------------------------------------------------------
      if (!initialised) {
        fileOffset  = fileSize;
        initialised = true;
        console.log(`[parser] Starting at byte offset ${fileOffset} (existing content skipped)`);
        return;
      }

      // ------------------------------------------------------------------
      // 3. Detect file truncation / rotation (fileSize shrank).
      // ------------------------------------------------------------------
      if (fileSize < fileOffset) {
        console.warn("[parser] Log file was truncated/rotated — resetting offset to 0");
        fileOffset = 0;
        lineBuffer  = "";
      }

      // ------------------------------------------------------------------
      // 4. Nothing new yet.
      // ------------------------------------------------------------------
      if (fileSize === fileOffset) return;

      // ------------------------------------------------------------------
      // 5. Read only the new bytes since the last poll.
      // ------------------------------------------------------------------
      const length = fileSize - fileOffset;
      const buf    = Buffer.alloc(length);

      const fh = await fs.promises.open(LOG_PATH, "r");
      try {
        const { bytesRead } = await fh.read(buf, 0, length, fileOffset);
        fileOffset += bytesRead;
      } finally {
        await fh.close();
      }

      // ------------------------------------------------------------------
      // 6. Decode, prepend any leftover partial line, then split into lines.
      // ------------------------------------------------------------------
      const text = lineBuffer + buf.toString("utf8");
      const { lines, remainder } = splitLines(text);
      lineBuffer = remainder; // hold incomplete final line for next poll

      // ------------------------------------------------------------------
      // 7. Process each complete line.
      // ------------------------------------------------------------------
      for (const line of lines) {
        processLine(line);
      }

    } catch (err) {
      console.error("[parser] Poll error:", err.message);
    }
  };

  // Kick off the interval.
  const timer = setInterval(poll, POLL_INTERVAL);

  // Allow the process to exit cleanly if nothing else is keeping it alive.
  if (timer.unref) timer.unref();
}

module.exports = { startParser };