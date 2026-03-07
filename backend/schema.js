/**
 * schema.js
 * ---------
 * Validates the RAW event format written by the Python engine, then
 * normalizes it into a clean flat shape for WebSocket broadcast.
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * RAW shape (from attacks.log):
 * {
 *   "time stamp":  "2023-10-27T10:00:05Z",
 *   "src ip":      "192.168.1.50",
 *   "event id":    "event.cowrie.login",
 *   "session id":  "session_999",
 *   "input":       null,
 *   "user":        "root",
 *   "password":    "password123",
 *   "response": {
 *     "tactic": "Initial Access",
 *     "techniques": [{ "mitigations": [{ "id": "M1036", "name": "...", "description": "..." }] }]
 *   },
 *   "ai_response": {
 *     "summary": { "<summary text as object key>": null },
 *     "persona": "Human" | "bot" | "cant decide"
 *   }
 * }
 *
 * ─────────────────────────────────────────────────────────────────────────────
 * NORMALIZED shape broadcast to frontend:
 * {
 *   timestamp, src_ip, event_id, session_id,
 *   input, username, password,
 *   tactic,
 *   mitigations: [{ id, name, description }] | null,
 *   ai_summary:  "<plain string>",
 *   persona:     "Human" | "bot" | "cant decide" | null
 * }
 */

const { z } = require("zod");

// ---------------------------------------------------------------------------
// Sub-schemas
// ---------------------------------------------------------------------------

const MitigationSchema = z.object({
  id:          z.string(),
  name:        z.string(),
  description: z.string().optional(),
});

const TechniqueSchema = z.object({
  mitigations: z.array(MitigationSchema).optional(),
});

const ResponseSchema = z.object({
  tactic:     z.string().optional(),
  techniques: z.array(TechniqueSchema).optional(),
});

// ai_response schema:
//   summary  — object whose single key IS the summary text (Python quirk)
//              also accept plain string defensively
//   persona  — "Human" | "bot" | "cant decide"
const AiResponseSchema = z.object({
  summary: z.union([
    z.record(z.unknown()),   // { "<summary text>": ... }  ← real shape
    z.string(),              // plain string               ← defensive fallback
  ]).optional(),
  persona: z.enum(['Human', 'bot', 'cant decide']).optional(),
});

// ---------------------------------------------------------------------------
// Raw event schema  (keys exactly as written by the Python engine)
// ---------------------------------------------------------------------------

const RawEventSchema = z.object({
  "time stamp": z.string(),
  "src ip":     z.string(),
  "event id":   z.string().optional(),
  "session id": z.string().optional(),
  input:        z.string().nullable().optional(),
  user:         z.string().optional(),
  password:     z.string().optional(),
  response:     ResponseSchema.optional(),
  ai_response:  AiResponseSchema.optional(),
});

// ---------------------------------------------------------------------------
// validateEvent
// ---------------------------------------------------------------------------

/**
 * Validates a raw parsed object against RawEventSchema.
 *
 * @param {unknown} data
 * @returns {{ success: true, data: RawEvent } | { success: false, error: ZodError }}
 */
function validateEvent(data) {
  return RawEventSchema.safeParse(data);
}

// ---------------------------------------------------------------------------
// normalizeEvent
// ---------------------------------------------------------------------------

/**
 * Flattens a validated raw event into the clean shape sent to the dashboard.
 *
 * @param {z.infer<typeof RawEventSchema>} raw
 * @returns {NormalizedEvent}
 */
function normalizeEvent(raw) {
  // Collect all mitigations from all technique entries into one flat array
  const mitigations = (raw.response?.techniques ?? []).flatMap(
    (t) => t.mitigations ?? []
  );

  // summary is stored as an object whose key IS the summary text:
  //   { "The attacker is attempting...": null }
  // Extract the first key as the plain string.
  // Fall back to plain string if the Python engine ever fixes the format.
  const rawSummary = raw.ai_response?.summary;
  let ai_summary = null;
  if (typeof rawSummary === 'string') {
    ai_summary = rawSummary;
  } else if (rawSummary && typeof rawSummary === 'object') {
    const firstKey = Object.keys(rawSummary)[0] ?? null;
    ai_summary = firstKey;
  }

  // persona comes directly from the Python engine — pass through as-is.
  // Possible values: "Human" | "bot" | "cant decide" | undefined → null
  const persona = raw.ai_response?.persona ?? null;

  return {
    timestamp:   raw["time stamp"],
    src_ip:      raw["src ip"],
    event_id:    raw["event id"]   ?? null,
    session_id:  raw["session id"] ?? null,
    input:       raw.input         ?? null,
    username:    raw.user          ?? null,
    password:    raw.password      ?? null,
    tactic:      raw.response?.tactic ?? null,
    mitigations: mitigations.length ? mitigations : null,
    ai_summary,
    persona,
  };
}

module.exports = { validateEvent, normalizeEvent };