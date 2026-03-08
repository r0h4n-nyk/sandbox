/**
 * eventBus.js
 * -----------
 * Centralized singleton EventEmitter used to decouple the parser
 * from the WebSocket broadcast logic in server.js.
 *
 * Events:
 *   "attack_event" — emitted by parser.js, consumed by server.js
 */

const { EventEmitter } = require("events");

const eventBus = new EventEmitter();

// Raise the listener cap to avoid warnings in larger deployments
// where multiple modules attach listeners to the same event.
eventBus.setMaxListeners(50);

module.exports = eventBus;