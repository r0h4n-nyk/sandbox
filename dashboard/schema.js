/**
 * schema.js
 * ---------
 * Helper logic to normalize raw Cowrie events into the clean 
 * timeline objects required for the AI narrative and dashboard graphs.
 */

function normalizeCowrieEvent(raw) {
  const eventId = raw.eventid || "";
  
  // Base event data
  const cleanEvent = {
    timestamp: raw.timestamp,
    action: eventId
  };

  // Extract relevant context based on the type of attack event
  if (eventId.includes("login")) {
    cleanEvent.username = raw.username || raw.user || "";
    cleanEvent.password = raw.password || "";
    cleanEvent.status = eventId.includes("success") ? "Success" : "Failed";
    return cleanEvent;
  } 
  
  if (eventId.includes("command.input")) {
    cleanEvent.command = raw.input || "";
    return cleanEvent;
  } 
  
  if (eventId.includes("file_download")) {
    cleanEvent.url = raw.url || "";
    return cleanEvent;
  }

  // If it's just a connect/closed or kex event, just return the action and timestamp
  if (eventId.includes("session.connect") || eventId.includes("session.closed")) {
      return cleanEvent;
  }

  // Ignore noisy protocol events (kex, versions, etc) for the timeline
  return null; 
}

module.exports = { normalizeCowrieEvent };