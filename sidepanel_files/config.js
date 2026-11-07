/* =====================================================================
   Zero Day: configuration (loaded by sidepanel.html before sidepanel.js)

   People who use Zero Day never see or enter an API key. The key lives
   here, on the "backend" side of the project, and the scan runs for them.

   HOW A SCAN IS SENT (checked in this order):
     1. SCAN_PROXY_URL is set  -> sends the cleaned page to YOUR server.
        Your server holds the Gemini key and the instructions, calls
        Gemini, and replies with the verdict JSON (see "Verdict format").
        RECOMMENDED for the Chrome Web Store: nothing secret ships inside
        the extension.
     2. GEMINI_API_KEY is set  -> calls Gemini directly from the extension.
        Good for development. Anyone can unpack an installed extension and
        read this file, so don't publish a real key this way. Restrict the
        key in Google AI Studio, or use option 1 before release.
     3. Neither is set         -> demo mode (simple keyword check, nothing
        is sent anywhere).

   If Chrome blocks the request with a CORS error, add the server's origin
   to "host_permissions" in manifest.json (this adds an install warning).
   ===================================================================== */
'use strict';

const SCAN_PROXY_URL = '';   // e.g. 'https://api.example.com/zero-day/scan'  (POST { payload } -> verdict JSON)
const GEMINI_API_KEY = 'AQ.Ab8RN6LVTrkBUUPeWguMSpCfio8uK1JJOGk3w3f-m--mfgx6hQ';   // paste the key here for direct mode (development only)
const GEMINI_MODEL   = 'gemini-3.1-flash-lite'; // change to whichever Gemini model you use

// While true, scan errors also show the technical reason (and the full reply
// is logged in the browser console). Set to false before you publish.
const DEBUG_SCAN = true;

const GEMINI_ENDPOINT = `https://generativelanguage.googleapis.com/v1beta/models/${GEMINI_MODEL}:generateContent`;

/* ---------------------------------------------------------------------
   Gemini instructions (used in direct mode; in proxy mode your server
   should hold its own copy so nobody can reuse your proxy for other things).
   --------------------------------------------------------------------- */
const GEMINI_SYSTEM_PROMPT = `You are a friendly, highly skilled IT and cybersecurity consultant. Your job is to analyze the text content of a webpage or email provided to you and determine if it contains a phishing attempt, scam, or malware threat.

Your target audience is an average internet user with low tech-literacy. You must communicate in simple, reassuring, and completely jargon-free English.

Analyze the provided text for:
1. Urgency or threatening language (e.g., "Your account will be suspended").
2. Requests for sensitive information or untrustworthy URLs.
3. Too-good-to-be-true offers.

Provide your response in strictly formatted JSON with the following four keys:
- "threat_level": A single string that must be exactly "SAFE", "CAUTION", or "DANGER".
- "meter_score": An integer from 1 to 100 representing the likelihood of a scam (1 = completely safe, 100 = confirmed scam).
- "action_items": An array of 2 to 3 short, highly actionable strings telling the user exactly what to do next. Do not use technical terms. (e.g., "Close this tab immediately," or "This looks like a standard receipt, it is safe to keep.")
- "verdict": A short paragraph explaining the decision that was made and how you judge the page's safety

Do not include any markdown formatting outside of the JSON object.`;

// Asks Gemini to follow the format above exactly.
const GEMINI_RESPONSE_SCHEMA = {
  type: 'OBJECT',
  properties: {
    threat_level: { type: 'STRING', enum: ['SAFE', 'CAUTION', 'DANGER'] },
    meter_score:  { type: 'INTEGER' },
    action_items: { type: 'ARRAY', items: { type: 'STRING' } },
    verdict:      { type: 'STRING' }
  },
  required: ['threat_level', 'meter_score', 'action_items', 'verdict']
};
