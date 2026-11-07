/* =====================================================================
   Zero Day: shared settings (loaded by sidepanel.html and options.html)

   Saved in chrome.storage.local under the key "settings".
   Both pages call initSettings(), so a change made on the options page
   shows up in the open side panel straight away, with no reload.
   ===================================================================== */

const DEFAULT_SETTINGS = Object.freeze({
  textScale: 100,      // percent, 60 to 200 (100% is the default, which is smaller than before). Scales all text AND spacing (everything uses rem).
  compact: false,      // tighter spacing and fewer helper sentences, for narrow panels
  highContrast: false, // black-on-white with strong outlines
  reduceMotion: false  // meter jumps instead of sliding; no other movement
});

async function loadSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  return { ...DEFAULT_SETTINGS, ...(settings || {}) };
}

function applySettings(settings) {
  const root = document.documentElement;
  const percent = Math.min(200, Math.max(60, Number(settings.textScale) || 100));
  root.style.setProperty('--text-scale', String(percent / 100));
  root.classList.toggle('compact', Boolean(settings.compact));
  root.classList.toggle('high-contrast', Boolean(settings.highContrast));
  root.classList.toggle('reduce-motion', Boolean(settings.reduceMotion));
}

async function initSettings() {
  applySettings(await loadSettings());
  chrome.storage.onChanged.addListener((changes, area) => {
    if (area === 'local' && changes.settings) {
      applySettings({ ...DEFAULT_SETTINGS, ...(changes.settings.newValue || {}) });
    }
  });
}
