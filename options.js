/* =====================================================================
   Zero Day: options page logic

   - Accessibility settings save on every change (see settings.js).
   - The optional "every page" access uses chrome.permissions, which only
     works from a click, so it is a button.
   ===================================================================== */
'use strict';

const $ = (selector) => document.querySelector(selector);

let current = { ...DEFAULT_SETTINGS };
let flashTimer = null;

function flash(message) {
  const box = $('#flash');
  box.textContent = message;
  box.hidden = false;
  clearTimeout(flashTimer);
  flashTimer = setTimeout(() => { box.hidden = true; }, 2500);
}

async function saveSettings(partial) {
  current = { ...current, ...partial };
  await chrome.storage.local.set({ settings: current });
  flash('Saved.');
}

/* ---------- Text size and display options ---------- */

function showTextScale(percent) {
  $('#text-scale').value = String(percent);
  $('#text-scale-value').textContent = `${percent}%`;
}

function wireDisplaySettings() {
  const slider = $('#text-scale');

  // Live label while sliding; save when the person lets go.
  slider.addEventListener('input', () => {
    $('#text-scale-value').textContent = `${slider.value}%`;
    applySettings({ ...current, textScale: Number(slider.value) });
  });
  slider.addEventListener('change', () => saveSettings({ textScale: Number(slider.value) }));

  $('#text-reset').addEventListener('click', () => {
    showTextScale(DEFAULT_SETTINGS.textScale);
    saveSettings({ textScale: DEFAULT_SETTINGS.textScale });
  });

  [['#compact', 'compact'], ['#high-contrast', 'highContrast'], ['#reduce-motion', 'reduceMotion']]
    .forEach(([selector, key]) => {
      const box = $(selector);
      box.checked = Boolean(current[key]);
      box.addEventListener('change', () => saveSettings({ [key]: box.checked }));
    });
}

/* ---------- Optional "scan on every page" access ---------- */

const ALL_PAGES = { origins: ['<all_urls>'] };

async function refreshAccess() {
  const allowed = await chrome.permissions.contains(ALL_PAGES);
  $('#access-status strong').textContent = allowed
    ? 'Scanning is allowed on every page.'
    : 'Scanning needs a click on the shield icon for each new website.';
  $('#access-toggle').textContent = allowed ? 'Turn off scanning on every page' : 'Allow scanning on every page';
}

function wireAccess() {
  $('#access-toggle').addEventListener('click', async () => {
    try {
      const allowed = await chrome.permissions.contains(ALL_PAGES);
      if (allowed) await chrome.permissions.remove(ALL_PAGES);
      else await chrome.permissions.request(ALL_PAGES); // Chrome shows its own confirmation
    } catch (error) {
      console.error('Zero Day: permission change failed', error);
      flash("That didn't work. Please try again.");
    }
    refreshAccess();
  });
}

/* ---------- Start-up ---------- */

(async function init() {
  await initSettings();          // applies saved settings and keeps them live
  current = await loadSettings();
  showTextScale(current.textScale);
  wireDisplaySettings();
  wireAccess();
  refreshAccess();
})();
