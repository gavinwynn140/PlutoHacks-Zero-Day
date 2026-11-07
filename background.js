/* =====================================================================
   Zero Day: background service worker

   Job: open the side panel when the person clicks the toolbar icon.

   Why we listen for the click ourselves instead of using
   chrome.sidePanel.setPanelBehavior({ openPanelOnActionClick: true }):
   a real action click is one of the few gestures Chrome documents as
   granting the "activeTab" permission. Handling onClicked ourselves
   makes sure that grant happens, so the Scan button can read the page
   without us asking for broad "all websites" access at install time.
   (activeTab lasts until the tab moves to a different site, so
   sidepanel.js explains how to re-grant it when needed.)
   ===================================================================== */

// Make sure the panel is registered and available on every tab.
chrome.runtime.onInstalled.addListener(() => {
  chrome.sidePanel
    .setOptions({ path: 'sidepanel.html', enabled: true })
    .catch((err) => console.error('Zero Day: could not set up side panel', err));
});

// Toolbar icon click: open the panel for this window.
// sidePanel.open() must run straight away inside the click handler
// (no awaiting anything first), or Chrome will treat it as "not a user action".
chrome.action.onClicked.addListener((tab) => {
  chrome.sidePanel
    .open({ windowId: tab.windowId })
    .catch((err) => console.error('Zero Day: could not open side panel', err));
});
