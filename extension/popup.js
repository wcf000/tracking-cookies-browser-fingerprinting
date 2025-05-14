/**
 * Popup script for Privacy Shield extension
 * Handles user interaction with the popup UI
 */

// Element references
let currentDomainEl;
let currentFingerprintingEl;
let currentCookiesEl;
let totalFingerprintingEl;
let totalCookiesEl;
let totalBlockedEl;
let blockFingerprintingToggle;
let blockCookiesToggle;
let showNotificationsToggle;
let saveStatusEl;
let dashboardButton;

// Initialize element references
function initializeElements() {
  currentDomainEl = document.getElementById('current-domain');
  currentFingerprintingEl = document.getElementById('current-fingerprinting');
  currentCookiesEl = document.getElementById('current-cookies');
  totalFingerprintingEl = document.getElementById('total-fingerprinting');
  totalCookiesEl = document.getElementById('total-cookies');
  totalBlockedEl = document.getElementById('total-blocked');
  blockFingerprintingToggle = document.getElementById('block-fingerprinting');
  blockCookiesToggle = document.getElementById('block-cookies');
  showNotificationsToggle = document.getElementById('show-notifications');
  saveStatusEl = document.getElementById('save-status');
  dashboardButton = document.getElementById('dashboard-button');
}

// Load settings from storage
function loadSettings() {
  chrome.storage.local.get('settings', function(result) {
    if (result.settings) {
      if (blockFingerprintingToggle) blockFingerprintingToggle.checked = result.settings.blockFingerprinting;
      if (blockCookiesToggle) blockCookiesToggle.checked = result.settings.blockTrackingCookies;
      if (showNotificationsToggle) showNotificationsToggle.checked = result.settings.showNotifications;
    }
  });
}

// Save settings to storage
function saveSettings() {
  const settings = {
    blockFingerprinting: blockFingerprintingToggle.checked,
    blockTrackingCookies: blockCookiesToggle.checked,
    showNotifications: showNotificationsToggle.checked,
    whitelist: []
  };
  
  chrome.storage.local.set({ settings }, function() {
    showSavedMessage();
    
    // Notify background script about the settings change
    chrome.runtime.sendMessage({
      type: 'updateSettings',
      settings: settings
    });
  });
}

// Show saved message
function showSavedMessage() {
  if (saveStatusEl) {
    saveStatusEl.textContent = 'Settings saved!';
    setTimeout(() => {
      saveStatusEl.textContent = '';
    }, 2000);
  }
}

// Update statistics
function updateStats() {
  chrome.tabs.query({ active: true, currentWindow: true }, function(tabs) {
    if (tabs && tabs.length > 0) {
      const currentTab = tabs[0];
      const url = new URL(currentTab.url);
      const domain = url.hostname;
      
      if (currentDomainEl) currentDomainEl.textContent = domain;
      
      // Get tracking data from background script
      chrome.runtime.sendMessage({ type: 'getTrackingData' }, function(data) {
        if (!data) {
          console.error("No tracking data received from background script");
          return;
        }
        
        // Update total counts
        if (data.fingerprinting) {
          if (totalFingerprintingEl) totalFingerprintingEl.textContent = data.fingerprinting.attempts || '0';
          if (totalCookiesEl) totalCookiesEl.textContent = data.cookies.trackers || '0';
          if (totalBlockedEl) totalBlockedEl.textContent = data.stats.blocked || '0';
          
          // Update domain-specific data if available
          const domainData = data.domains[domain];
          if (domainData) {
            if (currentFingerprintingEl) currentFingerprintingEl.textContent = domainData.fingerprinting || '0';
            if (currentCookiesEl) currentCookiesEl.textContent = domainData.trackers || '0';
          } else {
            if (currentFingerprintingEl) currentFingerprintingEl.textContent = '0';
            if (currentCookiesEl) currentCookiesEl.textContent = '0';
          }
        } 
        // Handle dashboard.js format (with fingerprintingAttempts as array)
        else if (data.fingerprintingAttempts) {
          if (totalFingerprintingEl) totalFingerprintingEl.textContent = data.fingerprintingAttempts.length || '0';
          
          // Count cookies
          let totalCookies = 0;
          if (data.trackingCookies) {
            Object.values(data.trackingCookies).forEach(domainCookies => {
              if (Array.isArray(domainCookies)) {
                totalCookies += domainCookies.length;
              }
            });
          }
          if (totalCookiesEl) totalCookiesEl.textContent = totalCookies;
          
          // Blocked count
          if (totalBlockedEl) totalBlockedEl.textContent = data.totalBlocked || '0';
          
          // Domain-specific data
          if (data.sitesVisited && data.sitesVisited[domain]) {
            const siteData = data.sitesVisited[domain];
            if (currentFingerprintingEl) currentFingerprintingEl.textContent = siteData.fingerprintingAttempts || '0';
            if (currentCookiesEl) currentCookiesEl.textContent = siteData.trackingCookies || '0';
          } else {
            if (currentFingerprintingEl) currentFingerprintingEl.textContent = '0';
            if (currentCookiesEl) currentCookiesEl.textContent = '0';
          }
        }
      });
    }
  });
}

// When popup loads
document.addEventListener('DOMContentLoaded', () => {
  initializeElements();
  loadSettings();
  updateStats();
  const statsInterval = setInterval(updateStats, 2000);
  
  // Clean up when popup closes
  window.addEventListener('unload', function() {
    clearInterval(statsInterval);
  });
  
  // Event listeners for settings changes
  if (blockFingerprintingToggle) blockFingerprintingToggle.addEventListener('change', saveSettings);
  if (blockCookiesToggle) blockCookiesToggle.addEventListener('change', saveSettings);
  if (showNotificationsToggle) showNotificationsToggle.addEventListener('change', saveSettings);
  
  // Dashboard button
  if (dashboardButton) {
    dashboardButton.addEventListener('click', () => {
      chrome.tabs.create({
        url: chrome.runtime.getURL('dashboard.html')
      });
    });
  }
});