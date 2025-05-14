/**
 * Content script for Privacy Shield extension
 * This is injected into web pages to detect fingerprinting and cookies
 */

// Initialize extension state
let isExtensionValid = true;

// Handle extension context invalidation safely
function safeRuntimeCall(callback) {
  if (!isExtensionValid) return;
  
  try {
    callback();
  } catch (e) {
    if (e.message.includes('Extension context invalidated')) {
      isExtensionValid = false;
      console.warn('Extension context invalidated. Please reload this page.');
    } else {
      console.error('Extension error:', e);
    }
  }
}

// Create a console logger
const extensionLog = function(msg) {
  if (typeof msg === 'object') {
    msg = JSON.stringify(msg);
  }
  console.log(`[Privacy Shield] ${msg}`);
};
let fingerprintingAttempts = [];

// Inject the fingerprinting detector script
function injectDetector() {
  extensionLog("Injecting Fingerprint Detector...");
  const script = document.createElement('script');
  script.src = chrome.runtime.getURL('detector.js');
  script.onload = function() {
    const initScript = document.createElement('script');
    initScript.src = chrome.runtime.getURL('detector-init.js');
    document.head.appendChild(initScript);
  };
  (document.head || document.documentElement).appendChild(script);
}

// Safer message sending in content script
function safelyPostMessage(message) {
  try {
    chrome.runtime.sendMessage(message, response => {
      if (chrome.runtime.lastError) {
        console.error("Runtime error:", chrome.runtime.lastError.message);
        return;
      }
    });
  } catch (error) {
    console.error("Error sending message:", error);
  }
}

// Listen for messages from the injected script
window.addEventListener('message', function(event) {
  if (event.source !== window) return;
  if (event.data.type === 'FINGERPRINTING_DETECTED') {
    safelyPostMessage({
      type: 'fingerprintingDetected',
      data: {
        technique: event.data.data?.technique || 'unknown',
        domain: window.location.hostname,
        timestamp: Date.now()
      }
    });
  }
  
  // Forward full data exports
  if (event.data.type === 'FINGERPRINTING_DATA') {
    safeRuntimeCall(() => {
      chrome.runtime.sendMessage({
        type: 'fingerprintingData',
        domain: window.location.hostname,
        url: window.location.href,
        data: event.data.data,
        timestamp: Date.now()
      });
    });
  }

  if (event.data.type === 'GET_PRIVACY_SHIELD_SETTINGS') {
    // Get settings from background script
    safeRuntimeCall(() => {
      chrome.runtime.sendMessage({type: 'getSettings'}, response => {
        if (chrome.runtime.lastError) {
          console.error("Runtime error:", chrome.runtime.lastError.message);
          return;
        }
        
        // Send settings back to the page
        window.postMessage({
          type: 'PRIVACY_SHIELD_SETTINGS_UPDATE',
          settings: response
        }, '*');
        
        console.log("Sent settings to detector:", response);
      });
    });
  }
});

// Send page activity to background script periodically
const pageActivityInterval = setInterval(() => {
  safeRuntimeCall(() => {
    chrome.runtime.sendMessage({
      type: 'pageActive',
      domain: window.location.hostname,
      url: window.location.href,
      timestamp: Date.now()
    });
  });
}, 5000);

// Clean up interval when page is unloaded
window.addEventListener('beforeunload', () => {
  clearInterval(pageActivityInterval);
});

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'getStatus') {
    sendResponse({
      url: window.location.href,
      domain: window.location.hostname,
      attempts: fingerprintingAttempts.length
    });
    return true;
  }

  if (message.type === 'settingsUpdated') {
    // Forward to page context
    window.postMessage({
      type: 'PRIVACY_SHIELD_SETTINGS_UPDATE',
      settings: message.settings
    }, '*');
    
    console.log("Settings updated in content script:", message.settings);
    sendResponse({success: true});
    return false;
  }

  if (message.type === 'resetDetectorData') {
    // Forward to page context
    window.postMessage({
      type: 'PRIVACY_SHIELD_RESET_DATA'
    }, '*');
    sendResponse({success: true});
    return false;
  }
});

// Initialize when the page loads
function initialize() {
  injectDetector();
  // Check for existing cookies and report them
  document.addEventListener('DOMContentLoaded', () => {
    if (document.cookie) {
      const cookieCount = document.cookie.split(';').length;
      
      safeRuntimeCall(() => {
        chrome.runtime.sendMessage({
          type: 'pageCookies',
          domain: window.location.hostname,
          url: window.location.href,
          count: cookieCount,
          timestamp: Date.now()
        });
      });
    }
    // Send initial page data
    safeRuntimeCall(() => {
      chrome.runtime.sendMessage({
        type: 'pageActive',
        domain: window.location.hostname,
        url: window.location.href,
        timestamp: Date.now()
      });
    });
  });
}

initialize();