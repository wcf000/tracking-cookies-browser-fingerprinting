/**
 * Background script for Privacy Shield extension
 * Handles tracking detection, blocking, and data storage
 */

// Initialize tracking data storage
let trackingData = {
  fingerprinting: {
    attempts: 0,
    domains: {},
    techniques: {}
  },
  cookies: {
    total: 0,
    trackers: 0,
    thirdParty: 0,
    domains: {}
  },
  stats: {
    pagesAnalyzed: 0,
    startTime: Date.now(),
    blocked: 0
  },
  domains: {},
  fingerprintingAttempts: []
};

// Add an initialization function to ensure data structure is consistent
function ensureTrackingDataStructure() {
  if (!trackingData) {
    trackingData = {
      fingerprinting: {
        attempts: 0,
        domains: {},
        techniques: {}
      },
      cookies: {
        total: 0,
        trackers: 0,
        thirdParty: 0,
        domains: {}
      },
      stats: {
        pagesAnalyzed: 0,
        startTime: Date.now(),
        blocked: 0
      },
      domains: {},
      fingerprintingAttempts: []
    };
  }
  
  // Ensure all nested objects exist
  if (!trackingData.fingerprinting) trackingData.fingerprinting = {attempts: 0, domains: {}, techniques: {}};
  if (!trackingData.fingerprinting.domains) trackingData.fingerprinting.domains = {};
  if (!trackingData.fingerprinting.techniques) trackingData.fingerprinting.techniques = {};
  if (!trackingData.cookies) trackingData.cookies = {total: 0, trackers: 0, thirdParty: 0, domains: {}};
  if (!trackingData.cookies.domains) trackingData.cookies.domains = {};
  if (!trackingData.domains) trackingData.domains = {};
  if (!trackingData.fingerprintingAttempts) trackingData.fingerprintingAttempts = [];
  if (!trackingData.stats) trackingData.stats = {pagesAnalyzed: 0, startTime: Date.now(), blocked: 0};
}
ensureTrackingDataStructure();

// Known tracking domains
const KNOWN_TRACKERS = [
  'doubleclick.net',
  'google-analytics.com',
  'facebook.net',
  'facebook.com',
  'adnxs.com',
  'amazon-adsystem.com',
  'criteo.com',
  'scorecardresearch.com',
  'googletagmanager.com',
  'advertising.com',
  'googlesyndication.com',
  'adsrvr.org',
  'demdex.net',
  'rlcdn.com',
  'adition.com',
  'hotjar.com',
  'quantserve.com',
  'rubiconproject.com',
  'mathtag.com',
  'pubmatic.com',
  'casalemedia.com',
  'moatads.com',
  'addthis.com',
  'taboola.com',
  'outbrain.com',
  'sharethis.com',
  'optimizely.com',
  'foresee.com',
  'liveperson.net',
  'hotjar.com'
];

// Default Settings
let settings = {
  blockFingerprinting: true,
  blockTrackingCookies: true,
  showNotifications: true,
  whitelist: []
};
const handledTypes = [
  'resetData',
  'getTrackingData', 
  'getSettings',
  'updateSettings',
  'fingerprintingDetected',
  'someAsyncOperation',
  'pageCookies',
  'testCookieBlocking'
];

// Track cookies already seen to avoid processing duplicates
const processedCookies = new Set();

function migrateOldCookieData() {
  if (!trackingData || !trackingData.cookies || !trackingData.cookies.domains) {
    return;
  }
  
  Object.entries(trackingData.cookies.domains).forEach(([domain, data]) => {
    // Skip if already in new format
    if (data && typeof data === 'object' && data.purposes) {
      return;
    }
    
    // Convert old number format
    if (typeof data === 'number') {
      trackingData.cookies.domains[domain] = {
        count: data,
        blocked: settings.blockTrackingCookies && !isWhitelisted(domain),
        lastSeen: Date.now(),
        purposes: {
          'Other Tracker': {
            count: data,
            examples: []
          }
        },
        examples: []
      };
    } 
    // Convert old object format with single category
    else if (typeof data === 'object') {
      const category = data.category || 'Other Tracker';
      trackingData.cookies.domains[domain] = {
        count: data.count || 0,
        blocked: data.blocked || false,
        lastSeen: data.lastSeen || Date.now(),
        purposes: {
          [category]: {
            count: data.count || 0,
            examples: data.examples || []
          }
        },
        examples: data.examples || []
      };
    }
  });
  chrome.storage.local.set({ trackingData });
}

// Load settings from storage
chrome.storage.local.get(['settings', 'trackingData'], function(result) {
  if (result.settings) {
    settings = result.settings;
  } else {
    chrome.storage.local.set({ settings });
  }
  
  if (result.trackingData) {
    trackingData = result.trackingData;
    if (!trackingData.fingerprintingAttempts) {
      trackingData.fingerprintingAttempts = [];
    }
    migrateOldCookieData();
  }
});

// Listen for messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'resetData') {
    resetTrackingData();
    sendResponse({ success: true });
    return false;
  }
  
  if (message.type === 'getTrackingData') {
    sendResponse(trackingData);
    return false;
  }
  
  if (message.type === 'getSettings') {
    sendResponse(settings);
    return false;
  }
  
  if (message.type === 'updateSettings') {
    updateSettings(message.settings);
    sendResponse({success: true});
    return false;
  }
  
  if (message.type === 'fingerprintingDetected') {
    // Process data and send response
    handleFingerprintingDetection(message.data, sender.tab);
    sendResponse({success: true});
    return false;
  }
  
  if (message.type === 'someAsyncOperation') {
    try {
      someAsyncFunction()
        .then(result => {
          try {
            sendResponse({ success: true, data: result });
          } catch (e) {
            console.error("Error in async response:", e);
          }
        })
        .catch(error => {
          try {
            sendResponse({ success: false, error: error.message });
          } catch (e) {
            console.error("Error in async error response:", e);
          }
        });
    } catch (e) {
      // Handle the case where someAsyncFunction throws synchronously
      sendResponse({ success: false, error: e.message });
      return false;
    }
    
    return true;
  }
  
  if (message.type === 'pageCookies') {
    // Update page analyzed count
    trackingData.stats.pagesAnalyzed++;
    
    // Update domain data
    const domain = message.domain;
    if (!trackingData.domains[domain]) {
      trackingData.domains[domain] = {
        fingerprinting: 0,
        cookies: message.count || 0,
        trackers: 0,
        lastDetected: Date.now()
      };
    } else {
      trackingData.domains[domain].lastDetected = Date.now();
    }
    
    sendResponse({success: true});
    return false;
  }
  
  // For debug testing with a test cookie
  if (message.type === 'testCookieBlocking') {
    console.log("Testing cookie blocking functionality");
    const testDomain = message.domain || 'example.com';
    chrome.cookies.set({
      url: `https://${testDomain}`,
      name: 'test_analytics_cookie',
      value: 'test_tracking_value',
      domain: `.${testDomain}`,
      path: '/',
      secure: true,
      httpOnly: false,
      expirationDate: Math.floor(Date.now()/1000) + 86400*60
    }, function(cookie) {
      console.log("Test cookie set:", cookie);
    });
    
    sendResponse({success: true});
    return false;
  }
  if (!message.type || !handledTypes.includes(message.type)) {
    sendResponse({ success: false, error: 'Unknown message type' });
  }
  
  return false;
});

// Handle fingerprinting detection from content script
function handleFingerprintingDetection(data, tab) {
  trackingData.fingerprinting.attempts++;
  
  // Extract domain
  let domain = 'unknown';
  if (tab && tab.url) {
    try {
      domain = new URL(tab.url).hostname;
    } catch (e) {
      console.error('Error parsing URL:', e);
      if (data.domain) domain = data.domain;
    }
  } else if (data.domain) {
    domain = data.domain;
  }
  
  // Get timestamp, technique
  const timestamp = data.timestamp || Date.now();
  const technique = data.technique || 'unknown';
  
  console.log(`Fingerprinting detected: ${technique} on ${domain}`);
  
  // Update domain-specific data
  if (!trackingData.domains[domain]) {
    trackingData.domains[domain] = {
      fingerprinting: 0,
      cookies: 0,
      trackers: 0,
      lastDetected: Date.now()
    };
  }
  
  trackingData.domains[domain].fingerprinting++;
  trackingData.domains[domain].lastDetected = Date.now();
  
  // Initialize techniques object if it doesn't exist
  if (!trackingData.fingerprinting.techniques) {
    trackingData.fingerprinting.techniques = {};
  }
  
  // Update technique-specific data
  trackingData.fingerprinting.techniques[technique] = 
    (trackingData.fingerprinting.techniques[technique] || 0) + 1;
  
  // Make sure domains is initialized
  if (!trackingData.fingerprinting.domains) {
    trackingData.fingerprinting.domains = {};
  }
  
  // Update domains counter
  trackingData.fingerprinting.domains[domain] = 
    (trackingData.fingerprinting.domains[domain] || 0) + 1;
    
  // Add to fingerprintingAttempts array
  trackingData.fingerprintingAttempts.push({
    domain: domain,
    technique: technique,
    timestamp: timestamp,
    blocked: settings.blockFingerprinting && !isWhitelisted(domain)
  });
  if (settings.blockFingerprinting && !isWhitelisted(domain)) {
    trackingData.stats.blocked++;
  }
  
  // Save updated data
  chrome.storage.local.set({ trackingData }, function() {
    chrome.tabs.query({url: chrome.runtime.getURL("dashboard.html")}, function(tabs) {
      if (tabs && tabs.length > 0) {
        tabs.forEach(tab => {
          try {
            chrome.tabs.sendMessage(tab.id, {
              type: 'dataUpdated',
              data: trackingData
            });
          } catch (e) {
            console.error("Error sending message to dashboard:", e);
          }
        });
      }
    });
  });
  
  // Show notification if enabled
  if (settings.showNotifications) {
    chrome.action.setBadgeText({ text: trackingData.fingerprinting.attempts.toString() });
    chrome.action.setBadgeBackgroundColor({ color: '#e74c3c' });
  }
}

// Handle cookie detection
function handleCookieDetection(data, tab) {
  // Extract domain
  let domain = 'unknown';
  let originDomain = 'unknown';
  
  if (tab && tab.url) {
    try {
      originDomain = new URL(tab.url).hostname;
    } catch (e) {
      console.error('Error parsing URL:', e);
    }
  }
  
  if (data.domain) {
    domain = data.domain.startsWith('.') ? data.domain.substring(1) : data.domain;
  }
  
  // Update tracking data
  trackingData.cookies.total++;
  
  // Check if this is a tracker
  const isTracker = isTrackingCookie(data, originDomain);
  if (isTracker) {
    console.log(`Tracking cookie detected: ${data.name} from ${data.domain}`);
    trackingData.cookies.trackers++;
    
    // Update domain records
    const domain = data.domain.startsWith('.') ? data.domain.substring(1) : data.domain;
    const cookieCategory = categorizeCookie(data);
    
    // Initialize domain entry if it doesn't exist
    if (!trackingData.cookies.domains[domain]) {
      trackingData.cookies.domains[domain] = {
        count: 0,
        blocked: settings.blockTrackingCookies && !isWhitelisted(domain),
        lastSeen: Date.now(),
        purposes: {},
        examples: []
      };
    }
    
    // Initialize purpose counter if it doesn't exist
    if (!trackingData.cookies.domains[domain].purposes[cookieCategory]) {
      trackingData.cookies.domains[domain].purposes[cookieCategory] = {
        count: 0,
        examples: []
      };
    }
    trackingData.cookies.domains[domain].count++;
    trackingData.cookies.domains[domain].purposes[cookieCategory].count++;
    
    // Store example cookies for each purpose
    if (!trackingData.cookies.domains[domain].purposes[cookieCategory].examples.includes(data.name) && 
        trackingData.cookies.domains[domain].purposes[cookieCategory].examples.length < 2) {
      trackingData.cookies.domains[domain].purposes[cookieCategory].examples.push(data.name);
    }
    
    // Also store in the overall examples list
    if (!trackingData.cookies.domains[domain].examples.includes(data.name) && 
        trackingData.cookies.domains[domain].examples.length < 5) {
      trackingData.cookies.domains[domain].examples.push(data.name);
    }
    // Update domain-specific data
    if (!trackingData.domains[domain]) {
      trackingData.domains[domain] = {
        fingerprinting: 0,
        cookies: 0,
        trackers: 1,
        lastDetected: Date.now()
      };
    } else {
      trackingData.domains[domain].trackers++;
      trackingData.domains[domain].lastDetected = Date.now();
    }
    // Immediately update the dashboard
    chrome.tabs.query({url: chrome.runtime.getURL("dashboard.html")}, function(tabs) {
      if (tabs && tabs.length > 0) {
        tabs.forEach(tab => {
          try {
            chrome.tabs.sendMessage(tab.id, {
              type: 'dataUpdated',
              data: trackingData
            });
          } catch (e) {
            console.error("Error sending message to dashboard:", e);
          }
        });
      }
    });
  }
  
  // Check if third-party
  if (isThirdPartyCookie(data, originDomain)) {
    trackingData.cookies.thirdParty++;
  }
  
  // Save updated data periodically
  if (trackingData.cookies.total % 10 === 0) {
    chrome.storage.local.set({ trackingData });
  }
  console.log("Current cookie tracking stats:", {
    total: trackingData.cookies.total,
    trackers: trackingData.cookies.trackers,
    domains: Object.keys(trackingData.cookies.domains).length,
    domainData: trackingData.cookies.domains
  });
}

// Identify frequently changing cookies that should be ignored
function isFrequentlyChangingCookie(cookie) {
  // Common session-state cookies that change frequently
  const frequentlyChaningPatterns = [
    '_dd_s',
    'RT',
    'AWSALB',
    'session_id'
  ];
  return frequentlyChaningPatterns.some(pattern => 
    cookie.name.includes(pattern)
  );
}

// Add this function to classify cookies by purpose
function categorizeCookie(cookie) {
  const name = cookie.name.toLowerCase();
  const domain = (cookie.domain || '').toLowerCase();
  
  // Analytics cookies
  if (name.includes('_ga') || name.includes('analytics') || name.includes('_utm') || 
      domain.includes('google-analytics') || domain.includes('hotjar')) {
    return 'Analytics';
  }
  
  // Advertising cookies
  if (name.includes('ads') || name.includes('advert') || name.includes('_fbp') || 
      domain.includes('doubleclick') || domain.includes('ad.') || 
      domain.includes('adnxs') || domain.includes('adsystem')) {
    return 'Advertising';
  }
  
  // Session/functional cookies
  if (name.includes('session') || name.includes('csrf') || 
      name.includes('auth') || name.includes('login')) {
    return 'Session/Authentication';
  }
  
  // Social media cookies
  if (domain.includes('facebook') || domain.includes('twitter') || 
      domain.includes('linkedin') || domain.includes('instagram') || 
      name.includes('share') || name.includes('social')) {
    return 'Social Media';
  }
  
  // Preferences cookies
  if (name.includes('pref') || name.includes('setting') || 
      name.includes('consent') || name.includes('notice')) {
    return 'Preferences';
  }
  
  // Performance/Technical cookies
  if (name.includes('cache') || name.includes('__cf') || name.includes('load') || 
      name.includes('perf') || domain.includes('cloudflare')) {
    return 'Performance';
  }
  
  // If it's a third-party cookie with none of the above, likely a tracker
  if (KNOWN_TRACKERS.some(tracker => domain.includes(tracker))) {
    return 'Tracking Network';
  }
  
  // Default fallback
  return 'Other Tracker';
}

// Monitor cookies
chrome.cookies.onChanged.addListener((changeInfo) => {
  const cookie = changeInfo.cookie;
  const removed = changeInfo.removed;
  const cause = changeInfo.cause;
  
  // Create a unique identifier for this cookie
  const cookieId = `${cookie.domain}|${cookie.name}|${cookie.path}`;
  console.log(`Cookie ${removed ? 'removed' : 'added'}: ${cookie.name} from ${cookie.domain} (${cause})`);
  if (removed || cause === 'overwrite' || 
      processedCookies.has(cookieId) || isFrequentlyChangingCookie(cookie)) {
    return;
  }

  // Add to processed set
  processedCookies.add(cookieId);
  if (processedCookies.size > 1000) {
    // Remove the oldest entries (convert to array, slice, convert back to set)
    const cookieArray = Array.from(processedCookies);
    processedCookies.clear();
    cookieArray.slice(-500).forEach(c => processedCookies.add(c));
  }
  trackingData.cookies.total++;
  
  // Check if this is a tracking cookie
  if (isTrackingCookie(cookie)) {
    console.log(`Tracking cookie detected: ${cookie.name} from ${cookie.domain}`);
    trackingData.cookies.trackers++;
    const domain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
    const cookieCategory = categorizeCookie(cookie);
    
    // Initialize domain entry if it doesn't exist
    if (!trackingData.cookies.domains[domain]) {
      trackingData.cookies.domains[domain] = {
        count: 0,
        blocked: settings.blockTrackingCookies && !isWhitelisted(domain),
        lastSeen: Date.now(),
        purposes: {},
        examples: []
      };
    }
    if (!trackingData.cookies.domains[domain].purposes[cookieCategory]) {
      trackingData.cookies.domains[domain].purposes[cookieCategory] = {
        count: 0,
        examples: []
      };
    }
    trackingData.cookies.domains[domain].count++;
    trackingData.cookies.domains[domain].purposes[cookieCategory].count++;
    
    // Store example cookies for each purpose (up to 2 per purpose)
    if (!trackingData.cookies.domains[domain].purposes[cookieCategory].examples.includes(cookie.name) && 
        trackingData.cookies.domains[domain].purposes[cookieCategory].examples.length < 2) {
      trackingData.cookies.domains[domain].purposes[cookieCategory].examples.push(cookie.name);
    }
    
    // Also store in the overall examples list (up to 5 total)
    if (!trackingData.cookies.domains[domain].examples.includes(cookie.name) && 
        trackingData.cookies.domains[domain].examples.length < 5) {
      trackingData.cookies.domains[domain].examples.push(cookie.name);
    }
    chrome.tabs.query({url: chrome.runtime.getURL("dashboard.html")}, function(tabs) {
      if (tabs && tabs.length > 0) {
        tabs.forEach(tab => {
          try {
            chrome.tabs.sendMessage(tab.id, {
              type: 'dataUpdated',
              data: trackingData
            });
          } catch (e) {
            console.error("Error sending message to dashboard:", e);
          }
        });
      }
    });
    
    // Find origin domain (what page set this cookie)
    let originDomain = 'unknown';
    chrome.tabs.query({active: true, lastFocusedWindow: true}, function(tabs) {
      if (tabs && tabs.length > 0) {
        try {
          originDomain = new URL(tabs[0].url).hostname;
          console.log(`Active tab domain: ${originDomain}, cookie domain: ${domain}`);
        } catch (e) {
          console.error('Error parsing URL:', e);
        }
      } else {
        console.log("No active tab found when processing cookie");
      }
      
      // Update domain-specific data
      if (!trackingData.domains[domain]) {
        trackingData.domains[domain] = {
          fingerprinting: 0,
          cookies: 0,
          trackers: 1,
          lastDetected: Date.now()
        };
      } else {
        trackingData.domains[domain].trackers++;
        trackingData.domains[domain].lastDetected = Date.now();
      }
      
      // Check if this is third-party
      if (isThirdPartyCookie(cookie, originDomain)) {
        trackingData.cookies.thirdParty++;
      }
      
      // Check if it should block this cookie
      if (settings.blockTrackingCookies && !isWhitelisted(domain)) {
        const cookieId = `${cookie.domain}|${cookie.name}|${cookie.path}`;
        processedCookies.add(cookieId);
        chrome.cookies.remove({
          url: getCookieUrl(cookie),
          name: cookie.name
        }, () => {
          trackingData.stats.blocked++;   
          console.log(`Blocked tracking cookie: ${cookie.name} from ${domain}`);
          chrome.storage.local.set({ trackingData });
        });
      } else {
        // Save updated data periodically
        if (trackingData.cookies.total % 10 === 0) {
          chrome.storage.local.set({ trackingData });
        }
      }
    });
  }
});

// Check if a domain is in the whitelist
function isWhitelisted(domain) {
  if (!domain || !settings.whitelist) return false;
  return settings.whitelist.some(whitelistedDomain => 
    domain.includes(whitelistedDomain) || whitelistedDomain.includes(domain)
  );
}

// Check if a cookie is a tracking cookie
function isTrackingCookie(cookie, originDomain) {
  // Check if domain is a known tracker
  const domain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
  const isKnownTracker = KNOWN_TRACKERS.some(tracker => domain.includes(tracker));
  
  if (isKnownTracker) return true;
  
  // Check cookie name patterns
  const trackingNames = ['_ga', '_gid', '_fbp', 'uuid', 'visitor', 'track',
                         'analytics', 'adid', 'userid', 'session', 'sid',
                         '__utm', 'visitor_id', 'tracking', 'uid', '_ym_'];
  const hasTrackingName = trackingNames.some(name => 
    cookie.name.toLowerCase().includes(name)
  );
  if (hasTrackingName) return true;
  
  // Check if third-party and has long expiration
  const isThirdParty = originDomain && !domain.includes(originDomain);
  const hasLongExpiration = cookie.expirationDate && 
    (cookie.expirationDate > (Date.now()/1000 + 86400*30));
  if (isThirdParty && hasLongExpiration) return true;
  return false;
}

// Check if a cookie is third-party
function isThirdPartyCookie(cookie, originDomain) {
  if (!originDomain) return false;
  const cookieDomain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
  return !cookieDomain.includes(originDomain) && !originDomain.includes(cookieDomain);
}

// Get URL for a cookie
function getCookieUrl(cookie) {
  const domain = cookie.domain.startsWith('.') ? cookie.domain.substring(1) : cookie.domain;
  const prefix = cookie.secure ? 'https://' : 'http://';
  return prefix + domain + cookie.path;
}

// Reset tracking data
function resetTrackingData() {
  trackingData = {
    fingerprinting: {
      attempts: 0,
      domains: {},
      techniques: {}
    },
    cookies: {
      total: 0,
      trackers: 0,
      thirdParty: 0,
      domains: {}
    },
    stats: {
      pagesAnalyzed: 0,
      startTime: Date.now(),
      blocked: 0
    },
    domains: {},
    fingerprintingAttempts: []
  };
  
  chrome.storage.local.set({ trackingData });
  chrome.action.setBadgeText({ text: '' });
  chrome.tabs.query({}, (tabs) => {
    tabs.forEach(tab => {
      try {
        chrome.tabs.sendMessage(tab.id, { type: 'resetDetectorData' });
      } catch (e) {
      }
    });
  });
}

async function getAllCookiesForDomain(domain) {
  return new Promise((resolve) => {
    chrome.cookies.getAll({domain}, (cookies) => {
      resolve(cookies);
    });
  });
}

// Export tracking data as JSON
async function exportTrackingData() {
  return new Promise((resolve) => {
    chrome.storage.local.get(['trackingData'], (result) => {
      const jsonData = JSON.stringify(result.trackingData, null, 2);
      const blob = new Blob([jsonData], {type: 'application/json'});
      const url = URL.createObjectURL(blob);
      
      chrome.downloads.download({
        url: url,
        filename: `tracking_data_${new Date().toISOString().slice(0,10)}.json`,
        saveAs: true
      }, () => {
        URL.revokeObjectURL(url);
        resolve();
      });
    });
  });
}

chrome.action.setBadgeBackgroundColor({ color: '#e74c3c' });

// Track pages analyzed
chrome.webNavigation.onCompleted.addListener((details) => {
  if (details.frameId === 0) {
    trackingData.stats.pagesAnalyzed++;
    chrome.storage.local.set({ trackingData });
  }
});

// Periodically save data (backup)
setInterval(() => {
  chrome.storage.local.set({ trackingData });
}, 5 * 60 * 1000);

// Update settings
function updateSettings(newSettings) {
  settings = {...settings, ...newSettings};
  
  // Save to storage
  chrome.storage.local.set({settings}, function() {
    console.log("Settings saved:", settings);
    
    // Notify all tabs about the update
    chrome.tabs.query({}, tabs => {
      tabs.forEach(tab => {
        try {
          chrome.tabs.sendMessage(tab.id, {
            type: 'settingsUpdated',
            settings: settings
          }, response => {
            if (chrome.runtime.lastError) {
            }
          });
        } catch (e) {
          console.error("Error sending settings to tab:", e);
        }
      });
    });
  });
}

// Update badge with total tracking count
function updateBadge() {
  if (!settings.showNotifications) {
    chrome.action.setBadgeText({ text: '' });
    return;
  }
  
  const totalTracking = trackingData.fingerprinting.attempts + trackingData.cookies.trackers;
  chrome.action.setBadgeText({ text: totalTracking.toString() });
  chrome.action.setBadgeBackgroundColor({ color: '#e74c3c' });
}

// Call this periodically or after updates
setInterval(updateBadge, 5000);

function someAsyncFunction() {
  return new Promise((resolve) => {
    setTimeout(() => {
      resolve({ result: "Operation completed" });
    }, 500);
  });
}

// Debug storage changes
chrome.storage.onChanged.addListener((changes, namespace) => {
  if (changes.trackingData) {
    const newValue = changes.trackingData.newValue;
    if (newValue && newValue.cookies) {
      console.log("Cookie tracking data updated:", {
        total: newValue.cookies.total,
        trackers: newValue.cookies.trackers,
        domains: Object.keys(newValue.cookies.domains || {}).length
      });
    }
  }
});