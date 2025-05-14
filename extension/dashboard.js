/**
 * Dashboard script for Privacy Shield extension
 */

// Known trackers
const KNOWN_TRACKERS = [
  'doubleclick.net',
  'google-analytics.com',
  'facebook.net',
  'facebook.com',
];

// DOM elements - stats
const totalFingerprintingEl = document.getElementById('total-fingerprinting');
const totalCookiesEl = document.getElementById('total-cookies');
const totalSitesEl = document.getElementById('total-sites');
const totalBlockedEl = document.getElementById('total-blocked');

// DOM elements - tables
const fingerprintingTableEl = document.getElementById('fingerprinting-table').querySelector('tbody');
const cookiesTableEl = document.getElementById('cookies-table').querySelector('tbody');
const sitesTableEl = document.getElementById('sites-table').querySelector('tbody');

// DOM elements - charts
const fingerprintingTypesChartEl = document.getElementById('fingerprintingTypesChart');
const topDomainsChartEl = document.getElementById('topDomainsChart');
const cookiePurposesChartEl = document.getElementById('cookiePurposesChart');

// DOM elements - buttons
const exportJsonBtn = document.getElementById('export-json');
const exportCsvBtn = document.getElementById('export-csv');
const clearDataBtn = document.getElementById('clear-data');

// DOM elements - settings
const blockFingerprintingToggle = document.getElementById('block-fingerprinting');
const blockCookiesToggle = document.getElementById('block-cookies');
const showNotificationsToggle = document.getElementById('show-notifications');
const saveStatusEl = document.getElementById('save-status');

// Data storage
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

let settings = {
  blockFingerprinting: true,
  blockTrackingCookies: true,
  showNotifications: true,
  whitelist: []
};

// Charts
let fingerprintingTypesChart;
let topDomainsChart;
let cookiePurposesChart;

// Initialize the dashboard
function initDashboard() {
  loadData();
  setupEventListeners();
  listenForUpdates();
  setInterval(loadData, 10000);
}

// Setup event listeners
function setupEventListeners() {
  exportJsonBtn.addEventListener('click', exportDataAsJson);
  exportCsvBtn.addEventListener('click', exportDataAsCsv);
  clearDataBtn.addEventListener('click', clearAllData);
  
  blockFingerprintingToggle.addEventListener('change', saveSettings);
  blockCookiesToggle.addEventListener('change', saveSettings);
  showNotificationsToggle.addEventListener('change', saveSettings);
}

// Load settings from storage
function loadSettings() {
  chrome.storage.local.get('settings', function(result) {
    if (result.settings) {
      blockFingerprintingToggle.checked = result.settings.blockFingerprinting;
      blockCookiesToggle.checked = result.settings.blockTrackingCookies;
      showNotificationsToggle.checked = result.settings.showNotifications;
    }
  });
}

// Save settings
function saveSettings() {
  const settings = {
    blockFingerprinting: blockFingerprintingToggle.checked,
    blockTrackingCookies: blockCookiesToggle.checked,
    showNotifications: showNotificationsToggle.checked,
    whitelist: []
  };
  
  chrome.storage.local.set({ settings }, function() {
    // Show saved message
    saveStatusEl.textContent = 'Settings saved!';
    setTimeout(() => {
      saveStatusEl.textContent = '';
    }, 2000);
    
    // Notify background script about the settings change
    chrome.runtime.sendMessage({
      type: 'updateSettings',
      settings: settings
    });
  });
}

// Load tracking data from storage
function loadData() {
  chrome.runtime.sendMessage({ type: 'getTrackingData' }, function(response) {
    if (response) {
      trackingData = response;
      updateDashboard(trackingData);
    } else {
      chrome.storage.local.get('trackingData', function(result) {
        if (result.trackingData) {
          trackingData = result.trackingData;
          updateDashboard(trackingData);
        }
      });
    }
  });
}

// Listen for real-time updates from background script
function listenForUpdates() {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === 'dataUpdated') {
      trackingData = message.data;
      updateDashboard(trackingData);
    }
    return true;
  });
}

// Update the dashboard with current data
function updateDashboard(data) {
  updateStats(data);
  updateTables(data);
  updateCharts(data);
}

// Update statistic counters
function updateStats(data) {
  totalFingerprintingEl.textContent = data.fingerprinting.attempts;
  totalCookiesEl.textContent = data.cookies.trackers;
  totalSitesEl.textContent = Object.keys(data.domains).length;
  totalBlockedEl.textContent = data.stats.blocked;
}

// Update data tables
function updateTables(data) {
  updateFingerprintingTable(data.fingerprintingAttempts);
  updateSitesTable(data.domains);
  updateCookiesTable(data);
}

// Update fingerprinting attempts table
function updateFingerprintingTable(attempts) {
  if (!fingerprintingTableEl) return;
  
  if (!attempts || attempts.length === 0) {
    fingerprintingTableEl.innerHTML = `
      <tr>
        <td colspan="4" class="empty-message">No fingerprinting attempts detected yet</td>
      </tr>
    `;
    return;
  }
  
  // Sort by most recent
  const sortedAttempts = [...attempts].sort((a, b) => {
    return new Date(b.timestamp) - new Date(a.timestamp);
  }).slice(0, 50);
  
  let tableHTML = '';
  
  sortedAttempts.forEach(attempt => {
    const date = new Date(attempt.timestamp);
    const formattedTime = date.toLocaleTimeString();
    const status = attempt.blocked ? 
      '<span class="status status-blocked">Blocked</span>' : 
      '<span class="status status-allowed">Allowed</span>';
    
    tableHTML += `
      <tr>
        <td>${attempt.domain || 'unknown'}</td>
        <td>${attempt.technique}</td>
        <td>${formattedTime}</td>
        <td>${status}</td>
      </tr>
    `;
  });
  
  fingerprintingTableEl.innerHTML = tableHTML;
}

// Update sites table
function updateSitesTable(domains) {
  if (!sitesTableEl) return;
  
  if (!domains || Object.keys(domains).length === 0) {
    sitesTableEl.innerHTML = `
      <tr>
        <td colspan="4" class="empty-message">No tracking domains detected yet</td>
      </tr>
    `;
    return;
  }
  
  // Convert to array and sort by total tracking activities
  const domainsArray = Object.entries(domains).map(([domain, stats]) => {
    return {
      domain,
      fingerprinting: stats.fingerprinting || 0,
      cookies: stats.cookies || 0,
      trackers: stats.trackers || 0,
      lastDetected: stats.lastDetected || Date.now()
    };
  }).sort((a, b) => {
    const aTotal = a.fingerprinting + a.trackers;
    const bTotal = b.fingerprinting + b.trackers;
    return bTotal - aTotal;
  }).slice(0, 20);
  
  let tableHTML = '';
  
  domainsArray.forEach(site => {
    const date = new Date(site.lastDetected);
    const formattedTime = date.toLocaleString();
    
    tableHTML += `
      <tr>
        <td>${site.domain}</td>
        <td>${site.fingerprinting}</td>
        <td>${site.trackers}</td>
        <td>${formattedTime}</td>
      </tr>
    `;
  });
  
  sitesTableEl.innerHTML = tableHTML;
}

// Update cookies table
function updateCookiesTable(data) {
  if (!cookiesTableEl) return;
  const cookieData = [];
  
  // Create entries from domain data - now split by purpose
  Object.entries(data.cookies.domains || {}).forEach(([domain, cookieInfo]) => {
    const isKnownTracker = KNOWN_TRACKERS.some(tracker => domain.includes(tracker));
    if (typeof cookieInfo === 'number' || !cookieInfo.purposes) {
      let category = isKnownTracker ? 'Tracking Network' : 'Other Tracker';
      let count = typeof cookieInfo === 'number' ? cookieInfo : (cookieInfo.count || 0);
      let blocked = settings.blockTrackingCookies && !isWhitelisted(domain);
      
      cookieData.push({
        domain: domain,
        purpose: category,
        count: count,
        blocked: blocked,
        examples: ''
      });
    } 
    else {
      // Add an entry for each purpose
      Object.entries(cookieInfo.purposes || {}).forEach(([purpose, purposeData]) => {
        cookieData.push({
          domain: domain,
          purpose: purpose,
          count: purposeData.count || 0,
          blocked: cookieInfo.blocked,
          examples: (purposeData.examples || []).join(', ')
        });
      });
    }
  });
  
  if (cookieData.length === 0) {
    cookiesTableEl.innerHTML = `
      <tr>
        <td colspan="4" class="empty-message">No tracking cookies detected yet</td>
      </tr>
    `;
    return;
  }
  
  // Sort by domain and then by count
  cookieData.sort((a, b) => {
    if (a.domain === b.domain) {
      return b.count - a.count;
    }
    return a.domain.localeCompare(b.domain);
  });
  
  let tableHTML = '';
  let currentDomain = '';
  
  cookieData.forEach(cookie => {
    const status = cookie.blocked ? 
      '<span class="status status-blocked">Blocked</span>' : 
      '<span class="status status-allowed">Allowed</span>';
    
    // Add domain separator if this is a new domain
    if (cookie.domain !== currentDomain) {
      if (currentDomain !== '') {
        tableHTML += `<tr class="domain-separator"><td colspan="4"></td></tr>`;
      }
      currentDomain = cookie.domain;
    }
    
    const tooltipContent = cookie.examples ? 
      `<div class="tooltip">Examples: ${cookie.examples}</div>` : '';
    
    tableHTML += `
      <tr>
        <td>${cookie.domain}</td>
        <td>${cookie.purpose}${tooltipContent}</td>
        <td>${cookie.count}</td>
        <td>${status}</td>
      </tr>
    `;
  });
  
  cookiesTableEl.innerHTML = tableHTML;
}

// Update charts
function updateCharts(data) {
  updateFingerprintingTypesChart(data);
  updateCookiePurposesChart(data);
  updateTopDomainsChart(data);
}

// Update the fingerprinting types chart
function updateFingerprintingTypesChart(data) {
  if (!fingerprintingTypesChartEl) return;
  const techniques = data.fingerprinting.techniques || {};
  const labels = Object.keys(techniques);
  const values = Object.values(techniques);
  if (labels.length === 0) {
    labels.push('No data yet');
    values.push(1);
  }
  
  const chartData = {
    labels: labels,
    datasets: [{
      label: 'Fingerprinting Techniques',
      data: values,
      backgroundColor: [
        'rgba(54, 162, 235, 0.8)',
        'rgba(75, 192, 192, 0.8)',
        'rgba(153, 102, 255, 0.8)',
        'rgba(54, 162, 235, 0.6)',
        'rgba(75, 192, 192, 0.6)',
        'rgba(153, 102, 255, 0.6)'
      ],
      borderWidth: 1
    }]
  };
  
  if (fingerprintingTypesChart) {
    fingerprintingTypesChart.data = chartData;
    fingerprintingTypesChart.update();
  } else {
    fingerprintingTypesChart = new Chart(fingerprintingTypesChartEl, {
      type: 'pie',
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              boxWidth: 12,
              font: {
                size: 11
              }
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const label = context.label || '';
                const value = context.raw || 0;
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = Math.round((value / total) * 100);
                return `${label}: ${value} (${percentage}%)`;
              }
            }
          }
        }
      }
    });
  }
}

// Update the cookie purposes chart
function updateCookiePurposesChart(data) {
  if (!cookiePurposesChartEl) return;
  const cookiePurposes = {};
  
  // Extract cookie purposes from domains
  Object.values(data.cookies.domains || {}).forEach(domainData => {
    if (domainData.purposes) {
      Object.entries(domainData.purposes).forEach(([purpose, purposeData]) => {
        cookiePurposes[purpose] = (cookiePurposes[purpose] || 0) + purposeData.count;
      });
    }
  });
  
  const labels = Object.keys(cookiePurposes);
  const values = Object.values(cookiePurposes);
  
  // If no data, add placeholder
  if (labels.length === 0) {
    labels.push('No data yet');
    values.push(1);
  }
  
  const chartData = {
    labels: labels,
    datasets: [{
      label: 'Cookie Purposes',
      data: values,
      backgroundColor: [
        'rgba(255, 99, 132, 0.8)',
        'rgba(255, 159, 64, 0.8)',
        'rgba(255, 205, 86, 0.8)',
        'rgba(255, 99, 132, 0.6)',
        'rgba(255, 159, 64, 0.6)',
        'rgba(255, 205, 86, 0.6)'
      ],
      borderWidth: 1
    }]
  };
  
  if (cookiePurposesChart) {
    cookiePurposesChart.data = chartData;
    cookiePurposesChart.update();
  } else {
    cookiePurposesChart = new Chart(cookiePurposesChartEl, {
      type: 'pie',
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            position: 'right',
            labels: {
              boxWidth: 12,
              font: {
                size: 11
              }
            }
          },
          tooltip: {
            callbacks: {
              label: function(context) {
                const label = context.label || '';
                const value = context.raw || 0;
                const total = context.dataset.data.reduce((a, b) => a + b, 0);
                const percentage = Math.round((value / total) * 100);
                return `${label}: ${value} (${percentage}%)`;
              }
            }
          }
        }
      }
    });
  }
}

// Update the top domains chart
function updateTopDomainsChart(data) {
  if (!topDomainsChartEl) return;
  
  // Get domain data
  const domains = data.fingerprinting.domains || {};
  
  // Convert to array and sort by count
  const sortedDomains = Object.entries(domains)
    .map(([domain, count]) => ({ domain, count }))
    .sort((a, b) => b.count - a.count)
    .slice(0, 5);  // Top 5 domains
  
  const labels = sortedDomains.map(d => d.domain);
  const values = sortedDomains.map(d => d.count);
  if (labels.length === 0) {
    labels.push('No data yet');
    values.push(0);
  }
  
  const chartData = {
    labels: labels,
    datasets: [{
      label: 'Fingerprinting Attempts',
      data: values,
      backgroundColor: 'rgba(54, 162, 235, 0.8)',
      borderColor: 'rgba(54, 162, 235, 1)',
      borderWidth: 1
    }]
  };
  
  if (topDomainsChart) {
    topDomainsChart.data = chartData;
    topDomainsChart.update();
  } else {
    topDomainsChart = new Chart(topDomainsChartEl, {
      type: 'bar',
      data: chartData,
      options: {
        responsive: true,
        maintainAspectRatio: false,
        indexAxis: 'y',
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          x: {
            beginAtZero: true,
            title: {
              display: true,
              text: 'Number of Attempts'
            }
          }
        }
      }
    });
  }
}

// Export data as JSON
function exportDataAsJson() {
  const dataStr = JSON.stringify(trackingData, null, 2);
  const dataUri = 'data:application/json;charset=utf-8,'+ encodeURIComponent(dataStr);
  
  const exportFileDefaultName = `privacy-shield-data-${new Date().toISOString().slice(0, 10)}.json`;
  
  const linkElement = document.createElement('a');
  linkElement.setAttribute('href', dataUri);
  linkElement.setAttribute('download', exportFileDefaultName);
  linkElement.click();
}

// Export data as CSV
function exportDataAsCsv() {
  // Convert fingerprinting attempts to CSV
  let csvContent = 'data:text/csv;charset=utf-8,';
  csvContent += 'Domain,Technique,Timestamp,Blocked\n';
  
  // Add each fingerprinting attempt
  trackingData.fingerprintingAttempts.forEach(attempt => {
    const row = [
      attempt.domain || 'unknown',
      attempt.technique,
      attempt.timestamp,
      attempt.blocked ? 'Yes' : 'No'
    ];
    const escapedRow = row.map(field => {
      if (typeof field === 'string' && field.includes(',')) {
        return `"${field}"`;
      }
      return field;
    });
    
    csvContent += escapedRow.join(',') + '\n';
  });
  
  const encodedUri = encodeURI(csvContent);
  const exportFileDefaultName = `privacy-shield-data-${new Date().toISOString().slice(0, 10)}.csv`;
  
  const linkElement = document.createElement('a');
  linkElement.setAttribute('href', encodedUri);
  linkElement.setAttribute('download', exportFileDefaultName);
  linkElement.click();
}

// Clear all tracking data
function clearAllData() {
  if (confirm('Are you sure you want to clear all tracking data? This cannot be undone.')) {
    chrome.runtime.sendMessage({ type: 'resetData' }, response => {
      if (response && response.success) {
        // Reload data
        loadData();
        alert('All tracking data has been cleared.');
      }
    });
  }
}

// Check if a domain is whitelisted
function isWhitelisted(domain) {
  if (!domain || !settings || !settings.whitelist) return false;
  return settings.whitelist.some(whitelistedDomain => 
    domain.includes(whitelistedDomain) || whitelistedDomain.includes(domain)
  );
}

// Start the dashboard and settings
initDashboard();
loadSettings();