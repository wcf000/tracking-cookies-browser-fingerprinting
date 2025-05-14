/**
 * Dashboard initialization script
 * Loads the required scripts in the correct order
 */

// First load Chart.js library
function loadChartJs() {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'chart.js'; // Local file, not CDN
    script.onload = resolve;
    script.onerror = reject;
    document.head.appendChild(script);
  });
}

// Then load dashboard.js
function loadDashboardJs() {
  return new Promise((resolve, reject) => {
    const script = document.createElement('script');
    script.src = 'dashboard.js';
    script.onload = resolve;
    script.onerror = reject;
    document.head.appendChild(script);
  });
}

// Chain the loading in sequence
document.addEventListener('DOMContentLoaded', async () => {
  try {
    // First load Chart.js
    await loadChartJs();
    console.log('Chart.js loaded successfully');
    
    // Then load our dashboard script
    await loadDashboardJs();
    console.log('Dashboard script loaded successfully');
  } catch (error) {
    console.error('Error loading scripts:', error);
    document.querySelectorAll('.chart-container').forEach(container => {
      container.innerHTML = '<div class="error-message">Charts could not be loaded</div>';
    });
  }
});