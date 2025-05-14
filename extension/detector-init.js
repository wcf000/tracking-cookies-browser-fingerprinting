/**
 * Initializes the fingerprint detector in the page context
 */

try {
  // Initialize detector
  window.fingerprintDetector = new FingerprintDetector().init();
  
  // Immediately request current settings
  window.postMessage({
    type: 'GET_PRIVACY_SHIELD_SETTINGS'
  }, '*');
  
  console.log("Fingerprint detector initialized and requested settings");
  setInterval(() => {
    if (window.fingerprintDetector) {
      const data = window.fingerprintDetector.exportData();
      
      // Create and dispatch a custom event with the data
      const event = new CustomEvent('fingerprintingData', {
        detail: data
      });
      window.dispatchEvent(event);
      
      //Post a message for content.js to receive
      window.postMessage({
        type: 'FINGERPRINTING_DATA',
        data: data
      }, '*');
    }
  }, 2000);
  
  // Also send individual attempts as they happen
  window.addEventListener('fingerprintingDetected', function(e) {
    window.postMessage({
      type: 'FINGERPRINTING_DETECTED',
      data: e.detail
    }, '*');
  });
  console.log("Fingerprint detector initialized successfully");
} catch(e) {
  console.error("Error initializing fingerprint detector:", e);
}