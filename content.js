// URLGuard Content Script
// Handles displaying warning banners and interacting with webpage content

// Create container for warning banners
let bannerContainer = null;

// Initialize the content script
function initialize() {
  // Create a container for our UI elements if it doesn't exist
  if (!bannerContainer) {
    bannerContainer = document.createElement('div');
    bannerContainer.id = 'urlguard-banner-container';
    document.body.prepend(bannerContainer);
  }

  // Let the background script know we're ready
  chrome.runtime.sendMessage({ action: "contentScriptReady" });
}

// Listen for messages from the background script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "showWarningBanner") {
    showWarningBanner(message.analysis);
    sendResponse({ success: true });
  } else if (message.action === "hideWarningBanner") {
    hideWarningBanner();
    sendResponse({ success: true });
  }
  return true;
});

/**
 * Show a warning banner for suspicious URLs
 * @param {Object} analysis - The URL analysis result
 */
function showWarningBanner(analysis) {
  // Remove any existing banner
  hideWarningBanner();
  
  // Determine the appropriate color based on the category
  let bannerColor = analysis.color;
  if (analysis.category === "HIGH_RISK") {
    bannerColor = "#F44336"; // Force red color for HIGH_RISK
  }
  
  // Create the banner element
  const banner = document.createElement('div');
  banner.id = 'urlguard-warning-banner';
  banner.style.cssText = `
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    background-color: ${bannerColor};
    color: white;
    z-index: 2147483647;
    font-family: Arial, sans-serif;
    box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
    display: flex;
    flex-direction: column;
    animation: urlguard-slide-down 0.3s ease-out;
  `;
  
  // Create the banner content
  const content = document.createElement('div');
  content.style.cssText = `
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 12px 20px;
  `;
  
  // Warning icon and title
  const warningTitle = document.createElement('div');
  warningTitle.style.cssText = `
    display: flex;
    align-items: center;
    gap: 10px;
    font-weight: bold;
    font-size: 16px;
  `;
  
  // Warning icon (shield)
  const icon = document.createElement('span');
  icon.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
    </svg>
  `;
  
  // Warning text
  const warningText = document.createElement('span');
  warningText.textContent = `URLGuard Alert: ${analysis.category} Risk Detected`;
  
  warningTitle.appendChild(icon);
  warningTitle.appendChild(warningText);
  
  // Description
  const description = document.createElement('div');
  description.style.cssText = `
    font-size: 14px;
    max-width: 60%;
  `;
  description.textContent = analysis.explanation;
  
  // Action buttons
  const actions = document.createElement('div');
  actions.style.cssText = `
    display: flex;
    gap: 10px;
  `;
  
  // Create button style function
  const createButton = (text, primary = false) => {
    const button = document.createElement('button');
    button.textContent = text;
    button.style.cssText = `
      padding: 8px 16px;
      border: none;
      border-radius: 4px;
      font-weight: bold;
      cursor: pointer;
      transition: background-color 0.2s;
      ${primary ? 
        'background-color: white; color: ' + bannerColor + ';' : 
        'background-color: transparent; color: white; border: 1px solid white;'}
    `;
    return button;
  };
  
  // Back button
  const backButton = createButton('Go Back', true);
  backButton.addEventListener('click', () => {
    history.back();
    hideWarningBanner();
  });
  
  // Proceed button
  const proceedButton = createButton('Proceed Anyway');
  proceedButton.addEventListener('click', () => {
    hideWarningBanner();
  });
  
  // Report button
  const reportButton = createButton('Report Site');
  reportButton.addEventListener('click', () => {
    // Open Google's safe browsing report page in new tab
    window.open('https://safebrowsing.google.com/safebrowsing/report_phish/', '_blank');
  });
  
  // Add buttons to actions container
  actions.appendChild(backButton);
  actions.appendChild(proceedButton);
  actions.appendChild(reportButton);
  
  // Close button
  const closeButton = document.createElement('button');
  closeButton.innerHTML = '&times;';
  closeButton.style.cssText = `
    background: none;
    border: none;
    color: white;
    font-size: 24px;
    cursor: pointer;
    padding: 0 10px;
    position: absolute;
    right: 10px;
    top: 10px;
  `;
  closeButton.addEventListener('click', hideWarningBanner);
  
  // Assemble the banner
  content.appendChild(warningTitle);
  content.appendChild(description);
  content.appendChild(actions);
  
  // Add the threat score visualization
  const scoreBar = createScoreBar(analysis.threatScore);
  
  banner.appendChild(content);
  banner.appendChild(scoreBar);
  banner.appendChild(closeButton);
  
  // Add the banner to the page
  if (bannerContainer) {
    bannerContainer.appendChild(banner);
  } else {
    document.body.prepend(banner);
  }
  
  // Add animation styles
  const style = document.createElement('style');
  style.id = 'urlguard-styles';
  style.textContent = `
    @keyframes urlguard-slide-down {
      from { transform: translateY(-100%); }
      to { transform: translateY(0); }
    }
    
    #urlguard-warning-banner button:hover {
      opacity: 0.9;
    }
  `;
  document.head.appendChild(style);
}

/**
 * Create a threat score visualization bar
 * @param {number} score - The threat score (0-100)
 * @returns {HTMLElement} Score bar element
 */
function createScoreBar(score) {
  const container = document.createElement('div');
  container.style.cssText = `
    padding: 5px 20px 10px;
    display: flex;
    flex-direction: column;
    gap: 5px;
  `;
  
  const label = document.createElement('div');
  label.style.cssText = `
    display: flex;
    justify-content: space-between;
    font-size: 12px;
  `;
  
  const scoreText = document.createElement('span');
  scoreText.textContent = `Threat Score: ${score}/100`;
  
  const safeText = document.createElement('span');
  safeText.textContent = 'Safe';
  
  const dangerText = document.createElement('span');
  dangerText.textContent = 'Dangerous';
  
  label.appendChild(scoreText);
  label.appendChild(safeText);
  label.appendChild(dangerText);
  
  const barBackground = document.createElement('div');
  barBackground.style.cssText = `
    height: 6px;
    width: 100%;
    background-color: rgba(255, 255, 255, 0.3);
    border-radius: 3px;
    overflow: hidden;
  `;
  
  const bar = document.createElement('div');
  bar.style.cssText = `
    height: 100%;
    width: ${score}%;
    background-color: white;
    border-radius: 3px;
  `;
  
  barBackground.appendChild(bar);
  container.appendChild(label);
  container.appendChild(barBackground);
  
  return container;
}

/**
 * Hide the warning banner
 */
function hideWarningBanner() {
  const banner = document.getElementById('urlguard-warning-banner');
  if (banner) {
    banner.remove();
  }
  
  const styles = document.getElementById('urlguard-styles');
  if (styles) {
    styles.remove();
  }
}

// Initialize the content script when the DOM is ready
if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initialize);
} else {
  initialize();
} 