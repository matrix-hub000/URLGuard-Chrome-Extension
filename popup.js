// URLGuard Popup Script
// Handles UI interactions and communication with the background script

// DOM Elements
const statusTab = document.getElementById('status-tab');
const historyTab = document.getElementById('history-tab');
const settingsTab = document.getElementById('settings-tab');
const tabButtons = document.querySelectorAll('.urlguard-tab');
const statusContainer = document.querySelector('.urlguard-status');
const statusIcon = document.querySelector('.urlguard-status-icon');
const statusText = document.querySelector('.urlguard-status-text');
const statusDesc = document.querySelector('.urlguard-status-desc');
const scoreValue = document.getElementById('score-value');
const scoreBar = document.querySelector('.urlguard-score-value');
const currentUrlDisplay = document.getElementById('current-url');
const analyzeButton = document.getElementById('analyze-btn');
const whitelistButton = document.getElementById('whitelist-btn');
const historyList = document.getElementById('history-list');
const clearHistoryButton = document.getElementById('clear-history');
const enableMonitoringToggle = document.getElementById('enable-monitoring');
const showNotificationsToggle = document.getElementById('show-notifications');
const storeHistoryToggle = document.getElementById('store-history');
const deepseekApiKeyInput = document.getElementById('deepseek-api-key');
const openaiApiKeyInput = document.getElementById('openai-api-key');
const whitelistContainer = document.getElementById('whitelist');
const blacklistContainer = document.getElementById('blacklist');
const addWhitelistButton = document.getElementById('add-whitelist');
const addBlacklistButton = document.getElementById('add-blacklist');
const onlineSearchButton = document.getElementById('online-search-btn');
const onlineSearchResults = document.getElementById('online-search-results');
const searchStatus = document.getElementById('search-status');
const searchContent = document.getElementById('search-content');

// State
let currentUrl = '';
let currentDomain = '';
let currentAnalysis = null;
let settings = {
  enableRealTimeMonitoring: true,
  showNotifications: true,
  storeHistory: false,
  whitelistedDomains: [],
  blacklistedDomains: [],
  deepseekApiKey: "",
  openaiApiKey: ""
};

// Initialize popup
function initializePopup() {
  // Load settings from background
  chrome.runtime.sendMessage({ action: "getSettings" }, (response) => {
    if (response) {
      settings = response;
      updateSettingsUI();
    }
  });
  
  // Get current tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    if (tabs && tabs[0] && tabs[0].url) {
      currentUrl = tabs[0].url;
      currentUrlDisplay.textContent = currentUrl;
      
      try {
        currentDomain = new URL(currentUrl).hostname;
      } catch (e) {
        currentDomain = '';
      }
      
      // Update whitelist/blacklist button state
      updateDomainButtonState();
      
      // Request analysis from background script
      chrome.runtime.sendMessage({ 
        action: "analyzeUrl", 
        url: currentUrl 
      }, (response) => {
        if (response) {
          updateAnalysisUI(response);
        }
      });
    }
  });
  
  // Load history if on history tab
  if (historyTab.style.display !== 'none') {
    loadHistory();
  }
}

// Tab switching
tabButtons.forEach(button => {
  button.addEventListener('click', () => {
    const tabName = button.getAttribute('data-tab');
    
    // Update active tab button
    tabButtons.forEach(btn => btn.classList.remove('active'));
    button.classList.add('active');
    
    // Hide all tab content
    document.querySelectorAll('.urlguard-tab-content').forEach(content => {
      content.style.display = 'none';
    });
    
    // Show selected tab content
    const selectedTab = document.getElementById(`${tabName}-tab`);
    if (selectedTab) {
      selectedTab.style.display = 'block';
      
      // Load data for specific tabs
      if (tabName === 'history') {
        loadHistory();
      } else if (tabName === 'settings') {
        loadWhitelistBlacklist();
      }
    }
  });
});

// Update the UI based on URL analysis
function updateAnalysisUI(analysis) {
  currentAnalysis = analysis;
  
  // Determine category class
  let categoryClass = 'safe';
  if (analysis.category === 'PHISHING') {
    categoryClass = 'phishing';
  } else if (analysis.category === 'HIGH_RISK') {
    categoryClass = 'high-risk';
  } else if (analysis.category === 'SUSPICIOUS') {
    categoryClass = 'suspicious';
  }
  
  // Update status container
  statusContainer.className = `urlguard-status ${categoryClass.toLowerCase()}`;
  statusIcon.className = `urlguard-status-icon ${categoryClass.toLowerCase()}`;
  
  // Update icon based on category
  let iconSvg = '';
  if (categoryClass === 'safe') {
    iconSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path>
      <polyline points="22 4 12 14.01 9 11.01"></polyline>
    </svg>`;
  } else {
    iconSvg = `<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
      <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"></path>
      <line x1="12" y1="9" x2="12" y2="13"></line>
      <line x1="12" y1="17" x2="12.01" y2="17"></line>
    </svg>`;
  }
  statusIcon.innerHTML = iconSvg;
  
  // Update text content
  statusText.textContent = `Current URL is ${analysis.category}`;
  statusDesc.textContent = analysis.explanation;
  scoreValue.textContent = `Threat Score: ${analysis.threatScore}/100`;
  
  // Update score bar
  scoreBar.className = `urlguard-score-value ${categoryClass.toLowerCase()}`;
  scoreBar.style.width = `${analysis.threatScore}%`;
}

// Event listeners
analyzeButton.addEventListener('click', () => {
  chrome.runtime.sendMessage({ 
    action: "analyzeUrl", 
    url: currentUrl,
    forceRefresh: true
  }, (response) => {
    if (response) {
      updateAnalysisUI(response);
    }
  });
});

whitelistButton.addEventListener('click', () => {
  if (!currentDomain) return;
  
  // Check if domain is already whitelisted or blacklisted
  if (settings.whitelistedDomains.includes(currentDomain)) {
    // Remove from whitelist
    settings.whitelistedDomains = settings.whitelistedDomains.filter(d => d !== currentDomain);
    whitelistButton.textContent = 'Add to Whitelist';
  } else {
    // Remove from blacklist if present
    if (settings.blacklistedDomains.includes(currentDomain)) {
      settings.blacklistedDomains = settings.blacklistedDomains.filter(d => d !== currentDomain);
    }
    
    // Add to whitelist
    settings.whitelistedDomains.push(currentDomain);
    whitelistButton.textContent = 'Remove from Whitelist';
  }
  
  // Save changes
  chrome.runtime.sendMessage({ 
    action: "updateSettings", 
    settings
  }, () => {
    // Re-analyze URL with new settings
    chrome.runtime.sendMessage({ 
      action: "analyzeUrl", 
      url: currentUrl,
      forceRefresh: true
    }, (response) => {
      if (response) {
        updateAnalysisUI(response);
      }
    });
  });
});

clearHistoryButton.addEventListener('click', () => {
  chrome.runtime.sendMessage({ action: "clearHistory" }, () => {
    loadHistory();
  });
});

enableMonitoringToggle.addEventListener('change', () => {
  settings.enableRealTimeMonitoring = enableMonitoringToggle.checked;
  saveSettings();
});

showNotificationsToggle.addEventListener('change', () => {
  settings.showNotifications = showNotificationsToggle.checked;
  saveSettings();
});

storeHistoryToggle.addEventListener('change', () => {
  settings.storeHistory = storeHistoryToggle.checked;
  saveSettings();
});

deepseekApiKeyInput.addEventListener('input', () => {
  settings.deepseekApiKey = deepseekApiKeyInput.value;
  saveSettings();
});

openaiApiKeyInput.addEventListener('input', () => {
  settings.openaiApiKey = openaiApiKeyInput.value;
  saveSettings();
});

addWhitelistButton.addEventListener('click', () => {
  promptAddDomain('whitelist');
});

addBlacklistButton.addEventListener('click', () => {
  promptAddDomain('blacklist');
});

// Online Search functionality
onlineSearchButton.addEventListener('click', async () => {
  if (!currentUrl) return;
  
  // Show search results section
  onlineSearchResults.style.display = 'block';
  searchStatus.style.display = 'block';
  searchContent.style.display = 'none';
  
  // Update button state
  onlineSearchButton.disabled = true;
  onlineSearchButton.innerHTML = `
    <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;">
      <line x1="12" y1="2" x2="12" y2="6"></line>
      <line x1="12" y1="18" x2="12" y2="22"></line>
      <line x1="4.93" y1="4.93" x2="7.76" y2="7.76"></line>
      <line x1="16.24" y1="16.24" x2="19.07" y2="19.07"></line>
      <line x1="2" y1="12" x2="6" y2="12"></line>
      <line x1="18" y1="12" x2="22" y2="12"></line>
      <line x1="4.93" y1="19.07" x2="7.76" y2="16.24"></line>
      <line x1="16.24" y1="7.76" x2="19.07" y2="4.93"></line>
    </svg>
    Searching...
  `;
  
  try {
    // Request online search from background script
    const searchResult = await new Promise((resolve, reject) => {
      chrome.runtime.sendMessage({ 
        action: "onlineSearch", 
        url: currentUrl 
      }, (response) => {
        if (chrome.runtime.lastError) {
          reject(chrome.runtime.lastError);
        } else {
          resolve(response);
        }
      });
    });
    
    // Display search results
    displaySearchResults(searchResult);
    
  } catch (error) {
    console.error('Online search failed:', error);
    displaySearchError('Failed to search online. Please try again.');
  } finally {
    // Reset button state
    onlineSearchButton.disabled = false;
    onlineSearchButton.innerHTML = `
      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;">
        <circle cx="11" cy="11" r="8"></circle>
        <path d="m21 21-4.35-4.35"></path>
      </svg>
      Online Search
    `;
  }
});

// Load history data
function loadHistory() {
  chrome.runtime.sendMessage({ action: "getHistory" }, (history) => {
    if (!history || history.length === 0) {
      historyList.innerHTML = `
        <div class="urlguard-empty">
          <svg xmlns="http://www.w3.org/2000/svg" width="48" height="48" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
            <circle cx="12" cy="12" r="10"></circle>
            <line x1="12" y1="8" x2="12" y2="12"></line>
            <line x1="12" y1="16" x2="12.01" y2="16"></line>
          </svg>
          <p>No history yet</p>
          <p style="font-size: 14px;">URL analysis history will appear here</p>
        </div>
      `;
      return;
    }
    
    // Create history items
    const items = history.map(item => createHistoryItem(item));
    historyList.innerHTML = items.join('');
  });
}

// Create a history item HTML
function createHistoryItem(item) {
  // Determine category class
  let categoryClass = 'safe';
  if (item.category === 'PHISHING') {
    categoryClass = 'phishing';
  } else if (item.category === 'HIGH_RISK') {
    categoryClass = 'high-risk';
  } else if (item.category === 'SUSPICIOUS') {
    categoryClass = 'suspicious';
  }
  
  // Format date
  const date = new Date(item.timestamp);
  const formattedDate = date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  
  // Create URL display
  let displayUrl = item.url;
  try {
    const urlObj = new URL(item.url);
    displayUrl = urlObj.hostname + urlObj.pathname;
    if (displayUrl.length > 40) {
      displayUrl = displayUrl.substring(0, 40) + '...';
    }
  } catch (e) {
    // Use full URL if parsing fails
  }
  
  // Check if this is an online search entry
  const isOnlineSearch = item.searchType === 'online_search';
  const searchIcon = isOnlineSearch ? `
    <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="margin-right: 4px;">
      <circle cx="11" cy="11" r="8"></circle>
      <path d="m21 21-4.35-4.35"></path>
    </svg>
  ` : '';
  
  const legitimacyStatus = isOnlineSearch && item.confidence !== undefined ? 
    `<div class="urlguard-history-legitimacy">${item.isLegitimate !== undefined ? (item.isLegitimate ? 'Legitimate' : 'Suspicious') : 'Unknown'}</div>` : '';
  
  return `
    <div class="urlguard-history-item ${isOnlineSearch ? 'online-search' : ''}" data-url="${item.url}">
      <div class="urlguard-history-status ${categoryClass}"></div>
      <div class="urlguard-history-details">
        <div class="urlguard-history-url">${searchIcon}${displayUrl}</div>
        <div class="urlguard-history-date">${formattedDate}</div>
        ${legitimacyStatus}
      </div>
      <div class="urlguard-history-score">${isOnlineSearch ? item.confidence + '%' : item.threatScore}</div>
    </div>
  `;
}

// Load whitelist and blacklist
function loadWhitelistBlacklist() {
  updateWhitelistUI();
  updateBlacklistUI();
}

// Update whitelist UI
function updateWhitelistUI() {
  if (!settings.whitelistedDomains || settings.whitelistedDomains.length === 0) {
    whitelistContainer.innerHTML = '<div class="urlguard-empty">No whitelisted domains</div>';
    return;
  }
  
  const items = settings.whitelistedDomains.map(domain => `
    <div class="urlguard-list-item">
      <span>${domain}</span>
      <button class="urlguard-list-item-remove" data-domain="${domain}" data-list="whitelist">✕</button>
    </div>
  `);
  
  whitelistContainer.innerHTML = items.join('');
  
  // Add event listeners for remove buttons
  document.querySelectorAll('[data-list="whitelist"]').forEach(button => {
    button.addEventListener('click', handleRemoveDomain);
  });
}

// Update blacklist UI
function updateBlacklistUI() {
  if (!settings.blacklistedDomains || settings.blacklistedDomains.length === 0) {
    blacklistContainer.innerHTML = '<div class="urlguard-empty">No blacklisted domains</div>';
    return;
  }
  
  const items = settings.blacklistedDomains.map(domain => `
    <div class="urlguard-list-item">
      <span>${domain}</span>
      <button class="urlguard-list-item-remove" data-domain="${domain}" data-list="blacklist">✕</button>
    </div>
  `);
  
  blacklistContainer.innerHTML = items.join('');
  
  // Add event listeners for remove buttons
  document.querySelectorAll('[data-list="blacklist"]').forEach(button => {
    button.addEventListener('click', handleRemoveDomain);
  });
}

// Handle removing a domain from whitelist/blacklist
function handleRemoveDomain(event) {
  const domain = event.target.getAttribute('data-domain');
  const list = event.target.getAttribute('data-list');
  
  if (list === 'whitelist') {
    settings.whitelistedDomains = settings.whitelistedDomains.filter(d => d !== domain);
    updateWhitelistUI();
  } else if (list === 'blacklist') {
    settings.blacklistedDomains = settings.blacklistedDomains.filter(d => d !== domain);
    updateBlacklistUI();
  }
  
  saveSettings();
}

// Prompt to add a domain to whitelist/blacklist
function promptAddDomain(listType) {
  const domain = prompt(`Enter a domain to add to the ${listType}:`);
  if (!domain) return;
  
  // Validate domain syntax
  if (!isValidDomain(domain)) {
    alert('Please enter a valid domain (e.g., example.com)');
    return;
  }
  
  if (listType === 'whitelist') {
    // Remove from blacklist if present
    settings.blacklistedDomains = settings.blacklistedDomains.filter(d => d !== domain);
    
    // Add to whitelist if not already present
    if (!settings.whitelistedDomains.includes(domain)) {
      settings.whitelistedDomains.push(domain);
      updateWhitelistUI();
    }
  } else if (listType === 'blacklist') {
    // Remove from whitelist if present
    settings.whitelistedDomains = settings.whitelistedDomains.filter(d => d !== domain);
    
    // Add to blacklist if not already present
    if (!settings.blacklistedDomains.includes(domain)) {
      settings.blacklistedDomains.push(domain);
      updateBlacklistUI();
    }
  }
  
  saveSettings();
}

// Validate domain format
function isValidDomain(domain) {
  const domainRegex = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}

// Update the UI based on settings
function updateSettingsUI() {
  enableMonitoringToggle.checked = settings.enableRealTimeMonitoring;
  showNotificationsToggle.checked = settings.showNotifications;
  storeHistoryToggle.checked = settings.storeHistory;
  deepseekApiKeyInput.value = settings.deepseekApiKey || "";
  openaiApiKeyInput.value = settings.openaiApiKey || "";
  
  updateWhitelistUI();
  updateBlacklistUI();
  updateDomainButtonState();
}

// Update the whitelist/blacklist button text based on current domain status
function updateDomainButtonState() {
  if (!currentDomain) return;
  
  if (settings.whitelistedDomains.includes(currentDomain)) {
    whitelistButton.textContent = 'Remove from Whitelist';
  } else if (settings.blacklistedDomains.includes(currentDomain)) {
    whitelistButton.textContent = 'Remove from Blacklist';
  } else {
    whitelistButton.textContent = 'Add to Whitelist';
  }
}

// Save all settings
function saveSettings() {
  chrome.runtime.sendMessage({ 
    action: "updateSettings", 
    settings
  });
}

// Listen for messages from background script
chrome.runtime.onMessage.addListener((message) => {
  if (message.action === "updateStatus" && message.analysis) {
    updateAnalysisUI(message.analysis);
  }
});

// Helper functions for online search
function displaySearchResults(result) {
  searchStatus.style.display = 'none';
  searchContent.style.display = 'block';
  
  const domain = extractDomain(currentUrl);
  
  let html = `
    <div class="urlguard-search-summary">
      <div class="urlguard-search-header">
        <h4>${domain}</h4>
        <span class="urlguard-search-confidence">Confidence: ${result.confidence}%</span>
      </div>
      <div class="urlguard-search-verdict ${result.isLegitimate ? 'legitimate' : 'suspicious'}">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
          ${result.isLegitimate ? 
            '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline>' :
            '<circle cx="12" cy="12" r="10"></circle><line x1="15" y1="9" x2="9" y2="15"></line><line x1="9" y1="9" x2="15" y2="15"></line>'
          }
        </svg>
        ${result.isLegitimate ? 'Likely Legitimate' : 'Potentially Suspicious'}
      </div>
    </div>
    
    <div class="urlguard-search-details">
      <h5>Analysis Summary:</h5>
      <p>${result.summary}</p>
      
      ${result.keyFindings && result.keyFindings.length > 0 ? `
        <h5>Key Findings:</h5>
        <ul>
          ${result.keyFindings.map(finding => `<li>${finding}</li>`).join('')}
        </ul>
      ` : ''}
      
      ${result.recommendations && result.recommendations.length > 0 ? `
        <h5>Recommendations:</h5>
        <ul>
          ${result.recommendations.map(rec => `<li>${rec}</li>`).join('')}
        </ul>
      ` : ''}
    </div>
  `;
  
  searchContent.innerHTML = html;
}

function displaySearchError(message) {
  searchStatus.style.display = 'none';
  searchContent.style.display = 'block';
  
  searchContent.innerHTML = `
    <div class="urlguard-search-error">
      <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
        <circle cx="12" cy="12" r="10"></circle>
        <line x1="15" y1="9" x2="9" y2="15"></line>
        <line x1="9" y1="9" x2="15" y2="15"></line>
      </svg>
      <p>${message}</p>
    </div>
  `;
}

function extractDomain(url) {
  try {
    const hostname = new URL(url).hostname;
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    
    const secondLevelDomains = ['co', 'com', 'org', 'net', 'gov', 'edu'];
    const tld = parts[parts.length - 1];
    const possibleSld = parts[parts.length - 2];
    
    if (secondLevelDomains.includes(possibleSld)) {
      return `${parts[parts.length - 3]}.${possibleSld}.${tld}`;
    }
    
    return `${parts[parts.length - 2]}.${tld}`;
  } catch (e) {
    return "";
  }
}

// Initialize popup when DOM is fully loaded
document.addEventListener('DOMContentLoaded', initializePopup); 