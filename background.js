// URLGuard Background Service Worker
// Handles URL monitoring and LLM-based security analysis

// Configuration
const API_ENDPOINT = "https://api.deepseek.com/v1/chat/completions";  
// API keys are now stored securely in user settings

// OpenAI Configuration for Online Search
const OPENAI_API_ENDPOINT = "https://api.openai.com/v1/chat/completions";
const OPENAI_RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses";
const THREAT_LEVELS = {
  SAFE: { name: "Safe", color: "#4CAF50", score: [0, 25] },
  SUSPICIOUS: { name: "Suspicious", color: "#FFC107", score: [26, 50] },
  HIGH_RISK: { name: "High Risk", color: "#F44336", score: [51, 75] },
  PHISHING: { name: "Phishing", color: "#F44336", score: [76, 100] }
};

// Initialize state
let analysisCache = {};
let userSettings = {
  enableRealTimeMonitoring: true,
  showNotifications: true,
  storeHistory: false,
  whitelistedDomains: [],
  blacklistedDomains: [],
  deepseekApiKey: "",
  openaiApiKey: ""
};

// Load settings on startup
chrome.storage.local.get(['urlguard_settings'], function(result) {
  if (result.urlguard_settings) {
    const settings = result.urlguard_settings;
    userSettings = { 
      ...userSettings, 
      enableRealTimeMonitoring: settings.enableRealTimeMonitoring !== undefined ? settings.enableRealTimeMonitoring : userSettings.enableRealTimeMonitoring,
      showNotifications: settings.showNotifications !== undefined ? settings.showNotifications : userSettings.showNotifications,
      storeHistory: settings.storeHistory !== undefined ? settings.storeHistory : userSettings.storeHistory,
      whitelistedDomains: settings.whitelistedDomains || [],
      blacklistedDomains: settings.blacklistedDomains || [],
      deepseekApiKey: settings.deepseekApiKey || "",
      openaiApiKey: settings.openaiApiKey || ""
    };
  }
});

// URL Navigation monitoring
chrome.webNavigation.onCompleted.addListener(async (details) => {
  // Only analyze main frame navigation (not iframes, etc)
  if (details.frameId === 0 && userSettings.enableRealTimeMonitoring) {
    await analyzeUrl(details.url, details.tabId);
  }
});

// Handle messages from popup and content scripts
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  if (request.action === "analyzeUrl") {
    analyzeUrl(request.url, sender.tab?.id, request.forceRefresh).then(result => sendResponse(result));
    return true; // Keep the message channel open for async response
  } else if (request.action === "onlineSearch") {
    performOnlineSearch(request.url).then(result => sendResponse(result));
    return true; // Keep the message channel open for async response
  } else if (request.action === "getSettings") {
    sendResponse(userSettings);
  } else if (request.action === "updateSettings") {
    const newSettings = request.settings;
    userSettings = { 
      ...userSettings, 
      enableRealTimeMonitoring: newSettings.enableRealTimeMonitoring !== undefined ? newSettings.enableRealTimeMonitoring : userSettings.enableRealTimeMonitoring,
      showNotifications: newSettings.showNotifications !== undefined ? newSettings.showNotifications : userSettings.showNotifications,
      storeHistory: newSettings.storeHistory !== undefined ? newSettings.storeHistory : userSettings.storeHistory,
      whitelistedDomains: newSettings.whitelistedDomains || userSettings.whitelistedDomains,
      blacklistedDomains: newSettings.blacklistedDomains || userSettings.blacklistedDomains,
      deepseekApiKey: newSettings.deepseekApiKey !== undefined ? newSettings.deepseekApiKey : userSettings.deepseekApiKey,
      openaiApiKey: newSettings.openaiApiKey !== undefined ? newSettings.openaiApiKey : userSettings.openaiApiKey
    };
    chrome.storage.local.set({ 'urlguard_settings': userSettings });
    sendResponse({ success: true });
  } else if (request.action === "getHistory") {
    chrome.storage.local.get(['urlguard_history'], function(result) {
      sendResponse(result.urlguard_history || []);
    });
    return true;
  } else if (request.action === "clearHistory") {
    chrome.storage.local.remove(['urlguard_history']);
    sendResponse({ success: true });
  }
});

/**
 * Analyzes a URL for security threats
 * @param {string} url - The URL to analyze
 * @param {number} tabId - The tab ID where the URL is loaded
 * @param {boolean} forceRefresh - Whether to bypass cache and force a new analysis
 * @returns {Object} Analysis results
 */
async function analyzeUrl(url, tabId, forceRefresh = false) {
  // Quick check for whitelisted/blacklisted domains
  const domain = extractDomain(url);
  
  if (userSettings.whitelistedDomains.includes(domain)) {
    const result = createAnalysisResult(url, 0, "Domain is whitelisted by user", "SAFE");
    updateBadge(tabId, result);
    return result;
  }
  
  if (userSettings.blacklistedDomains.includes(domain)) {
    const result = createAnalysisResult(url, 100, "Domain is blacklisted by user", "PHISHING");
    updateBadge(tabId, result);
    showWarningBanner(tabId, result);
    return result;
  }
  
  // Check cache to avoid redundant analysis (unless force refresh is requested)
  if (!forceRefresh && analysisCache[url]) {
    updateBadge(tabId, analysisCache[url]);
    
    // Show warning banner for high-risk URLs
    if (analysisCache[url].threatScore > 25) {
      showWarningBanner(tabId, analysisCache[url]);
    }
    
    return analysisCache[url];
  }
  
  // Perform URL analysis
  try {
    const urlData = parseUrl(url);
    const analysis = await performLlmAnalysis(urlData);
    
    // Cache the result
    analysisCache[url] = analysis;
    
    // Update storage if history is enabled
    if (userSettings.storeHistory) {
      storeAnalysisInHistory(analysis);
    }
    
    // Update the badge with the result
    updateBadge(tabId, analysis);
    
    // Show warning banner for high-risk URLs
    if (analysis.threatScore > 25) {
      showWarningBanner(tabId, analysis);
    }

    // Open popup for suspicious or dangerous URLs
    if (analysis.threatScore > 25) {
      chrome.windows.getLastFocused({ populate: false }, (win) => {
        if (win && win.focused) {
          chrome.action.openPopup().catch(() => {});
        }
      });
    }
    
    return analysis;
  } catch (error) {
    console.error("Error analyzing URL:", error);
    return {
      url,
      threatScore: 0,
      explanation: "Error analyzing URL",
      category: "SAFE",
      timestamp: new Date().toISOString()
    };
  }
}

/**
 * Extract components from a URL for analysis
 * @param {string} url 
 * @returns {Object} URL components for analysis
 */
function parseUrl(url) {
  try {
    const urlObj = new URL(url);
    return {
      fullUrl: url,
      protocol: urlObj.protocol,
      hostname: urlObj.hostname,
      domain: extractDomain(url),
      path: urlObj.pathname,
      query: urlObj.search,
      hasSubdomains: urlObj.hostname.split('.').length > 2,
      numSpecialChars: (urlObj.hostname + urlObj.pathname).replace(/[a-zA-Z0-9]/g, '').length,
      urlLength: url.length,
      isPunycode: urlObj.hostname.includes('xn--'),
      // Add detection for Unicode characters that could be used in homograph attacks
      hasUnicodeChars: /[^\x00-\x7F]/.test(urlObj.hostname),
      // Check for common typosquatting patterns
      containsCommonBrands: checkForCommonBrands(urlObj.hostname)
    };
  } catch (e) {
    return {
      fullUrl: url,
      protocol: "",
      hostname: "",
      domain: "",
      path: "",
      query: "",
      hasSubdomains: false,
      numSpecialChars: 0,
      urlLength: url.length,
      isPunycode: false,
      hasUnicodeChars: false,
      containsCommonBrands: []
    };
  }
}

/**
 * Check if URL contains references to common brand names
 * @param {string} hostname 
 * @returns {Array} List of detected brands
 */
function checkForCommonBrands(hostname) {
  const commonBrands = [
    'google', 'apple', 'amazon', 'microsoft', 'facebook', 'instagram',
    'paypal', 'netflix', 'gmail', 'yahoo', 'linkedin', 'twitter',
    'dropbox', 'spotify', 'chase', 'wellsfargo', 'bankofamerica',
    'amex', 'visa', 'mastercard', 'verizon', 'att', 'tmobile'
  ];
  
  return commonBrands.filter(brand => hostname.toLowerCase().includes(brand));
}

/**
 * Extract the base domain from a URL
 * @param {string} url 
 * @returns {string} Domain
 */
function extractDomain(url) {
  try {
    const hostname = new URL(url).hostname;
    const parts = hostname.split('.');
    if (parts.length <= 2) return hostname;
    
    // Handle special cases like co.uk, com.au
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

/**
 * Perform LLM-based analysis on the URL
 * @param {Object} urlData - Parsed URL data
 * @returns {Object} Analysis results
 */
async function performLlmAnalysis(urlData) {
  try {
    // Check if API key is available
    if (!userSettings.deepseekApiKey) {
      console.log("No DeepSeek API key configured, falling back to heuristic analysis");
      return performHeuristicAnalysis(urlData);
    }

    // Enhanced prompt for better phishing detection
    const prompt = `You are a cybersecurity expert. Analyze the following URL and determine if it is safe, suspicious, or dangerous based on phishing threat indicators. Return a risk score from 0 (safe) to 100 (dangerous), a clear risk category (Safe, Suspicious, Dangerous), and list at most 3 short reasons to justify your classification:

URL: ${urlData.fullUrl}

Additional URL details:
- Protocol: ${urlData.protocol}
- Domain: ${urlData.domain}
- Hostname: ${urlData.hostname}
- Path: ${urlData.path}
- Is Punycode: ${urlData.isPunycode}
- Has Unicode Characters: ${urlData.hasUnicodeChars}
- Contains Brand References: ${urlData.containsCommonBrands.join(', ')}

Make sure to detect:
- Unicode spoofing or IDN homographs
- Subdomain/path deception
- Domain typosquatting
- Suspicious keywords (login, update, secure, etc.)
- Obfuscation (Punycode, percent encoding)
- SSL/TLS issues
- Homoglyph attacks (e.g., using 0 for O)
- URL shorteners or redirects

Return response in JSON format:
{
  "risk_score": <number from 0-100>,
  "risk_level": "<Safe, Suspicious, or Dangerous>",
  "evidence": ["<short reason 1>", "<short reason 2>", "<short reason 3>"]
}`;
    
    const response = await fetch(API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userSettings.deepseekApiKey}`
      },
      body: JSON.stringify({
        model: "deepseek-chat",
        messages: [
          {
            role: "system",
            content: "You are a cybersecurity expert specializing in URL security analysis, phishing detection, and web threats. Provide concise, accurate assessments."
          },
          {
            role: "user",
            content: prompt
          }
        ],
        temperature: 0.2,
        top_p: 0.9,
        max_tokens: 300
      })
    });
    
    if (!response.ok) {
      throw new Error(`API request failed: ${response.status}`);
    }
    
    const data = await response.json();
    let analysisResult;
    
    try {
      // Try to parse the LLM response as JSON
      const contentText = data.choices[0].message.content;
      const jsonMatch = contentText.match(/\{[\s\S]*\}/);
      
      if (jsonMatch) {
        analysisResult = JSON.parse(jsonMatch[0]);
      } else {
        throw new Error("Could not extract JSON from response");
      }
      
      // Map the response to our expected format
      const threatScore = analysisResult.risk_score || 0;
      let category;
      
      if (threatScore <= 25) {
        category = "SAFE";
      } else if (threatScore <= 50) {
        category = "SUSPICIOUS";
      } else if (threatScore <= 75) {
        category = "HIGH_RISK";
      } else {
        category = "PHISHING";
      }
      
      const explanation = analysisResult.evidence ? analysisResult.evidence.join(". ") : "No specific threats detected";
      
      return createAnalysisResult(
        urlData.fullUrl,
        threatScore,
        explanation,
        category
      );
    } catch (e) {
      console.error("Error parsing LLM response:", e);
      // If parsing fails, fall back to heuristic analysis
      return performHeuristicAnalysis(urlData);
    }
  } catch (error) {
    console.error("LLM analysis failed:", error);
    // Fallback to heuristic analysis
    return performHeuristicAnalysis(urlData);
  }
}

/**
 * Perform online search to determine if a URL is legitimate
 * Uses OpenAI GPT-4o-mini-search-preview model for enhanced web search capabilities
 * @param {string} url - The URL to search for
 * @returns {Object} Search results with legitimacy assessment
 */
async function performOnlineSearch(url) {
  try {
    // Check if API key is available
    if (!userSettings.openaiApiKey) {
      throw new Error('No OpenAI API key configured. Please add your API key in settings.');
    }

    // Validate API key format
    if (!userSettings.openaiApiKey.startsWith('sk-')) {
      throw new Error('Invalid OpenAI API key format');
    }
    
    const domain = extractDomain(url);
    const hostname = new URL(url).hostname;
    
    // Enhanced prompt for online search analysis using OpenAI GPT-4o-mini-search-preview
    const prompt = `You are a cybersecurity expert conducting an online search to determine if a website is legitimate or potentially malicious. 

Analyze the following domain/website and provide a comprehensive assessment:

Domain: ${domain}
Hostname: ${hostname}
Full URL: ${url}

Please search for and analyze:
1. Domain age and registration information
2. Company/business legitimacy and reputation
3. Online reviews and user feedback
4. Security certificates and HTTPS implementation
5. Known phishing or scam reports in security databases
6. Similarity to known legitimate brands (potential typosquatting)
7. Suspicious patterns or red flags
8. Social media presence and activity
9. Contact information and business details
10. Website design and professionalism indicators

Based on your analysis, provide:
- A confidence score (0-100%) indicating how certain you are about the assessment
- Whether the site is likely legitimate or suspicious
- A detailed summary of your findings
- Key evidence points that support your conclusion
- Specific recommendations for the user

Focus on finding concrete evidence about the website's legitimacy, including domain registration details, company information, security practices, and any reported security issues. Be conservative in your assessment - when in doubt, err on the side of caution.

IMPORTANT: You MUST respond with ONLY valid JSON in this exact format. Do not include any text before or after the JSON:

{
  "confidence": <number 0-100>,
  "isLegitimate": <boolean>,
  "summary": "<detailed summary of findings>",
  "keyFindings": ["<finding1>", "<finding2>", "<finding3>"],
  "recommendations": ["<recommendation1>", "<recommendation2>"]
}`;
    
    // Disable Responses API due to server errors, use standard Chat Completions
    const useResponsesApi = false;
    
    const responsesBody = {
      model: "gpt-5-mini",
      input: [
        {
          role: "system",
          content: "You are a cybersecurity expert specializing in online reputation analysis and phishing detection. Conduct thorough research and provide accurate, evidence-based assessments. Focus on finding concrete evidence about the website's legitimacy, including domain registration details, company information, security practices, and any reported security issues. Be conservative in your assessment - when in doubt, err on the side of caution."
        },
        {
          role: "user",
          content: prompt
        }
      ],
      tools: [
        { type: "web_search" }
      ],
      max_output_tokens: 800
    };
    
    const chatCompletionsBody = {
      model: "gpt-4o-mini-search-preview",
      messages: [
        {
          role: "system",
          content: "You are a cybersecurity expert specializing in online reputation analysis and phishing detection. Conduct thorough research and provide accurate, evidence-based assessments. Focus on finding concrete evidence about the website's legitimacy, including domain registration details, company information, security practices, and any reported security issues. Be conservative in your assessment - when in doubt, err on the side of caution."
        },
        {
          role: "user",
          content: `${prompt}\n\nPlease search the web for current information about this domain, including:\n- Domain registration details and age\n- Company information and legitimacy\n- Recent security reports or warnings\n- User reviews and reputation\n- Any known phishing or scam reports\n\nUse your web search capabilities to gather real-time information before making your assessment.`
        }
      ],
      max_completion_tokens: 800
    };
    
    console.log("OpenAI API Request:", {
      endpoint: useResponsesApi ? OPENAI_RESPONSES_ENDPOINT : OPENAI_API_ENDPOINT,
      model: useResponsesApi ? "gpt-5-mini" : "gpt-4o-mini-search-preview",
      mode: useResponsesApi ? "responses" : "chat.completions"
    });
    
    const response = await fetch(useResponsesApi ? OPENAI_RESPONSES_ENDPOINT : OPENAI_API_ENDPOINT, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${userSettings.openaiApiKey}`
      },
      body: JSON.stringify(useResponsesApi ? responsesBody : chatCompletionsBody)
    });
    
    if (!response.ok) {
      const errorText = await response.text();
      console.error(`OpenAI API request failed: ${response.status} - ${errorText}`);
      throw new Error(`OpenAI API request failed: ${response.status} - ${errorText}`);
    }
    
    const data = await response.json();
    console.log("Full OpenAI API response:", JSON.stringify(data, null, 2));
    
    let searchResult;
    
    try {
      // Check if response has expected structure
      // Normalize content depending on API used
      let contentText;
      if (useResponsesApi) {
        // Responses API returns output in content array with text items
        const textItem = data.output && data.output[0] && data.output[0].content
          ? data.output[0].content.find((c) => c.type === 'output_text' || c.type === 'text' || (c.text && c.text.value))
          : null;
        contentText = textItem?.text?.value || textItem?.value || null;
      } else {
        if (!data.choices || !data.choices[0] || !data.choices[0].message) {
          throw new Error("Invalid API response structure");
        }
        contentText = data.choices[0].message.content;
      }
      console.log("GPT-4o-mini-search-preview raw response:");
      console.log("Response length:", contentText ? contentText.length : "null/undefined");
      console.log("Full content:", contentText);
      
      // Check if content is empty or null
      if (!contentText || contentText.trim().length === 0) {
        throw new Error("Empty response from GPT-4o-mini-search-preview");
      }
      
      // Try multiple JSON extraction methods
      let jsonMatch = contentText.match(/\{[\s\S]*\}/);
      
      if (!jsonMatch) {
        // Try to find JSON between code blocks
        jsonMatch = contentText.match(/```json\s*(\{[\s\S]*?\})\s*```/);
        if (jsonMatch) {
          jsonMatch[0] = jsonMatch[1];
        }
      }
      
      if (!jsonMatch) {
        // Try to find JSON between triple backticks
        jsonMatch = contentText.match(/```\s*(\{[\s\S]*?\})\s*```/);
        if (jsonMatch) {
          jsonMatch[0] = jsonMatch[1];
        }
      }
      
      if (jsonMatch) {
        try {
          searchResult = JSON.parse(jsonMatch[0]);
        } catch (parseError) {
          console.error("JSON parse error:", parseError);
          throw new Error("Invalid JSON format in response");
        }
      } else {
        // If no JSON found, try to extract information from plain text
        console.log("No JSON found, parsing plain text response");
        searchResult = parseTextResponse(contentText, domain);
      }
      
             // Validate and sanitize the response
       const searchAnalysisResult = {
         confidence: Math.min(100, Math.max(0, searchResult.confidence || 50)),
         isLegitimate: Boolean(searchResult.isLegitimate),
         summary: searchResult.summary || "Analysis completed but no specific findings available.",
         keyFindings: Array.isArray(searchResult.keyFindings) ? searchResult.keyFindings.slice(0, 5) : [],
         recommendations: Array.isArray(searchResult.recommendations) ? searchResult.recommendations.slice(0, 3) : []
       };
       
       // Store online search result in history if enabled
       if (userSettings.storeHistory) {
         const historyEntry = {
           url: url,
           threatScore: searchAnalysisResult.isLegitimate ? 10 : 75, // Convert legitimacy to threat score
           explanation: `Online Search: ${searchAnalysisResult.summary}`,
           category: searchAnalysisResult.isLegitimate ? "SAFE" : "HIGH_RISK",
           color: searchAnalysisResult.isLegitimate ? "#4CAF50" : "#F44336",
           timestamp: new Date().toISOString(),
           searchType: "online_search",
           confidence: searchAnalysisResult.confidence,
           isLegitimate: searchAnalysisResult.isLegitimate,
           keyFindings: searchAnalysisResult.keyFindings,
           recommendations: searchAnalysisResult.recommendations
         };
         storeAnalysisInHistory(historyEntry);
       }
       
       return searchAnalysisResult;
      
    } catch (e) {
      console.error("Error parsing online search response:", e);
      // Fallback response
      const fallbackResult = {
        confidence: 50,
        isLegitimate: false,
        summary: "Unable to complete online search analysis. Please exercise caution and verify the website through other means.",
        keyFindings: ["Analysis could not be completed"],
        recommendations: ["Verify the website through other sources", "Check for HTTPS certificate", "Look for contact information and company details"]
      };
      
      // Store fallback result in history if enabled
      if (userSettings.storeHistory) {
        const historyEntry = {
          url: url,
          threatScore: 75,
          explanation: `Online Search Failed: ${fallbackResult.summary}`,
          category: "HIGH_RISK",
          color: "#F44336",
          timestamp: new Date().toISOString(),
          searchType: "online_search",
          confidence: fallbackResult.confidence,
          isLegitimate: fallbackResult.isLegitimate,
          keyFindings: fallbackResult.keyFindings,
          recommendations: fallbackResult.recommendations
        };
        storeAnalysisInHistory(historyEntry);
      }
      
      return fallbackResult;
    }
    
  } catch (error) {
    console.error("Online search failed:", error);
    console.error("Error details:", error.message);
    
    const errorResult = {
      confidence: 0,
      isLegitimate: false,
      summary: `Failed to perform online search: ${error.message}. Please try again or verify the website manually.`,
      keyFindings: ["Search failed", error.message],
      recommendations: ["Try the search again", "Verify the website manually", "Check for HTTPS and security certificates"]
    };
    
    // Store error result in history if enabled
    if (userSettings.storeHistory) {
      const historyEntry = {
        url: url,
        threatScore: 75,
        explanation: `Online Search Error: ${errorResult.summary}`,
        category: "HIGH_RISK",
        color: "#F44336",
        timestamp: new Date().toISOString(),
        searchType: "online_search",
        confidence: errorResult.confidence,
        isLegitimate: errorResult.isLegitimate,
        keyFindings: errorResult.keyFindings,
        recommendations: errorResult.recommendations
      };
      storeAnalysisInHistory(historyEntry);
    }
    
    return errorResult;
  }
}

/**
 * Parse plain text response when JSON extraction fails
 * @param {string} textResponse - The plain text response from GPT-5-nano
 * @param {string} domain - The domain being analyzed
 * @returns {Object} Parsed analysis result
 */
function parseTextResponse(textResponse, domain) {
  console.log("Parsing text response for domain:", domain);
  console.log("Full response text:", textResponse);
  
  const text = textResponse.toLowerCase();
  
  // Determine legitimacy based on keywords
  const legitimateKeywords = ['legitimate', 'safe', 'trusted', 'official', 'verified', 'authentic', 'reputable', 'established', 'well-known'];
  const suspiciousKeywords = ['suspicious', 'phishing', 'scam', 'fraudulent', 'malicious', 'dangerous', 'fake', 'typosquatting', 'deceptive'];
  
  const legitimateScore = legitimateKeywords.filter(word => text.includes(word)).length;
  const suspiciousScore = suspiciousKeywords.filter(word => text.includes(word)).length;
  
  const isLegitimate = legitimateScore > suspiciousScore;
  const confidence = Math.min(90, Math.max(30, (Math.abs(legitimateScore - suspiciousScore) + 1) * 20));
  
  // Extract meaningful sentences as key findings
  const sentences = textResponse.split(/[.!?]+/)
    .map(s => s.trim())
    .filter(s => s.length > 20 && s.length < 150)
    .slice(0, 3);
  
  // If no good sentences, create basic findings
  const keyFindings = sentences.length > 0 ? sentences : [
    `Domain analysis indicates ${isLegitimate ? 'legitimate' : 'suspicious'} characteristics`,
    `Confidence level: ${confidence}%`,
    `Keyword analysis: ${legitimateScore} positive vs ${suspiciousScore} negative indicators`
  ];
  
  // Generate recommendations based on analysis
  const recommendations = isLegitimate ? 
    ["Website appears to be legitimate based on analysis", "Verify through official channels for sensitive activities", "Check for secure HTTPS connection"] :
    ["Exercise caution when using this website", "Verify authenticity through official sources", "Avoid entering sensitive personal information"];
  
  // Create a better summary from the full response
  let summary = textResponse.trim();
  if (summary.length > 300) {
    summary = summary.substring(0, 297) + "...";
  }
  
  if (summary.length < 50) {
    summary = `Based on analysis of ${domain}, the website appears to be ${isLegitimate ? 'legitimate' : 'potentially suspicious'}. ${summary}`;
  }
  
  return {
    confidence,
    isLegitimate,
    summary,
    keyFindings,
    recommendations
  };
}

/**
 * Perform heuristic-based analysis when LLM is not available
 * @param {Object} urlData - Parsed URL data
 * @returns {Object} Analysis results
 */
function performHeuristicAnalysis(urlData) {
  let threatScore = 0;
  let reasons = [];
  
  // Check for HTTPS
  if (urlData.protocol !== 'https:') {
    threatScore += 15;
    reasons.push("Not using HTTPS");
  }
  
  // Check for Punycode (potential IDN homograph attack)
  if (urlData.isPunycode) {
    threatScore += 50;
    reasons.push("Uses Punycode (potential IDN homograph attack)");
  }
  
  // Check for Unicode characters (potential homograph attack)
  if (urlData.hasUnicodeChars) {
    threatScore += 45;
    reasons.push("Contains non-standard Unicode characters");
  }
  
  // Check URL length (excessively long URLs are suspicious)
  if (urlData.urlLength > 100) {
    threatScore += 15;
    reasons.push("Unusually long URL");
  }
  
  // Check for excessive special characters
  if (urlData.numSpecialChars > 15) {
    threatScore += 20;
    reasons.push("Excessive special characters");
  }
  
  // Check for IP address as hostname
  if (/^\d+\.\d+\.\d+\.\d+$/.test(urlData.hostname)) {
    threatScore += 30;
    reasons.push("IP address used as hostname");
  }
  
  // Check for suspicious TLDs
  const suspiciousTLDs = ['.tk', '.top', '.xyz', '.gq', '.ml', '.ga', '.cf'];
  if (suspiciousTLDs.some(tld => urlData.hostname.endsWith(tld))) {
    threatScore += 20;
    reasons.push("Suspicious top-level domain");
  }
  
  // Check for brand impersonation
  if (urlData.containsCommonBrands.length > 0) {
    // If brand is in hostname but not the main domain (potential typosquatting)
    if (urlData.containsCommonBrands.some(brand => 
        urlData.hostname.includes(brand) && !urlData.domain.includes(brand))) {
      threatScore += 40;
      reasons.push("Brand name in subdomain but not main domain");
    }
    
    // Check for common typosquatting patterns
    const brandSimilarityScore = checkBrandSimilarity(urlData.domain, urlData.containsCommonBrands);
    if (brandSimilarityScore > 0) {
      threatScore += brandSimilarityScore;
      reasons.push("Domain similar to known brand (potential typosquatting)");
    }
  }
  
  // Check for homograph attack characters
  if (/[а-яА-Я\u00A0-\u024F]/.test(urlData.hostname)) { // Cyrillic or Latin-extended chars
    threatScore += 45;
    reasons.push("Potential homograph attack (non-standard characters)");
  }
  
  // Check for excessive subdomains
  if ((urlData.hostname.match(/\./g) || []).length > 3) {
    threatScore += 15;
    reasons.push("Excessive number of subdomains");
  }
  
  // Check for suspicious keywords in the URL
  const suspiciousKeywords = ['login', 'secure', 'account', 'update', 'verify', 'password', 'auth', 'signin', 'confirm'];
  const hasKeywords = suspiciousKeywords.some(keyword => urlData.fullUrl.toLowerCase().includes(keyword));
  if (hasKeywords) {
    threatScore += 15;
    reasons.push("Contains sensitive keywords often used in phishing");
  }
  
  // Determine category based on threat score
  let category;
  if (threatScore <= 25) {
    category = "SAFE";
  } else if (threatScore <= 50) {
    category = "SUSPICIOUS";
  } else if (threatScore <= 75) {
    category = "HIGH_RISK";
  } else {
    category = "PHISHING";
  }
  
  // Limit to top 3 reasons for cleaner UI
  if (reasons.length > 3) {
    reasons = reasons.slice(0, 3);
  }
  
  return createAnalysisResult(
    urlData.fullUrl,
    threatScore,
    reasons.join(". "),
    category
  );
}

/**
 * Check similarity between domain and known brands
 * @param {string} domain 
 * @param {Array} brands 
 * @returns {number} Similarity score (0-50)
 */
function checkBrandSimilarity(domain, brands) {
  if (!domain || brands.length === 0) return 0;
  
  // Simple Levenshtein distance calculation
  function levenshteinDistance(a, b) {
    if (a.length === 0) return b.length;
    if (b.length === 0) return a.length;
    
    const matrix = [];
    
    // Initialize matrix
    for (let i = 0; i <= b.length; i++) {
      matrix[i] = [i];
    }
    
    for (let j = 0; j <= a.length; j++) {
      matrix[0][j] = j;
    }
    
    // Fill matrix
    for (let i = 1; i <= b.length; i++) {
      for (let j = 1; j <= a.length; j++) {
        if (b.charAt(i - 1) === a.charAt(j - 1)) {
          matrix[i][j] = matrix[i - 1][j - 1];
        } else {
          matrix[i][j] = Math.min(
            matrix[i - 1][j - 1] + 1, // substitution
            matrix[i][j - 1] + 1,     // insertion
            matrix[i - 1][j] + 1      // deletion
          );
        }
      }
    }
    
    return matrix[b.length][a.length];
  }
  
  // Check domain against each brand
  let maxScore = 0;
  
  for (const brand of brands) {
    // Skip very short brands to avoid false positives
    if (brand.length < 4) continue;
    
    const distance = levenshteinDistance(domain.toLowerCase(), brand.toLowerCase());
    const similarity = 1 - (distance / Math.max(domain.length, brand.length));
    
    // If very similar but not exact match (typosquatting)
    if (similarity > 0.7 && similarity < 1) {
      const score = Math.floor(similarity * 50); // Score between 0-50
      maxScore = Math.max(maxScore, score);
    }
  }
  
  return maxScore;
}

/**
 * Create a standardized analysis result object
 * @param {string} url - The analyzed URL
 * @param {number} score - Threat score (0-100)
 * @param {string} explanation - Explanation of the analysis
 * @param {string} category - Threat category
 * @returns {Object} Standardized analysis result
 */
function createAnalysisResult(url, score, explanation, category) {
  return {
    url,
    threatScore: score,
    explanation,
    category,
    color: getCategoryColor(category),
    timestamp: new Date().toISOString()
  };
}

/**
 * Get the color associated with a threat category
 * @param {string} category - Threat category
 * @returns {string} Color hex code
 */
function getCategoryColor(category) {
  const threatLevel = Object.values(THREAT_LEVELS).find(level => 
    level.name.toUpperCase() === category.toUpperCase()
  );
  
  return threatLevel ? threatLevel.color : "#4CAF50";
}

/**
 * Update the extension badge with the analysis result
 * @param {number} tabId - The tab ID
 * @param {Object} analysis - The analysis result
 */
function updateBadge(tabId, analysis) {
  if (!tabId) return;
  
  let color, text;
  
  if (analysis.threatScore <= 25) {
    color = "#4CAF50"; // Green
    text = "✓";
  } else if (analysis.threatScore <= 50) {
    color = "#FFC107"; // Yellow
    text = "!";
  } else if (analysis.threatScore <= 75) {
    color = "#F44336"; // Red
    text = "!!";
  } else {
    color = "#F44336"; // Red
    text = "!!!";
  }
  
  chrome.action.setBadgeBackgroundColor({ color, tabId });
  chrome.action.setBadgeText({ text, tabId });
  
  // Send message to popup if it's open
  chrome.runtime.sendMessage({
    action: "updateStatus",
    analysis
  }).catch(() => {
    // Popup not open, ignore error
  });
}

/**
 * Show a warning banner for high-risk URLs
 * @param {number} tabId - The tab ID
 * @param {Object} analysis - The analysis result
 */
function showWarningBanner(tabId, analysis) {
  if (!tabId || !userSettings.showNotifications) return;
  
  // Send message to content script to show warning banner
  chrome.tabs.sendMessage(tabId, {
    action: "showWarningBanner",
    analysis
  }).catch(() => {
    // Content script not ready yet, try injecting it first
    chrome.scripting.executeScript({
      target: { tabId },
      files: ['content.js']
    }).then(() => {
      // Now send the message again
      setTimeout(() => {
        chrome.tabs.sendMessage(tabId, {
          action: "showWarningBanner",
          analysis
        }).catch(err => console.error("Failed to show warning banner:", err));
      }, 100);
    }).catch(err => console.error("Failed to inject content script:", err));
  });
  
  // Also show a browser notification
  const iconUrl = chrome.runtime.getURL('icons/icon128.png');
  chrome.notifications.create({
    type: "basic",
    iconUrl,
    title: `URLGuard: ${analysis.category} Detected`,
    message: analysis.explanation
  });
}

/**
 * Store analysis result in history
 * @param {Object} analysis - The analysis result
 */
function storeAnalysisInHistory(analysis) {
  chrome.storage.local.get(['urlguard_history'], function(result) {
    const history = result.urlguard_history || [];
    
    // Limit history to 1000 entries
    if (history.length >= 1000) {
      history.pop();
    }
    
    // Add new entry at the beginning
    history.unshift(analysis);
    
    chrome.storage.local.set({ 'urlguard_history': history });
  });
}

// Initialize the extension
function initialize() {
  // Clear badge on startup
  chrome.tabs.query({}, tabs => {
    tabs.forEach(tab => {
      chrome.action.setBadgeText({ text: "", tabId: tab.id });
    });
  });
  
  console.log("URLGuard background service initialized");
}

initialize(); 