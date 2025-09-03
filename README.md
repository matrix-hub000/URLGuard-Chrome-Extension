# URLGuard - AI-powered URL Security & Phishing Detection

URLGuard is a Chrome extension that enhances your web browsing security by detecting and alerting you of potentially phishing or malicious URLs in real-time. It uses AI-powered analysis to identify suspicious patterns and content-based anomalies.

**Created by: Hiu Kai Zhi**

## Features

- **Real-Time URL Monitoring**: Automatically analyzes every URL you visit
- **AI-Powered Analysis**: Uses DeepSeek LLM API for advanced security analysis
- **Threat Scoring System**: Assigns a threat score (0-100) to each URL
- **Risk Categories**: Classifies threats as Safe, Suspicious, High Risk, or Phishing
- **Visual Alerts**: Color-coded warnings with detailed explanations
- **Domain Management**: Whitelist trusted sites and blacklist known threats
- **Dashboard Interface**: View your recent URL analysis history
- **Privacy-Focused**: Minimal data storage and optional history tracking

## Installation

### Manual Installation (Developer Mode)
1. Download and unzip the extension files
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" (toggle in the top-right corner)
4. Click "Load unpacked" and select the unzipped extension folder
5. The URLGuard extension should now appear in your extensions list

### From Chrome Web Store (Coming Soon)
1. Visit the URLGuard page on the Chrome Web Store
2. Click "Add to Chrome"
3. Confirm the installation when prompted

## Setup

1. Click on the URLGuard icon in your browser toolbar
2. Go to the Settings tab
3. Configure your preferences for notifications and history tracking
4. Add any trusted domains to your whitelist or known malicious sites to your blacklist

## How It Works

URLGuard combines multiple security techniques to protect you from phishing and malicious websites:

1. **URL Structure Analysis**: Examines domain names, subdomains, paths, and parameters
2. **AI-Powered Assessment**: Uses the integrated DeepSeek API to analyze URLs for security threats
3. **Threat Indicators**: Checks for homograph attacks, suspicious TLDs, excessive redirects, and other warning signs
4. **Real-Time Alerts**: Displays warning banners for suspicious sites with clear explanations

## Privacy Policy

URLGuard is designed with privacy in mind:
- All basic URL analysis happens locally on your device
- DeepSeek API analysis uses minimal data transfer with API keys stored securely
- URL history storage is optional and stored only on your local device
- No browsing data is shared with third parties

## Contributing

Contributions are welcome! If you have suggestions or want to report issues, please open an issue or submit a pull request.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 