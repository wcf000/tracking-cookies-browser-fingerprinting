# Privacy Shield: Tracking Cookies & Fingerprinting Protection

Privacy Shield is a toolkit for detecting, analyzing, and blocking browser fingerprinting and tracking cookies. It consists of two main components:

1. A **cookie analysis tool** for in-depth analysis of current browser cookies
2. A **browser extension** for real-time protection and monitoring

## Cookie Analysis Tool

The Python-based cookie analysis tool provides deeper insights into cookies stored in your browsers.

### Features

- Extracts cookies directly from browser databases
- Classifies cookies based on purpose and tracking potential
- Generates detailed HTML reports with visualizations
- Provides insights on tracking domains, cookie lifespans, etc.

### Installation

1. Make sure you have Python 3.7+ installed
2. Install required packages:
   ```bash
   pip install -r requirements.txt
   ```

### Usage
Run the analysis tool by selecting the browser that you want to analyze, and optionally add a custom path if the default path doesn't work:
```bash
python main.py --browsers edge
```

## Browser Extension

### Features

- Detects and blocks browser fingerprinting attempts in real-time
- Identifies and blocks tracking cookies
- Provides a dashboard with detailed statistics and visualizations
- Displays notifications when tracking is detected
- Supports customizable protection settings

### Installation

1. Clone this repository or download the source code
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable "Developer mode" in the top-right corner
4. Click "Load unpacked" and select the `extension` folder from this project

### Usage

- **Popup UI**: Click the extension icon to see current page tracking statistics and toggle settings
- **Dashboard**: Access the full dashboard by clicking "View Dashboard" in the popup
- **Settings**:
  - **Block Fingerprinting**: Detect and prevent browser fingerprinting techniques
  - **Block Tracking Cookies**: Automatically block third-party tracking cookies
  - **Show Notifications**: Display the tracking counter badge on the extension icon