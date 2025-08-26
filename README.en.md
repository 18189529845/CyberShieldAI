# CyberShield AI

"CyberShield AI - Guarding Every Click"

An automated illegal website detection system based on multi-dimensional feature analysis, integrating domain name features, content analysis, network behavior, certificate verification and other detection dimensions to efficiently identify various types of illegal websites.

## 📚 Project Introduction

CyberShield AI is a comprehensive website security detection solution that achieves rapid identification and risk assessment of illegal websites by collecting and analyzing multi-dimensional features of websites. The system adopts a combined detection method based on rules and machine learning, featuring high accuracy and scalability.

Suitable for network security supervision, enterprise security protection, website security auditing and other scenarios, it can effectively help users identify potential network security risks.

## 🚀 Features

- **Multi-dimensional Detection**: Comprehensive analysis based on 7 major dimensional features
- **Batch Processing**: Support for large-scale URL parallel detection
- **Real-time Scoring**: Dynamic risk scoring and level classification
- **Machine Learning**: Integration of algorithms such as Random Forest to improve accuracy
- **Detailed Reports**: Generate reports in JSON, CSV, and text formats
- **Concurrent Optimization**: Support for multi-threaded concurrent detection
- **Scheduled Tasks**: Support for scheduled automatic execution of detection tasks
- **Database Integration**: Can obtain URLs and sensitive keywords from the database
- **Blacklist Management**: Automatically update and manage malicious domain/IP blacklists
- **Subpage Analysis**: Deep detection of website subpage content features

## 📊 Detection Dimensions (Enhanced Version)

| Dimension Category | Detection Indicators |
|-------------------|----------------------|
| **Domain Features** | Domain age, spelling anomalies, suspicious suffixes, WHOIS information, blacklist matching, brand phishing detection, homograph character attacks, domain entropy, registrar reputation |
| **Content Analysis** | Classification keyword detection, page quality, SSL certificate enhanced detection, security header detection, page structure analysis, redirect analysis, malicious code |
| **Network Features** | DNS resolution, response time, IP address, HTTP status, IP blacklist check, email server detection, server fingerprint identification, accessibility test |
| **Behavior Patterns** | Access anomalies, redirect chains, resource loading, login form detection, contact information integrity, privacy policy existence, suspicious image detection, malicious script detection |
| **Subpage Features** | Number of subpages, sensitive subpage detection, average risk score, keyword distribution |

## 🏗️ System Architecture

The system adopts a modular design, mainly including the following core components:

1. **Data Collection Module**: Responsible for obtaining website content, domain name information, network features and other data
2. **Feature Extraction Module**: Extract valuable features from the collected raw data
3. **Risk Assessment Module**: Perform risk scoring based on rules and machine learning models
4. **Report Generation Module**: Generate multi-format detection reports
5. **Data Storage Module**: Connect to the database for data reading/writing and blacklist updating
6. **Task Scheduling Module**: Implement scheduled detection functionality

## 🛠️ Quick Start

### 1. Environment Preparation

```bash
# Install dependencies
pip install -r requirements.txt

# Or use conda
conda install --file requirements.txt
```

### 2. Configure Blacklists (Optional)
The system has pre-configured blacklist files:
- `blacklist_domains.txt` - List of known malicious domains
- `blacklist_ips.txt` - List of known malicious IP addresses

You can add more entries as needed. The system also supports automatic blacklist updates from the database.

### 3. Database Configuration
The system supports obtaining URL and keyword information from MySQL database. The configuration is located in the `DB_CONFIG` variable in the code file:

```python
# Database configuration example
DB_CONFIG = {
    'host': '127.0.0.1',  # Database host address
    'port': 3306,
    'user': 'root',       # Database username
    'password': 'your_password',  # Database password
    'db': 'ntmv3',  # Database name
    'charset': 'utf8mb4',
    'cursorclass': pymysql.cursors.DictCursor
}
```

### 4. Basic Usage

#### Method 1: Detect Single URL
```python
from batch_website_detector import WebsiteDetector

detector = WebsiteDetector()
features = detector.extract_all_features("https://example.com")
risk_level, risk_score = detector.predict_risk(features)
print(f"Risk Level: {risk_level}, Score: {risk_score}%")
```

#### Method 2: Batch Detect from File
```bash
# Detect URLs from a file
python batch_website_detector.py -f sample_urls.txt -o results

# Directly specify URLs for detection
python batch_website_detector.py -u https://site1.com https://site2.com

# Specify number of concurrent threads
python batch_website_detector.py -f urls.txt -w 20
```

#### Method 3: Scheduled Task Detection
The system supports scheduled automatic execution of detection tasks, defaulting to once every 10 seconds:

```bash
# Start scheduled detection task
python batch_website_detector.py

# Custom detection interval (seconds)
python batch_website_detector.py --interval 30

# Execute detection only once (without scheduling)
python batch_website_detector.py --once
```

### 5. Using Test Script
```bash
# Run complete test
python test_detector.py

# Test a single website
python test_detector.py --single https://example.com

# Test batch detection
python test_detector.py --batch sample_urls.txt
```

## 📋 Input/Output Formats

### Input Formats

#### URL List File Format
```
# Comments are supported
https://www.google.com
https://www.baidu.com
https://example123.tk
```

#### Command Line Parameters
```bash
usage: batch_website_detector.py [-h] [-f FILE] [-u URLS [URLS ...]] 
                                [-o OUTPUT] [-w WORKERS] [--interval INTERVAL] [--once]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  File containing list of URLs
  -u URLS [URLS ...], --urls URLS [URLS ...]
                        Directly specify list of URLs
  -o OUTPUT, --output OUTPUT
                        Output file name prefix
  -w WORKERS, --workers WORKERS
                        Number of concurrent worker threads, default 10
  --interval INTERVAL   Scheduled detection interval (seconds), default 10 seconds
  --once                Execute detection only once, disable scheduling
```

### Output Results

#### Result Files

After detection is completed, three files will be generated:
- `{prefix}.json` - Complete detection results (including all features)
- `{prefix}.csv` - Brief results (URL, risk level, score)
- `{prefix}_summary.txt` - Detection report summary

#### Risk Levels

| Level | Score Range | Description |
|------|------------|-------------|
| **High Risk** | 70-100% | High risk, suspected illegal website |
| **Medium Risk** | 40-69% | Medium risk, needs further verification |
| **Low Risk** | 0-39% | Low risk, relatively safe |

#### Example Output

```json
{
  "Website": "https://example123.tk",
  "Risk Level": "High Risk",
  "Risk Score": "75%",
  "Risk Description": "🚨 This website has serious security risks\n• Extremely short domain registration time (within 7 days)\n• Contains sensitive content",
  "Detection Time": "2024-01-15 10:30:00",
  "Detailed Features": {
    "Domain Length": 15,
    "Domain Age (days)": 5,
    "Suspicious Top-Level Domain": 1,
    "Sensitive Word Ratio": 0.08,
    "Has SSL Certificate": 0,
    ...
  }
}
```

## 🔧 Advanced Configuration

### 1. Custom Sensitive Keywords

The system supports loading keywords from the database, or you can modify the keyword configuration in the `WebsiteDetector` class.

### 2. Adjust Risk Score Weights

Adjust the weights of various factors in the `predict_risk` method:

```python
# Domain risk factor
if features.get('is_new_domain', 0) == 1:
    risk_score += 25  # Adjust weight
```

### 3. Train Machine Learning Models

```python
# Prepare training data
from sklearn.ensemble import RandomForestClassifier

# Features and labels
X = [...]  # Feature matrix
y = [...]  # Labels

# Train model
model = RandomForestClassifier(n_estimators=100)
model.fit(X, y)

# Save model
joblib.dump(model, 'website_detection_model.pkl')
```

### 4. Scheduled Task Configuration

The system supports configuring the scheduled detection interval through command line parameters, or you can directly modify the default value in the code:

```python
# Set default detection interval (seconds)
DEFAULT_INTERVAL = 10
```

## ⚡ Performance Optimization

### 1. Concurrency Configuration

- **Low Concurrency** (5-10 threads): Suitable for poor network environments
- **Medium Concurrency** (10-20 threads): Balance between performance and stability
- **High Concurrency** (20-50 threads): Suitable for large-scale detection tasks

### 2. Cache Optimization

```python
# Enable DNS cache
import dns.resolver
dns.resolver.default_resolver.cache = dns.resolver.Cache()

# Enable request cache
import requests_cache
requests_cache.install_cache('website_cache', expire_after=3600)
```

### 3. Detection Timeout Configuration

You can adjust the timeout time of each module to adapt to different network environments:

```python
# Set default timeout time
session_timeout = 10  # seconds
subpage_timeout = 8   # seconds
```

## 🚨 Notes

1. **Network Permissions**: Ensure you have permission to access the external network
2. **DNS Configuration**: Check if local DNS configuration is correct
3. **Firewall**: May need to configure firewall to allow relevant ports
4. **Rate Limiting**: Avoid detection frequencies that are too fast to trigger target website protection
5. **Legal Compliance**: Only for legal security detection purposes
6. **Resource Usage**: Pay attention to system resource usage during large-scale detection

## 📞 Technical Support

### Frequently Asked Questions

**Q: What if the detection speed is very slow?**
A: Adjust the `-w` parameter to reduce concurrent threads, or check network connection

**Q: SSL certificate verification error occurs?**
A: Update the system's CA certificate package or temporarily disable SSL verification

**Q: How to add new detection dimensions?**
A: Add new feature extraction methods in the `WebsiteDetector` class

**Q: Detection results are inaccurate?**
A: Collect more training data to retrain the machine learning model

**Q: How to stop scheduled tasks?**
A: Use Ctrl+C key combination to exit scheduled tasks gracefully

### Update Log

- v1.0.0 - Initial version, including basic detection functions
- v1.1.0 - Added machine learning model support
- v1.2.0 - Optimized concurrent performance and report generation
- v1.3.0 - Added subpage deep detection function
- v1.4.0 - Added database integration and scheduled task functions

## 📄 License

This project is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE Version 3, 19 November 2007.

Please refer to the LICENSE file in the project root directory for detailed license information.

This project is for learning and research purposes only. Please ensure use within legal scope.
```