# GoCheck 🎣

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Perfect bot detection for GoPhish phishing campaigns**

GoCheck analyzes GoPhish campaign events to accurately distinguish automated scanner activity from genuine human interactions using context-aware detection, dynamic whitelisting, and persistent learning. Perfect for enterprise environments with VPNs and email gateways.

## ✨ Key Features

- 🧠 **Intelligent VPN Detection** - Dynamic whitelisting learns legitimate corporate VPN patterns (3+ interactions)
- ⏱️ **Smart Timing Analysis** - Distinguishes send→open (hours OK) from open→click (1-30s)
- 📧 **Email Client Support** - Recognizes Outlook, Apple Mail, Thunderbird as legitimate access
- 🌍 **IP Intelligence** - Geolocation, ISP classification, cloud provider detection
- 🎯 **Multi-IP Tracking** - Separates bot scans from real user clicks on same email
- 📊 **Comprehensive Reports** - Clean CSV exports with human-only interactions
- 💻 **Full-Featured CLI** - Command-line interface with verbose mode
- 💾 **Persistent Learning** - Whitelist saved automatically, improves over time

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/Givaa/GoCheck.git
cd GoCheck

# Install dependencies
pip install -r requirements.txt

# Run analysis
python gocheck/GoCheck.py -i raw_events.csv
```

## 📖 Usage

### Command Line Interface

```bash
# Basic analysis
python gocheck/GoCheck.py -i events.csv

# Custom output directory
python gocheck/GoCheck.py -i events.csv -o reports/

# Verbose mode (see detailed scoring)
python gocheck/GoCheck.py -i events.csv -v

# Show help
python gocheck/GoCheck.py --help
```

### As a Python Module

```python
from gocheck.GoCheck import GoPhishAnalyzer

# Analyze campaign
analyzer = GoPhishAnalyzer('raw_events.csv')
results = analyzer.analyze_campaign(verbose=True)

# Generate human-only report
human_report = analyzer.generate_human_report(results)

# Access whitelist data
print(analyzer.ip_whitelist)
```

## 🎯 How It Works

GoCheck uses an **intelligent, context-aware** scoring system that adapts to enterprise environments:

### Detection Factors

#### 1. IP Analysis (0-100 penalty)
- **Security scanners** (Proofpoint, Mimecast): -95 points
- **Cloud providers** (AWS, Azure, GCP): -80 points
- **Datacenters/Hosting**: -75 points
- **VPN/Proxy**:
  - First time: -40 points
  - Whitelisted: -15 points (learned behavior)
- **Legitimate ISPs**: 0 points

#### 2. Smart Timing Analysis

**Send → Open** (humans take hours):
```
< 2s    = Bot (immediate scanner)
2-10s   = Suspicious
> 10s   = Normal human ✓
```

**Open → Click** (humans read 3-30s):
```
< 1s    = Bot (automation)
1-3s    = Suspicious
3-30s   = Normal human ✓
> 30s   = Re-reading email ✓
```

#### 3. User Agent Analysis
- **Bot/Crawler keywords**: -80 points
- **Security tools**: -70 points
- **Email clients** (Outlook, Apple Mail): 0 points ✓
- **Standard browsers**: 0 points ✓
- **Missing UA**: -30 points

#### 4. Behavioral Bonuses
- **Clicked link**: +10 points
- **VPN with human behavior**: +25 points

### Dynamic Whitelist System

GoCheck learns which IPs are legitimate for specific email domains:

```python
# Example: Corporate VPN Gateway
mail.com users → 192.168.1.50 (VPN)

User 1: First interaction
  - Score: 100 - 40 (VPN) + 25 (human timing) = 85 ✓
  - Whitelist: human_behaviors = 1

User 2: Second interaction
  - Score: 100 - 40 (VPN) + 25 (human timing) = 85 ✓
  - Whitelist: human_behaviors = 2
  - ✅ IP now whitelisted for mail.com

User 3: Uses whitelisted IP
  - Score: 100 - 15 (whitelisted!) + 25 = 110 (capped to 100) ✓
```

### Scoring Thresholds

- **70-100**: ✅ Genuine human user
- **40-69**: ⚠️ Suspicious, review recommended
- **0-39**: 🤖 Bot/scanner detected

## 📊 Output Reports

### Human Users Report (`human_users_report.csv`)

| email | human_opened | human_clicked | human_score | human_ip | details |
|-------|--------------|---------------|-------------|----------|---------|
| user@company.com | YES | YES | 95 | 192.168.1.50 | Actions: opened email, clicked link |
| admin@company.com | YES | NO | 78 | 93.45.123.87 | Actions: opened email |
| bot@company.com | NO | NO | 0 | N/A | Bot/scanner only detected |

### Complete Analysis (`complete_campaign_analysis.csv`)

Detailed breakdown of every IP interaction with:
- IP classifications and scores
- Timing analysis
- Event timelines
- Bot vs human determination

## 🔬 Real-World Examples

### Example 1: Corporate VPN with Outlook

```
Email: john@company.com
IP: 172.16.0.50 (Corporate VPN)
User Agent: Microsoft Outlook/16.0

Timeline:
  09:00:00  Email Sent
  11:30:00  Email Opened (2.5 hours later)
  11:30:15  Clicked Link (15 seconds after open)

Analysis:
  Base score: 100
  - VPN (first time): -40
  - Send→Open (2.5h): 0 (normal human delay)
  - Open→Click (15s): 0 (normal reading time)
  - UA Outlook: 0 (legitimate email client)
  + Human behavior: +25
  + Clicked link: +10

  Final Score: 95/100 → Genuine User ✅

Next time this IP opens email from company.com domain:
  - VPN (whitelisted): -15 (instead of -40)
  - Final Score: 100/100 ✅
```

### Example 2: Security Scanner vs Real User

```
Email: target@company.com

IP #1: 1.2.3.4 (Proofpoint Scanner)
  Timeline:
    10:00:00.000  Email Sent
    10:00:00.800  Email Opened (0.8s after send)
    10:00:01.200  Clicked Link (0.4s after open)

  Analysis:
    - Security scanner: -95
    - Instant open: -95
    - Instant click: -95
    - Bot UA: -70
    Score: 0/100 → Bot/Scanner 🤖

IP #2: 93.45.78.12 (Telecom Italia)
  Timeline:
    14:30:00  Email Opened (4.5h after send)
    14:30:22  Clicked Link (22s after open)

  Analysis:
    - Legitimate ISP: 0
    - Normal delays: 0
    - Browser UA: 0
    + Clicked: +10
    Score: 100/100 → Genuine User ✅

Final Result: ✅ Real user clicked (bot activity ignored)
```

### Example 3: Re-reading Email (Multiple Opens)

```
Email: alice@domain.com
IP: 151.18.45.67 (Vodafone IT)
User Agent: Apple Mail/16.0

Timeline:
  15:40:00  Email Sent
  17:20:00  Email Opened (100 min after send)
  17:22:00  Email Opened again (re-reading)
  17:25:30  Clicked Link (5.5 min after first open)

Analysis:
  - Legitimate ISP: 0
  - Send→Open (100 min): 0 (normal)
  - Multiple opens (2 min apart): 0 (re-reading behavior)
  - Open→Click (5.5 min): 0 (thinking/reading)
  - Email client UA: 0 (legitimate)
  + Clicked: +10

  Score: 100/100 → Genuine User ✅
```

## 📋 Requirements

- Python 3.8+
- pandas
- requests

See [requirements.txt](requirements.txt) for complete dependencies.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Documentation

- **[ALGORITHM.md](docs/ALGORITHM.md)** - Deep dive into detection methodology

## 🐛 Known Issues & Limitations

- **IP lookup** requires internet connection (uses ip-api.com)
- **Rate limiting**: ~45 requests/minute (free tier)
- **Whitelist persistence**: In-memory only (not saved between runs)
- **Regional optimization**: Currently tuned for Italian campaigns (easily configurable)

## 🗺️ Roadmap

- [ ] Persistent whitelist (JSON/DB storage)
- [ ] Multi-region configuration profiles
- [ ] Machine learning-based pattern detection
- [ ] REST API endpoint
- [ ] Docker container
- [ ] Real-time GoPhish integration
- [ ] Dashboard UI

## 🔧 Configuration

All thresholds are configurable in the source code:

```python
# Timing thresholds
BOT_SEND_TO_OPEN = 2           # <2s = bot scanner
SUSPICIOUS_SEND_TO_OPEN = 10   # 2-10s = suspicious
BOT_OPEN_TO_CLICK = 1          # <1s = bot
SUSPICIOUS_OPEN_TO_CLICK = 3   # 1-3s = suspicious
NORMAL_CLICK_RANGE = 30        # 3-30s = normal human

# Score thresholds
GENUINE_HUMAN_THRESHOLD = 70   # 70+ = genuine user
SUSPICIOUS_THRESHOLD = 40      # 40-69 = review
BOT_THRESHOLD = 40             # <40 = bot

# IP penalties
VPN_PENALTY = 40               # First-time VPN
VPN_WHITELISTED_PENALTY = 15   # Whitelisted VPN
CLOUD_PROVIDER_PENALTY = 80
SECURITY_SCANNER_PENALTY = 95
```

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

- GitHub: [@holygivaa](https://github.com/holygivaa)

## 🙏 Acknowledgments

- [GoPhish](https://getgophish.com/) - The awesome phishing framework
- [ip-api.com](https://ip-api.com/) - IP geolocation service
- Security research community

## ⚠️ Disclaimer

This tool is designed for legitimate security awareness training and authorized penetration testing only. Users are responsible for complying with applicable laws and regulations.

---

<div align="center">

Made with ❤️ by @Givaa

**"We erase what tries to replace us."**

If you find this tool useful, please consider giving it a ⭐

</div>
