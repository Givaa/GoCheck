# GoCheck 🎣

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

**Advanced bot detection for GoPhish phishing campaigns**

goCheck analyzes GoPhish campaign events to distinguish automated scanner activity from genuine human interactions. Stop counting bot clicks as successful phishing attempts and get accurate metrics on real user behavior.

<div align="center">
  <img src="docs/images/banner.png" alt="goCheck Banner" width="800"/>
</div>

## ✨ Features

- 🤖 **Intelligent Bot Detection** - Identifies security scanners, email gateways, and automated systems
- ⏱️ **Timing Analysis** - Detects millisecond-level automation patterns
- 🌍 **IP Intelligence** - Geolocation, ISP, and hosting provider classification
- 🔍 **Multi-IP Tracking** - Separates bot scans from real user clicks on the same email
- 📊 **Comprehensive Reports** - Clean CSV exports with human-only interactions
- 🎨 **Dark Mode GUI** - User-friendly interface with real-time analysis
- 💻 **CLI Tool** - Full-featured command-line interface for automation

## 🚀 Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/holygivaa/goCheck.git
cd goCheck

# Install dependencies
pip install -r requirements.txt

# Run analysis
python gocheck/analyzer.py -i raw_events.csv
```

## 📖 Usage

### Command Line Interface

```bash
# Basic analysis
python gocheck/analyzer.py -i events.csv

# Custom output directory
python gocheck/analyzer.py -i events.csv -o reports/

# Verbose mode
python gocheck/analyzer.py -i events.csv -v

# Show help
python gocheck/analyzer.py --help
```

### As a Python Module

```python
from gocheck import GoPhishAnalyzer

analyzer = GoPhishAnalyzer('raw_events.csv')
results = analyzer.analyze_campaign()
human_report = analyzer.generate_human_report(results)
```

## 🎯 How It Works

goCheck uses a multi-factor scoring system to classify each IP interaction:

### Detection Factors

1. **IP Analysis** (0-90 penalty)
   - Cloud providers (AWS, Azure, GCP)
   - Security vendors (Proofpoint, Mimecast, Barracuda)
   - VPN/Proxy detection
   - Geographic filtering

2. **Timing Analysis** (0-90 penalty)
   - Sub-second events = automation
   - Millisecond patterns = bot signatures
   - Human-like delays = legitimate user

3. **User Agent Analysis** (0-80 penalty)
   - Bot/crawler signatures
   - Security tool identifiers
   - Standard browser fingerprints

4. **Behavioral Patterns** (+/- 10-20)
   - Click-through behavior
   - Multi-stage interactions
   - Consistency checks

### Scoring System

- **70-100**: Genuine human user ✅
- **40-69**: Suspicious, requires review ⚠️
- **0-39**: Bot/scanner detected 🤖

## 📊 Output Reports

### Human Users Report (`human_users_report.csv`)

| email | human_opened | human_clicked | human_score | human_ip |
|-------|--------------|---------------|-------------|----------|
| user@company.com | YES | YES | 85 | 151.18.45.123 |
| admin@company.com | YES | NO | 78 | 93.45.123.87 |
| bot@company.com | NO | NO | 0 | N/A |

### Complete Analysis (`complete_campaign_analysis.csv`)

Detailed breakdown of every IP interaction with classifications, scores, and event timelines.

## 🔬 Real-World Example

**Scenario:** Email security gateway opens email in 250ms, then real user clicks 2 hours later.

```
Email: john.doe@company.com

IP #1: 52.18.134.87 (AWS) - Bot/Scanner
  Score: 20/100
  Events: Email Opened, Clicked Link
  Timing: 250ms between events
  Classification: Security scanner detected

IP #2: 151.18.45.123 (Telecom Italia) - Genuine User
  Score: 85/100
  Events: Email Opened, Clicked Link
  Timing: 5m 32s between events
  Classification: Real user interaction

Final Result: ✅ User clicked (despite bot scanner activity)
```

### Code Style

```bash
# Format code
black gocheck/

# Lint
flake8 gocheck/
```

## 📋 Requirements

- Python 3.8+
- pandas
- requests

See `requirements.txt` for complete dependencies.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📝 Algorithm Details

For a deep dive into the detection algorithms and scoring methodology, see [ALGORITHM.md](docs/ALGORITHM.md).

## 🐛 Known Issues

- IP lookup requires internet connection
- Rate limited to ~45 requests/minute (ip-api.com free tier)
- Currently optimized for Italian campaigns (easily configurable)

## 🗺️ Roadmap

- [ ] Go version for GoPhish integration
- [ ] Support for additional IP lookup providers
- [ ] Machine learning-based detection
- [ ] REST API endpoint
- [ ] Docker container
- [ ] Multi-language support

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**@Givaa**

- GitHub: [@Givaa](https://github.com/Givaa)

## 🙏 Acknowledgments

- [GoPhish](https://getgophish.com/) - The awesome phishing framework
- [ip-api.com](https://ip-api.com/) - IP geolocation service
- Security research community

## ⚠️ Disclaimer

This tool is designed for legitimate security awareness training and penetration testing with proper authorization. Users are responsible for complying with applicable laws and regulations.

---

<div align="center">
  Made with ❤️ by @Givaa
  
  If you find this tool useful, please consider giving it a ⭐
</div>
