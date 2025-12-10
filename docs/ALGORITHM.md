# GoCheck Detection Algorithm

This document describes the methodology used by GoCheck to distinguish automated bot activity from genuine human interactions in GoPhish campaigns.

## Overview

GoCheck uses a **multi-factor scoring system** that analyzes each IP interaction independently, then aggregates results per email target. The system is designed to be conservative: when in doubt, it favors classifying activity as human to avoid false negatives.

## Scoring System

Each IP group starts with a base score of **100 points**. Various factors apply penalties, with the final score determining classification:

- **70-100 points**: Genuine human user ✅
- **40-69 points**: Suspicious, requires review ⚠️
- **0-39 points**: Bot/scanner detected 🤖

## Detection Factors

### 1. IP Analysis (0-100 penalty)

The system performs geolocation and organization lookup for each IP address.

#### Foreign IPs (-100 penalty)
Any IP outside Italy receives maximum penalty. This is configurable for different regions.

```python
if ip_info.get('countryCode') != 'IT':
    return False, 'foreign', 100, f"Foreign IP: {country}"
```

#### Security Vendors (-90 penalty)
Known security scanner IPs from vendors like:
- Proofpoint
- Mimecast
- Barracuda
- Microsoft Defender
- Cisco IronPort

These are almost always automated email gateway scanners.

#### Cloud Providers (-70 penalty)
IP ranges from:
- AWS
- Google Cloud
- Microsoft Azure
- DigitalOcean
- Hetzner

Cloud IPs are commonly used for automated scanning infrastructure.

#### VPN/Proxy (-60 penalty)
Detected through:
- Organization name keywords
- IP-API proxy flag
- Known VPN provider ranges

#### Datacenter/Hosting (-65 penalty)
Hosting providers and datacenters that commonly host scanning services.

#### Legitimate ISPs (0 penalty)
Residential and business ISPs from major telecom providers receive no penalty.

### 2. Timing Analysis (0-90 penalty)

The system analyzes time intervals between consecutive events from the same IP.

#### Sub-second timing (-90 penalty)
```
Email Opened → Clicked Link: 250ms
```
Events occurring within 1 second are **definitively automated**. No human can click that fast.

#### 1-3 seconds (-70 penalty)
```
Email Opened → Clicked Link: 2.1s
```
Highly suspicious. While technically possible, legitimate users rarely act this quickly.

#### 3-10 seconds (-50 penalty)
```
Email Opened → Clicked Link: 7.3s
```
Fast but plausible. Could be automated or a very quick user.

#### 10-30 seconds (-25 penalty)
```
Email Opened → Clicked Link: 18.5s
```
Moderate timing. More likely human but still somewhat fast.

#### >30 seconds (0 penalty)
```
Email Opened → Clicked Link: 2m 15s
```
Normal human timing patterns.

### 3. User Agent Analysis (0-80 penalty)

#### Bot/Crawler Keywords (-80 penalty)
User agents containing:
- "bot", "crawler", "spider"
- "scan", "check", "monitor"
- "validation", "test", "probe"

Example: `Mozilla/5.0 SecurityBot/1.0`

#### Security Tool Keywords (-70 penalty)
User agents containing:
- "security", "protection", "safe"
- "sandbox", "analyzer", "scanner"

Example: `Mimecast-Security-Scanner/2.0`

#### Standard Browsers (0 penalty)
Recognized browsers:
- Chrome, Firefox, Safari
- Edge, Opera

Example: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0`

#### Email Clients (-10 penalty)
Outlook, Thunderbird, Apple Mail - slight penalty as some automated systems use these identifiers.

#### Missing User Agent (-30 penalty)
No user agent provided suggests automated access.

### 4. Behavioral Patterns (+/- 10-20 points)

#### Positive Signals
- **Clicked Link (+10)**: Shows continued engagement
- User demonstrates multi-step interaction patterns

#### Negative Signals
- **No activity after opening**: Possible automated scan

## Multi-IP Scenarios

A single email target may have interactions from multiple IPs:

```
user@company.com
  IP 1: 52.18.134.87 (AWS) - Score: 10 (Bot)
  IP 2: 151.18.45.123 (Telecom) - Score: 85 (Human)
```

### Classification Logic

1. **Separate analysis**: Each IP is scored independently
2. **Bot identification**: IPs with score < 40 are classified as bots
3. **Human identification**: IPs with score ≥ 70 are classified as humans
4. **Final determination**: If ANY human IP exists, the email is marked as "human clicked"

This approach ensures that legitimate user clicks are counted even when security scanners also accessed the email.

## Real-World Example

### Scenario: Security Gateway + Real User

```
Timeline for john.doe@company.com:

09:15:23.000  Email Sent
09:15:23.250  Email Opened    IP: 52.18.134.87 (AWS)
09:15:23.480  Clicked Link    IP: 52.18.134.87 (AWS)
11:30:15.000  Email Opened    IP: 151.18.45.123 (Telecom Italia)
11:35:22.000  Clicked Link    IP: 151.18.45.123 (Telecom Italia)
```

### Analysis

**IP Group 1: 52.18.134.87**
- Organization: Amazon AWS (-70)
- Timing: 230ms between events (-90)
- User Agent: "SecurityBot/1.0" (-80)
- **Final Score: 0/100** → Bot/Scanner

**IP Group 2: 151.18.45.123**
- Organization: Telecom Italia (0)
- Timing: 5m 7s average (0)
- User Agent: Chrome/120 (0)
- Behavior: Clicked link (+10)
- **Final Score: 85/100** → Genuine User

**Campaign Result**: ✅ **Real user clicked** (despite bot scanner activity)

## Algorithm Advantages

1. **Conservative approach**: Prefers false positives (marking bots as humans) over false negatives
2. **Multi-factor analysis**: No single factor dominates; combined evidence required
3. **IP separation**: Distinguishes multiple actors on same email
4. **Transparent scoring**: Each penalty is documented and adjustable
5. **No machine learning required**: Deterministic, explainable rules

## Limitations

1. **Sophisticated bots**: Very advanced bots mimicking human timing could evade detection
2. **VPN users**: Legitimate users on VPNs receive penalties
3. **Shared IPs**: Multiple users behind same corporate gateway may be grouped
4. **Regional focus**: Currently optimized for Italian campaigns (easily adjusted)

## Future Improvements

- Machine learning model for pattern recognition
- Behavioral fingerprinting beyond timing
- Browser automation detection (Selenium, Puppeteer)
- Historical pattern analysis
- Adaptive thresholds based on campaign type

## Configuration

All thresholds are configurable in the source code:

```python
# Timing thresholds (seconds)
BOT_TIMING_THRESHOLD = 1
SUSPICIOUS_TIMING_THRESHOLD = 3
FAST_TIMING_THRESHOLD = 10

# Score thresholds
GENUINE_USER_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40
```

---

For questions or suggestions about the algorithm, please open an issue on GitHub.