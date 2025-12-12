# GoCheck Detection Algorithm

This document describes the **aggressive, high-confidence** methodology used by GoCheck to distinguish automated bot activity from genuine human interactions in GoPhish campaigns.

## Philosophy: "When in Doubt, It's a Bot"

### Why Aggressive Detection?

In **phishing awareness training**, the goal is to accurately measure human susceptibility to phishing attacks. False positives (counting bots as humans) completely invalidate campaign results by:

- Inflating success metrics with automated scanner activity
- Misrepresenting actual employee vulnerability
- Wasting training resources on non-existent issues
- Undermining trust in security metrics

**Therefore, GoCheck prioritizes precision over recall**: It's better to miss some edge-case humans than to count a single bot as a successful phishing attempt.

## Design Principles

1. **High bar for human classification** - Only clear, strong evidence results in "genuine human" status
2. **Strict thresholds** - Score ≥80 required for confirmed human
3. **Aggressive penalties** - Suspicious indicators receive harsh penalties
4. **No benefit of the doubt** - Ambiguous cases are classified as bots
5. **Multi-factor validation** - Multiple strong signals required for human classification

## Scoring System

Each IP group starts with a base score of **100 points**. Various factors apply penalties:

- **80-100 points**: ✅ **Confirmed genuine human** - Safe to count as campaign success
- **60-79 points**: ⚠️ **Likely human - review recommended** - Probable human but verify manually
- **40-59 points**: 🤖 **Suspicious - likely bot** - Do NOT count as success
- **0-39 points**: 🔴 **Definite bot/scanner** - Automated activity

### Key Difference from Typical Systems

Most detection systems use 70+ as "human". GoCheck requires **80+** for confirmed human status, with 60-79 marked for review. This ensures high confidence in human classifications.

## Detection Factors

### 1. IP Analysis (0-100 penalty)

The system performs geolocation and organization lookup for each IP address with **aggressive classification**.

#### Foreign IPs (-100 penalty)
Any IP outside Italy receives maximum penalty. This is configurable for different regions.

```python
if ip_info.get('countryCode') != 'IT':
    return False, 'foreign', 100, f"Foreign IP: {country}"
```

#### Security Vendors (-95 penalty)
Known security scanner IPs from vendors like:
- Proofpoint
- Mimecast
- Barracuda
- Microsoft Defender
- Cisco IronPort

#### Cloud Providers (-80 penalty)
IP ranges from:
- AWS
- Google Cloud
- Microsoft Azure
- DigitalOcean
- Hetzner

#### Datacenter/Hosting (-75 penalty)
Hosting providers and datacenters that commonly host scanning services.

#### VPN/Proxy (-70 penalty)
Detected through:
- Organization name keywords
- IP-API proxy flag
- Known VPN provider ranges

#### IP Lookup Failure (-60 penalty)
When IP geolocation fails or times out.

#### Unknown Type (-30 penalty)
IPs that resolve but don't match known categories.

#### Legitimate ISPs (0 penalty)
Residential and business ISPs from major telecom providers receive no penalty.

Examples: Telecom Italia, Vodafone, Wind Tre, Fastweb

### 2. Timing Analysis (0-95 penalty)

The system analyzes time intervals between consecutive events with **very strict thresholds**.

#### Sub-second timing (-95 penalty)
```
Email Opened → Clicked Link: 250ms
```
Events occurring within 1 second are **definitively automated**. No human can read and click that fast. This is an absolute bot signature.

#### 1-3 seconds (-80 penalty)
```
Email Opened → Clicked Link: 2.1s
```
Highly suspicious. Even if technically possible, legitimate users don't act this quickly. Likely automated.

#### 3-5 seconds (-65 penalty)
```
Email Opened → Clicked Link: 4.2s
```
Very fast behavior that's extremely unlikely for legitimate users reading email content.

#### 5-10 seconds (-45 penalty)
```
Email Opened → Clicked Link: 7.3s
```
Fast but technically plausible for a user who instantly recognizes a familiar link without reading.

#### 10-20 seconds (-20 penalty)
```
Email Opened → Clicked Link: 15.5s
```
Quick but reasonable for a short email. Minor penalty.

#### >30 seconds (0 penalty)
```
Email Opened → Clicked Link: 2m 15s
```
Normal human timing patterns. Users read emails before acting.

### 3. User Agent Analysis (0-85 penalty)

User agent strings are analyzed with **strict validation**.

#### Bot/Crawler Keywords (-85 penalty)
User agents containing:
- "bot", "crawler", "spider"
- "scan", "check", "monitor"
- "validation", "test", "probe"

Example: `Mozilla/5.0 SecurityBot/1.0`

#### Security Tool Keywords (-80 penalty)
User agents containing:
- "security", "protection", "safe"
- "sandbox", "analyzer", "scanner"

Example: `Mimecast-Security-Scanner/2.0`

#### Missing User Agent (-40 penalty)
No user agent provided suggests automated access or misconfigured client.

**Increased from -30 to -40**: Legitimate browsers always send user agents. Missing UA is highly suspicious.

#### Anomalous User Agent (-35 penalty)
User agent that doesn't match any known pattern.

#### Email Clients (-15 penalty)
Outlook, Thunderbird, Apple Mail receive minor penalty.

#### Standard Browsers (0 penalty)
Recognized browsers:
- Chrome, Firefox, Safari
- Edge, Opera

Example: `Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0`

Only standard, well-formed browser user agents receive no penalty.

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

1. **Aggressive accuracy**: Prioritizes precision over recall - better to miss edge cases than count bots
2. **High-confidence thresholds**: Score ≥80 required for "confirmed human" classification
3. **Multi-factor validation**: No single weak factor can override strong bot signals
4. **IP-based separation**: Distinguishes bot scanners from real users on same email
5. **Transparent scoring**: Each penalty is documented, auditable, and adjustable
6. **No ML required**: Deterministic, explainable rules that security teams can understand
7. **Conservative approach**: "When in doubt, it's a bot" philosophy protects metric integrity

## Limitations & Trade-offs

1. **False negatives acceptable**: Some legitimate users with VPNs or unusual patterns will be marked as bots
   - **Decision**: This is acceptable - better than counting bots as humans
   
2. **Regional specificity**: Currently optimized for Italian campaigns
   - **Solution**: Easily configurable for other regions
   
3. **VPN users penalized**: Legitimate VPN users receive heavy penalties
   - **Decision**: In corporate phishing training, VPN usage during email access is rare enough to be suspicious
   
4. **Shared IPs**: Multiple users behind same corporate gateway may be grouped
   - **Mitigation**: User agent and timing differences still distinguish individuals
   
5. **Sophisticated bots**: Advanced bots with human-like timing and residential proxies could evade detection
   - **Acceptance**: These are extremely rare and expensive; most phishing campaigns face basic scanners

## Philosophy vs Traditional Approaches

### Traditional "Conservative" Approach (BAD for phishing)
```
Score 70+ = Human ✓
In doubt? → Assume human
Goal: Don't miss any real users
```
**Problem**: Includes bots in success metrics, invalidates campaign results

### GoCheck "Aggressive" Approach (CORRECT for phishing)
```
Score 80+ = Confirmed human ✓
Score 60-79 = Review required ⚠️
Score <60 = Bot 🤖
In doubt? → Assume bot
Goal: Only count verified humans
```
**Benefit**: Accurate metrics, trustworthy campaign results, proper training focus

## Future Improvements

- Machine learning model for pattern recognition
- Behavioral fingerprinting beyond timing
- Browser automation detection (Selenium, Puppeteer)
- Historical pattern analysis
- Adaptive thresholds based on campaign type

## Configuration

All thresholds are configurable in the source code. **Current aggressive values:**

```python
# Timing thresholds (seconds)
DEFINITE_BOT_TIMING = 1      # <1s = definite bot
HIGHLY_SUSPICIOUS_TIMING = 3  # 1-3s = highly suspicious
VERY_FAST_TIMING = 5          # 3-5s = very fast (NEW)
FAST_TIMING = 10              # 5-10s = fast
QUICK_TIMING = 20             # 10-20s = quick
NORMAL_HUMAN_TIMING = 30      # >30s = normal human

# Score thresholds
CONFIRMED_HUMAN_THRESHOLD = 80  # Was 70 - now stricter
LIKELY_HUMAN_THRESHOLD = 60     # Was 40 - now stricter
SUSPICIOUS_THRESHOLD = 40       # Below this = definite bot

# IP penalties
SECURITY_SCANNER_PENALTY = 95   # Was 90
CLOUD_PROVIDER_PENALTY = 80     # Was 70
DATACENTER_PENALTY = 75         # Was 65
VPN_PENALTY = 70                # Was 60
UNKNOWN_IP_PENALTY = 60         # Was 50
IP_LOOKUP_FAILED_PENALTY = 60   # Was 50

# User Agent penalties
BOT_UA_PENALTY = 85             # Was 80
SECURITY_TOOL_UA_PENALTY = 80   # Was 70
MISSING_UA_PENALTY = 40         # Was 30
ANOMALOUS_UA_PENALTY = 35       # Was 25
EMAIL_CLIENT_PENALTY = 15       # Was 10

# Behavioral bonuses (reduced)
CLICKED_LINK_BONUS = 5          # Was 10
```

### Adjusting for Your Environment

**More aggressive (stricter):**
- Increase CONFIRMED_HUMAN_THRESHOLD to 85
- Increase penalties by 5-10 points
- Reduce CLICKED_LINK_BONUS to 0

**Less aggressive (more permissive):**
- Reduce CONFIRMED_HUMAN_THRESHOLD to 75
- Reduce penalties by 5-10 points
- Not recommended for phishing training

---

For questions or suggestions about the algorithm, please open an issue on GitHub.