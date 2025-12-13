# GoCheck Detection Algorithm

This document describes the **intelligent, adaptive** methodology used by GoCheck to distinguish automated bot activity from genuine human interactions in GoPhish campaigns.

## Philosophy: "Smart Detection, Not Aggressive Rejection"

### Why Intelligent Detection?

In **phishing awareness training**, the goal is to accurately measure human susceptibility to phishing attacks while avoiding false positives that flag legitimate users as bots. The challenge is distinguishing between:

- **Security scanners** (immediate, automated, cloud-based)
- **VPN users** (legitimate employees accessing email through corporate gateways)
- **Email clients** (Outlook, Apple Mail opening links)
- **Real human behavior** (variable timing, legitimate ISPs)

**GoCheck's approach**: Use context-aware scoring with dynamic whitelisting to adapt to legitimate enterprise patterns while catching actual bots.

## Design Principles

1. **Context-aware classification** - VPN behavior is evaluated based on timing and domain patterns
2. **Dynamic whitelisting** - Learn which IPs are legitimate for specific email domains (persisted to JSON)
3. **Timing intelligence** - Distinguish send→open (hours) from open→click (seconds), uses LAST open before click
4. **Email client support** - Recognize legitimate email client access patterns
5. **Multi-factor validation** - Multiple signals combine for accurate classification
6. **Event deduplication** - Remove duplicate events (same IP+message within 2 seconds)
7. **Robust error handling** - Structured logging, proper exception handling, rate limit management
8. **Configurable constants** - All thresholds and penalties defined as named constants

## Scoring System

Each IP group starts with a base score of **100 points**. Various factors apply penalties and bonuses:

- **70-100 points**: ✅ **Genuine human** - Legitimate user interaction
- **40-69 points**: ⚠️ **Suspicious** - Review recommended
- **0-39 points**: 🤖 **Bot/Scanner** - Automated activity

## Detection Factors

## Event Processing Pipeline

Before analysis begins, events undergo preprocessing:

### Event Deduplication

GoCheck removes duplicate events that occur within a short time window to avoid skewing the analysis:

```python
DUPLICATE_EVENT_WINDOW = 2  # seconds

# Deduplication criteria (all must match):
1. Same email address
2. Same IP address
3. Same event type (opened/clicked)
4. Within 2 seconds of each other
```

**Example:**
```
15:40:00.123  user@company.com  192.168.1.1  opened  → KEPT
15:40:01.456  user@company.com  192.168.1.1  opened  → REMOVED (duplicate within 2s)
15:40:30.789  user@company.com  192.168.1.1  opened  → KEPT (>2s gap, legitimate re-open)
```

**What is NOT removed:**
- Different IPs (multi-device access)
- Different event types (open vs click)
- Events >2 seconds apart (legitimate re-reading)

This ensures that:
✅ Rapid bot re-scanning is filtered out
✅ Legitimate human re-reading is preserved
✅ Multi-IP scenarios are fully analyzed

## Detection Factors

### 1. IP Analysis (0-100 penalty)

The system performs geolocation and organization lookup with **intelligent classification**.

**Configuration constants:**
```python
SECURITY_SCANNER_PENALTY = 95
CLOUD_PROVIDER_PENALTY = 80
DATACENTER_PENALTY = 75
VPN_PENALTY = 40
VPN_WHITELISTED_PENALTY = 15
IP_LOOKUP_FAILED_PENALTY = 60
UNKNOWN_IP_PENALTY = 30
FOREIGN_IP_PENALTY = 100
```

#### Foreign IPs (-100 penalty)
IPs outside allowed countries receive maximum penalty (configurable via `--countries` flag).

```python
# Default: Italy only
allowed_countries = ['IT']

# Multi-country support
allowed_countries = ['IT', 'US', 'GB']

if ip_info.get('countryCode') not in self.allowed_countries:
    return False, 'foreign', FOREIGN_IP_PENALTY, f"Foreign IP: {country}"
```

#### Security Vendors (-95 penalty)
Known security scanner IPs from:
- Proofpoint, Mimecast, Barracuda
- Microsoft Defender, Cisco IronPort
- Sophos, Fortinet, Trend Micro

#### Cloud Providers (-80 penalty)
IP ranges from:
- AWS, Google Cloud, Microsoft Azure
- DigitalOcean, Hetzner, OVH
- Linode, Vultr, Scaleway

#### Datacenter/Hosting (-75 penalty)
Hosting providers commonly used by scanning services.

#### VPN/Proxy (40 penalty, adaptive)

**New intelligent approach:**

**First-time VPN**: -40 points (moderate penalty)
```python
if 'vpn' in combined or 'proxy' in combined:
    return True, 'vpn', 40, "VPN/Proxy (pending validation)"
```

**Whitelisted VPN**: -15 points only
```python
if self._is_ip_whitelisted(ip, email_domain):
    return True, 'vpn_whitelisted', 15, f"VPN/Proxy (whitelisted for {email_domain})"
```

**VPN with human behavior**: +25 bonus
```python
if ip_type == 'vpn' and not is_bot_timing and score >= 50:
    score += 25  # Reward human-like behavior from VPN
```

**Whitelisting criteria:**
- IP seen ≥2 times for same domain
- Consistent human-like behavior (timing, UA, clicks)
- More human behaviors than bot behaviors

**Example:**
```
mail.com users → 126.12.4.21 (Corporate Outlook VPN)
First time:  -40 penalty, but +25 human behavior = 85/100 ✓
Second time: -15 penalty (whitelisted) = 95/100 ✓
```

#### Unknown Type (-30 penalty)
IPs that resolve but don't match known categories.

#### Legitimate ISPs (0 penalty)
Residential and business ISPs from major telecom providers.

Examples: Telecom Italia, Vodafone, Wind Tre, Fastweb

### 2. Timing Analysis (0-95 penalty)

**Key innovations**:
1. Separate analysis for **send→open** vs **open→click**
2. Uses **LAST open before click** (not first) to accurately measure reading time

**Configuration constants:**
```python
BOT_SEND_TO_OPEN = 2           # <2s = bot scanner
SUSPICIOUS_SEND_TO_OPEN = 10   # 2-10s = suspicious
BOT_OPEN_TO_CLICK = 1          # <1s = bot
SUSPICIOUS_OPEN_TO_CLICK = 3   # 1-3s = suspicious
NORMAL_CLICK_RANGE = 30        # 3-30s = normal human
MULTIPLE_OPEN_BOT = 2          # <2s between opens = bot
```

#### Send → Open Timing

**Humans open emails hours after receiving them:**

```python
if sent_time and events_list[0]['message'] == EVENT_OPENED:
    send_to_open = (events_list[0]['time'] - sent_time).total_seconds()

    if send_to_open < 2:      # Scanner opens immediately
        penalty = 95 (BOT)
    elif send_to_open < 10:   # Very fast, suspicious
        penalty = 70 (SUSPICIOUS)
    else:                      # Normal human delay
        penalty = 0 (NORMAL)
```

**Examples:**
```
15:40 sent → 15:40:01 opened = BOT (1s)
15:40 sent → 15:40:08 opened = Suspicious (8s)
15:40 sent → 17:20 opened   = Normal human (100 minutes) ✓
```

#### Open → Click Timing

**Humans read before clicking (3-30s typical):**

**IMPORTANT**: GoCheck uses the **LAST open before click**, not the first open. This correctly measures the actual reading time.

```python
# Find LAST open before click
last_open_before_click = None
for event in reversed(events_list):
    if event['time'] < click_time and event['message'] == EVENT_OPENED:
        last_open_before_click = event
        break

if event1 == EVENT_OPENED and event2 == EVENT_CLICKED:
    if time_diff < BOT_OPEN_TO_CLICK:           # <1s = Instant click
        penalty = 95 (BOT)
    elif time_diff < SUSPICIOUS_OPEN_TO_CLICK:  # 1-3s = Very fast
        penalty = 60 (SUSPICIOUS)
    elif time_diff <= NORMAL_CLICK_RANGE:       # 3-30s = Normal human range
        penalty = 0 (NORMAL)
    else:                                        # >30s = Re-reading email
        penalty = 0 (NORMAL)
```

**Examples:**
```
Opened → 0.5s → Clicked  = BOT
Opened → 2s → Clicked    = Suspicious
Opened → 15s → Clicked   = Normal human ✓
Opened → 2min → Clicked  = Re-reading email ✓
```

#### Multiple Opens (re-reading)

```python
if event1 == EVENT_OPENED and event2 == EVENT_OPENED:
    if time_diff < 2:         # Rapid re-opens
        penalty = 80 (BOT)
    else:                      # Human re-reading
        penalty = 0 (NORMAL)
```

**Example:**
```
Test scenario: Email sent 15:40, opened 17:20, opened again 17:22, opened 17:24
Result: Normal human behavior (re-reading) ✓
```

### 3. User Agent Analysis (0-80 penalty)

**Improved email client recognition:**

**Configuration constants:**
```python
BOT_UA_PENALTY = 80            # Bot/crawler keywords
SECURITY_TOOL_UA_PENALTY = 70  # Security tool keywords
MISSING_UA_PENALTY = 30        # No user agent
ANOMALOUS_UA_PENALTY = 25      # Unknown user agent
EMAIL_CLIENT_PENALTY = 0       # Email clients (legitimate)
```

#### Bot/Crawler Keywords (-80 penalty)
User agents containing:
- "bot", "crawler", "spider"
- "scan", "check", "monitor"
- "validation", "test", "probe"

#### Security Tool Keywords (-70 penalty)
User agents containing:
- "security", "protection", "safe"
- "sandbox", "analyzer", "scanner"

#### Missing User Agent (-30 penalty)
No user agent suggests automated access.

#### Email Clients (0 penalty) ✅ NEW
**Legitimate access patterns:**
```python
if any(client in ua_lower for client in ['outlook', 'thunderbird', 'mail', 'msoffice', 'apple mail']):
    return 0, "Email client (legitimate)"
```

Outlook, Thunderbird, Apple Mail are now treated as legitimate human access.

#### Standard Browsers (0 penalty)
Chrome, Firefox, Safari, Edge, Opera

#### Anomalous User Agent (-25 penalty)
User agent that doesn't match known patterns.

### 4. Behavioral Patterns (Bonuses)

**Configuration constants:**
```python
CLICKED_LINK_BONUS = 10        # User clicked link
VPN_HUMAN_BEHAVIOR_BONUS = 25  # VPN with human behavior
```

#### Positive Signals
- **Clicked Link (+10)**: Shows continued engagement
- **VPN with human behavior (+25)**: VPN/proxy with human-like timing and score ≥50

## Dynamic Whitelist System

### How It Works

GoCheck learns which IPs are legitimate for specific email domains and **persists this knowledge** to a JSON file for future runs.

**Configuration constants:**
```python
WHITELIST_EXPIRY_DAYS = 90              # Expire old entries
WHITELIST_MIN_SCORE = 60                # Minimum score for whitelist
WHITELIST_MIN_INTERACTIONS = 2          # Minimum interactions for whitelist
WHITELIST_VARIANCE_THRESHOLD = 5.0      # Variance threshold for bot detection
```

**Data structure per IP:**
```python
# In-memory structure
ip_whitelist[ip] = {
    'domains': set(['mail.com', 'company.com']),
    'scores': [85, 90, 88],
    'human_behaviors': 5,
    'bot_behaviors': 0,
    'timing_samples': [12.3, 8.7, 15.2, 18.9],
    'first_seen': datetime(2025, 10, 15, 9, 0, 0),
    'last_seen': datetime(2025, 12, 12, 14, 30, 0)
}

# Persisted to JSON (whitelist.json)
{
  "192.168.100.50": {
    "domains": ["mail.com", "company.com"],
    "scores": [85, 90, 88],
    "human_behaviors": 5,
    "bot_behaviors": 0,
    "timing_samples": [12.3, 8.7, 15.2, 18.9],
    "first_seen": "2025-10-15T09:00:00",
    "last_seen": "2025-12-12T14:30:00"
  }
}
```

**Whitelist persistence:**
- Automatically loaded at startup from `whitelist.json` (or custom path via `--whitelist`)
- Automatically saved after analysis (unless `--no-auto-save` specified)
- Entries older than 90 days are automatically expired during save
- Manual control: `analyzer.save_whitelist()` / `analyzer.load_whitelist()`

### Whitelisting Process

1. **First interaction**: IP receives standard penalty (-40 for VPN)
2. **Behavior analysis**: Timing and actions evaluated
3. **Score calculation**: If score ≥60 and no bot timing → human-like
4. **Whitelist update**: Record behavior for this IP+domain pair
5. **Second interaction**: If ≥2 human behaviors for this domain → whitelisted
6. **Reduced penalty**: Whitelisted IPs get -15 instead of -40

### Whitelist Criteria

```python
def _is_ip_whitelisted(ip, email_domain):
    # Must have domain association
    if email_domain not in whitelist_entry['domains']:
        return False

    # Must have ≥2 human-like interactions
    if whitelist_entry['human_behaviors'] < WHITELIST_MIN_INTERACTIONS:
        return False

    # Human behaviors must outweigh bot behaviors
    if whitelist_entry['bot_behaviors'] > whitelist_entry['human_behaviors']:
        return False

    # CRITICAL: Variance check to detect bots with identical timing
    if len(whitelist_entry['timing_samples']) >= 3:
        try:
            variance = statistics.variance(whitelist_entry['timing_samples'])
            if variance < WHITELIST_VARIANCE_THRESHOLD:
                # All values identical = bot with fixed timing - REJECT
                logger.info(f"IP {ip} rejected: all timing values identical (bot)")
                return False
        except statistics.StatisticsError:
            # Error calculating variance = reject to be safe
            logger.info(f"IP {ip} rejected: variance calculation failed")
            return False

    return True
```

### Example: Corporate VPN Gateway

```
Company: ACME Corp
Domain: acme.com
VPN Gateway: 192.168.100.50 (Outlook server)

User 1: alice@acme.com
  - Opens from 192.168.100.50 (VPN)
  - Opened 2h after send
  - Clicked after 18s
  - Score: 100 - 40 (VPN) + 25 (human) + 10 (click) = 95 ✓
  - Whitelist updated: human_behaviors = 1

User 2: bob@acme.com
  - Opens from 192.168.100.50 (VPN)
  - Opened 1.5h after send
  - Clicked after 12s
  - Score: 100 - 40 (VPN) + 25 (human) + 10 (click) = 95 ✓
  - Whitelist updated: human_behaviors = 2
  - ✅ IP now whitelisted for acme.com

User 3: charlie@acme.com
  - Opens from 192.168.100.50 (VPN) ← Same IP
  - IP is whitelisted for acme.com
  - Penalty reduced: -15 instead of -40
  - Score: 100 - 15 + 25 + 10 = 120 (capped to 100) ✓
```

## Multi-IP Scenarios

A single email may have interactions from multiple IPs:

```
user@company.com
  IP 1: 52.18.134.87 (AWS) - Score: 5 (Bot)
  IP 2: 192.168.1.50 (VPN) - Score: 85 (Human)
```

### Classification Logic

1. **Separate analysis**: Each IP scored independently
2. **Bot identification**: IPs with score < 40 are bots
3. **Human identification**: IPs with score ≥ 70 are humans
4. **Final determination**: If ANY human IP exists → "human clicked"

## Real-World Examples

### Example 1: Corporate VPN Outlook

```
Email: john@company.com
IP: 172.16.0.50 (Corporate VPN)
UA: Microsoft Outlook/16.0

Timeline:
  09:00:00  Email Sent
  11:30:00  Email Opened (2.5h after send)
  11:30:15  Clicked Link (15s after open)

Analysis:
  Base: 100
  - VPN (first time): -40
  - Send→Open (2.5h): 0 (normal)
  - Open→Click (15s): 0 (normal human)
  - UA Outlook: 0 (legitimate)
  + Human behavior: +25
  + Clicked: +10
  = 95/100 → Genuine User ✓

Next time same IP+domain: whitelisted, only -15 penalty
```

### Example 2: Security Scanner

```
Email: target@company.com
IP: 1.2.3.4 (Proofpoint)
UA: ProofpointScanner/1.0

Timeline:
  10:00:00.000  Email Sent
  10:00:00.800  Email Opened (0.8s after send)
  10:00:01.200  Clicked Link (0.4s after open)

Analysis:
  Base: 100
  - Security scanner: -95
  - Send→Open (0.8s): -95 (instant bot)
  - Open→Click (0.4s): -95 (instant bot)
  - UA security tool: -70
  = 0/100 → Bot/Scanner ✓
```

### Example 3: Email Client Multiple Opens

```
Email: alice@domain.com
IP: 93.45.78.12 (Telecom Italia)
UA: Apple Mail/16.0

Timeline:
  15:40:00  Email Sent
  17:20:00  Email Opened (100min after send)
  17:22:00  Email Opened again (re-reading)
  17:25:30  Clicked Link (5.5min after first open)

Analysis:
  Base: 100
  - ISP Telecom: 0 (legitimate)
  - Send→Open (100min): 0 (normal)
  - Multiple opens (2min apart): 0 (re-reading)
  - Open→Click (5.5min): 0 (thinking/reading)
  - UA Apple Mail: 0 (legitimate)
  + Clicked: +10
  = 110 (capped to 100) → Genuine User ✓
```

### Example 4: Fast But Human

```
Email: bob@company.com
IP: 151.18.45.67 (Vodafone IT)
UA: Chrome/120.0

Timeline:
  14:00:00  Email Sent
  14:30:00  Email Opened (30min after send)
  14:30:05  Clicked Link (5s after open)

Analysis:
  Base: 100
  - ISP Vodafone: 0 (legitimate)
  - Send→Open (30min): 0 (normal)
  - Open→Click (5s): -40 (fast but not bot)
  - UA Chrome: 0 (legitimate)
  + Clicked: +10
  = 70/100 → Genuine User (borderline) ✓
```

## Algorithm Advantages

1. **Context-aware**: Distinguishes VPN gateways from cloud scanners
2. **Adaptive learning**: Whitelist system learns legitimate patterns and persists them
3. **Timing intelligence**: Separate send→open and open→click analysis, uses LAST open
4. **Email client support**: Recognizes legitimate email client access
5. **Multi-factor validation**: Combines IP, timing, UA, and behavior
6. **Transparent scoring**: Documented, auditable, adjustable rules via named constants
7. **Enterprise-friendly**: Handles corporate VPNs and email gateways
8. **Event deduplication**: Removes duplicate bot scans while preserving human re-reading
9. **Robust error handling**: Structured logging (verbose mode), proper exception handling
10. **Configurable**: Multi-country support, custom whitelist paths, auto-save options
11. **Whitelist security**: Variance analysis detects bots with fixed timing patterns
12. **Automatic maintenance**: Whitelist entries expire after 90 days

## Key Features

### Configuration & Code Quality
```
✅ All thresholds defined as named constants for easy tuning
✅ Structured logging with verbose mode control
✅ Proper exception handling throughout the codebase
✅ Intelligent rate limiting with automatic backoff
✅ Multi-country support via --countries flag
```

### Event Processing
```
✅ Event deduplication (same IP+message within 2s)
✅ Uses LAST open before click for accurate reading time measurement
✅ Preserves legitimate re-reading behavior while filtering bot scans
```

### Whitelist System
```
✅ Persistent storage (JSON file with auto-load/save)
✅ Automatic expiry (90 days old entries removed)
✅ Variance analysis to reject bots with identical timing patterns
✅ Domain-specific learning (IP whitelisted per email domain)
```

### Scoring & Analysis
```
✅ Raw score tracking (in addition to capped score)
✅ Adaptive VPN penalty (40 first time, 15 when whitelisted)
✅ Email clients recognized as legitimate (0 penalty)
✅ VPN human behavior bonus (+25 points)
✅ Multi-factor validation combining IP, timing, UA, and behavior
```

## Configuration

### Command Line Options

```bash
python gocheck/GoCheck.py -i events.csv [OPTIONS]

Options:
  -i, --input PATH              Input CSV file (required)
  -o, --output PATH             Output directory (default: current directory)
  -v, --verbose                 Enable detailed logging
  --countries CODE [CODE ...]   Allowed country codes (default: IT)
  --whitelist PATH              Whitelist JSON path (default: ./whitelist.json)
  --no-auto-save                Disable automatic whitelist saving
```

### Configuration Constants

All thresholds are defined as named constants at the top of the source code:

```python
# IP API Configuration
IP_API_FIELDS = 'status,message,country,countryCode,region,city,isp,org,as,mobile,proxy,hosting,query'
IP_API_RATE_LIMIT = 45         # Requests per minute (free tier)
IP_API_RATE_WINDOW = 60        # Time window in seconds

# Timing thresholds (seconds)
BOT_SEND_TO_OPEN = 2           # <2s = bot scanner
SUSPICIOUS_SEND_TO_OPEN = 10   # 2-10s = suspicious
BOT_OPEN_TO_CLICK = 1          # <1s = bot
SUSPICIOUS_OPEN_TO_CLICK = 3   # 1-3s = suspicious
NORMAL_CLICK_RANGE = 30        # 3-30s = normal human
MULTIPLE_OPEN_BOT = 2          # <2s between opens = bot
DUPLICATE_EVENT_WINDOW = 2     # Events within 2s considered duplicates

# Score thresholds
GENUINE_HUMAN_THRESHOLD = 70   # 70+ = genuine user
SUSPICIOUS_THRESHOLD = 40      # 40-69 = review
BOT_THRESHOLD = 40             # <40 = bot

# IP classification penalties
SECURITY_SCANNER_PENALTY = 95  # Proofpoint, Mimecast, etc.
CLOUD_PROVIDER_PENALTY = 80    # AWS, Azure, GCP
DATACENTER_PENALTY = 75        # Hosting providers
VPN_PENALTY = 40               # First-time VPN/proxy
VPN_WHITELISTED_PENALTY = 15   # Whitelisted VPN/proxy
IP_LOOKUP_FAILED_PENALTY = 60  # IP lookup failed
UNKNOWN_IP_PENALTY = 30        # Unknown IP type
FOREIGN_IP_PENALTY = 100       # Outside allowed countries

# User Agent penalties
BOT_UA_PENALTY = 80            # Bot/crawler/spider keywords
SECURITY_TOOL_UA_PENALTY = 70  # Security scanner keywords
MISSING_UA_PENALTY = 30        # No user agent provided
ANOMALOUS_UA_PENALTY = 25      # Unrecognized user agent
EMAIL_CLIENT_PENALTY = 0       # Email clients (Outlook, Apple Mail, etc.)

# Behavioral bonuses
CLICKED_LINK_BONUS = 10        # User clicked link
VPN_HUMAN_BEHAVIOR_BONUS = 25  # VPN with human-like behavior

# Whitelist configuration
WHITELIST_EXPIRY_DAYS = 90              # Expire entries older than 90 days
WHITELIST_MIN_SCORE = 60                # Minimum score to be added to whitelist
WHITELIST_MIN_INTERACTIONS = 2          # Minimum interactions to activate whitelist
WHITELIST_VARIANCE_THRESHOLD = 5.0      # Min variance for timing (detect bots)
```

## Limitations & Trade-offs

1. **Requires ≥2 interactions**: First VPN user gets higher penalty (necessary for learning)
2. **Domain-specific**: Whitelist tied to email domain (by design for security)
3. **Learning phase**: First campaign may have higher VPN penalties (improves over time)
4. **IP lookup dependency**: Requires internet connection to ip-api.com
5. **Rate limiting**: 45 requests/minute (free tier) - managed automatically with backoff
6. **Whitelist decay**: Entries expire after 90 days (prevents stale data)

## Future Improvements

- Machine learning pattern recognition
- Browser fingerprinting
- Historical trend analysis
- Per-campaign threshold overrides (currently global)
- Real-time GoPhish API integration
- Dashboard UI for visualization
- Export to SIEM formats
- Custom IP classification rules
- Geofencing policies

---

For questions or suggestions, please open an issue on GitHub.
