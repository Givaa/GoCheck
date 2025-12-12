"""
GoPhish Campaign Analyzer
Analyzes phishing campaign events to distinguish automated activity from genuine human interactions.
Supports all GoPhish event types and data formats.

Author: @Givaa
"""

import pandas as pd
import requests
import json
from datetime import datetime, timedelta
from collections import defaultdict
import time
import argparse
import sys
import os
import statistics
import random

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BLACK = '\033[30m'

# Human vs Machine quotes - hacker culture
HACKER_QUOTES = [
    "We erase what tries to replace us.",
    "In a world of algorithms, human intuition is the ultimate exploit.",
    "Machines learn patterns. Humans break them.",
    "They automate. We investigate. We win.",
    "Every bot leaves a signature. Every human leaves chaos.",
    "The difference between 0.8s and 8s? Humanity.",
    "Artificial intelligence vs actual intelligence. Place your bets.",
    "Bots follow rules. Humans write new ones.",
    "Security scanners think in milliseconds. We think in context.",
    "Machine precision meets human unpredictability. Game over.",
    "They optimize for speed. We optimize for truth.",
    "In the battle of bits vs bytes, we're the compiler.",
    "Automated threats require manual genius.",
    "Silicon logic cannot simulate human curiosity.",
    "We don't detect bots. We expose them."
]

def print_banner():
    """Print GoCheck banner with random hacker quote."""
    quote = random.choice(HACKER_QUOTES)

    banner = f"""
{Colors.BLACK}{Colors.BOLD}

 ▗▄▄▖ ▄▄▄   ▗▄▄▖▐▌   ▗▞▀▚▖▗▞▀▘█  ▄
▐▌   █   █ ▐▌   ▐▌   ▐▛▀▀▘▝▚▄▖█▄▀       {Colors.BLACK}"{quote}"{Colors.ENDC}{Colors.BLACK}{Colors.BOLD}
▐▌▝▜▌▀▄▄▄▀ ▐▌   ▐▛▀▚▖▝▚▄▄▖    █ ▀▄      Author: @Givaa
▝▚▄▞▘      ▝▚▄▄▖▐▌ ▐▌         █  █

{Colors.ENDC}
    """
    print(banner)

class GoPhishAnalyzer:
    # GoPhish supported events
    EVENT_SENT = 'Email Sent'
    EVENT_OPENED = 'Email Opened'
    EVENT_CLICKED = 'Clicked Link'
    EVENT_SUBMITTED = 'Submitted Data'
    EVENT_REPORTED = 'Email Reported'
    EVENT_ERROR = 'Error Sending Email'
    EVENT_PROXY = 'Proxied request'

    def __init__(self, csv_path):
        """
        Initialize analyzer with GoPhish events CSV file.

        Args:
            csv_path: Path to raw events CSV file exported from GoPhish
        """
        self.df = pd.read_csv(
            csv_path,
            names=['campaign', 'email', 'time', 'message', 'details'],
            skiprows=1
        )
        self.df['time'] = pd.to_datetime(self.df['time'], format='mixed')

        # Store original df with SENT events for timing analysis
        self.df_with_sent = self.df.copy()

        # Filter out events not relevant for behavioral analysis
        self.df = self.df[~self.df['message'].isin([
            self.EVENT_SENT,
            self.EVENT_ERROR,
            self.EVENT_PROXY
        ])]

        # Dynamic whitelist: IP -> {domains, behavior_scores, first_seen, last_seen, timing_variance}
        self.ip_whitelist = defaultdict(lambda: {
            'domains': set(),
            'scores': [],
            'human_behaviors': 0,
            'bot_behaviors': 0,
            'timing_samples': [],
            'first_seen': None,
            'last_seen': None
        })
        
        # Suspicious IP detection configuration
        self.cloud_providers = [
            # AWS
            'amazon', 'aws', 'amazonses', 'amazon technologies',
            'amazon data services', 'amazon.com',
            # Google Cloud
            'google', 'google llc', 'google cloud', 'google compute engine',
            # Microsoft Azure
            'microsoft', 'azure', 'microsoft corporation', 'microsoft azure',
            # Oracle / IBM / Alibaba
            'oracle cloud', 'oracle corporation',
            'ibm cloud', 'ibm corporation',
            'alibaba', 'alibaba cloud', 'alicloud',
            'tencent cloud', 'tencent',
            # OVH / Hetzner / Linode / DO / Vultr
            'ovh', 'ovh sas', 'ovhcloud',
            'hetzner', 'hetzner online', 'hetzner online gmbh',
            'linode', 'akamai linode', 'linode llc',
            'digitalocean', 'digitalocean llc',
            'vultr', 'choopa', 'constant', 'the constant company',
            # Aruba / Ionos / Leaseweb
            'aruba', 'aruba spa',
            'ionos', '1&1', '1 and 1', '1and1',
            'leaseweb', 'leaseweb net', 'leaseweb usa',
            # Contabo / Scaleway / M247
            'contabo', 'contabo gmbh',
            'scaleway', 'iliad', 'online sas',
            'm247', 'm247 ltd',
            # Fastly / Cloudflare / Akamai
            'cloudflare', 'cloudflare inc',
            'fastly', 'fastly inc',
            'akamai', 'akamai technologies',
            # Italian telecom (datacenter)
            'seeweb', 'seeweb s.r.l.',
            'keliweb', 'serverplan', 'nautilus', 'sparkle',
        ]

        self.security_vendors = [
            # Proofpoint
            'proofpoint', 'proofpoint inc',
            # Mimecast
            'mimecast', 'mimecast services limited',
            # Barracuda
            'barracuda', 'barracuda networks inc', 'barracuda networks',
            # Cisco / Ironport / Talos
            'cisco', 'cisco systems', 'ironport', 'talos',
            # Sophos / Fortinet / Trend Micro / McAfee
            'sophos', 'sophos ltd',
            'fortinet', 'fortinet inc',
            'trend micro', 'trend micro inc',
            'mcafee', 'mcafee inc', 'intel security',
            # Microsoft ATP / Defender
            'microsoft defender', 'ms-atp', 'office 365 atp',
            'exchange online protection', 'eop',
            # Palo Alto Networks
            'palo alto', 'palo alto networks',
            # Check Point / Forcepoint
            'check point', 'checkpoint software',
            'forcepoint', 'forcepoint llc',
            # Google Safe Browsing / URL scanner
            'google cloud security scanner',
            'google safe browsing',
            # Zscaler / Netskope / Bluecoat
            'zscaler', 'zscaler inc',
            'netskope', 'netskope inc',
            'bluecoat', 'blue coat', 'broadcom (blue coat)',
            # Crowdstrike / FireEye
            'crowdstrike', 'crowdstrike inc',
            'fireeye', 'mandiant',
            # Proofpoint TAP / Sandbox
            'tap email security', 'proofpoint threat',
        ]
        
        self.ip_cache = {}
        
    def parse_details(self, details_str):
        """
        Extract data from JSON details field.
        Supports both browser and payload formats.
        """
        if pd.isna(details_str) or details_str == '':
            return {}
        try:
            data = json.loads(details_str)
            return data if isinstance(data, dict) else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def extract_ip_and_ua(self, event):
        """
        Extract IP and User Agent from event.
        Handles both 'browser' and 'payload.browser' structures.
        """
        details = self.parse_details(event['details'])
        ip = None
        user_agent = None
        
        # Look in browser (standard)
        if isinstance(details.get('browser'), dict):
            ip = details['browser'].get('address')
            user_agent = details['browser'].get('user-agent')
        
        # Look in payload.browser (submitted data)
        elif isinstance(details.get('payload'), dict):
            payload = details['payload']
            if isinstance(payload.get('browser'), dict):
                ip = payload['browser'].get('address')
                user_agent = payload['browser'].get('user-agent')
        
        return ip, user_agent
    
    def get_ip_info(self, ip):
        """
        Get geolocation and ISP information for an IP.
        Uses cache to reduce API calls.
        """
        if not ip or ip == '':
            return None
            
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}?fields=16969727', timeout=5)
            if response.status_code == 200:
                data = response.json()
                self.ip_cache[ip] = data
                time.sleep(1.5)  # Rate limiting
                return data
        except Exception:
            pass
        
        return None
    
    def classify_ip(self, ip_info, email_domain=None, ip=None):
        """
        Classify IP type and calculate penalty for scoring.
        Now considers whitelisting for VPNs that show consistent human behavior.

        Returns:
            tuple: (is_italian, ip_type, penalty, description)
        """
        if not ip_info or ip_info.get('status') == 'fail':
            return None, 'unknown', 30, "IP lookup failed - insufficient data"

        is_italian = ip_info.get('countryCode') == 'IT'
        country = ip_info.get('country', 'Unknown')

        if not is_italian:
            return False, 'foreign', 100, f"Foreign IP: {country}"

        org = ip_info.get('org', '').lower()
        isp = ip_info.get('isp', '').lower()
        as_name = ip_info.get('as', '').lower()
        proxy = ip_info.get('proxy', '')
        hosting = ip_info.get('hosting', '')
        combined = f"{org} {isp} {as_name}"

        # Security vendor (definite bot)
        if any(vendor in combined for vendor in self.security_vendors):
            return True, 'security_scanner', 95, f"Security scanner: {org}"

        # Cloud provider (very likely bot)
        if any(provider in combined for provider in self.cloud_providers):
            return True, 'cloud', 80, f"Cloud provider: {org}"

        # VPN/Proxy - check whitelist first
        if 'vpn' in combined or 'proxy' in combined or proxy == True:
            # Check if this IP is whitelisted for this domain
            if ip and email_domain and self._is_ip_whitelisted(ip, email_domain):
                return True, 'vpn_whitelisted', 15, f"VPN/Proxy (whitelisted for {email_domain})"
            # Not whitelisted yet, apply moderate penalty (will be reduced if behavior is human-like)
            return True, 'vpn', 40, "VPN/Proxy (pending validation)"

        # Datacenter/Hosting (likely automated)
        if any(term in combined for term in ['datacenter', 'hosting', 'server']) or hosting == True:
            return True, 'datacenter', 75, "Datacenter"

        # Legitimate business/residential ISP
        if ip_info.get('isp'):
            return True, 'legitimate_isp', 0, f"ISP: {ip_info.get('isp')}"

        return True, 'unknown', 30, "Unknown type - suspicious"
    
    def analyze_user_agent(self, user_agent):
        """
        Analyze User Agent to detect bots/scanners.
        Email clients are now treated as legitimate human access patterns.

        Returns:
            tuple: (penalty, description)
        """
        if not user_agent or user_agent == '':
            return 30, "User Agent missing"

        ua_lower = user_agent.lower()

        # Bot keywords
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scan', 'check', 'monitor',
            'validation', 'test', 'probe', 'fetch'
        ]
        if any(indicator in ua_lower for indicator in bot_indicators):
            return 80, "Bot/Crawler detected"

        # Security tools
        security_indicators = [
            'security', 'protection', 'safe', 'guard', 'threat',
            'sandbox', 'analyzer', 'scanner'
        ]
        if any(indicator in ua_lower for indicator in security_indicators):
            return 70, "Security tool"

        # Standard browsers
        if any(browser in ua_lower for browser in ['chrome', 'firefox', 'safari', 'edge', 'opera']):
            return 0, "Standard browser"

        # Email clients - legitimate human access, minimal penalty
        if any(client in ua_lower for client in ['outlook', 'thunderbird', 'mail', 'msoffice', 'apple mail']):
            return 0, "Email client (legitimate)"

        return 25, "Anomalous User Agent"
    
    def _is_ip_whitelisted(self, ip, email_domain):
        """
        Check if an IP is whitelisted for a specific email domain.
        An IP is whitelisted if it has shown consistent human behavior for this domain.

        Whitelist criteria:
        - At least 3 human-like interactions (increased from 2)
        - Human behaviors must outweigh bot behaviors
        - Timing variance check (not too uniform = bot)
        - Not expired (90 days decay)
        """
        if ip not in self.ip_whitelist:
            return False

        whitelist_entry = self.ip_whitelist[ip]

        # Must have seen this domain before
        if email_domain not in whitelist_entry['domains']:
            return False

        # Whitelist decay: expires after 90 days
        if whitelist_entry['last_seen']:
            age = datetime.now() - whitelist_entry['last_seen']
            if age.days > 90:
                return False

        # Must have at least 3 human-like interactions (more restrictive)
        if whitelist_entry['human_behaviors'] < 3:
            return False

        # Human behaviors should outweigh bot behaviors
        if whitelist_entry['bot_behaviors'] > whitelist_entry['human_behaviors']:
            return False

        # Check timing variance: bots have very uniform timing
        timing_samples = whitelist_entry.get('timing_samples', [])
        if len(timing_samples) >= 3:
            try:
                variance = statistics.stdev(timing_samples)
                # If variance is too low (< 2 seconds), likely a bot with programmed delays
                if variance < 2.0:
                    return False
            except statistics.StatisticsError:
                # Not enough data or all values identical
                pass

        return True

    def _update_whitelist(self, ip, email_domain, is_human_like, score, timing=None):
        """
        Update the whitelist with behavior information for an IP/domain pair.

        Args:
            ip: IP address
            email_domain: Email domain
            is_human_like: Whether behavior was human-like
            score: Final score
            timing: Open->click timing in seconds (for variance analysis)
        """
        if not ip or ip == 'unknown':
            return

        whitelist_entry = self.ip_whitelist[ip]
        whitelist_entry['domains'].add(email_domain)
        whitelist_entry['scores'].append(score)

        # Update timestamps
        now = datetime.now()
        if whitelist_entry['first_seen'] is None:
            whitelist_entry['first_seen'] = now
        whitelist_entry['last_seen'] = now

        # Track timing for variance analysis
        if timing is not None and timing > 0:
            whitelist_entry['timing_samples'].append(timing)
            # Keep only last 10 samples
            if len(whitelist_entry['timing_samples']) > 10:
                whitelist_entry['timing_samples'].pop(0)

        if is_human_like:
            whitelist_entry['human_behaviors'] += 1
        else:
            whitelist_entry['bot_behaviors'] += 1

    def _extract_email_domain(self, email):
        """Extract domain from email address."""
        if '@' in email:
            return email.split('@')[1].lower()
        return None

    def _get_sent_time(self, email):
        """Get the time when email was sent for this recipient."""
        sent_events = self.df_with_sent[
            (self.df_with_sent['email'] == email) &
            (self.df_with_sent['message'] == self.EVENT_SENT)
        ]
        if not sent_events.empty:
            return sent_events.iloc[0]['time']
        return None

    def save_whitelist(self, filepath='whitelist.json'):
        """
        Save whitelist to JSON file for persistence across runs.

        Args:
            filepath: Path to save whitelist JSON file
        """
        whitelist_serializable = {}
        for ip, data in self.ip_whitelist.items():
            whitelist_serializable[ip] = {
                'domains': list(data['domains']),
                'scores': data['scores'],
                'human_behaviors': data['human_behaviors'],
                'bot_behaviors': data['bot_behaviors'],
                'timing_samples': data['timing_samples'],
                'first_seen': data['first_seen'].isoformat() if data['first_seen'] else None,
                'last_seen': data['last_seen'].isoformat() if data['last_seen'] else None
            }

        with open(filepath, 'w') as f:
            json.dump(whitelist_serializable, f, indent=2)

    def load_whitelist(self, filepath='whitelist.json'):
        """
        Load whitelist from JSON file.

        Args:
            filepath: Path to whitelist JSON file

        Returns:
            bool: True if loaded successfully, False if file doesn't exist
        """
        if not os.path.exists(filepath):
            return False

        with open(filepath, 'r') as f:
            data = json.load(f)
            for ip, entry in data.items():
                self.ip_whitelist[ip]['domains'] = set(entry['domains'])
                self.ip_whitelist[ip]['scores'] = entry['scores']
                self.ip_whitelist[ip]['human_behaviors'] = entry['human_behaviors']
                self.ip_whitelist[ip]['bot_behaviors'] = entry['bot_behaviors']
                self.ip_whitelist[ip]['timing_samples'] = entry['timing_samples']
                self.ip_whitelist[ip]['first_seen'] = datetime.fromisoformat(entry['first_seen']) if entry['first_seen'] else None
                self.ip_whitelist[ip]['last_seen'] = datetime.fromisoformat(entry['last_seen']) if entry['last_seen'] else None

        return True

    def group_events_by_ip(self, email_events):
        """
        Group events by source IP for separate bot/human analysis.
        """
        ip_groups = defaultdict(list)

        for idx, event in email_events.iterrows():
            ip, ua = self.extract_ip_and_ua(event)
            ip_key = ip if ip else 'unknown'
            ip_groups[ip_key].append({
                'time': event['time'],
                'message': event['message'],
                'ip': ip,
                'user_agent': ua,
                'event': event
            })

        # Sort chronologically
        for ip in ip_groups:
            ip_groups[ip] = sorted(ip_groups[ip], key=lambda x: x['time'])

        return ip_groups
    
    def analyze_timing(self, events_list, sent_time=None):
        """
        Analyze time intervals between events to identify automation.
        Distinguishes between send->open (can be hours) and open->click (max 30s for humans).

        Returns:
            tuple: (penalty, is_bot, details, open_to_click_timing)
        """
        if len(events_list) < 1:
            return 0, False, [], None

        details = []
        max_penalty = 0
        is_bot = False
        open_to_click_timing = None

        # Analyze send->open if we have sent time
        if sent_time and events_list[0]['message'] == self.EVENT_OPENED:
            send_to_open = (events_list[0]['time'] - sent_time).total_seconds()
            if send_to_open < 2:
                details.append(f"Bot detected: opened {send_to_open:.1f}s after send")
                max_penalty = max(max_penalty, 95)
                is_bot = True
            elif send_to_open < 10:
                details.append(f"Suspicious: opened {send_to_open:.1f}s after send")
                max_penalty = max(max_penalty, 70)
                is_bot = True
            else:
                details.append(f"Normal: opened {send_to_open/60:.1f}min after send")
        elif not sent_time and events_list[0]['message'] == self.EVENT_OPENED:
            # Fallback: sent time missing
            details.append("Sent time missing - limited timing analysis")
            max_penalty = max(max_penalty, 10)

        # Pattern analysis: detect suspicious re-opening patterns
        consecutive_opens = []
        for i in range(len(events_list) - 1):
            if events_list[i]['message'] == self.EVENT_OPENED and events_list[i+1]['message'] == self.EVENT_OPENED:
                time_diff = (events_list[i+1]['time'] - events_list[i]['time']).total_seconds()
                consecutive_opens.append(time_diff)

        # Check for bot pattern: too many rapid consecutive opens
        if len(consecutive_opens) > 2:
            avg_reopen = sum(consecutive_opens) / len(consecutive_opens)
            if avg_reopen < 5:
                details.append(f"Bot pattern: {len(consecutive_opens)} rapid re-opens (avg {avg_reopen:.1f}s)")
                max_penalty = max(max_penalty, 50)
                is_bot = True

        # Analyze open->click and click->submit
        for i in range(len(events_list) - 1):
            time_diff = (events_list[i+1]['time'] - events_list[i]['time']).total_seconds()
            event1 = events_list[i]['message']
            event2 = events_list[i+1]['message']

            # open->click or click->submit timing (should be quick but not instant)
            if event1 == self.EVENT_OPENED and event2 == self.EVENT_CLICKED:
                open_to_click_timing = time_diff  # Capture for whitelist variance analysis

                if time_diff < 1:
                    details.append(f"Bot: open->click in {time_diff*1000:.0f}ms")
                    max_penalty = max(max_penalty, 95)
                    is_bot = True
                elif time_diff < 3:
                    # FIXED: Don't mark as definite bot, just suspicious
                    details.append(f"Very fast: open->click in {time_diff:.1f}s")
                    max_penalty = max(max_penalty, 40)
                    # NOT setting is_bot = True here anymore
                elif time_diff <= 30:
                    details.append(f"Normal: open->click in {time_diff:.1f}s")
                    max_penalty = max(max_penalty, 0)
                else:
                    # Clicked after long time - multiple opens or thinking
                    details.append(f"Slow: open->click in {time_diff:.1f}s (re-reading email)")
                    max_penalty = max(max_penalty, 0)

            elif event2 == self.EVENT_CLICKED:
                if time_diff < 1:
                    details.append(f"Bot: {event1}->click in {time_diff*1000:.0f}ms")
                    max_penalty = max(max_penalty, 90)
                    is_bot = True
                elif time_diff < 5:
                    # FIXED: Reduced penalty from 40 to 20
                    details.append(f"Fast: {event1}->click in {time_diff:.1f}s")
                    max_penalty = max(max_penalty, 20)
                elif time_diff <= 30:
                    details.append(f"Normal: {event1}->click in {time_diff:.1f}s")

            # Multiple opens (human re-reading)
            elif event1 == self.EVENT_OPENED and event2 == self.EVENT_OPENED:
                if time_diff < 2:
                    details.append(f"Bot: multiple opens in {time_diff:.1f}s")
                    max_penalty = max(max_penalty, 80)
                    is_bot = True
                else:
                    details.append(f"Re-opened email after {time_diff:.1f}s")

        return max_penalty, is_bot, details, open_to_click_timing
    
    def calculate_ip_score(self, ip, events_list, email, sent_time=None):
        """
        Calculate reliability score for an IP group.
        High score (70-100) = likely human
        Low score (0-40) = likely bot

        Now with whitelist support and improved timing analysis.
        """
        score = 100
        analysis_details = []
        email_domain = self._extract_email_domain(email)

        # IP analysis
        ip_info = self.get_ip_info(ip) if ip and ip != 'unknown' else None
        is_italian, ip_type, ip_penalty, ip_desc = self.classify_ip(ip_info, email_domain, ip)

        if is_italian is False:
            return {
                'ip': ip,
                'score': 0,
                'type': ip_type,
                'is_bot': True,
                'classification': 'Foreign IP',
                'details': [ip_desc],
                'events': [e['message'] for e in events_list],
                'first_event': events_list[0]['time'],
                'last_event': events_list[-1]['time']
            }

        score -= ip_penalty
        if ip_penalty > 0:
            analysis_details.append(f"IP: {ip_desc} (-{ip_penalty})")

        # Timing analysis with sent_time (now returns 4 values including timing)
        timing_penalty, is_bot_timing, timing_details, open_to_click_timing = self.analyze_timing(events_list, sent_time)
        score -= timing_penalty
        if timing_penalty > 0:
            analysis_details.append(f"Timing: penalty {timing_penalty}")
        analysis_details.extend(timing_details)

        # User Agent analysis
        ua = next((e['user_agent'] for e in events_list if e['user_agent']), None)
        if ua:
            ua_penalty, ua_desc = self.analyze_user_agent(ua)
            score -= ua_penalty
            if ua_penalty > 0:
                analysis_details.append(f"User Agent: {ua_desc} (-{ua_penalty})")
        else:
            score -= 25
            analysis_details.append("User Agent: missing (-25)")

        # Behavior bonuses
        messages = [e['message'] for e in events_list]
        if self.EVENT_CLICKED in messages:
            score += 10
            analysis_details.append("Clicked link (+10)")

        # VPN whitelist bonus: if VPN but behavior is human-like
        if ip_type == 'vpn' and not is_bot_timing and score >= 50:
            score += 25
            analysis_details.append("VPN with human behavior (+25)")
            is_human_like = True
        else:
            is_human_like = score >= 60 and not is_bot_timing

        # Update whitelist with timing data for variance analysis
        if email_domain:
            self._update_whitelist(ip, email_domain, is_human_like, score, open_to_click_timing)

        # Final determination
        is_bot = is_bot_timing or ip_type in ['security_scanner', 'cloud'] or score < 40

        # Override bot detection for whitelisted VPNs
        if ip_type == 'vpn_whitelisted' and score >= 50:
            is_bot = False

        if score >= 70:
            classification = 'Genuine user'
        elif score >= 40:
            classification = 'Suspicious'
        else:
            classification = 'Bot/Scanner'

        return {
            'ip': ip or 'N/A',
            'score': max(0, min(100, score)),
            'type': ip_type,
            'is_bot': is_bot,
            'classification': classification,
            'details': analysis_details,
            'events': messages,
            'first_event': events_list[0]['time'],
            'last_event': events_list[-1]['time']
        }
    
    def analyze_email(self, email, email_events):
        """
        Analyze all events for a single target email.
        """
        ip_groups = self.group_events_by_ip(email_events)
        sent_time = self._get_sent_time(email)

        ip_analyses = []
        for ip, events_list in ip_groups.items():
            analysis = self.calculate_ip_score(ip, events_list, email, sent_time)
            ip_analyses.append(analysis)

        ip_analyses.sort(key=lambda x: x['first_event'])

        # Determine bot/human presence
        human_analyses = [a for a in ip_analyses if not a['is_bot']]
        bot_analyses = [a for a in ip_analyses if a['is_bot']]

        if human_analyses:
            final_score = max(a['score'] for a in human_analyses)
            has_human = True
        else:
            final_score = max((a['score'] for a in ip_analyses), default=0)
            has_human = False

        has_bot = len(bot_analyses) > 0

        # Final classification
        if has_bot and has_human:
            final_class = "Bot scanner + Real user"
        elif has_human:
            final_class = "Real user only"
        else:
            final_class = "Bot/scanner only"

        return {
            'email': email,
            'final_score': final_score,
            'final_classification': final_class,
            'has_bot': has_bot,
            'has_human': has_human,
            'ip_analyses': ip_analyses,
            'num_ips': len(ip_groups)
        }
    
    def analyze_campaign(self, verbose=False):
        """Execute complete campaign analysis."""
        results = []
        if verbose:
            print(f"\n{'='*80}")
            print(f"GOPHISH CAMPAIGN ANALYSIS - Real User Detection")
            print(f"{'='*80}\n")
        
        grouped = self.df.groupby('email')
        
        if verbose:
            print(f"Emails analyzed: {len(grouped)}")
            print(f"Total events: {len(self.df)}\n")
        
        for email, events in grouped:
            result = self.analyze_email(email, events)
            results.append(result)
            
            if verbose:
                print(f"\n{'─'*80}")
                print(f"Email: {email}")
                print(f"Final score: {result['final_score']}/100")
                print(f"Classification: {result['final_classification']}")
                print(f"Unique IPs detected: {result['num_ips']}")
            
            for i, ip_analysis in enumerate(result['ip_analyses'], 1):
                if verbose:
                    print(f"\n   {'─'*70}")
                    print(f"   IP #{i}: {ip_analysis['ip']} - {ip_analysis['classification']}")
                    print(f"   Score: {ip_analysis['score']}/100 | Type: {ip_analysis['type']}")
                    print(f"   Events: {', '.join(ip_analysis['events'])}")
                    print(f"   Period: {ip_analysis['first_event']} -> {ip_analysis['last_event']}")
                
                    if ip_analysis['details']:
                        print(f"   Details:")
                        for detail in ip_analysis['details']:
                            print(f"      - {detail}")

        if verbose:
            print(f"\n{'='*80}")
        self._print_summary(results, verbose)
        
        return results
    
    def generate_human_report(self, results):
        """
        Generate report focused only on genuine human interactions.
        Excludes all automated bots/scanners.
        """
        human_report = []
        
        for r in results:
            human_ips = [a for a in r['ip_analyses'] if not a['is_bot']]
            
            if not human_ips:
                human_report.append({
                    'email': r['email'],
                    'human_opened': 'NO',
                    'human_clicked': 'NO',
                    'human_score': 0,
                    'details': 'Bot/scanner only detected',
                    'human_ip': 'N/A'
                })
                continue
            
            best_human = max(human_ips, key=lambda x: x['score'])
            human_events = best_human['events']
            
            opened = 'YES' if self.EVENT_OPENED in human_events else 'NO'
            clicked = 'YES' if self.EVENT_CLICKED in human_events else 'NO'
            
            actions = []
            if opened == 'YES':
                actions.append('opened email')
            if clicked == 'YES':
                actions.append('clicked link')
            
            details = f"Actions: {', '.join(actions)}" if actions else "No action"
            
            human_report.append({
                'email': r['email'],
                'human_opened': opened,
                'human_clicked': clicked,
                'human_score': best_human['score'],
                'details': details,
                'human_ip': best_human['ip']
            })
        
        return human_report
    
    def _print_summary(self, results, verbose=False):
        """Print campaign statistics summary."""
        total = len(results)
        only_human = len([r for r in results if r['has_human'] and not r['has_bot']])
        only_bot = len([r for r in results if r['has_bot'] and not r['has_human']])
        both = len([r for r in results if r['has_bot'] and r['has_human']])
        
        if verbose:
            print(f"\nCAMPAIGN SUMMARY:")
            print(f"   Real users only: {only_human} ({only_human/total*100:.1f}%)")
            print(f"   Bot/scanner only: {only_bot} ({only_bot/total*100:.1f}%)")
            print(f"   Bot + Real user: {both} ({both/total*100:.1f}%)")
            print(f"\n   Total human interactions: {only_human + both} ({(only_human + both)/total*100:.1f}%)")
        
        avg_score = sum(r['final_score'] for r in results) / total if total > 0 else 0

        if verbose:
            print(f"   Average score: {avg_score:.1f}/100")
            print(f"\n{'='*80}\n")


def main():
    """Main function for standalone execution."""
    
    parser = argparse.ArgumentParser(
        description=f'{Colors.BLACK}{Colors.BOLD}GoPhish Campaign Analyzer{Colors.ENDC} - Distinguish bots from real users',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.BLACK}Usage examples:{Colors.ENDC}
  python gophish_analyzer.py -i raw_events.csv
  python gophish_analyzer.py --input-file events.csv --output-dir results/
  python gophish_analyzer.py -i data.csv -o reports/ --verbose
        """
    )
    
    parser.add_argument(
        '-i', '--input-file',
        type=str,
        required=True,
        metavar='FILE',
        help='Raw events CSV file exported from GoPhish'
    )
    
    parser.add_argument(
        '-o', '--output-dir',
        type=str,
        default='.',
        metavar='DIR',
        help='Directory to save generated reports (default: current directory)'
    )
    
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Show detailed output during analysis'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Don\'t show banner on startup'
    )
    
    parser.add_argument(
        '--version',
        action='version',
        version=f'{Colors.BLACK}GoPhish Analyzer v1.0{Colors.ENDC} by @Ggivaa'
    )
    
    args = parser.parse_args()
    
    # Show banner
    if not args.no_banner:
        print_banner()
    
    # Verify input file
    if not os.path.exists(args.input_file):
        print(f"{Colors.RED}[ERROR]{Colors.ENDC} File not found: {args.input_file}")
        sys.exit(1)
    
    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        print(f"{Colors.GREEN}[INFO]{Colors.ENDC} Directory created: {args.output_dir}")
    
    print(f"{Colors.BLUE}[INFO]{Colors.ENDC} Starting GoPhish analysis...")
    print(f"{Colors.YELLOW}[NOTE]{Colors.ENDC} Analysis requires several minutes for remote IP lookups\n")
    
    try:
        analyzer = GoPhishAnalyzer(args.input_file)

        # Load existing whitelist if available
        whitelist_path = os.path.join(args.output_dir, 'whitelist.json')
        if analyzer.load_whitelist(whitelist_path):
            print(f"{Colors.GREEN}[INFO]{Colors.ENDC} Loaded whitelist from: {whitelist_path}")

        results = analyzer.analyze_campaign(verbose=args.verbose)
        
        # Human report
        print("\n" + "="*80)
        print("HUMAN INTERACTIONS REPORT")
        print("="*80 + "\n")
        
        human_report = analyzer.generate_human_report(results)
        
        print("\n" + "─"*80)
        print("USERS WHO CLICKED THE LINK")
        print("─"*80 + "\n")
        
        clicked_count = 0
        opened_count = 0
        
        for entry in human_report:
            if entry['human_clicked'] == 'YES':
                clicked_count += 1
                if args.verbose:
                    print(f"{Colors.GREEN}✓{Colors.ENDC} {entry['email']}")
                    print(f"  Opened: {entry['human_opened']}")
                    print(f"  Clicked: {entry['human_clicked']}")
                    print(f"  Reliability score: {entry['human_score']}/100")
                    print(f"  IP: {entry['human_ip']}\n")
                else:
                    print(f"{Colors.GREEN}✓{Colors.ENDC} {entry['email']}")
            
            if entry['human_opened'] == 'YES':
                opened_count += 1
        
        print(f"\n{'─'*80}")
        print(f"{Colors.BOLD}HUMAN INTERACTION STATISTICS:{Colors.ENDC}")
        print(f"   {Colors.CYAN}Opened (users):{Colors.ENDC} {opened_count}/{len(human_report)} ({opened_count/len(human_report)*100:.1f}%)")
        print(f"   {Colors.GREEN}Clicked (users):{Colors.ENDC} {clicked_count}/{len(human_report)} ({clicked_count/len(human_report)*100:.1f}%)")
        print(f"{'─'*80}\n")
        
        # Export CSV
        human_file = os.path.join(args.output_dir, 'human_users_report.csv')
        df_human = pd.DataFrame(human_report)
        df_human.to_csv(human_file, index=False)
        print(f"{Colors.GREEN}[SAVED]{Colors.ENDC} Human users report: {human_file}")
        
        # Complete analysis
        full_file = os.path.join(args.output_dir, 'complete_campaign_analysis.csv')
        df_full = []
        for r in results:
            for ip in r['ip_analyses']:
                df_full.append({
                    'email': r['email'],
                    'ip': ip['ip'],
                    'ip_score': ip['score'],
                    'ip_classification': ip['classification'],
                    'ip_type': ip['type'],
                    'is_bot': ip['is_bot'],
                    'events': ' | '.join(ip['events']),
                    'final_email_score': r['final_score'],
                    'final_classification': r['final_classification']
                })
        
        df_output = pd.DataFrame(df_full)
        df_output.to_csv(full_file, index=False)
        print(f"{Colors.GREEN}[SAVED]{Colors.ENDC} Complete analysis: {full_file}")

        # Save updated whitelist
        analyzer.save_whitelist(whitelist_path)
        print(f"{Colors.GREEN}[SAVED]{Colors.ENDC} Updated whitelist: {whitelist_path}")

        print(f"\n{Colors.BOLD}{Colors.GREEN}Analysis completed successfully!{Colors.ENDC}\n")
        
    except Exception as e:
        print(f"\n{Colors.RED}[ERROR]{Colors.ENDC} Error during analysis: {str(e)}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()