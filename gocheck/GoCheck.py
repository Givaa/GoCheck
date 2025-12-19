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
import logging
import dns.resolver
import ipaddress

# Import OutputManager and Report Generators (handle both package and direct execution)
try:
    from .output_manager import OutputManager, VerbosityLevel, Colors
    from .report_generators import HTMLReportGenerator, JSONReportGenerator, MarkdownReportGenerator
except ImportError:
    from output_manager import OutputManager, VerbosityLevel, Colors
    from report_generators import HTMLReportGenerator, JSONReportGenerator, MarkdownReportGenerator

# Optional tqdm import - fallback to dummy progress bar if not available
try:
    from tqdm import tqdm
    TQDM_AVAILABLE = True
except ImportError:
    TQDM_AVAILABLE = False
    # Dummy tqdm that just returns the iterable
    def tqdm(iterable, **kwargs):
        return iterable

# API Configuration Constants
IP_API_FIELDS = 16973823  # Bitmask for ip-api.com fields: country, ISP, org, AS, proxy, hosting, mobile, geolocation
IP_API_RATE_LIMIT = 1.35  # Seconds between API calls (45 req/min = 1.33s, using 1.35s for safety)
IP_API_TIMEOUT = 5  # Seconds

# Timing Thresholds (seconds)
BOT_SEND_TO_OPEN = 2
SUSPICIOUS_SEND_TO_OPEN = 10
BOT_OPEN_TO_CLICK = 1
SUSPICIOUS_OPEN_TO_CLICK = 3
NORMAL_CLICK_RANGE = 30
MULTIPLE_OPEN_BOT = 2

# Score Thresholds
GENUINE_HUMAN_THRESHOLD = 70
SUSPICIOUS_THRESHOLD = 40
BOT_THRESHOLD = 40

# IP Classification Penalties
FOREIGN_IP_PENALTY = 100
SECURITY_SCANNER_PENALTY = 95
CLOUD_PROVIDER_PENALTY = 80
DATACENTER_PENALTY = 75
VPN_PENALTY = 40
VPN_WHITELISTED_PENALTY = 15
UNKNOWN_IP_PENALTY = 30
IP_LOOKUP_FAILED_PENALTY = 60

# User Agent Penalties
BOT_UA_PENALTY = 80
SECURITY_TOOL_UA_PENALTY = 70
MISSING_UA_PENALTY = 30
ANOMALOUS_UA_PENALTY = 25
EMAIL_CLIENT_PENALTY = 0

# Behavioral Bonuses
CLICKED_LINK_BONUS = 10
VPN_HUMAN_BEHAVIOR_BONUS = 25

# Whitelist Configuration
WHITELIST_MIN_HUMAN_BEHAVIORS = 3
WHITELIST_TIMING_VARIANCE_MIN = 2.0  # Seconds
WHITELIST_DECAY_DAYS = 90

# Colors are now imported from output_manager

QUOTES = [
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
    quote = random.choice(QUOTES)

    banner = f"""
{Colors.DEFAULT}{Colors.BOLD}

 ▗▄▄▖ ▄▄▄   ▗▄▄▖▐▌   ▗▞▀▚▖▗▞▀▘█  ▄
▐▌   █   █ ▐▌   ▐▌   ▐▛▀▀▘▝▚▄▖█▄▀       {Colors.DEFAULT}"{quote}"{Colors.ENDC}{Colors.DEFAULT}{Colors.BOLD}
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

    def __init__(self, csv_path, allowed_countries=None, whitelist_path=None, auto_save_whitelist=True,
                 verbosity=VerbosityLevel.QUIET, output_manager=None):
        """
        Initialize analyzer with GoPhish events CSV file.

        Args:
            csv_path: Path to raw events CSV file exported from GoPhish
            allowed_countries: List of allowed country codes (default: ['IT'])
            whitelist_path: Path to load/save whitelist JSON (default: None, uses './whitelist.json')
            auto_save_whitelist: Automatically save whitelist after analysis (default: True)
            verbosity: Verbosity level (0-4) (default: VerbosityLevel.QUIET)
            output_manager: OutputManager instance (default: None, creates new one)
        """
        # Setup output manager
        self.out = output_manager or OutputManager(verbosity)
        self.logger = self.out.get_logger(__name__)

        # Configuration
        self.allowed_countries = allowed_countries or ['IT']
        self.whitelist_path = whitelist_path or './whitelist.json'
        self.auto_save_whitelist = auto_save_whitelist

        self.out.info(f"Initializing GoPhish Analyzer for countries: {self.allowed_countries}",
                     min_level=VerbosityLevel.DEBUG)

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

        # Deduplicate events (same email, IP, message, within 2 seconds)
        self.df = self._deduplicate_events(self.df)

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

        # Load existing whitelist if available
        if os.path.exists(self.whitelist_path):
            loaded = self.load_whitelist(self.whitelist_path)
            if loaded:
                self.logger.info(f"Loaded whitelist from {self.whitelist_path}")
                self.out.debug(f"Loaded whitelist from {self.whitelist_path}")

        # Track API calls for rate limiting
        self.last_api_call = None
        
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

    def _deduplicate_events(self, df):
        """
        Remove duplicate events (same email, IP, message within 2 seconds).
        This handles cases where GoPhish exports duplicate events due to bugs.

        Args:
            df: DataFrame with events

        Returns:
            DataFrame with duplicates removed
        """
        if df.empty:
            return df

        # Sort by time first
        df = df.sort_values('time').copy()

        # Extract IP from details for comparison
        def get_ip(details_str):
            try:
                details = json.loads(details_str) if pd.notna(details_str) else {}
                if isinstance(details.get('browser'), dict):
                    return details['browser'].get('address', '')
                elif isinstance(details.get('payload'), dict):
                    payload = details['payload']
                    if isinstance(payload.get('browser'), dict):
                        return payload['browser'].get('address', '')
            except:
                pass
            return ''

        df['_temp_ip'] = df['details'].apply(get_ip)

        # Mark duplicates
        duplicates_mask = []
        prev_row = None

        for idx, row in df.iterrows():
            is_duplicate = False
            if prev_row is not None:
                # Same email, IP, message
                if (row['email'] == prev_row['email'] and
                    row['_temp_ip'] == prev_row['_temp_ip'] and
                    row['message'] == prev_row['message']):
                    # Within 2 seconds
                    time_diff = (row['time'] - prev_row['time']).total_seconds()
                    if 0 < time_diff < 2:
                        is_duplicate = True
                        self.logger.debug(f"Duplicate event removed: {row['email']} - {row['message']} - {time_diff:.2f}s apart")

            duplicates_mask.append(is_duplicate)
            if not is_duplicate:
                prev_row = row

        df = df[~pd.Series(duplicates_mask, index=df.index)]
        df = df.drop(columns=['_temp_ip'])

        self.logger.info(f"Removed {sum(duplicates_mask)} duplicate events")
        self.out.debug(f"Removed {sum(duplicates_mask)} duplicate events")
        return df

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
        Uses cache to reduce API calls and implements proper rate limiting.
        """
        if not ip or ip == '':
            self.logger.debug(f"Empty IP address provided")
            return None

        # Return cached result
        if ip in self.ip_cache:
            self.logger.debug(f"IP {ip} found in cache")
            self.out.trace(f"IP {ip} found in cache")
            return self.ip_cache[ip]

        # Rate limiting: ensure minimum time between API calls
        if self.last_api_call is not None:
            elapsed = time.time() - self.last_api_call
            if elapsed < IP_API_RATE_LIMIT:
                sleep_time = IP_API_RATE_LIMIT - elapsed
                self.logger.debug(f"Rate limiting: sleeping {sleep_time:.2f}s before API call")
                self.out.trace(f"Rate limiting: sleeping {sleep_time:.2f}s")
                time.sleep(sleep_time)

        # Make API call
        try:
            self.logger.debug(f"Fetching IP info for {ip} from ip-api.com")
            self.out.api_call(ip, "Fetching", "from ip-api.com")
            response = requests.get(
                f'http://ip-api.com/json/{ip}?fields={IP_API_FIELDS}',
                timeout=IP_API_TIMEOUT
            )
            self.last_api_call = time.time()

            if response.status_code == 200:
                try:
                    data = response.json()
                    self.ip_cache[ip] = data
                    self.logger.debug(f"IP {ip}: {data.get('org', 'Unknown')} - {data.get('country', 'Unknown')}")
                    self.out.api_call(ip, "Success", f"{data.get('org', 'Unknown')} - {data.get('country', 'Unknown')}")
                    return data
                except json.JSONDecodeError as e:
                    self.logger.warning(f"Invalid JSON response for IP {ip}: {e}")
                    self.out.warning(f"Invalid JSON response for IP {ip}", min_level=VerbosityLevel.DEBUG)
                    return None
            else:
                self.logger.warning(f"API returned status {response.status_code} for IP {ip}")
                self.out.warning(f"API returned status {response.status_code} for IP {ip}", min_level=VerbosityLevel.DEBUG)
                return None

        except requests.Timeout:
            self.logger.warning(f"Timeout fetching IP info for {ip}")
            self.out.warning(f"Timeout fetching IP info for {ip}", min_level=VerbosityLevel.DEBUG)
            return None
        except requests.ConnectionError as e:
            self.logger.warning(f"Connection error for IP {ip}: {e}")
            self.out.warning(f"Connection error for IP {ip}", min_level=VerbosityLevel.TRACE)
            return None
        except requests.RequestException as e:
            self.logger.warning(f"Request failed for IP {ip}: {e}")
            self.out.warning(f"Request failed for IP {ip}", min_level=VerbosityLevel.TRACE)
            return None

        return None

    def check_spf_record(self, ip, email_domain):
        """
        Check if an IP address is authorized in the SPF record of the email domain.

        Args:
            ip: IP address to check
            email_domain: Domain extracted from recipient email address

        Returns:
            tuple: (is_in_spf, spf_record, details)
        """
        if not ip or not email_domain or ip == 'unknown':
            self.logger.debug("SPF check skipped: missing IP or email domain")
            return False, None, "Missing IP or email domain"

        try:
            self.logger.debug(f"Checking SPF record for domain: {email_domain}")
            self.out.trace(f"Checking SPF for {email_domain}")

            # Query TXT records for the domain
            try:
                answers = dns.resolver.resolve(email_domain, 'TXT')
            except dns.resolver.NoAnswer:
                self.logger.debug(f"No TXT records found for {email_domain}")
                self.out.trace(f"No TXT records for {email_domain}")
                return False, None, "No TXT records found"
            except dns.resolver.NXDOMAIN:
                self.logger.debug(f"Domain does not exist: {email_domain}")
                self.out.trace(f"Domain not found: {email_domain}")
                return False, None, "Domain does not exist"
            except dns.resolver.Timeout:
                self.logger.warning(f"DNS timeout querying {email_domain}")
                self.out.trace(f"DNS timeout for {email_domain}")
                return False, None, "DNS query timeout"

            # Find SPF record
            spf_record = None
            for rdata in answers:
                txt_string = b''.join(rdata.strings).decode('utf-8')
                if txt_string.startswith('v=spf1'):
                    spf_record = txt_string
                    break

            if not spf_record:
                self.logger.debug(f"No SPF record found for {email_domain}")
                self.out.trace(f"No SPF record for {email_domain}")
                return False, None, "No SPF record found"

            self.logger.info(f"SPF record found for {email_domain}: {spf_record[:100]}...")
            self.out.debug(f"SPF record found: {spf_record[:100]}...")

            # Parse IP address
            try:
                ip_obj = ipaddress.ip_address(ip)
            except ValueError:
                self.logger.warning(f"Invalid IP address format: {ip}")
                return False, spf_record, "Invalid IP format"

            # Check if IP is in SPF record (simple check for ip4:/ip6: mechanisms)
            is_in_spf = False
            matched_mechanism = None

            # Split SPF record into mechanisms
            mechanisms = spf_record.split()

            for mechanism in mechanisms:
                # Check ip4: mechanism
                if mechanism.startswith('ip4:'):
                    try:
                        ip_spec = mechanism[4:]  # Remove 'ip4:' prefix

                        # Handle CIDR notation
                        if '/' in ip_spec:
                            network = ipaddress.ip_network(ip_spec, strict=False)
                            if ip_obj in network:
                                is_in_spf = True
                                matched_mechanism = mechanism
                                break
                        else:
                            # Single IP address
                            if str(ip_obj) == ip_spec:
                                is_in_spf = True
                                matched_mechanism = mechanism
                                break
                    except (ValueError, ipaddress.AddressValueError):
                        self.logger.debug(f"Invalid ip4 mechanism: {mechanism}")
                        continue

                # Check ip6: mechanism
                elif mechanism.startswith('ip6:'):
                    try:
                        ip_spec = mechanism[4:]  # Remove 'ip6:' prefix

                        # Handle CIDR notation
                        if '/' in ip_spec:
                            network = ipaddress.ip_network(ip_spec, strict=False)
                            if ip_obj in network:
                                is_in_spf = True
                                matched_mechanism = mechanism
                                break
                        else:
                            # Single IP address
                            if str(ip_obj) == ip_spec:
                                is_in_spf = True
                                matched_mechanism = mechanism
                                break
                    except (ValueError, ipaddress.AddressValueError):
                        self.logger.debug(f"Invalid ip6 mechanism: {mechanism}")
                        continue

            if is_in_spf:
                self.logger.info(f"✅ IP {ip} found in SPF record: {matched_mechanism}")
                self.out.debug(f"✅ SPF match: {ip} in {matched_mechanism}")
                return True, spf_record, f"IP found in SPF: {matched_mechanism}"
            else:
                self.logger.debug(f"IP {ip} not found in SPF record")
                self.out.trace(f"IP {ip} not in SPF")
                return False, spf_record, "IP not in SPF record"

        except Exception as e:
            self.logger.warning(f"SPF check failed for {email_domain}: {e}")
            self.out.trace(f"SPF check error: {e}")
            return False, None, f"SPF check error: {str(e)}"

    def classify_ip(self, ip_info, email_domain=None, ip=None):
        """
        Classify IP type and calculate penalty for scoring.
        Now considers whitelisting for VPNs that show consistent human behavior.

        Returns:
            tuple: (is_allowed_country, ip_type, penalty, description, is_mobile)
        """
        if not ip_info or ip_info.get('status') == 'fail':
            self.logger.debug(f"IP classification failed: {ip} - lookup failed")
            return None, 'unknown', UNKNOWN_IP_PENALTY, "IP lookup failed - insufficient data", False

        country_code = ip_info.get('countryCode')
        country = ip_info.get('country', 'Unknown')
        is_allowed_country = country_code in self.allowed_countries
        is_mobile = ip_info.get('mobile', False)  # Extract mobile status

        if not is_allowed_country:
            self.logger.debug(f"Foreign IP detected: {ip} from {country}")
            self.out.debug(f"Foreign IP detected: {ip} from {country}")
            return False, 'foreign', FOREIGN_IP_PENALTY, f"Foreign IP: {country}", is_mobile

        org = ip_info.get('org', '').lower()
        isp = ip_info.get('isp', '').lower()
        as_name = ip_info.get('as', '').lower()
        proxy = ip_info.get('proxy', '')
        hosting = ip_info.get('hosting', '')
        combined = f"{org} {isp} {as_name}"

        # Security vendor (definite bot)
        if any(vendor in combined for vendor in self.security_vendors):
            self.logger.info(f"Security scanner detected: {ip} - {org}")
            self.out.debug(f"Security scanner detected: {ip} - {org}")
            return True, 'security_scanner', SECURITY_SCANNER_PENALTY, f"Security scanner: {org}", is_mobile

        # Cloud provider (very likely bot)
        if any(provider in combined for provider in self.cloud_providers):
            self.logger.info(f"Cloud provider detected: {ip} - {org}")
            self.out.debug(f"Cloud provider detected: {ip} - {org}")
            return True, 'cloud', CLOUD_PROVIDER_PENALTY, f"Cloud provider: {org}", is_mobile

        # Datacenter/Hosting (likely automated)
        if any(term in combined for term in ['datacenter', 'hosting', 'server']) or hosting == True:
            self.logger.info(f"Datacenter detected: {ip}")
            self.out.debug(f"Datacenter detected: {ip}")
            return True, 'datacenter', DATACENTER_PENALTY, "Datacenter", is_mobile

        # VPN/Proxy - check whitelist first
        if 'vpn' in combined or 'proxy' in combined or proxy == True:
            # Check if this IP is whitelisted for this domain
            if ip and email_domain and self._is_ip_whitelisted(ip, email_domain):
                self.logger.info(f"Whitelisted VPN detected: {ip} for {email_domain}")
                self.out.debug(f"Whitelisted VPN: {ip} for {email_domain}")
                return True, 'vpn_whitelisted', VPN_WHITELISTED_PENALTY, f"VPN/Proxy (whitelisted for {email_domain})", is_mobile
            # Not whitelisted yet, apply moderate penalty (will be reduced if behavior is human-like)
            self.logger.debug(f"VPN detected (not whitelisted): {ip}")
            self.out.trace(f"VPN detected (not whitelisted): {ip}")
            return True, 'vpn', VPN_PENALTY, "VPN/Proxy (pending validation)", is_mobile

        # Legitimate business/residential ISP
        if ip_info.get('isp'):
            self.logger.debug(f"Legitimate ISP detected: {ip} - {ip_info.get('isp')}")
            self.out.trace(f"Legitimate ISP: {ip} - {ip_info.get('isp')}")
            return True, 'legitimate_isp', 0, f"ISP: {ip_info.get('isp')}", is_mobile

        self.logger.debug(f"Unknown IP type: {ip}")
        return True, 'unknown', UNKNOWN_IP_PENALTY, "Unknown type - suspicious", is_mobile
    
    def analyze_user_agent(self, user_agent):
        """
        Analyze User Agent to detect bots/scanners.
        Email clients are now treated as legitimate human access patterns.

        Returns:
            tuple: (penalty, description)
        """
        if not user_agent or user_agent == '':
            self.logger.debug("User Agent missing")
            return MISSING_UA_PENALTY, "User Agent missing"

        ua_lower = user_agent.lower()

        # Bot keywords
        bot_indicators = [
            'bot', 'crawler', 'spider', 'scan', 'check', 'monitor',
            'validation', 'test', 'probe', 'fetch'
        ]
        if any(indicator in ua_lower for indicator in bot_indicators):
            self.logger.info(f"Bot UA detected: {user_agent[:50]}")
            self.out.debug(f"Bot User Agent detected: {user_agent[:50]}")
            return BOT_UA_PENALTY, "Bot/Crawler detected"

        # Security tools
        security_indicators = [
            'security', 'protection', 'safe', 'guard', 'threat',
            'sandbox', 'analyzer', 'scanner'
        ]
        if any(indicator in ua_lower for indicator in security_indicators):
            self.logger.info(f"Security tool UA detected: {user_agent[:50]}")
            self.out.debug(f"Security tool User Agent: {user_agent[:50]}")
            return SECURITY_TOOL_UA_PENALTY, "Security tool"

        # Standard browsers
        if any(browser in ua_lower for browser in ['chrome', 'firefox', 'safari', 'edge', 'opera']):
            self.logger.debug(f"Standard browser UA: {user_agent[:50]}")
            self.out.trace(f"Standard browser: {user_agent[:50]}")
            return 0, "Standard browser"

        # Email clients - legitimate human access, minimal penalty
        if any(client in ua_lower for client in ['outlook', 'thunderbird', 'mail', 'msoffice', 'apple mail']):
            self.logger.debug(f"Email client UA: {user_agent[:50]}")
            self.out.trace(f"Email client: {user_agent[:50]}")
            return EMAIL_CLIENT_PENALTY, "Email client (legitimate)"

        self.logger.debug(f"Anomalous UA: {user_agent[:50]}")
        return ANOMALOUS_UA_PENALTY, "Anomalous User Agent"
    
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
        if whitelist_entry['human_behaviors'] < WHITELIST_MIN_HUMAN_BEHAVIORS:
            self.logger.debug(f"IP {ip} not whitelisted for {email_domain}: only {whitelist_entry['human_behaviors']} human behaviors")
            return False

        # Human behaviors should outweigh bot behaviors
        if whitelist_entry['bot_behaviors'] > whitelist_entry['human_behaviors']:
            self.logger.debug(f"IP {ip} not whitelisted for {email_domain}: more bot behaviors than human")
            return False

        # Check timing variance: bots have very uniform timing
        timing_samples = whitelist_entry.get('timing_samples', [])
        if len(timing_samples) >= 3:
            try:
                variance = statistics.stdev(timing_samples)
                # If variance is too low (< 2 seconds), likely a bot with programmed delays
                if variance < WHITELIST_TIMING_VARIANCE_MIN:
                    self.logger.info(f"IP {ip} rejected from whitelist: timing variance too low ({variance:.2f}s)")
                    self.out.debug(f"IP {ip} rejected from whitelist: timing variance too low ({variance:.2f}s)")
                    return False
            except statistics.StatisticsError:
                # All values identical = bot with fixed timing - REJECT
                self.logger.info(f"IP {ip} rejected from whitelist: all timing values identical (bot)")
                self.out.debug(f"IP {ip} rejected from whitelist: uniform timing (bot)")
                return False

        self.logger.info(f"IP {ip} whitelisted for {email_domain}")
        self.out.whitelist_update(ip, email_domain, "whitelisted")
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
        Only saves non-expired entries (last_seen within WHITELIST_DECAY_DAYS).

        Args:
            filepath: Path to save whitelist JSON file
        """
        whitelist_serializable = {}
        now = datetime.now()
        expired_count = 0

        for ip, data in self.ip_whitelist.items():
            # Skip expired entries
            if data['last_seen']:
                age = now - data['last_seen']
                if age.days > WHITELIST_DECAY_DAYS:
                    expired_count += 1
                    self.logger.debug(f"Skipping expired whitelist entry: {ip} (age: {age.days} days)")
                    continue

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

        self.logger.info(f"Saved whitelist to {filepath}: {len(whitelist_serializable)} entries ({expired_count} expired entries removed)")
        self.out.debug(f"Whitelist saved: {len(whitelist_serializable)} entries ({expired_count} expired)")

    def load_whitelist(self, filepath='whitelist.json'):
        """
        Load whitelist from JSON file.

        Args:
            filepath: Path to whitelist JSON file

        Returns:
            bool: True if loaded successfully, False if file doesn't exist
        """
        if not os.path.exists(filepath):
            self.logger.debug(f"Whitelist file not found: {filepath}")
            return False

        try:
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

            self.logger.info(f"Loaded {len(data)} whitelist entries from {filepath}")
            self.out.debug(f"Whitelist loaded: {len(data)} entries")
            return True
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse whitelist JSON from {filepath}: {e}")
            self.out.error(f"Failed to parse whitelist JSON from {filepath}")
            return False
        except Exception as e:
            self.logger.error(f"Failed to load whitelist from {filepath}: {e}")
            self.out.error(f"Failed to load whitelist from {filepath}")
            return False

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

        # Find all CLICK events and calculate timing from LAST OPEN before each click
        # This handles the case where a user opens email multiple times before clicking
        for i, event in enumerate(events_list):
            if event['message'] == self.EVENT_CLICKED:
                # Find the last OPEN event before this CLICK
                last_open_idx = None
                for j in range(i - 1, -1, -1):
                    if events_list[j]['message'] == self.EVENT_OPENED:
                        last_open_idx = j
                        break

                if last_open_idx is not None:
                    time_diff = (event['time'] - events_list[last_open_idx]['time']).total_seconds()
                    open_to_click_timing = time_diff  # Capture for whitelist variance analysis

                    if time_diff < BOT_OPEN_TO_CLICK:
                        details.append(f"Bot: open->click in {time_diff*1000:.0f}ms")
                        max_penalty = max(max_penalty, 95)
                        is_bot = True
                    elif time_diff < SUSPICIOUS_OPEN_TO_CLICK:
                        details.append(f"Very fast: open->click in {time_diff:.1f}s")
                        max_penalty = max(max_penalty, 40)
                        # NOT setting is_bot = True here anymore
                    elif time_diff <= NORMAL_CLICK_RANGE:
                        details.append(f"Normal: open->click in {time_diff:.1f}s")
                        max_penalty = max(max_penalty, 0)
                    else:
                        # Clicked after long time - thinking/re-reading
                        details.append(f"Slow: open->click in {time_diff:.1f}s (re-reading email)")
                        max_penalty = max(max_penalty, 0)

        # Analyze open->click and other sequential events
        for i in range(len(events_list) - 1):
            time_diff = (events_list[i+1]['time'] - events_list[i]['time']).total_seconds()
            event1 = events_list[i]['message']
            event2 = events_list[i+1]['message']

            # Skip open->click as it's already handled above with better logic
            if event1 == self.EVENT_OPENED and event2 == self.EVENT_CLICKED:
                continue

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

        Now with whitelist support, improved timing analysis, and SPF validation.
        """
        score = 100
        analysis_details = []
        email_domain = self._extract_email_domain(email)

        # IP analysis
        ip_info = self.get_ip_info(ip) if ip and ip != 'unknown' else None
        is_italian, ip_type, ip_penalty, ip_desc, is_mobile = self.classify_ip(ip_info, email_domain, ip)

        # SPF validation check
        spf_validated = False
        spf_record = None
        spf_details = None
        if ip and ip != 'unknown' and email_domain:
            is_in_spf, spf_record, spf_details = self.check_spf_record(ip, email_domain)
            spf_validated = is_in_spf

        # Log mobile detection
        if is_mobile:
            self.logger.info(f"Mobile device detected: {ip}")
            self.out.debug(f"📱 Mobile access from {ip}")

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

        # SPF validation: informational only (no score bonus)
        # SPF indicates organizational authorization, not human vs bot distinction

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

        # Store raw score before capping (useful for debugging)
        raw_score = score
        capped_score = max(0, min(100, score))

        if capped_score >= GENUINE_HUMAN_THRESHOLD:
            classification = 'Genuine user'
        elif capped_score >= SUSPICIOUS_THRESHOLD:
            classification = 'Suspicious'
        else:
            classification = 'Bot/Scanner'

        self.logger.debug(f"IP {ip} final score: raw={raw_score}, capped={capped_score}, classification={classification}")
        self.out.trace(f"IP {ip} score: {capped_score}/100 ({classification})")

        # Generate decision breakdown for human review
        decision_breakdown = self._generate_decision_breakdown(
            ip, ip_info, ip_type, ip_penalty, ua, ua_penalty, ua_desc,
            timing_penalty, is_bot_timing, timing_details, messages,
            raw_score, capped_score, is_bot, classification,
            spf_validated, spf_record, spf_details, is_mobile
        )

        return {
            'ip': ip or 'N/A',
            'score': capped_score,
            'raw_score': raw_score,  # Added for debugging/analysis
            'type': ip_type,
            'is_bot': is_bot,
            'is_mobile': is_mobile,  # NEW: mobile device detection
            'classification': classification,
            'details': analysis_details,
            'events': messages,
            'first_event': events_list[0]['time'],
            'last_event': events_list[-1]['time'],
            'decision_breakdown': decision_breakdown  # NEW: detailed reasoning
        }
    
    def _generate_decision_breakdown(self, ip, ip_info, ip_type, ip_penalty, ua, ua_penalty, ua_desc,
                                     timing_penalty, is_bot_timing, timing_details, messages,
                                     raw_score, capped_score, is_bot, classification,
                                     spf_validated=False, spf_record=None, spf_details=None, is_mobile=False):
        """
        Generate detailed breakdown explaining why this decision was made.
        Returns a structured dictionary with step-by-step reasoning.
        Now includes SPF validation and mobile device detection.
        """
        breakdown = {
            'steps': [],
            'score_calculation': {},
            'final_verdict': {},
            'key_factors': [],
            'spf_validation': {
                'checked': spf_validated is not None,
                'validated': spf_validated,
                'record': spf_record,
                'details': spf_details
            },
            'device_info': {
                'is_mobile': is_mobile
            }
        }

        # Step 1: IP Lookup
        if ip_info:
            breakdown['steps'].append({
                'step': 1,
                'name': 'IP Lookup',
                'status': 'success',
                'icon': '✅',
                'details': f"{ip_info.get('org', 'Unknown')} - {ip_info.get('country', 'Unknown')}"
            })
        else:
            breakdown['steps'].append({
                'step': 1,
                'name': 'IP Lookup',
                'status': 'failed',
                'icon': '❌',
                'details': 'IP lookup failed - insufficient data'
            })
            breakdown['key_factors'].append('IP lookup failed - automatic bot classification')

        # Step 2: Country Check
        if ip_type == 'foreign':
            breakdown['steps'].append({
                'step': 2,
                'name': 'Country Check',
                'status': 'failed',
                'icon': '❌',
                'details': f"Foreign IP from {ip_info.get('country', 'Unknown')} (outside allowed countries)",
                'penalty': ip_penalty,
                'decision': 'REJECT - Analysis stopped (foreign IPs are always bots)'
            })
            breakdown['key_factors'].append(f"Foreign IP - outside allowed countries list")
            breakdown['final_verdict']['reason'] = 'Foreign IP detected - automatic bot classification'
        else:
            country = ip_info.get('country', 'Unknown') if ip_info else 'Unknown'
            breakdown['steps'].append({
                'step': 2,
                'name': 'Country Check',
                'status': 'success',
                'icon': '✅',
                'details': f"IP from {country} (allowed)"
            })

            # Step 2.5: Device Type (Mobile detection)
            device_icon = '📱' if is_mobile else '💻'
            device_type = 'Mobile Device' if is_mobile else 'Desktop/Other'
            breakdown['steps'].append({
                'step': 2.5,
                'name': 'Device Type',
                'status': 'info',
                'icon': device_icon,
                'details': device_type,
                'is_mobile': is_mobile
            })
            if is_mobile:
                breakdown['key_factors'].append('Mobile device access detected')

            # Step 3: IP Type Classification
            ip_type_emoji = {
                'legitimate_isp': '✅',
                'vpn_whitelisted': '✅',
                'vpn': '⚠️',
                'cloud': '❌',
                'datacenter': '❌',
                'security_scanner': '❌',
                'unknown': '⚠️'
            }.get(ip_type, '⚠️')

            ip_type_names = {
                'legitimate_isp': 'Legitimate ISP',
                'vpn_whitelisted': 'VPN (Whitelisted)',
                'vpn': 'VPN (Pending Validation)',
                'cloud': 'Cloud Provider',
                'datacenter': 'Datacenter/Hosting',
                'security_scanner': 'Security Scanner',
                'unknown': 'Unknown Type'
            }

            breakdown['steps'].append({
                'step': 3,
                'name': 'IP Type Classification',
                'status': 'success' if ip_penalty == 0 else 'warning' if ip_penalty < 50 else 'failed',
                'icon': ip_type_emoji,
                'details': f"{ip_type_names.get(ip_type, ip_type)} ({ip_info.get('org', 'Unknown') if ip_info else 'Unknown'})",
                'penalty': ip_penalty
            })

            if ip_penalty > 0:
                breakdown['key_factors'].append(f"IP type: {ip_type_names.get(ip_type, ip_type)} (-{ip_penalty} points)")

            # Step 4: Timing Analysis
            timing_icon = '✅' if timing_penalty == 0 else '⚠️' if timing_penalty < 50 else '❌'
            timing_status = 'success' if timing_penalty == 0 else 'warning' if timing_penalty < 50 else 'failed'

            timing_step = {
                'step': 4,
                'name': 'Timing Analysis',
                'status': timing_status,
                'icon': timing_icon,
                'details': timing_details,
                'penalty': timing_penalty
            }

            if is_bot_timing:
                timing_step['verdict'] = 'BOT DETECTED - Automated timing pattern'
                breakdown['key_factors'].append('Bot-like timing pattern detected')

            breakdown['steps'].append(timing_step)

            # Step 5: User Agent Analysis
            ua_icon = '✅' if ua_penalty == 0 else '⚠️' if ua_penalty < 50 else '❌'
            ua_status = 'success' if ua_penalty == 0 else 'warning' if ua_penalty < 50 else 'failed'

            breakdown['steps'].append({
                'step': 5,
                'name': 'User Agent Analysis',
                'status': ua_status,
                'icon': ua_icon,
                'details': ua_desc if ua else 'No user agent provided',
                'penalty': ua_penalty if ua else 25,
                'user_agent': ua[:100] if ua else None
            })

            if ua_penalty >= 50:
                breakdown['key_factors'].append(f"Suspicious user agent: {ua_desc}")

            # Step 6: SPF Validation (if performed) - informational only
            if spf_validated is not None and spf_validated:
                breakdown['steps'].append({
                    'step': 6,
                    'name': 'SPF Validation (Informational)',
                    'status': 'info',
                    'icon': '✉️',
                    'details': spf_details or 'IP found in SPF record (organizational authorization)',
                    'spf_record': spf_record[:100] + '...' if spf_record and len(spf_record) > 100 else spf_record
                })
                breakdown['key_factors'].append('IP authorized in organization SPF record')

            # Step 7: Behavior Bonuses
            bonuses = []
            bonus_total = 0
            if self.EVENT_CLICKED in messages:
                bonuses.append({'action': 'Clicked link', 'points': 10})
                bonus_total += 10

            if ip_type == 'vpn' and not is_bot_timing and raw_score >= 50:
                bonuses.append({'action': 'VPN with human behavior', 'points': 25})
                bonus_total += 25

            # SPF validation removed from bonuses - now informational only

            if bonuses:
                breakdown['steps'].append({
                    'step': 7,
                    'name': 'Behavior Bonuses',
                    'status': 'success',
                    'icon': '🎯',
                    'bonuses': bonuses,
                    'total_bonus': bonus_total
                })

        # Score Calculation
        breakdown['score_calculation'] = {
            'base_score': 100,
            'ip_penalty': -ip_penalty if ip_penalty else 0,
            'timing_penalty': -timing_penalty if timing_penalty else 0,
            'user_agent_penalty': -(ua_penalty if ua else 25),
            'bonuses': bonus_total if ip_type != 'foreign' else 0,
            'raw_total': raw_score,
            'capped_score': capped_score
        }

        # Final Verdict
        if is_bot:
            verdict_icon = '❌'
            verdict_text = 'BOT/SCANNER'

            reasons = []
            if ip_type == 'foreign':
                reasons.append('Foreign IP (outside allowed countries)')
            elif ip_type in ['security_scanner', 'cloud', 'datacenter']:
                reasons.append(f'IP type: {ip_type.replace("_", " ").title()}')

            if is_bot_timing:
                reasons.append('Automated timing pattern detected')

            if capped_score < BOT_THRESHOLD:
                reasons.append(f'Score {capped_score}/100 < {BOT_THRESHOLD} (bot threshold)')

            # Add context info even for bots
            context_notes = []
            if is_mobile:
                context_notes.append('Note: Mobile device detected')
            if spf_validated:
                context_notes.append('Note: IP found in SPF record (authorized by organization)')

            breakdown['final_verdict'] = {
                'icon': verdict_icon,
                'classification': verdict_text,
                'reasons': reasons,
                'context': context_notes,
                'conclusion': f"This IP is classified as a BOT because: {', '.join(reasons)}" + (f"\n\n{' | '.join(context_notes)}" if context_notes else "")
            }
        else:
            verdict_icon = '✅'
            verdict_text = 'GENUINE HUMAN'

            reasons = []
            if ip_type == 'legitimate_isp':
                reasons.append('Legitimate residential/business ISP')
            elif ip_type == 'vpn_whitelisted':
                reasons.append('Whitelisted VPN with consistent human behavior')

            if is_mobile:
                reasons.append('Mobile device access detected')

            if not is_bot_timing and timing_penalty == 0:
                reasons.append('Natural human timing patterns')

            if ua_penalty == 0:
                reasons.append('Standard browser/email client')

            if self.EVENT_CLICKED in messages:
                reasons.append('Clicked the link (human behavior)')

            # SPF removed from reasons - shown in Additional Context instead

            if capped_score >= GENUINE_HUMAN_THRESHOLD:
                reasons.append(f'Score {capped_score}/100 ≥ {GENUINE_HUMAN_THRESHOLD} (genuine human threshold)')

            # Add context info for humans too
            context_notes = []
            if spf_validated:
                context_notes.append('Note: IP found in SPF record (authorized by organization)')

            breakdown['final_verdict'] = {
                'icon': verdict_icon,
                'classification': verdict_text,
                'reasons': reasons,
                'context': context_notes,
                'conclusion': f"This IP is classified as HUMAN because: {', '.join(reasons)}" + (f"\n\n{' | '.join(context_notes)}" if context_notes else "")
            }

        return breakdown

    def analyze_email(self, email, email_events):
        """
        Analyze all events for a single target email.
        Handles emails with no events (only sent, no open/click).
        """
        # Handle emails with no events (only Email Sent, no interactions)
        if email_events.empty:
            return {
                'email': email,
                'final_score': 0,
                'final_classification': "No response",
                'has_bot': False,
                'has_human': False,
                'ip_analyses': [],
                'num_ips': 0
            }

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
    
    def analyze_campaign(self):
        """Execute complete campaign analysis with progress bar."""
        results = []

        # Print header based on verbosity
        self.out.section("GOPHISH CAMPAIGN ANALYSIS - Real User Detection",
                        min_level=VerbosityLevel.VERBOSE)

        # Get all sent emails from df_with_sent to include emails with no events
        sent_emails = self.df_with_sent[self.df_with_sent['message'] == self.EVENT_SENT]['email'].unique()

        # Get emails with events
        grouped = self.df.groupby('email')
        emails_with_events = set(grouped.groups.keys())

        # Combine: all sent emails (includes those with no events)
        all_emails = set(sent_emails)

        self.out.info(f"Emails sent: {len(all_emails)}", min_level=VerbosityLevel.VERBOSE)
        self.out.info(f"Emails with events: {len(emails_with_events)}", min_level=VerbosityLevel.VERBOSE)
        self.out.info(f"Total events: {len(self.df)}", min_level=VerbosityLevel.VERBOSE)

        # Progress bar for email analysis - iterate over ALL sent emails
        pbar_emails = tqdm(
            sorted(all_emails),
            desc=f"{Colors.DEFAULT}Analyzing emails{Colors.ENDC}",
            unit="email",
            disable=not self.out.should_show_progressbar(),  # Show only in QUIET/NORMAL modes
            bar_format='{desc}: {percentage:3.0f}%|{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]'
        )

        for email in pbar_emails:
            if TQDM_AVAILABLE and self.out.should_show_progressbar():
                pbar_emails.set_postfix_str(f"{email[:30]}...")

            # Get events for this email (may be empty if only sent event exists)
            if email in emails_with_events:
                events = grouped.get_group(email)
            else:
                # Email was sent but has no events (no open, click, etc.)
                events = pd.DataFrame()

            result = self.analyze_email(email, events)
            results.append(result)

            # Show detailed output per email if VERBOSE or higher
            self.out.email_summary(
                email,
                result['final_score'],
                result['final_classification'],
                result['num_ips'],
                min_level=VerbosityLevel.VERBOSE
            )

            for i, ip_analysis in enumerate(result['ip_analyses'], 1):
                self.out.ip_analysis(
                    i,
                    ip_analysis['ip'],
                    ip_analysis['score'],
                    ip_analysis['classification'],
                    ip_analysis['type'],
                    ip_analysis['events'],
                    min_level=VerbosityLevel.VERBOSE
                )

                # Show IP details (timing, user agent) only in DEBUG mode
                if ip_analysis['details']:
                    self.out.ip_details(ip_analysis['details'], min_level=VerbosityLevel.DEBUG)

        self._print_summary(results)

        # Auto-save whitelist if enabled
        if self.auto_save_whitelist:
            self.save_whitelist(self.whitelist_path)
            self.logger.info(f"Auto-saved whitelist to {self.whitelist_path}")

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
    
    def _print_summary(self, results):
        """Print campaign statistics summary."""
        total = len(results)
        only_human = len([r for r in results if r['has_human'] and not r['has_bot']])
        only_bot = len([r for r in results if r['has_bot'] and not r['has_human']])
        both = len([r for r in results if r['has_bot'] and r['has_human']])

        avg_score = sum(r['final_score'] for r in results) / total if total > 0 else 0

        # Print campaign statistics
        self.out.campaign_stats(
            total, only_human, only_bot, both, avg_score,
            min_level=VerbosityLevel.NORMAL
        )


def extract_client_name(results):
    """
    Extract client name from email domains.
    Uses the most common domain from the results.
    Examples: user@gmail.com -> gmail, user@company.com -> company
    """
    if not results or len(results) == 0:
        return "campaign"

    # Count domain occurrences
    from collections import Counter
    domains = []
    for r in results:
        email = r.get('email', '')
        if '@' in email:
            domain = email.split('@')[1].lower()
            # Extract main part before .com, .it, etc.
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                client_name = domain_parts[0]  # e.g., 'gmail' from 'gmail.com'
            else:
                client_name = domain
            domains.append(client_name)

    if not domains:
        return "campaign"

    # Get most common domain
    counter = Counter(domains)
    most_common_client = counter.most_common(1)[0][0]
    return most_common_client


def main():
    """Main function for standalone execution."""

    parser = argparse.ArgumentParser(
        description=f'{Colors.DEFAULT}{Colors.BOLD}GoPhish Campaign Analyzer{Colors.ENDC} - Distinguish bots from real users',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
{Colors.DEFAULT}Usage examples:{Colors.ENDC}
  python gocheck/GoCheck.py -i raw_events.csv
  python gocheck/GoCheck.py -i events.csv -o results/
  python gocheck/GoCheck.py -i data.csv -o reports/ --verbose
  python gocheck/GoCheck.py -i events.csv --countries IT US GB
  python gocheck/GoCheck.py -i events.csv --whitelist custom.json
  python gocheck/GoCheck.py -i events.csv --no-auto-save

{Colors.DEFAULT}For more information:{Colors.ENDC}
  Documentation: https://github.com/Givaa/GoCheck
  Algorithm details: docs/ALGORITHM.md
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
        action='count',
        default=0,
        help='Increase verbosity (-v: normal, -vv: verbose, -vvv: debug, -vvvv: trace)'
    )
    
    parser.add_argument(
        '--no-banner',
        action='store_true',
        help='Don\'t show banner on startup'
    )

    parser.add_argument(
        '--countries',
        nargs='+',
        default=['IT'],
        metavar='CODE',
        help='Allowed country codes (e.g., IT US GB). Default: IT'
    )

    parser.add_argument(
        '--whitelist',
        type=str,
        default=None,
        metavar='PATH',
        help='Path to whitelist JSON file (default: ./whitelist.json in output dir)'
    )

    parser.add_argument(
        '--no-auto-save',
        action='store_true',
        help='Disable automatic whitelist saving after analysis'
    )

    parser.add_argument(
        '--html',
        action='store_true',
        help='Generate interactive HTML report'
    )

    parser.add_argument(
        '--json',
        action='store_true',
        help='Generate JSON report for machine-readable output'
    )

    parser.add_argument(
        '--markdown',
        action='store_true',
        help='Generate Markdown report'
    )

    parser.add_argument(
        '--all-reports',
        action='store_true',
        help='Generate all report formats (HTML, JSON, Markdown)'
    )

    parser.add_argument(
        '--version',
        action='version',
        version=f'{Colors.DEFAULT}GoPhish Analyzer v2.2.0{Colors.ENDC} by @Givaa'
    )

    args = parser.parse_args()

    # Map verbose count to VerbosityLevel
    verbosity = VerbosityLevel(min(args.verbose, 4))  # Cap at 4 (TRACE)

    # Create output manager
    out = OutputManager(verbosity)

    # Show banner
    if not args.no_banner:
        print_banner()

    # Verify input file
    if not os.path.exists(args.input_file):
        out.error(f"File not found: {args.input_file}")
        sys.exit(1)

    # Create output directory if it doesn't exist
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)
        out.info(f"Directory created: {args.output_dir}", min_level=VerbosityLevel.NORMAL)

    out.info("Starting GoPhish analysis...")
    out.info("Analysis requires several minutes for remote IP lookups", min_level=VerbosityLevel.NORMAL)
    out.blank_line()

    try:
        # Initialize analyzer with new configuration options
        whitelist_path = args.whitelist if args.whitelist else os.path.join(args.output_dir, 'whitelist.json')
        analyzer = GoPhishAnalyzer(
            args.input_file,
            allowed_countries=args.countries,
            whitelist_path=whitelist_path,
            auto_save_whitelist=not args.no_auto_save,
            verbosity=verbosity,
            output_manager=out
        )

        results = analyzer.analyze_campaign()
        
        # Human report
        out.section("HUMAN INTERACTIONS REPORT")

        human_report = analyzer.generate_human_report(results)

        out.subsection("USERS WHO CLICKED THE LINK")

        clicked_count = 0
        opened_count = 0

        for entry in human_report:
            if entry['human_clicked'] == 'YES':
                clicked_count += 1
                out.human_clicked(
                    entry['email'],
                    entry['human_opened'],
                    entry['human_clicked'],
                    entry['human_score'],
                    entry['human_ip']
                )

            if entry['human_opened'] == 'YES':
                opened_count += 1

        out.separator()
        out.print(f"{Colors.BOLD}HUMAN INTERACTION STATISTICS:{Colors.ENDC}")
        out.key_value("Opened (users)",
                     f"{opened_count}/{len(human_report)} ({opened_count/len(human_report)*100:.1f}%)",
                     color=Colors.CYAN, indent=3)
        out.key_value("Clicked (users)",
                     f"{clicked_count}/{len(human_report)} ({clicked_count/len(human_report)*100:.1f}%)",
                     color=Colors.GREEN, indent=3)
        out.separator()
        out.blank_line()
        
        # Export CSV
        human_file = os.path.join(args.output_dir, 'human_users_report.csv')
        df_human = pd.DataFrame(human_report)
        df_human.to_csv(human_file, index=False)
        out.file_saved("Human users report", human_file)

        # Complete analysis
        full_file = os.path.join(args.output_dir, 'complete_campaign_analysis.csv')
        df_full = []
        for r in results:
            for ip in r['ip_analyses']:
                df_full.append({
                    'email': r['email'],
                    'ip': ip['ip'],
                    'ip_score': ip['score'],
                    'ip_raw_score': ip.get('raw_score', ip['score']),  # Include raw score for analysis
                    'ip_classification': ip['classification'],
                    'ip_type': ip['type'],
                    'is_bot': ip['is_bot'],
                    'events': ' | '.join(ip['events']),
                    'final_email_score': r['final_score'],
                    'final_classification': r['final_classification']
                })

        df_output = pd.DataFrame(df_full)
        df_output.to_csv(full_file, index=False)
        out.file_saved("Complete analysis", full_file)

        # Whitelist is auto-saved after analysis (auto_save_whitelist=True)
        out.file_saved("Whitelist auto-saved", whitelist_path)

        # Extract client name from email domains
        client_name = extract_client_name(results)
        out.info(f"Detected client: {client_name}", min_level=VerbosityLevel.VERBOSE)

        # Generate additional reports if requested (using client name)
        if args.all_reports or args.html:
            html_file = os.path.join(args.output_dir, f'{client_name}_report.html')
            html_gen = HTMLReportGenerator(results, human_report, campaign_name=f"{client_name.title()} Campaign Analysis")
            html_gen.generate(html_file)
            out.file_saved("HTML report", html_file)

        if args.all_reports or args.json:
            json_file = os.path.join(args.output_dir, f'{client_name}_report.json')
            json_gen = JSONReportGenerator(results, human_report, campaign_name=f"{client_name.title()} Campaign Analysis")
            json_gen.generate(json_file)
            out.file_saved("JSON report", json_file)

        if args.all_reports or args.markdown:
            md_file = os.path.join(args.output_dir, f'{client_name}_report.md')
            md_gen = MarkdownReportGenerator(results, human_report, campaign_name=f"{client_name.title()} Campaign Analysis")
            md_gen.generate(md_file)
            out.file_saved("Markdown report", md_file)

        out.blank_line()
        out.success(f"{Colors.BOLD}Analysis completed successfully!{Colors.ENDC}")
        out.blank_line()
        
    except Exception as e:
        out.blank_line()
        out.error(f"Error during analysis: {str(e)}")
        if verbosity >= VerbosityLevel.VERBOSE:
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()