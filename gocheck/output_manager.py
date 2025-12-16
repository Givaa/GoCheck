"""
Output Manager for GoCheck
Centralizes all logging and console output with multiple verbosity levels.

Author: @Givaa
"""

import logging
from enum import IntEnum
from typing import Any, Optional


class VerbosityLevel(IntEnum):
    """Verbosity levels for output control."""
    QUIET = 0      # Minimal: solo summary finale + file salvati
    NORMAL = 1     # Normal: + statistiche + nomi utenti che hanno cliccato (-v)
    VERBOSE = 2    # Verbose: + dettagli email, scores per email (-vv)
    DEBUG = 3      # Debug: + dettagli IP, timing analysis, whitelist updates (-vvv)
    TRACE = 4      # Trace: + logging completo + network details (-vvvv)


class Colors:
    """ANSI color codes for terminal output."""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    BLACK = '\033[30m'
    DEFAULT = '\033[39m'
    GRAY = '\033[90m'

    @staticmethod
    def strip(text: str) -> str:
        """Remove all ANSI color codes from text."""
        import re
        return re.sub(r'\033\[[0-9;]+m', '', text)


class OutputManager:
    """
    Centralized output manager for GoCheck.
    Handles all console output and logging based on verbosity level.
    """

    def __init__(self, verbosity: VerbosityLevel = VerbosityLevel.QUIET):
        """
        Initialize output manager.

        Args:
            verbosity: Verbosity level (0-4)
        """
        self.verbosity = verbosity
        self._configure_logging()

    def _configure_logging(self):
        """Configure Python logging based on verbosity level."""
        if self.verbosity == VerbosityLevel.TRACE:
            level = logging.DEBUG
            format_str = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        elif self.verbosity == VerbosityLevel.DEBUG:
            level = logging.INFO
            format_str = '%(levelname)s: %(message)s'
        elif self.verbosity >= VerbosityLevel.NORMAL:
            level = logging.WARNING
            format_str = '%(levelname)s: %(message)s'
        else:
            # QUIET mode: suppress everything
            level = logging.CRITICAL + 1
            format_str = '%(levelname)s: %(message)s'

        logging.basicConfig(
            level=level,
            format=format_str,
            force=True  # Override any existing configuration
        )

    def get_logger(self, name: str) -> logging.Logger:
        """Get a logger instance."""
        return logging.getLogger(name)

    # === Printing Methods ===

    def print(self, message: str, min_level: VerbosityLevel = VerbosityLevel.QUIET):
        """
        Print message if current verbosity >= min_level.

        Args:
            message: Message to print
            min_level: Minimum verbosity level required to show this message
        """
        if self.verbosity >= min_level:
            print(message)

    def info(self, message: str, min_level: VerbosityLevel = VerbosityLevel.NORMAL):
        """Print info message (blue [INFO] prefix)."""
        if self.verbosity >= min_level:
            print(f"{Colors.BLUE}[INFO]{Colors.ENDC} {message}")

    def success(self, message: str, min_level: VerbosityLevel = VerbosityLevel.QUIET):
        """Print success message (green [OK] prefix)."""
        if self.verbosity >= min_level:
            print(f"{Colors.GREEN}[OK]{Colors.ENDC} {message}")

    def warning(self, message: str, min_level: VerbosityLevel = VerbosityLevel.QUIET):
        """Print warning message (yellow [WARN] prefix)."""
        if self.verbosity >= min_level:
            print(f"{Colors.YELLOW}[WARN]{Colors.ENDC} {message}")

    def error(self, message: str, min_level: VerbosityLevel = VerbosityLevel.QUIET):
        """Print error message (red [ERROR] prefix)."""
        if self.verbosity >= min_level:
            print(f"{Colors.RED}[ERROR]{Colors.ENDC} {message}")

    def debug(self, message: str, min_level: VerbosityLevel = VerbosityLevel.DEBUG):
        """Print debug message (gray [DEBUG] prefix)."""
        if self.verbosity >= min_level:
            print(f"{Colors.GRAY}[DEBUG]{Colors.ENDC} {message}")

    def trace(self, message: str, min_level: VerbosityLevel = VerbosityLevel.TRACE):
        """Print trace message (gray [TRACE] prefix)."""
        if self.verbosity >= min_level:
            print(f"{Colors.GRAY}[TRACE]{Colors.ENDC} {message}")

    # === Formatted Output Methods ===

    def section(self, title: str, min_level: VerbosityLevel = VerbosityLevel.QUIET, width: int = 80):
        """Print section header with separator lines."""
        if self.verbosity >= min_level:
            print(f"\n{'='*width}")
            print(f"{Colors.BOLD}{title}{Colors.ENDC}")
            print(f"{'='*width}\n")

    def subsection(self, title: str, min_level: VerbosityLevel = VerbosityLevel.NORMAL, width: int = 80):
        """Print subsection header with lighter separator."""
        if self.verbosity >= min_level:
            print(f"\n{'─'*width}")
            print(f"{title}")
            print(f"{'─'*width}\n")

    def separator(self, min_level: VerbosityLevel = VerbosityLevel.NORMAL, width: int = 80, char: str = '─'):
        """Print a separator line."""
        if self.verbosity >= min_level:
            print(char * width)

    def blank_line(self, min_level: VerbosityLevel = VerbosityLevel.NORMAL):
        """Print a blank line."""
        if self.verbosity >= min_level:
            print()

    def key_value(self, key: str, value: Any, min_level: VerbosityLevel = VerbosityLevel.NORMAL,
                  color: str = Colors.CYAN, indent: int = 0):
        """Print key-value pair with color."""
        if self.verbosity >= min_level:
            indent_str = ' ' * indent
            print(f"{indent_str}{color}{key}:{Colors.ENDC} {value}")

    def bullet(self, text: str, min_level: VerbosityLevel = VerbosityLevel.VERBOSE,
               indent: int = 0, symbol: str = '•'):
        """Print bulleted item."""
        if self.verbosity >= min_level:
            indent_str = ' ' * indent
            print(f"{indent_str}{symbol} {text}")

    def table_row(self, columns: list, min_level: VerbosityLevel = VerbosityLevel.VERBOSE,
                  widths: Optional[list] = None):
        """Print table row with aligned columns."""
        if self.verbosity >= min_level:
            if widths is None:
                widths = [20] * len(columns)
            row = ' '.join(f"{str(col):<{w}}" for col, w in zip(columns, widths))
            print(row)

    # === Progress and Status ===

    def progress_message(self, current: int, total: int, item: str,
                        min_level: VerbosityLevel = VerbosityLevel.VERBOSE):
        """Print progress message (used when progress bar is disabled)."""
        if self.verbosity >= min_level:
            percentage = (current / total * 100) if total > 0 else 0
            print(f"  [{current}/{total}] ({percentage:.1f}%) - {item}")

    def status(self, message: str, min_level: VerbosityLevel = VerbosityLevel.DEBUG):
        """Print status message without newline (for updates)."""
        if self.verbosity >= min_level:
            print(f"\r{message}", end='', flush=True)

    # === Specialized Output for GoCheck ===

    def email_summary(self, email: str, score: int, classification: str, num_ips: int,
                     min_level: VerbosityLevel = VerbosityLevel.VERBOSE):
        """Print email analysis summary."""
        if self.verbosity >= min_level:
            self.separator(min_level=min_level)
            self.print(f"{Colors.BOLD}Email:{Colors.ENDC} {email}", min_level)
            self.key_value("Score", f"{score}/100", min_level)
            self.key_value("Classification", classification, min_level)
            self.key_value("Unique IPs", num_ips, min_level)

    def ip_analysis(self, ip_num: int, ip: str, score: int, classification: str,
                   ip_type: str, events: list, min_level: VerbosityLevel = VerbosityLevel.VERBOSE):
        """Print IP analysis details."""
        if self.verbosity >= min_level:
            print(f"\n   {'─'*70}")
            print(f"   {Colors.BOLD}IP #{ip_num}:{Colors.ENDC} {ip} - {classification}")
            print(f"   Score: {score}/100 | Type: {ip_type}")
            print(f"   Events: {', '.join(events)}")

    def ip_details(self, details: list, min_level: VerbosityLevel = VerbosityLevel.DEBUG):
        """Print IP analysis details (timing, user agent, etc.)."""
        if self.verbosity >= min_level and details:
            print(f"   {Colors.GRAY}Details:{Colors.ENDC}")
            for detail in details:
                print(f"      {Colors.GRAY}• {detail}{Colors.ENDC}")

    def campaign_stats(self, total: int, only_human: int, only_bot: int, both: int,
                      avg_score: float, min_level: VerbosityLevel = VerbosityLevel.NORMAL):
        """Print campaign statistics summary."""
        if self.verbosity >= min_level:
            self.blank_line(min_level)
            self.print(f"{Colors.BOLD}CAMPAIGN SUMMARY:{Colors.ENDC}", min_level)
            self.key_value("Real users only", f"{only_human} ({only_human/total*100:.1f}%)", min_level, indent=3)
            self.key_value("Bot/scanner only", f"{only_bot} ({only_bot/total*100:.1f}%)", min_level, indent=3)
            self.key_value("Bot + Real user", f"{both} ({both/total*100:.1f}%)", min_level, indent=3)
            self.blank_line(min_level)
            self.key_value("Total human interactions",
                          f"{only_human + both} ({(only_human + both)/total*100:.1f}%)",
                          min_level, indent=3)
            self.key_value("Average score", f"{avg_score:.1f}/100", min_level, indent=3)

    def human_clicked(self, email: str, opened: str, clicked: str, score: int, ip: str,
                     min_level: VerbosityLevel = VerbosityLevel.QUIET):
        """Print human user who clicked."""
        if self.verbosity >= min_level:
            print(f"{Colors.GREEN}✓{Colors.ENDC} {email}")
            if self.verbosity >= VerbosityLevel.NORMAL:
                print(f"  Opened: {opened}")
                print(f"  Clicked: {clicked}")
                print(f"  Reliability: {score}/100")
                print(f"  IP: {ip}\n")

    def file_saved(self, description: str, filepath: str,
                  min_level: VerbosityLevel = VerbosityLevel.QUIET):
        """Print file saved message."""
        if self.verbosity >= min_level:
            print(f"{Colors.GREEN}[SAVED]{Colors.ENDC} {description}: {filepath}")

    def api_call(self, ip: str, status: str, details: str = "",
                min_level: VerbosityLevel = VerbosityLevel.TRACE):
        """Print API call information."""
        if self.verbosity >= min_level:
            detail_str = f" - {details}" if details else ""
            print(f"{Colors.GRAY}[API] {ip}: {status}{detail_str}{Colors.ENDC}")

    def whitelist_update(self, ip: str, domain: str, action: str,
                        min_level: VerbosityLevel = VerbosityLevel.DEBUG):
        """Print whitelist update."""
        if self.verbosity >= min_level:
            print(f"{Colors.GRAY}[WHITELIST] {ip} @ {domain}: {action}{Colors.ENDC}")

    # === Utility Methods ===

    def should_show_progressbar(self) -> bool:
        """Determine if progress bar should be shown."""
        # Show progress bar only in QUIET and NORMAL modes
        # In VERBOSE+ modes, we show detailed per-item output instead
        return self.verbosity <= VerbosityLevel.NORMAL

    def is_level(self, level: VerbosityLevel) -> bool:
        """Check if current verbosity is at least the specified level."""
        return self.verbosity >= level
