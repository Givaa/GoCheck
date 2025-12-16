"""
GoCheck - GoPhish Campaign Analyzer
Analyzes phishing campaign events to distinguish bots from real users.
"""

from .GoCheck import GoPhishAnalyzer, main
from .output_manager import OutputManager, VerbosityLevel, Colors

__all__ = ['GoPhishAnalyzer', 'OutputManager', 'VerbosityLevel', 'Colors', 'main']
__version__ = '2.2.0'
