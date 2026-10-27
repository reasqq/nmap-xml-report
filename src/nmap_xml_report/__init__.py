"""Read-only offline Nmap report parsing."""

from .parser import ReportError, parse_report

__all__ = ["ReportError", "parse_report"]
