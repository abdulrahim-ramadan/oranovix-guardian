"""Dependency scanning: known vulnerabilities (CVE / GHSA) in third-party packages."""
from .dependency_scanner import DependencyScanner
from .osv_db import OSVDatabase, OSVUpdateError, Vulnerability
from .versions import Ecosystem

__all__ = ["DependencyScanner", "Ecosystem", "OSVDatabase", "OSVUpdateError", "Vulnerability"]
