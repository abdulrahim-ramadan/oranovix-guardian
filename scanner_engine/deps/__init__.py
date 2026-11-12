"""Dependency scanning: known vulnerabilities (CVE / GHSA) in third-party packages."""
from .osv_db import OSVDatabase, OSVUpdateError, Vulnerability
from .versions import Ecosystem

__all__ = ["Ecosystem", "OSVDatabase", "OSVUpdateError", "Vulnerability"]
