"""
Central factory that resolves and instantiates the correct scanner for any target.

This module implements the Factory Method pattern for the Oranovix Guardian
scanner engine.  ``ScannerFactory`` is the single entry-point that maps a file
path, a ``Language`` enum value, or an arbitrary target directory to the
appropriate ``BaseScanner`` subclass.  All language-specific imports are
contained here so that the rest of the codebase never needs to reference
individual scanner modules directly.

The factory also exposes two introspection helpers — ``all_supported_extensions``
and ``all_scanners`` — which are used by the UI and CLI layers to enumerate
capabilities without hard-coding language lists elsewhere.

Version: 1.1.0
"""
from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Optional

from .base import BaseScanner, Language
from .python_scanner import PythonScanner
from .php_scanner import PHPScanner
from .java_scanner import JavaScanner
from .csharp_scanner import CSharpScanner
from .js_scanner import JSScanner


class ScannerFactory:
    """Factory that instantiates and returns the correct scanner for a given target.

    ``ScannerFactory`` is a stateless utility class (all methods are class
    methods) that encapsulates the mapping from ``Language`` enum values to
    concrete ``BaseScanner`` implementations.  Callers obtain scanners through
    one of three factory methods:

    - ``for_path``     – given a single file path, infer language from extension.
    - ``for_language`` – given a ``Language`` enum member directly.
    - ``for_target``   – given a file *or* directory; uses extension frequency
                          heuristics for directories.

    All three fall back to ``PythonScanner`` when the language cannot be
    determined, ensuring that callers always receive a usable scanner.
    """

    # Map each Language to its concrete scanner class.
    # Language.UNKNOWN maps to None because there is no generic scanner.
    _MAP = {
        Language.PYTHON:     PythonScanner,
        Language.PHP:        PHPScanner,
        Language.JAVA:       JavaScanner,
        Language.CSHARP:     CSharpScanner,
        Language.JAVASCRIPT: JSScanner,
        Language.UNKNOWN:    None,
    }

    # ------------------------------------------------------------------
    # Public factory methods
    # ------------------------------------------------------------------

    @classmethod
    def for_path(cls, path: str) -> Optional[BaseScanner]:
        """Return a scanner for the language inferred from the file's extension.

        Extracts the file extension from *path*, converts it to a ``Language``
        enum value via ``Language.from_extension``, and delegates to
        ``for_language``.

        Args:
            path: Path to the source file (only the extension is inspected).

        Returns:
            An instantiated ``BaseScanner`` subclass, or ``None`` when the
            extension maps to an unsupported or unknown language.
        """
        ext  = Path(path).suffix.lower()
        lang = Language.from_extension(ext)
        return cls.for_language(lang)

    @classmethod
    def for_language(cls, lang: Language) -> Optional[BaseScanner]:
        """Return an instantiated scanner for the given ``Language``, or ``None``.

        Performs a direct lookup in the ``_MAP`` registry and instantiates the
        corresponding scanner class if one exists.

        Args:
            lang: A ``Language`` enum member identifying the desired scanner.

        Returns:
            A fresh instance of the matching ``BaseScanner`` subclass, or
            ``None`` if no scanner is registered for *lang*.
        """
        klass = cls._MAP.get(lang)
        return klass() if klass else None

    @classmethod
    def for_target(cls, target: str) -> BaseScanner:
        """Return the best available scanner for *target* (file or directory).

        For a **single file** the language is inferred directly from its
        extension via ``for_path``.

        For a **directory** the method walks the entire tree, counts how often
        each known source-file extension appears, and picks the scanner for
        the most prevalent extension.  This heuristic works well for typical
        single-language projects.

        Falls back to ``PythonScanner`` in either of these cases:
        - The file's extension is unrecognised.
        - The directory contains no recognised source files.
        - The dominant-extension lookup returns ``None``.

        Args:
            target: Absolute path to a source file or project directory.

        Returns:
            An instantiated ``BaseScanner`` subclass; never ``None``.
        """
        p = Path(target)

        if p.is_file():
            scanner = cls.for_path(target)
            # Fall back to Python scanner if extension is unrecognised
            return scanner if scanner else PythonScanner()

        # Directory path: count known source-file extensions to find the dominant language
        ext_counts: Counter = Counter(
            Path(f).suffix.lower()
            for f in BaseScanner.collect_files(target, cls.all_supported_extensions())
        )

        if not ext_counts:
            # No recognised source files found – default to Python scanner
            return PythonScanner()

        # Pick the extension that appears most frequently in the tree
        dominant_ext = ext_counts.most_common(1)[0][0]
        # Re-use for_path by constructing a synthetic filename with the dominant extension
        scanner = cls.for_path(f"dummy{dominant_ext}")
        return scanner if scanner else PythonScanner()

    @classmethod
    def scanners_for_target(cls, target: str) -> list[BaseScanner]:
        """Return one scanner per language that has files under *target*.

        Unlike ``for_target`` this never drops a minority language: a
        Python project containing JavaScript files gets both scanners.
        """
        scanners: list[BaseScanner] = []
        for klass in cls._MAP.values():
            if klass is None:
                continue
            if BaseScanner.collect_files(target, klass.SUPPORTED_EXTENSIONS):
                scanners.append(klass())
        return scanners

    # ------------------------------------------------------------------
    # Introspection helpers
    # ------------------------------------------------------------------

    @classmethod
    def all_supported_extensions(cls) -> list[str]:
        """Return a list of every file extension handled by at least one scanner.

        Returns:
            A list of lowercase extension strings including the leading dot
            (e.g. ``[".py", ".php", ".java", ".cs", ".js", ".ts"]``).
        """
        extensions: list[str] = []
        for klass in cls._MAP.values():
            if klass is not None:
                extensions.extend(klass.SUPPORTED_EXTENSIONS)
        return extensions

    @classmethod
    def all_scanners(cls) -> list[BaseScanner]:
        """Return one instantiated scanner for every supported language.

        Iterates over ``_MAP`` and skips entries that have no associated class
        (i.e. ``Language.UNKNOWN``).  Useful for batch operations and UI
        capability discovery.

        Returns:
            A list of freshly created ``BaseScanner`` instances, one per
            supported language.
        """
        scanners: list[BaseScanner] = []
        for lang, klass in cls._MAP.items():
            if klass is not None:
                scanners.append(klass())
        return scanners
