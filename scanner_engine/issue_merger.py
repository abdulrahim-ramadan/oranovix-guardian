"""
Collapses findings that describe the same weakness on the same line.
"""
from __future__ import annotations

import os
from typing import Dict, Iterable, List, Tuple

from .base import Issue
from .categories import IssueCategory

_MergeKey = Tuple[str, int, str]


class IssueMerger:
    """Merges issues sharing (file, line, category) into one issue.

    The highest-severity issue of each group survives; the rule IDs of
    the others are recorded in ``also_detected_by``.  Uncategorised
    issues are only merged with exact repeats of the same rule.
    """

    def merge(self, issues: Iterable[Issue]) -> List[Issue]:
        groups: Dict[_MergeKey, List[Issue]] = {}
        for issue in issues:
            groups.setdefault(self._key(issue), []).append(issue)
        return [self._merge_group(group) for group in groups.values()]

    @staticmethod
    def _key(issue: Issue) -> _MergeKey:
        path = os.path.normcase(os.path.abspath(issue.file_path)) if issue.file_path else ""
        if issue.category is IssueCategory.OTHER:
            return (path, issue.line_number, f"rule:{issue.rule_id}")
        return (path, issue.line_number, issue.category.value)

    @staticmethod
    def _merge_group(group: List[Issue]) -> Issue:
        primary = max(group, key=lambda issue: issue.severity.weight)
        for other in group:
            if other is primary:
                continue
            for rule_id in (other.rule_id, *other.also_detected_by):
                if rule_id != primary.rule_id and rule_id not in primary.also_detected_by:
                    primary.also_detected_by.append(rule_id)
        return primary
