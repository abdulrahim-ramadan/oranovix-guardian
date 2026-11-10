"""
Collapses findings that describe the same weakness on the same line.
"""
from __future__ import annotations

import os
import re
from typing import Dict, Iterable, List, Tuple

from .base import Issue
from .categories import IssueCategory

_MergeKey = Tuple[str, int, str]
_BANDIT_RULE_ID = re.compile(r"^B\d{3}$")


class IssueMerger:
    """Merges issues sharing (file, line, category) into one issue.

    The highest-severity issue of each group survives; the rule IDs of
    the others are recorded in ``also_detected_by``.  Uncategorised
    issues are only merged with exact repeats of the same rule.  When a
    Bandit issue survives, it takes the title of one of our own rules in
    the group, which names the problem more precisely.
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
        if _BANDIT_RULE_ID.match(primary.rule_id):
            own_rules = [i for i in group if not _BANDIT_RULE_ID.match(i.rule_id)]
            if own_rules:
                primary.title = max(own_rules, key=lambda i: i.severity.weight).title
        return primary
