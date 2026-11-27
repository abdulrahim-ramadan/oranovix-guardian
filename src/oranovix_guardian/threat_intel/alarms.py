"""
Alarms for feed items that hit one of the user's projects.

Only an item that is confirmed for an installed version AND is either
exploited in the wild or rated critical is announced, once. Everything
else stays silent and is only listed on the page.

More than three such items at once are announced as one alarm with a
count, so the first download of a whole catalog does not ring N times.
"""
from __future__ import annotations

import hashlib
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from oranovix_guardian.core.alarm_center import Alarm, AlarmCenter
from oranovix_guardian.core.language_manager import LanguageManager
from oranovix_guardian.scanner_engine.base import Issue, Severity
from oranovix_guardian.scanner_engine.categories import IssueCategory

from .models import ProjectMatch, Relevance, StoredItem, project_key
from .store import ThreatStore

Pending = Tuple[StoredItem, List[ProjectMatch]]


class ThreatAlarmRaiser:
    """Hands qualifying feed items to the alarm center, once per item and project."""

    RULE_ID = "TF001"
    SUMMARY_RULE_ID = "TF002"
    MAX_SINGLE_ALARMS = 3

    def __init__(self, alarm_center: Optional[AlarmCenter], store: ThreatStore) -> None:
        self._alarm_center = alarm_center
        self._store = store

    @staticmethod
    def deserves_alarm(stored: StoredItem) -> bool:
        if stored.relevance is not Relevance.AFFECTS_YOU:
            return False
        confirmed = [match for match in stored.matches if match.confirmed]
        if not confirmed:
            return False
        return stored.item.is_known_exploited or any(
            match.severity is Severity.CRITICAL for match in confirmed
        )

    def raise_for(self, items: Iterable[StoredItem]) -> List[Alarm]:
        """Raise one CRITICAL alarm per qualifying item that has not alarmed yet.

        More than ``MAX_SINGLE_ALARMS`` of them become a single alarm.
        """
        if self._alarm_center is None:
            return []
        accepted = self._store.accepted_risks()
        pending: List[Pending] = []
        for stored in items:
            if not self.deserves_alarm(stored):
                continue
            matches = [
                match for match in self._one_per_project(stored)
                if not self._store.was_alarmed(stored.id, self._project_key(match))
                and (stored.id, self._project_key(match)) not in accepted
            ]
            if matches:
                pending.append((stored, matches))

        if len(pending) > self.MAX_SINGLE_ALARMS:
            batches = [[self.summary_issue(pending)]]
        else:
            batches = [[self.issue(stored, match) for match in matches] for stored, matches in pending]
        alarms: List[Alarm] = []
        for issues in batches:
            # The projects differ, so the root is left empty and the project
            # is part of each finding id instead.
            alarm = self._alarm_center.notify(issues, scan_root="", full_scan=False)
            if alarm is not None:
                alarms.append(alarm)
        for stored, matches in pending:
            for match in matches:
                self._store.mark_alarmed(stored.id, self._project_key(match))
        return alarms

    @classmethod
    def summary_issue(cls, pending: Sequence[Pending]) -> Issue:
        """One issue for many items: the count, and the first three by name."""
        lm = LanguageManager()
        count = len(pending)
        exploited = all(stored.item.is_known_exploited for stored, _ in pending)
        named = [
            lm.t("tf_alarm_many_line", project=matches[0].project, package=matches[0].package,
                 version=matches[0].version, advisory=matches[0].advisory_id)
            for _, matches in pending[: cls.MAX_SINGLE_ALARMS]
        ]
        description = "; ".join(named)
        if count > cls.MAX_SINGLE_ALARMS:
            description += "; " + lm.t("tf_alarm_many_more", count=count - cls.MAX_SINGLE_ALARMS)
        first = pending[0][1][0]
        keys = sorted(
            f"{stored.id}|{cls._project_key(match)}" for stored, matches in pending for match in matches
        )
        digest = hashlib.sha256("\n".join(keys).encode("utf-8")).hexdigest()[:32]
        return Issue(
            rule_id=cls.SUMMARY_RULE_ID,
            title=lm.t("tf_alarm_many" if exploited else "tf_alarm_many_mixed", count=count),
            description=description,
            severity=Severity.CRITICAL,
            file_path=first.file_path or first.project_path,
            line_number=first.line,
            recommendation=lm.t("tf_alarm_many_fix"),
            confidence="HIGH",
            category=IssueCategory.DEPENDENCY,
            finding_key=f"threat-feed|many|{digest}",
        )

    @classmethod
    def issue(cls, stored: StoredItem, match: ProjectMatch) -> Issue:
        lm = LanguageManager()
        item = stored.item
        key = "tf_alarm_exploited" if item.is_known_exploited else "tf_alarm_critical"
        title = lm.t(
            key, project=match.project, package=match.package,
            version=match.version, advisory=match.advisory_id,
        )
        fix = (
            lm.t("tf_alarm_fix", version=match.fixed_version)
            if match.fixed_version else lm.t("tf_alarm_fix_unknown")
        )
        return Issue(
            rule_id=cls.RULE_ID,
            title=title,
            description=f"{item.title} ({item.source})",
            severity=Severity.CRITICAL,
            file_path=match.file_path or match.project_path,
            line_number=match.line,
            recommendation=fix,
            confidence="HIGH",
            category=IssueCategory.DEPENDENCY,
            finding_key=f"threat-feed|{item.id}|{cls._project_key(match)}",
        )

    @staticmethod
    def _one_per_project(stored: StoredItem) -> List[ProjectMatch]:
        chosen: Dict[str, ProjectMatch] = {}
        for match in stored.matches:
            if not match.confirmed:
                continue
            key = ThreatAlarmRaiser._project_key(match)
            current = chosen.get(key)
            if current is None or (match.severity and current.severity
                                   and match.severity.weight > current.severity.weight):
                chosen[key] = match
        return list(chosen.values())

    @staticmethod
    def _project_key(match: ProjectMatch) -> str:
        return project_key(match.project_path)
