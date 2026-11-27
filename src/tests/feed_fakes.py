"""Stand-ins for the network, shared by the Threat Feed tests."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Union

from oranovix_guardian.threat_intel.fetcher import FetchError, Fetcher, FetchResponse

Answer = Union[FetchResponse, Exception, bytes]


@dataclass
class FakeFetcher(Fetcher):
    """Answers from a table; records every request. Unknown URLs fail."""

    answers: Dict[str, Answer] = field(default_factory=dict)
    requests: List[Tuple[str, str, str]] = field(default_factory=list)

    def get(self, url: str, etag: str = "", last_modified: str = "") -> FetchResponse:
        self.requests.append((url, etag, last_modified))
        answer = self.answers.get(url)
        if answer is None:
            raise FetchError("no route to host")
        if isinstance(answer, Exception):
            raise answer
        if isinstance(answer, bytes):
            return FetchResponse(status=200, body=answer)
        return answer

    @property
    def urls(self) -> List[str]:
        return [url for url, _, _ in self.requests]
