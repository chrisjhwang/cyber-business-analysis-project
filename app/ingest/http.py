"""A small HTTP client that is polite to rate-limited APIs.

Two separate behaviours, often confused:

1. Pacing (proactive): never send requests faster than `min_interval` seconds
   apart. This keeps us under NVD's published limit so we are not blocked in
   the first place.
2. Retrying (reactive): if the server still says "slow down" (NVD sends 403,
   most APIs send 429) or has a transient failure (5xx, timeout), wait with
   exponential backoff and try again rather than crashing a long ingestion run
   on one bad response.

`sleep` and `clock` are injectable so tests can check the timing logic
without actually waiting.
"""
import logging
import time
from collections.abc import Callable
from typing import Any

import httpx

log = logging.getLogger(__name__)

# NVD answers 403 when you exceed the rate limit. It also answers 403 for a
# bad API key, which retrying will not fix, but the final error says so.
RETRYABLE_STATUS = {403, 429, 500, 502, 503, 504}


class FetchError(RuntimeError):
    """An HTTP fetch failed permanently or ran out of retries."""


class RateLimitedClient:
    def __init__(
        self,
        *,
        min_interval: float = 0.0,
        max_retries: int = 5,
        backoff_base: float = 2.0,
        timeout: float = 60.0,
        headers: dict[str, str] | None = None,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.min_interval = min_interval
        self.max_retries = max_retries
        self.backoff_base = backoff_base
        self._sleep = sleep
        self._clock = clock
        self._last_request: float | None = None
        self._client = httpx.Client(
            timeout=timeout, headers=headers, transport=transport, follow_redirects=True
        )

    def __enter__(self) -> "RateLimitedClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._client.close()

    def _wait_for_slot(self) -> None:
        if self._last_request is None:
            return
        remaining = self.min_interval - (self._clock() - self._last_request)
        if remaining > 0:
            self._sleep(remaining)

    def get_json(self, url: str, params: dict[str, Any] | None = None) -> Any:
        for attempt in range(self.max_retries + 1):
            self._wait_for_slot()
            self._last_request = self._clock()
            retry_after = None
            try:
                response = self._client.get(url, params=params)
            except httpx.TransportError as exc:
                reason = f"{type(exc).__name__}: {exc}"
            else:
                if response.status_code == 200:
                    return response.json()
                if response.status_code not in RETRYABLE_STATUS:
                    raise FetchError(
                        f"GET {response.url} -> HTTP {response.status_code}: "
                        f"{response.text[:200]}"
                    )
                reason = f"HTTP {response.status_code}"
                retry_after = _retry_after_seconds(response)

            if attempt == self.max_retries:
                raise FetchError(
                    f"GET {url} failed after {self.max_retries + 1} attempts (last: {reason})"
                )
            delay = retry_after if retry_after is not None else self.backoff_base * 2**attempt
            log.warning("GET %s: %s, retrying in %.1fs", url, reason, delay)
            self._sleep(delay)
        raise AssertionError("unreachable")


def _retry_after_seconds(response: httpx.Response) -> float | None:
    value = response.headers.get("Retry-After")
    try:
        return float(value) if value is not None else None
    except ValueError:
        return None  # HTTP-date form; fall back to exponential backoff
