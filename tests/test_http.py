"""Retry and pacing logic, with a fake transport and a fake clock: no network,
no real waiting."""
import httpx
import pytest

from app.ingest.http import FetchError, RateLimitedClient


def make_client(responses, **kwargs):
    """responses: a list of httpx.Response, or exceptions to raise, in order."""
    calls: list[httpx.Request] = []
    sleeps: list[float] = []

    def handler(request):
        calls.append(request)
        item = responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    client = RateLimitedClient(
        transport=httpx.MockTransport(handler),
        sleep=sleeps.append,
        clock=lambda: 0.0,  # time never advances, so pacing always has to sleep
        **kwargs,
    )
    return client, calls, sleeps


def test_retries_rate_limit_then_succeeds():
    client, calls, sleeps = make_client(
        [httpx.Response(403), httpx.Response(200, json={"ok": True})], backoff_base=2.0
    )
    assert client.get_json("https://example.test/x") == {"ok": True}
    assert len(calls) == 2
    assert sleeps == [2.0]


def test_backoff_is_exponential_and_gives_up():
    client, calls, sleeps = make_client(
        [httpx.Response(503)] * 3, max_retries=2, backoff_base=2.0
    )
    with pytest.raises(FetchError, match="after 3 attempts"):
        client.get_json("https://example.test/x")
    assert len(calls) == 3
    assert sleeps == [2.0, 4.0]


def test_retry_after_header_is_honored():
    client, _, sleeps = make_client(
        [httpx.Response(429, headers={"Retry-After": "7"}), httpx.Response(200, json={})]
    )
    client.get_json("https://example.test/x")
    assert sleeps == [7.0]


def test_client_errors_are_not_retried():
    client, calls, sleeps = make_client([httpx.Response(404, text="nope")])
    with pytest.raises(FetchError, match="404"):
        client.get_json("https://example.test/x")
    assert len(calls) == 1
    assert sleeps == []


def test_network_errors_are_retried():
    client, calls, _ = make_client(
        [httpx.ConnectError("boom"), httpx.Response(200, json={"ok": 1})], backoff_base=1.0
    )
    assert client.get_json("https://example.test/x") == {"ok": 1}
    assert len(calls) == 2


def test_requests_are_paced():
    client, _, sleeps = make_client(
        [httpx.Response(200, json={}), httpx.Response(200, json={})], min_interval=6.5
    )
    client.get_json("https://example.test/a")
    client.get_json("https://example.test/b")
    assert sleeps == [6.5]  # no wait before the first request, full interval before the second
