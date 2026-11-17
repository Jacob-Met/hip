from http.cookiejar import CookieJar

import hip
from hip.client.base import CookieMiddleware, RedirectMiddleware
from hip.client.transport import SendContext, Transport


class MemoryStream(hip.Stream):
    def read(self, size=-1):
        return b""

    def close(self):
        pass


class RecordingTransport(Transport):
    def __init__(self):
        self.seen = []
        self.responses = {}

    def send(self, request):
        self.seen.append(request)
        status, headers = self.responses.get(request.url.path, (200, []))
        return SendContext(
            (hip.StatusCode(status), hip.Headers(headers), MemoryStream())
        )


def test_duplicate_set_cookie_roundtrip_and_immutable_edits():
    source = hip.Headers(
        [
            ("Set-Cookie", "a=1; Path=/"),
            ("Set-Cookie", "b=2; Path=/"),
            ("X-Test", "yes"),
        ]
    )
    assert source.get_all("set-cookie") == ["a=1; Path=/", "b=2; Path=/"]
    assert source.as_byte_pairs()[:2] == [
        (b"Set-Cookie", b"a=1; Path=/"),
        (b"Set-Cookie", b"b=2; Path=/"),
    ]
    assert hip.Headers(source).get_all("Set-Cookie") == source.get_all("Set-Cookie")
    assert source.copy_set("set-cookie", "c=3").get_all("set-cookie") == ["c=3"]
    assert source.copy_remove("set-cookie").get_all("Set-Cookie") == []
    assert source.copy_update(
        hip.Headers([("Set-Cookie", "x=1"), ("Set-Cookie", "y=2")])
    ).get_all("set-cookie") == ["x=1", "y=2"]
    assert source.get_all("Set-Cookie") == ["a=1; Path=/", "b=2; Path=/"]


def test_cookie_jar_scope_security_and_expiry():
    transport = RecordingTransport()
    transport.responses["/set"] = (
        200,
        [
            ("Set-Cookie", "sid=abc; Path=/; Secure; HttpOnly"),
            ("Set-Cookie", "private=yes; Path=/private"),
            ("Set-Cookie", "domain=shared; Domain=example.test; Path=/"),
            ("Set-Cookie", "intruder=no; Domain=evil.test; Path=/"),
        ],
    )
    cookies = CookieMiddleware(transport)

    def do(url, headers=None):
        with cookies.send(hip.Request("GET", url, headers)):
            pass
        return transport.seen[-1].headers.get("Cookie", "")

    assert do("https://example.test/set") == ""
    received = do("https://example.test/private/one")
    assert all(s in received for s in ["sid=abc", "private=yes", "domain=shared"])
    assert "intruder=no" not in received
    assert "sid=abc" not in do("http://example.test/private/one")
    assert "private=yes" not in do("https://example.test/public")
    shared = do("https://sub.example.test/public")
    assert "domain=shared" in shared and "sid=abc" not in shared
    assert do("https://evil.test/public") == ""
    assert do("https://example.test/public", {"Cookie": "manual=1"}) == "manual=1"
    transport.responses["/delete"] = (
        200,
        [("Set-Cookie", "sid=gone; Path=/; Secure; Max-Age=0")],
    )
    do("https://example.test/delete")
    assert "sid=abc" not in do("https://example.test/private/one")


def test_cookies_across_redirect_without_credential_leak():
    transport = RecordingTransport()
    transport.responses["/start"] = (
        302,
        [("Location", "/next"), ("Set-Cookie", "sid=abc; Path=/; Secure")],
    )
    transport.responses["/jump"] = (302, [("Location", "https://evil.test/landing")])
    transport.responses["/next"] = (200, [])
    chain = RedirectMiddleware(CookieMiddleware(transport))
    with chain.send(hip.Request("GET", "https://example.test/start")):
        pass
    assert "sid=abc" in transport.seen[-1].headers["Cookie"]
    with chain.send(
        hip.Request(
            "GET",
            "https://example.test/jump",
            {"Cookie": "explicit=1", "Authorization": "Bearer secret"},
        )
    ):
        pass
    leaked = transport.seen[-1].headers
    assert transport.seen[-1].url.host == "evil.test"
    assert "Cookie" not in leaked and "Authorization" not in leaked
    assert leaked["Host"] == "evil.test"


def test_client_default_cookie_middleware(monkeypatch):
    from hip.client import base

    transport = RecordingTransport()
    transport.responses["/login"] = (
        200,
        [("Set-Cookie", "session=123; Path=/")],
    )
    monkeypatch.setattr(base, "ConnectionPool", lambda: transport)
    with hip.Client() as client:
        assert isinstance(client.cookies, CookieJar)
        client.get("https://example.test/login")
        client.get("https://example.test/account")
    assert transport.seen[-1].headers["Cookie"] == "session=123"


def test_real_http_cookie_roundtrip():
    def app(request):
        if request.url.path == "/set":
            return hip.Response(
                200,
                headers=hip.Headers(
                    [
                        ("Set-Cookie", "alpha=one; Path=/"),
                        ("Set-Cookie", "beta=two; Path=/"),
                    ]
                ),
            )
        return hip.Response(
            200, content=hip.Text(request.headers.get("Cookie", "none"))
        )

    with hip.Server(app) as server, hip.Client() as client:
        response = client.get(server.url + "set")
        assert response.headers.get_all("Set-Cookie") == [
            "alpha=one; Path=/",
            "beta=two; Path=/",
        ]
        response = client.get(server.url + "account")
        assert "alpha=one" in response.body.decode()
        assert "beta=two" in response.body.decode()
