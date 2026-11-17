"""Cookie middleware using Python's standard-library cookie jar."""

from email.message import Message
from http.client import HTTPResponse
from http.cookiejar import CookieJar, DefaultCookiePolicy
from typing import cast
from urllib.request import Request as URLRequest

from ..core.headers import Headers
from ..core.request import Request
from .transport import SendContext, Transport

__all__ = ["CookieMiddleware"]


class _CookieResponse:
    def __init__(self, headers: Headers):
        self._message = Message()
        for value in headers.get_all("Set-Cookie"):
            self._message["Set-Cookie"] = value

    def info(self):
        return self._message


class CookieMiddleware(Transport):
    """Store cookies and apply them only to requests in their declared scope."""

    def __init__(self, transport: Transport, cookies: CookieJar | None = None):
        self._transport = transport
        self.cookies = (
            cookies
            if cookies is not None
            else CookieJar(
                policy=DefaultCookiePolicy(
                    strict_ns_domain=DefaultCookiePolicy.DomainStrictNonDomain
                )
            )
        )

    def send(self, request: Request) -> SendContext:
        url_request = URLRequest(str(request.url), method=str(request.method))
        if "Cookie" not in request.headers:
            self.cookies.add_cookie_header(url_request)
            cookie_value = url_request.get_header("Cookie")
            if cookie_value:
                request = Request(
                    request.method,
                    request.url,
                    headers=request.headers.copy_set("Cookie", cookie_value),
                    content=request.content,
                )

        ctx = self._transport.send(request)
        if ctx[1].get_all("Set-Cookie"):
            self.cookies.extract_cookies(
                cast(HTTPResponse, _CookieResponse(ctx[1])), url_request
            )
        return ctx

    def close(self) -> None:
        self._transport.close()
