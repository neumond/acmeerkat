from collections import abc
from dataclasses import dataclass
from typing import Literal
from urllib.request import Request, urlopen
from urllib.error import HTTPError

from acmeerkat import BaseHttpsClient


__all__ = ('UrllibHttpsClient', )


@dataclass
class UrllibHttpsClient(BaseHttpsClient):
    debug: bool = False
    timeout: float = 10.0

    def request(
        self,
        method: Literal['GET', 'POST', 'HEAD', 'DELETE'],
        url: str,
        send_body: bytes | None,
        send_headers: dict[str, str],
        return_headers: abc.Iterable[str],
    ) -> tuple[int, bytes | None, dict[str, str]]:
        if self.debug:
            print('===========')
            print('REQUEST', method, url)
            for k, v in send_headers.items():
                print(f'    {k}: {v}')
            print(f'    {send_body!r}')
        req = Request(url, method=method, headers=send_headers, data=send_body)
        try:
            resp = urlopen(req, timeout=self.timeout)
        except HTTPError as e:
            resp = e
        hdrs = {}
        for h in return_headers:
            if (v := resp.getheader(h)):
                hdrs[h] = v
        body = None if method == 'HEAD' else resp.read()
        if self.debug:
            print('RESPONSE', resp.status)
            for k, v in hdrs.items():
                print(f'    {k}: {v}')
            print(f'    {body!r}')
        return (
            resp.status,
            body,
            hdrs)
