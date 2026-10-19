"""公式掲載hrefのpath ASCII spaceを通信URLへ最小導出する（ADR 0299）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
network・公式性・request grant・内容／適合を発行せず、既存URL検査を緩和しない。
"""
from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

import collector_registry as cr

TRANSFORMATION = 'PATH_ASCII_SPACE_PERCENT20_V1'


def href_text(value: object) -> str:
    """urljoinが除去する先頭空白／controlを解決前に拒否する。"""
    cr.require(type(value) is str and 0 < len(value) <= 2048, 'HREF_TYPE_OR_SIZE')
    cr.require(not value[0].isspace() and not any(ord(char) < 32 or ord(char) == 127 or
        (char.isspace() and char != ' ') for char in value) and '\\' not in value and
        not cr.PRIVATE_TEXT.search(value), 'HREF_UNSAFE_TEXT')
    return value


def path_space_url(value: object) -> str:
    """queryless HTTPS pathだけを一回変換し、既存public_urlで結果を検査する。"""
    value = href_text(value)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise cr.RegistryError('HREF_URL_SYNTAX') from error
    cr.require(value.startswith('https://') and parsed.scheme == 'https' and parsed.netloc and
        parsed.username is None and parsed.password is None and port in (None, 443) and
        ' ' not in parsed.netloc and not parsed.query and '?' not in value and
        not parsed.fragment and '#' not in value, 'HREF_COMPONENT_POLICY')
    cr.require(re.search(r'%(?![0-9a-fA-F]{2})', parsed.path) is None and
        re.search(r'%25[0-9a-fA-F]{2}', parsed.path, re.IGNORECASE) is None, 'HREF_PERCENT_POLICY')
    # percent tripletをdecodeせず、元path中のASCII spaceだけを変える。
    wire_url = 'https://' + parsed.netloc + parsed.path.replace(' ', '%20')
    cr.public_url(wire_url, purpose='PAYLOAD')
    return wire_url


def resolve_published_href(base: str, value: object) -> tuple[str, str]:
    """relative hrefを解決し、原解決hrefとwire URLを返す。呼出側のprofile検査は必須。"""
    value = href_text(value)
    resolved = urljoin(base, value)
    # 空白のない既存query/profileは呼出側の従来validatorへ渡し、ここでは拡張しない。
    return resolved, path_space_url(resolved) if ' ' in resolved else resolved
