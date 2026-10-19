"""日次保守監視の有限HTTPS transport。Production grantを発行しない（ADR 0229／0233／0236／0237）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Registryにないhrefを追跡せず、HTML本文・header・例外本文を永続化しない。
"""
from __future__ import annotations

from html.parser import HTMLParser
import ctypes
import ipaddress
import json
import os
import fnmatch
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time
from urllib.parse import unquote, urlsplit

import collector_registry as cr
import collector_public_locators as pl
import collector_published_hrefs as hrefs
import collector_page_encoding as encoding


MAX_BODY = 2 * 1024 * 1024
MAX_HEADERS = 128 * 1024

# 同梱._pthでも親のsys.pathへ依存せず、固定兄弟moduleだけを解決する。
DNS_BOOTSTRAP = (
    "import sys;from pathlib import Path;p=Path(sys.argv[1]);"
    "sys.path[:]=[str(p/'runtime'/'python313.zip'),str(p/'runtime'),str(p/'scripts')];"
    "import registry_monitor_http as h;sys.exit(h.resolve_main(sys.argv[2:]))"
)
ROUTE_BOOTSTRAP = (
    "import sys;from pathlib import Path;p=Path(sys.argv[1]);"
    "sys.path[:]=[str(p/'runtime'/'python313.zip'),str(p/'runtime'),str(p/'scripts')];"
    "import registry_monitor_http as h;sys.exit(h.route_main(sys.argv[2:]))"
)
PROXY_ERRORS = {"PROXY_ROUTE_UNSUPPORTED", "PROXY_AUTH_UNSUPPORTED", "PROXY_CONFIG_FAILED",
                "PROXY_RESOLUTION_FAILED", "PROXY_RESOLUTION_TIMEOUT"}


def proxy_endpoint(value: str, *, default_port: int = 80) -> str:
    """単一HTTP/HTTPS proxyだけを正規化し、credentialや任意argvを受けない。"""
    cr.require(type(value) is str and 0 < len(value) <= 4096 and
               not any(ord(c) <= 32 or ord(c) >= 127 for c in value), "PROXY_ROUTE_UNSUPPORTED")
    try:
        parsed = urlsplit(value if "://" in value else "http://" + value)
        parsed_port = parsed.port
    except ValueError:
        raise cr.RegistryError("PROXY_ROUTE_UNSUPPORTED") from None
    cr.require(parsed.username is None and parsed.password is None, "PROXY_AUTH_UNSUPPORTED")
    cr.require(parsed.scheme in {"http", "https"} and parsed.hostname and
               parsed.path in {"", "/"} and not parsed.query and not parsed.fragment and
               not any(c in parsed.hostname for c in "%\\;="), "PROXY_ROUTE_UNSUPPORTED")
    port = parsed_port if parsed_port is not None else (443 if parsed.scheme == "https" else default_port)
    cr.require(0 < port <= 65535, "PROXY_ROUTE_UNSUPPORTED")
    host = "[" + parsed.hostname + "]" if ":" in parsed.hostname else parsed.hostname
    return f"{parsed.scheme}://{host}:{port}"


def bypassed(host: str, value: str | None, *, environment: bool) -> bool:
    """対応する明示bypassを適用し、未知の表現をDIRECTへ読み替えない。"""
    if not value:
        return False
    cr.require(type(value) is str and len(value) <= 4096, "PROXY_ROUTE_UNSUPPORTED")
    tokens = value.split("," if environment else ";")
    result = False
    for raw in tokens:
        token = raw.strip().lower()
        if not token:
            continue
        if token == "<local>" and not environment:
            result |= "." not in host
            continue
        cr.require(not any(c in token for c in "/@\\<>?") and
                   (not environment or "*" not in token or token == "*"), "PROXY_ROUTE_UNSUPPORTED")
        if token == "*":
            result = True
            continue
        if token.endswith(":443"):
            token = token[:-4]
        cr.require(":" not in token, "PROXY_ROUTE_UNSUPPORTED")
        token = token.lstrip(".")
        result |= (host == token or host.endswith("." + token)) if environment else fnmatch.fnmatchcase(host, token)
    return result


def windows_proxy_configuration(url: str) -> dict:
    """OS/per-user/PACを正式照会し、解決失敗をDIRECTへfallbackしない。

    固定route子だけから呼び、親が5秒で打ち切る。返却値はRAM内だけで保持する。
    """
    from ctypes import wintypes
    class ProxyInfo(ctypes.Structure):
        """WinHTTPの固定出力ABIとしてaccess種別とproxy/bypass文字列pointerを保持する。

        三fieldの型と順序を維持する。文字列は呼出し中にPython strへcopyし、
        API割当pointerは親関数のfinallyでGlobalFreeする。
        """
        _fields_ = [("access", wintypes.DWORD), ("proxy", ctypes.c_void_p), ("bypass", ctypes.c_void_p)]
    class UserConfig(ctypes.Structure):
        """WinHTTPのuser設定出力ABIとしてauto検出とPAC url/proxy/bypassを保持する。

        四fieldの型と順序を維持する。auto/urlで自動経路を選び、必要な文字列をcopyした後、
        API割当の三pointerは親関数のfinallyでGlobalFreeする。
        """
        _fields_ = [("auto", wintypes.BOOL), ("url", ctypes.c_void_p),
                    ("proxy", ctypes.c_void_p), ("bypass", ctypes.c_void_p)]
    class AutoOptions(ctypes.Structure):
        """WinHttpGetProxyForUrlへ渡すflags/detect/PAC urlの固定入力ABIを保持する。

        reserved=None、reservedFlags=0、autoLogon=Falseも配置に必要なfieldとして残す。
        PAC文字列は同じ同期API呼出し中だけ入力として使用する。
        """
        _fields_ = [("flags", wintypes.DWORD), ("detect", wintypes.DWORD),
                    ("url", wintypes.LPCWSTR), ("reserved", ctypes.c_void_p),
                    ("reservedFlags", wintypes.DWORD), ("autoLogon", wintypes.BOOL)]
    api = ctypes.WinDLL("winhttp", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.GlobalFree.argtypes = [ctypes.c_void_p]
    api.WinHttpGetIEProxyConfigForCurrentUser.argtypes = [ctypes.POINTER(UserConfig)]
    api.WinHttpGetDefaultProxyConfiguration.argtypes = [ctypes.POINTER(ProxyInfo)]
    api.WinHttpOpen.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.DWORD]
    api.WinHttpOpen.restype = wintypes.HANDLE
    api.WinHttpCloseHandle.argtypes = [wintypes.HANDLE]
    api.WinHttpSetTimeouts.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int]
    api.WinHttpGetProxyForUrl.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                        ctypes.POINTER(AutoOptions), ctypes.POINTER(ProxyInfo)]
    user = UserConfig()
    default = ProxyInfo()
    resolved = ProxyInfo()
    session = None
    try:
        cr.require(api.WinHttpGetIEProxyConfigForCurrentUser(ctypes.byref(user)) and
                   api.WinHttpGetDefaultProxyConfiguration(ctypes.byref(default)), "PROXY_CONFIG_FAILED")
        if user.auto or user.url:
            session = api.WinHttpOpen("DriverCrate-maintenance-route/1", 1, None, None, 0)
            cr.require(session and api.WinHttpSetTimeouts(session, 3000, 3000, 3000, 3000), "PROXY_CONFIG_FAILED")
            options = AutoOptions((1 if user.auto else 0) | (2 if user.url else 0),
                                  3 if user.auto else 0, ctypes.wstring_at(user.url) if user.url else None,
                                  None, 0, False)
            cr.require(api.WinHttpGetProxyForUrl(session, url, ctypes.byref(options), ctypes.byref(resolved)),
                       "PROXY_RESOLUTION_FAILED")
            cr.require(resolved.access in {1, 3}, "PROXY_ROUTE_UNSUPPORTED")
            return {"source":"AUTO", "proxy":ctypes.wstring_at(resolved.proxy) if resolved.proxy else None,
                    "bypass":ctypes.wstring_at(resolved.bypass) if resolved.bypass else None,
                    "direct":resolved.access == 1}
        if user.proxy:
            return {"source":"USER", "proxy":ctypes.wstring_at(user.proxy),
                    "bypass":ctypes.wstring_at(user.bypass) if user.bypass else None, "direct":False}
        cr.require(default.access in {1, 3}, "PROXY_ROUTE_UNSUPPORTED")
        return {"source":"SYSTEM", "proxy":ctypes.wstring_at(default.proxy) if default.proxy else None,
                "bypass":ctypes.wstring_at(default.bypass) if default.bypass else None,
                "direct":default.access == 1}
    finally:
        if session:
            api.WinHttpCloseHandle(session)
        for value in (user.url, user.proxy, user.bypass, default.proxy, default.bypass, resolved.proxy, resolved.bypass):
            if value:
                kernel.GlobalFree(value)


def resolve_route(url: str, *, environment=None, configuration=None) -> dict:
    """明示環境→per-user/auto→systemの順に一つの実routeを選ぶ。"""
    environment = os.environ if environment is None else environment
    host = urlsplit(url).hostname
    bypass = environment.get("no_proxy", environment.get("NO_PROXY"))
    if bypassed(host, bypass, environment=True):
        return {"source":"ENVIRONMENT", "proxy":""}
    selected = next((environment[name] for name in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY")
                     if environment.get(name)), None)
    if selected is not None:
        proxy = proxy_endpoint(selected, default_port=1080)
        return {"source":"ENVIRONMENT", "proxy":proxy}
    config = (configuration or windows_proxy_configuration)(url)
    cr.require(type(config) is dict and config.get("source") in {"USER", "SYSTEM", "AUTO"} and
               type(config.get("direct")) is bool, "PROXY_CONFIG_FAILED")
    if config["direct"]:
        cr.require(not config.get("proxy"), "PROXY_ROUTE_UNSUPPORTED")
        return {"source":config["source"], "proxy":""}
    value = config.get("proxy")
    cr.require(type(value) is str and value, "PROXY_ROUTE_UNSUPPORTED")
    if "=" in value:
        mapping = {}
        for token in value.split(";"):
            pieces = token.split("=")
            cr.require(len(pieces) == 2 and pieces[0] in {"http", "https", "ftp", "socks"} and
                       pieces[0] not in mapping, "PROXY_ROUTE_UNSUPPORTED")
            mapping[pieces[0]] = pieces[1]
        cr.require("socks" not in mapping, "PROXY_ROUTE_UNSUPPORTED")
        if "https" not in mapping:
            return {"source":config["source"], "proxy":""}
        value = mapping["https"]
    proxy = proxy_endpoint(value)
    return {"source":config["source"], "proxy":"" if bypassed(host, config.get("bypass"), environment=False) else proxy}


def validate_route(route: dict) -> dict:
    """固定子のroute結果を再検査し、未対応表現をcurlへ渡さない。"""
    cr.require(type(route) is dict and set(route) == {"source", "proxy"} and
               route["source"] in {"ENVIRONMENT", "USER", "SYSTEM", "AUTO"} and
               type(route["proxy"]) is str, "PROXY_ROUTE_UNSUPPORTED")
    if route["proxy"]:
        cr.require(proxy_endpoint(route["proxy"]) == route["proxy"], "PROXY_ROUTE_UNSUPPORTED")
    return route


def route_command(package: Path, url: str) -> list[str]:
    """登録URL一つだけを固定route/DNS子へ渡す。"""
    cr.require(type(url) is str and len(url) <= 4096, "URL_TYPE_OR_SIZE")
    return [str(package / "runtime/python.exe"), "-I", "-B", "-S", "-c", ROUTE_BOOTSTRAP, str(package), url]


def route_main(arguments: list[str]) -> int:
    """policy解決失敗ではtarget DNSも行わず、routeと公開宛先だけを親へ返す。"""
    if len(arguments) != 1:
        return 1
    try:
        route = validate_route(resolve_route(arguments[0]))
        addresses = public_addresses(urlsplit(arguments[0]).hostname)
        print(json.dumps({"route":route, "addresses":addresses}, separators=(",", ":")))
        return 0
    except cr.RegistryError as error:
        reason = str(error)
        print(json.dumps({"error":reason if reason in PROXY_ERRORS | {"PRIVATE_DNS", "DNS_EMPTY"} else "DNS_FAILED"}))
        return 2
    except (OSError, ValueError):
        print('{"error":"PROXY_RESOLUTION_FAILED"}')
        return 2


def curl_command(curl: str, kind: str, url: str, route: dict, address: str,
                 headers_path: Path, body_path: Path) -> list[str]:
    """解決済みroute・公開IP・元TLS名を一つの固定argvへ結合する。"""
    validate_route(route)
    parsed = ipaddress.ip_address(address)
    cr.require(parsed.is_global and not parsed.is_multicast and not parsed.is_reserved, "PRIVATE_DNS")
    host = urlsplit(url).hostname
    pinned = f"[{address}]" if ":" in address else address
    arguments = [curl, "-q", "--silent", "--fail", "--proto", "=https", "--max-redirs", "0",
        "--connect-timeout", "5", "--max-time", "20", "--proxy", route["proxy"], "--noproxy", "",
        "--connect-to", f"{host}:443:{pinned}:443", "--dump-header", str(headers_path),
        "--output", str(body_path), "--write-out", "%{http_code}", "--user-agent", "DriverCrate-maintenance-monitor/1"]
    arguments += ["--head"] if kind == "LINK" else ["--max-filesize", str(MAX_BODY)]
    return arguments + [url]


def system_curl_path() -> str:
    """環境やPATHを参照せずOS API起点のSystem32 curlだけを返す。"""
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetSystemDirectoryW(buffer, len(buffer))
    cr.require(0 < length < len(buffer), "SYSTEM_CURL_DIRECTORY")
    return str(Path(buffer.value) / "curl.exe")


def dns_command(package: Path, host: str) -> list[str]:
    """Native固定runtimeと同じisolated bootstrapだけをDNS子へ渡す。"""
    cr.require(type(host) is str and re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host) is not None,
               "DNS_HOST")
    return [str(package / "runtime" / "python.exe"), "-I", "-B", "-S", "-c", DNS_BOOTSTRAP,
            str(package), host]


def resolve_main(arguments: list[str]) -> int:
    """固定bootstrapのhost一個だけを受け、HTTPやfile保存は行わない。"""
    if len(arguments) != 1:
        return 1
    try:
        print(json.dumps(public_addresses(arguments[0])))
        return 0
    except cr.RegistryError:
        return 2
    except (OSError, ValueError):
        return 1


def public_addresses(host: str) -> list[str]:
    """全DNSの公開性確認後、IPv4優先・同familyは数値順の固定候補を返す。"""
    addresses = sorted({item[4][0] for item in socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)})
    cr.require(bool(addresses), "DNS_EMPTY")
    for value in addresses:
        address = ipaddress.ip_address(value)
        cr.require(address.is_global and not address.is_multicast and not address.is_reserved,
                   "PRIVATE_DNS")
        cr.require(not isinstance(address, ipaddress.IPv6Address) or
                   (address.ipv4_mapped is None and address.sixtofour is None and address.teredo is None),
                   "PRIVATE_DNS")
    # private応答を除いて続行せず、全件合格後だけaddress familyを優先する。
    return sorted(addresses, key=lambda value: (ipaddress.ip_address(value).version,
                                                int(ipaddress.ip_address(value))))


def known_payload_path(url: str) -> bool:
    """本体suffixとsuffixなしdp endpointをPAGE要求前に判別する。"""
    path = urlsplit(url).path
    # 共通URL validatorと同じ三層まで読み、本体suffixをpercent表現で迂回させない。
    for _ in range(3):
        path = unquote(path)
    return path.lower().startswith("/dp/") or re.search(
        r"\.(?:exe|msi|zip|7z|rar|cab|iso|bin|img|dmg|deb|rpm|tgz|tar|gz|inf|sys|cat|dll)$", path, re.IGNORECASE) is not None


def literal_navigation_url(value: object) -> str | None:
    """単純な定数URL代入だけを非実行で読む。動的式・余計なstatementは拒否する。"""
    if type(value) is not str or len(value) > 4096:
        return None
    match = re.fullmatch(r"\s*window\.location\s*=\s*(['\"])(https://[^'\"\s]+)\1\s*;\s*return\s+false\s*;\s*", value)
    return match[2] if match else None


class PageLinks(HTMLParser):
    """hrefを観測するだけで、script・base・link先を実行しない。"""

    def __init__(self, base: str, *, allow_public_query: bool = False,
                 registered_links: dict[str, tuple[str, str]] | None = None):
        cr.require(type(allow_public_query) is bool, "URL_QUERY_MODE")
        cr.require(registered_links is None or isinstance(registered_links, dict), "LOCATOR_LINK_PROFILES")
        self.registered_links = dict(registered_links or {})
        for url, spec in self.registered_links.items():
            cr.require(isinstance(spec, tuple) and len(spec) == 2, "LOCATOR_LINK_PROFILE")
            pl.public_locator_url(url, profile=spec[0], purpose=spec[1])
        super().__init__(convert_charrefs=True)
        self.base = base
        self.allow_public_query = allow_public_query
        self.links = set()
        # 変換した属性href／解決href／wire URLをRAM内だけへ保持する。
        self.derived_links = set()
        self.html = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() in {"html", "body", "main", "section", "article", "div", "a", "p", "table"}:
            self.html = True
        if tag.lower() == "base":
            return
        for name, value in attrs:
            # 固定形のhandlerを読むだけで実行せず、同意やURL要求へ昇格しない。
            if name.lower() == "onclick":
                value = literal_navigation_url(value)
                name = "href"
            if name.lower() in {"href", "data-href", "data-url"} and value:
                try:
                    resolved, wire_url = hrefs.resolve_published_href(self.base, value)
                    if wire_url in self.registered_links:
                        profile, purpose = self.registered_links[wire_url]
                        pl.public_locator_url(wire_url, profile=profile, purpose=purpose)
                    else:
                        # 本体hrefは観測だけに使い、PAGE GETの許可へ昇格させない。
                        cr.public_url(wire_url, allow_public_query=self.allow_public_query, purpose="PAYLOAD")
                except cr.RegistryError:
                    continue
                self.links.add(cr.digest(wire_url.encode("utf-8")))
                if wire_url != resolved:
                    self.derived_links.add((value, resolved, wire_url))


def response(status: int | None = None, error: str = "NONE", body: bytes = b"",
             links: list[str] | None = None, retry_after: str | None = None) -> dict:
    """取得の成否を本文非保持の観測値へ射影する。"""
    return {"status": status, "error": error, "bodySha256": cr.digest(body) if body else None,
            "bodyBytes": len(body), "linkHashes": links or [], "retryAfter": retry_after}


class CurlTransport:
    """DNS／HTTPSを子processの時間上限内で行い、同hostへの要求間隔を空ける。"""

    def __init__(self, *, allow_public_query: bool = False, registry: dict | None = None,
                 public_locators: dict | None = None, held_source_ids: tuple[str, ...] = (),
                 research_page_profiles: dict[str, tuple[str, str]] | None = None,
                 package: Path | None = None, curl_path: str | None = None, process_gate=None, route_gate=None):
        cr.require(type(allow_public_query) is bool, "URL_QUERY_MODE")
        self.allow_public_query = allow_public_query
        self.last_finished = {}
        self.registered_links = {}
        self.blocked_locator_urls = set()
        self.source_page_urls = set()
        self.registry_bound = public_locators is not None
        self.package = package
        self.curl_path = curl_path
        self.process_gate = process_gate
        self.route_gate = route_gate or getattr(getattr(process_gate, "__self__", None), "bind_route", None)
        cr.require(type(held_source_ids) is tuple and all(type(value) is str for value in held_source_ids),
                   "LOCATOR_HELD_SOURCES")
        cr.require(research_page_profiles is None or (type(research_page_profiles) is dict and
                   0 < len(research_page_profiles) <= 16), "RESEARCH_PAGE_MAP")
        # 初回研究mapは未取得PAGEの表現だけであり、registry-bound運用へ混ぜない。
        cr.require(research_page_profiles is None or public_locators is None, "RESEARCH_PAGE_MODE")
        if public_locators is None:
            cr.require(registry is None and not held_source_ids, "LOCATOR_TRANSPORT_BINDING")
            for url, spec in (research_page_profiles or {}).items():
                cr.require(isinstance(spec, tuple) and len(spec) == 2 and
                           spec[0] == "PUBLIC_PRODUCT_PID", "RESEARCH_PAGE_PROFILE")
                source_root = cr.public_url(spec[1])
                pl.public_locator_url(url, profile=spec[0], purpose="PAGE")
                root = urlsplit(source_root)
                page = urlsplit(url)
                cr.require(root.hostname == page.hostname and (root.port or 443) == (page.port or 443),
                           "RESEARCH_PAGE_ORIGIN")
                cr.require(not known_payload_path(url) and not known_payload_path(source_root),
                           "PAGE_PAYLOAD_ENDPOINT")
                self.registered_links[url] = (spec[0], "PAGE")
        else:
            registry = cr.validate_registry(registry)
            public_locators = pl.validate_locators(public_locators, registry)
            self.source_page_urls = {row["officialPage"] for row in registry["sources"]}
            self.blocked_locator_urls.update(row["downloadUrl"] for row in registry["records"]
                                             if row["downloadUrl"] is not None)
            cr.require(set(held_source_ids) <= {row["id"] for row in registry["sources"]}, "LOCATOR_HELD_SOURCES")
            for locator in public_locators["locators"]:
                url = locator["url"]
                cr.require(url not in self.registered_links, "LOCATOR_MONITOR_PURPOSE_COLLISION")
                self.registered_links[url] = (locator["urlProfile"], locator["purpose"])
                if locator["purpose"] == "PAYLOAD" or locator["sourceId"] in held_source_ids:
                    self.blocked_locator_urls.add(url)
            # Locatorと同じURLを別の保留sourceが共有していても、その保留を維持する。
            held_urls = {row["officialPage"] for row in registry["sources"] if row["id"] in held_source_ids}
            held_urls.update(row["downloadUrl"] for row in registry["records"]
                             if row["sourceId"] in held_source_ids and row["downloadUrl"] is not None)
            self.blocked_locator_urls.update(held_urls)

    def __call__(self, kind: str, url: str) -> dict:
        """instanceを直列利用し、host待機時計を更新して有限のHTTP観測を返す。

        DNS子は5秒、curl子は22秒で待機を打ち切り、temporary body/headerはwithで
        後始末する。try前の入力拒否は例外、try内の捕捉対象の通信/解析失敗は固定応答へ
        変換する。finallyで完了時計を更新するため、同instanceの並行利用はしない。
        """
        # 誤ったkindをGETへ読み替えず、URL契約とともに通信前に拒否する。
        cr.require(type(kind) is str and kind in {"PAGE", "LINK"}, "REQUEST_KIND")
        cr.require(isinstance(url, str), "URL_TYPE_OR_SIZE")
        # 保守PAGEを本体取得へ転用せず、登録graphにない頁を自動追跡しない。
        cr.require(url not in self.blocked_locator_urls, "LOCATOR_REQUEST_HELD")
        cr.require(kind != "PAGE" or not known_payload_path(url), "PAGE_PAYLOAD_ENDPOINT")
        if url in self.registered_links:
            cr.require(url not in self.blocked_locator_urls, "LOCATOR_REQUEST_HELD")
            profile, purpose = self.registered_links[url]
            cr.require(kind == "PAGE" and purpose == "PAGE", "LOCATOR_REQUEST_PURPOSE")
            pl.public_locator_url(url, profile=profile, purpose=purpose)
        else:
            cr.require(not self.registry_bound or (kind == "PAGE" and url in self.source_page_urls),
                       "LOCATOR_PAGE_NOT_REGISTERED")
            cr.public_url(url, allow_public_query=self.allow_public_query,
                          purpose="PAYLOAD" if kind == "LINK" else "PAGE")
            # Basenameの保存契約を自動HEAD／GET許可へ昇格させず、旧数値modeだけを維持する。
            if "?" in url:
                cr.require(cr.public_numeric_query(urlsplit(url).query,
                    purpose="PAYLOAD" if kind == "LINK" else "PAGE"), "URL_QUERY_POLICY")
        host = urlsplit(url).hostname
        if host in self.last_finished:
            time.sleep(max(0.0, 1.0 - (time.monotonic() - self.last_finished[host])))
        try:
            # DNS解決の停滞も子process timeoutへ含め、例外のhost/pathを出力しない。
            # v5はnativeの実handle/署名検証済みpathへ結合し、旧手動経路もPATH探索しない。
            curl = system_curl_path()
            cr.require(self.curl_path is None or self.curl_path == curl, "SYSTEM_CURL_PATH")
            dns_args = (route_command(self.package, url) if self.package is not None else
                        [sys.executable, "-I", "-B", "-S", "-c",
                         "import sys;sys.path.insert(0,sys.argv[1]);import registry_monitor_http as h;"
                         "sys.exit(h.route_main(sys.argv[2:]))", str(Path(__file__).resolve().parent), url])
            if self.process_gate:
                self.process_gate(dns_args)
            dns = subprocess.run(dns_args, executable=dns_args[0], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                 timeout=5, check=False)
            if dns.returncode:
                failed = json.loads(dns.stdout) if dns.stdout else {}
                reason = failed.get("error", "DNS_FAILED")
                cr.require(reason in PROXY_ERRORS | {"PRIVATE_DNS", "DNS_EMPTY", "DNS_FAILED"}, "DNS_RESULT")
                return response(error=reason)
            resolved = json.loads(dns.stdout)
            cr.require(type(resolved) is dict and set(resolved) == {"route", "addresses"}, "DNS_RESULT")
            route = validate_route(resolved["route"])
            addresses = resolved["addresses"]
            cr.require(type(addresses) is list and 0 < len(addresses) <= 128 and
                       all(type(value) is str and ipaddress.ip_address(value).is_global and
                           not ipaddress.ip_address(value).is_multicast and
                           not ipaddress.ip_address(value).is_reserved for value in addresses), "DNS_RESULT")
            address = addresses[0]
            if self.route_gate:
                self.route_gate(url, route, address)
            with tempfile.TemporaryDirectory(prefix="drivercrate-monitor-http-") as folder:
                body_path = Path(folder) / "body"
                headers_path = Path(folder) / "headers"
                args = curl_command(curl, kind, url, route, address, headers_path, body_path)
                if self.process_gate:
                    self.process_gate(args)
                result = subprocess.run(args, executable=args[0], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        timeout=22, check=False)
                status = int(result.stdout) if result.stdout.isdigit() else None
                if status is not None and not 100 <= status <= 599:
                    status = None
                headers = b""
                if headers_path.exists():
                    with headers_path.open("rb") as stream:
                        headers = stream.read(MAX_HEADERS + 1)
                if len(headers) > MAX_HEADERS:
                    return response(status, "HEADER_SIZE")
                # CONNECT／interim responseがあっても最後のheader blockだけを調べる。
                blocks = [part for part in headers.split(b"\r\n\r\n") if part.startswith(b"HTTP/")]
                values = {}
                for line in (blocks[-1].split(b"\r\n")[1:] if blocks else []):
                    if b":" in line:
                        name, value = line.split(b":", 1)
                        values.setdefault(name.lower(), []).append(value.strip().decode("latin-1"))
                retry_values = values.get(b"retry-after", [])
                retry_after = retry_values[0] if len(retry_values) == 1 else ("INVALID" if retry_values else None)
                if result.returncode or status != 200:
                    reason = "PROXY_AUTH_UNSUPPORTED" if status == 407 else "BODY_SIZE" if result.returncode == 63 else "TIMEOUT" if result.returncode == 28 else (
                        "HTTP_ERROR" if status is not None and status != 200 else "TRANSFER_FAILED")
                    return response(status, reason, retry_after=retry_after)
                if kind == "LINK":
                    return response(200)
                with body_path.open("rb") as stream:
                    body = stream.read(MAX_BODY + 1)
                if not body or len(body) > MAX_BODY:
                    return response(200, "BODY_SIZE")
                content_types = values.get(b"content-type", [])
                if len(content_types) != 1 or content_types[0].split(";", 1)[0].strip().lower() not in {
                        "text/html", "application/xhtml+xml"}:
                    return response(200, "CONTENT_TYPE", body)
                if values.get(b"content-encoding", ["identity"]) != ["identity"]:
                    return response(200, "CONTENT_ENCODING", body)
                try:
                    # 明示宣言を共通strict decoderで読み、codec推定や元byteの置換を行わない。
                    text = encoding.decode_page(body, content_types[0])
                except encoding.PageEncodingError:
                    return response(200, "TEXT_ENCODING", body)
                parser = PageLinks(url, allow_public_query=self.allow_public_query, registered_links=self.registered_links)
                parser.feed(text)
                parser.close()
                if not parser.html:
                    return response(200, "HTML_STRUCTURE", body)
                return response(200, body=body, links=sorted(parser.links))
        except subprocess.TimeoutExpired:
            return response(error="TIMEOUT")
        except cr.RegistryError as error:
            return response(error=str(error) if str(error) in PROXY_ERRORS else "TRANSPORT_FAILED")
        except (OSError, ValueError, KeyError, IndexError):
            return response(error="TRANSPORT_FAILED")
        finally:
            self.last_finished[host] = time.monotonic()


if __name__ == "__main__":
    # この入口はDNS検証だけを子processへ分離し、HTTP・file保存を行わない。
    if len(sys.argv) != 3 or sys.argv[1] != "--resolve":
        sys.exit(1)
    try:
        print(json.dumps(public_addresses(sys.argv[2])))
    except cr.RegistryError:
        sys.exit(2)
    except (OSError, ValueError):
        sys.exit(1)
