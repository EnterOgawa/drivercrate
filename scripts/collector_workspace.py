"""収集setupの固定bootstrap用workspace／明示monitor adapter（ADR0355／0357）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Nativeが実handle・ACL・payload・receiptを検査してからだけ呼び出す。
現行v7の非通信workspace操作と明示実行を扱う。
既存native writerと保護原点へ結合した非共有PAGEだけを明示一回実行する。
bind済みworkspaceの非通信verify／exportも同じactive原点へ結合する。
monitor一回64要求／32MiB／600秒とnative共有JST日予算は別の制約である。
共有／未知native modeは専用HOLDへ残す。実HTTPの受入は別工程である。
Task、鍵、実端末inventoryは扱わず、明示runの実収集成功は未確認である。
"""
from __future__ import annotations

# 通常importの探索条件は変更せず、直接file起動だけを固定packageへ結合する。
if __name__ == "__main__":
    import sys
    from pathlib import Path

    entry = Path(__file__)
    package = entry.parent.parent
    if (not entry.is_absolute() or entry != entry.resolve(strict=True) or
            entry != package / "scripts/collector_workspace.py" or len(sys.argv) < 2 or
            not Path(sys.argv[1]).is_absolute() or Path(sys.argv[1]) != package or
            not (sys.flags.isolated and sys.flags.no_site and sys.dont_write_bytecode) or
            Path(sys.executable) != package / "runtime/python.exe"):
        raise SystemExit("WORKSPACE_FILE_ENTRY_REJECTED")
    paths = [str(package / "runtime/python313.zip"), str(package / "runtime"), str(package / "scripts")]
    sys.path[:] = paths
    # canonical名で通常importし、Task側と同じ実module originを残す。
    import collector_workspace
    if Path(collector_workspace.__file__) != entry or sys.path != paths:
        raise SystemExit("WORKSPACE_FILE_MODULE_REJECTED")
    raise SystemExit(collector_workspace.main(sys.argv[1:]))

import json
import copy
import ctypes
from ctypes import wintypes
import os
from pathlib import Path
import subprocess
import sys
import registry_monitor_http as http

import collector_locator_snapshot as snapshot
import collector_registry as cr
import registry_daily_monitor as monitor

SCHEMA = "dc-collector-explicit-workspace-v1"
ACTIONS = frozenset({"initialize", "verify", "export", "import", "resume"})
RUN_ACTION = "run-once"
CONTEXT_LIMIT = 256 * 1024
SWITCH_HISTORY_LIMIT = 256


def directory_identity(root: Path) -> str:
    """Windows実directory identityをnativeと同じ式でhashし、path文字列を証明にしない。"""
    class Information(ctypes.Structure):
        """GetFileInformationByHandleの出力を受ける固定layoutである。
        属性とvolume/file indexを読み、未使用の時刻・size・link fieldもABI上の位置を保つために宣言する。
        """
        _fields_ = [("attributes", wintypes.DWORD), ("created", wintypes.FILETIME),
                    ("accessed", wintypes.FILETIME), ("written", wintypes.FILETIME),
                    ("volume", wintypes.DWORD), ("sizeHigh", wintypes.DWORD),
                    ("sizeLow", wintypes.DWORD), ("links", wintypes.DWORD),
                    ("indexHigh", wintypes.DWORD), ("indexLow", wintypes.DWORD)]
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
                               wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE]
    api.CreateFileW.restype = wintypes.HANDLE
    api.GetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.POINTER(Information)]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = api.CreateFileW(str(root), 0x80, 3, None, 3, 0x02200000, None)
    cr.require(handle not in {None, ctypes.c_void_p(-1).value}, "ORIGIN_IDENTITY")
    try:
        value = Information()
        cr.require(api.GetFileInformationByHandle(handle, ctypes.byref(value)) and
                   value.attributes & 0x10 and not value.attributes & 0x400, "ORIGIN_IDENTITY")
        return cr.digest(f"{value.volume}:{(value.indexHigh << 32) | value.indexLow}".encode("ascii"))
    finally:
        api.CloseHandle(handle)


def native_pipe_parent(package: Path, *, pipe=None):
    """継承pipeのserverと固定setup imageを確認し、生存検査を所有callbackとして返す。"""
    import msvcrt
    api = ctypes.WinDLL("kernel32", use_last_error=True)
    api.GetNamedPipeServerProcessId.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.ULONG)]
    api.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    api.OpenProcess.restype = wintypes.HANDLE
    api.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR,
                                              ctypes.POINTER(wintypes.DWORD)]
    api.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    server = wintypes.ULONG()
    pipe = msvcrt.get_osfhandle(sys.stdin.fileno()) if pipe is None else pipe
    cr.require(api.GetNamedPipeServerProcessId(pipe, ctypes.byref(server)) and server.value != os.getpid(),
               "NATIVE_CONTEXT_PIPE")
    handle = api.OpenProcess(0x1000 | 0x100000, False, server.value)
    cr.require(handle, "NATIVE_CONTEXT_PARENT")
    name = ctypes.create_unicode_buffer(32768)
    size = wintypes.DWORD(len(name))
    try:
        cr.require(api.QueryFullProcessImageNameW(handle, 0, name, ctypes.byref(size)) and
                   Path(name.value).samefile(package / "DriverCrateCollectorSetup.exe"), "NATIVE_CONTEXT_IMAGE")
    except Exception:
        api.CloseHandle(handle)
        raise

    def alive():
        """保持した同じprocess HANDLEが稼働中かを確認する。"""
        value = wintypes.DWORD()
        return bool(api.GetExitCodeProcess(handle, ctypes.byref(value)) and value.value == 259)

    def close():
        """借用期間後にparent process HANDLEを一度解放する。"""
        api.CloseHandle(handle)

    return alive, close


class NativeAdmission:
    """固定親から取得した一回だけのcontextをmonitor writer内で消費する。"""

    def __init__(self, document: dict, *, parent_alive, close=lambda: None, identity=directory_identity):
        cr.require(type(document) is dict and document.get("schema") == "dc-collector-live-admission-v1",
                   "NATIVE_CONTEXT_SCHEMA")
        self.document = document
        self.parent_alive = parent_alive
        self.close = close
        self.identity = identity
        self.used = False

    @classmethod
    def read(cls, package: Path):
        """public proof引数を受けず、認証済み継承pipeだけを有限読取りする。"""
        alive, close = native_pipe_parent(package)
        try:
            raw = sys.stdin.buffer.read(CONTEXT_LIMIT + 1)
            cr.require(0 < len(raw) <= CONTEXT_LIMIT, "NATIVE_CONTEXT_SIZE")
            return cls(cr.parse_json(raw), parent_alive=alive, close=close)
        except Exception:
            close()
            raise

    def validate(self, package: Path, root: Path, expected: dict, policy: dict, clock) -> Path:
        """現在のpackage／policy／実原点と有限な発行時刻へ結合する。"""
        doc = self.document
        cr.require(not self.used and self.parent_alive(), "NATIVE_CONTEXT_RELEASED")
        cr.require(doc.get("nativeMode") == "VERIFIED_LEGACY_V4", "NATIVE_SCOPE_UNVERIFIED")
        for name in ("nativeDigest", "workspaceIdentity", "monitorIdentity", "packageManifestSha256",
                     "seedManifestSha256", "policySha256"):
            cr.sha256(doc.get(name))
            cr.require(doc.get(name) is not None, "NATIVE_CONTEXT_BINDING")
        cr.require(doc["workspaceIdentity"] == self.identity(root) and
                   all(doc[name] == expected[name] for name in ("packageManifestSha256", "seedManifestSha256")) and
                   doc["policySha256"] == cr.digest((package / "config/monitor-policy.json").read_bytes()),
                   "NATIVE_CONTEXT_BINDING")
        issued = doc.get("issuedAtUtcMillis")
        now = int(clock().replace(tzinfo=monitor.timezone.utc).timestamp() * 1000)
        cr.require(type(issued) is int and 0 <= now - issued <= 660000, "NATIVE_CONTEXT_CLOCK")
        store = Path(doc.get("monitorRoot", ""))
        cr.require(store.is_absolute() and doc["monitorIdentity"] == self.identity(store), "MONITOR_ORIGIN_CHANGED")
        for name in ("requestHashes", "hostHashes"):
            values = doc.get(name)
            cr.require(type(values) is list and 0 < len(values) <= 300 and values == sorted(set(values)),
                       "NATIVE_REQUEST_SCOPE_UNVERIFIED")
            for value in values:
                cr.sha256(value)
                cr.require(value is not None, "NATIVE_REQUEST_SCOPE_UNVERIFIED")
        return store

    def consume(self, requests: list[dict], state: dict, store: Path, registry: dict, policy: dict) -> dict:
        """run_onceがwriterを所有した後でleaseと原点を再検査し、全行を残して保留を付ける。"""
        cr.require(not self.used and self.parent_alive(), "NATIVE_CONTEXT_RELEASED")
        cr.require(self.identity(store) == self.document["monitorIdentity"], "MONITOR_ORIGIN_CHANGED")
        self.used = True
        native_hosts = set(self.document["hostHashes"])
        native_requests = set(self.document["requestHashes"])
        held_sources = set(policy["heldSourceIds"]) | {"asus-catalog-legacy", "intel-ethernet-win11"}
        held_urls = {row["officialPage"] for row in registry["sources"] if row["id"] in held_sources}
        held_urls.update(row["url"] for row in requests if set(row["sourceIds"]) & held_sources)
        native_hosts.update(monitor.hash_text(http.urlsplit(url).hostname) for url in held_urls)
        held = {}
        for row in requests:
            if row["url"] in held_urls or set(row["sourceIds"]) & held_sources:
                held[row["id"]] = "NATIVE_COORDINATION_PENDING"
            elif monitor.hash_text("GET\n" + row["url"]) in native_requests:
                held[row["id"]] = "NATIVE_SHARED_REQUEST_HELD"
            elif monitor.hash_text(http.urlsplit(row["url"]).hostname) in native_hosts:
                held[row["id"]] = "NATIVE_SHARED_HOST_HELD"
        return held


class DistributionAdmission(NativeAdmission):
    """専用origin検査済みの二型だけを受け、旧metadata admissionの非空条件を変えない。"""

    def validate(self, package: Path, root: Path, expected: dict, policy: dict, clock) -> Path:
        mode = self.document.get("nativeMode")
        cr.require(mode in {"VERIFIED_LEGACY_V4", "VERIFIED_PRISTINE_V1"}, "NATIVE_SCOPE_UNVERIFIED")
        # 専用native callerはpristineでも現在target/policyの予約scopeを必ず渡す。
        document = self.document
        cr.require(document.get("operation") in {"distribution-run-once", "verify", "export", "switch-package",
                                               "review-held-host", "stage-candidate"} and
                   document.get("originInitializationComplete") is True, "DISTRIBUTION_ORIGIN_REQUIRED")
        if mode == "VERIFIED_PRISTINE_V1":
            cr.require(document.get("legacyHistoryEverObserved") is False and
                       document.get("nativeFileCount") == 0, "DISTRIBUTION_PRISTINE_HISTORY")
        # 元validatorへ明示legacy型を一時射影するが、元context自体の型を保持する。
        self.document = {**document, "nativeMode": "VERIFIED_LEGACY_V4"}
        try:
            return super().validate(package, root, expected, policy, clock)
        finally:
            self.document = document


def history_fingerprint(store: Path) -> dict[str, str]:
    """検証済みstateと全reportのbyteを有限に照合し、相対member名からSHA-256を返す。

    辞書のkeyはstate.jsonやreports配下の相対名で、端末の絶対pathは結果へ含めない。
    storeのwriterは呼出側が所有し、本関数では取得・解放しない。検証・I/O失敗は伝播する。
    """
    monitor.verify_store(store)
    paths = [store / "state.json", *sorted((store / "reports").iterdir())]
    cr.require(len(paths) <= 4096, "MONITOR_ORIGIN_CAPACITY")
    result = {}
    total = 0
    for path in paths:
        cr.regular_path(path)
        size = path.stat().st_size
        total += size
        cr.require(size <= cr.MAX_JSON_BYTES and total <= 64 * 1024 * 1024, "MONITOR_ORIGIN_CAPACITY")
        raw = path.read_bytes()
        cr.require(len(raw) == size, "MONITOR_ORIGIN_CHANGED")
        result[path.relative_to(store).as_posix()] = cr.digest(raw)
    return result


def bind_origins(package: Path, root: Path, admission: NativeAdmission, clock=monitor.utc_now) -> dict:
    """正式選択した既存monitorまたは停止importを検証し、nativeだけが後でlocal参照を保存する。"""
    expected = binding(package)
    cr.require(expected["schema"] == "dc-collector-explicit-workspace-v1", "WORKSPACE_RUN_VERSION")
    validate_workspace(root, expected)
    policy = cr.read_json(package / "config/monitor-policy.json")
    cr.require(admission.document.get("operation") == "bind-origins", "NATIVE_CONTEXT_OPERATION")
    store = admission.validate(package, root, expected, policy, clock)
    with monitor.writer_lock(store):
        state = monitor.verify_store(store)
        cr.require(clock() >= cr.timestamp(state["observedAt"]), "WORKSPACE_CLOCK")
        cr.require(state["requests"] and any((store / "reports").iterdir()), "MONITOR_ORIGIN_HISTORY_REQUIRED")
        cr.require(all(row["outcome"] != "IN_PROGRESS" for row in state["requests"].values()),
                   "MONITOR_ORIGIN_NOT_STOPPED")
        previous = admission.document.get("previousMonitorRoot")
        if previous and Path(previous) != store:
            original = Path(previous)
            cr.require(admission.identity(original) == admission.document.get("previousMonitorIdentity"),
                       "MONITOR_ORIGIN_CHANGED")
            with monitor.writer_lock(original):
                metadata = monitor.validate_import_metadata(cr.read_json(store / "import-metadata.json"))
                old = monitor.verify_store(original)
                cr.require(metadata["sourceObservedAt"] == old["observedAt"] and
                           history_fingerprint(original) == history_fingerprint(store), "MONITOR_ORIGIN_IMPORT_CHANGED")
        cr.require(not admission.used and admission.parent_alive(), "NATIVE_CONTEXT_RELEASED")
        admission.used = True
    return {"result":"ORIGINS_VERIFIED_OFFLINE", "communicationAuthorized":False,
            "requests":len(state["requests"]), "reports":len(list((store / "reports").iterdir())), "tasks":0}


class ProcessGate:
    """検証済みtransportが直前に結合した完全argv一回だけをauditで許可する。"""

    def __init__(self, package: Path, curl: str, permitted_urls: tuple[str, ...] = ()):
        self.package = package
        self.curl = curl
        self.permitted_urls = frozenset(permitted_urls)
        self.permitted_hosts = frozenset(http.urlsplit(value).hostname for value in permitted_urls)
        self.pending = None
        self.routes = {}

    def bind_route(self, url: str, route: dict, address: str) -> None:
        """固定route/DNS子の検証済み結果だけを一要求へ結合する。"""
        cr.require(url in self.permitted_urls, "WORKSPACE_PROCESS_ROUTE")
        http.validate_route(route)
        parsed = http.ipaddress.ip_address(address)
        cr.require(parsed.is_global and not parsed.is_multicast and not parsed.is_reserved,
                   "WORKSPACE_PROCESS_ROUTE")
        self.routes[url] = (route.copy(), address)

    def prepare(self, arguments: list[str]) -> None:
        """固定DNSまたはtransport固定curl argv以外を事前拒否する。"""
        is_dns = (len(arguments) == 8 and arguments[-1] in self.permitted_hosts and
                  arguments == http.dns_command(self.package, arguments[-1]))
        is_route = len(arguments) == 8 and arguments[-1] in self.permitted_urls and arguments == http.route_command(self.package, arguments[-1])
        is_curl = False
        if len(arguments) == 29 and arguments[-1] in self.routes:
            route, address = self.routes[arguments[-1]]
            headers, body = Path(arguments[19]), Path(arguments[21])
            is_curl = (headers.is_absolute() and headers.name == "headers" and body.name == "body" and
                       headers.parent == body.parent and arguments == http.curl_command(
                           self.curl, "PAGE", arguments[-1], route, address, headers, body))
        cr.require(is_dns or is_route or is_curl, "WORKSPACE_PROCESS_ARGV")
        if is_curl:
            del self.routes[arguments[-1]]
        self.pending = (tuple(arguments), subprocess.list2cmdline(arguments))

    def audit(self, event: str, arguments: tuple) -> None:
        """親socket/shellを拒否し、完全argvの一回消費だけを許可する。"""
        if event == "subprocess.Popen":
            executable, argv, cwd, environment = arguments
            cr.require(self.pending is not None and
                       (argv == self.pending[1] if isinstance(argv, str) else tuple(argv) == self.pending[0]) and
                       executable == self.pending[0][0] and environment is None and cwd is None,
                       "WORKSPACE_PROCESS_AUTHORITY")
            self.pending = None
        else:
            reject_external_execution(event, arguments)


def run_monitor_once(package: Path, root: Path, *, confirmed: bool, curl: str, curl_sha256: str | None = None,
                     admission=None, transport=None, clock=monitor.utc_now) -> dict:
    """既知制約と同意へ結合した一回だけを既存run_onceへ委譲する。

    admission/transportは内部単体試験でも同じ検証・run_once・保存を通す。public proofは受けない。
    """
    cr.require(confirmed, "WORKSPACE_RUN_CONSENT_REQUIRED")
    expected = binding(package)
    cr.require(expected["schema"] == "dc-collector-explicit-workspace-v1", "WORKSPACE_RUN_VERSION")
    validate_workspace(root, expected)
    registry, locators, _ = snapshot.verify_snapshot(package / "seed" / "collector-data")
    policy = cr.read_json(package / "config" / "monitor-policy.json")
    if admission is None:
        return {"result":"HOLD", "reason":"NATIVE_LIVE_CONTEXT_REQUIRED", "communicationAuthorized":False,
                "nativeConstraints":"UNKNOWN", "originalDayBudget":"UNVERIFIED", "httpRequests":0}
    cr.require(admission.document.get("operation") == "run-once", "NATIVE_CONTEXT_OPERATION")
    store = admission.validate(package, root, expected, policy, clock)
    requests = monitor.page_requests(registry, locators, policy, monitor.make_requests(registry, policy))
    gate = ProcessGate(package, curl, tuple(row["url"] for row in requests if not row["held"]))
    if transport is None:
        cr.require(curl == http.system_curl_path(), "SYSTEM_CURL_PATH")
        cr.require(type(curl_sha256) is str and len(curl_sha256) == 64 and
                   0 < Path(curl).stat().st_size <= 16777216 and
                   cr.digest(Path(curl).read_bytes()) == curl_sha256, "SYSTEM_CURL_BYTE_BINDING")
        sys.addaudithook(gate.audit)
        transport = http.CurlTransport(registry=registry, public_locators=locators,
            held_source_ids=tuple(policy["heldSourceIds"]), package=package, curl_path=curl,
            process_gate=gate.prepare, route_gate=gate.bind_route)
    report = monitor.run_once(registry, policy, store, transport=transport, clock=clock,
        public_locators=locators, pages_only=True,
        admission=lambda rows, state: admission.consume(rows, state, store, registry, policy))
    return {"result": "MONITOR_REPORT_SAVED", "reportId": report["id"], "counts": report["counts"],
            "communicationAuthorized": True, "nativeConstraints": "VERIFIED_LEGACY_V4",
            "originalDayBudget": "NOT_APPLICABLE_TO_PROVEN_NONSHARING_PAGES",
            "nativeSharedScope": "HELD", "requestScope": "REGISTERED_NONSHARING_PAGES",
            "publishableIndex": False, "driverContentVerified": False}


def reject_external_execution(event: str, arguments: tuple) -> None:
    """非通信操作からsocket接続、子process、shellへの逸脱を拒否する。"""
    if event.startswith(("socket.", "subprocess.", "os.exec", "os.spawn")) or event == "os.system":
        raise cr.RegistryError("WORKSPACE_EXTERNAL_EXECUTION_FORBIDDEN")


def binding(package: Path, *, require_receipt: bool = True) -> dict:
    """現在のv7 seed・policyを結合し、通常は配置receiptも必須にする。

    非通信stagingだけは未installを許す。存在するreceiptは同じ通常規則で必ず検査する。
    """
    registry, _, _ = snapshot.verify_snapshot(package / "seed" / "collector-data")
    monitor.validate_policy(registry, cr.read_json(package / "config" / "monitor-policy.json"))
    manifest = cr.read_json(package / "package-manifest.json")
    cr.require(manifest["schema"] == "dc-collector-package-v7" and
               manifest["mode"] == "EXPLICIT_DISTRIBUTION_DATA_DAILY", "WORKSPACE_PACKAGE_VERSION")
    package_hash = cr.digest((package / "package-manifest.json").read_bytes())
    if require_receipt or (package / "install-receipt.json").exists():
        receipt = cr.read_json(package / "install-receipt.json")
        cr.fields(receipt, {"schema", "packageManifestSha256", "installedUtc"}, "WORKSPACE_RECEIPT_FIELDS")
        cr.require(receipt["schema"] == "dc-collector-install-receipt-v3" and
                   receipt["packageManifestSha256"] == package_hash, "WORKSPACE_RECEIPT")
    return {"schema": "dc-collector-explicit-workspace-v1", "packageManifestSha256": package_hash,
            "seedManifestSha256": cr.digest((package / "seed" / "collector-data" / "manifest.json").read_bytes()),
            "communicationAuthorized": False, "nativeConstraints": "UNKNOWN",
            "originalDayBudget": "UNVERIFIED"}


def validate_binding(value: dict) -> dict:
    """切替元と保持archiveにも現在の六fieldだけを要求し、旧形式を補完しない。"""
    cr.fields(value, {"schema", "packageManifestSha256", "seedManifestSha256", "communicationAuthorized",
                      "nativeConstraints", "originalDayBudget"}, "WORKSPACE_BINDING_FIELDS")
    cr.require(value["schema"] == SCHEMA and value["communicationAuthorized"] is False and
               value["nativeConstraints"] == "UNKNOWN" and value["originalDayBudget"] == "UNVERIFIED",
               "WORKSPACE_BINDING_SCHEMA")
    for name in ("packageManifestSha256", "seedManifestSha256"):
        cr.sha256(value[name])
        cr.require(value[name] is not None, "WORKSPACE_BINDING_HASH")
    return value


def validate_switch_history(root: Path) -> None:
    """原byte archiveの有限閉集合を検証し、中断pendingを通常操作へ持ち込まない。"""
    history = root / "package-switches"
    if not history.exists():
        return
    cr.regular_path(history, directory=True)
    paths = list(history.iterdir())
    cr.require(len(paths) <= SWITCH_HISTORY_LIMIT, "WORKSPACE_SWITCH_CAPACITY")
    for path in paths:
        cr.require(path.name != "workspace.pending.json", "WORKSPACE_SWITCH_INCOMPLETE")
        cr.require(len(path.name) == 69 and path.name.endswith(".json"), "WORKSPACE_SWITCH_FILE_SET")
        digest = path.name[:-5]
        cr.sha256(digest)
        raw = monitor.read_import_bytes(path)
        cr.require(len(raw) <= CONTEXT_LIMIT and cr.digest(raw) == digest, "WORKSPACE_SWITCH_ARCHIVE_HASH")
        validate_binding(cr.parse_json(raw))


def validate_workspace(root: Path, expected: dict, *, allow_stage: bool = False) -> None:
    """Rootは固定bindingとmonitorだけを持ち、再開時だけ同名stagingを許す。"""
    cr.require(cr.read_json(root / "workspace.json") == expected, "WORKSPACE_BINDING")
    names = {path.name for path in root.iterdir()}
    allowed = {"workspace.json", "monitor", "origin.json", "distribution-origin-init-v1.json",
               "distribution-initial-plan-v1.json", "data", "package-switches", "host-reviews"}
    if allow_stage:
        stages = {name for name in names if name.startswith("monitor.import-") and
                  len(name) == len("monitor.import-") + 32 and
                  all(letter in "0123456789abcdef" for letter in name[len("monitor.import-"):])}
        cr.require(len(stages) <= 1, "WORKSPACE_STAGE_COUNT")
        allowed |= stages
    cr.require(names <= allowed and "workspace.json" in names, "WORKSPACE_FILE_SET")
    validate_switch_history(root)


def switch_package(package: Path, root: Path, reviewed_sha256: str, admission: DistributionAdmission,
                   *, checkpoint=None, clock=monitor.utc_now) -> dict:
    """原hashを明示reviewした停止workspaceだけを、生きたnative leaseの内側で切り替える。

    現package/receiptはnativeが全byteを固定検査する。旧bindingの例外は本操作だけであり、
    旧packageの実行/通信権限は復元しない。保存後の中断もarchive/pendingを削除しない。
    """
    cr.sha256(reviewed_sha256)
    cr.require(reviewed_sha256 is not None, "WORKSPACE_SWITCH_REVIEW_HASH")
    expected = validate_binding(binding(package))
    raw = monitor.read_import_bytes(root / "workspace.json")
    cr.require(len(raw) <= CONTEXT_LIMIT and cr.digest(raw) == reviewed_sha256, "WORKSPACE_SWITCH_REVIEW_HASH")
    previous = validate_binding(cr.parse_json(raw))
    cr.require(previous != expected, "WORKSPACE_SWITCH_ALREADY_CURRENT")
    validate_workspace(root, previous)
    cr.require(admission is not None and admission.document.get("operation") == "switch-package" and
               admission.document.get("reviewedWorkspaceSha256") == reviewed_sha256,
               "NATIVE_CONTEXT_OPERATION")
    policy = cr.read_json(package / "config/monitor-policy.json")
    store = admission.validate(package, root, expected, policy, clock)
    with monitor.writer_lock(store):
        state = monitor.verify_store(store)
        cr.require(clock() >= cr.timestamp(state["observedAt"]), "WORKSPACE_CLOCK")
        cr.require(all(row["outcome"] not in {"IN_PROGRESS", "UNKNOWN_OUTCOME"}
                       for row in state["requests"].values()), "WORKSPACE_SWITCH_NOT_STOPPED")
        if (store / "distribution").exists():
            import collector_distribution_pipeline as distribution
            journal = distribution.verify_layout(store / "distribution")
            cr.require(clock() >= cr.timestamp(journal["observedAt"]), "WORKSPACE_CLOCK")
            cr.require(journal["pendingRun"] is None and
                       all(run["phase"] == "FINISHED" and run["pendingJob"] is None and
                           all(job["phase"] != "RESERVED" for job in run["jobs"])
                           for run in journal["runs"].values()) and
                       all(row["phase"] != "RESERVED" for row in journal["requests"].values()),
                       "WORKSPACE_SWITCH_NOT_STOPPED")
            portable = store / "distribution/portable-history.json"
            if portable.exists():
                cr.require(all(run["phase"] == "FINISHED" for run in cr.read_json(portable)["runs"].values()),
                           "WORKSPACE_SWITCH_NOT_STOPPED")
        if (root / "data").exists():
            import collector_distribution_data as data
            data.active_bundle(root, retained=True)
        cr.require(not admission.used and admission.parent_alive(), "NATIVE_CONTEXT_RELEASED")
        cr.require(admission.identity(root) == admission.document["workspaceIdentity"] and
                   admission.identity(store) == admission.document["monitorIdentity"], "MONITOR_ORIGIN_CHANGED")
        cr.require(monitor.read_import_bytes(root / "workspace.json") == raw, "WORKSPACE_SWITCH_INPUT_CHANGED")
        history = root / "package-switches"
        if not history.exists():
            history.mkdir()
        validate_switch_history(root)
        cr.require(len(list(history.iterdir())) < SWITCH_HISTORY_LIMIT, "WORKSPACE_SWITCH_CAPACITY")
        archive = history / (reviewed_sha256 + ".json")
        cr.require(not archive.exists(), "WORKSPACE_SWITCH_ALREADY_RECORDED")
        admission.used = True
        monitor.write_new_bytes(archive, raw)
        cr.require(monitor.read_import_bytes(archive) == raw, "WORKSPACE_SWITCH_ARCHIVE_HASH")
        if checkpoint is not None:
            checkpoint("ORIGINAL_SAVED", archive)
        pending = history / "workspace.pending.json"
        current_raw = cr.json_bytes(expected)
        monitor.write_new_bytes(pending, current_raw)
        if checkpoint is not None:
            checkpoint("REPLACEMENT_SAVED", pending)
        cr.require(admission.parent_alive() and monitor.read_import_bytes(root / "workspace.json") == raw,
                   "WORKSPACE_SWITCH_INPUT_CHANGED")
        cr.require(admission.identity(root) == admission.document["workspaceIdentity"] and
                   admission.identity(store) == admission.document["monitorIdentity"], "MONITOR_ORIGIN_CHANGED")
        os.replace(pending, root / "workspace.json")
        if checkpoint is not None:
            checkpoint("REPLACED", root / "workspace.json")
        cr.require(monitor.read_import_bytes(root / "workspace.json") == current_raw and
                   monitor.read_import_bytes(archive) == raw, "WORKSPACE_SWITCH_READBACK")
        validate_workspace(root, expected)
    return {"schema": "dc-collector-offline-result-v1", "operation": "switch-package", "result": "VERIFIED_OFFLINE",
            "previousWorkspaceSha256": reviewed_sha256, "workspaceSha256": cr.digest(current_raw),
            "communicationAuthorized": False, "nativeConstraints": "UNKNOWN", "originalDayBudget": "UNVERIFIED",
            "requests": len(state["requests"]), "reports": len(list((store / "reports").iterdir())), "tasks": 0}


def held_review_request(path: Path) -> tuple[dict, dict[str, bytes]]:
    """閉じたrequestと同directoryの固定raw二件だけを有限読取りする。"""
    raw = monitor.read_import_bytes(path)
    cr.require(len(raw) <= 65536, "HOST_REVIEW_REQUEST_SIZE")
    request = cr.fields(cr.parse_json(raw), {
        "schema", "reviewId", "hostSha256", "profileId", "recordId", "workspaceSha256",
        "stateSha256", "journalSha256", "inputHashes", "cause", "currentPage", "review",
        "baselineRevalidationOnly", "preserveChargesAndWaits"}, "HOST_REVIEW_FIELDS")
    cr.require(request["schema"] == "dc-collector-held-host-review-v1" and
               request["baselineRevalidationOnly"] is True and request["preserveChargesAndWaits"] is True,
               "HOST_REVIEW_ACKNOWLEDGEMENT")
    for name in ("reviewId", "profileId", "recordId"):
        cr.identity(request[name])
    for name in ("hostSha256", "workspaceSha256", "stateSha256", "journalSha256"):
        cr.sha256(request[name])
        cr.require(request[name] is not None, "HOST_REVIEW_HASH")
    cr.fields(request["inputHashes"], {"registry", "locators", "profiles"}, "HOST_REVIEW_INPUT_FIELDS")
    for digest in request["inputHashes"].values():
        cr.sha256(digest)
        cr.require(digest is not None, "HOST_REVIEW_HASH")
    cause = cr.fields(request["cause"], {"kind", "runId", "ordinal", "resultSha256", "originalRawMissing"},
                      "HOST_REVIEW_CAUSE_FIELDS")
    import collector_distribution_pipeline as distribution
    cr.require(cause["kind"] == "PAGE_CONTENT_CHANGED_REVALIDATE_BASELINE" and
               distribution.valid_run_id(cause["runId"]) and type(cause["ordinal"]) is int and
               0 <= cause["ordinal"] < 32 and type(cause["originalRawMissing"]) is bool,
               "HOST_REVIEW_CAUSE")
    cr.sha256(cause["resultSha256"])
    cr.require(cause["resultSha256"] is not None, "HOST_REVIEW_HASH")
    page = cr.fields(request["currentPage"], {"bodySha256", "bodyBytes", "observedAt"},
                     "HOST_REVIEW_PAGE_FIELDS")
    cr.sha256(page["bodySha256"])
    cr.require(page["bodySha256"] is not None and type(page["bodyBytes"]) is int and
               0 < page["bodyBytes"] <= 1024 * 1024, "HOST_REVIEW_PAGE_SIZE")
    cr.timestamp(page["observedAt"])
    files = {"request.json": raw}
    for member in ("baseline.raw.html", "current.raw.html"):
        files[member] = monitor.read_import_bytes(path.parent / member)
        cr.require(len(files[member]) <= 1024 * 1024, "HOST_REVIEW_PAGE_SIZE")
    cr.require(len(files["current.raw.html"]) == page["bodyBytes"] and
               cr.digest(files["current.raw.html"]) == page["bodySha256"], "HOST_REVIEW_PAGE_HASH")
    return request, files


def held_review_evidence(package: Path, root: Path, request: dict, files: dict, state: dict,
                         journal: dict, admission: DistributionAdmission, now) -> dict:
    """現在baselineと最新の一原因を結合し、課金・原待機・失敗を変更せず検査する。"""
    import collector_collection_profiles as profiles
    import collector_distribution_pipeline as distribution
    inputs, value, hashes = distribution.inputs_at(package, root)
    cr.require(hashes == request["inputHashes"], "HOST_REVIEW_INPUT_CHANGED")
    cr.require(now >= cr.timestamp(value["asOf"]), "HOST_REVIEW_WAIT")
    policy = monitor.validate_policy(inputs["registry"], cr.read_json(package / "config/monitor-policy.json"))
    plan = profiles.plan_profiles(value, inputs)
    current = next((row for row in value["profiles"] if row["id"] == request["profileId"]), None)
    cr.require(current is not None and current["recordId"] == request["recordId"], "HOST_REVIEW_PROFILE")
    target = next(row for row in plan["targets"] if row["profileId"] == current["id"])
    cr.require(not target["reasons"], "HOST_REVIEW_PROFILE_HELD")
    job = profiles.make_static_job(current, inputs)
    host = request["hostSha256"]
    cr.require(all(monitor.hash_text(job["source"][key]) == host for key in ("rootHost", "payloadHost")) and
               host not in admission.document["hostHashes"] and
               job["sourceId"] not in set(policy["heldSourceIds"]) | {"asus-catalog-legacy", "intel-ethernet-win11"},
               "HOST_REVIEW_SCOPE_HELD")
    # 一hostの共有profileを一URLの承認で解除しない。
    for row in value["profiles"]:
        if row["id"] != current["id"]:
            reference = profiles.reference_data(row, inputs)
            cr.require(all(monitor.hash_text(http.urlsplit(reference[key]["url"]).hostname) != host
                           for key in ("page", "payload")), "HOST_REVIEW_SHARED_PROFILE")
    cr.require(request["review"] == job["review"], "HOST_REVIEW_SCOPE_CHANGED")
    baseline = files["baseline.raw.html"]
    current_raw = files["current.raw.html"]
    content_hash = profiles.page_content_sha256(baseline)
    cr.require(content_hash == profiles.page_content_sha256(current_raw), "HOST_REVIEW_CONTENT_CHANGED")
    # 厳密content一致はHTML全体の同一性を保持し、anchorや条件の部分抽出で救済しない。
    cr.require(cr.digest(baseline) == job["pageObservation"]["bodySha256"] and
               len(baseline) == job["pageObservation"]["bodyBytes"], "HOST_REVIEW_BASELINE_HASH")
    observed = cr.timestamp(request["currentPage"]["observedAt"])
    cr.require(now >= observed >= cr.timestamp(state["hosts"][host]["failedAt"]) and
               now - observed <= monitor.DAY, "HOST_REVIEW_PAGE_STALE")
    for scope in profiles.REVIEW_STATES:
        evidence = job["review"][scope]["evidence"]
        checked = cr.timestamp(evidence["checkedAt"])
        cr.require(evidence["contentSha256"] == content_hash and
                   now >= checked and now - checked <= monitor.DAY * 8, "HOST_REVIEW_SCOPE_STALE")
    cause = request["cause"]
    run = journal["runs"].get(cause["runId"])
    cr.require(run is not None and cause["ordinal"] < len(run["jobs"]), "HOST_REVIEW_CAUSE_MISSING")
    item = run["jobs"][cause["ordinal"]]
    cr.require(item["phase"] == "SETTLED_MAXIMUM" and item["status"] == "FAILED" and
               item["reason"] == "ACQUISITION_REJECTED" and item["resultSha256"] == cause["resultSha256"],
               "HOST_REVIEW_CAUSE_CHANGED")
    directory = Path(admission.document["monitorRoot"]) / "distribution/runs" / cause["runId"]
    reservation = distribution.read_hash(directory / f"reservation-{cause['ordinal']}.json",
                                          item["reservationSha256"])
    result = distribution.read_hash(directory / f"result-{cause['ordinal']}.json", cause["resultSha256"])
    original = distribution.read_hash(directory / f"job-{cause['ordinal']}.json", reservation["jobSha256"])
    cr.require(result["schema"] == "dc-collector-registry-native-result-v1" and result["job"] == original and
               result["jobSha256"] == reservation["jobSha256"] and
               all(original[key] == job[key] for key in
                   ("jobId", "recordId", "sourceId", "referenceSha256", "source", "record", "products")),
               "HOST_REVIEW_CAUSE_BINDING")
    page = result["pageTransfer"]
    payload = result["payloadTransfer"]
    cr.require(result["status"] == "FAILED" and result["reason"] == "ACQUISITION_REJECTED" and
               result["error"] == -2147023590 and result["sourceVerified"] is False and
               result["archiveBytes"] == 0 and result["verifiedInfs"] == 0 and
               page["stage"] == "PAGE" and page["completion"] == "COMPLETE" and page["terminalStatus"] == 200 and
               page["attemptedRequests"] == 1 and payload == {"stage": "UNSTARTED", "completion": "UNKNOWN",
                   "attemptedRequests": 0, "bodyBytesRead": 0, "terminalStatus": 0} and
               result["pageObservation"]["finalUrl"] == job["source"]["rootUrl"] and
               result["pageObservation"]["bodySha256"] != original["pageObservation"]["bodySha256"] and
               page["bodyBytesRead"] == result["pageObservation"]["bodyBytes"] > 0,
               "HOST_REVIEW_UNSUPPORTED_CAUSE")
    old_raw = directory / f"page-{cause['ordinal']}.body"
    cr.require(cause["originalRawMissing"] == (not old_raw.exists()), "HOST_REVIEW_MISSING_RAW_ACK")
    # v2原結果では保存原byteの厳密content不一致も確認し、別の1306原因を解除しない。
    if old_raw.exists():
        previous = monitor.read_import_bytes(old_raw)
        cr.require(cr.digest(previous) == result["pageObservation"]["bodySha256"] and
                   profiles.page_content_sha256(previous) !=
                   original["review"]["official"]["evidence"].get("contentSha256",
                                                                             original["pageObservation"]["bodySha256"]),
                   "HOST_REVIEW_UNSUPPORTED_CAUSE")
    page_key, payload_key = (monitor.hash_text("GET\n" + job["source"][key]) for key in ("rootUrl", "payloadUrl"))
    failed = state["hosts"][host]["failedAt"]
    related = {key: row for key, row in journal["requests"].items() if row["hostSha256"] == host}
    cr.require(set(related) == {page_key, payload_key} and reservation["pageHost"] == host and
               reservation["payloadHost"] == host and reservation["pageKey"] == page_key and
               reservation["payloadKey"] == payload_key, "HOST_REVIEW_HOST_CAUSE_AMBIGUOUS")
    for key, row in related.items():
        cr.require(row["runId"] == cause["runId"] and row["ordinal"] == cause["ordinal"] and
                   row["endedAt"] == failed and row["phase"] ==
                   ("SETTLED_ACTUAL" if key == page_key else "SETTLED_MAXIMUM"), "HOST_REVIEW_NEWER_CAUSE")
        cr.require(row["kind"] == ("PAGE" if key == page_key else "PAYLOAD") and
                   row["chargedRequests"] == (page["attemptedRequests"] if key == page_key else reservation["payloadRequests"]) and
                   row["chargedBytes"] == (page["bodyBytesRead"] if key == page_key else reservation["payloadBytes"]),
                   "HOST_REVIEW_CHARGES_CHANGED")
    # monitor側に独立した失敗/未確定/別requestがあれば今回の一原因へ束ねない。
    cr.require({key for key, row in state["requests"].items() if row["hostSha256"] == host} == {page_key},
               "HOST_REVIEW_OTHER_CAUSE")
    for key, row in state["requests"].items():
        if row["hostSha256"] == host:
            cr.require(key == page_key and row["outcome"] == "SUCCESS" and row["endedAt"] == failed and
                       row["lastSuccess"]["bodySha256"] == result["pageObservation"]["bodySha256"],
                       "HOST_REVIEW_OTHER_CAUSE")
    return {"inputHashes": hashes, "policySha256": cr.digest((package / "config/monitor-policy.json").read_bytes()),
            "contentSha256": content_hash, "causeResultSha256": cause["resultSha256"],
            "originalRawMissing": cause["originalRawMissing"]}


def review_held_host(package: Path, root: Path, path: Path, admission: DistributionAdmission,
                     *, checkpoint=None, clock=monitor.utc_now) -> dict:
    """同じnative lease→monitor writerで一hostだけを原監査保存後に明示reviewする。

    故障注入は内部試験だけのcallback。原fileを削除/rollbackせず、exact-afterの同request
    だけ完了receiptを補える。新しいstateや未知の部分監査は保持して拒否する。
    """
    import collector_distribution_pipeline as distribution
    expected = binding(package)
    validate_workspace(root, expected)
    request, files = held_review_request(path)
    cr.require(admission is not None and admission.document.get("operation") == "review-held-host" and
               admission.document.get("reviewRequestSha256") == cr.digest(files["request.json"]),
               "NATIVE_CONTEXT_OPERATION")
    policy = cr.read_json(package / "config/monitor-policy.json")
    store = admission.validate(package, root, expected, policy, clock)
    with monitor.writer_lock(store):
        now = clock()
        state = monitor.verify_store(store)
        journal = distribution.verify_layout(store / "distribution")
        cr.require(journal["pendingRun"] is None and
                   all(run["phase"] == "FINISHED" and run["pendingJob"] is None and
                       all(row["phase"] != "RESERVED" for row in run["jobs"]) for run in journal["runs"].values()) and
                   all(row["phase"] != "RESERVED" for row in journal["requests"].values()) and
                   all(row["outcome"] not in {"IN_PROGRESS", "UNKNOWN_OUTCOME"} for row in state["requests"].values()),
                   "HOST_REVIEW_NOT_SETTLED")
        portable = store / "distribution/portable-history.json"
        if portable.exists():
            cr.require(all(run["phase"] == "FINISHED" for run in cr.read_json(portable)["runs"].values()),
                       "HOST_REVIEW_NOT_SETTLED")
        host = request["hostSha256"]
        cr.require(host in state["hosts"], "HOST_REVIEW_HOST_MISSING")
        cr.require(now >= cr.timestamp(state["observedAt"]) and now >= cr.timestamp(journal["observedAt"]) and
                   now >= cr.timestamp(state["hosts"][host]["nextDueAt"]) and
                   all(now >= cr.timestamp(row["nextDueAt"]) for rows in (state["requests"], journal["requests"])
                       for row in rows.values() if row["hostSha256"] == host), "HOST_REVIEW_WAIT")
        workspace_raw = monitor.read_import_bytes(root / "workspace.json")
        journal_raw = monitor.read_import_bytes(store / "distribution/journal.json")
        state_raw = monitor.read_import_bytes(store / "state.json")
        cr.require(cr.digest(workspace_raw) == request["workspaceSha256"] and
                   cr.digest(journal_raw) == request["journalSha256"], "HOST_REVIEW_CAS")
        evidence = held_review_evidence(package, root, request, files, state, journal, admission, now)
        history = root / "host-reviews"
        if not history.exists():
            history.mkdir()
        cr.regular_path(history, directory=True)
        cr.require(len(list(history.iterdir())) <= 256, "HOST_REVIEW_CAPACITY")
        audit = history / request["reviewId"]
        resumed = audit.exists()
        cr.require(resumed or len(list(history.iterdir())) < 256, "HOST_REVIEW_CAPACITY")
        if resumed:
            cr.regular_path(audit, directory=True)
            names = {entry.name for entry in audit.iterdir()}
            required = set(files) | {"state-before.json", "journal-before.json", "state-after.json", "intent.json"}
            cr.require(required <= names <= required | {"receipt.json"}, "HOST_REVIEW_AUDIT_INCOMPLETE")
            cr.require(all(monitor.read_import_bytes(audit / name) == raw for name, raw in files.items()) and
                       monitor.read_import_bytes(audit / "journal-before.json") == journal_raw,
                       "HOST_REVIEW_AUDIT_CHANGED")
            before_raw = monitor.read_import_bytes(audit / "state-before.json")
            after_raw = monitor.read_import_bytes(audit / "state-after.json")
            before = monitor.validate_state(monitor.read_envelope(audit / "state-before.json", "dc-monitor-state-envelope-v1"))
            after = monitor.validate_state(monitor.read_envelope(audit / "state-after.json", "dc-monitor-state-envelope-v1"))
            intended = copy.deepcopy(before)
            intended["hosts"][host]["held"] = False
            intended["observedAt"] = after["observedAt"]
            cr.require(before["hosts"][host]["held"] is True and after == intended and
                       cr.timestamp(before["observedAt"]) <= cr.timestamp(after["observedAt"]) <= now and
                       cr.digest(before_raw) == request["stateSha256"] and state_raw in (before_raw, after_raw),
                       "HOST_REVIEW_CAS")
            intent = cr.read_json(audit / "intent.json")
        else:
            cr.require(state["hosts"][host]["held"] is True and cr.digest(state_raw) == request["stateSha256"],
                       "HOST_REVIEW_CAS")
            before_raw = state_raw
            after = copy.deepcopy(state)
            after["hosts"][host]["held"] = False
            after["observedAt"] = monitor.stamp(now)
            after_raw = monitor.envelope("dc-monitor-state-envelope-v1", monitor.validate_state(after))
            intent = {"schema": "dc-collector-host-review-intent-v1", "requestSha256": cr.digest(files["request.json"]),
                      "stateBeforeSha256": cr.digest(before_raw), "stateAfterSha256": cr.digest(after_raw),
                      "workspaceSha256": request["workspaceSha256"], "journalSha256": request["journalSha256"],
                      "workspaceIdentity": admission.document["workspaceIdentity"],
                      "monitorIdentity": admission.document["monitorIdentity"], "nativeDigest": admission.document["nativeDigest"],
                      "nativeIdentity": admission.document["nativeIdentity"],
                      "packageManifestSha256": expected["packageManifestSha256"], **evidence}
            audit.mkdir()
            for name, raw in {**files, "state-before.json": before_raw, "journal-before.json": journal_raw,
                              "state-after.json": after_raw}.items():
                monitor.write_new_bytes(audit / name, raw)
                cr.require(monitor.read_import_bytes(audit / name) == raw, "HOST_REVIEW_AUDIT_CHANGED")
            if checkpoint:
                checkpoint("ORIGINAL_SAVED", audit)
            monitor.write_new_bytes(audit / "intent.json", cr.json_bytes(intent))
            if checkpoint:
                checkpoint("INTENT_SAVED", audit)
        expected_intent = {"schema": "dc-collector-host-review-intent-v1", "requestSha256": cr.digest(files["request.json"]),
                           "stateBeforeSha256": cr.digest(before_raw), "stateAfterSha256": cr.digest(after_raw),
                           "workspaceSha256": request["workspaceSha256"], "journalSha256": request["journalSha256"],
                           "workspaceIdentity": admission.document["workspaceIdentity"],
                           "monitorIdentity": admission.document["monitorIdentity"], "nativeDigest": admission.document["nativeDigest"],
                           "nativeIdentity": admission.document["nativeIdentity"],
                           "packageManifestSha256": expected["packageManifestSha256"], **evidence}
        cr.require(intent == expected_intent, "HOST_REVIEW_AUDIT_CHANGED")
        commit_now = clock()
        cr.require(commit_now >= now, "HOST_REVIEW_CLOCK")
        # 保存窓の間にdata/policy/実identity/親/全CAS入力が変わった場合は元監査を残して拒否する。
        cr.require(not admission.used and admission.parent_alive() and
                   admission.identity(root) == admission.document["workspaceIdentity"] and
                   admission.identity(store) == admission.document["monitorIdentity"], "NATIVE_CONTEXT_RELEASED")
        cr.require(monitor.read_import_bytes(root / "workspace.json") == workspace_raw and
                   monitor.read_import_bytes(store / "distribution/journal.json") == journal_raw and
                   monitor.read_import_bytes(store / "state.json") == state_raw and
                   held_review_request(path)[1] == files and
                   held_review_evidence(package, root, request, files, state, journal, admission, commit_now) == evidence,
                   "HOST_REVIEW_CAS")
        admission.used = True
        receipt = {"schema": "dc-collector-host-review-receipt-v1", "intentSha256": cr.digest(cr.json_bytes(intent)),
                   "stateAfterSha256": cr.digest(after_raw), "communicationAuthorized": False}
        completed = (audit / "receipt.json").exists()
        if completed:
            cr.require(state_raw == after_raw and cr.read_json(audit / "receipt.json") == receipt,
                       "HOST_REVIEW_AUDIT_CHANGED")
        elif state_raw == before_raw:
            monitor.save_state(store, after)
            if checkpoint:
                checkpoint("REPLACED", audit)
        cr.require(monitor.read_import_bytes(store / "state.json") == after_raw and
                   monitor.read_import_bytes(store / "distribution/journal.json") == journal_raw,
                   "HOST_REVIEW_READBACK")
        if not completed:
            monitor.write_new_bytes(audit / "receipt.json", cr.json_bytes(receipt))
            cr.require(cr.read_json(audit / "receipt.json") == receipt, "HOST_REVIEW_READBACK")
        return {"schema": "dc-collector-offline-result-v1", "operation": "review-held-host",
                "result": "ALREADY_REVIEWED" if completed else "REVIEWED_BASELINE_OFFLINE",
                "reviewId": request["reviewId"], "stateSha256": cr.digest(after_raw),
                "originalRawMissing": evidence["originalRawMissing"], "baselineRevalidationOnly": True,
                "communicationAuthorized": False, "freshSuccess": False, "tasks": 0}


def stage_candidate(package: Path, root: Path, transfer: Path, admission, *,
                    clock=monitor.utc_now, checkpoint=None) -> dict:
    """保持中native leaseとmonitor writerから未署名原byteだけを新規受渡しする。

    現在packageはsource固定のcallerであり、保存済みproducerを再発行しない。
    発行用ACL・unsigned codec・世代予約・署名は保存先の通常発行入口が別途検査する。
    途中失敗は部分fileを保持し、source/state/待機/課金へ書き込まない。
    """
    import collector_distribution_pipeline as distribution
    cr.require(isinstance(admission, DistributionAdmission) and
               admission.document.get("operation") == "stage-candidate", "CANDIDATE_STAGE_ADMISSION")
    expected = binding(package, require_receipt=False)
    workspace_raw = monitor.read_import_bytes(root / "workspace.json")
    original_binding = validate_binding(cr.parse_json(workspace_raw))
    validate_workspace(root, original_binding)
    cr.regular_path(transfer, directory=True)
    cr.require(not any(transfer.iterdir()), "CANDIDATE_STAGE_NOT_EMPTY")
    for origin in (package, root, Path(admission.document["monitorRoot"])):
        cr.require(transfer != origin and transfer not in origin.parents and origin not in transfer.parents,
                   "CANDIDATE_STAGE_OVERLAP")
    policy = cr.read_json(package / "config/monitor-policy.json")
    store = admission.validate(package, root, expected, policy, clock)
    with monitor.writer_lock(store):
        state = monitor.verify_store(store)
        now = clock().replace(tzinfo=None, microsecond=0)
        cr.require(now >= cr.timestamp(state["observedAt"]), "CANDIDATE_STAGE_CLOCK")
        journal_raw = monitor.read_import_bytes(store / "distribution/journal.json")
        state_raw = monitor.read_import_bytes(store / "state.json")
        journal = distribution.verify_layout(store / "distribution")
        cr.require(journal["pendingRun"] is None and all(run["phase"] == "FINISHED" and
                   run["pendingJob"] is None for run in journal["runs"].values()), "CANDIDATE_STAGE_PENDING")
        head = distribution.read_candidate_head(store, admission.document)
        cr.require(head is not None, "CANDIDATE_STAGE_NO_HEAD")
        cr.require(all(head[name] == original_binding[name] for name in
                   ("packageManifestSha256", "seedManifestSha256")), "CANDIDATE_STAGE_ORIGINAL_BINDING")
        _, _, hashes = distribution.inputs_at(package, root)
        cr.require(head["inputHashes"] == hashes, "CANDIDATE_STAGE_INPUT_CHANGED")
        original_context = {name: head[name] for name in ("monitorIdentity", "packageManifestSha256",
                            "seedManifestSha256", "producerHashes")}
        observations = [{"reference": reference, "observation": distribution.read_candidate(
                        store, reference, journal, original_context)} for reference in head["includedCandidates"]]
        cr.require(observations and all(now < cr.timestamp(row["observation"]["validUntilUtc"])
                   for row in observations), "CANDIDATE_STAGE_EXPIRED")
        cr.require(any(0 <= (now - cr.timestamp(row["observation"]["checkedAtUtc"])).total_seconds() <= 86400
                   for row in observations), "CANDIDATE_STAGE_NO_FRESH_OBSERVATION")
        directory = store / "distribution/runs" / head["runId"]
        content = {name: distribution.profiles.read_raw(directory / name) for name in
                   sorted(set(head["outputs"]) | {"build-commit.json", "unsigned-validation.json"})}
        head_raw = distribution.profiles.read_raw(store / "distribution/candidate-head.json")
        cr.require(content["build-commit.json"] == head_raw and cr.parse_json(head_raw) == head,
                   "CANDIDATE_STAGE_COMMIT")
        provenance = cr.parse_json(content["provenance.json"])
        cr.require(provenance["observations"] == observations and all(provenance[name] == head[name]
                   for name in ("runId", "inputHashes", "producerHashes", "monitorIdentity")),
                   "CANDIDATE_STAGE_PROVENANCE")
        sources, records = {}, {}
        for row in observations:
            candidate = row["observation"]
            for source in candidate["sources"]:
                key = source["sourceId"]
                cr.require(key not in sources or sources[key] == source, "CANDIDATE_STAGE_SOURCE_CONFLICT")
                sources[key] = source
            for record in candidate["records"]:
                key = (record["sourceId"], record["recordId"])
                cr.require(key not in records, "CANDIDATE_STAGE_RECORD_CONFLICT")
                records[key] = record
        entries = []
        for key in sorted(records):
            raw = json.dumps(records[key], ensure_ascii=False, sort_keys=True,
                             separators=(",", ":"), allow_nan=False).encode("utf-8")
            entries.append({"recordBytesBase64": distribution.base64.b64encode(raw).decode("ascii"),
                            "recordSha256": cr.digest(raw)})
        index = cr.parse_json(content["index.json"])
        cr.require(entries and index == {"schema": "driver-index-records-v2", "assetGeneration": head["generation"],
                   "sources": [sources[key] for key in sorted(sources)], "records": entries},
                   "CANDIDATE_STAGE_RECORD_BINDING")
        output = transfer / "distribution"
        output.mkdir()
        target = output / "runs" / head["runId"]
        target.mkdir(parents=True)
        for name, raw in content.items():
            monitor.write_new_bytes(target / name, raw)
            cr.require(distribution.profiles.read_raw(target / name) == raw, "CANDIDATE_STAGE_READBACK")
        if checkpoint:
            checkpoint("OUTPUTS_SAVED", output)
        cr.require(not admission.used and admission.parent_alive() and
                   admission.identity(root) == admission.document["workspaceIdentity"] and
                   admission.identity(store) == admission.document["monitorIdentity"], "NATIVE_CONTEXT_RELEASED")
        cr.require(distribution.profiles.read_raw(store / "distribution/candidate-head.json") == head_raw and
                   monitor.read_import_bytes(root / "workspace.json") == workspace_raw and
                   monitor.read_import_bytes(store / "distribution/journal.json") == journal_raw and
                   monitor.read_import_bytes(store / "state.json") == state_raw and
                   distribution.inputs_at(package, root)[2] == hashes and
                   all(distribution.profiles.read_raw(directory / name) == raw for name, raw in content.items()),
                   "CANDIDATE_STAGE_SOURCE_CHANGED")
        monitor.write_new_bytes(output / "candidate-head.json", head_raw)
        cr.require(distribution.read_candidate_head(transfer, admission.document) == head,
                   "CANDIDATE_STAGE_READBACK")
        admission.used = True
        return {"schema": "dc-collector-offline-result-v1", "operation": "stage-candidate",
                "result": "STAGED_UNSIGNED", "candidateHeadSha256": cr.digest(head_raw),
                "runId": head["runId"], "records": len(records), "unsigned": True,
                "authenticated": False, "signingGenerationFinalized": False,
                "communicationAuthorized": False, "freshObservationCreated": False, "tasks": 0}


def operate(package: Path, action: str, root: Path, transfer: Path | None,
            *, checkpoint=None, clock=monitor.utc_now, admission=None) -> dict:
    """明示された閉集合の一操作を既存monitorへ委譲し、通信不可を別fieldに残す。

    initialize/importはworkspace.jsonを先に排他的保存してからmonitorへ委譲する。
    後段の例外や最終再検査失敗でも先行workspace、staging、stateは保持し、
    自動削除・rollbackしない。resumeは同じsnapshotの中断状態だけを既存monitorで検査する。
    """
    cr.require(action in ACTIONS, "WORKSPACE_ACTION")
    expected = binding(package)
    if action in {"initialize", "import"}:
        cr.require(not any(root.iterdir()), "WORKSPACE_NOT_EMPTY")
        monitor.write_new_bytes(root / "workspace.json", cr.json_bytes(expected))
    validate_workspace(root, expected, allow_stage=action == "resume")
    store = root / "monitor"
    if (action in {"verify", "export"} and expected["schema"] == "dc-collector-explicit-workspace-v1"
            and (root / "origin.json").exists()):
        cr.require(admission is not None, "NATIVE_LIVE_CONTEXT_REQUIRED")
        cr.require(admission.document.get("operation") == action, "NATIVE_CONTEXT_OPERATION")
        policy = cr.read_json(package / "config/monitor-policy.json")
        store = admission.validate(package, root, expected, policy, clock)
    if action == "initialize":
        monitor.initialize(store, clock=clock)
        if (package / "seed/distribution-data").exists():
            import collector_distribution_data as data
            data.import_data(root, package / "seed/distribution-data")
    elif action == "verify":
        if (root / "data").exists():
            import collector_distribution_data as data
            data.active_bundle(root, retained=True)
        with monitor.writer_lock(store):
            state = monitor.verify_store(store)
            cr.require(clock() >= cr.timestamp(state["observedAt"]), "WORKSPACE_CLOCK")
    elif action == "export":
        cr.require(transfer is not None and not any(transfer.iterdir()), "WORKSPACE_EXPORT_ROOT")
        state = monitor.verify_store(store)
        cr.require(clock() >= cr.timestamp(state["observedAt"]), "WORKSPACE_CLOCK")
        monitor.export_store(store, transfer / "snapshot")
    else:
        cr.require(transfer is not None, "WORKSPACE_SNAPSHOT_REQUIRED")
        monitor.import_export(transfer, store, source_stop_acknowledged=True,
                              resume=action == "resume", checkpoint=checkpoint, clock=clock)
    validate_workspace(root, expected)
    state = monitor.verify_store(store)
    if admission is not None:
        cr.require(not admission.used and admission.parent_alive(), "NATIVE_CONTEXT_RELEASED")
        cr.require(admission.identity(store) == admission.document["monitorIdentity"], "MONITOR_ORIGIN_CHANGED")
        admission.used = True
    return {"schema": "dc-collector-offline-result-v1", "operation": action, "result": "VERIFIED_OFFLINE",
            "communicationAuthorized": False, "nativeConstraints": "UNKNOWN",
            "originalDayBudget": "UNVERIFIED", "requests": len(state["requests"]),
            "reports": len(list((store / "reports").iterdir())), "tasks": 0}


def main(arguments: list[str] | None = None) -> int:
    """固定native argvを受理し、非通信操作または明示run-onceの結果を有限JSONで返す。

    run-onceは明示同意と生きたnative capabilityが必要で、許可されたHTTPを含む。
    正常は0、捕捉対象の拒否は診断値付きJSONで2、run-onceのHOLDは3を返す。
    取得したlive capabilityは各finallyでcloseする。登録したaudit hookは解除せず、
    このprocessの終了まで残る。
    """
    arguments = sys.argv[1:] if arguments is None else arguments
    try:
        cr.require(len(arguments) in {4, 6}, "WORKSPACE_ARGUMENTS")
        package, action, root, transfer = arguments[:4]
        if action in {"switch-package", "review-held-host", "stage-candidate"}:
            cr.require(len(arguments) == 4 and transfer, "WORKSPACE_ARGUMENTS")
            sys.addaudithook(reject_external_execution)
            live = DistributionAdmission.read(Path(package))
            try:
                if action == "stage-candidate":
                    result = stage_candidate(Path(package), Path(root), Path(transfer), live)
                else:
                    result = (switch_package(Path(package), Path(root), transfer, live) if action == "switch-package" else
                              review_held_host(Path(package), Path(root), Path(transfer), live))
            finally:
                live.close()
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
            return 0
        if action == "import-data":
            cr.require(len(arguments) == 4 and transfer, "DATA_IMPORT_ARGUMENTS")
            sys.addaudithook(reject_external_execution)
            validate_workspace(Path(root), binding(Path(package)))
            import collector_distribution_data as data
            result = data.import_data(Path(root), Path(transfer))
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
            return 0
        if action == "distribution-run-once":
            cr.require(len(arguments) == 6 and transfer == "--confirm-inspection-download" and
                       arguments[4] == "--fixed-distribution-bridge", "DISTRIBUTION_CONSENT_REQUIRED")
            sys.addaudithook(reject_external_execution)
            import collector_distribution_pipeline as distribution
            bridge = distribution.NativeBridge.connect(Path(package), arguments[5])
            try:
                result = distribution.run_once(Path(package), Path(root), bridge, confirmed=True)
            finally:
                bridge.stream.close()
                bridge.close()
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
            return 0 if result["result"] == "COMPLETE" else 3
        if action == "initialize-distribution-origins":
            cr.require(len(arguments) == 4 and transfer, "DISTRIBUTION_ORIGIN_ARGUMENTS")
            sys.addaudithook(reject_external_execution)
            validate_workspace(Path(root), binding(Path(package)))
            import collector_distribution_pipeline as distribution
            inputs, value, _ = distribution.inputs_at(Path(package), Path(root))
            plan = distribution.profiles.plan_profiles(value, inputs)
            plan_path = Path(root) / "distribution-initial-plan-v1.json"
            if plan_path.exists():
                cr.require(cr.read_json(plan_path) == plan, "DISTRIBUTION_INITIAL_PLAN_CHANGED")
            else:
                distribution.save_json(plan_path, plan)
            store = Path(transfer)
            # 初回専用であり既存historyは初期化し直さない。部分作成窓は空集合だけ再開する。
            if not store.exists():
                monitor.initialize(store)
            else:
                descriptor = cr.read_json(Path(root) / "distribution-origin-init-v1.json")
                imported = (store / "import-metadata.json").exists()
                if imported:
                    monitor.validate_import_metadata(cr.read_json(store / "import-metadata.json"))
                    monitor.verify_store(store)
                # monitor identity確定前の既知空保存窓だけをresumeし、既知state消失は修復しない。
                if not descriptor["monitorIdentity"] and not descriptor["legacyHistoryEverObserved"] and not imported:
                    cr.regular_path(store, directory=True)
                    cr.require({path.name for path in store.iterdir()} <= {"reports", "writer.lock", "state.json"},
                               "DISTRIBUTION_ORIGIN_NOT_EMPTY")
                    if not (store / "reports").exists():
                        (store / "reports").mkdir()
                    cr.require(not any((store / "reports").iterdir()), "DISTRIBUTION_ORIGIN_NOT_EMPTY")
                    if not (store / "writer.lock").exists():
                        monitor.write_new_bytes(store / "writer.lock", b"0")
                    if not (store / "state.json").exists():
                        now = monitor.stamp(monitor.utc_now())
                        monitor.write_new_bytes(store / "state.json", monitor.envelope("dc-monitor-state-envelope-v1",
                            {"schema": monitor.STATE_SCHEMA, "createdAt": now, "observedAt": now,
                             "requests": {}, "hosts": {}}))
                with monitor.writer_lock(store):
                    state = monitor.verify_store(store)
                    legacy = descriptor["legacyHistoryEverObserved"] is True
                    imported = (store / "import-metadata.json").exists()
                    if imported:
                        monitor.validate_import_metadata(cr.read_json(store / "import-metadata.json"))
                    cr.require(legacy or imported or (not state["requests"] and not state["hosts"] and
                               not any((store / "reports").iterdir())), "DISTRIBUTION_ORIGIN_NOT_EMPTY")
            print('{"result":"PRISTINE_MONITOR_INITIALIZED","network":0,"tasks":0}')
            return 0
        if action == "bind-origins":
            cr.require(len(arguments) == 4 and not transfer, "WORKSPACE_ARGUMENTS")
            sys.addaudithook(reject_external_execution)
            live = NativeAdmission.read(Path(package))
            try:
                result = bind_origins(Path(package), Path(root), live)
            finally:
                live.close()
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
            return 0
        if action == RUN_ACTION:
            cr.require(len(arguments) == 6 and transfer == "--confirm-monitor-once", "WORKSPACE_RUN_CONSENT_REQUIRED")
            # Nativeの実leaseを継承pipeへ結合し、argvの値だけで許可を発行しない。
            cr.require(arguments[5] and len(arguments[5]) == 64, "WORKSPACE_TRANSPORT_BINDING")
            live = NativeAdmission.read(Path(package))
            try:
                result = run_monitor_once(Path(package), Path(root), confirmed=True, curl=arguments[4],
                                          curl_sha256=arguments[5], admission=live)
            finally:
                live.close()
            print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
            return 3 if result["result"] == "HOLD" else 0
        cr.require(len(arguments) == 4, "WORKSPACE_ARGUMENTS")
        cr.require(action in ACTIONS and bool(transfer) == (action in {"export", "import", "resume"}),
                   "WORKSPACE_ARGUMENTS")
        sys.addaudithook(reject_external_execution)
        live = None
        try:
            if (action in {"verify", "export"} and (Path(root) / "origin.json").exists()
                    and cr.read_json(Path(root) / "workspace.json")["schema"] == "dc-collector-explicit-workspace-v1"):
                admission_type = DistributionAdmission if (Path(root) / "distribution-origin-init-v1.json").exists() else NativeAdmission
                live = admission_type.read(Path(package))
            result = operate(Path(package), action, Path(root), Path(transfer) if transfer else None, admission=live)
        finally:
            if live is not None:
                live.close()
        print(json.dumps(result, ensure_ascii=True, separators=(",", ":")))
        return 0
    except (OSError, ValueError, KeyError, cr.RegistryError) as error:
        code = str(error) if isinstance(error, cr.RegistryError) else type(error).__name__
        print(json.dumps({"result": "REJECTED", "code": code, "communicationAuthorized": False,
                          "nativeConstraints": "UNKNOWN", "originalDayBudget": "UNVERIFIED"},
                         ensure_ascii=True, separators=(",", ":")))
        return 2
