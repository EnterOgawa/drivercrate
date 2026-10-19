"""収集setupの固定bootstrap用workspace／明示monitor adapter（ADR0355／0357）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
Nativeが実handle・ACL・payload・receiptを検査してからだけ呼び出す。
v4は非通信のinitialize／verify／export／import／resumeだけを扱う。
v5は既存native writerと保護原点へ結合した非共有PAGEだけを明示一回実行する。
bind済みv5の非通信verify／exportも同じactive原点へ結合する。
monitor一回64要求／32MiB／600秒とnative共有JST日予算は別の制約である。
共有／未知native modeは専用HOLDへ残す。実HTTPの受入は別工程である。
Task、鍵、実端末inventoryは扱わず、明示runの実収集成功は未確認である。
"""
from __future__ import annotations

import json
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

SCHEMA = "dc-collector-offline-workspace-v1"
ACTIONS = frozenset({"initialize", "verify", "export", "import", "resume"})
RUN_ACTION = "run-once"
CONTEXT_LIMIT = 256 * 1024


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


def native_pipe_parent(package: Path):
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
    pipe = msvcrt.get_osfhandle(sys.stdin.fileno())
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


def binding(package: Path) -> dict:
    """固定seed全意味とpolicyを既存validatorへ委譲し非通信結合だけを返す。"""
    registry, _, _ = snapshot.verify_snapshot(package / "seed" / "collector-data")
    monitor.validate_policy(registry, cr.read_json(package / "config" / "monitor-policy.json"))
    manifest = cr.read_json(package / "package-manifest.json")
    offline = manifest["schema"] == "dc-collector-package-v4" and manifest["mode"] == "OFFLINE_PROTECTED_REGISTRY_WORKSPACE"
    explicit = manifest["schema"] == "dc-collector-package-v5" and manifest["mode"] == "EXPLICIT_ONCE_REGISTRY_MONITOR"
    cr.require(offline or explicit, "WORKSPACE_PACKAGE_VERSION")
    receipt = cr.read_json(package / "install-receipt.json")
    package_hash = cr.digest((package / "package-manifest.json").read_bytes())
    cr.require(receipt["packageManifestSha256"] == package_hash, "WORKSPACE_RECEIPT")
    return {"schema": "dc-collector-explicit-workspace-v1" if explicit else SCHEMA, "packageManifestSha256": package_hash,
            "seedManifestSha256": cr.digest((package / "seed" / "collector-data" / "manifest.json").read_bytes()),
            "communicationAuthorized": False, "nativeConstraints": "UNKNOWN",
            "originalDayBudget": "UNVERIFIED"}


def validate_workspace(root: Path, expected: dict, *, allow_stage: bool = False) -> None:
    """Rootは固定bindingとmonitorだけを持ち、再開時だけ同名stagingを許す。"""
    cr.require(cr.read_json(root / "workspace.json") == expected, "WORKSPACE_BINDING")
    names = {path.name for path in root.iterdir()}
    allowed = {"workspace.json", "monitor", "origin.json"}
    if allow_stage:
        stages = {name for name in names if name.startswith("monitor.import-") and
                  len(name) == len("monitor.import-") + 32 and
                  all(letter in "0123456789abcdef" for letter in name[len("monitor.import-"):])}
        cr.require(len(stages) <= 1, "WORKSPACE_STAGE_COUNT")
        allowed |= stages
    cr.require(names <= allowed and "workspace.json" in names, "WORKSPACE_FILE_SET")


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
    elif action == "verify":
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
                live = NativeAdmission.read(Path(package))
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


if __name__ == "__main__":
    raise SystemExit(main())
