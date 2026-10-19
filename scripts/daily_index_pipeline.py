"""固定Intel日次収集・明示用途の配布署名・Private索引限定反映（ADR0344/0366/0370/0373）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
監視PC専用Python3。plan/task/reportは収集・鍵・GitHub書込みを行わない。
用途別開始記録と公表hashの契約: docs/adr/0373-acquisition-digest-and-legacy-day-entry.md。
一段だけの修復継承: docs/adr/0374-receipt-anchor-and-code-only-continuation.md。
既知の署名前checkpoint継承: docs/adr/0375-explicit-presign-checkpoint-continuation.md。
四原file保持の一回caller更新: docs/adr/0376-verified-unsigned-presign-caller-refresh.md。
asset実byte長と証拠専用回復の境界: docs/adr/0377-asset-upload-length-and-pinned-draft-recovery.md。
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
import uuid

# Task uses Python -I; only the explicitly protected sibling module directory is added.
sys.path.insert(0, str(Path(__file__).resolve().parent))
import collector_registry as cr
import project_collected_native_index as projection

REPOSITORY = "EnterOgawa/drivercrate"
API = "repos/" + REPOSITORY
STATE_RELATIVE = Path("work/state/driver-collector-acceptance-20261013-202")
WORKSPACE_APPROVAL_FIELDS = frozenset({"schema", "approvalKind", "taskName", "collectorManifestSha256",
                                      "repositoryRoot", "stateRoot"})
ASSETS = frozenset({"index.json.gz", "manifest.json"})
ASSET_UPLOAD_PATTERN = (re.escape("https://uploads.github.com/" + API) +
    r"/releases/[1-9][0-9]*/assets\?name=(index\.json\.gz|manifest\.json)")
MAX_FILE = 16 * 1024 * 1024
MAX_SECONDS = 1800
MAX_WAIT = 300
TASK_NAME = "DriverCrate.PrivateIndex.Daily229"
TASK_NS = "http://schemas.microsoft.com/windows/2004/02/mit/task"
CONFIG_FIELDS = frozenset({"schema", "repositoryRoot", "stateRoot", "manifestFile", "manifestSha256",
    "scopeFile", "scopeSha256", "collectorExe", "collectorSha256", "signerExe", "signerSha256",
    "publicKeyFile", "fingerprint", "pythonExe", "ghExe", "outputRoot", "smokeLocal", "firstDailyLocal",
    "pipelineSha256", "producerSha256"})
ACQUISITION_PURPOSE = "DISTRIBUTION_ACQUISITION"
V2_CONFIG_FIELDS = CONFIG_FIELDS | {"purpose", "termsReviewMode", "modulePins", "originalInputs",
    "archiveFile", "archiveSha256", "archiveBytes", "selectedInf", "legacyMetadata", "legacyReservationFence"}
MODULE_NAMES = frozenset({"daily_index_pipeline.py", "project_collected_native_index.py", "collector_registry.py",
                          "prepare_daily_index_config.py"})
CODE_REPAIR_FIELDS = frozenset({"schema", "configFile", "configSha256", "startFile", "startSha256",
    "receiptFile", "receiptSha256", "priorNativeCalls", "priorElapsedSeconds", "preparationNativeCalls",
    "preparationElapsedSeconds"})
PRESIGN_FIELDS = frozenset({"schema", "configFile", "configSha256", "markerFile", "markerSha256",
    "bodySha256", "releaseSha256", "phaseEvidenceFile", "phaseEvidenceSha256", "contentEvidenceFile",
    "contentEvidenceSha256", "failureTerminalFile", "failureTerminalSha256", "priorNativeCalls",
    "priorElapsedSeconds", "preparationNativeCalls", "preparationElapsedSeconds"})
VERIFIED_UNSIGNED_SCHEMA = "dc-daily-presign-verified-unsigned-refresh-v1"
VERIFIED_UNSIGNED_FIELDS = frozenset({"schema", "configFile", "configSha256", "markerFile", "markerSha256",
    "bodySha256", "releaseSha256", "inspectionSha256", "scriptSha256", "failureTerminalFile",
    "failureTerminalSha256", "budgetWitnessFile", "budgetWitnessSha256", "priorNativeCalls",
    "priorElapsedSeconds", "preparationNativeCalls", "preparationElapsedSeconds"})
CARRY_WITNESS_FIELDS = frozenset({"utc", "priorNativeCalls", "priorElapsedSeconds", "actualPrepareNativeCalls",
    "actualPrepareMeasuredSeconds", "prepareOuterObservedSeconds", "runActualMeasuredSeconds",
    "runProcessCountDirectlyObserved", "runPathNativeCallUpperBound", "runWallSecondsConservativeUpperBound",
    "runWallUpperBoundBasis", "nativeCallsIncludingCarryUpperBound",
    "elapsedSecondsIncludingCarryConservativeUpperBound", "globalLimits", "qualification"})
VERIFIED_UNSIGNED_CARRY_CALLS = 15
VERIFIED_UNSIGNED_CARRY_SECONDS = 144.72357580207824
LEGACY_FIELDS = frozenset({"kind", "configFile", "configSha256", "receiptFile", "receiptSha256",
    "rawManifestFile", "rawManifestSha256", "gzipFile", "gzipSha256", "envelopeFile", "envelopeSha256",
    "fenceReceiptFile"})
MANIFEST_SHA256 = "556636e998dc3b33f8d9223aaacf9301c3c99cf5b2bbcedc569756065c18dd83"
TRUSTED_OWNERS = frozenset({"S-1-5-18", "S-1-5-32-544",
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"})
# 診断は固定用途だけを公開し、routeに含まれる動的な識別子は保持しない。
GITHUB_ROUTES = (
    ("GET", "user", "USER_READ"),
    ("GET", re.escape(API), "REPOSITORY_READ"),
    ("GET", re.escape(API) + r"/git/ref/heads/driver-index", "INDEX_REF_READ"),
    ("GET", re.escape(API) + r"/releases/tags/index-v1-[0-9]{8}-[0-9a-f]{64}", "RELEASE_LOOKUP"),
    ("GET", re.escape(API) + r"/releases/assets/[1-9][0-9]*", "ASSET_READ"),
    ("POST", re.escape(API) + r"/releases", "RELEASE_CREATE"),
    ("POST", ASSET_UPLOAD_PATTERN, "ASSET_UPLOAD"),
    ("GET", re.escape(API) + r"/releases/[1-9][0-9]*", "RELEASE_READ"),
    ("PATCH", re.escape(API) + r"/releases/[1-9][0-9]*", "RELEASE_UPDATE"),
    ("GET", re.escape(API) + r"/git/commits/[0-9a-f]{40}", "INDEX_COMMIT_READ"),
    ("GET", re.escape(API) + r"/git/trees/[0-9a-f]{40}\?recursive=1", "INDEX_TREE_READ"),
    ("GET", re.escape(API) + r"/git/blobs/[0-9a-f]{40}", "INDEX_BLOB_READ"),
    ("POST", re.escape(API) + r"/git/blobs", "INDEX_BLOB_CREATE"),
    ("POST", re.escape(API) + r"/git/trees", "INDEX_TREE_CREATE"),
    ("POST", re.escape(API) + r"/git/commits", "INDEX_COMMIT_CREATE"),
    ("POST", "graphql", "INDEX_REF_CAS"),
)
GITHUB_PURPOSE_METHODS = {purpose: method for method, _, purpose in GITHUB_ROUTES}
GITHUB_FAILURE_FIELDS = frozenset({"schema", "api", "method", "ordinal", "stage", "childExitCode",
    "outerTimeout", "cliReportedHttpStatus", "httpStatusSource", "remoteWriteOutcome"})
GITHUB_FAILURE_STAGES = frozenset({"BUDGET_TIMEOUT", "BUDGET_OUTPUT_LIMIT", "BUDGET_EXCEPTION",
    "CLI_EXIT", "RESPONSE_PARSE"})


def require(value: bool, code: str) -> None:
    if not value:
        raise ValueError(code)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_time(value: str) -> datetime:
    require(type(value) is str, "TIME_TYPE")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None and result.microsecond == 0, "TIME_ZONE")
    return result


def normal_path(value: str, *, exists: bool = True) -> Path:
    require(type(value) is str and bool(value) and "\x00" not in value, "PATH_TYPE")
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts and ":" not in str(path)[2:] and
            not str(path).startswith("\\\\"), "ABSOLUTE_FIXED_PATH")
    for item in (path, *path.parents):
        require(not item.is_symlink() and not item.is_junction(), "REPARSE_PATH")
        if item.exists():
            require(item.stat().st_file_attributes & 0x400 == 0, "REPARSE_PATH")
    require(not exists or path.exists(), "MISSING_PATH")
    return path


def protected_root() -> Path:
    """環境変数を使わずOSのProgramData既知folderから専用rootを得る。"""
    require(os.name == "nt", "WINDOWS_PROTECTED_RUNTIME_REQUIRED")
    shell = ctypes.WinDLL("shell32", use_last_error=True)
    ole = ctypes.WinDLL("ole32", use_last_error=True)
    shell.SHGetKnownFolderPath.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_void_p,
                                          ctypes.POINTER(ctypes.c_void_p)]
    shell.SHGetKnownFolderPath.restype = ctypes.c_long
    ole.CoTaskMemFree.argtypes = [ctypes.c_void_p]
    folder = ctypes.create_string_buffer(uuid.UUID("62AB5D82-FDC1-4DC3-A9DD-070D1D495D97").bytes_le)
    raw = ctypes.c_void_p()
    require(shell.SHGetKnownFolderPath(folder, 0x4000, None, ctypes.byref(raw)) == 0 and raw.value,
            "PROGRAMDATA_LOOKUP")
    try:
        return normal_path(str(Path(ctypes.wstring_at(raw)) / "DriverCrate/PrivateIndex229"), exists=False)
    finally:
        ole.CoTaskMemFree(raw)


def acl_snapshot(path: Path) -> tuple[str, bool, list[tuple[int, int, int, str]]]:
    """owner/DACLをOSから読み、未知ACEをfail-closed用の型情報と共に返す。"""
    adv = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    ptr = ctypes.c_void_p
    adv.GetNamedSecurityInfoW.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32,
        ctypes.POINTER(ptr), ptr, ctypes.POINTER(ptr), ptr, ctypes.POINTER(ptr)]
    adv.GetNamedSecurityInfoW.restype = ctypes.c_uint32
    adv.ConvertSidToStringSidW.argtypes = [ptr, ctypes.POINTER(ptr)]
    adv.ConvertSidToStringSidW.restype = ctypes.c_int
    adv.GetSecurityDescriptorControl.argtypes = [ptr, ctypes.POINTER(ctypes.c_ushort),
                                                ctypes.POINTER(ctypes.c_uint32)]
    adv.GetSecurityDescriptorControl.restype = ctypes.c_int
    adv.GetAce.argtypes = [ptr, ctypes.c_uint32, ctypes.POINTER(ptr)]
    adv.GetAce.restype = ctypes.c_int
    kernel.LocalFree.argtypes = [ptr]
    kernel.LocalFree.restype = ptr
    owner, dacl, descriptor = ptr(), ptr(), ptr()
    require(adv.GetNamedSecurityInfoW(str(path), 1, 5, ctypes.byref(owner), None,
            ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0, "PROTECTED_ACL_QUERY")

    def sid_text(sid):
        value = ptr()
        require(adv.ConvertSidToStringSidW(sid, ctypes.byref(value)), "PROTECTED_SID_QUERY")
        try:
            return ctypes.wstring_at(value)
        finally:
            kernel.LocalFree(value)

    try:
        require(owner.value and dacl.value, "PROTECTED_NULL_DACL")
        control, revision = ctypes.c_ushort(), ctypes.c_uint32()
        require(adv.GetSecurityDescriptorControl(descriptor, ctypes.byref(control), ctypes.byref(revision)),
                "PROTECTED_DACL_CONTROL")
        count = int.from_bytes(ctypes.string_at(dacl.value + 4, 2), "little")
        require(count <= 4096, "PROTECTED_ACE_LIMIT")
        entries = []
        for position in range(count):
            ace = ptr()
            require(adv.GetAce(dacl, position, ctypes.byref(ace)), "PROTECTED_ACE_QUERY")
            header = ctypes.string_at(ace, 8)
            kind, flags = header[0], header[1]
            require(int.from_bytes(header[2:4], "little") >= 8, "PROTECTED_ACE_SIZE")
            entries.append((kind, flags, int.from_bytes(header[4:8], "little"),
                            sid_text(ace.value + 8) if kind in {0, 1} else ""))
        return sid_text(owner), bool(control.value & 0x1000), entries
    finally:
        kernel.LocalFree(descriptor)


# 借用snapshotのownerは信頼集合内、require_protected時のDACLは保護済みであることを要求する。
# INHERIT_ONLYとdeny ACEはallow付与の検査から外し、その後の未知ACE kindは拒否する。
# 固定maskによるsnapshot policyの検査であり、完全なOS有効アクセス計算ではない。
def check_acl(snapshot, *, ancestor=False, require_protected=False) -> None:
    owner, protected, entries = snapshot
    require(owner in TRUSTED_OWNERS, "PROTECTED_OWNER")
    require(not require_protected or protected, "PROTECTED_DACL_REQUIRED")
    # protected_pathの対象/専用root内等では内容・属性の変更も、遠い外祖先では既存子の
    # 置換に関わる権限を拒否する。二maskとも一般利用者の削除・DACL/owner変更等を含む。
    mask = (0x000D0040 if ancestor else 0x000D0156) | 0x50000000
    for kind, flags, rights, sid in entries:
        if flags & 8 or kind == 1:
            continue
        require(kind == 0, "PROTECTED_ACE_KIND")
        require(not rights & mask or sid in TRUSTED_OWNERS, "PROTECTED_GENERAL_USER_WRITE")


def protected_path(path: Path, *, root: Path | None = None) -> None:
    """実対象/専用root内は内容書込み、外祖先は既存子の置換を拒否する。ACLを変更しない。"""
    path = normal_path(str(path))
    root = root or protected_root()
    if path.is_file():
        require(path.stat().st_nlink == 1, "PROTECTED_HARDLINK")
    for position, item in enumerate((path, *path.parents)):
        inside = item == root or root in item.parents
        check_acl(acl_snapshot(item), ancestor=not inside and position >= 2,
                  require_protected=item == root)


def operation_root(path: Path, *, exists=True) -> Path:
    path = normal_path(str(path), exists=exists)
    root = protected_root()
    require(path.parent == root / "operations" and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,79}", path.name),
            "PROTECTED_OPERATION_ROOT")
    protected_path(path if exists else path.parent, root=root)
    require(not exists or path.is_dir(), "PROTECTED_OPERATION_DIRECTORY")
    return path


def protected_tree(directory: Path) -> None:
    """runtimeと操作中間物を4096項目/20秒で列挙し、全対象の実ACLを検査する。"""
    deadline = time.monotonic() + 20
    protected_path(directory)
    count = 0
    for parent, directories, files in os.walk(directory, followlinks=False):
        for name in directories + files:
            count += 1
            require(count <= 4096 and time.monotonic() < deadline, "PROTECTED_TREE_LIMIT")
            protected_path(Path(parent) / name)


def read(path: Path, maximum: int = MAX_FILE) -> bytes:
    """通常pathの非空fileを最大maximum byteで読み、所有byte列を返す。

    開いたstreamは本関数が閉じる。過大・空・path違反は拒否し、I/O例外は伝播する。
    ACLと用途の許可は呼出し側が別途検証する。
    """
    normal_path(str(path))
    require(path.is_file() and 0 < path.stat().st_size <= maximum, "FILE_SIZE")
    with path.open("rb") as stream:
        value = stream.read(maximum + 1)
    require(0 < len(value) <= maximum, "READ_SIZE")
    return value


def write_new(path: Path, raw: bytes) -> None:
    """非空・MAX_FILE以下のbyteを新規fileへ書き、flush/fsync後に閉じる。

    呼出し側が保護された保存先を選ぶ。既存fileは拒否し、失敗時の部分fileは残して
    例外を伝播する。上書き・自動削除・原子的な一括commitは行わない。
    """
    normal_path(str(path), exists=False)
    require(0 < len(raw) <= MAX_FILE, "WRITE_SIZE")
    with path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def keep_exact(path: Path, raw: bytes) -> None:
    """既存fileは原byte一致時だけ再利用し、欠損時だけwrite_newで作る。

    不一致とI/O失敗は伝播し、再開のために既存byteを置換しない。
    """
    if path.exists():
        require(read(path) == raw, "RESUME_BYTES_CONFLICT")
    else:
        write_new(path, raw)


@dataclass(frozen=True)
class WorkspaceBinding:
    """保護された明示承認recordの位置・全byte hashと既存root/stateをprocess内へ固定する。"""
    approvalFile: Path
    approvalSha256: str
    repositoryRoot: Path
    stateRoot: Path


# 承認recordは発行せず、初回に検証した原byteのhashとroot/stateの組をprocess終了まで保持する。
_APPROVED_WORKSPACE: WorkspaceBinding | None = None


def approved_workspace() -> WorkspaceBinding:
    """OS既知の保護位置にある明示承認だけを読み、原byte変更と任意pathへのfallbackを拒否する。

    recordの実発行・配置は別途承認を要し、本関数は生成やACL変更を行わない。
    root/stateは既存の通常directoryで固定相対stateが一致する必要がある。使用のたびに
    ACL/path/hashを再確認し、検証失敗やI/O例外は伝播する。収集やTask切替の許可は発行しない。
    """
    global _APPROVED_WORKSPACE
    root = protected_root()
    path = root / "control/approved-workspace.json"
    require(path.exists(), "WORKSPACE_APPROVAL_REQUIRED")
    protected_path(path, root=root)
    raw = read(path, 65536)
    digest = sha(raw)
    if _APPROVED_WORKSPACE is not None:
        require(path == _APPROVED_WORKSPACE.approvalFile and digest == _APPROVED_WORKSPACE.approvalSha256,
                "WORKSPACE_APPROVAL_CHANGED")
    approval = cr.parse_json(raw)
    cr.fields(approval, WORKSPACE_APPROVAL_FIELDS, "WORKSPACE_APPROVAL_FIELDS")
    require(approval["schema"] == "dc-approved-daily-workspace-v1" and
            approval["approvalKind"] == "EXPLICIT_EXISTING_DAILY_WORKSPACE" and
            approval["taskName"] == TASK_NAME and approval["collectorManifestSha256"] == MANIFEST_SHA256,
            "WORKSPACE_APPROVAL_AUTHORITY")
    repository = normal_path(approval["repositoryRoot"])
    state = normal_path(approval["stateRoot"])
    require(repository.is_dir() and state.is_dir() and state == repository / STATE_RELATIVE,
            "FIXED_EXISTING_ROOT")
    binding = WorkspaceBinding(path, digest, repository, state)
    require(_APPROVED_WORKSPACE is None or binding == _APPROVED_WORKSPACE, "WORKSPACE_APPROVAL_CHANGED")
    _APPROVED_WORKSPACE = binding
    return binding


def require_config_workspace(config: dict) -> WorkspaceBinding:
    """通常configのroot/stateを独立した明示承認へ完全一致させ、承認済みの組を返す。"""
    binding = approved_workspace()
    require(normal_path(config["repositoryRoot"]) == binding.repositoryRoot and
            normal_path(config["stateRoot"]) == binding.stateRoot, "FIXED_EXISTING_ROOT")
    return binding


def load_config(path: Path, *, inherited_v1: bool = False, predecessor_v2: bool = False,
                presign_predecessor: bool = False,
                verified_unsigned_predecessor: bool = False) -> tuple[dict, dict, str]:
    """固定保護配置のconfig・入力・runtimeをACL/hash/scopeで検証して返す。

    読取りだけを行い、拒否やI/O失敗は伝播する。この検証は収集・署名・Task登録・
    GitHub操作を実行せず、それらの実行承認も発行しない。
    verified_unsigned_predecessorは追加遷移が旧preSign v1を認証する内部contextに限り、
    旧版の実moduleを検証する。通常入口のpartial拒否や実行権限は変更しない。
    """
    root = protected_root()
    require(root / "control" in path.parents and path.name == "config.json", "PROTECTED_CONFIG_LOCATION")
    protected_path(path, root=root)
    raw = read(path, 65536)
    config = cr.parse_json(raw)
    acquisition = config.get("schema") == "dc-private-daily-index-config-v2"
    fields = V2_CONFIG_FIELDS | ({"codeRepair"} if "codeRepair" in config else set()) | (
        {"preSignContinuation"} if "preSignContinuation" in config else set())
    cr.fields(config, fields if acquisition else CONFIG_FIELDS,
              "CONFIG_FIELDS_V2" if acquisition else "CONFIG_FIELDS")
    require(config["schema"] == ("dc-private-daily-index-config-v2" if acquisition else
            "dc-private-daily-index-config-v1") and not (acquisition and inherited_v1), "CONFIG_SCHEMA")
    # 前configは旧codeの実byteで検証し、修復chainの多段化を許可しない。
    require(not predecessor_v2 or (acquisition and not inherited_v1 and "codeRepair" not in config),
            "CODE_REPAIR_PREDECESSOR")
    require(not presign_predecessor or (acquisition and not inherited_v1 and not predecessor_v2 and
            "codeRepair" in config and "preSignContinuation" not in config), "PRESIGN_PREDECESSOR")
    require("preSignContinuation" not in config or "codeRepair" in config, "PRESIGN_PREDECESSOR")
    require(not verified_unsigned_predecessor or (acquisition and not inherited_v1 and
            not predecessor_v2 and not presign_predecessor and "codeRepair" in config and
            type(config.get("preSignContinuation")) is dict and
            config["preSignContinuation"].get("schema") == "dc-daily-presign-continuation-v1"),
            "VERIFIED_UNSIGNED_PREDECESSOR")
    require_config_workspace(config)
    for name in ("manifestFile", "scopeFile", "collectorExe", "signerExe", "publicKeyFile", "pythonExe", "ghExe"):
        config[name] = str(normal_path(config[name]))
        protected_path(Path(config[name]), root=root)
        require(name == "ghExe" or root in Path(config[name]).parents, "PROTECTED_INPUT_LOCATION")
    require(Path(config["ghExe"]) == Path("C:/Program Files/GitHub CLI/gh.exe"), "FIXED_GH_INSTALL")
    require(config["manifestSha256"] == MANIFEST_SHA256, "FIXED_MANIFEST_PIN")
    for name, digest in (("manifestFile", "manifestSha256"), ("scopeFile", "scopeSha256"),
                         ("collectorExe", "collectorSha256"), ("signerExe", "signerSha256"),
                         ("publicKeyFile", "fingerprint")):
        require(re.fullmatch(r"[0-9a-f]{64}", config[digest]) is not None and
                sha(read(Path(config[name]))) == config[digest], "CONFIG_PIN_" + name)
    modules = (Path(__file__).resolve(), Path(projection.__file__).resolve(), Path(cr.__file__).resolve())
    if predecessor_v2 or presign_predecessor or verified_unsigned_predecessor:
        version = root / "scripts" / Path(config["collectorExe"]).parent.name
        modules = tuple(version / name for name in
                        ("daily_index_pipeline.py", "project_collected_native_index.py", "collector_registry.py"))
    if inherited_v1:
        modules = tuple(root / "scripts" / name for name in
                        ("daily_index_pipeline.py", "project_collected_native_index.py", "collector_registry.py"))
    for source, pin in ((modules[0], "pipelineSha256"), (modules[1], "producerSha256")):
        require(sha(read(source)) == config[pin], "SCRIPT_PIN")
    if acquisition:
        validate_v2_code(config, version=modules[0].parent if
                         predecessor_v2 or presign_predecessor or verified_unsigned_predecessor else None)
    else:
        for module in modules:
            require(module.parent == root / "scripts", "PROTECTED_MODULE_LOCATION")
            protected_path(module, root=root)
    require(Path(config["pythonExe"]).parent == root / "runtime", "PROTECTED_RUNTIME_LOCATION")
    protected_tree(root / "runtime")
    require(Path(config["collectorExe"]).name == "DriverCrateCollector.exe" and
            Path(config["signerExe"]).name == "DriverCrateLocalIndexSigner.exe" and
            Path(config["ghExe"]).name.lower() == "gh.exe" and
            Path(config["pythonExe"]).name.lower() in {"python.exe", "pythonw.exe"}, "EXECUTABLE_KIND")
    out = operation_root(Path(config["outputRoot"]))
    protected_tree(out)
    require(len(read(Path(config["publicKeyFile"]), 411)) == 411, "PUBLIC_BLOB_SIZE")
    scope = cr.parse_json(read(Path(config["scopeFile"]), 65536))
    if acquisition:
        projection._validate_distribution_scope(scope)
        require(scope["collectorManifestSha256"] == config["manifestSha256"] and
                scope["publicFingerprint"] == config["fingerprint"] and
                config["purpose"] == ACQUISITION_PURPOSE and
                config["termsReviewMode"] == projection.PINNED_STATIC_REVALIDATION_V1,
                "ACQUISITION_CONFIG_PURPOSE")
        acquisition_originals(config)
        validate_legacy_metadata(config)
    else:
        cr.fields(scope, {"schema", "targetCount", "source", "distributionPage", "sourceId", "recordId",
                      "collectorManifestSha256", "keyId"}, "SCOPE_FIELDS")
        require(scope["collectorManifestSha256"] == config["manifestSha256"] and
            scope["keyId"] == "distribution-index-" + config["fingerprint"][:32] and
            scope["schema"] == "dc-fixed-collector-native-index-scope-v1" and
            scope["targetCount"] == 1 and scope["source"] == projection.SOURCE and
            scope["distributionPage"] == projection.PAGE and scope["sourceId"] == "intel-ethernet-win11" and
                scope["recordId"] == "intel-wired-31-2-2-win11", "FIXED_SCOPE")
    smoke, first = (parse_time(config[name]) for name in ("smokeLocal", "firstDailyLocal"))
    require(smoke.utcoffset() == first.utcoffset() and smoke.date() < first.date() and
            first - smoke <= timedelta(days=7), "SCHEDULE_WINDOW")
    if acquisition and "preSignContinuation" in config:
        # 決定的markerの現config hashを、保存した全byteのhashと一致させる。
        require(raw == canonical(config), "PRESIGN_CONFIG_BYTES")
        validate_presign_continuation(config,
            version=modules[0].parent if verified_unsigned_predecessor else None,
            refresh_predecessor=verified_unsigned_predecessor)
    elif acquisition and "codeRepair" in config:
        validate_code_repair(config, version=modules[0].parent if presign_predecessor else None,
                             original_bucket=presign_predecessor)
    return config, scope, sha(raw)


def validate_v2_code(config: dict, *, version: Path | None = None) -> None:
    """四moduleと新binの全pin・実ACLをnative実行前に照合する。旧v1は呼び出さない。"""
    root = protected_root()
    modules = (Path(__file__).resolve(), Path(projection.__file__).resolve(), Path(cr.__file__).resolve())
    if version is not None:
        modules = tuple(version / name for name in
                        ("daily_index_pipeline.py", "project_collected_native_index.py", "collector_registry.py"))
    version = modules[0].parent
    require(version.parent == root / "scripts" and
            re.fullmatch(r"v2-[a-z0-9-]{1,64}", version.name) is not None and
            tuple(module.name for module in modules) ==
            ("daily_index_pipeline.py", "project_collected_native_index.py", "collector_registry.py") and
            all(module.parent == version for module in modules), "PROTECTED_MODULE_LOCATION")
    cr.fields(config["modulePins"], MODULE_NAMES, "MODULE_PIN_FIELDS")
    protected_tree(version)
    require({path.name for path in version.glob("*.py")} == MODULE_NAMES, "MODULE_ALLOWLIST")
    for name in sorted(MODULE_NAMES):
        module = version / name
        protected_path(module, root=root)
        require(type(config["modulePins"][name]) is str and
                re.fullmatch(r"[0-9a-f]{64}", config["modulePins"][name]) is not None and
                sha(read(module)) == config["modulePins"][name], "MODULE_PIN")
    require(config["modulePins"]["daily_index_pipeline.py"] == config["pipelineSha256"] and
            config["modulePins"]["project_collected_native_index.py"] == config["producerSha256"], "SCRIPT_PIN")
    binary = root / "bin" / version.name
    for field, name, pin in (("collectorExe", "DriverCrateCollector.exe", "collectorSha256"),
                              ("signerExe", "DriverCrateLocalIndexSigner.exe", "signerSha256")):
        path = normal_path(config[field])
        require(path == binary / name, "PROTECTED_VERSIONED_BIN")
        protected_path(path, root=root)
        require(sha(read(path)) == config[pin], "CONFIG_PIN_" + field)
    protected_tree(binary)


def validate_code_repair(config: dict, *, version: Path | None = None, original_bucket: bool = False) -> dict:
    """一段だけの前config/start/成功receiptと不変意味入力を実byteへ結合する。副作用はない。"""
    repair = config["codeRepair"]
    cr.fields(repair, CODE_REPAIR_FIELDS, "CODE_REPAIR_FIELDS")
    require(repair["schema"] == "dc-daily-code-only-repair-v1", "CODE_REPAIR_SCHEMA")
    validate_v2_code(config, version=version)
    # nativeと元時間の使用分を新しいrunへ持ち越し、修復による予算resetを拒否する。
    require(type(repair["priorNativeCalls"]) is int and 1 <= repair["priorNativeCalls"] <= 93 and
            type(repair["preparationNativeCalls"]) is int and repair["preparationNativeCalls"] == 2 and
            all(type(repair[name]) in {int, float} and 0 <= repair[name] < MAX_SECONDS
                for name in ("priorElapsedSeconds", "preparationElapsedSeconds")) and
            repair["priorElapsedSeconds"] > 0 and
            repair["priorElapsedSeconds"] + repair["preparationElapsedSeconds"] < MAX_SECONDS,
            "CODE_REPAIR_BUDGET")
    values = {}
    for name in ("config", "start", "receipt"):
        path = normal_path(repair[name + "File"])
        protected_path(path)
        raw = read(path, 1048576 if name == "receipt" else 65536)
        require(type(repair[name + "Sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", repair[name + "Sha256"]) is not None and
                sha(raw) == repair[name + "Sha256"], "CODE_REPAIR_PIN")
        values[name] = (path, raw)
    old, old_scope, old_hash = load_config(values["config"][0], predecessor_v2=True)
    require(old_hash == repair["configSha256"], "CODE_REPAIR_PIN")
    mutable = {"scopeFile", "collectorExe", "signerExe", "pipelineSha256", "modulePins"}
    require(all(config[name] == old[name] for name in V2_CONFIG_FIELDS - mutable) and
            all(config["modulePins"][name] == old["modulePins"][name] for name in
                ("project_collected_native_index.py", "collector_registry.py")) and
            config["modulePins"] != old["modulePins"], "CODE_REPAIR_SEMANTICS")
    directory = operation_root(Path(config["outputRoot"]))
    now = utc()
    first, smoke = (parse_time(config[name]) for name in ("firstDailyLocal", "smokeLocal"))
    day = now.astimezone(first.tzinfo).strftime("%Y%m%d")
    if original_bucket:
        # 明示署名前継承の旧configだけに、pin確認済み元startのbucketを使用する。
        day = cr.parse_json(values["start"][1]).get("day")
        require(type(day) is str and re.fullmatch(r"[0-9]{8}", day) is not None and
                day in [smoke.strftime("%Y%m%d")] +
                [(first + timedelta(days=i)).strftime("%Y%m%d") for i in range(7)], "CODE_REPAIR_DAY")
    require(smoke <= now < first + timedelta(days=7), "OUTSIDE_OBSERVATION_WINDOW")
    start_path, start_raw = values["start"]
    require(start_path == directory / (day + ".acquisition.start.json"), "CODE_REPAIR_DAY")
    legacy_path = directory / (day + ".start.json")
    legacy_raw = read(legacy_path, 65536) if legacy_path.exists() else None
    require(legacy_raw is None or legacy_raw == canonical({"schema": "dc-daily-start-v1",
        "configSha256": config["legacyMetadata"]["configSha256"], "day": day}), "RESUME_BYTES_CONFLICT")
    require(start_raw == canonical({"schema": "dc-daily-acquisition-start-v1", "purpose": ACQUISITION_PURPOSE,
        "configSha256": old_hash, "legacyConfigSha256": config["legacyMetadata"]["configSha256"],
        "legacyStartSha256": sha(legacy_raw) if legacy_raw is not None else None, "day": day}),
        "RESUME_BYTES_CONFLICT")
    receipt_path, receipt_raw = values["receipt"]
    require(receipt_path.parent == directory and
            re.fullmatch(day + r"\.collection-[0-9]{2}\.json", receipt_path.name) is not None, "CODE_REPAIR_DAY")
    receipt = cr.parse_json(receipt_raw)
    projection._validated_daily_generation(receipt, now)
    projection._project_metadata_for_scope(old_scope, receipt, receipt["generation"], now, daily=True)
    require(receipt["day"] == now.strftime("%Y%m%d") and
            receipt["generation"] > config["legacyReservationFence"]["generation"], "CODE_REPAIR_DAY")
    attempts = sorted(directory.glob(day + ".collection-*.json"))
    require(len(attempts) <= 32, "DAILY_ATTEMPT_COUNT")
    observed = [path for path in attempts if cr.parse_json(read(path, 1048576)).get("outcome") in
                {"NEW_200", "REVALIDATED_304"}]
    require(observed == [receipt_path], "CODE_REPAIR_RECEIPT")
    return {"path": receipt_path, "raw": receipt_raw, "repair": repair, "old": old}


def acquisition_job_day(config: dict) -> str:
    """load済み明示継承だけを元start bucketへ結合し、任意の日付指定を受け付けない。"""
    if "preSignContinuation" in config:
        repair = config["codeRepair"]
        raw = read(Path(repair["startFile"]), 65536)
        require(sha(raw) == repair["startSha256"], "CODE_REPAIR_PIN")
        day = cr.parse_json(raw).get("day")
        require(type(day) is str and re.fullmatch(r"[0-9]{8}", day) is not None, "CODE_REPAIR_DAY")
        return day
    return utc().astimezone(parse_time(config["firstDailyLocal"]).tzinfo).strftime("%Y%m%d")


def validate_presign_continuation(config: dict, *, initial: bool = False,
                                  version: Path | None = None, refresh_predecessor: bool = False) -> dict:
    """一個の旧修復checkpointを実byte/原process/既使用予算へ結合する。副作用はない。

    marker前はbody+releaseだけと署名前の永続状態を要求する。marker後の完全束は
    通常の投影・claim/署名/CAS再開検査に委譲し、未知署名を補完しない。
    追加schemaはADR0376の閉じた四原file更新だけに分岐し、旧schemaを一般化しない。
    """
    binding = config["preSignContinuation"]
    if type(binding) is dict and binding.get("schema") == VERIFIED_UNSIGNED_SCHEMA:
        require(version is None and not refresh_predecessor, "VERIFIED_UNSIGNED_PREDECESSOR")
        return validate_verified_unsigned_refresh(config, initial=initial)
    require(not refresh_predecessor or (version is not None and not initial), "VERIFIED_UNSIGNED_PREDECESSOR")
    cr.fields(binding, PRESIGN_FIELDS, "PRESIGN_FIELDS")
    require(binding["schema"] == "dc-daily-presign-continuation-v1", "PRESIGN_SCHEMA")
    validate_v2_code(config, version=version)
    values = {}
    for name in ("config", "marker", "phaseEvidence", "contentEvidence", "failureTerminal"):
        path = normal_path(binding[name + "File"])
        protected_path(path)
        raw = read(path, 1048576)
        require(type(binding[name + "Sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", binding[name + "Sha256"]) is not None and
                sha(raw) == binding[name + "Sha256"], "PRESIGN_PIN")
        values[name] = (path, raw)
    old, _, old_hash = load_config(values["config"][0], presign_predecessor=True)
    require(old_hash == binding["configSha256"], "PRESIGN_PIN")
    mutable = {"scopeFile", "collectorExe", "signerExe", "pipelineSha256", "modulePins"}
    require(all(config[name] == old[name] for name in V2_CONFIG_FIELDS - mutable) and
            config["codeRepair"] == old["codeRepair"] and
            all(config["modulePins"][name] == old["modulePins"][name] for name in
                ("project_collected_native_index.py", "collector_registry.py")) and
            config["modulePins"] != old["modulePins"], "PRESIGN_SEMANTICS")
    old_version = protected_root() / "scripts" / Path(old["collectorExe"]).parent.name
    continuation = validate_code_repair(old, version=old_version, original_bucket=True)
    directory = operation_root(Path(config["outputRoot"]))
    day = acquisition_job_day(config)
    prefix = directory / day
    repair = old["codeRepair"]
    require(values["marker"][0] == Path(str(prefix) + ".acquisition.code-repair.json") and
            values["marker"][1] == canonical({"schema": "dc-daily-code-repair-start-v1",
                "configSha256": old_hash, "predecessorConfigSha256": repair["configSha256"],
                "startSha256": repair["startSha256"], "receiptSha256": repair["receiptSha256"], "day": day}),
            "PRESIGN_MARKER")
    receipt = cr.parse_json(continuation["raw"])
    stem = "acquisition-" + continuation["path"].stem
    paths = {name: directory / (stem + "." + suffix) for name, suffix in
             (("body", "body"), ("release", "release.json"), ("inspection", "inspection.json"),
              ("script", "script.json"), ("review", "review.json"))}
    body, release_raw = read(paths["body"], 262144), read(paths["release"], 1048576)
    require(binding["bodySha256"] == sha(body) == receipt["bodySha256"] and
            body == base64.b64decode(receipt["bodyBytesBase64"], validate=True) and
            binding["releaseSha256"] == sha(release_raw), "PRESIGN_CHECKPOINT_PIN")
    originals, _ = acquisition_originals(config)
    release = cr.parse_json(release_raw)
    old_release = cr.parse_json(originals["release"])
    expected_release = dict(old_release, observedUtcSeconds=str(int(receipt["lastSuccessfulValidationAt"])))
    require(release == expected_release and type(release["observedUtcSeconds"]) is str and
            release["bodyBytes"] == len(body), "PRESIGN_RELEASE_CONTRACT")
    projection.confirm_terms_review(body, old_release, cr.parse_json(originals["review"]),
                                    cr.parse_json(originals["script"]), utc())
    terminal_path, terminal_raw = values["failureTerminal"]
    require(terminal_path.parent == directory and
            re.fullmatch(day + r"\.terminal-[0-9]+\.json", terminal_path.name) is not None and
            cr.parse_json(terminal_raw) == {"status": "FAILED", "reason": "FRESH_INSPECTION_FAILED",
                "configSha256": old_hash, "purpose": ACQUISITION_PURPOSE,
                "signingOutcome": "UNKNOWN_NO_RE_SIGN"}, "PRESIGN_PHASE")
    phase = cr.parse_json(values["phaseEvidence"][1])
    content = cr.parse_json(values["contentEvidence"][1])
    for name in ("phaseEvidence", "contentEvidence"):
        require(protected_root() / "control" in values[name][0].parents, "PRESIGN_PHASE")
    native = phase.get("native")
    require(type(native) is list and 4 <= len(native) <= 32 and
            phase.get("nativeProcessesThisStage") == len(native) and
            phase.get("priorRunNativeCarry") == repair["priorNativeCalls"] and
            phase.get("totalNativeIncludingCarry") == len(native) + repair["priorNativeCalls"], "PRESIGN_PHASE")
    allowed = {"--verify-daily-reservation", "--distribution-verify-history", "--parse-collected-release",
               "--inspect-collected-package"}
    for process in native:
        argv = process.get("actualArgv")
        require(type(argv) is list and len(argv) >= 2 and argv[1] in allowed and
                process.get("mode") in {"prepare", "run", "diagnostic"} and
                process.get("sameHandleTerminal") is True and type(process.get("exitCode")) is int and
                type(process.get("pid")) is int and process["pid"] > 0 and
                Path(process.get("actualCwd", "")) == Path(old["repositoryRoot"]) and
                datetime.fromisoformat(process["creationUtc"]) <= datetime.fromisoformat(process["exitUtc"]),
                "PRESIGN_PHASE")
    observed = [process for process in native if process.get("mode") == "run"]
    verify_argv = [old["collectorExe"], "--verify-daily-reservation", old["manifestFile"], old["stateRoot"],
                   str(continuation["path"]), "FRESH_INPUT"]
    parse_argv = [old["signerExe"], "--parse-collected-release", str(paths["body"]), receipt["bodySha256"],
                  str(int(receipt["lastSuccessfulValidationAt"])), str(paths["release"])]
    inspect_argv = [old["signerExe"], "--inspect-collected-package", old["archiveFile"],
                    old_release["publishedSha256"], str(paths["inspection"]), old["selectedInf"]]
    require(len(observed) == 4 and [p["actualArgv"] for p in observed] ==
            [verify_argv, verify_argv, parse_argv, inspect_argv] and
            [p["exitCode"] for p in observed] == [0, 0, 0, 2], "PRESIGN_PHASE")
    diagnostic = content.get("native", {})
    diagnostic_argv = diagnostic.get("argv", [])
    require(content.get("totalNativeCalls") == phase.get("totalNativeIncludingCarry", -1) + 1 and
            content.get("priorNativeCalls") == phase.get("totalNativeIncludingCarry") and
            content.get("additionalNativeCalls") == 1 and content.get("pipelineComplete") == 0 and
            content.get("signaturesIssued") == 0 and content.get("privateRegistrations") == 0 and
            diagnostic.get("sameHandleTerminal") is True and diagnostic.get("exitCode") == 0 and
            len(diagnostic_argv) == 6 and diagnostic_argv[:4] ==
                [old["signerExe"], "--inspect-collected-package", old["archiveFile"],
                 projection.digest(old_release["publishedSha256"])] and
            diagnostic_argv[5] == old["selectedInf"].replace("/", "\\") and
            content.get("artifact", {}).get("inspectionError") == 0 and
            content["artifact"].get("verifiedIdentityInfs") == 1, "PRESIGN_PHASE")
    require(type(binding["priorNativeCalls"]) is int and
            binding["priorNativeCalls"] == content["totalNativeCalls"] and
            repair["priorNativeCalls"] + repair["preparationNativeCalls"] + len(observed) <=
                binding["priorNativeCalls"] <= 93 and
            type(binding["preparationNativeCalls"]) is int and binding["preparationNativeCalls"] == 2 and
            all(type(binding[name]) in {int, float} and 0 <= binding[name] < MAX_SECONDS for name in
                ("priorElapsedSeconds", "preparationElapsedSeconds")) and
            binding["priorElapsedSeconds"] == content.get("totalNativeSeconds") and
            binding["priorElapsedSeconds"] >= repair["priorElapsedSeconds"] + repair["preparationElapsedSeconds"] and
            0 < binding["priorElapsedSeconds"] + binding["preparationElapsedSeconds"] < MAX_SECONDS,
            "PRESIGN_BUDGET")
    marker = canonical({"schema": "dc-daily-presign-start-v1", "configSha256": sha(canonical(config)),
        "predecessorConfigSha256": old_hash, "repairMarkerSha256": binding["markerSha256"],
        "receiptSha256": repair["receiptSha256"], "bodySha256": binding["bodySha256"],
        "releaseSha256": binding["releaseSha256"], "day": day})
    marker_path = Path(str(prefix) + ".acquisition.presign-continuation.json")
    resumed = marker_path.exists()
    require(not initial or not resumed, "PRESIGN_ALREADY_STARTED")
    if resumed:
        require(read(marker_path, 65536) == marker, "RESUME_BYTES_CONFLICT")
    present = {path.name for path in directory.glob(stem + ".*")}
    partial = {paths[name].name for name in ("body", "release")}
    complete = {path.name for path in paths.values()}
    if refresh_predecessor:
        # 閉じた新版遷移の旧版認証だけで四原fileを許し、通常入口のpartial拒否は保持する。
        four = {paths[name].name for name in ("body", "release", "inspection", "script")}
        require(resumed and present in (four, complete), "PRESIGN_CHECKPOINT_SHAPE")
    else:
        require(present == partial or (resumed and present == complete), "PRESIGN_CHECKPOINT_SHAPE")
    if not resumed or present == partial:
        publication = str(prefix) + ".acquisition"
        require(not (directory / f"issuance-v1-{receipt['generation']:016d}.claim.json").exists() and
                all(not Path(publication + suffix).exists() for suffix in
                    (".manifest.raw.json", ".index.json.gz", ".manifest.json", ".success.json")),
                "SIGNING_OUTCOME_UNKNOWN")
        terminals = sorted(directory.glob("*.terminal-*.json"))
        require(len(terminals) <= 512 and len(list(directory.glob(day + ".terminal-*.json"))) <= 61,
                "REPORT_ATTEMPT_LIMIT")
        for path in terminals:
            value = cr.parse_json(read(path, 65536))
            relevant = value.get("generation") == receipt["generation"] or (
                value.get("generation") is None and value.get("configSha256") in
                {old_hash, sha(canonical(config))})
            require(not relevant or (value.get("signingOutcome") in {None, "UNKNOWN_NO_RE_SIGN"} and
                    not any(name in value for name in
                        ("signingClaimSha256", "envelopeSha256", "publicationOutcome"))), "SIGNING_OUTCOME_UNKNOWN")
    return dict(continuation, binding=binding, marker=marker, markerPath=marker_path,
                day=day, paths=paths, partial=present == partial)


def validate_verified_unsigned_carry(binding: dict, old_binding: dict, raw: bytes) -> None:
    """元runの観測欠損を保持する閉witnessと、累積保守上界の縮小禁止を検証する。"""
    witness = cr.parse_json(raw)
    cr.fields(witness, CARRY_WITNESS_FIELDS, "VERIFIED_UNSIGNED_BUDGET_WITNESS")
    cr.fields(witness["globalLimits"], {"calls", "seconds", "attempts", "holdWaitSeconds"},
              "VERIFIED_UNSIGNED_BUDGET_WITNESS")
    basis = witness["runWallUpperBoundBasis"]
    cr.fields(basis, {"earliestPrelaunchStreamBirthUtc", "laterNoExactRunProcessObservedUtc",
                      "originalHandleTerminal"}, "VERIFIED_UNSIGNED_BUDGET_WITNESS")
    require(all(type(witness[name]) in {int, float} and 0 <= witness[name] < MAX_SECONDS for name in
        ("priorElapsedSeconds", "actualPrepareMeasuredSeconds", "prepareOuterObservedSeconds",
         "runWallSecondsConservativeUpperBound", "elapsedSecondsIncludingCarryConservativeUpperBound")),
        "VERIFIED_UNSIGNED_BUDGET")
    require(all(type(witness[name]) is int for name in ("priorNativeCalls", "actualPrepareNativeCalls",
        "runPathNativeCallUpperBound", "nativeCallsIncludingCarryUpperBound")) and
        witness["priorNativeCalls"] == old_binding["priorNativeCalls"] and
        witness["priorElapsedSeconds"] == old_binding["priorElapsedSeconds"] and
        witness["actualPrepareNativeCalls"] == old_binding["preparationNativeCalls"] == 2 and
        witness["actualPrepareMeasuredSeconds"] == old_binding["preparationElapsedSeconds"] and
        witness["prepareOuterObservedSeconds"] >= witness["actualPrepareMeasuredSeconds"] and
        witness["runPathNativeCallUpperBound"] == 4 and
        witness["nativeCallsIncludingCarryUpperBound"] == witness["priorNativeCalls"] +
            witness["actualPrepareNativeCalls"] + witness["runPathNativeCallUpperBound"] and
        witness["elapsedSecondsIncludingCarryConservativeUpperBound"] == witness["priorElapsedSeconds"] +
            witness["actualPrepareMeasuredSeconds"] + witness["runWallSecondsConservativeUpperBound"] and
        witness["runActualMeasuredSeconds"] is None and witness["runProcessCountDirectlyObserved"] is None and
        basis["originalHandleTerminal"] is False and type(witness["qualification"]) is str and
        0 < len(witness["qualification"]) <= 1024, "VERIFIED_UNSIGNED_BUDGET")
    clocks = [datetime.fromisoformat(value) for value in
        (basis["earliestPrelaunchStreamBirthUtc"], basis["laterNoExactRunProcessObservedUtc"], witness["utc"])
        if type(value) is str]
    require(len(clocks) == 3 and all(value.tzinfo is not None and value.utcoffset() == timedelta(0)
            for value in clocks) and clocks[0] <= clocks[1] <= clocks[2] <= utc() and
            witness["runWallSecondsConservativeUpperBound"] >= (clocks[1] - clocks[0]).total_seconds(),
            "VERIFIED_UNSIGNED_BUDGET")
    require(all(type(witness["globalLimits"][name]) is int for name in witness["globalLimits"]) and
            witness["globalLimits"] == {"calls": 96, "seconds": 1800, "attempts": 32, "holdWaitSeconds": 300} and
            type(binding["priorNativeCalls"]) is int and
            VERIFIED_UNSIGNED_CARRY_CALLS <= binding["priorNativeCalls"] ==
                witness["nativeCallsIncludingCarryUpperBound"] <= 93 and
            type(binding["priorElapsedSeconds"]) in {int, float} and
            VERIFIED_UNSIGNED_CARRY_SECONDS <= binding["priorElapsedSeconds"] ==
                witness["elapsedSecondsIncludingCarryConservativeUpperBound"] < MAX_SECONDS and
            type(binding["preparationNativeCalls"]) is int and binding["preparationNativeCalls"] == 2 and
            type(binding["preparationElapsedSeconds"]) in {int, float} and
            0 <= binding["preparationElapsedSeconds"] < MAX_SECONDS and
            binding["priorElapsedSeconds"] + binding["preparationElapsedSeconds"] < MAX_SECONDS,
            "VERIFIED_UNSIGNED_BUDGET")


def validate_verified_unsigned_refresh(config: dict, *, initial: bool = False) -> dict:
    """旧preSign全版と四原byteだけを認証し、一回限りの未署名caller更新を検証する。"""
    binding = config["preSignContinuation"]
    cr.fields(binding, VERIFIED_UNSIGNED_FIELDS, "VERIFIED_UNSIGNED_FIELDS")
    require(binding["schema"] == VERIFIED_UNSIGNED_SCHEMA, "VERIFIED_UNSIGNED_SCHEMA")
    validate_v2_code(config)
    values = {}
    for name in ("config", "marker", "failureTerminal", "budgetWitness"):
        path = normal_path(binding[name + "File"])
        protected_path(path)
        raw = read(path, 65536)
        require(type(binding[name + "Sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", binding[name + "Sha256"]) is not None and
                sha(raw) == binding[name + "Sha256"], "VERIFIED_UNSIGNED_PIN")
        values[name] = (path, raw)
    old, _, old_hash = load_config(values["config"][0], verified_unsigned_predecessor=True)
    require(old_hash == binding["configSha256"], "VERIFIED_UNSIGNED_PIN")
    mutable = {"scopeFile", "collectorExe", "signerExe", "pipelineSha256", "modulePins"}
    require(all(config[name] == old[name] for name in V2_CONFIG_FIELDS - mutable) and
            config["codeRepair"] == old["codeRepair"] and
            all(config["modulePins"][name] == old["modulePins"][name] for name in
                ("project_collected_native_index.py", "collector_registry.py")) and
            config["modulePins"] != old["modulePins"], "VERIFIED_UNSIGNED_SEMANTICS")
    require(protected_root() / "control" in values["budgetWitness"][0].parents,
            "VERIFIED_UNSIGNED_BUDGET_WITNESS")
    validate_verified_unsigned_carry(binding, old["preSignContinuation"], values["budgetWitness"][1])
    directory = operation_root(Path(config["outputRoot"]))
    day = acquisition_job_day(old)
    prefix = directory / day
    repair = old["codeRepair"]
    old_binding = old["preSignContinuation"]
    old_marker = canonical({"schema": "dc-daily-presign-start-v1", "configSha256": old_hash,
        "predecessorConfigSha256": old_binding["configSha256"], "repairMarkerSha256": old_binding["markerSha256"],
        "receiptSha256": repair["receiptSha256"], "bodySha256": old_binding["bodySha256"],
        "releaseSha256": old_binding["releaseSha256"], "day": day})
    require(values["marker"][0] == Path(str(prefix) + ".acquisition.presign-continuation.json") and
            values["marker"][1] == old_marker, "VERIFIED_UNSIGNED_MARKER")
    terminal_path, terminal_raw = values["failureTerminal"]
    require(terminal_path.parent == directory and
            re.fullmatch(day + r"\.terminal-[0-9]+\.json", terminal_path.name) is not None and
            cr.parse_json(terminal_raw) == {"status": "FAILED", "reason": "DISTRIBUTION_UTC_SECONDS",
                "configSha256": old_hash, "purpose": ACQUISITION_PURPOSE,
                "signingOutcome": "UNKNOWN_NO_RE_SIGN"}, "VERIFIED_UNSIGNED_PHASE")
    receipt_path = Path(repair["receiptFile"])
    receipt_raw = read(receipt_path, 1048576)
    require(sha(receipt_raw) == repair["receiptSha256"], "VERIFIED_UNSIGNED_PIN")
    receipt = cr.parse_json(receipt_raw)
    stem = "acquisition-" + receipt_path.stem
    paths = {name: directory / (stem + "." + suffix) for name, suffix in
             (("body", "body"), ("release", "release.json"), ("inspection", "inspection.json"),
              ("script", "script.json"), ("review", "review.json"))}
    for name, maximum in (("body", 262144), ("release", 1048576), ("inspection", 1048576), ("script", 1048576)):
        raw = read(paths[name], maximum)
        require(type(binding[name + "Sha256"]) is str and
                re.fullmatch(r"[0-9a-f]{64}", binding[name + "Sha256"]) is not None and
                sha(raw) == binding[name + "Sha256"], "VERIFIED_UNSIGNED_CHECKPOINT_PIN")
    require(binding["bodySha256"] == old_binding["bodySha256"] == receipt["bodySha256"] and
            binding["releaseSha256"] == old_binding["releaseSha256"], "VERIFIED_UNSIGNED_CHECKPOINT_PIN")
    marker_path = Path(str(prefix) + ".acquisition.verified-unsigned-refresh.json")
    marker = canonical({"schema": "dc-daily-verified-unsigned-refresh-start-v1",
        "configSha256": sha(canonical(config)), "predecessorConfigSha256": old_hash,
        "preSignMarkerSha256": binding["markerSha256"], "receiptSha256": repair["receiptSha256"],
        "inputPins": {name: binding[name + "Sha256"] for name in ("body", "release", "inspection", "script")},
        "budgetWitnessSha256": binding["budgetWitnessSha256"], "day": day})
    resumed = marker_path.exists()
    require(not initial or not resumed, "VERIFIED_UNSIGNED_ALREADY_STARTED")
    if resumed:
        require(read(marker_path, 65536) == marker, "RESUME_BYTES_CONFLICT")
    present = {path.name for path in directory.glob(stem + ".*")}
    four = {paths[name].name for name in ("body", "release", "inspection", "script")}
    complete = {path.name for path in paths.values()}
    require(present == four or (resumed and present == complete), "VERIFIED_UNSIGNED_CHECKPOINT_SHAPE")
    if not resumed or present == four:
        publication = str(prefix) + ".acquisition"
        require(not (directory / f"issuance-v1-{receipt['generation']:016d}.claim.json").exists() and
                all(not Path(publication + suffix).exists() for suffix in
                    (".manifest.raw.json", ".index.json.gz", ".manifest.json", ".success.json")),
                "SIGNING_OUTCOME_UNKNOWN")
        terminals = sorted(directory.glob("*.terminal-*.json"))
        require(len(terminals) <= 512 and len(list(directory.glob(day + ".terminal-*.json"))) <= 61,
                "REPORT_ATTEMPT_LIMIT")
        for path in terminals:
            value = cr.parse_json(read(path, 65536))
            relevant = value.get("generation") == receipt["generation"] or (
                value.get("generation") is None and value.get("configSha256") in
                {old_hash, sha(canonical(config)), old_binding["configSha256"], repair["configSha256"]})
            require(not relevant or (value.get("signingOutcome") in {None, "UNKNOWN_NO_RE_SIGN"} and
                    not any(name in value for name in
                        ("signingClaimSha256", "envelopeSha256", "publicationOutcome", "nativeCurrentVerified"))),
                    "SIGNING_OUTCOME_UNKNOWN")
    return {"path": receipt_path, "raw": receipt_raw, "binding": binding, "marker": marker,
            "markerPath": marker_path, "day": day, "paths": paths, "partial": present == four}


def carry_code_repair_budget(budget, calls: int, seconds: float) -> None:
    """実Budgetだけへ既使用分を一度控除する。人工Budgetの実process成功は主張しない。"""
    if isinstance(budget, Budget):
        require(budget.calls == 0 and 0 <= calls < 96 and 0 <= seconds < MAX_SECONDS, "CODE_REPAIR_BUDGET")
        budget.calls = calls
        budget.end -= seconds
        budget.remaining(MAX_SECONDS)


def acquisition_originals(config: dict) -> tuple[dict[str, bytes], dict[str, str]]:
    """保護された原manual/release/scriptだけを読み、archiveはbyteを読まず契約へ結ぶ。"""
    cr.fields(config["originalInputs"], {"release", "review", "script"}, "TERMS_REVALIDATION_FIELDS")
    originals, pins = {}, {}
    root = protected_root()
    for name, entry in config["originalInputs"].items():
        cr.fields(entry, {"file", "sha256"}, "TERMS_REVALIDATION_FIELDS")
        path = normal_path(entry["file"])
        require(root in path.parents, "PROTECTED_INPUT_LOCATION")
        protected_path(path, root=root)
        raw = read(path, 65536 if name == "review" else 1048576)
        require(type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None and
                sha(raw) == entry["sha256"], "TERMS_REVALIDATION_PIN")
        originals[name], pins[name] = raw, entry["sha256"]
    release = cr.parse_json(originals["release"])
    # 原byte/pinを保持し、公表hexの表記だけを既存strict validatorで値へ正規化する。
    require(projection.digest(config["archiveSha256"]) == projection.digest(release["publishedSha256"]) ==
            "2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5" and
            type(config["archiveBytes"]) is int and config["archiveBytes"] == 40477087 and
            config["selectedInf"] == "PRO2500/Winx64/W11/e2fn.inf", "ACQUISITION_ARCHIVE_BINDING")
    archive = normal_path(config["archiveFile"])
    require(root in archive.parents, "PROTECTED_INPUT_LOCATION")
    protected_path(archive, root=root)
    return originals, pins


def validate_legacy_metadata(config: dict) -> dict:
    """旧原config/receipt/署名assetを再投影へ拘束する。暗号と実headは別途nativeで照合する。"""
    binding = config["legacyMetadata"]
    cr.fields(binding, LEGACY_FIELDS, "LEGACY_METADATA_FIELDS")
    require(binding["kind"] == "LEGACY_METADATA_BOUND", "LEGACY_METADATA_BINDING")
    legacy, scope, digest = load_config(Path(binding["configFile"]), inherited_v1=True)
    require(digest == binding["configSha256"] and legacy["outputRoot"] == config["outputRoot"],
            "INHERIT_OUTPUT_ROOT")
    require(all(legacy[name] == config[name] for name in
                ("repositoryRoot", "stateRoot", "manifestFile", "manifestSha256", "publicKeyFile", "fingerprint",
                 "pythonExe", "ghExe", "smokeLocal", "firstDailyLocal")), "INHERIT_SCHEDULE_IMMUTABLE")
    values = {}
    for name, maximum in (("receipt", 1048576), ("rawManifest", 65536), ("gzip", MAX_FILE),
                          ("envelope", 98304)):
        path = normal_path(binding[name + "File"])
        require(path.parent == Path(config["outputRoot"]), "LEGACY_METADATA_LOCATION")
        protected_path(path)
        values[name] = read(path, maximum)
        require(sha(values[name]) == binding[name + "Sha256"], "LEGACY_METADATA_BINDING")
    receipt = cr.parse_json(values["receipt"])
    manifest, raw = unpack_envelope(values["envelope"])
    require(raw == values["rawManifest"] and manifest["keyId"] == scope["keyId"] and
            parse_time(manifest["publishedAtUtc"]) <= utc(), "LEGACY_METADATA_BINDING")
    _, packed, expected, _ = projection.project_daily(scope, receipt, parse_time(manifest["publishedAtUtc"]))
    require(packed == values["gzip"] and expected == raw, "LEGACY_METADATA_BINDING")
    fence = config["legacyReservationFence"]
    cr.fields(fence, {"generation", "receiptSha256"}, "LEGACY_FENCE_FIELDS")
    require(type(fence["generation"]) is int and 1 <= receipt["generation"] <= fence["generation"] <=
            9007199254740991 and type(fence["receiptSha256"]) is str and
            re.fullmatch(r"[0-9a-f]{64}", fence["receiptSha256"]) is not None, "LEGACY_FENCE_BINDING")
    fence_path = normal_path(binding["fenceReceiptFile"])
    require(fence_path.parent == Path(config["outputRoot"]), "LEGACY_METADATA_LOCATION")
    protected_path(fence_path)
    fence_raw = read(fence_path, 1048576)
    require(sha(fence_raw) == fence["receiptSha256"] and
            cr.parse_json(fence_raw)["generation"] == fence["generation"], "LEGACY_FENCE_BINDING")
    return values


def verify_reservation(config: dict, path: Path, raw: bytes, budget, mode: str) -> dict:
    """明示用途の既存native照合を一回だけ呼び、公開factsの完全一致を要求する。"""
    require(mode in {"FRESH_INPUT", "LEGACY_FENCE"}, "DAILY_RESERVATION_MODE")
    generation = cr.parse_json(raw)["generation"]
    require(type(generation) is int and 1 <= generation <= 9007199254740991, "ACQUISITION_GENERATION")
    code, output, _ = budget.run([config["collectorExe"], "--verify-daily-reservation",
        config["manifestFile"], config["stateRoot"], str(path), mode], maximum=4096, seconds=120)
    expected = (f"COLLECTOR_RESERVATION error=0 mode={mode} generation={generation} receipt_sha256={sha(raw)}")
    require(code == 0 and type(output) is bytes and output.decode("ascii").strip() == expected,
            "DAILY_RESERVATION_HEAD")
    return {"mode": mode, "generation": generation, "receiptSha256": sha(raw)}


class Budget:
    """実時間とsubprocess数の固定上限。失敗時に上限をresetしない。"""
    def __init__(self, seconds: int = MAX_SECONDS):
        require(0 < seconds <= MAX_SECONDS, "BUDGET")
        self.end = time.monotonic() + seconds
        self.calls = 0
        self.directory = None

    def remaining(self, maximum: int = 600) -> float:
        result = min(float(maximum), self.end - time.monotonic())
        require(result > 0, "TOTAL_TIMEOUT")
        return result

    def run(self, argv: list[str], data: bytes | None = None, maximum: int = MAX_FILE,
            seconds: int = 600) -> tuple[int, bytes, bytes]:
        """承認済みargvを残予算内で起動し、exit codeと有限stdout/stderrを返す。

        呼出し側が実行権限と固定toolを検証する。保護操作directory内の一時streamは
        本methodが閉じる。起動後の監視失敗時は子をkill/waitして例外を伝播し、
        子が既に行った外部変更は巻き戻さない。非0終了だけでは例外にしない。
        """
        self.calls += 1
        require(self.calls <= 96, "PROCESS_COUNT")
        timeout = self.remaining(seconds)
        env = dict(os.environ)
        env.update(GH_PROMPT_DISABLED="1", GH_PAGER="", GH_NO_UPDATE_NOTIFIER="1", GH_DEBUG="")
        flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        # Bounded file-backed output avoids unbounded communicate buffers and console windows.
        require(self.directory is not None, "PROTECTED_PROCESS_TEMP_REQUIRED")
        operation_root(self.directory)
        workspace = approved_workspace()
        with tempfile.TemporaryFile(dir=self.directory) as output, tempfile.TemporaryFile(dir=self.directory) as error, tempfile.TemporaryFile(dir=self.directory) as input_file:
            require(data is None or len(data) <= MAX_FILE, "PROCESS_INPUT_LIMIT")
            if data:
                input_file.write(data)
            input_file.seek(0)
            started = time.monotonic()
            process = subprocess.Popen(argv, cwd=workspace.repositoryRoot, stdin=input_file, stdout=output, stderr=error,
                                       env=env, creationflags=flags)
            try:
                while process.poll() is None:
                    require(time.monotonic() - started < timeout, "PROCESS_TIMEOUT")
                    require(os.fstat(output.fileno()).st_size <= maximum and os.fstat(error.fileno()).st_size <= 65536,
                            "PROCESS_OUTPUT_LIMIT")
                    time.sleep(0.05)
                output.seek(0)
                error.seek(0)
                stdout, stderr = output.read(maximum + 1), error.read(65537)
                require(len(stdout) <= maximum and len(stderr) <= 65536, "PROCESS_OUTPUT_LIMIT")
                return process.returncode, stdout, stderr
            except BaseException:
                process.kill()
                process.wait(timeout=10)
                raise


class Missing(Exception):
    """既存CLI診断のHTTP 404識別列を検出した場合の内部値。実wire観測ではない。"""


def safe_github_failure(value: object) -> dict | None:
    """固定診断の全fieldを検証し、許可値だけの新しい辞書を返す。不正値は省略する。

    例外の属性集合や未知keyを複写しない。boolと整数、文字列subclassも区別し、
    CLI診断をHTTP開始・remote書込み結果へ昇格しない。I/Oは行わない。
    """
    if type(value) is not dict or any(type(key) is not str for key in value) or set(value) != GITHUB_FAILURE_FIELDS:
        return None
    for key in ("schema", "api", "method", "stage", "httpStatusSource", "remoteWriteOutcome"):
        if type(value[key]) is not str:
            return None
    if (value["schema"] != "dc-github-failure-v1" or
            value["api"] not in {*GITHUB_PURPOSE_METHODS, "UNKNOWN"} or
            value["method"] not in {"GET", "POST", "PATCH", "UNKNOWN"} or
            value["stage"] not in GITHUB_FAILURE_STAGES or value["remoteWriteOutcome"] != "UNKNOWN"):
        return None
    if value["api"] != "UNKNOWN" and value["method"] != GITHUB_PURPOSE_METHODS[value["api"]]:
        return None
    if type(value["ordinal"]) is not int or not 1 <= value["ordinal"] <= 96 or type(value["outerTimeout"]) is not bool:
        return None
    code, status = value["childExitCode"], value["cliReportedHttpStatus"]
    if code is not None and (type(code) is not int or not -2147483648 <= code <= 4294967295):
        return None
    if status is not None and (type(status) is not int or not 100 <= status <= 599):
        return None
    if value["httpStatusSource"] != ("UNKNOWN" if status is None else "CLI_REPORTED"):
        return None
    if value["outerTimeout"] != (value["stage"] == "BUDGET_TIMEOUT"):
        return None
    if value["stage"] == "CLI_EXIT":
        if code == 0:
            return None
    elif value["stage"] == "RESPONSE_PARSE":
        if code != 0 or status is not None:
            return None
    elif code is not None or status is not None:
        return None
    return {"schema": "dc-github-failure-v1", "api": value["api"], "method": value["method"],
            "ordinal": value["ordinal"], "stage": value["stage"], "childExitCode": code,
            "outerTimeout": value["outerTimeout"], "cliReportedHttpStatus": status,
            "httpStatusSource": value["httpStatusSource"], "remoteWriteOutcome": "UNKNOWN"}


def github_failure(method: str, path: str, ordinal: int, stage: str, *, code=None, stderr=b"") -> dict | None:
    """共通境界の観測値を有限診断へ変換する。raw routeと出力は戻り値へ含めない。

    stderrは65536 byte以内のCLI診断としてだけ扱う。一意の括弧付きHTTP整数以外は
    nullとし、子の終了値が返らなかった場合の起動・通信・remote作用は推測しない。
    """
    purpose = "UNKNOWN"
    for expected_method, pattern, identifier in GITHUB_ROUTES:
        if method == expected_method and re.fullmatch(pattern, path) is not None:
            purpose = identifier
            break
    status = None
    if type(stderr) is bytes and len(stderr) <= 65536:
        markers = set(re.findall(rb"\(HTTP ([0-9]+)\)", stderr))
        if len(markers) == 1:
            marker = next(iter(markers))
            if len(marker) == 3 and b"100" <= marker <= b"599":
                status = int(marker)
    safe_code = code if type(code) is int and -2147483648 <= code <= 4294967295 else None
    return safe_github_failure({"schema": "dc-github-failure-v1", "api": purpose,
        "method": method if type(method) is str and method in {"GET", "POST", "PATCH"} else "UNKNOWN",
        "ordinal": ordinal, "stage": stage, "childExitCode": safe_code,
        "outerTimeout": stage == "BUDGET_TIMEOUT", "cliReportedHttpStatus": status,
        "httpStatusSource": "UNKNOWN" if status is None else "CLI_REPORTED", "remoteWriteOutcome": "UNKNOWN"})


def safe_native_failure(value: object) -> dict | None:
    """固定receipt欠損stageと有限整数exitだけを受理し、余分なfieldを拒否する。"""
    if (type(value) is not dict or set(value) != {"schema", "stage", "childExitCode"} or
            value.get("schema") != "dc-native-stage-failure-v1" or
            value.get("stage") != "DAILY_EVIDENCE_RECEIPT" or
            type(value.get("childExitCode")) is not int or
            not -(1 << 31) <= value["childExitCode"] <= (1 << 32) - 1):
        return None
    return dict(value)


def require_native_receipt(path: Path, code: int) -> None:
    """欠損時に元の失敗codeを保ち、child出力を含めない任意診断だけを付ける。"""
    if not path.exists():
        error = ValueError("NATIVE_RECEIPT_MISSING")
        error.native_failure = safe_native_failure({"schema": "dc-native-stage-failure-v1",
            "stage": "DAILY_EVIDENCE_RECEIPT", "childExitCode": code})
        raise error


def result_with_safe_github_failure(value: dict) -> dict:
    """既存結果fieldを保ち、任意のGitHub/native最小診断を保存時に再検証する。

    診断のない旧terminalと互換とし、不正診断を省略する。元のstatus/reasonや
    attemptを成功へ変更せず、入力辞書と原fileも変更しない。
    """
    result = dict(value)
    detail = safe_github_failure(result.pop("githubFailure", None))
    if detail is not None:
        result["githubFailure"] = detail
    native = safe_native_failure(result.pop("nativeFailure", None))
    if native is not None:
        result["nativeFailure"] = native
    return result


class GitHub:
    """固定host/repositoryだけを既存gh認証で扱う。tokenを読み出さない。"""
    def __init__(self, executable: str, budget: Budget):
        """固定toolと既存Budgetを借用し、診断用の呼出し順を初期化する。"""
        self.executable, self.budget = executable, budget
        self.ordinal = 0

    def api(self, method: str, path: str, body: dict | bytes | None = None,
            *, binary: bool = False, content_type: str = "application/json"):
        """呼出し側が承認した操作を固定GitHub経路へ既存gh認証で送る。

        path検査自体は公開許可を与えない。既存の404識別列だけMissingとし、他の非0終了は
        固定codeで拒否する。元例外へ有限診断だけを付加し、型/reasonを維持する。
        失敗時の自動retryや外部変更の取消しは行わない。
        """
        require(path in {"user", API, "graphql"} or path.startswith(API + "/") or
                path.startswith("https://uploads.github.com/" + API + "/releases/"), "FIXED_API")
        upload_size = None
        if path.startswith("https://uploads.github.com/"):
            upload = re.fullmatch(ASSET_UPLOAD_PATTERN, path)
            require(method == "POST" and upload is not None, "ASSET_UPLOAD_REQUEST")
            require(type(body) is bytes, "ASSET_UPLOAD_BYTES")
            upload_size = len(body)
            require(0 < upload_size <= MAX_FILE, "ASSET_UPLOAD_BYTES")
            require(content_type == ("application/gzip" if upload[1] == "index.json.gz" else
                    "application/json"), "ASSET_UPLOAD_CONTENT_TYPE")
        self.ordinal += 1
        argv = [self.executable, "api", "--hostname", "github.com", "--method", method, path,
                "--header", "X-GitHub-Api-Version: 2022-11-28",
                "--header", "Accept: " + ("application/octet-stream" if binary else "application/vnd.github+json")]
        data = canonical(body) if type(body) is dict else body
        if data is not None:
            argv += ["--input", "-", "--header", "Content-Type: " + content_type]
        if upload_size is not None:
            # ghのstdinは未知長扱いのため、送る同じbyte列の確定長を一件だけ指定する。
            argv += ["--header", "Content-Length: " + str(upload_size)]
        try:
            code, raw, error = self.budget.run(argv, data, seconds=30)
        except Exception as failure:
            # BudgetのOSErrorは一時fileにも由来するため、起動済みとは判定しない。
            stage = "BUDGET_EXCEPTION"
            if type(failure) is ValueError and failure.args in (("PROCESS_TIMEOUT",), ("TOTAL_TIMEOUT",)):
                stage = "BUDGET_TIMEOUT"
            elif type(failure) is ValueError and failure.args == ("PROCESS_OUTPUT_LIMIT",):
                stage = "BUDGET_OUTPUT_LIMIT"
            failure.github_failure = github_failure(method, path, self.ordinal, stage)
            raise
        if code != 0:
            if b"HTTP 404" in error:
                raise Missing()
            failure = ValueError("GITHUB_REQUEST_FAILED")
            failure.github_failure = github_failure(method, path, self.ordinal, "CLI_EXIT", code=code, stderr=error)
            raise failure
        try:
            return raw if binary else cr.parse_json(raw)
        except Exception as failure:
            failure.github_failure = github_failure(method, path, self.ordinal, "RESPONSE_PARSE", code=code)
            raise


def unpack_envelope(envelope: bytes) -> tuple[dict, bytes]:
    require(len(envelope) <= 96 * 1024, "ENVELOPE_SIZE")
    value = cr.parse_json(envelope)
    cr.fields(value, {"schema", "keyId", "manifestBytesBase64", "signatureBase64"}, "ENVELOPE_FIELDS")
    require(value["schema"] == "driver-index-envelope-v1", "ENVELOPE_SCHEMA")
    raw = base64.b64decode(value["manifestBytesBase64"], validate=True)
    require(0 < len(raw) <= 65536 and len(base64.b64decode(value["signatureBase64"], validate=True)) == 384,
            "ENVELOPE_SHAPE")
    return cr.parse_json(raw), raw


def audit_bundle(bundle: dict[str, bytes], scope: dict, receipt: dict, now: datetime) -> dict:
    """二assetの形式・期限・原receiptからの再投影byteと公開fieldを検証する。

    署名の暗号検証は呼出し側のnative verifierが別途行う。本関数だけでは署名や
    公開権限を確定しない。不一致は例外とし、file書込みや通信は行わない。
    """
    require(set(bundle) == ASSETS, "ASSET_ALLOWLIST")
    manifest, raw_manifest = unpack_envelope(bundle["manifest.json"])
    require(parse_time(manifest["publishedAtUtc"]) <= now < parse_time(manifest["expiresAtUtc"]), "EXPIRY")
    raw_index, packed, expected_manifest, _ = projection.project_daily(
        scope, receipt, parse_time(manifest["publishedAtUtc"]))
    require(raw_manifest == expected_manifest and packed == bundle["index.json.gz"], "PUBLIC_PROJECTION_BYTES")
    # The exact producer fixes every public field and leaves payload, IDs and acquisition UNKNOWN.
    decoded = cr.parse_json(raw_index)
    public_record = base64.b64decode(decoded["records"][0]["recordBytesBase64"], validate=True)
    forbidden = rb"(?i)(github_pat_|gh[pousr]_[a-z0-9]|-----BEGIN|Bearer\s|[a-z]:[\\/](?!/)|\\\\|PCI\\|USB\\|HID\\|instance.?id|serial.?number|access.?token|password|cookie)"
    require(re.search(forbidden, public_record + raw_index + raw_manifest) is None, "PUBLIC_PRIVACY")
    return manifest


def audit_distribution_acquisition_bundle(bundle: dict[str, bytes], inputs: dict[str, bytes],
                                          input_pins: dict[str, str], *, generation: int,
                                          published_at: datetime, now: datetime) -> dict:
    """六原JSON byteと二assetの完全再投影・期限・限定privacyを監査する（ADR0363）。

    bundle、inputs、input_pinsは呼出し中だけ借用し、変更しない。scope/reviewは各64KiB、
    その他の入力は各1MiB、gzipはMAX_FILE、envelopeは96KiB以内の非空exact bytesとする。
    六keyと小文字SHA-256全64桁を要求し、重複JSON keyや型違いもfail-closedで拒否する。
    generationはboolを除く1..2^53-1、published_at/nowはtimezone付きUTC秒とする。
    原pinとP1原byteの一致後だけ公開pnpIds.valueを検査用copyで中立化し、元byteを保つ。
    戻り値は新たに解析した通常のmanifest辞書だけで、暗号署名検証結果ではない。
    ValueError/RegistryError、decode・型・容量等の例外は入力を出力せず伝播する。
    file/network/subprocess/鍵/保護stateへのI/Oは0。callerの自己pinは整合性だけであり、
    公式由来、世代予約、署名authority、snapshot、取得/導入grant、同意を発行しない。
    後段のnative署名verifierと各権限境界は呼出し側が別途成立させる必要がある。
    """
    return _audit_distribution_acquisition_bundle(
        bundle, inputs, input_pins, generation=generation, published_at=published_at, now=now, daily=False)


def audit_daily_distribution_acquisition_bundle(bundle: dict[str, bytes], inputs: dict[str, bytes],
                                                input_pins: dict[str, str], *, generation: int,
                                                published_at: datetime, now: datetime,
                                                terms_review_mode: str | None = None) -> dict:
    """厳密日次receiptの六原byteを明示入口だけで監査する（ADR0364）。

    evidence欄だけを日次receiptとし、世代は原receiptと明示generationの一致を要求する。
    terms_review_mode=Noneではreview/scope各64KiBとし、明示的な
    PINNED_STATIC_REVALIDATION_V1時だけreviewを1MiBとする。このmodeではreview内の
    freshRelease/freshScriptの埋込原byteをinputsのrelease/scriptと完全一致させる。
    scopeを含む他五入力と二assetの上限、pin/UTC/原byte/privacy契約は旧取得監査と同じで、
    入力を変更しない。この例外は旧非日次入口へ適用しない。
    返す通常manifest辞書は未署名dataであり、予約・由来・暗号・権限を証明しない。
    callbackやschema fallbackは受け付けず、失敗は原例外を伝播する。I/Oは行わない。
    """
    return _audit_distribution_acquisition_bundle(
        bundle, inputs, input_pins, generation=generation, published_at=published_at, now=now, daily=True,
        terms_review_mode=terms_review_mode)


def _audit_distribution_acquisition_bundle(bundle: dict[str, bytes], inputs: dict[str, bytes],
                                           input_pins: dict[str, str], *, generation: int,
                                           published_at: datetime, now: datetime, daily: bool,
                                           terms_review_mode: str | None = None) -> dict:
    """公開入口が固定するprofileだけを選び、元pin/asset/privacy検査順を共用する。"""
    # 固定二asset以外を検査前に拒否し、巨大・可変bufferを取り込まない。
    require(type(bundle) is dict and len(bundle) == 2 and all(type(key) is str for key in bundle),
            "ASSET_ALLOWLIST")
    cr.fields(bundle, ASSETS, "ASSET_ALLOWLIST")
    for name, maximum in (("index.json.gz", MAX_FILE), ("manifest.json", 96 * 1024)):
        require(type(bundle[name]) is bytes and 0 < len(bundle[name]) <= maximum,
                "ACQUISITION_ASSET_BYTES")

    # 六原byteの完全pinを全件先に照合し、自己申告pinを権限へ変換しない。
    limits = {"scope": 65536, "evidence": 1048576, "release": 1048576,
              "inspection": 1048576, "review": 65536, "script": 1048576}
    require(terms_review_mode in {None, projection.PINNED_STATIC_REVALIDATION_V1} and
            (terms_review_mode is None or daily), "TERMS_REVIEW_MODE")
    if terms_review_mode == projection.PINNED_STATIC_REVALIDATION_V1:
        limits["review"] = 1048576
    for value, code in ((inputs, "ACQUISITION_INPUT_FIELDS"), (input_pins, "ACQUISITION_PIN_FIELDS")):
        require(type(value) is dict and len(value) == 6 and all(type(key) is str for key in value), code)
        cr.fields(value, set(limits), code)
    for name, maximum in limits.items():
        require(type(inputs[name]) is bytes and 0 < len(inputs[name]) <= maximum,
                "ACQUISITION_INPUT_BYTES")
        require(type(input_pins[name]) is str and re.fullmatch(r"[0-9a-f]{64}", input_pins[name]) is not None,
                "ACQUISITION_INPUT_PIN")
        require(sha(inputs[name]) == input_pins[name], "ACQUISITION_INPUT_PIN")
    parsed = {name: cr.parse_json(inputs[name]) for name in limits}
    require(all(type(value) is dict for value in parsed.values()), "ACQUISITION_INPUT_OBJECT")
    if terms_review_mode == projection.PINNED_STATIC_REVALIDATION_V1:
        for name, field in (("release", "freshRelease"), ("script", "freshScript")):
            embedded, _ = projection._revalidation_artifact(parsed["review"][field], 1048576)
            require(embedded == inputs[name], "TERMS_REVALIDATION_PIN")
    require(type(generation) is int and 1 <= generation <= 9007199254740991, "ACQUISITION_GENERATION")
    for value in (published_at, now):
        require(isinstance(value, datetime) and value.tzinfo is not None and
                value.utcoffset() == timedelta(0) and value.microsecond == 0, "ACQUISITION_UTC_SECONDS")
    require(published_at <= now, "ACQUISITION_PUBLICATION_TIME")

    # 外側形は暗号検証ではない。原manifest/gzipをproducerの出力全byteへ拘束する。
    outer = cr.parse_json(bundle["manifest.json"])
    cr.fields(outer, {"schema", "keyId", "manifestBytesBase64", "signatureBase64"}, "ENVELOPE_FIELDS")
    require(all(type(value) is str for value in outer.values()), "ACQUISITION_ENVELOPE_TYPE")
    manifest, raw_manifest = unpack_envelope(bundle["manifest.json"])
    require(type(manifest) is dict, "ACQUISITION_MANIFEST_OBJECT")
    # 日次は原receipt世代だけを使う。caller世代をproducerへ上書き注入しない。
    if daily:
        raw_index, packed, expected_manifest, _ = projection.project_daily_distribution_acquisition(
            parsed["scope"], parsed["evidence"], parsed["release"], parsed["inspection"],
            parsed["review"], parsed["script"], published_at, terms_review_mode=terms_review_mode)
        require(generation == parsed["evidence"]["generation"], "DAILY_ACQUISITION_GENERATION_BINDING")
    else:
        raw_index, packed, expected_manifest, _ = projection.project_distribution_acquisition(
            parsed["scope"], parsed["evidence"], parsed["release"], parsed["inspection"],
            parsed["review"], parsed["script"], generation, published_at)
    require(raw_manifest == expected_manifest and packed == bundle["index.json.gz"], "PUBLIC_PROJECTION_BYTES")
    require(outer["keyId"] == manifest["keyId"], "ACQUISITION_ENVELOPE_KEY")
    require(published_at <= now < parse_time(manifest["expiresAtUtc"]), "EXPIRY")

    # Base64内のrecordと元source/manifestでも、公開IDを含む秘密の混入を先に拒否する。
    decoded = cr.parse_json(raw_index)
    public_record = base64.b64decode(decoded["records"][0]["recordBytesBase64"], validate=True)
    secrets = rb"(?i)(github_pat_|gh[pousr]_[a-z0-9]|-----BEGIN|Bearer\s|access.?token|password|cookie|credential|secret|token)"
    require(re.search(secrets, public_record + raw_index + raw_manifest) is None, "PUBLIC_PRIVACY_SECRET")

    # 完全一致済みrecordの指定leafだけを中立化する。元署名byte/hashは書き換えない。
    privacy_record = cr.parse_json(public_record)
    for item in privacy_record["publishedIdentityEvidence"]["pnpIds"]:
        item["value"] = "PUBLIC_INF_ID"
    privacy_raw = canonical(privacy_record)
    decoded["records"][0]["recordBytesBase64"] = base64.b64encode(privacy_raw).decode("ascii")
    forbidden = rb"(?i)(github_pat_|gh[pousr]_[a-z0-9]|-----BEGIN|Bearer\s|[a-z]:[\\/](?!/)|\\\\|PCI\\|USB\\|HID\\|instance.?id|serial.?number|access.?token|password|cookie)"
    require(re.search(forbidden, privacy_raw + canonical(decoded) + raw_manifest) is None, "PUBLIC_PRIVACY")
    return manifest


def collect_daily_acquisition_receipt(config: dict, prefix: Path, budget) -> dict:
    """既存一回HOLD待機契約で原receiptを残し、due後の同config明示再開を許す。"""
    directory = operation_root(prefix.parent)
    protected_tree(directory)
    attempts = sorted(directory.glob(prefix.name + ".collection-*.json"))
    require(len(attempts) <= 32, "DAILY_ATTEMPT_COUNT")
    observations = []
    for path in attempts:
        raw = read(path, 1048576)
        value = cr.parse_json(raw)
        if value.get("outcome") in {"NEW_200", "REVALIDATED_304"}:
            observations.append((path, raw, value))
    require(len(observations) <= 1, "MULTIPLE_DAILY_OBSERVATIONS")
    if observations:
        path, raw, receipt = observations[0]
        return {"status": "OBSERVED", "path": path, "raw": raw, "receipt": receipt, "sha256": sha(raw)}
    for position in range(2):
        ordinal = len(attempts) + position
        require(ordinal < 32, "DAILY_ATTEMPT_COUNT")
        path = directory / (prefix.name + f".collection-{ordinal:02d}.json")
        code, _, _ = budget.run([config["collectorExe"], "--daily-evidence", config["manifestFile"],
                                config["stateRoot"], str(path)])
        require_native_receipt(path, code)
        raw = read(path, 1048576)
        receipt = cr.parse_json(raw)
        if code == 3 and receipt.get("outcome") == "HOLD":
            delay = hold_seconds(receipt, utc(), budget.remaining(MAX_SECONDS))
            if position == 0 and delay is not None:
                time.sleep(delay)
                continue
            return {"status": "HOLD", "path": path, "raw": raw, "sha256": sha(raw),
                    "receipt": receipt, "newGeneration": False}
        if receipt.get("outcome") == "NO_NETWORK":
            return {"status": "NO_NETWORK", "path": path, "raw": raw, "sha256": sha(raw),
                    "receipt": receipt, "newGeneration": False}
        require(code == 0 and receipt.get("outcome") in {"NEW_200", "REVALIDATED_304"},
                "COLLECTION_FAILED_NO_PUBLICATION")
        return {"status": "OBSERVED", "path": path, "raw": raw, "receipt": receipt, "sha256": sha(raw)}
    raise ValueError("COLLECTION_FAILED_NO_PUBLICATION")


def prepare_daily_acquisition_inputs(config: dict, scope_raw: bytes, receipt_path: Path,
                                     originals: dict[str, bytes], original_pins: dict[str, str],
                                     archive: Path, selected_inf: str, budget, *,
                                     terms_review_mode: str, resume_presign: bool = False) -> dict:
    """原予約・必要なnative操作・機械再確認から、Bが直接使える六原byte/pin束を準備する。

    callerは承認config、固定scope/original pins、同operation lockを保持する。
    本入口は署名・配布・Task切替を行わず、失敗時の原fileも保持する。
    archiveをPythonで読み込まず、実hash/INF/CAT/署名検査は既存nativeへ渡す。
    明示継承では認証済み原fileを保持し、四原file更新では欠損reviewだけを生成する。
    """
    require(terms_review_mode == projection.PINNED_STATIC_REVALIDATION_V1, "TERMS_REVIEW_MODE")
    directory = operation_root(receipt_path.parent)
    protected_tree(directory)
    # operation包含は上で確認し、DACL保護必須anchorは専用rootのまま維持する。
    require(receipt_path.parent == directory, "PROTECTED_OPERATION_ROOT")
    protected_path(receipt_path, root=protected_root())
    require(type(scope_raw) is bytes and 0 < len(scope_raw) <= 65536, "ACQUISITION_INPUT_BYTES")
    raw = read(receipt_path, 1048576)
    receipt = cr.parse_json(raw)
    now = utc()
    scope = cr.parse_json(scope_raw)
    projection._validate_distribution_scope(scope)
    projection._validated_daily_generation(receipt, now)
    projection._project_metadata_for_scope(scope, receipt, receipt["generation"], now, daily=True)
    body = base64.b64decode(receipt["bodyBytesBase64"], validate=True)
    require(0 < len(body) <= 262144, "DAILY_PREPARATION_BODY_SIZE")
    body.decode("utf-8", errors="strict")
    require(selected_inf == "PRO2500/Winx64/W11/e2fn.inf", "NATIVE_INF_BINDING")
    archive = normal_path(str(archive), exists=False)
    require(archive.is_file() and not archive.is_symlink(), "ACQUISITION_ARCHIVE_MISSING")
    size = archive.stat().st_size
    require(size == 40477087 and size <= 134217728, "ACQUISITION_ARCHIVE_SIZE")
    code, output, _ = budget.run([config["collectorExe"], "--verify-daily-reservation",
        config["manifestFile"], config["stateRoot"], str(receipt_path), "FRESH_INPUT"], maximum=4096, seconds=120)
    expected = (f"COLLECTOR_RESERVATION error=0 mode=FRESH_INPUT generation={int(receipt['generation'])} "
                f"receipt_sha256={sha(raw)}")
    require(code == 0 and type(output) is bytes and output.decode("ascii").strip() == expected,
            "DAILY_RESERVATION_HEAD")
    prefix = "acquisition-" + receipt_path.stem
    body_path = directory / (prefix + ".body")
    release_path = directory / (prefix + ".release.json")
    inspection_path = directory / (prefix + ".inspection.json")
    script_path = directory / (prefix + ".script.json")
    review_path = directory / (prefix + ".review.json")
    verified_unsigned = False
    if resume_presign:
        checkpoint = validate_presign_continuation(config)
        require(checkpoint["partial"] and checkpoint["path"] == receipt_path and
                checkpoint["raw"] == raw, "PRESIGN_CHECKPOINT_SHAPE")
        verified_unsigned = config["preSignContinuation"]["schema"] == VERIFIED_UNSIGNED_SCHEMA
    else:
        require(all(not path.exists() for path in (body_path, release_path, inspection_path, script_path, review_path)),
                "ACQUISITION_PREPARATION_EXISTS")
    # 原承認pinをnative network操作より前に確認する。
    cr.fields(originals, {"release", "review", "script"}, "TERMS_REVALIDATION_FIELDS")
    cr.fields(original_pins, set(originals), "TERMS_REVALIDATION_FIELDS")
    for name, value in originals.items():
        require(type(value) is bytes and 0 < len(value) <= (65536 if name == "review" else 1048576) and
                type(original_pins[name]) is str and re.fullmatch(r"[0-9a-f]{64}", original_pins[name]) is not None and
                sha(value) == original_pins[name], "TERMS_REVALIDATION_PIN")
    old_review = cr.parse_json(originals["review"])
    old_release = cr.parse_json(originals["release"])
    old_script = cr.parse_json(originals["script"])
    require(receipt["bodySha256"] == old_release["bodySha256"], "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    projection.confirm_terms_review(body, old_release, old_review, old_script, now)
    if not resume_presign:
        write_new(body_path, body)
    validated = str(int(receipt["lastSuccessfulValidationAt"]))
    commands = [] if resume_presign else [
        ([config["signerExe"], "--parse-collected-release", str(body_path), receipt["bodySha256"],
          validated, str(release_path)], "FRESH_RELEASE_FAILED", 120)]
    commands += [] if verified_unsigned else [
        # 検証済みdigest値と論理INFだけを既存native境界の表記へ揃え、原JSON/pinは保持する。
        ([config["signerExe"], "--inspect-collected-package", str(archive),
          projection.digest(old_release["publishedSha256"]), str(inspection_path),
          selected_inf.replace("/", "\\")], "FRESH_INSPECTION_FAILED", 600),
        ([config["signerExe"], "--collect-terms-link-script", str(body_path), receipt["bodySha256"],
          validated, old_script["scriptUrl"], str(script_path)], "FRESH_SCRIPT_FAILED", 120)]
    for argv, failure, seconds in commands:
        code, _, _ = budget.run(argv, maximum=65536, seconds=seconds)
        require(code == 0, failure)
    release_raw = read(release_path, 1048576)
    inspection_raw = read(inspection_path, 1048576)
    script_raw = read(script_path, 1048576)
    completed = utc()
    review_raw = projection.make_pinned_static_terms_revalidation(body, originals, original_pins,
        release_raw, script_raw, int(completed.timestamp()), completed)
    inputs = {"scope": scope_raw, "evidence": raw, "release": release_raw, "inspection": inspection_raw,
              "review": review_raw, "script": script_raw}
    # 実完了観測は上の規約確認へ保ち、整数UTC秒を要求する投影境界だけを揃える。
    projected = projection.project_daily_distribution_acquisition(scope, receipt, cr.parse_json(release_raw),
        cr.parse_json(inspection_raw), cr.parse_json(review_raw), cr.parse_json(script_raw),
        completed.replace(microsecond=0),
        terms_review_mode=terms_review_mode)
    if verified_unsigned:
        # 四原file再利用時は既存六入力監査も通し、唯一欠損のreviewをその後だけ新規保存する。
        _, packed, raw_manifest, _ = projected
        unsigned = canonical({"schema": "driver-index-envelope-v1", "keyId": scope["keyId"],
            "manifestBytesBase64": base64.b64encode(raw_manifest).decode("ascii"),
            "signatureBase64": base64.b64encode(bytes(384)).decode("ascii")})
        audit_daily_distribution_acquisition_bundle({"manifest.json": unsigned, "index.json.gz": packed},
            inputs, {name: sha(value) for name, value in inputs.items()}, generation=receipt["generation"],
            published_at=completed.replace(microsecond=0), now=completed.replace(microsecond=0),
            terms_review_mode=terms_review_mode)
    write_new(review_path, review_raw)
    return {"inputs": inputs, "inputPins": {name: sha(value) for name, value in inputs.items()},
            "reservation": {"mode": "FRESH_INPUT", "generation": int(receipt["generation"]),
                            "receiptSha256": sha(raw)}, "projection": projected,
            "termsReviewMode": terms_review_mode, "authorityIssued": False}


CLAIM_FIELDS = frozenset({"schema", "state", "purpose", "generation", "assetGeneration", "inputPins",
    "termsReviewMode", "reservation", "previousReceiptSha256", "publishedAtUtc", "expiresAtUtc",
    "rawManifestSha256", "gzipSha256", "scopeSha256", "keyId", "fingerprint", "legacyConfigSha256",
    "legacyReservationFence"})


def issuance_claim(config: dict, prepared: dict, raw_manifest: bytes, packed: bytes) -> dict:
    """署名前の原byteと実予約factsを、URLや秘密を含まない一世代のintentへ結ぶ。"""
    manifest = cr.parse_json(raw_manifest)
    receipt = cr.parse_json(prepared["inputs"]["evidence"])
    return {"schema": "dc-distribution-issuance-claim-v1", "state": "SIGNING_INTENT",
        "purpose": ACQUISITION_PURPOSE, "generation": receipt["generation"],
        "assetGeneration": manifest["assetGeneration"], "inputPins": {name: prepared["inputPins"][name]
            for name in ("scope", "evidence", "release", "inspection", "review", "script")},
        "termsReviewMode": config["termsReviewMode"], "reservation": prepared["reservation"],
        "previousReceiptSha256": receipt["previousReceiptSha256"],
        "publishedAtUtc": manifest["publishedAtUtc"], "expiresAtUtc": manifest["expiresAtUtc"],
        "rawManifestSha256": sha(raw_manifest), "gzipSha256": sha(packed),
        "scopeSha256": prepared["inputPins"]["scope"], "keyId": manifest["keyId"],
        "fingerprint": config["fingerprint"], "legacyConfigSha256": config["legacyMetadata"]["configSha256"],
        "legacyReservationFence": config["legacyReservationFence"]}


def acquisition_profile(config: dict, candidate: dict[str, bytes], directory: Path) -> str:
    """明示legacy拘束または同世代claimから一用途だけを選ぶ。nativeの試行fallbackはしない。"""
    manifest, raw = unpack_envelope(candidate["manifest.json"])
    require(parse_time(manifest["publishedAtUtc"]) <= utc(), "ACQUISITION_PUBLICATION_TIME")
    legacy = config["legacyMetadata"]
    if (sha(raw) == legacy["rawManifestSha256"] and sha(candidate["index.json.gz"]) == legacy["gzipSha256"] and
            sha(candidate["manifest.json"]) == legacy["envelopeSha256"]):
        return "distribution"
    generation = manifest["generation"]
    require(type(generation) is int and config["legacyReservationFence"]["generation"] < generation <=
            9007199254740991, "SIGNING_PROFILE_UNKNOWN")
    path = directory / f"issuance-v1-{generation:016d}.claim.json"
    require(path.exists(), "SIGNING_PROFILE_UNKNOWN")
    claim_raw = read(path, 65536)
    claim = cr.parse_json(claim_raw)
    cr.fields(claim, CLAIM_FIELDS, "SIGNING_PROFILE_UNKNOWN")
    cr.fields(claim["inputPins"], {"scope", "evidence", "release", "inspection", "review", "script"},
              "SIGNING_PROFILE_UNKNOWN")
    cr.fields(claim["reservation"], {"mode", "generation", "receiptSha256"}, "SIGNING_PROFILE_UNKNOWN")
    require(canonical(claim) == claim_raw and all(type(value) is str and
            re.fullmatch(r"[0-9a-f]{64}", value) is not None for value in claim["inputPins"].values()) and
            claim["reservation"] == {"mode": "FRESH_INPUT", "generation": generation,
                "receiptSha256": claim["inputPins"]["evidence"]} and
            claim["scopeSha256"] == claim["inputPins"]["scope"] and
            type(claim["previousReceiptSha256"]) is str and
            re.fullmatch(r"[0-9a-f]{64}", claim["previousReceiptSha256"]) is not None,
            "SIGNING_PROFILE_UNKNOWN")
    require(claim["schema"] == "dc-distribution-issuance-claim-v1" and claim["state"] == "SIGNING_INTENT" and
            claim["purpose"] == ACQUISITION_PURPOSE and claim["generation"] == generation ==
            claim["assetGeneration"] == manifest["assetGeneration"] and
            claim["rawManifestSha256"] == sha(raw) and claim["gzipSha256"] == sha(candidate["index.json.gz"]) and
            claim["keyId"] == manifest["keyId"] == projection.DISTRIBUTION_KEY_ID and
            claim["fingerprint"] == config["fingerprint"] and
            claim["legacyConfigSha256"] == legacy["configSha256"] and
            claim["legacyReservationFence"] == config["legacyReservationFence"] and
            claim["publishedAtUtc"] == manifest["publishedAtUtc"] and
            claim["expiresAtUtc"] == manifest["expiresAtUtc"] and
            claim["termsReviewMode"] == config["termsReviewMode"], "SIGNING_PROFILE_UNKNOWN")
    return "distribution-acquisition"


def acquisition_verifier(config: dict, prepared: dict, directory: Path, budget, *,
                         generation: int, publication: datetime):
    """既存の一用途native検証とcurrent六入力監査を同じ順序・byteで行うclosureを返す。

    config/prepared/budgetはcallerが認証し、operation lockを保持して借用する。
    historyは原公開秒でnative検証し、currentだけ六入力を再監査する。
    検証用二fileのkeep_exactとnative実行以外に収集・署名・公開を行わない。
    """
    def verify(candidate: dict[str, bytes], *, historical: bool):
        """一用途のnative暗号検査を行い、currentは六入力と原公開byteも再監査する。"""
        require(set(candidate) == ASSETS, "ASSET_ALLOWLIST")
        profile = acquisition_profile(config, candidate, directory)
        require(historical or profile == "distribution-acquisition", "SIGNING_PROFILE_UNKNOWN")
        candidate_hash = sha(candidate["manifest.json"] + candidate["index.json.gz"])
        env_file = directory / ("verify-" + candidate_hash + ".manifest.json")
        gz_file = directory / ("verify-" + candidate_hash + ".index.json.gz")
        keep_exact(env_file, candidate["manifest.json"])
        keep_exact(gz_file, candidate["index.json.gz"])
        argv = [config["signerExe"], "--" + profile + ("-verify-history" if historical else "-verify"),
                str(env_file), str(gz_file), config["publicKeyFile"], config["fingerprint"]]
        if historical:
            manifest, _ = unpack_envelope(candidate["manifest.json"])
            argv.append(str(int(parse_time(manifest["publishedAtUtc"]).timestamp())))
        code, _, _ = budget.run(argv)
        require(code == 0, "NATIVE_DISTRIBUTION_VERIFY_FAILED")
        if not historical:
            audit_daily_distribution_acquisition_bundle(candidate, prepared["inputs"], prepared["inputPins"],
                generation=generation, published_at=publication, now=utc().replace(microsecond=0),
                terms_review_mode=config["termsReviewMode"])

    return verify


def run_acquisition(config: dict, scope: dict, config_hash: str, prefix: Path, budget, remote) -> dict:
    """既存mainの同じlock内で、A入力束からclaim・一回署名・既存Publisherへ接続する。"""
    directory = prefix.parent
    day_terminals = sorted(directory.glob(prefix.name + ".terminal-*.json"))
    # 署名結果、CAS intent、main結果の三枠を元64件の範囲に確保する。
    require(len(day_terminals) <= 61, "REPORT_ATTEMPT_LIMIT")
    terminal_paths = sorted(directory.glob("*.terminal-*.json"))
    require(len(terminal_paths) <= 512, "REPORT_ATTEMPT_LIMIT")
    terminal_results = [cr.parse_json(read(path, 65536)) for path in terminal_paths]
    observed = collect_daily_acquisition_receipt(config, prefix, budget)
    if observed["status"] != "OBSERVED":
        return {key: value for key, value in observed.items() if key in {"status", "newGeneration"}} | {
            "configSha256": config_hash, "purpose": ACQUISITION_PURPOSE}
    receipt, receipt_path = observed["receipt"], observed["path"]
    generation = receipt["generation"]
    require(type(generation) is int and generation > config["legacyReservationFence"]["generation"],
            "LEGACY_GENERATION_NOT_ISSUABLE")
    projection._validated_daily_generation(receipt, utc())
    require(receipt["day"] == utc().strftime("%Y%m%d"), "DAILY_RECEIPT_WRONG_DAY")
    originals, pins = acquisition_originals(config)
    # receipt/terminalの共通日次予算を維持し、用途で異なる公開byteだけを分離する。
    publication_prefix = str(prefix) + ".acquisition"
    manifest_path = Path(publication_prefix + ".manifest.raw.json")
    gzip_path = Path(publication_prefix + ".index.json.gz")
    envelope_path = Path(publication_prefix + ".manifest.json")
    claim_path = directory / f"issuance-v1-{generation:016d}.claim.json"
    require(not envelope_path.exists() or claim_path.exists(), "ISSUANCE_ENVELOPE_WITHOUT_CLAIM")
    stem = "acquisition-" + receipt_path.stem
    paths = {name: directory / (stem + "." + suffix) for name, suffix in
             (("release", "release.json"), ("inspection", "inspection.json"), ("review", "review.json"),
              ("script", "script.json"))}
    if all(path.exists() for path in paths.values()):
        inputs = {name: read(path, 1048576) for name, path in paths.items()}
        inputs.update(scope=read(Path(config["scopeFile"]), 65536), evidence=observed["raw"])
        wrapper = cr.parse_json(inputs["review"])
        for name in originals:
            raw, _ = projection._revalidation_artifact(wrapper["original" + name.title()],
                                                       65536 if name == "review" else 1048576)
            require(raw == originals[name], "TERMS_REVALIDATION_PIN")
        prepared = {"inputs": inputs, "inputPins": {name: sha(raw) for name, raw in inputs.items()},
                    "reservation": {"mode": "FRESH_INPUT", "generation": generation,
                                    "receiptSha256": observed["sha256"]}}
    else:
        require(not claim_path.exists(), "SIGNING_OUTCOME_UNKNOWN")
        resume_presign = "preSignContinuation" in config
        if not resume_presign:
            require(not any(path.exists() for path in paths.values()), "ACQUISITION_PREPARATION_INCOMPLETE")
        prepared = prepare_daily_acquisition_inputs(config, read(Path(config["scopeFile"]), 65536), receipt_path,
            originals, pins, Path(config["archiveFile"]), config["selectedInf"], budget,
            terms_review_mode=config["termsReviewMode"], resume_presign=resume_presign)
    # 初回公開だけを既存wire契約の秒精度へ揃え、再利用時は保存済み公開時刻を固定する。
    publication = (parse_time(cr.parse_json(read(manifest_path, 65536))["publishedAtUtc"])
                   if manifest_path.exists() else utc().replace(microsecond=0))
    require(publication <= utc(), "ACQUISITION_PUBLICATION_TIME")
    documents = {name: cr.parse_json(raw) for name, raw in prepared["inputs"].items()}
    _, packed, raw_manifest, _ = projection.project_daily_distribution_acquisition(
        documents["scope"], documents["evidence"], documents["release"], documents["inspection"],
        documents["review"], documents["script"], publication, terms_review_mode=config["termsReviewMode"])
    require(utc() < parse_time(cr.parse_json(raw_manifest)["expiresAtUtc"]), "EXPIRY")
    unsigned = canonical({"schema": "driver-index-envelope-v1", "keyId": scope["keyId"],
        "manifestBytesBase64": base64.b64encode(raw_manifest).decode("ascii"),
        "signatureBase64": base64.b64encode(bytes(384)).decode("ascii")})
    # RAM内shapeは署名前監査だけに使い、暗号成功として保存・公開しない。
    audit_daily_distribution_acquisition_bundle({"manifest.json": unsigned, "index.json.gz": packed},
        prepared["inputs"], prepared["inputPins"], generation=generation, published_at=publication,
        now=utc().replace(microsecond=0), terms_review_mode=config["termsReviewMode"])
    keep_exact(manifest_path, raw_manifest)
    keep_exact(gzip_path, packed)
    claim_raw = canonical(issuance_claim(config, prepared, raw_manifest, packed))
    require(len(claim_raw) <= 65536, "ISSUANCE_CLAIM_SIZE")
    existing_claim = claim_path.exists()
    if existing_claim:
        require(read(claim_path, 65536) == claim_raw, "ISSUANCE_CLAIM_CONFLICT")
        require(envelope_path.exists(), "SIGNING_OUTCOME_UNKNOWN")

    def signing_result(outcome: str, *, envelope_hash=None):
        """既存terminal系列へ署名の実結果だけを保存し、別markerを作らない。"""
        result = {"status": "UNKNOWN" if outcome == "NATIVE_OUTCOME_UNKNOWN" else "SIGNED_NOT_PUBLISHED",
            "reason": "SIGNING_OUTCOME_UNKNOWN" if outcome == "NATIVE_OUTCOME_UNKNOWN" else "ACQUISITION_CURRENT_VERIFIED",
            "purpose": ACQUISITION_PURPOSE, "configSha256": config_hash, "generation": generation,
            "signingClaimSha256": sha(claim_raw), "signingOutcome": outcome}
        if envelope_hash is not None:
            result.update(envelopeSha256=envelope_hash, childExitCode=0, nativeCurrentVerified=True)
        write_new(Path(str(prefix) + f".terminal-{time.time_ns()}.json"), canonical(result))

    previous_results = [result for result in terminal_results if result.get("generation") == generation and
                        result.get("signingOutcome") in {"NATIVE_OUTCOME_UNKNOWN", "NATIVE_CURRENT_VERIFIED"}]
    for result in previous_results:
        require(result.get("purpose") == ACQUISITION_PURPOSE and result.get("configSha256") == config_hash and
                result.get("signingClaimSha256") == sha(claim_raw), "ISSUANCE_CLAIM_CONFLICT")
    require(not any(result["signingOutcome"] == "NATIVE_OUTCOME_UNKNOWN" for result in previous_results),
            "SIGNING_OUTCOME_UNKNOWN")
    if not existing_claim:
        verify_reservation(config, receipt_path, observed["raw"], budget, "FRESH_INPUT")
        write_new(claim_path, claim_raw)
        try:
            code, _, _ = budget.run([config["signerExe"], "--distribution-acquisition-sign",
                str(manifest_path), str(gzip_path), str(envelope_path), config["fingerprint"]])
            require(code == 0 and envelope_path.exists(), "SIGNING_OUTCOME_UNKNOWN")
        except Exception as failure:
            signing_result("NATIVE_OUTCOME_UNKNOWN")
            raise ValueError("SIGNING_OUTCOME_UNKNOWN") from failure
    try:
        bundle = {"index.json.gz": read(gzip_path), "manifest.json": read(envelope_path, 98304)}
        unpack_envelope(bundle["manifest.json"])
    except Exception as failure:
        raise ValueError("SIGNING_OUTCOME_UNKNOWN") from failure
    if existing_claim:
        # 原exit0とnative current完了の結果欠損は、形が正しいenvelopeだけで補わない。
        require(any(result.get("signingOutcome") == "NATIVE_CURRENT_VERIFIED" and
                    result.get("envelopeSha256") == sha(bundle["manifest.json"]) and
                    type(result.get("childExitCode")) is int and result["childExitCode"] == 0 and
                    result.get("nativeCurrentVerified") is True for result in previous_results),
                "SIGNING_OUTCOME_UNKNOWN")

    verify = acquisition_verifier(config, prepared, directory, budget,
                                  generation=generation, publication=publication)
    verify(bundle, historical=False)
    if not existing_claim:
        signing_result("NATIVE_CURRENT_VERIFIED", envelope_hash=sha(bundle["manifest.json"]))
    terminals = sorted(directory.glob(prefix.name + ".terminal-*.json"))
    # CAS intentとmain terminalの二枠を確保し、元64件上限を越えない。
    require(len(terminals) <= 62, "REPORT_ATTEMPT_LIMIT")
    readback_only = False
    for path in terminals:
        terminal = cr.parse_json(read(path, 65536))
        if terminal.get("publicationOutcome") == "CAS_INTENT_UNKNOWN":
            require(terminal.get("configSha256") == config_hash and terminal.get("generation") == generation and
                    terminal.get("envelopeSha256") == sha(bundle["manifest.json"]), "ISSUANCE_CLAIM_CONFLICT")
            readback_only = True

    def before_cas():
        """既存terminal系列へCAS直前意図を残し、crash後の追加CASを禁止する。"""
        write_new(Path(str(prefix) + f".terminal-{time.time_ns()}.json"), canonical({
            "status": "UNKNOWN", "reason": "CURRENT_CAS_OUTCOME_UNKNOWN", "configSha256": config_hash,
            "purpose": ACQUISITION_PURPOSE, "generation": generation,
            "envelopeSha256": sha(bundle["manifest.json"]), "publicationOutcome": "CAS_INTENT_UNKNOWN"}))

    result = Publisher(remote or GitHub(config["ghExe"], budget), verify, purpose=ACQUISITION_PURPOSE,
                       before_cas=before_cas).publish(bundle, readback_only=readback_only)
    result.update(configSha256=config_hash, purpose=ACQUISITION_PURPOSE, envelopeSha256=sha(bundle["manifest.json"]),
        originalFetchedAt=receipt["lastFetchedAt"], validatedAt=receipt["lastSuccessfulValidationAt"],
        signingClaimSha256=sha(claim_raw))
    success_path = Path(publication_prefix + ".success.json")
    if success_path.exists():
        saved = cr.parse_json(read(success_path, 65536))
        require(all(saved.get(name) == result[name] for name in
                    ("status", "generation", "configSha256", "envelopeSha256", "signingClaimSha256", "purpose")),
                "SUCCESS_BINDING")
    else:
        write_new(success_path, canonical(result))
    return result


class Publisher:
    """二assetの再取得/検証後だけindex-only branchへ一度CASする。"""
    def __init__(self, remote, verify, *, purpose="METADATA_ONLY", before_cas=None):
        self.remote, self.verify = remote, verify
        self.purpose, self.before_cas = purpose, before_cas

    def identity(self) -> None:
        user = self.remote.api("GET", "user")
        repo = self.remote.api("GET", API)
        require(user.get("login") == "EnterOgawa" and repo.get("full_name") == REPOSITORY and
                repo.get("private") is True and repo.get("visibility") == "private", "PRIVATE_IDENTITY")
        node_id = repo.get("node_id")
        require(type(node_id) is str and re.fullmatch(r"[A-Za-z0-9_+=/-]{1,256}", node_id) is not None,
                "REPOSITORY_NODE_ID")
        self.repository_id = node_id

    def release(self, tag: str):
        require(re.fullmatch(r"index-v1-[0-9]{8}-[0-9a-f]{64}", tag) is not None, "TAG")
        return self.remote.api("GET", API + "/releases/tags/" + tag)

    def release_bytes(self, release: dict, *, complete: bool) -> dict[str, bytes]:
        entries = release.get("assets", [])
        require(type(entries) is list and len(entries) <= 2, "REMOTE_ASSET_COUNT")
        result = {}
        for entry in entries:
            name, identifier = entry.get("name"), entry.get("id")
            require(name in ASSETS and name not in result and type(identifier) is int and identifier > 0 and
                    entry.get("state") == "uploaded" and 0 < entry.get("size", 0) <= MAX_FILE,
                    "REMOTE_ASSET_ALLOWLIST")
            raw = self.remote.api("GET", API + f"/releases/assets/{identifier}", binary=True)
            require(type(raw) is bytes and len(raw) == entry["size"], "REMOTE_ASSET_SIZE")
            result[name] = raw
        require(not complete or set(result) == ASSETS, "REMOTE_ASSETS_INCOMPLETE")
        return result

    def current(self) -> tuple[str | None, bytes | None, int]:
        try:
            ref = self.remote.api("GET", API + "/git/ref/heads/driver-index")
        except Missing:
            return None, None, 0
        head = ref["object"]["sha"]
        require(re.fullmatch(r"[0-9a-f]{40}", head) is not None, "HEAD_SHA")
        commit = self.remote.api("GET", API + "/git/commits/" + head)
        tree = self.remote.api("GET", API + "/git/trees/" + commit["tree"]["sha"] + "?recursive=1")
        require(tree.get("truncated") is False and type(tree.get("tree")) is list, "BRANCH_TREE")
        files = []
        for item in tree["tree"]:
            if item.get("type") == "tree":
                require(item.get("path") == "index" and item.get("mode") == "040000", "BRANCH_DIRECTORY")
            else:
                require(item.get("path") == "index/current.json" and item.get("type") == "blob" and
                        item.get("mode") == "100644", "BRANCH_FOREIGN_CONTENT")
                files.append(item)
        require(len(files) == 1, "BRANCH_CONTENT_COUNT")
        blob = self.remote.api("GET", API + "/git/blobs/" + files[0]["sha"])
        require(blob.get("encoding") == "base64" and 0 < blob.get("size", 0) <= 96 * 1024, "CURRENT_BLOB")
        envelope = base64.b64decode(blob["content"].replace("\n", ""), validate=True)
        require(len(envelope) == blob["size"], "CURRENT_SIZE")
        manifest, _ = unpack_envelope(envelope)
        release = self.release(manifest["asset"]["tag"])
        require(release.get("draft") is False and release.get("prerelease") is True, "CURRENT_RELEASE")
        bundle = self.release_bytes(release, complete=True)
        require(bundle["manifest.json"] == envelope, "CURRENT_RELEASE_ENVELOPE")
        # Expired current is verified at its publication time for the high-water check only.
        self.verify(bundle, historical=True)
        return head, envelope, manifest["generation"]

    # 呼出し中に借用する二assetはfresh verifyし、既存currentはhistory/high-water用に検証する。
    # readback_onlyは原envelope完全一致の確認以外のremote追加writeを拒否する。
    # verify等のcallback内部まで無I/Oとは保証せず、その作用は呼出し側が管理する。
    # before_casは一度のCAS直前に呼び、例外時はCASへ進まず原例外を伝播する。
    # 途中のrelease/asset/blob/tree/commit等のremote作用はrollbackしない。CAS/最終確認の
    # unknownを成功や自動retryへ変えず、取得用途のclaim/terminal再開制御はcallerが担う。
    def publish(self, bundle: dict[str, bytes], *, readback_only=False) -> dict:
        require(set(bundle) == ASSETS, "ASSET_ALLOWLIST")
        self.verify(bundle, historical=False)
        manifest, _ = unpack_envelope(bundle["manifest.json"])
        self.identity()
        head, previous, generation = self.current()
        if previous == bundle["manifest.json"]:
            if self.purpose == ACQUISITION_PURPOSE:
                self.verify(bundle, historical=False)
            return {"status": "PUBLISHED", "generation": generation, "commit": head,
                    "tag": manifest["asset"]["tag"], "resumed": True}
        require(not readback_only, "CURRENT_CAS_OUTCOME_UNKNOWN")
        require(type(manifest["generation"]) is int and manifest["generation"] > generation, "REMOTE_GENERATION")
        tag = manifest["asset"]["tag"]
        try:
            release = self.release(tag)
        except Missing:
            release = self.remote.api("POST", API + "/releases", {
                "tag_name": tag, "target_commitish": "main", "name": "DriverCrate " +
                    ("acquisition" if self.purpose == ACQUISITION_PURPOSE else "metadata") + " index " + str(manifest["generation"]),
                "body": ("Acquisition-descriptor private validation index." if self.purpose == ACQUISITION_PURPOSE else
                         "Metadata-only private validation index.") + " No driver packages. DriverCrate metadata: Apache-2.0.",
                "draft": True, "prerelease": True, "make_latest": "false"})
        require(type(release.get("id")) is int and release["id"] > 0 and release.get("tag_name") == tag and
                release.get("prerelease") is True, "RELEASE_IDENTITY")
        identifier = release["id"]
        existing = self.release_bytes(release, complete=False)
        require(all(bundle[name] == raw for name, raw in existing.items()), "IMMUTABLE_ASSET_CONFLICT")
        for name in sorted(ASSETS - set(existing)):
            require(release.get("draft") is True, "PUBLISHED_ASSET_MISSING")
            self.remote.api("POST", "https://uploads.github.com/" + API + f"/releases/{identifier}/assets?name=" + name,
                            bundle[name], content_type="application/gzip" if name.endswith(".gz") else "application/json")
        uploaded = self.remote.api("GET", API + f"/releases/{identifier}")
        readback = self.release_bytes(uploaded, complete=True)
        require(readback == bundle, "REMOTE_BYTE_MISMATCH")
        self.verify(readback, historical=False)
        if uploaded.get("draft") is True:
            self.remote.api("PATCH", API + f"/releases/{identifier}", {
                "draft": False, "prerelease": True, "make_latest": "false"})
        published = self.remote.api("GET", API + f"/releases/{identifier}")
        require(published.get("draft") is False and published.get("prerelease") is True and
                published.get("tag_name") == tag, "RELEASE_NOT_PUBLISHED")
        self.identity()
        blob = self.remote.api("POST", API + "/git/blobs", {
            "content": base64.b64encode(bundle["manifest.json"]).decode("ascii"), "encoding": "base64"})
        tree = self.remote.api("POST", API + "/git/trees", {"tree": [{
            "path": "index/current.json", "mode": "100644", "type": "blob", "sha": blob["sha"]}]})
        commit = self.remote.api("POST", API + "/git/commits", {
            "message": "Update " + ("acquisition" if self.purpose == ACQUISITION_PURPOSE else "metadata") +
                       " index generation " + str(manifest["generation"]),
            "tree": tree["sha"], "parents": [head] if head else []})
        # beforeOid is a true expected-head CAS, including branch nonexistence. Never force/retry.
        query = "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}"
        if self.before_cas is not None:
            self.before_cas()
        cas = self.remote.api("POST", "graphql", {"query": query, "variables": {"input": {
            "repositoryId": self.repository_id, "refUpdates": [{"name": "refs/heads/driver-index",
                "beforeOid": head or "0" * 40, "afterOid": commit["sha"], "force": False}]}}})
        require(not cas.get("errors") and type(cas.get("data")) is dict and
                type(cas["data"].get("updateRefs")) is dict, "CURRENT_CAS_REJECTED_OR_UNKNOWN")
        confirmed = self.remote.api("GET", API + "/git/ref/heads/driver-index")
        require(confirmed["object"]["sha"] == commit["sha"], "CURRENT_CONFIRMATION_UNKNOWN")
        return {"status": "PUBLISHED", "generation": manifest["generation"], "commit": commit["sha"],
                "tag": tag, "resumed": False}


@contextmanager
def exclusive(path: Path):
    """保護保存先を呼出し側で検証したWindows lock fileの先頭1 byteを排他取得する。

    非待機取得に失敗するとyieldせず拒否する。取得後はwith本体の成功・例外とも
    finallyでunlockを試み、streamを閉じる。lock fileは残し、解除失敗も伝播する。
    """
    require(os.name == "nt", "WINDOWS_REQUIRED")
    import msvcrt
    normal_path(str(path), exists=False)
    with path.open("a+b") as stream:
        if stream.tell() == 0:
            stream.write(b"0")
            stream.flush()
        stream.seek(0)
        try:
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError as error:
            raise ValueError("PIPELINE_ALREADY_RUNNING") from error
        try:
            yield
        finally:
            stream.seek(0)
            msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)


def hold_seconds(receipt: dict, now: datetime, remaining: float) -> float | None:
    # Native preflight HOLD has no dayrun generation, HTTP or body. Never wait on a failed dayrun.
    require(receipt.get("schema") == "dc-collector-daily-receipt-v1" and receipt.get("outcome") == "HOLD" and
            receipt.get("httpStatus") == 0 and receipt.get("generation") == 0 and
            receipt.get("error") == 0 and receipt.get("stateError") == 0, "HOLD_NOT_PREFLIGHT")
    target = receipt.get("notBefore")
    require(type(target) in {int, float} and int(target) == target and target > now.timestamp(), "HOLD_NOT_BEFORE")
    delay = target - now.timestamp() + 1
    return delay if delay <= MAX_WAIT and delay + 60 < remaining else None


def run_pipeline(config: dict, scope: dict, config_hash: str, *, budget=None, remote=None) -> dict:
    """検証済みconfigと明示承認のもとで、一日分の収集・署名・Private索引配布を進める。

    呼出し側はload_configを通した入力を渡す。operation lockをwith終了まで保持し、
    実行済みreceiptと同一byteの中間物を残して再開する。HOLD/NO_NETWORKは公開せず返し、
    他の失敗は例外とする。署名・再取得検証後だけcurrentをCASし、途中のfileや
    remote変更は自動取消ししない。budget/remoteの注入はfake試験用の境界である。
    """
    directory = operation_root(Path(config["outputRoot"]))
    protected_tree(directory)
    budget = budget or Budget()
    if isinstance(budget, Budget):
        budget.directory = directory
    now = utc()
    first, smoke = (parse_time(config[name]) for name in ("firstDailyLocal", "smokeLocal"))
    local = now.astimezone(first.tzinfo)
    dates = [smoke.date()] + [(first + timedelta(days=i)).date() for i in range(7)]
    require(local.date() in dates and smoke <= now < first + timedelta(days=7), "OUTSIDE_OBSERVATION_WINDOW")
    prefix = directory / acquisition_job_day(config)
    with exclusive(directory / "pipeline.lock"):
        # 正当な旧configへの拘束と旧startの全byteだけを継承し、任意markerを許可しない。
        if config.get("purpose") == ACQUISITION_PURPOSE:
            validate_legacy_metadata(config)
            if "preSignContinuation" in config:
                continuation = validate_presign_continuation(config)
                binding = continuation["binding"]
                carry_code_repair_budget(budget, binding["priorNativeCalls"] + binding["preparationNativeCalls"],
                    binding["priorElapsedSeconds"] + binding["preparationElapsedSeconds"])
                verify_reservation(config, continuation["path"], continuation["raw"], budget, "FRESH_INPUT")
                keep_exact(continuation["markerPath"], continuation["marker"])
                return run_acquisition(config, scope, config_hash, prefix, budget, remote)
            # 元startを保持し、現headで再検証した同receiptからだけ修正版を再開する。
            if "codeRepair" in config:
                continuation = validate_code_repair(config)
                repair = continuation["repair"]
                carry_code_repair_budget(budget, repair["priorNativeCalls"] + repair["preparationNativeCalls"],
                    repair["priorElapsedSeconds"] + repair["preparationElapsedSeconds"])
                verify_reservation(config, continuation["path"], continuation["raw"], budget, "FRESH_INPUT")
                marker = canonical({"schema": "dc-daily-code-repair-start-v1", "configSha256": config_hash,
                    "predecessorConfigSha256": repair["configSha256"], "startSha256": repair["startSha256"],
                    "receiptSha256": repair["receiptSha256"], "day": local.strftime("%Y%m%d")})
                keep_exact(Path(str(prefix) + ".acquisition.code-repair.json"), marker)
                return run_acquisition(config, scope, config_hash, prefix, budget, remote)
            legacy_hash = config["legacyMetadata"]["configSha256"]
            legacy_path = Path(str(prefix) + ".start.json")
            legacy_start_hash = None
            if legacy_path.exists():
                legacy_start = read(legacy_path, 65536)
                require(legacy_start == canonical({"schema": "dc-daily-start-v1", "configSha256": legacy_hash,
                        "day": local.strftime("%Y%m%d")}), "RESUME_BYTES_CONFLICT")
                legacy_start_hash = sha(legacy_start)
            start = canonical({"schema": "dc-daily-acquisition-start-v1", "purpose": ACQUISITION_PURPOSE,
                "configSha256": config_hash, "legacyConfigSha256": legacy_hash,
                "legacyStartSha256": legacy_start_hash, "day": local.strftime("%Y%m%d")})
            # 原startの有無が変わった再開も、native/networkの前にexact比較で止める。
            keep_exact(Path(str(prefix) + ".acquisition.start.json"), start)
            return run_acquisition(config, scope, config_hash, prefix, budget, remote)
        start = canonical({"schema": "dc-daily-start-v1", "configSha256": config_hash, "day": local.strftime("%Y%m%d")})
        keep_exact(Path(str(prefix) + ".start.json"), start)
        success_path = Path(str(prefix) + ".success.json")
        if success_path.exists():
            saved = cr.parse_json(read(success_path, 65536))
            require(saved.get("configSha256") == config_hash and saved.get("status") == "PUBLISHED", "SUCCESS_BINDING")
            return saved
        receipt = None
        attempts = sorted(directory.glob(prefix.name + ".collection-*.json"))
        require(len(attempts) <= 32, "DAILY_ATTEMPT_COUNT")
        for path in attempts:
            value = cr.parse_json(read(path, 1024 * 1024))
            if value.get("outcome") in {"NEW_200", "REVALIDATED_304"}:
                require(receipt is None, "MULTIPLE_DAILY_OBSERVATIONS")
                receipt = value
        if receipt is None:
            for position in range(2):
                receipt_path = directory / (prefix.name + f".collection-{len(attempts) + position:02d}.json")
                code, _, _ = budget.run([config["collectorExe"], "--daily-evidence", config["manifestFile"],
                                         config["stateRoot"], str(receipt_path)])
                require_native_receipt(receipt_path, code)
                receipt = cr.parse_json(read(receipt_path, 1024 * 1024))
                outcome = receipt.get("outcome")
                if code == 3 and outcome == "HOLD":
                    delay = hold_seconds(receipt, utc(), budget.remaining(MAX_SECONDS))
                    if position == 0 and delay is not None:
                        time.sleep(delay)
                        continue
                    return {"status": "HOLD", "notBefore": receipt["notBefore"], "newGeneration": False}
                if outcome == "NO_NETWORK":
                    return {"status": "NO_NETWORK", "newGeneration": False}
                require(code == 0 and outcome in {"NEW_200", "REVALIDATED_304"}, "COLLECTION_FAILED_NO_PUBLICATION")
                break
        raw_index, packed, raw_manifest, _ = projection.project_daily(scope, receipt, utc())
        require(receipt["day"] == utc().strftime("%Y%m%d"), "DAILY_RECEIPT_WRONG_DAY")
        # Freeze publication time across resume; regenerate all bytes before reusing existing outputs.
        manifest_path = Path(str(prefix) + ".manifest.raw.json")
        if manifest_path.exists():
            frozen = cr.parse_json(read(manifest_path, 65536))
            raw_index, packed, raw_manifest, _ = projection.project_daily(scope, receipt, parse_time(frozen["publishedAtUtc"]))
        gzip_path, envelope_path = Path(str(prefix) + ".index.json.gz"), Path(str(prefix) + ".manifest.json")
        keep_exact(manifest_path, raw_manifest)
        keep_exact(gzip_path, packed)
        if not envelope_path.exists():
            code, _, _ = budget.run([config["signerExe"], "--distribution-sign", str(manifest_path),
                                     str(gzip_path), str(envelope_path), config["fingerprint"]])
            require(code == 0, "DISTRIBUTION_SIGNATURE_FAILED")
        bundle = {"index.json.gz": read(gzip_path), "manifest.json": read(envelope_path, 96 * 1024)}
        audit_bundle(bundle, scope, receipt, utc())

        def verify(candidate: dict[str, bytes], *, historical: bool):
            require(set(candidate) == ASSETS, "ASSET_ALLOWLIST")
            candidate_hash = sha(candidate["manifest.json"] + candidate["index.json.gz"])
            env_file = directory / ("verify-" + candidate_hash + ".manifest.json")
            gz_file = directory / ("verify-" + candidate_hash + ".index.json.gz")
            keep_exact(env_file, candidate["manifest.json"])
            keep_exact(gz_file, candidate["index.json.gz"])
            argv = [config["signerExe"], "--distribution-verify-history" if historical else "--distribution-verify",
                    str(env_file), str(gz_file), config["publicKeyFile"], config["fingerprint"]]
            if historical:
                historical_manifest, _ = unpack_envelope(candidate["manifest.json"])
                argv.append(str(int(parse_time(historical_manifest["publishedAtUtc"]).timestamp())))
            code, _, _ = budget.run(argv)
            require(code == 0, "NATIVE_DISTRIBUTION_VERIFY_FAILED")
            if not historical:
                audit_bundle(candidate, scope, receipt, utc())

        result = Publisher(remote or GitHub(config["ghExe"], budget), verify).publish(bundle)
        result.update(configSha256=config_hash, envelopeSha256=sha(bundle["manifest.json"]),
                      originalFetchedAt=receipt["lastFetchedAt"], validatedAt=receipt["lastSuccessfulValidationAt"])
        write_new(success_path, canonical(result))
        return result


def task_xml(config: dict, config_path: Path, user_sid: str, *, smoke: bool = False) -> bytes:
    """検証済みconfigのActionと同じ承認workspaceのcwdを持つ有限Task XMLを返す。"""
    require(re.fullmatch(r"S-1-5-21-(?:[0-9]+-){2}[0-9]+-[0-9]+", user_sid) is not None, "CURRENT_USER_SID")
    workspace = require_config_workspace(config)
    start = parse_time(config["smokeLocal" if smoke else "firstDailyLocal"])
    end = start + (timedelta(minutes=31) if smoke else timedelta(days=6, minutes=31))
    ET.register_namespace("", TASK_NS)
    task = ET.Element("{" + TASK_NS + "}Task", {"version": "1.4"})

    def child(parent, name, value=None, attributes=None):
        node = ET.SubElement(parent, "{" + TASK_NS + "}" + name, attributes or {})
        if value is not None:
            node.text = value
        return node

    info = child(task, "RegistrationInfo")
    child(info, "Description", "DriverCrate private " +
          ("acquisition" if config.get("purpose") == ACQUISITION_PURPOSE else "metadata") +
          " index; finite seven-day observation; no driver install.")
    triggers = child(task, "Triggers")
    trigger = child(triggers, "TimeTrigger" if smoke else "CalendarTrigger")
    child(trigger, "StartBoundary", start.isoformat())
    child(trigger, "EndBoundary", end.isoformat())
    child(trigger, "Enabled", "true")
    if not smoke:
        child(child(trigger, "ScheduleByDay"), "DaysInterval", "1")
    principal = child(child(task, "Principals"), "Principal", attributes={"id": "CurrentUser"})
    child(principal, "UserId", user_sid)
    child(principal, "LogonType", "InteractiveToken")
    child(principal, "RunLevel", "HighestAvailable")
    settings = child(task, "Settings")
    for name, value in (("MultipleInstancesPolicy", "IgnoreNew"), ("DisallowStartIfOnBatteries", "false"),
                        ("StopIfGoingOnBatteries", "false"), ("StartWhenAvailable", "true"),
                        ("RunOnlyIfNetworkAvailable", "false"), ("AllowHardTerminate", "false"),
                        ("Enabled", "true"), ("Hidden", "true"), ("RunOnlyIfIdle", "false"),
                        ("WakeToRun", "false"), ("ExecutionTimeLimit", "PT30M")):
        child(settings, name, value)
    action = child(child(task, "Actions", attributes={"Context": "CurrentUser"}), "Exec")
    pythonw = Path(config["pythonExe"]).with_name("pythonw.exe")
    require(pythonw.is_file(), "HIDDEN_PYTHON_REQUIRED")
    child(action, "Command", str(pythonw))
    child(action, "Arguments", subprocess.list2cmdline(["-I", str(Path(__file__).resolve()), "run", str(config_path)]))
    child(action, "WorkingDirectory", str(workspace.repositoryRoot))
    return ET.tostring(task, encoding="utf-8", xml_declaration=True)


def report(config: dict) -> dict:
    """七日分母と全terminalを保持し、新旧結果の追加診断だけを再検証して返す。"""
    operation_root(Path(config["outputRoot"]))
    first = parse_time(config["firstDailyLocal"])
    acquisition = config.get("purpose") == ACQUISITION_PURPOSE
    rows = []
    for position in range(7):
        day = first + timedelta(days=position)
        prefix = Path(config["outputRoot"]) / day.strftime("%Y%m%d")
        success = Path(str(prefix) + (".acquisition" if acquisition else "") + ".success.json")
        row = {"scheduledLocal": day.isoformat(), "status": "NOT_RUN" if day < utc() else "PENDING"}
        terminals = sorted(prefix.parent.glob(prefix.name + ".terminal-*.json"))
        require(len(terminals) <= 64, "REPORT_ATTEMPT_LIMIT")
        row["attempts"] = [result_with_safe_github_failure(cr.parse_json(read(path, 65536))) for path in terminals]
        # 全terminalは保持し、旧metadata成功を取得用途の現在成功へ昇格させない。
        if terminals and (not acquisition or row["attempts"][-1].get("status") != "PUBLISHED" or
                          row["attempts"][-1].get("purpose") == ACQUISITION_PURPOSE):
            row.update(row["attempts"][-1])
        legacy_success = Path(str(prefix) + ".success.json")
        if acquisition and legacy_success.exists():
            row["legacyMetadataResult"] = result_with_safe_github_failure(cr.parse_json(read(legacy_success, 65536)))
        if success.exists():
            row.update(result_with_safe_github_failure(cr.parse_json(read(success, 65536))))
        rows.append(row)
    result = {"schema": "dc-seven-day-observation-v1", "denominator": 7, "days": rows,
            "smokeExcluded": True, "lockExecutionObserved": None, "privateAnonymousAppDistribution": False}
    if config.get("purpose") == ACQUISITION_PURPOSE:
        result["purpose"] = ACQUISITION_PURPOSE
        result["legacyPurpose"] = "METADATA_ONLY"
    return result


def main() -> int:
    """明示modeを実行し、元の終了区分と固定codeに検証済み任意診断だけを添えて保存する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("plan", "run", "report", "task"))
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--user-sid")
    parser.add_argument("--smoke", action="store_true")
    args = parser.parse_args()
    config, scope, config_hash = load_config(args.config.resolve())
    if args.mode == "run":
        try:
            result = run_pipeline(config, scope, config_hash)
        except Exception as error:
            # Only fixed codes are retained; subprocess stderr/token/path/body are never copied here.
            code = str(error) if re.fullmatch(r"[A-Z_]+", str(error)) else "PIPELINE_EXCEPTION"
            result = {"status": "FAILED", "reason": code, "configSha256": config_hash}
            result["githubFailure"] = getattr(error, "github_failure", None)
            result["nativeFailure"] = getattr(error, "native_failure", None)
            if config.get("purpose") == ACQUISITION_PURPOSE:
                result.update(purpose=ACQUISITION_PURPOSE, signingOutcome="UNKNOWN_NO_RE_SIGN")
        result = result_with_safe_github_failure(result)
        prefix = Path(config["outputRoot"]) / acquisition_job_day(config)
        path = Path(str(prefix) + f".terminal-{time.time_ns()}.json")
        write_new(path, canonical(result))
        print(json.dumps(result))
        return 0 if result["status"] == "PUBLISHED" else 3 if result["status"] in {"HOLD", "NO_NETWORK"} else 2
    require(args.output is not None and args.output.is_absolute(), "NEW_OUTPUT_REQUIRED")
    normal_path(str(args.output), exists=False)
    require(args.output.parent == args.config.parent, "CONTROL_OUTPUT_REQUIRED")
    protected_path(args.output.parent)
    if args.mode == "task":
        raw = task_xml(config, args.config.resolve(), args.user_sid or "", smoke=args.smoke)
    elif args.mode == "report":
        raw = canonical(report(config))
    else:
        raw = canonical({"schema": "dc-private-daily-plan-v1", "configSha256": config_hash,
            "repository": REPOSITORY, "privateRequired": True, "assetAllowlist": sorted(ASSETS),
            "stateRootInherited": True, "maximumSeconds": MAX_SECONDS, "maximumHoldWait": MAX_WAIT,
            "realOperations": 0, "taskName": TASK_NAME, "smokeLocal": config["smokeLocal"],
            "firstDailyLocal": config["firstDailyLocal"], "days": 7, "credentialRead": False})
    write_new(args.output, raw)
    print("DAILY_INDEX_PLAN_COMPLETED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError):
        print("DAILY_INDEX_INPUT_REJECTED")
        raise SystemExit(2)
