"""固定Intel日次収集・独立した成功候補の明示署名準備・索引限定反映（ADR0344/0397/0403）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
監視PC専用Python3。plan/task/reportは収集・鍵・GitHub書込みを行わない。
prepare-candidateはPublic読取りと世代予約まで。sign-candidateだけが既存native署名器を呼び、
両者ともGitHub書込みや通常Taskの署名/公開を行わない。publish-candidateは固定署名束だけを
既存Publisherへ渡し、収集/署名を行わない。
用途別開始記録と公表hashの契約: docs/adr/0373-acquisition-digest-and-legacy-day-entry.md。
一段だけの修復継承: docs/adr/0374-receipt-anchor-and-code-only-continuation.md。
既知の署名前checkpoint継承: docs/adr/0375-explicit-presign-checkpoint-continuation.md。
四原file保持の一回caller更新: docs/adr/0376-verified-unsigned-presign-caller-refresh.md。
asset実byte長と証拠専用回復の境界: docs/adr/0377-asset-upload-length-and-pinned-draft-recovery.md。
明示Public identityの内部byte検証境界: docs/adr/0381-public-daily-index-publisher-identity.md。
Public設定と未接続履歴の閉入口: docs/adr/0382-public-daily-config-and-history-transition.md。
明示history限定のfresh-due接続: docs/adr/0383-public-history-and-fresh-due-transition.md。
匿名原byte確認と同予算の閉再観測: docs/adr/0385-public-anonymous-index-readback.md。
"""
from __future__ import annotations

import argparse
import base64
import ctypes
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import gzip
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

# 既存loaderの探索順序を保ち、単独-I起動で不在のsiblingだけを追加する。
if str(Path(__file__).resolve().parent) not in sys.path:
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
PUBLIC_APPROVAL_VALUES = (
    ("schema", "dc-approved-public-index-publisher-v1"),
    ("approvalKind", "EXPLICIT_PUBLIC_SIGNED_INDEX"),
    ("mode", "PUBLIC_SIGNED_INDEX_V1"), ("purpose", ACQUISITION_PURPOSE),
    ("repository", REPOSITORY), ("repositoryId", 1425267459),
    ("repositoryNodeId", "R_kgDOVPPbAw"),
    ("ownerLogin", "EnterOgawa"), ("ownerId", 113655398),
    ("actorLogin", "EnterOgawa"), ("actorId", 113655398), ("visibility", "public"),
    ("publicFingerprint", "0ac4d0ce9873c82b3c7bb7bd3fb3f5d2a57044bf968c5c6e2af02176cee39d3f"),
)
V2_CONFIG_FIELDS = CONFIG_FIELDS | {"purpose", "termsReviewMode", "modulePins", "originalInputs",
    "archiveFile", "archiveSha256", "archiveBytes", "selectedInf", "legacyMetadata", "legacyReservationFence"}
PUBLIC_CONFIG_SCHEMA = "dc-public-daily-index-config-v3"
PUBLIC_CONFIG_FIELDS = frozenset({"predecessorConfigFile", "predecessorConfigSha256",
                                  "publicPublisherApprovalSha256"})
PUBLIC_RUNTIME_FIELDS = frozenset({"collectorExe", "collectorSha256", "signerExe", "signerSha256",
                                  "pipelineSha256", "producerSha256", "modulePins"})
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
    # Publicは原v2の通常検証を再利用し、旧loaderの例外contextへ入れない。
    if config.get("schema") == PUBLIC_CONFIG_SCHEMA:
        require(not any((inherited_v1, predecessor_v2, presign_predecessor, verified_unsigned_predecessor)),
                "PUBLIC_CONFIG_CONTEXT")
        scope, _ = validate_public_config(config)
        return config, scope, sha(raw)
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
        if scope["schema"] == projection.METADATA_BOUND_SCOPE:
            require(config["selectedInf"] == scope["acquisitionBinding"]["selectedInf"], "NATIVE_INF_BINDING")
        require(scope["collectorManifestSha256"] == config["manifestSha256"] and
                scope["publicFingerprint"] == config["fingerprint"] and
                config["purpose"] == ACQUISITION_PURPOSE and
                config["termsReviewMode"] == (projection.PINNED_STATIC_REVALIDATION_V2 if
                    scope["schema"] == projection.METADATA_BOUND_SCOPE else projection.PINNED_STATIC_REVALIDATION_V1),
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
    # 保存済みphaseの旧検査名は証拠として保持し、新準備はfloor専用名だけを記録する。
    allowed = {"--verify-daily-reservation", "--distribution-verify-history", "--distribution-verify-floor-history",
               "--parse-collected-release",
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
    metadata_bound = config["termsReviewMode"] == projection.PINNED_STATIC_REVALIDATION_V2
    technical = bool(set(config["originalInputs"]) & projection.TECHNICAL_REVIEW_INPUTS)
    require(not technical or metadata_bound, "TERMS_REVIEW_MODE")
    cr.fields(config["originalInputs"], {"release", "review", "script"} | ({"body"} if metadata_bound else set()) |
              (projection.TECHNICAL_REVIEW_INPUTS if technical else set()), "TERMS_REVALIDATION_FIELDS")
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
    historical_hash = projection.digest(config["archiveSha256"])
    require(historical_hash == projection.digest(release["publishedSha256"]) and
            (metadata_bound or historical_hash == "2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5") and
            type(config["archiveBytes"]) is int and 0 < config["archiveBytes"] <= projection.MAX_ARCHIVE_BYTES and
            (metadata_bound or (config["archiveBytes"] == 40477087 and
             config["selectedInf"] == "PRO2500/Winx64/W11/e2fn.inf")), "ACQUISITION_ARCHIVE_BINDING")
    if metadata_bound:
        projection.relative_inf(config["selectedInf"])
        require(sha(originals["body"]) == release["bodySha256"] and len(originals["body"]) == release["bodyBytes"],
                "TERMS_REVALIDATION_PIN")
    archive = normal_path(config["archiveFile"])
    require(root in archive.parents, "PROTECTED_INPUT_LOCATION")
    protected_path(archive, root=root)
    return originals, pins


def measured_archive_identity(archive: Path, maximum: int) -> dict:
    """有限streamの同handleから実SHA256/512/sizeを計算する。公表値を実identityへ代用しない。"""
    require(type(maximum) is int and 0 < maximum <= projection.MAX_ARCHIVE_BYTES, "ACQUISITION_ARCHIVE_SIZE")
    protected_path(archive)
    sha256, sha512 = hashlib.sha256(), hashlib.sha512()
    count = 0
    with archive.open("rb") as stream:
        before = os.fstat(stream.fileno())
        require(0 < before.st_size <= maximum and before.st_nlink == 1, "ACQUISITION_ARCHIVE_SIZE")
        while True:
            raw = stream.read(min(1024*1024, maximum-count+1))
            if not raw:
                break
            count += len(raw)
            require(count <= maximum, "ACQUISITION_ARCHIVE_SIZE")
            sha256.update(raw)
            sha512.update(raw)
        after = os.fstat(stream.fileno())
    require(count == before.st_size == after.st_size and
            (before.st_ino, before.st_dev, before.st_mtime_ns) ==
            (after.st_ino, after.st_dev, after.st_mtime_ns), "ACQUISITION_ARCHIVE_CHANGED")
    protected_path(archive)
    return {"sha256": sha256.hexdigest(), "sha512": sha512.hexdigest(), "sizeBytes": count}


def validate_legacy_metadata(config: dict) -> dict:
    """旧原byte/同root/世代を構造検査する。署名floorと実headは別途nativeで認証する。"""
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
    publication = parse_time(manifest["publishedAtUtc"])
    require(raw == values["rawManifest"] and manifest["keyId"] == scope["keyId"] and
            publication <= utc(), "LEGACY_METADATA_BINDING")
    # 旧recordを現codecで再生成せず、原receiptと署名対象の世代/assetだけを結ぶ。
    generation = projection._validated_daily_generation(receipt, publication)
    require(receipt["manifestSha256"] == config["manifestSha256"] and
            manifest["generation"] == manifest["assetGeneration"] == generation and
            manifest["asset"]["sizeBytes"] == len(values["gzip"]) and
            manifest["asset"]["sha256"] == sha(values["gzip"]), "LEGACY_METADATA_BINDING")
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
    require(terms_review_mode in {None, projection.PINNED_STATIC_REVALIDATION_V1, projection.PINNED_STATIC_REVALIDATION_V2} and
            (terms_review_mode is None or daily), "TERMS_REVIEW_MODE")
    if terms_review_mode in {projection.PINNED_STATIC_REVALIDATION_V1, projection.PINNED_STATIC_REVALIDATION_V2}:
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
    if terms_review_mode in {projection.PINNED_STATIC_REVALIDATION_V1, projection.PINNED_STATIC_REVALIDATION_V2}:
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
    require(terms_review_mode in {projection.PINNED_STATIC_REVALIDATION_V1, projection.PINNED_STATIC_REVALIDATION_V2}, "TERMS_REVIEW_MODE")
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
    metadata_bound = scope["schema"] == projection.METADATA_BOUND_SCOPE
    binding, expected_release, _ = projection.metadata_acquisition_binding(scope) if metadata_bound else (None, None, None)
    require(terms_review_mode == (projection.PINNED_STATIC_REVALIDATION_V2 if metadata_bound else
            projection.PINNED_STATIC_REVALIDATION_V1), "TERMS_REVIEW_MODE")
    require(selected_inf == (binding["selectedInf"] if metadata_bound else "PRO2500/Winx64/W11/e2fn.inf"), "NATIVE_INF_BINDING")
    archive = normal_path(str(archive), exists=False)
    require(archive.is_file() and not archive.is_symlink(), "ACQUISITION_ARCHIVE_MISSING")
    size = archive.stat().st_size
    require(0 < size <= (binding["maximumBytes"] if metadata_bound else 134217728) and
            (metadata_bound or size == 40477087), "ACQUISITION_ARCHIVE_SIZE")
    measured = measured_archive_identity(archive, binding["maximumBytes"]) if metadata_bound else None
    if metadata_bound:
        require(all(measured[algorithm] == value for algorithm, value in
                    projection.published_digests(expected_release).items()) and
                (expected_release.get("publishedSizeBytes") is None or
                 size == expected_release["publishedSizeBytes"]), "ACQUISITION_ARCHIVE_BINDING")
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
    technical = bool(set(originals) & projection.TECHNICAL_REVIEW_INPUTS)
    cr.fields(originals, {"release", "review", "script"} | ({"body"} if metadata_bound else set()) |
              (projection.TECHNICAL_REVIEW_INPUTS if technical else set()), "TERMS_REVALIDATION_FIELDS")
    cr.fields(original_pins, set(originals), "TERMS_REVALIDATION_FIELDS")
    for name, value in originals.items():
        require(type(value) is bytes and 0 < len(value) <= (65536 if name == "review" else 1048576) and
                type(original_pins[name]) is str and re.fullmatch(r"[0-9a-f]{64}", original_pins[name]) is not None and
                sha(value) == original_pins[name], "TERMS_REVALIDATION_PIN")
    old_review = cr.parse_json(originals["review"])
    old_release = cr.parse_json(originals["release"])
    old_script = cr.parse_json(originals["script"])
    if not metadata_bound:
        require(receipt["bodySha256"] == old_release["bodySha256"], "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
    original_body = originals["body"] if metadata_bound else body
    require(sha(original_body) == old_release["bodySha256"] and len(original_body) == old_release["bodyBytes"],
            "TERMS_REVALIDATION_PIN")
    projection.confirm_terms_review(original_body, old_release, old_review, old_script, now)
    if not resume_presign:
        write_new(body_path, body)
    validated = str(int(receipt["lastSuccessfulValidationAt"]))
    commands = [] if resume_presign else [
        ([config["signerExe"], "--parse-collected-release", str(body_path), receipt["bodySha256"],
          validated, str(release_path)], "FRESH_RELEASE_FAILED", 120)]
    commands += [] if verified_unsigned else [
        # 検証済みdigest値と論理INFだけを既存native境界の表記へ揃え、原JSON/pinは保持する。
        ([config["signerExe"], "--inspect-collected-package", str(archive),
          measured["sha256"] if metadata_bound else projection.digest(old_release["publishedSha256"]), str(inspection_path),
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
    review_options = {"mode": terms_review_mode} if metadata_bound else {}
    review_raw = projection.make_pinned_static_terms_revalidation(body, originals, original_pins,
        release_raw, script_raw, int(completed.timestamp()), completed, **review_options)
    if metadata_bound:
        inspection = cr.parse_json(inspection_raw)
        require(all(inspection.get("archive"+algorithm.capitalize()) == measured[algorithm]
                    for algorithm in ("sha256", "sha512")) and inspection.get("archiveBytes") == measured["sizeBytes"],
                "ACQUISITION_INSPECTION_IDENTITY")
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


def prepare_fresh_daily_acquisition_inputs(config: dict, receipt_path: Path, *,
        maximum_bytes: int, consent_not_after: int, accept_pinned_terms: bool, budget=None) -> dict:
    """同native runの明示本体取得から既存六入力へ接続する。署名/公開/鍵操作は行わない。

    保護された原releaseの全byte pinを同意対象とし、原terms/scriptレビューは既存検査を維持する。
    旧archiveを代用せず、新receiptから導出するarchiveだけを既存内容検査へ渡す。
    失敗/不確定は新receipt/partial/孤立archiveを保持し、自動再試行や待機resetを行わない。
    """
    now = utc()
    require(config.get("schema") == "dc-private-daily-index-config-v2" and
        config.get("purpose") == ACQUISITION_PURPOSE, "FRESH_NATIVE_CONFIG")
    require(type(maximum_bytes) is int and 0 < maximum_bytes <= 134217728 and
        type(consent_not_after) is int and type(accept_pinned_terms) is bool and accept_pinned_terms and
        type(now) is datetime and now.tzinfo is not None and now.utcoffset() == timedelta(0) and
        0 < int(now.timestamp()) < consent_not_after <= int(now.timestamp()) + 86400,
        "FRESH_NATIVE_CONSENT")
    directory = operation_root(Path(config["outputRoot"]))
    protected_tree(directory)
    receipt_path = normal_path(str(receipt_path), exists=False)
    require(receipt_path.parent == directory and receipt_path.suffix == ".json" and
        re.fullmatch(r"[a-z0-9][a-z0-9.-]{0,120}\.json", receipt_path.name) is not None,
        "FRESH_NATIVE_OUTPUT")
    archive = receipt_path.with_suffix(".payload.zip")
    partial = receipt_path.with_suffix(".payload.partial.zip")
    diagnostic = receipt_path.with_suffix(".failed-page.json")
    approved = receipt_path.with_suffix(".approved-release.json")
    bundle_path = receipt_path.with_suffix(".native-inputs.json")
    budget = budget or Budget()
    if isinstance(budget, Budget):
        budget.directory = directory
    with exclusive(directory / "pipeline.lock"):
        require_config_workspace(config)
        validate_v2_code(config)
        for name, pin in (("collectorExe", "collectorSha256"), ("signerExe", "signerSha256"),
                          ("manifestFile", "manifestSha256"), ("scopeFile", "scopeSha256")):
            path = normal_path(config[name])
            protected_path(path)
            require(sha(read(path)) == config[pin], "FRESH_NATIVE_RUNTIME_PIN")
        originals, pins = acquisition_originals(config)
        scope_raw = read(Path(config["scopeFile"]), 65536)
        scope = cr.parse_json(scope_raw)
        projection._validate_distribution_scope(scope)
        metadata_bound = scope["schema"] == projection.METADATA_BOUND_SCOPE
        binding, _, expected_raw = projection.metadata_acquisition_binding(scope) if metadata_bound else (None, None, originals["release"])
        require(config["termsReviewMode"] == (projection.PINNED_STATIC_REVALIDATION_V2 if metadata_bound else
                projection.PINNED_STATIC_REVALIDATION_V1), "TERMS_REVIEW_MODE")
        require(not metadata_bound or (maximum_bytes <= binding["maximumBytes"] and
                config["selectedInf"] == binding["selectedInf"] and "body" in originals), "FRESH_NATIVE_BINDING")
        require(all(not path.exists() for path in (receipt_path, archive, partial, approved, bundle_path, diagnostic)),
            "FRESH_NATIVE_OUTPUT_EXISTS")
        # このcopyは同意対象の原public metadataだけ。private record/grantを保存しない。
        write_new(approved, expected_raw)
        code, output, _ = budget.run([config["collectorExe"], "--daily-acquire", config["manifestFile"],
            config["stateRoot"], str(receipt_path), str(approved), sha(expected_raw), str(maximum_bytes),
            str(consent_not_after), "--accept-pinned-terms"], maximum=4096, seconds=budget.remaining(MAX_SECONDS))
        require_native_receipt(receipt_path, code)
        receipt = cr.parse_json(read(receipt_path, 1048576))
        if code == 3 and receipt.get("outcome") in {"HOLD", "NO_NETWORK"}:
            return {"status": receipt["outcome"], "prepared": False, "signed": False, "published": False}
        require(code == 0 and receipt.get("outcome") == "NEW_200" and type(output) is bytes and
            re.fullmatch(rb"COLLECTOR_PAYLOAD save_error=0 held=0 not_before=[0-9]+ stage=0 acquired=1 installed=0\s*",
                output) is not None and archive.is_file() and not archive.is_symlink() and
            0 < archive.stat().st_size <= maximum_bytes, "FRESH_NATIVE_PAYLOAD_FAILED")
        protected_path(archive)
        prepared = prepare_daily_acquisition_inputs(config, scope_raw, receipt_path, originals, pins,
            archive, config["selectedInf"], budget, terms_review_mode=config["termsReviewMode"])
        stem = "acquisition-" + receipt_path.stem
        files = {"scope": Path(config["scopeFile"]), "evidence": receipt_path,
            **{name: directory / (stem + "." + name + ".json") for name in
                ("release", "inspection", "review", "script")}}
        # 既存candidate readerの六file形式だけへ投影し、claim/署名は発行しない。
        raw = canonical({"schema": "dc-candidate-native-inputs-v1", "inputs": {
            name: {"file": str(path), "sha256": prepared["inputPins"][name]} for name, path in files.items()}})
        write_new(bundle_path, raw)
        return {"status": "PREPARED_UNSIGNED", "prepared": True, "signed": False, "published": False,
            "nativeInputsFile": str(bundle_path), "nativeInputsSha256": sha(raw),
            "reservation": prepared["reservation"], "archiveBytes": archive.stat().st_size}


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
    historyは原公開秒でnative検証し、旧metadataは世代下限だけを認証する。
    currentは従来どおりacquisitionの全recordと六入力を再監査する。
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
        mode = ("--distribution-verify-floor-history" if historical and profile == "distribution" else
                "--" + profile + ("-verify-history" if historical else "-verify"))
        argv = [config["signerExe"], mode,
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


PUBLIC_READBACK_FIELDS = ("schema", "outcome", "startedAtUtc", "completedAtUtc", "elapsedMilliseconds",
    "resources", "sends", "receivedBytes", "nativeError", "failureStage")
PUBLIC_RESOURCE_FIELDS = ("role", "state", "httpStatus", "sends", "receivedBytes", "sha256", "nativeError")
PUBLIC_RESOURCE_ROLES = ("CURRENT_ENVELOPE", "IMMUTABLE_ENVELOPE", "IMMUTABLE_GZIP")
PUBLIC_ANONYMOUS_FIELDS = ("schema", "status", "configSha256", "signingClaimSha256", "generation", "commit",
    "tag", "envelopeSha256", "gzipSha256", "sourceCycleSha256", "worker", "verifier", "verifiedAtUtc")
PUBLIC_WORKER_FIELDS = ("ordinal", "intentSha256", "completeSha256", "exeSha256", "childExitCode",
    "stdoutSha256", "report")
PUBLIC_VERIFIER_FIELDS = PUBLIC_WORKER_FIELDS[:5]
PUBLIC_ANONYMOUS_CODES = frozenset({"TRANSPORT", "HTTP", "PARTIAL", "BYTE_MISMATCH", "SIGNATURE", "CONTENT",
    "EXPIRED", "TIME_UNKNOWN", "CANCELLED", "BUDGET", "PROCESS_UNKNOWN", "REPORT_INVALID"})
_PUBLIC_ANONYMOUS_AUTHORITY = object()


def public_wire_integer(value, maximum, minimum=0) -> bool:
    """boolと浮動小数を整数へ補正せず、閉wireの原値だけを認める。"""
    return type(value) is int and minimum <= value <= maximum


def public_wire_time(value) -> bool:
    """秒精度の実在UTC20byteだけを認め、offset等価表現を正規化しない。"""
    if type(value) is not str or re.fullmatch(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z", value) is None:
        return False
    try:
        return parse_time(value).strftime("%Y-%m-%dT%H:%M:%SZ") == value
    except (ValueError, OverflowError):
        return False


def public_readback_report(raw: bytes, *, bundle=None, milliseconds=90000) -> dict:
    """native stdoutの閉shape・固定順canonical原byte・実byte根拠を検査する。"""
    require(type(raw) is bytes and 0 < len(raw) <= 65536, "PUBLIC_ANONYMOUS_REPORT_INVALID")
    report = cr.parse_json(raw)
    cr.fields(report, set(PUBLIC_READBACK_FIELDS), "PUBLIC_ANONYMOUS_REPORT_INVALID")
    require(report["schema"] == "dc-public-index-readback-result-v1" and report["outcome"] in
        {"VERIFIED", "UNKNOWN"} and type(report["resources"]) is list and len(report["resources"]) == 3 and
        all(report[name] is None or public_wire_time(report[name]) for name in ("startedAtUtc", "completedAtUtc")) and
        (report["elapsedMilliseconds"] is None or public_wire_integer(report["elapsedMilliseconds"], 2**64 - 1)) and
        public_wire_integer(report["sends"], 9) and public_wire_integer(report["receivedBytes"], 16973825) and
        public_wire_integer(report["nativeError"], 2**32 - 1) and report["failureStage"] in
        {"NONE", "ARGUMENTS", "INPUT", "TRUST", "TIME", "CURRENT", "MANIFEST_ASSET", "GZIP_ASSET", "CONTENT", "CANCELLED"},
        "PUBLIC_ANONYMOUS_REPORT_INVALID")
    resources = []
    for index, resource in enumerate(report["resources"]):
        cr.fields(resource, set(PUBLIC_RESOURCE_FIELDS), "PUBLIC_ANONYMOUS_REPORT_INVALID")
        require(resource["role"] == PUBLIC_RESOURCE_ROLES[index] and resource["state"] in
            {"NOT_STARTED", "COMPLETE", "FAILED"} and public_wire_integer(resource["httpStatus"], 599) and
            (resource["httpStatus"] == 0 or resource["httpStatus"] >= 100) and
            public_wire_integer(resource["sends"], 1 if index == 0 else 4) and
            public_wire_integer(resource["receivedBytes"], 16777217 if index == 2 else 98305) and
            public_wire_integer(resource["nativeError"], 2**32 - 1), "PUBLIC_ANONYMOUS_REPORT_INVALID")
        if resource["state"] == "COMPLETE":
            require(resource["httpStatus"] == 200 and resource["sends"] > 0 and resource["receivedBytes"] > 0 and
                public_sha(resource["sha256"]) and resource["nativeError"] == 0, "PUBLIC_ANONYMOUS_REPORT_INVALID")
            if bundle is not None:
                expected = bundle["index.json.gz" if index == 2 else "manifest.json"]
                require(resource["receivedBytes"] == len(expected) and resource["sha256"] == sha(expected),
                    "PUBLIC_ANONYMOUS_REPORT_INVALID")
        else:
            require(resource["sha256"] is None and (resource["nativeError"] != 0 if resource["state"] == "FAILED" else
                resource["nativeError"] == resource["httpStatus"] == resource["sends"] == resource["receivedBytes"] == 0),
                "PUBLIC_ANONYMOUS_REPORT_INVALID")
        resources.append({name: resource[name] for name in PUBLIC_RESOURCE_FIELDS})
    require(report["sends"] == sum(item["sends"] for item in resources) and
        report["receivedBytes"] == sum(item["receivedBytes"] for item in resources), "PUBLIC_ANONYMOUS_REPORT_INVALID")
    states = [item["state"] for item in resources]
    complete_count = next((index for index, state in enumerate(states) if state != "COMPLETE"), 3)
    require(states == ["COMPLETE"] * complete_count + ["NOT_STARTED"] * (3 - complete_count) or
        (complete_count < 3 and states == ["COMPLETE"] * complete_count + ["FAILED"] +
         ["NOT_STARTED"] * (2 - complete_count)), "PUBLIC_ANONYMOUS_REPORT_INVALID")
    rebuilt = {name: resources if name == "resources" else report[name] for name in PUBLIC_READBACK_FIELDS}
    require(canonical(rebuilt) == raw, "PUBLIC_ANONYMOUS_REPORT_INVALID")
    if report["outcome"] == "VERIFIED":
        require(report["failureStage"] == "NONE" and report["nativeError"] == 0 and
            all(item["state"] == "COMPLETE" for item in resources) and
            public_wire_time(report["startedAtUtc"]) and public_wire_time(report["completedAtUtc"]) and
            report["startedAtUtc"] <= report["completedAtUtc"] and
            public_wire_integer(report["elapsedMilliseconds"], min(90000, milliseconds)),
            "PUBLIC_ANONYMOUS_REPORT_INVALID")
    else:
        require(report["failureStage"] != "NONE" and report["nativeError"] != 0,
                "PUBLIC_ANONYMOUS_REPORT_INVALID")
    return rebuilt


def public_child_record(budget, ordinal: int, exe_sha256: str, code) -> dict:
    """同じdurable journalと同handleが返した元終了値を狭めず保持する。"""
    require(type(budget) is PublicOperationBudget and public_wire_integer(ordinal, 95) and ordinal < budget.calls and
        public_sha(exe_sha256) and (code is None or public_wire_integer(code, 2**32 - 1, -(2**31))),
        "PUBLIC_ANONYMOUS_CHILD_BINDING")
    intent = read(budget.path(ordinal, "intent"), 4096)
    value = cr.parse_json(intent)
    require(value["contextSha256"] == budget.context_hash and value["ordinal"] == ordinal,
            "PUBLIC_ANONYMOUS_CHILD_BINDING")
    completed_path = budget.path(ordinal, "complete")
    completed = read(completed_path, 4096) if completed_path.exists() else None
    require(completed is None or cr.parse_json(completed)["intentSha256"] == sha(intent),
            "PUBLIC_ANONYMOUS_CHILD_BINDING")
    return dict(zip(PUBLIC_VERIFIER_FIELDS, (ordinal, sha(intent), sha(completed) if completed else None, exe_sha256, code)))


def validate_public_anonymous(value: dict, config: dict, config_hash: str, bundle: dict, claim_hash: str,
                              commit: str, budget, *, source_cycle=None, require_verified=False) -> dict:
    """annotationを元束、実pin、同startのjournalへ照合し、自己申告boolを認証しない。"""
    require(type(value) is dict, "PUBLIC_ANONYMOUS_BINDING")
    status = value.get("status")
    cr.fields(value, set(PUBLIC_ANONYMOUS_FIELDS) | ({"failure"} if status == "UNKNOWN" else set()),
              "PUBLIC_ANONYMOUS_BINDING")
    manifest, _ = unpack_envelope(bundle["manifest.json"])
    require(value["schema"] == "dc-public-anonymous-readback-v1" and status in {"PENDING", "UNKNOWN", "VERIFIED"} and
        value["configSha256"] == config_hash and value["signingClaimSha256"] == claim_hash and
        public_wire_integer(value["generation"], 9007199254740991, 1) and value["generation"] == manifest["generation"] and
        type(commit) is str and re.fullmatch(r"[0-9a-f]{40}", commit) is not None and value["commit"] == commit and
        value["tag"] == manifest["asset"]["tag"] and value["envelopeSha256"] == sha(bundle["manifest.json"]) and
        value["gzipSha256"] == sha(bundle["index.json.gz"]) and value["sourceCycleSha256"] == source_cycle,
        "PUBLIC_ANONYMOUS_BINDING")
    for name, fields, pin in (("worker", PUBLIC_WORKER_FIELDS, "collectorSha256"),
                               ("verifier", PUBLIC_VERIFIER_FIELDS, "signerSha256")):
        child = value[name]
        if child is None:
            require(status != "VERIFIED", "PUBLIC_ANONYMOUS_BINDING")
            continue
        cr.fields(child, set(fields), "PUBLIC_ANONYMOUS_BINDING")
        actual = public_child_record(budget, child["ordinal"], config[pin], child["childExitCode"])
        require(all(child[field] == actual[field] for field in PUBLIC_VERIFIER_FIELDS), "PUBLIC_ANONYMOUS_BINDING")
        if status == "VERIFIED":
            require(type(child["childExitCode"]) is int and child["childExitCode"] == 0 and
                child["completeSha256"] is not None, "PUBLIC_ANONYMOUS_BINDING")
        if name == "worker":
            require(child["stdoutSha256"] is None or public_sha(child["stdoutSha256"]), "PUBLIC_ANONYMOUS_BINDING")
            if child["report"] is not None:
                raw = canonical(child["report"])
                intent = cr.parse_json(read(budget.path(child["ordinal"], "intent"), 4096))
                milliseconds = int(min(90, intent["reservedSeconds"]) * 1000)
                report = public_readback_report(raw, bundle=bundle, milliseconds=milliseconds)
                require(child["stdoutSha256"] == sha(raw) and (status != "VERIFIED" or report["outcome"] == "VERIFIED"),
                        "PUBLIC_ANONYMOUS_BINDING")
            else:
                require(status != "VERIFIED", "PUBLIC_ANONYMOUS_BINDING")
    if status == "PENDING":
        require(value["worker"] is value["verifier"] is value["verifiedAtUtc"] is None, "PUBLIC_ANONYMOUS_BINDING")
    elif status == "UNKNOWN":
        cr.fields(value["failure"], {"stage", "code"}, "PUBLIC_ANONYMOUS_BINDING")
        require(value["verifiedAtUtc"] is None and value["failure"]["stage"] in
            {"BEFORE_WORKER", "WORKER", "VERIFIER", "RESULT_SAVE"} and
            value["failure"]["code"] in PUBLIC_ANONYMOUS_CODES, "PUBLIC_ANONYMOUS_BINDING")
    else:
        require(public_wire_time(value["verifiedAtUtc"]) and value["worker"]["ordinal"] < value["verifier"]["ordinal"] and
            value["worker"]["report"]["completedAtUtc"] <= value["verifiedAtUtc"] and
            parse_time(manifest["publishedAtUtc"]) <= parse_time(value["verifiedAtUtc"]) <
            parse_time(manifest["expiresAtUtc"]) and parse_time(value["verifiedAtUtc"]) <= utc(), "PUBLIC_ANONYMOUS_BINDING")
    require(not require_verified or status == "VERIFIED", "PUBLIC_PREDECESSOR_ANONYMOUS_REQUIRED")
    return value


@dataclass(frozen=True)
class PublicAnonymousObservation:
    """元budgetで確認したclosureだけがPublisherへ渡す内部結果。boolの自己申告は受けない。"""
    authority: object
    value: dict


def public_anonymous_terminal(value: dict) -> dict:
    """認証commit確認後の閉PENDING/UNKNOWN/VERIFIED観測を元束へ結合する。"""
    return {"status": "PUBLISHED" if value["status"] == "VERIFIED" else "UNKNOWN",
        "reason": "PUBLIC_ANONYMOUS_VERIFIED" if value["status"] == "VERIFIED" else "PUBLIC_ANONYMOUS_CONFIRMATION_UNKNOWN",
        "purpose": ACQUISITION_PURPOSE, "configSha256": value["configSha256"], "generation": value["generation"],
        "signingClaimSha256": value["signingClaimSha256"], "envelopeSha256": value["envelopeSha256"],
        "commit": value["commit"], "tag": value["tag"], "publicOperationReadbackOnly": True,
        "publicAnonymousReadback": value}


def public_anonymous_callback(config: dict, config_hash: str, prefix: Path, budget, verify, claim_hash: str,
        *, bundle_paths=None):
    """既存Collector一回と親の既存verifier一回を同予算へ接続するclosureを返す。"""
    cycle_path = Path(str(prefix) + ".acquisition.public-cycle.json")
    source_cycle = sha(read(cycle_path, 1048576)) if cycle_path.exists() else None
    def confirm(bundle: dict, commit: str, tag: str) -> PublicAnonymousObservation:
        """CAS反映後の失敗も元commit・原byte・journalを保持したUNKNOWNで返す。"""
        manifest, _ = unpack_envelope(bundle["manifest.json"])
        value = dict(zip(PUBLIC_ANONYMOUS_FIELDS, ("dc-public-anonymous-readback-v1", "PENDING", config_hash,
            claim_hash, manifest["generation"], commit, tag, sha(bundle["manifest.json"]), sha(bundle["index.json.gz"]),
            source_cycle, None, None, None)))
        stage, failure_code = "BEFORE_WORKER", "PROCESS_UNKNOWN"
        worker_ordinal, verifier_ordinal, worker_code, verifier_code = None, None, None, None
        stdout = None
        try:
            require(type(budget) is PublicOperationBudget and not budget.pending, "PUBLIC_RESUME_READBACK_ONLY")
            require(config["fingerprint"] == dict(PUBLIC_APPROVAL_VALUES)["publicFingerprint"], "PUBLIC_CONFIG_FINGERPRINT")
            validate_v2_code(config)
            now = utc().replace(microsecond=0)
            failure_code = "EXPIRED"
            require(parse_time(manifest["publishedAtUtc"]) <= now < parse_time(manifest["expiresAtUtc"]),
                    "PUBLIC_ANONYMOUS_EXPIRED")
            failure_code = "BUDGET"
            budget.reserve_calls(2)
            write_new(Path(str(prefix) + f".terminal-{time.time_ns()}.json"), canonical(public_anonymous_terminal(value)))
            milliseconds = int(min(90.0, budget.remaining(90)) * 1000)
            require(1 <= milliseconds <= 90000, "TOTAL_TIMEOUT")
            stage, failure_code = "WORKER", "PROCESS_UNKNOWN"
            worker_ordinal = budget.calls
            observed_paths = bundle_paths or (Path(str(prefix) + ".acquisition.manifest.json"),
                Path(str(prefix) + ".acquisition.index.json.gz"))
            if bundle_paths is not None:
                require(tuple(read(path) for path in observed_paths) ==
                    (bundle["manifest.json"], bundle["index.json.gz"]), "PUBLIC_ANONYMOUS_INPUT_PIN")
            worker_code, stdout, _ = budget.run([config["collectorExe"], "--public-index-readback",
                *(str(path) for path in observed_paths),
                str(milliseconds)], maximum=65536, seconds=milliseconds / 1000)
            value["worker"] = public_child_record(budget, worker_ordinal, config["collectorSha256"], worker_code) | {
                "stdoutSha256": sha(stdout), "report": None}
            failure_code = "REPORT_INVALID"
            report = public_readback_report(stdout, bundle=bundle, milliseconds=milliseconds)
            value["worker"]["report"] = report
            failure_code = {"TRUST": "SIGNATURE", "CONTENT": "CONTENT", "TIME": "TIME_UNKNOWN",
                "CANCELLED": "CANCELLED"}.get(report["failureStage"],
                "HTTP" if any(item["httpStatus"] in {304, 401, 407} for item in report["resources"]) else
                "BYTE_MISMATCH" if any(item["state"] == "FAILED" and item["httpStatus"] == 200 for item in report["resources"]) else
                "TRANSPORT")
            if report["outcome"] == "VERIFIED" and worker_code != 0:
                failure_code = "PROCESS_UNKNOWN"
            require(type(worker_code) is int and worker_code == 0 and report["outcome"] == "VERIFIED",
                    "PUBLIC_ANONYMOUS_WORKER_UNKNOWN")
            stage, failure_code = "VERIFIER", "CONTENT"
            verifier_ordinal = budget.calls
            verify(bundle, historical=False)
            require(budget.calls == verifier_ordinal + 1 and budget.last_ordinal == verifier_ordinal,
                    "PUBLIC_ANONYMOUS_CHILD_BINDING")
            verifier_code = budget.last_result[0]
            value["verifier"] = public_child_record(budget, verifier_ordinal, config["signerSha256"], verifier_code)
            stage, failure_code = "RESULT_SAVE", "TIME_UNKNOWN"
            verified = utc().replace(microsecond=0)
            require(now <= verified < parse_time(manifest["expiresAtUtc"]), "PUBLIC_ANONYMOUS_EXPIRED")
            value["status"], value["verifiedAtUtc"] = "VERIFIED", verified.strftime("%Y-%m-%dT%H:%M:%SZ")
            validate_public_anonymous(value, config, config_hash, bundle, claim_hash, commit, budget,
                source_cycle=source_cycle, require_verified=True)
        except Exception:
            if worker_ordinal is not None and value["worker"] is None and worker_ordinal < budget.calls:
                value["worker"] = public_child_record(budget, worker_ordinal, config["collectorSha256"], worker_code) | {
                    "stdoutSha256": sha(stdout) if type(stdout) is bytes else None, "report": None}
            if verifier_ordinal is not None and value["verifier"] is None and verifier_ordinal < budget.calls:
                verifier_code = (budget.last_result[0] if budget.last_ordinal == verifier_ordinal and
                                 budget.last_result is not None else None)
                value["verifier"] = public_child_record(budget, verifier_ordinal, config["signerSha256"], verifier_code)
            value["status"], value["verifiedAtUtc"] = "UNKNOWN", None
            value["failure"] = {"stage": stage, "code": failure_code}
        return PublicAnonymousObservation(_PUBLIC_ANONYMOUS_AUTHORITY, value)
    return confirm


def run_acquisition(config: dict, scope: dict, config_hash: str, prefix: Path, budget, remote, *,
                    public_context=None) -> dict:
    """既存mainの同じlock内で、A入力束からclaim・一回署名・既存Publisherへ接続する。"""
    # 旧claim/原署名結果と正規due予約の結合前に、新configで同観測を実行させない。
    public = config.get("schema") == PUBLIC_CONFIG_SCHEMA
    require(not public or (type(public_context) is PublicFreshContext and
            public_context.authority is _PUBLIC_FRESH_AUTHORITY and public_context.config_hash == config_hash and
            public_context.prefix == prefix and public_context.budget is budget),
            "PUBLIC_HISTORY_TRANSITION_REQUIRED")
    directory = prefix.parent
    day_terminals = sorted(directory.glob(prefix.name + ".terminal-*.json"))
    # Publicは匿名pendingも含む四枠、Privateは既存三枠を元64件内へ確保する。
    require(len(day_terminals) <= (60 if public else 61), "REPORT_ATTEMPT_LIMIT")
    terminal_paths = sorted(directory.glob("*.terminal-*.json"))
    require(len(terminal_paths) <= 512, "REPORT_ATTEMPT_LIMIT")
    terminal_results = [cr.parse_json(read(path, 65536)) for path in terminal_paths]
    observed = (public_context.observed if public else collect_daily_acquisition_receipt(config, prefix, budget))
    if public:
        # 認証済みRAM contextでも、準備直前の原byteと同じ保護headを再確認する。
        require(read(observed["path"], 1048576) == observed["raw"], "PUBLIC_FRESH_RECEIPT_PIN")
        verify_reservation(config, observed["path"], observed["raw"], budget, "FRESH_INPUT")
    if observed["status"] != "OBSERVED":
        return {key: value for key, value in observed.items() if key in {"status", "newGeneration"}} | {
            "configSha256": config_hash, "purpose": ACQUISITION_PURPOSE}
    receipt, receipt_path = observed["receipt"], observed["path"]
    generation = receipt["generation"]
    require(type(generation) is int and generation > config["legacyReservationFence"]["generation"],
            "LEGACY_GENERATION_NOT_ISSUABLE")
    projection._validated_daily_generation(receipt, utc())
    require(receipt["day"] == (prefix.name if public else utc().strftime("%Y%m%d")), "DAILY_RECEIPT_WRONG_DAY")
    if public and not public_context.readback_only:
        require(public_jst_day() == prefix.name, "PUBLIC_OPERATION_DAY_CHANGED")
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
        resume_presign = "preSignContinuation" in config and not public
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
        if public:
            require(public_jst_day() == prefix.name, "PUBLIC_OPERATION_DAY_CHANGED")
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
    # Publicは匿名pendingとmainも確保し、元64件上限を越えない。
    require(len(terminals) <= (61 if public else 62), "REPORT_ATTEMPT_LIMIT")
    readback_only = public and public_context.readback_only
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

    anonymous = public_anonymous_callback(config, config_hash, prefix, budget, verify, sha(claim_raw)) if public else None
    result = acquisition_publisher(config, remote or GitHub(config["ghExe"], budget), verify,
                       before_cas=before_cas, anonymous=anonymous).publish(bundle, readback_only=readback_only)
    result.update(configSha256=config_hash, purpose=ACQUISITION_PURPOSE, envelopeSha256=sha(bundle["manifest.json"]),
        originalFetchedAt=receipt["lastFetchedAt"], validatedAt=receipt["lastSuccessfulValidationAt"],
        signingClaimSha256=sha(claim_raw))
    success_path = Path(publication_prefix + ".success.json")
    # CAS済みでも匿名不明の結果を成功fileへ保存・既存成功へ上書きしない。
    if public and result["status"] != "PUBLISHED":
        return result
    if success_path.exists():
        saved = cr.parse_json(read(success_path, 65536))
        require(all(saved.get(name) == result[name] for name in
                    ("status", "generation", "configSha256", "envelopeSha256", "signingClaimSha256", "purpose")),
                "SUCCESS_BINDING")
    else:
        write_new(success_path, canonical(result))
    return result


@dataclass(frozen=True)
class PublicPublisherTarget:
    """純粋検証済み原byteを所有する内部値。保護配置や公開authorityの証明ではない。"""
    approval_bytes: bytes
    approval_sha256: str


def public_publisher_approval(raw: bytes) -> PublicPublisherTarget:
    """閉schemaと固定公開identityを検証し、所有する不変byte/hashを返す。

    I/Oとauthority発行は行わない。保護位置/ACL/hash pinは後続の運用入口で別途必要。
    """
    # mutable容器、空、過大入力を解析前に拒否する。
    require(type(raw) is bytes and 0 < len(raw) <= 65536, "PUBLIC_APPROVAL_BYTES")
    value = cr.parse_json(raw)
    cr.fields(value, {name for name, _ in PUBLIC_APPROVAL_VALUES}, "PUBLIC_APPROVAL_FIELDS")
    # bool-as-intを含む型の別名と値の差を、全13fieldで拒否する。
    for name, expected in PUBLIC_APPROVAL_VALUES:
        require(type(value[name]) is type(expected) and value[name] == expected, "PUBLIC_APPROVAL_VALUE")
    return PublicPublisherTarget(raw, sha(raw))


# 固定保護位置と初回の原byteをprocess内へ固定し、承認recordを生成しない。
_APPROVED_PUBLIC_PUBLISHER: tuple[Path, PublicPublisherTarget] | None = None


def approved_public_publisher(expected_sha256: str) -> PublicPublisherTarget:
    """固定recordをACL/原hash/13fieldで検証し、所有する原byteを返す。authorityは発行しない。"""
    global _APPROVED_PUBLIC_PUBLISHER
    require(type(expected_sha256) is str and re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None,
            "PUBLIC_APPROVAL_PIN")
    root = protected_root()
    path = root / "control/approved-public-publisher.json"
    require(path.exists(), "PUBLIC_APPROVAL_REQUIRED")
    protected_path(path, root=root)
    raw = read(path, 65536)
    require(sha(raw) == expected_sha256, "PUBLIC_APPROVAL_PIN")
    target = public_publisher_approval(raw)
    binding = (path, target)
    require(_APPROVED_PUBLIC_PUBLISHER is None or binding == _APPROVED_PUBLIC_PUBLISHER,
            "PUBLIC_APPROVAL_CHANGED")
    _APPROVED_PUBLIC_PUBLISHER = binding
    return target


def validate_public_runtime(config: dict, scope: dict, *, historical_version: Path | None = None) -> None:
    """現在実行byteまたは保存された旧version byteを別の役割で照合し、旧codeは実行しない。"""
    root = protected_root()
    require_config_workspace(config)
    for name, digest in (("manifestFile", "manifestSha256"), ("scopeFile", "scopeSha256"),
                         ("publicKeyFile", "fingerprint")):
        path = normal_path(config[name])
        require(root in path.parents and type(config[digest]) is str and sha(read(path)) == config[digest],
                "PUBLIC_RUNTIME_PIN")
        protected_path(path, root=root)
    require(config["manifestSha256"] == MANIFEST_SHA256 and len(read(Path(config["publicKeyFile"]), 411)) == 411,
            "PUBLIC_RUNTIME_PIN")
    validate_v2_code(config, version=historical_version)
    python, gh = normal_path(config["pythonExe"]), normal_path(config["ghExe"])
    require(python.parent == root / "runtime" and python.name.lower() in {"python.exe", "pythonw.exe"} and
            gh == Path("C:/Program Files/GitHub CLI/gh.exe"), "PUBLIC_RUNTIME_LOCATION")
    protected_path(python)
    protected_path(gh)
    protected_tree(root / "runtime")
    operation_root(Path(config["outputRoot"]))
    protected_tree(Path(config["outputRoot"]))
    projection._validate_distribution_scope(scope)
    require(scope == cr.parse_json(read(Path(config["scopeFile"]), 65536)) and
        scope["collectorManifestSha256"] == config["manifestSha256"] and
        scope["publicFingerprint"] == config["fingerprint"] and config["purpose"] == ACQUISITION_PURPOSE and
        config["termsReviewMode"] == (projection.PINNED_STATIC_REVALIDATION_V2 if
            scope["schema"] == projection.METADATA_BOUND_SCOPE else projection.PINNED_STATIC_REVALIDATION_V1), "ACQUISITION_CONFIG_PURPOSE")
    acquisition_originals(config)
    validate_legacy_metadata(config)
    smoke, first = (parse_time(config[name]) for name in ("smokeLocal", "firstDailyLocal"))
    require(smoke.utcoffset() == first.utcoffset() and smoke.date() < first.date() and
            first - smoke <= timedelta(days=7), "SCHEDULE_WINDOW")


def historical_public_predecessor(config: dict) -> tuple[dict, dict, str, dict]:
    """原署名公開秒に結合した旧v2 metadataを有限profileで読む。現在loader/時計を変更しない。"""
    binding = config["historicalPredecessor"]
    cr.fields(binding, {"schema", "envelopeFile", "envelopeSha256"}, "PUBLIC_HISTORICAL_FIELDS")
    require(binding["schema"] == "dc-public-historical-predecessor-v1", "PUBLIC_HISTORICAL_PROFILE")
    envelope_path = normal_path(binding["envelopeFile"])
    require(envelope_path.parent == Path(config["outputRoot"]), "PUBLIC_HISTORY_LOCATION")
    protected_path(envelope_path)
    envelope = read(envelope_path, 98304)
    require(type(binding["envelopeSha256"]) is str and sha(envelope) == binding["envelopeSha256"],
            "PUBLIC_HISTORICAL_PIN")
    manifest, _ = unpack_envelope(envelope)
    publication = parse_time(manifest["publishedAtUtc"])
    require(publication <= utc(), "ACQUISITION_PUBLICATION_TIME")
    root, chain = protected_root(), []
    path, expected = Path(config["predecessorConfigFile"]), config["predecessorConfigSha256"]
    seen = set()
    # 採用済みbase→repair→preSign→verifiedUnsignedの最大四v2だけを逆向きに読む。
    for depth in range(4):
        path = normal_path(str(path))
        require(path not in seen and root / "control" in path.parents and path.name == "config.json",
                "PUBLIC_HISTORICAL_CHAIN")
        seen.add(path)
        protected_path(path)
        raw = read(path, 65536)
        require(type(expected) is str and sha(raw) == expected, "PUBLIC_HISTORICAL_PIN")
        old = cr.parse_json(raw)
        fields = V2_CONFIG_FIELDS | ({"codeRepair"} if "codeRepair" in old else set()) | (
            {"preSignContinuation"} if "preSignContinuation" in old else set())
        cr.fields(old, fields, "PUBLIC_HISTORICAL_FIELDS")
        require(old["schema"] == "dc-private-daily-index-config-v2" and raw == canonical(old),
                "PUBLIC_HISTORICAL_PROFILE")
        scope = cr.parse_json(read(Path(old["scopeFile"]), 65536))
        version = root / "scripts" / Path(old["collectorExe"]).parent.name
        validate_public_runtime(old, scope, historical_version=version)
        retained = {}
        # 原参照fileは全SHAを検査する。旧prepared条件を現在の実行許可として再現しない。
        for name in ("codeRepair", "preSignContinuation"):
            if name not in old:
                continue
            item = old[name]
            expected_fields = CODE_REPAIR_FIELDS if name == "codeRepair" else (
                VERIFIED_UNSIGNED_FIELDS if item.get("schema") == VERIFIED_UNSIGNED_SCHEMA else PRESIGN_FIELDS)
            cr.fields(item, expected_fields, "PUBLIC_HISTORICAL_FIELDS")
            require(item["schema"] == ("dc-daily-code-only-repair-v1" if name == "codeRepair" else
                VERIFIED_UNSIGNED_SCHEMA if expected_fields == VERIFIED_UNSIGNED_FIELDS else
                "dc-daily-presign-continuation-v1"), "PUBLIC_HISTORICAL_PROFILE")
            require(type(item["priorNativeCalls"]) is int and 1 <= item["priorNativeCalls"] <= 93 and
                type(item["preparationNativeCalls"]) is int and item["preparationNativeCalls"] == 2 and
                all(type(item[field]) in {int, float} and 0 <= item[field] < MAX_SECONDS for field in
                    ("priorElapsedSeconds", "preparationElapsedSeconds")) and
                item["priorElapsedSeconds"] + item["preparationElapsedSeconds"] < MAX_SECONDS,
                "PUBLIC_HISTORY_CARRY")
            for field in sorted(item):
                if not field.endswith("File"):
                    continue
                artifact = normal_path(item[field])
                require(root in artifact.parents, "PUBLIC_HISTORY_LOCATION")
                protected_path(artifact)
                artifact_raw = read(artifact, 1048576)
                require(sha(artifact_raw) == item[field[:-4] + "Sha256"], "PUBLIC_HISTORICAL_PIN")
                retained[field[:-4]] = artifact_raw
            if name == "codeRepair":
                receipt = cr.parse_json(retained["receipt"])
                projection._validated_daily_generation(receipt, publication)
                require(receipt["generation"] == manifest["generation"] and
                    receipt["manifestSha256"] == old["manifestSha256"], "PUBLIC_HISTORICAL_RECEIPT")
            else:
                receipt_path = Path(old["codeRepair"]["receiptFile"])
                stem = "acquisition-" + receipt_path.stem
                for field in ("body", "release", "inspection", "script"):
                    if field + "Sha256" not in item:
                        continue
                    artifact = receipt_path.parent / (stem + (".body" if field == "body" else "." + field + ".json"))
                    protected_path(artifact)
                    require(sha(read(artifact, 1048576)) == item[field + "Sha256"], "PUBLIC_HISTORICAL_PIN")
        chain.append((old, scope, expected, retained))
        if "preSignContinuation" in old:
            parent = old["preSignContinuation"]
        elif "codeRepair" in old:
            parent = old["codeRepair"]
        else:
            break
        path, expected = Path(parent["configFile"]), parent["configSha256"]
    require(chain and "codeRepair" not in chain[-1][0] and "preSignContinuation" not in chain[-1][0],
            "PUBLIC_HISTORICAL_CHAIN")
    mutable = {"scopeFile"} | PUBLIC_RUNTIME_FIELDS
    # 逆鎖ごとの不変意味と既存profileの遷移だけを要求し、任意chain/fallbackを許可しない。
    for index, (old, _, _, _) in enumerate(chain[:-1]):
        parent = chain[index + 1][0]
        require(all(old[name] == parent[name] for name in V2_CONFIG_FIELDS - mutable),
                "PUBLIC_HISTORICAL_SEMANTICS")
        if "preSignContinuation" in old:
            item = old["preSignContinuation"]
            require(old["codeRepair"] == parent.get("codeRepair"), "PUBLIC_HISTORICAL_SEMANTICS")
            if item["schema"] == VERIFIED_UNSIGNED_SCHEMA:
                require(type(parent.get("preSignContinuation")) is dict and
                    parent["preSignContinuation"]["schema"] == "dc-daily-presign-continuation-v1",
                    "PUBLIC_HISTORICAL_PROFILE")
                validate_verified_unsigned_carry(item, parent["preSignContinuation"],
                    chain[index][3]["budgetWitness"])
            else:
                require("codeRepair" in parent and "preSignContinuation" not in parent,
                        "PUBLIC_HISTORICAL_PROFILE")
        else:
            require("codeRepair" not in parent, "PUBLIC_HISTORICAL_PROFILE")
    old, scope, digest, _ = chain[0]
    carry = old.get("preSignContinuation", old.get("codeRepair"))
    retained_carry = {"calls": carry["priorNativeCalls"] + carry["preparationNativeCalls"],
        "seconds": carry["priorElapsedSeconds"] + carry["preparationElapsedSeconds"]} if carry else {
        "calls": 0, "seconds": 0}
    return old, scope, digest, {"chain": chain, "publication": publication, "carry": retained_carry}


def validate_public_config(config: dict) -> tuple[dict, PublicPublisherTarget]:
    """v3を通常v2または明示した歴史専用metadataへ結合する。新operation許可は返さない。"""
    require(type(config) is dict, "PUBLIC_CONFIG_FIELDS")
    fields = V2_CONFIG_FIELDS | PUBLIC_CONFIG_FIELDS | ({"codeRepair"} if "codeRepair" in config else set()) | (
        {"preSignContinuation"} if "preSignContinuation" in config else set()) | (
        {"historicalPredecessor"} if "historicalPredecessor" in config else set())
    cr.fields(config, fields, "PUBLIC_CONFIG_FIELDS")
    require(config["schema"] == PUBLIC_CONFIG_SCHEMA and config["purpose"] == ACQUISITION_PURPOSE,
            "PUBLIC_CONFIG_PURPOSE")
    require(type(config["predecessorConfigSha256"]) is str and
            re.fullmatch(r"[0-9a-f]{64}", config["predecessorConfigSha256"]) is not None,
            "PUBLIC_PREDECESSOR_PIN")
    path = normal_path(config["predecessorConfigFile"])
    root = protected_root()
    require(root / "control" in path.parents and path.name == "config.json", "PUBLIC_PREDECESSOR_LOCATION")
    protected_path(path, root=root)
    raw = read(path, 65536)
    require(sha(raw) == config["predecessorConfigSha256"], "PUBLIC_PREDECESSOR_PIN")
    # v3 chainやv1を解析直後に拒否し、自己参照と別loader条件を導入しない。
    require(cr.parse_json(raw).get("schema") == "dc-private-daily-index-config-v2",
            "PUBLIC_PREDECESSOR_SCHEMA")
    historical = "historicalPredecessor" in config
    if historical:
        old, scope, digest, _ = historical_public_predecessor(config)
        validate_public_runtime(config, scope)
    else:
        old, scope, digest = load_config(path)
    require(digest == config["predecessorConfigSha256"], "PUBLIC_PREDECESSOR_PIN")
    excluded = PUBLIC_CONFIG_FIELDS | ({"historicalPredecessor"} | PUBLIC_RUNTIME_FIELDS if historical else set())
    inherited = {name: value for name, value in config.items() if name not in excluded}
    inherited["schema"] = "dc-private-daily-index-config-v2"
    # objectのkey順は意味に含めず、bool/intやint/floatの別名は一致へ丸めない。
    require(json.dumps(inherited, sort_keys=True, allow_nan=False) ==
            json.dumps({name: value for name, value in old.items() if name not in
                (PUBLIC_RUNTIME_FIELDS if historical else set())}, sort_keys=True, allow_nan=False),
            "PUBLIC_CONFIG_SEMANTICS")
    target = approved_public_publisher(config["publicPublisherApprovalSha256"])
    approval = cr.parse_json(target.approval_bytes)
    require(config["fingerprint"] == scope["publicFingerprint"] == approval["publicFingerprint"],
            "PUBLIC_CONFIG_FINGERPRINT")
    return scope, target


def public_history_carry(evidence: dict, *, generation: int, minimum: dict) -> dict:
    """pin済みの元実行summaryと主担当sealed receiptから旧会計を再導出する。値の定数補完はしない。"""
    names = {"summary", "terminal", "index", "seal", "review", "reviewIndex", "reviewSeal"}
    cr.fields(evidence, names, "PUBLIC_HISTORY_CARRY_EVIDENCE")
    values = {}
    for name, entry in evidence.items():
        cr.fields(entry, {"file", "sha256"}, "PUBLIC_HISTORY_CARRY_EVIDENCE")
        path = normal_path(entry["file"])
        require(protected_root() / "control" in path.parents, "PUBLIC_HISTORY_LOCATION")
        protected_path(path)
        raw = read(path, 1048576)
        require(type(entry["sha256"]) is str and sha(raw) == entry["sha256"], "PUBLIC_HISTORY_CARRY_PIN")
        values[name] = raw
    # sealは署名ではなく、明示保護contextがpinした元受入receiptの完全性の根拠である。
    for index_name, seal_name, payloads in (("index", "seal", ("summary", "terminal")),
                                           ("reviewIndex", "reviewSeal", ("review",))):
        index, seal = cr.parse_json(values[index_name]), cr.parse_json(values[seal_name])
        index_fields = {"files"}
        seal_fields = {"sealedUtc", "indexSha256", "indexBytes", "payloadCount", "payloadBytes"}
        # 保存された子executionと主担当reviewの二形だけを受理し、未知のsealへfallbackしない。
        if index_name == "index":
            index_fields |= {"stage", "effortActuallyUsed", "payloadCount", "payloadBytes", "recoveryOutcome",
                             "rootNext", "remoteReadbackPerformedOutsideHelperByChild"}
            seal_fields |= {"controllerExplicitReadBytes", "returnedAuditReadBytes", "roadmapReadBytes",
                "sealPayloadReadBytes", "sourceReadConservativeUpperBytes", "sourceReadQualification",
                "operationalHelperCalls", "outsideHelperGhCalls", "outsideHelperNativeVerificationCalls",
                "wholeGoalComplete"}
        cr.fields(index, index_fields, "PUBLIC_HISTORY_CARRY_SEAL")
        cr.fields(seal, seal_fields, "PUBLIC_HISTORY_CARRY_SEAL")
        sealed = datetime.fromisoformat(seal["sealedUtc"].replace("Z", "+00:00"))
        require(sha(values[index_name]) == seal["indexSha256"] and len(values[index_name]) == seal["indexBytes"] and
            type(index["files"]) is list and 0 < len(index["files"]) <= 256 and
            len(index["files"]) == seal["payloadCount"] and sealed.tzinfo is not None and sealed <= utc(),
            "PUBLIC_HISTORY_CARRY_SEAL")
        total = 0
        for entry in index["files"]:
            cr.fields(entry, {"path", "bytes", "sha256"}, "PUBLIC_HISTORY_CARRY_SEAL")
            require(type(entry["path"]) is str and type(entry["bytes"]) is int and 0 <= entry["bytes"] <= MAX_FILE and
                type(entry["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]) is not None,
                "PUBLIC_HISTORY_CARRY_SEAL")
            total += entry["bytes"]
        require(total == seal["payloadBytes"], "PUBLIC_HISTORY_CARRY_SEAL")
        for name in payloads:
            require(sum(entry["sha256"] == sha(values[name]) and entry["bytes"] == len(values[name])
                for entry in index["files"]) == 1, "PUBLIC_HISTORY_CARRY_SEAL")
    summary, terminal, review = (cr.parse_json(values[name]) for name in ("summary", "terminal", "review"))
    cr.fields(summary, {"utc", "effortActuallyUsed", "mainExitCode", "mainActualPid", "mainSameHandleTerminal",
        "directoryBirthUtc", "mainExitUtc", "directoryBirthToMainExitSeconds", "resultPath", "resultStatus",
        "newGhCalls", "newNativeCalls", "totalManagedCalls", "carryCalls", "carrySeconds", "outsideHelperGhCalls",
        "outsideHelperNativeVerificationCalls", "originalIndividualPidKernelCoverage", "nativeSignCalls",
        "appAnonymousConfirmation", "pnpCandidateCount", "supportIncrease", "wholeGoalComplete",
        "rootRemoteVerification", "reads", "conservativeReadUpperBytes"}, "PUBLIC_HISTORY_CARRY_PROFILE")
    cr.fields(terminal, {"pid", "sameHandleTerminal", "exitCode", "originalHandleValue", "creationTicks",
        "exitTicks", "creationUtc", "exitUtc", "requestedArgv", "requestedCwd", "optionalObservation",
        "elapsedSeconds", "waitTimeouts", "stdoutRaw", "stderrRaw", "stdoutBytes", "stderrBytes", "stdoutSha256",
        "stderrSha256", "directChildObservation", "qualification"}, "PUBLIC_HISTORY_CARRY_PROFILE")
    cr.fields(review, {"stage", "status", "checks", "readBytes", "privateIndexAccepted", "denominator",
        "generation", "commit", "private", "normalAppAnonymousVerified", "pnpCandidates", "supportIncrease",
        "rootGhCalls", "nativeCalls", "remoteWrites", "carryCalls", "carrySeconds", "rootGhElapsedSeconds",
        "expiresAtUtc", "utc"}, "PUBLIC_HISTORY_CARRY_PROFILE")
    require(review.get("stage") == "G13-I7r231h14r16ev" and review.get("status") == "PASS" and
        type(review.get("checks")) is list and review["checks"] and
        all(type(item) is dict and set(item) == {"name", "pass"} and item["pass"] is True for item in review["checks"]) and
        review.get("generation") == generation and summary.get("resultStatus") == "PUBLISHED" and
        summary.get("mainExitCode") == terminal.get("exitCode") == 0 and
        type(terminal.get("exitCode")) is int and summary.get("mainSameHandleTerminal") is True and
        terminal.get("sameHandleTerminal") is True and summary.get("mainActualPid") == terminal.get("pid") and
        summary.get("outsideHelperGhCalls") == summary.get("outsideHelperNativeVerificationCalls") == 0,
        "PUBLIC_HISTORY_CARRY_PROFILE")
    integers = (summary.get("carryCalls"), summary.get("newGhCalls"), summary.get("newNativeCalls"),
                summary.get("totalManagedCalls"), review.get("rootGhCalls"), review.get("nativeCalls"),
                review.get("carryCalls"))
    require(all(type(value) is int and 0 <= value <= 96 for value in integers) and
        summary["totalManagedCalls"] == summary["carryCalls"] + summary["newGhCalls"] + summary["newNativeCalls"] and
        review["carryCalls"] == summary["totalManagedCalls"] + review["rootGhCalls"] + review["nativeCalls"],
        "PUBLIC_HISTORY_CARRY_ACCOUNTING")
    times = (summary.get("carrySeconds"), summary.get("directoryBirthToMainExitSeconds"),
             terminal.get("elapsedSeconds"), review.get("rootGhElapsedSeconds"), review.get("carrySeconds"))
    require(all(type(value) in {int, float} and 0 <= value <= MAX_SECONDS for value in times) and
        summary["directoryBirthToMainExitSeconds"] >= terminal["elapsedSeconds"] and
        review["carrySeconds"] == summary["carrySeconds"] + summary["directoryBirthToMainExitSeconds"] +
            review["rootGhElapsedSeconds"] and summary["carryCalls"] >= minimum["calls"] and
        summary["carrySeconds"] >= minimum["seconds"], "PUBLIC_HISTORY_CARRY_ACCOUNTING")
    return {"calls": review["carryCalls"], "seconds": review["carrySeconds"]}


def public_history_record(config: dict, scope: dict, config_hash: str, history, *, operation_day=None) -> dict:
    """明示保護historyと全原byteを読む。native/収集/署名や承認fileの発行は行わない。"""
    require(type(history) is tuple and len(history) == 2 and isinstance(history[0], Path) and
            type(history[1]) is str and re.fullmatch(r"[0-9a-f]{64}", history[1]) is not None,
            "PUBLIC_HISTORY_CONTEXT")
    path = normal_path(str(history[0]))
    require(protected_root() / "control" in path.parents and path.name == "history.json",
            "PUBLIC_HISTORY_LOCATION")
    protected_path(path)
    raw = read(path, 65536)
    require(sha(raw) == history[1], "PUBLIC_HISTORY_PIN")
    record = cr.parse_json(raw)
    cr.fields(record, {"schema", "publicConfigFile", "publicConfigSha256", "predecessorConfigSha256",
                       "oldDay", "operationDay", "files", "inputs", "terminalPins", "retainedCarry", "carryEvidence"},
              "PUBLIC_HISTORY_FIELDS")
    require(record["schema"] == "dc-public-daily-history-v1" and raw == canonical(record),
            "PUBLIC_HISTORY_SCHEMA")
    config_path = normal_path(record["publicConfigFile"])
    require(config_path.parent == path.parent, "PUBLIC_HISTORY_LOCATION")
    loaded, loaded_scope, digest = load_config(config_path)
    require(digest == record["publicConfigSha256"] == config_hash and loaded == config and loaded_scope == scope and
            record["predecessorConfigSha256"] == config["predecessorConfigSha256"], "PUBLIC_HISTORY_CONFIG")
    historical = "historicalPredecessor" in config
    if historical:
        old, _, old_hash, historical_facts = historical_public_predecessor(config)
    else:
        old, _, old_hash = load_config(Path(config["predecessorConfigFile"]))
        historical_facts = {"carry": {"calls": 0, "seconds": 0}}
    require(old_hash == config["predecessorConfigSha256"], "PUBLIC_PREDECESSOR_PIN")
    # 現在の通常loaderが認証できない修復chainを、history名目の例外へ変えない。
    require(historical or ("codeRepair" not in old and "preSignContinuation" not in old),
            "PUBLIC_HISTORY_REPAIR_NOT_SUPPORTED")
    day = record["oldDay"]
    require(type(day) is str and re.fullmatch(r"[0-9]{8}", day) is not None and
            type(record["operationDay"]) is str and re.fullmatch(r"[0-9]{8}", record["operationDay"]) is not None,
            "PUBLIC_HISTORY_DAY")
    old_date = datetime.strptime(day, "%Y%m%d").date()
    new_date = datetime.strptime(record["operationDay"], "%Y%m%d").date()
    expected_day = (utc().astimezone(parse_time(config["firstDailyLocal"]).tzinfo).date()
                    if operation_day is None else datetime.strptime(operation_day, "%Y%m%d").date())
    require(old_date < new_date and new_date == expected_day,
            "PUBLIC_HISTORY_OPERATION_DAY")
    artifacts = public_evidence_artifacts(config, record, old, old_hash, historical_facts, historical=historical)
    return artifacts | {"raw": raw, "sha256": sha(raw), "record": record, "old": old}


def public_evidence_artifacts(config: dict, record: dict, old: dict, old_hash: str, historical_facts: dict,
                              *, historical=False, cycle=False) -> dict:
    """bootstrapと派生cycleの同じ九成果物・六raw・原署名/claim監査を一箇所で行う。"""
    day = record["operationDay"] if cycle else record["oldDay"]
    out = operation_root(Path(config["outputRoot"]))
    prefix = out / day
    names = {"start", "receipt", "claim", "rawManifest", "gzip", "envelope", "signingResult", "success", "terminal"}
    cr.fields(record["files"], names, "PUBLIC_HISTORY_FILES")
    values, paths = {}, {}
    # 保護pathと原SHAを先に全件確認し、shapeから新しい根拠を作らない。
    for name, entry in record["files"].items():
        cr.fields(entry, {"file", "sha256"}, "PUBLIC_HISTORY_FILES")
        item = normal_path(entry["file"])
        require(item.parent == out, "PUBLIC_HISTORY_LOCATION")
        protected_path(item)
        value = read(item, MAX_FILE if name == "gzip" else 1048576)
        require(type(entry["sha256"]) is str and sha(value) == entry["sha256"], "PUBLIC_HISTORY_ARTIFACT_PIN")
        values[name], paths[name] = value, item
    receipt = cr.parse_json(values["receipt"])
    manifest, manifest_raw = unpack_envelope(values["envelope"])
    publication = parse_time(manifest["publishedAtUtc"])
    require(publication <= utc() and manifest_raw == values["rawManifest"], "PUBLIC_HISTORY_MANIFEST")
    # 発行当時の監査だけを行い、期限経過を現在の取得許可へ変換しない。
    projection._validated_daily_generation(receipt, publication)
    generation = receipt["generation"]
    require(type(generation) is int and generation > old["legacyReservationFence"]["generation"] and
            receipt["day"] == day and paths["receipt"].name.startswith(day + ".collection-") and
            paths["receipt"].name.endswith(".json"), "PUBLIC_HISTORY_RECEIPT")
    expected_paths = {"start": Path(str(prefix) + (".acquisition.public-start.json" if cycle else ".acquisition.start.json")),
        "claim": out / f"issuance-v1-{generation:016d}.claim.json",
        "rawManifest": Path(str(prefix) + ".acquisition.manifest.raw.json"),
        "gzip": Path(str(prefix) + ".acquisition.index.json.gz"),
        "envelope": Path(str(prefix) + ".acquisition.manifest.json"),
        "success": Path(str(prefix) + ".acquisition.success.json")}
    require(all(paths[name] == item for name, item in expected_paths.items()), "PUBLIC_HISTORY_LOCATION")
    start = cr.parse_json(values["start"])
    if cycle:
        validate_public_cycle_start(start)
        require(start["configSha256"] == old_hash and start["day"] == day and
                start["contextRootSha256"] == record["contextRootSha256"] and
                start["previousEvidenceSha256"] == record["previousEvidenceSha256"] and
                sha(values["start"]) == record["budgetContextSha256"], "PUBLIC_CYCLE_START")
    elif "codeRepair" in old:
        require(paths["start"] == Path(old["codeRepair"]["startFile"]) and
            sha(values["start"]) == old["codeRepair"]["startSha256"] and start.get("day") == day,
            "PUBLIC_HISTORY_START")
    else:
        require(start == {"schema": "dc-daily-acquisition-start-v1", "purpose": ACQUISITION_PURPOSE,
            "configSha256": old_hash, "legacyConfigSha256": old["legacyMetadata"]["configSha256"],
            "legacyStartSha256": None, "day": day}, "PUBLIC_HISTORY_START")
    if not cycle:
        carried = public_history_carry(record["carryEvidence"], generation=generation, minimum=historical_facts["carry"])
        require(record["retainedCarry"] == carried and
                type(record["retainedCarry"]["calls"]) is int and
                type(record["retainedCarry"]["seconds"]) in {int, float}, "PUBLIC_HISTORY_CARRY")
    if historical:
        require(config["historicalPredecessor"]["envelopeSha256"] == sha(values["envelope"]) and
            Path(config["historicalPredecessor"]["envelopeFile"]) == paths["envelope"], "PUBLIC_HISTORICAL_PIN")
    cr.fields(record["inputs"], {"scope", "evidence", "release", "inspection", "review", "script"},
              "PUBLIC_HISTORY_INPUTS")
    inputs = {}
    stem = "acquisition-" + paths["receipt"].stem
    for name, entry in record["inputs"].items():
        cr.fields(entry, {"file", "sha256"}, "PUBLIC_HISTORY_INPUTS")
        item = normal_path(entry["file"])
        expected = (Path(old["scopeFile"]) if name == "scope" else paths["receipt"] if name == "evidence" else
                    out / (stem + "." + name + ".json"))
        require(item == expected, "PUBLIC_HISTORY_LOCATION")
        protected_path(item)
        value = read(item, 1048576)
        require(type(entry["sha256"]) is str and sha(value) == entry["sha256"], "PUBLIC_HISTORY_INPUT_PIN")
        inputs[name] = value
    pins = {name: sha(value) for name, value in inputs.items()}
    prepared = {"inputs": inputs, "inputPins": pins, "reservation": {
        "mode": "FRESH_INPUT", "generation": generation, "receiptSha256": sha(values["receipt"])}}
    require(values["claim"] == canonical(issuance_claim(old, prepared, manifest_raw, values["gzip"])),
            "PUBLIC_HISTORY_CLAIM")
    bundle = {"manifest.json": values["envelope"], "index.json.gz": values["gzip"]}
    require(acquisition_profile(old, bundle, out) == "distribution-acquisition", "SIGNING_PROFILE_UNKNOWN")
    audit_daily_distribution_acquisition_bundle(bundle, inputs, pins, generation=generation,
        published_at=publication, now=publication, terms_review_mode=old["termsReviewMode"])
    terminals = sorted(out.glob(day + ".terminal-*.json"))
    terminal_names = {item.name for item in terminals}
    require(0 < len(terminals) <= 64 and type(record["terminalPins"]) is dict and
            (set(record["terminalPins"]) <= terminal_names if cycle else
             set(record["terminalPins"]) == terminal_names), "PUBLIC_HISTORY_TERMINALS")
    results = []
    for item in terminals:
        value = read(item, 65536)
        result = cr.parse_json(value)
        if item.name in record["terminalPins"]:
            require(sha(value) == record["terminalPins"][item.name], "PUBLIC_HISTORY_TERMINAL_PIN")
        else:
            anonymous = result.get("publicAnonymousReadback")
            closed_anonymous = type(anonymous) is dict and anonymous.get("schema") == "dc-public-anonymous-readback-v1" and \
                anonymous.get("status") in {"PENDING", "UNKNOWN", "VERIFIED"} and result.get("status") == (
                    "PUBLISHED" if anonymous.get("status") == "VERIFIED" else "UNKNOWN")
            if result.get("status") == "UNKNOWN":
                require(closed_anonymous, "PUBLIC_CYCLE_EXTRA_TERMINAL")
                require(set(result) == set(public_anonymous_terminal(anonymous)) and
                    result == public_anonymous_terminal(anonymous), "PUBLIC_CYCLE_EXTRA_TERMINAL")
            require(cycle and (result.get("status") == "PUBLISHED" or closed_anonymous) and
                result.get("configSha256") == old_hash and
                result.get("generation") == generation and result.get("envelopeSha256") == sha(values["envelope"]) and
                result.get("commit") == record["publicationCommit"] and
                result.get("purpose") == ACQUISITION_PURPOSE and result.get("signingClaimSha256") == sha(values["claim"]) and
                result.get("publicOperationReadbackOnly") is True, "PUBLIC_CYCLE_EXTRA_TERMINAL")
        results.append(result)
    require(paths["signingResult"] in terminals and paths["terminal"] in terminals,
            "PUBLIC_HISTORY_TERMINALS")
    signed = cr.parse_json(values["signingResult"])
    cr.fields(signed, {"status", "reason", "purpose", "configSha256", "generation", "signingClaimSha256",
                      "signingOutcome", "envelopeSha256", "childExitCode", "nativeCurrentVerified"},
              "PUBLIC_HISTORY_SIGNING_RESULT")
    require(signed.get("signingOutcome") == "NATIVE_CURRENT_VERIFIED" and
            type(signed.get("childExitCode")) is int and signed["childExitCode"] == 0 and
            signed.get("nativeCurrentVerified") is True and signed.get("status") == "SIGNED_NOT_PUBLISHED",
            "PUBLIC_HISTORY_SIGNING_RESULT")
    for value in (signed, cr.parse_json(values["terminal"]), cr.parse_json(values["success"])):
        require(value.get("configSha256") == old_hash and value.get("purpose") == ACQUISITION_PURPOSE and
                value.get("generation") == generation and value.get("signingClaimSha256") == sha(values["claim"]) and
                value.get("envelopeSha256") == sha(values["envelope"]), "PUBLIC_HISTORY_RESULT_BINDING")
    require(all(cr.parse_json(values[name]).get("status") == "PUBLISHED" for name in ("terminal", "success")),
            "PUBLIC_HISTORY_PUBLICATION_UNRESOLVED")
    require(not any(value.get("generation") == generation and
            value.get("signingOutcome") == "NATIVE_OUTCOME_UNKNOWN" for value in results),
            "SIGNING_OUTCOME_UNKNOWN")
    for position, value in enumerate(results):
        if value.get("publicationOutcome") == "CAS_INTENT_UNKNOWN":
            require(value.get("configSha256") == old_hash and value.get("generation") == generation and
                value.get("envelopeSha256") == sha(values["envelope"]) and any(
                    item.get("status") == "PUBLISHED" and item.get("configSha256") == old_hash and
                    item.get("generation") == generation and item.get("envelopeSha256") == sha(values["envelope"])
                    for item in results[position + 1:]), "PUBLIC_HISTORY_PUBLICATION_UNRESOLVED")
    return {"prepared": prepared, "paths": paths, "values": values,
        "bundle": bundle, "receipt": receipt, "receiptPath": paths["receipt"], "receiptRaw": values["receipt"],
        "generation": generation, "publication": publication, "terminalResults": results,
        "terminalNames": [item.name for item in terminals]}


class PublicOperationBudget:
    """同じ日次開始recordに結合したchild予算を、失敗・process再開を越えて有限に保つ。"""

    def __init__(self, inner, prefix: Path, context_hash: str, *, attempt_started=None, cycle_profile=False,
                 read_only=False):
        """旧carryを減らさず、別観測の既存journalだけを厳密に読み戻す。"""
        require(not isinstance(inner, Budget) or inner.calls == 0, "PUBLIC_BUDGET_NOT_FRESH")
        self.inner, self.prefix, self.context_hash = inner, prefix, context_hash
        self.read_only = read_only
        self.cycle_profile, self.completed_cycle, self.last_summary = cycle_profile, None, None
        self.pending = False
        self.last_ordinal, self.last_result = None, None
        self.calls, self.spent, self.previous = 0, 0.0, context_hash
        # 有効contextのmetadata認証・lock待ちも、このattemptの単調時間へ一度だけ含める。
        self.started = time.monotonic() if attempt_started is None else attempt_started
        require(type(self.started) in {int, float} and self.started <= time.monotonic(), "PUBLIC_BUDGET_CLOCK")
        paths = sorted(prefix.parent.glob(prefix.name + ".public-budget-*.intent.json"))
        require(len(paths) <= 96, "PROCESS_COUNT")
        known = {context_hash: (0, 0.0)}
        for ordinal, path in enumerate(paths):
            require(path == self.path(ordinal, "intent"), "PUBLIC_BUDGET_JOURNAL")
            raw = read(path, 4096)
            value = cr.parse_json(raw)
            cr.fields(value, {"schema", "contextSha256", "ordinal", "previousSha256",
                              "elapsedSecondsBefore", "reservedSeconds"}, "PUBLIC_BUDGET_JOURNAL")
            before, reserved = value["elapsedSecondsBefore"], value["reservedSeconds"]
            require(raw == canonical(value) and value["schema"] == "dc-public-operation-child-intent-v1" and
                value["contextSha256"] == context_hash and type(value["ordinal"]) is int and
                value["ordinal"] == ordinal and value["previousSha256"] == self.previous and
                type(before) in {int, float} and type(reserved) in {int, float} and
                self.spent <= before < MAX_SECONDS and 0 < reserved <= MAX_SECONDS - before,
                "PUBLIC_BUDGET_JOURNAL")
            completed = self.path(ordinal, "complete")
            elapsed, previous = before + reserved, sha(raw)
            if completed.exists():
                completed_raw = read(completed, 4096)
                result = cr.parse_json(completed_raw)
                cr.fields(result, {"schema", "intentSha256", "elapsedSeconds"}, "PUBLIC_BUDGET_JOURNAL")
                require(completed_raw == canonical(result) and
                    result["schema"] == "dc-public-operation-child-complete-v1" and
                    result["intentSha256"] == sha(raw) and type(result["elapsedSeconds"]) in {int, float} and
                    before <= result["elapsedSeconds"] <= elapsed, "PUBLIC_BUDGET_JOURNAL")
                elapsed, previous = result["elapsedSeconds"], sha(completed_raw)
            else:
                self.pending = True
            self.calls, self.spent, self.previous = ordinal + 1, float(elapsed), previous
            known[previous] = (self.calls, self.spent)
        completed_paths = set(prefix.parent.glob(prefix.name + ".public-budget-*.complete.json"))
        require(completed_paths <= {self.path(i, "complete") for i in range(self.calls)}, "PUBLIC_BUDGET_JOURNAL")
        summaries = sorted(prefix.parent.glob(prefix.name + ".public-budget-summary-*.json"))
        require(len(summaries) < 32, "DAILY_ATTEMPT_COUNT")
        prior_calls, prior_seconds = 0, 0.0
        for ordinal, path in enumerate(summaries):
            require(path == Path(str(prefix) + f".public-budget-summary-{ordinal:02d}.json"),
                    "PUBLIC_BUDGET_JOURNAL")
            summary_raw = read(path, 4096)
            value = cr.parse_json(summary_raw)
            summary_fields = {"schema", "contextSha256", "calls", "elapsedSeconds", "lastEntrySha256"}
            cr.fields(value, summary_fields | ({"completedCycleSha256"} if cycle_profile else set()),
                      "PUBLIC_BUDGET_JOURNAL")
            entry = known.get(value["lastEntrySha256"])
            require(value["schema"] == ("dc-public-operation-budget-summary-v2" if cycle_profile else
                                       "dc-public-operation-budget-summary-v1") and
                value["contextSha256"] == context_hash and type(value["calls"]) is int and entry is not None and
                value["calls"] == entry[0] and prior_calls <= value["calls"] <= self.calls and
                type(value["elapsedSeconds"]) in {int, float} and
                max(prior_seconds, entry[1]) <= value["elapsedSeconds"] <= MAX_SECONDS,
                "PUBLIC_BUDGET_JOURNAL")
            prior_calls, prior_seconds = value["calls"], float(value["elapsedSeconds"])
            if cycle_profile:
                digest = value["completedCycleSha256"]
                require(summary_raw == canonical(value) and (digest is None or public_sha(digest)) and
                    (self.completed_cycle is None or digest == self.completed_cycle), "PUBLIC_BUDGET_JOURNAL")
                self.completed_cycle = digest
                self.last_summary = {"file": str(path), "sha256": sha(summary_raw), "value": value}
        self.spent = max(self.spent, prior_seconds)
        self.summary_count = len(summaries)
        self.known_entries = known
        if cycle_profile and summaries:
            require(self.last_summary["value"]["lastEntrySha256"] == self.previous and
                self.last_summary["value"]["calls"] == self.calls, "PUBLIC_BUDGET_JOURNAL")
        if not read_only:
            self.remaining(MAX_SECONDS)

    def path(self, ordinal: int, kind: str) -> Path:
        """contextではなく固定dayに結合したjournal名を返す。"""
        return Path(str(self.prefix) + f".public-budget-{ordinal:02d}.{kind}.json")

    def elapsed(self) -> float:
        """全current attemptの単調時間を既使用journal時間へ加算する。"""
        return self.spent + max(0.0, time.monotonic() - self.started)

    def remaining(self, maximum=600) -> float:
        """再開前後と内側Budget双方の残上限を超えない。"""
        value = min(float(maximum), MAX_SECONDS - self.elapsed(), self.inner.remaining(maximum))
        require(value > 0, "TOTAL_TIMEOUT")
        return value

    def run(self, argv, data=None, maximum=MAX_FILE, seconds=600):
        """作用前intentを必須とし、結果不明は予約時間全体を次回へ課金する。"""
        require(not self.read_only, "PUBLIC_LEDGER_READ_ONLY")
        require(self.calls < 96, "PROCESS_COUNT")
        before, reserved = self.elapsed(), self.remaining(seconds)
        intent = canonical({"schema": "dc-public-operation-child-intent-v1", "contextSha256": self.context_hash,
            "ordinal": self.calls, "previousSha256": self.previous, "elapsedSecondsBefore": before,
            "reservedSeconds": min(reserved, MAX_SECONDS - before)})
        ordinal = self.calls
        write_new(self.path(ordinal, "intent"), intent)
        self.calls += 1
        self.previous = sha(intent)
        self.last_ordinal, self.last_result = ordinal, None
        try:
            result = self.inner.run(argv, data, maximum=maximum, seconds=reserved)
        except BaseException:
            self.spent, self.started = before + reserved, time.monotonic()
            self.pending = True
            raise
        self.last_result = result
        elapsed = self.elapsed()
        require(before <= elapsed <= before + reserved, "TOTAL_TIMEOUT")
        completed = canonical({"schema": "dc-public-operation-child-complete-v1",
            "intentSha256": sha(intent), "elapsedSeconds": elapsed})
        write_new(self.path(ordinal, "complete"), completed)
        self.previous = sha(completed)
        self.known_entries[self.previous] = (self.calls, elapsed)
        return result

    def reserve_calls(self, count: int):
        """追加検査を省略せず、同操作に必要な静的上界を作用前に確保する。"""
        require(type(count) is int and self.calls + count <= 96, "PUBLIC_CYCLE_BUDGET_INSUFFICIENT")
        self.remaining(MAX_SECONDS)

    def save(self, *, completed_cycle=None):
        """正常・失敗とも現在attemptの外側処理時間を追加summaryへ保存する。"""
        require(not self.read_only, "PUBLIC_LEDGER_READ_ONLY")
        require(self.summary_count < 32, "DAILY_ATTEMPT_COUNT")
        elapsed = self.elapsed()
        exhausted = self.cycle_profile and elapsed >= MAX_SECONDS
        value = {
            "schema": "dc-public-operation-budget-summary-v2" if self.cycle_profile else
                      "dc-public-operation-budget-summary-v1", "contextSha256": self.context_hash,
            "calls": self.calls, "elapsedSeconds": min(float(MAX_SECONDS), elapsed),
            "lastEntrySha256": self.previous}
        if self.cycle_profile:
            require(completed_cycle is None or public_sha(completed_cycle), "PUBLIC_BUDGET_JOURNAL")
            value["completedCycleSha256"] = None if exhausted else completed_cycle
        write_new(Path(str(self.prefix) + f".public-budget-summary-{self.summary_count:02d}.json"), canonical(value))
        require(not exhausted, "TOTAL_TIMEOUT")


def public_sha(value) -> bool:
    """bool/非文字列をSHAとして受けず、小文字原SHAだけを認める。"""
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def public_jst_day(now=None) -> str:
    """nativeと同じ固定JST暦日を返し、UTC epochによるdue判定と分ける。"""
    return (utc() if now is None else now).astimezone(timezone(timedelta(hours=9))).strftime("%Y%m%d")


def public_schedule_pin(config: dict) -> str:
    """元七日日程を固定JSTへ制約し、日々変更しない三fieldのhashを返す。"""
    require(all(parse_time(config[name]).utcoffset() == timedelta(hours=9) for name in
                ("smokeLocal", "firstDailyLocal")), "PUBLIC_JST_SCHEDULE_REQUIRED")
    return sha(canonical({"smokeLocal": config["smokeLocal"], "firstDailyLocal": config["firstDailyLocal"], "days": 7}))


def public_context_record(config: dict, scope: dict, config_hash: str, context) -> dict:
    """明示pinされた固定rootを保護位置で再検査し、bootstrapを歴史専用として認証する。"""
    require(type(context) is tuple and len(context) == 2 and isinstance(context[0], Path) and
            public_sha(context[1]), "PUBLIC_CONTEXT_REQUIRED")
    path = normal_path(str(context[0]))
    require(path.name == "public-context.json" and protected_root() / "control" in path.parents,
            "PUBLIC_CONTEXT_LOCATION")
    protected_path(path)
    raw = read(path, 65536)
    require(sha(raw) == context[1], "PUBLIC_CONTEXT_PIN")
    record = cr.parse_json(raw)
    cr.fields(record, {"schema", "kind", "publicConfigFile", "publicConfigSha256", "bootstrapHistoryFile",
        "bootstrapHistorySha256", "publisherApprovalSha256", "dayPolicy", "scheduleSha256"}, "PUBLIC_CONTEXT_FIELDS")
    require(raw == canonical(record) and record["schema"] == "dc-public-daily-context-v1" and
        record["kind"] == "BOOTSTRAP_ANCHORED_PUBLIC_CYCLE" and record["dayPolicy"] == "JST_NATIVE_RUN_DAY_V1" and
        all(public_sha(record[name]) for name in ("publicConfigSha256", "bootstrapHistorySha256",
            "publisherApprovalSha256", "scheduleSha256")), "PUBLIC_CONTEXT_SCHEMA")
    config_path = normal_path(record["publicConfigFile"])
    history_path = normal_path(record["bootstrapHistoryFile"])
    require(config_path == path.parent / "config.json" and history_path == path.parent / "history.json",
            "PUBLIC_CONTEXT_LOCATION")
    loaded, loaded_scope, digest = load_config(config_path)
    require(config.get("schema") == PUBLIC_CONFIG_SCHEMA and loaded == config and loaded_scope == scope and
        digest == config_hash == record["publicConfigSha256"] and record["publisherApprovalSha256"] ==
        config["publicPublisherApprovalSha256"] and record["scheduleSha256"] == public_schedule_pin(config) and
        read(config_path, 65536) == canonical(config),
        "PUBLIC_CONTEXT_CONFIG")
    protected_path(history_path)
    history_raw = read(history_path, 65536)
    require(sha(history_raw) == record["bootstrapHistorySha256"], "PUBLIC_HISTORY_PIN")
    history = cr.parse_json(history_raw)
    first = parse_time(config["firstDailyLocal"])
    dates = {(first + timedelta(days=i)).strftime("%Y%m%d") for i in range(7)}
    require(history.get("operationDay") in dates, "PUBLIC_CONTEXT_SCHEDULE")
    authenticated = public_history_record(config, scope, config_hash,
        (history_path, record["bootstrapHistorySha256"]), operation_day=history["operationDay"])
    return {"raw": raw, "sha256": sha(raw), "record": record, "bootstrap": authenticated}


def public_terminal_pins(prefix: Path) -> dict:
    """元64件上限で全terminal原byteをsnapshotし、旧失敗を捨てない。"""
    paths = sorted(prefix.parent.glob(prefix.name + ".terminal-*.json"))
    require(len(paths) <= 64, "REPORT_ATTEMPT_LIMIT")
    return {path.name: sha(read(path, 65536)) for path in paths}


def validate_public_cycle_start(start: dict):
    """継続start-v2の十閉fieldと型を検証し、旧bridgeを昇格させない。"""
    cr.fields(start, {"schema", "configSha256", "contextRootSha256", "previousEvidenceSha256",
        "previousReceiptSha256", "previousBudgetSummarySha256", "previousTerminalPins", "oldGeneration",
        "day", "retainedCarry"}, "PUBLIC_CYCLE_START")
    require(start["schema"] == "dc-public-daily-cycle-start-v2" and all(public_sha(start[name]) for name in
        ("configSha256", "contextRootSha256", "previousEvidenceSha256", "previousReceiptSha256")) and
        (start["previousBudgetSummarySha256"] is None or public_sha(start["previousBudgetSummarySha256"])) and
        type(start["oldGeneration"]) is int and start["oldGeneration"] > 0 and type(start["day"]) is str and
        re.fullmatch(r"[0-9]{8}", start["day"]) is not None and type(start["previousTerminalPins"]) is dict and
        len(start["previousTerminalPins"]) <= 64 and all(type(name) is str and public_sha(value) for name, value in
            start["previousTerminalPins"].items()), "PUBLIC_CYCLE_START")
    require(datetime.strptime(start["day"], "%Y%m%d").strftime("%Y%m%d") == start["day"], "PUBLIC_CYCLE_START")
    cr.fields(start["retainedCarry"], {"calls", "seconds"}, "PUBLIC_HISTORY_CARRY")
    require(type(start["retainedCarry"]["calls"]) is int and 0 <= start["retainedCarry"]["calls"] <= 96 and
        type(start["retainedCarry"]["seconds"]) in {int, float} and
        0 <= start["retainedCarry"]["seconds"] <= MAX_SECONDS, "PUBLIC_HISTORY_CARRY")


def public_cycle_start(config_hash: str, root: dict, previous: dict, day: str) -> dict:
    """認証済み直前結果からのみ、日付と予算来歴を持つ固定startを導出する。"""
    return {"schema": "dc-public-daily-cycle-start-v2", "configSha256": config_hash,
        "contextRootSha256": root["sha256"], "previousEvidenceSha256": previous["sha256"],
        "previousReceiptSha256": sha(previous["receiptRaw"]),
        "previousBudgetSummarySha256": previous.get("summarySha256"),
        "previousTerminalPins": public_terminal_pins(previous["receiptPath"].parent / previous["receipt"]["day"]),
        "oldGeneration": previous["generation"], "day": day,
        "retainedCarry": root["bootstrap"]["record"]["retainedCarry"]}


def public_cycle_record(config: dict, config_hash: str, root: dict, previous: dict, path: Path) -> dict:
    """祖先cycleをpureな原byte/閉shape/receipt鎖と完成journalで認証する。managed呼出はしない。"""
    protected_path(path)
    try:
        raw = read(path, 1048576)
        record = cr.parse_json(raw)
    except (ValueError, UnicodeError) as error:
        raise ValueError("PUBLIC_CYCLE_EVIDENCE_INCOMPLETE") from error
    cr.fields(record, {"schema", "contextRootSha256", "publicConfigSha256", "operationDay",
        "previousEvidenceSha256", "files", "inputs", "terminalPins", "budgetContextSha256",
        "budgetLastEntrySha256", "nativeGeneration", "publicationCommit", "retainedBootstrapCarry"},
        "PUBLIC_CYCLE_EVIDENCE_INCOMPLETE")
    require(raw == canonical(record) and record["schema"] == "dc-public-daily-cycle-evidence-v1" and
        record["contextRootSha256"] == root["sha256"] and record["publicConfigSha256"] == config_hash and
        record["previousEvidenceSha256"] == previous["sha256"] and
        type(record["operationDay"]) is str and re.fullmatch(r"[0-9]{8}", record["operationDay"]) is not None and
        path.name == record["operationDay"] + ".acquisition.public-cycle.json" and
        record["retainedBootstrapCarry"] == root["bootstrap"]["record"]["retainedCarry"] and
        type(record["nativeGeneration"]) is int and public_sha(record["budgetContextSha256"]) and
        public_sha(record["budgetLastEntrySha256"]) and type(record["publicationCommit"]) is str and
        re.fullmatch(r"[0-9a-f]{40}", record["publicationCommit"]) is not None,
        "PUBLIC_CYCLE_EVIDENCE_INCOMPLETE")
    artifacts = public_evidence_artifacts(config, record, config, config_hash, {}, cycle=True)
    prefix = path.parent / record["operationDay"]
    require(artifacts["values"]["start"] == canonical(public_cycle_start(config_hash, root, previous, prefix.name)) and
        artifacts["generation"] == record["nativeGeneration"] > previous["generation"] and
        artifacts["receipt"]["previousReceiptSha256"] == sha(previous["receiptRaw"]) and
        all(cr.parse_json(artifacts["values"][name]).get("commit") == record["publicationCommit"] for name in
            ("success", "terminal")), "PUBLIC_CYCLE_EVIDENCE_INCOMPLETE")
    ledger = PublicOperationBudget(Budget(), prefix, record["budgetContextSha256"], cycle_profile=True, read_only=True)
    require(not ledger.pending and ledger.last_summary is not None and ledger.completed_cycle == sha(raw) and
        record["budgetLastEntrySha256"] in ledger.known_entries, "PUBLIC_BUDGET_JOURNAL")
    latest_anonymous = None
    for name, result in zip(artifacts["terminalNames"], artifacts["terminalResults"]):
        annotation = result.get("publicAnonymousReadback")
        if annotation is None:
            continue
        source_cycle = None if name in record["terminalPins"] else sha(raw)
        latest_anonymous = validate_public_anonymous(annotation, config, config_hash, artifacts["bundle"],
            sha(artifacts["values"]["claim"]), record["publicationCommit"], ledger, source_cycle=source_cycle)
    return artifacts | {"raw": raw, "sha256": sha(raw), "record": record,
        "summarySha256": ledger.last_summary["sha256"], "commit": record["publicationCommit"],
        "anonymousVerified": latest_anonymous is not None and latest_anonymous["status"] == "VERIFIED"}


def public_cycle_target(config: dict, config_hash: str, root: dict, directory: Path) -> tuple[dict, str, dict | None]:
    """元七日bucketだけを辿り、欠測日/分岐/未来/未解決操作を飛ばさない。"""
    first = parse_time(config["firstDailyLocal"])
    days = [(first + timedelta(days=i)).strftime("%Y%m%d") for i in range(7)]
    initial = root["bootstrap"]["record"]["operationDay"]
    today = public_jst_day()
    valid = {day + suffix for day in days for suffix in
             (".acquisition.public-cycle.json", ".acquisition.public-start.json")}
    actual = list(directory.glob("*.acquisition.public-cycle.json")) + list(directory.glob("*.acquisition.public-start.json"))
    require(len(actual) <= 14 and all(path.name in valid and initial <= path.name[:8] <= today for path in actual),
            "PUBLIC_CYCLE_CHAIN")
    journals = list(directory.glob("*.public-budget-*.json"))
    require(len(journals) <= 7 * (96 * 2 + 32) and all(path.name[:8] in days and
        Path(str(directory / path.name[:8]) + ".acquisition.public-start.json").exists() and
        path.name[:8] >= initial for path in journals), "PUBLIC_BUDGET_JOURNAL")
    previous, current = root["bootstrap"], None
    for day in days[days.index(initial):]:
        prefix = directory / day
        cycle = Path(str(prefix) + ".acquisition.public-cycle.json")
        start = Path(str(prefix) + ".acquisition.public-start.json")
        if day > today:
            break
        if cycle.exists():
            require(start.exists(), "PUBLIC_CYCLE_CHAIN")
            current = public_cycle_record(config, config_hash, root, previous, cycle)
            if day == today:
                return previous, day, current
            if (datetime.strptime(today, "%Y%m%d").date() - datetime.strptime(day, "%Y%m%d").date()).days == 1 and \
                    int(utc().timestamp()) < current["receipt"]["notBefore"] and utc() < \
                    first + timedelta(days=days.index(today)):
                require(not any(path.name[:8] > day for path in actual), "PUBLIC_CYCLE_CHAIN")
                return previous, day, current
            require(current["anonymousVerified"], "PUBLIC_PREDECESSOR_ANONYMOUS_REQUIRED")
            previous = current
            continue
        require(not any(path.name[:8] > day for path in actual), "PUBLIC_CYCLE_CHAIN")
        if day < today:
            require(start.exists() and Path(str(prefix) + ".acquisition.manifest.json").exists(),
                    "PUBLIC_UNRESOLVED_PREVIOUS_DAY")
        return previous, day, None
    raise ValueError("PUBLIC_CYCLE_CHAIN")


def public_resume_observation(prefix: Path) -> dict:
    """再開では原成功receiptを一つだけ読み、native収集を呼ばない。"""
    paths = sorted(prefix.parent.glob(prefix.name + ".collection-*.json"))
    require(0 < len(paths) <= 32, "PUBLIC_RESUME_READBACK_ONLY")
    values = [(path, read(path, 1048576)) for path in paths]
    values = [(path, raw) for path, raw in values if cr.parse_json(raw).get("outcome") in
              {"NEW_200", "REVALIDATED_304"}]
    require(len(values) == 1, "PUBLIC_RESUME_READBACK_ONLY")
    path, raw = values[0]
    return {"status": "OBSERVED", "path": path, "raw": raw, "sha256": sha(raw), "receipt": cr.parse_json(raw)}


def public_preflight_hold(prefix: Path, config_hash: str, budget: PublicOperationBudget, *, old_generation: int) -> bool:
    """原run前HOLDだけを同日同予算の再入場として認め、NO_NETWORK/部分処理を閉じる。"""
    require(not budget.pending, "PUBLIC_RESUME_READBACK_ONLY")
    paths = sorted(prefix.parent.glob(prefix.name + ".collection-*.json"))
    require(0 < len(paths) <= 32, "PUBLIC_RESUME_READBACK_ONLY")
    for path in paths:
        value = cr.parse_json(read(path, 1048576))
        require(value.get("outcome") == "HOLD" and all(type(value.get(name)) is int and value[name] == 0 for name in
            ("generation", "httpStatus", "lastAttemptAt", "error", "stateError")), "PUBLIC_RESUME_READBACK_ONLY")
    require(not any(prefix.parent.glob("acquisition-" + prefix.name + ".collection-*")) and
        not any(prefix.parent.glob(prefix.name + ".acquisition.*" + "manifest*")), "PUBLIC_RESUME_READBACK_ONLY")
    claims = list(prefix.parent.glob("issuance-v1-*.claim.json"))
    require(len(claims) <= 512, "PUBLIC_RESUME_READBACK_ONLY")
    for path in claims:
        value = cr.parse_json(read(path, 65536))
        require(value.get("configSha256") != config_hash or (type(value.get("generation")) is int and
            value["generation"] <= old_generation), "PUBLIC_RESUME_READBACK_ONLY")
    terminals = sorted(prefix.parent.glob(prefix.name + ".terminal-*.json"))
    require(terminals and all(cr.parse_json(read(path, 65536)).get("status") == "HOLD" and
        cr.parse_json(read(path, 65536)).get("configSha256") == config_hash for path in terminals),
        "PUBLIC_RESUME_READBACK_ONLY")
    require(public_jst_day() == prefix.name, "PUBLIC_UNRESOLVED_PREVIOUS_DAY")
    return True


def public_complete_cycle(config: dict, config_hash: str, root: dict, previous: dict, prefix: Path,
                           observed: dict, result: dict, terminal: Path, budget: PublicOperationBudget) -> str:
    """同lock内の原成功からcycleを一度CREATE_NEWし、summaryからの一方向pinを返す。"""
    generation = observed["receipt"]["generation"]
    terminals = sorted(prefix.parent.glob(prefix.name + ".terminal-*.json"))
    signed = [path for path in terminals if cr.parse_json(read(path, 65536)).get("signingOutcome") ==
              "NATIVE_CURRENT_VERIFIED"]
    require(len(signed) == 1 and result.get("status") == "PUBLISHED" and type(result.get("commit")) is str and
        re.fullmatch(r"[0-9a-f]{40}", result["commit"]) is not None, "PUBLIC_CYCLE_EVIDENCE_INCOMPLETE")
    validate_public_anonymous(result.get("publicAnonymousReadback"), config, config_hash,
        {"manifest.json": read(Path(str(prefix) + ".acquisition.manifest.json"), 98304),
         "index.json.gz": read(Path(str(prefix) + ".acquisition.index.json.gz"))},
        result.get("signingClaimSha256"), result["commit"], budget, require_verified=True)
    stem = str(prefix) + ".acquisition"
    files = {"start": Path(stem + ".public-start.json"), "receipt": observed["path"],
        "claim": prefix.parent / f"issuance-v1-{generation:016d}.claim.json",
        "rawManifest": Path(stem + ".manifest.raw.json"), "gzip": Path(stem + ".index.json.gz"),
        "envelope": Path(stem + ".manifest.json"), "signingResult": signed[0], "success": Path(stem + ".success.json"),
        "terminal": terminal}
    inputs = {"scope": Path(config["scopeFile"]), "evidence": observed["path"]}
    inputs.update({name: prefix.parent / ("acquisition-" + observed["path"].stem + "." + name + ".json") for name in
                   ("release", "inspection", "review", "script")})
    def pin(path):
        """既存保護artifactの原byteだけをpinする。"""
        protected_path(path)
        return {"file": str(path), "sha256": sha(read(path))}
    record = {"schema": "dc-public-daily-cycle-evidence-v1", "contextRootSha256": root["sha256"],
        "publicConfigSha256": config_hash, "operationDay": prefix.name,
        "previousEvidenceSha256": previous["sha256"], "files": {name: pin(path) for name, path in files.items()},
        "inputs": {name: pin(path) for name, path in inputs.items()}, "terminalPins": public_terminal_pins(prefix),
        "budgetContextSha256": budget.context_hash, "budgetLastEntrySha256": budget.previous,
        "nativeGeneration": generation, "publicationCommit": result["commit"],
        "retainedBootstrapCarry": root["bootstrap"]["record"]["retainedCarry"]}
    artifacts = public_evidence_artifacts(config, record, config, config_hash, {}, cycle=True)
    require(all(cr.parse_json(artifacts["values"][name]).get("commit") == result["commit"] for name in
                ("success", "terminal")), "PUBLIC_HISTORY_REMOTE_CURRENT")
    raw = canonical(record)
    require(len(raw) <= 1048576, "PUBLIC_CYCLE_EVIDENCE_INCOMPLETE")
    write_new(Path(stem + ".public-cycle.json"), raw)
    return sha(raw)


def run_public_cycle(config: dict, scope: dict, config_hash: str, context, directory: Path, inner_budget,
                     remote, *, attempt_started: float, root: dict) -> dict:
    """固定rootと七日鎖を同lockで認証し、共通取得・terminal・cycle・最終予算を順に保存する。"""
    require(read(context[0], 65536) == root["raw"], "PUBLIC_CONTEXT_PIN")
    previous, day, completed = public_cycle_target(config, config_hash, root, directory)
    prefix = directory / day
    start = canonical(public_cycle_start(config_hash, root, previous, day))
    start_path = Path(str(prefix) + ".acquisition.public-start.json")
    resumed = start_path.exists()
    if resumed:
        require(read(start_path, 65536) == start and any(directory.glob(day + ".public-budget-summary-*.json")),
                "PUBLIC_BUDGET_JOURNAL")
    else:
        require(public_jst_day() == day, "PUBLIC_OPERATION_DAY_CHANGED")
        require(not any(directory.glob(day + ".public-budget-*.json")) and
                not any(directory.glob(day + ".collection-*.json")) and not public_terminal_pins(prefix),
                "PUBLIC_BUDGET_JOURNAL")
        write_new(start_path, start)
    budget = PublicOperationBudget(inner_budget, prefix, sha(start), attempt_started=attempt_started, cycle_profile=True)
    if isinstance(inner_budget, Budget):
        inner_budget.directory = directory
    completed_hash = completed["sha256"] if completed is not None else None
    try:
        require(not budget.pending, "PUBLIC_RESUME_READBACK_ONLY")
        readback = resumed and Path(str(prefix) + ".acquisition.manifest.json").exists()
        if resumed and not readback:
            public_preflight_hold(prefix, config_hash, budget, old_generation=previous["generation"])
        budget.reserve_calls(18 if readback else 69)
        old_verify = acquisition_verifier(config, previous["prepared"], directory, budget,
            generation=previous["generation"], publication=previous["publication"])
        old_verify(previous["bundle"], historical=True)
        if not readback:
            require(public_jst_day() == day, "PUBLIC_OPERATION_DAY_CHANGED")
            verify_reservation(config, previous["receiptPath"], previous["receiptRaw"], budget, "LEGACY_FENCE")
            preflight = acquisition_publisher(config, remote or GitHub(config["ghExe"], budget), old_verify)
            preflight.identity()
            head, old_envelope, old_generation = preflight.current()
            prior_success = cr.parse_json(previous["values"]["success"])
            require(old_envelope == previous["bundle"]["manifest.json"] and old_generation == previous["generation"] and
                head == prior_success.get("commit"), "PUBLIC_HISTORY_REMOTE_CURRENT")
            budget.reserve_calls(57)
            require(public_jst_day() == day, "PUBLIC_OPERATION_DAY_CHANGED")
            observed = collect_daily_acquisition_receipt(config, prefix, budget)
        else:
            observed = public_resume_observation(prefix)
        if observed["status"] != "OBSERVED":
            if observed["status"] == "HOLD":
                require(all(type(observed["receipt"].get(name)) is int and observed["receipt"][name] == 0 for name in
                    ("generation", "httpStatus", "lastAttemptAt", "error", "stateError")) and
                    observed["receipt"]["notBefore"] == previous["receipt"]["notBefore"], "HOLD_NOT_PREFLIGHT")
            result = {"status": observed["status"], "newGeneration": False, "purpose": ACQUISITION_PURPOSE,
                      "configSha256": config_hash}
        else:
            receipt, old_receipt = observed["receipt"], previous["receipt"]
            projection._validated_daily_generation(receipt, utc())
            require(receipt["day"] == day and (readback or public_jst_day() == day), "PUBLIC_OPERATION_DAY_CHANGED")
            require(type(receipt["generation"]) is int and receipt["generation"] > previous["generation"] and
                receipt["previousReceiptSha256"] == sha(previous["receiptRaw"]) and
                receipt["lastAttemptAt"] >= old_receipt["notBefore"] and
                receipt["lastSuccessfulValidationAt"] > old_receipt["lastSuccessfulValidationAt"] and
                all(receipt[name] == old_receipt[name] for name in
                    ("manifestSha256", "contractSha256", "requestBindingSha256")), "PUBLIC_FRESH_RECEIPT_BINDING")
            if receipt["httpStatus"] == 304:
                require(all(receipt[name] == old_receipt[name] for name in
                    ("lastFetchedAt", "bodySha256", "bodyBytesBase64", "projectionSha256", "projectionBytesBase64", "records")),
                    "PUBLIC_FRESH_304_BINDING")
            verify_reservation(config, observed["path"], observed["raw"], budget, "FRESH_INPUT")
            fresh = PublicFreshContext(_PUBLIC_FRESH_AUTHORITY, config_hash, prefix, budget, observed, readback)
            result = run_acquisition(config, scope, config_hash, prefix, budget, remote, public_context=fresh)
            result.update(publicHistorySha256=previous["sha256"], retainedCarry=root["bootstrap"]["record"]["retainedCarry"],
                publicOperationReadbackOnly=readback)
        terminal = Path(str(prefix) + f".terminal-{time.time_ns()}.json")
        budget.remaining(MAX_SECONDS)
        saved_result = (public_anonymous_terminal(result["publicAnonymousReadback"]) if
            result["status"] == "UNKNOWN" and "publicAnonymousReadback" in result else result)
        write_new(terminal, canonical(saved_result))
        if result["status"] == "PUBLISHED" and completed_hash is None:
            completed_hash = public_complete_cycle(config, config_hash, root, previous, prefix, observed, result, terminal, budget)
        return result
    except Exception as error:
        code = str(error) if re.fullmatch(r"[A-Z_]+", str(error)) else "PIPELINE_EXCEPTION"
        write_new(Path(str(prefix) + f".terminal-{time.time_ns()}.json"), canonical({
            "status": "FAILED", "reason": code, "purpose": ACQUISITION_PURPOSE, "configSha256": config_hash,
            "signingOutcome": "UNKNOWN_NO_RE_SIGN"}))
        raise
    finally:
        budget.save(completed_cycle=completed_hash)


_PUBLIC_FRESH_AUTHORITY = object()


@dataclass(frozen=True)
class PublicFreshContext:
    """同じlock内で実認証した新receiptだけを共通取得処理へ借用する内部context。"""
    authority: object
    config_hash: str
    prefix: Path
    budget: object
    observed: dict
    readback_only: bool


def run_public_acquisition(config: dict, scope: dict, config_hash: str, history, directory: Path,
                           inner_budget, remote, *, attempt_started: float) -> dict:
    """原履歴→同state予約→新観測を同じlock/予算で認証し、既存取得orchestrationへ渡す。"""
    authenticated = public_history_record(config, scope, config_hash, history)
    record = authenticated["record"]
    prefix = directory / record["operationDay"]
    start_path = Path(str(prefix) + ".acquisition.public-start.json")
    start = canonical({"schema": "dc-public-daily-transition-start-v1", "configSha256": config_hash,
        "historySha256": authenticated["sha256"], "previousReceiptSha256": sha(authenticated["receiptRaw"]),
        "oldGeneration": authenticated["generation"], "day": record["operationDay"],
        "retainedCarry": record["retainedCarry"]})
    resumed = start_path.exists()
    require(int(utc().timestamp()) >= authenticated["receipt"]["notBefore"], "PUBLIC_HISTORY_BEFORE_DUE")
    keep_exact(start_path, start)
    # 完全署名束の再開で全journalが消失していれば、新しい0予算へ戻さない。
    if resumed:
        require(any(directory.glob(prefix.name + ".public-budget-*.intent.json")) and
            any(directory.glob(prefix.name + ".public-budget-summary-*.json")), "PUBLIC_BUDGET_JOURNAL")
    budget = PublicOperationBudget(inner_budget, prefix, sha(start), attempt_started=attempt_started)
    if isinstance(inner_budget, Budget):
        inner_budget.directory = directory
    try:
        require(not budget.pending, "PUBLIC_RESUME_READBACK_ONLY")
        old_verify = acquisition_verifier(config, authenticated["prepared"], directory, budget,
            generation=authenticated["generation"], publication=authenticated["publication"])
        old_verify(authenticated["bundle"], historical=True)
        if not resumed:
            # 旧headを現stateで確認してからだけ、正規dueの新しいnative観測を許可する。
            verify_reservation(config, authenticated["receiptPath"], authenticated["receiptRaw"], budget, "LEGACY_FENCE")
            preflight = acquisition_publisher(config, remote or GitHub(config["ghExe"], budget), old_verify)
            preflight.identity()
            _, old_envelope, old_generation = preflight.current()
            require(old_envelope == authenticated["bundle"]["manifest.json"] and
                    old_generation == authenticated["generation"], "PUBLIC_HISTORY_REMOTE_CURRENT")
        else:
            # 再開は完全署名束の読戻しだけ。取得途中の再実行や別日の予約への再利用をしない。
            require(Path(str(prefix) + ".acquisition.manifest.json").exists(), "PUBLIC_RESUME_READBACK_ONLY")
        observed = collect_daily_acquisition_receipt(config, prefix, budget) if not resumed else None
        if resumed:
            attempts = sorted(directory.glob(prefix.name + ".collection-*.json"))
            require(0 < len(attempts) <= 32, "PUBLIC_RESUME_READBACK_ONLY")
            matches = [(path, read(path, 1048576)) for path in attempts]
            matches = [(path, raw) for path, raw in matches if cr.parse_json(raw).get("outcome") in
                       {"NEW_200", "REVALIDATED_304"}]
            require(len(matches) == 1, "PUBLIC_RESUME_READBACK_ONLY")
            path, raw = matches[0]
            observed = {"status": "OBSERVED", "path": path, "raw": raw, "sha256": sha(raw),
                        "receipt": cr.parse_json(raw)}
        if observed["status"] != "OBSERVED":
            return {"status": observed["status"], "newGeneration": False,
                    "purpose": ACQUISITION_PURPOSE, "configSha256": config_hash}
        receipt = observed["receipt"]
        projection._validated_daily_generation(receipt, utc())
        old_receipt = authenticated["receipt"]
        require(type(receipt["generation"]) is int and receipt["generation"] > authenticated["generation"] and
            receipt["previousReceiptSha256"] == sha(authenticated["receiptRaw"]) and
            receipt["lastAttemptAt"] >= old_receipt["notBefore"] and
            receipt["lastSuccessfulValidationAt"] > old_receipt["lastSuccessfulValidationAt"] and
            receipt["day"] == record["operationDay"] and
            all(receipt[name] == old_receipt[name] for name in
                ("manifestSha256", "contractSha256", "requestBindingSha256")), "PUBLIC_FRESH_RECEIPT_BINDING")
        if receipt["httpStatus"] == 304:
            require(all(receipt[name] == old_receipt[name] for name in
                ("lastFetchedAt", "bodySha256", "bodyBytesBase64", "projectionSha256", "projectionBytesBase64",
                 "records")), "PUBLIC_FRESH_304_BINDING")
        verify_reservation(config, observed["path"], observed["raw"], budget, "FRESH_INPUT")
        context = PublicFreshContext(_PUBLIC_FRESH_AUTHORITY, config_hash, prefix, budget, observed, resumed)
        result = run_acquisition(config, scope, config_hash, prefix, budget, remote, public_context=context)
        result.update(publicHistorySha256=authenticated["sha256"], retainedCarry=record["retainedCarry"],
                      publicOperationReadbackOnly=resumed)
        return result
    finally:
        budget.save()


def acquisition_publisher(config: dict, remote, verify, *, before_cas=None, anonymous=None):
    """取得用途のconfigから既存Publisherを作る。v3は固定承認を再検査しPublic原byteを渡す。"""
    target = None
    # v1/v2のPrivate既定とcallback順序を保持する。
    if config.get("schema") == PUBLIC_CONFIG_SCHEMA:
        _, target = validate_public_config(config)
    return Publisher(remote, verify, purpose=ACQUISITION_PURPOSE, before_cas=before_cas,
                     public_target=target.approval_bytes if target is not None else None, anonymous=anonymous)


class Publisher:
    """二assetの再取得/検証後だけindex-only branchへ一度CASする。"""
    def __init__(self, remote, verify, *, purpose="METADATA_ONLY", before_cas=None,
                 public_target: bytes | None = None, anonymous=None):
        self.remote, self.verify = remote, verify
        self.purpose, self.before_cas = purpose, before_cas
        self.anonymous = anonymous
        self._public_target = None
        # 明示原byteだけを取得用途へ結合し、運用configや任意repo入力を開かない。
        if public_target is not None:
            require(purpose == ACQUISITION_PURPOSE, "PUBLIC_PUBLISHER_PURPOSE")
            self._public_target = public_publisher_approval(public_target)

    def identity(self) -> None:
        # 公開targetは毎回再検証し、mutableな外部recordを借用しない。
        if self._public_target is not None:
            require(self.purpose == ACQUISITION_PURPOSE, "PUBLIC_PUBLISHER_PURPOSE")
            target = public_publisher_approval(self._public_target.approval_bytes)
            require(target.approval_sha256 == self._public_target.approval_sha256, "PUBLIC_APPROVAL_VALUE")
            expected = cr.parse_json(target.approval_bytes)
            user = self.remote.api("GET", "user")
            repo = self.remote.api("GET", API)
            require(type(user) is dict and type(repo) is dict, "PUBLIC_IDENTITY")
            owner = repo.get("owner")
            require(type(owner) is dict and
                    type(user.get("id")) is int and user["id"] == expected["actorId"] and
                    user.get("login") == expected["actorLogin"] and
                    type(repo.get("id")) is int and repo["id"] == expected["repositoryId"] and
                    repo.get("node_id") == expected["repositoryNodeId"] and
                    repo.get("full_name") == expected["repository"] and
                    type(owner.get("id")) is int and owner["id"] == expected["ownerId"] and
                    owner.get("login") == expected["ownerLogin"] and
                    repo.get("private") is False and repo.get("visibility") == expected["visibility"],
                    "PUBLIC_IDENTITY")
            self.repository_id = expected["repositoryNodeId"]
            return
        user = self.remote.api("GET", "user")
        repo = self.remote.api("GET", API)
        require(user.get("login") == "EnterOgawa" and repo.get("full_name") == REPOSITORY and
                repo.get("private") is True and repo.get("visibility") == "private", "PRIVATE_IDENTITY")
        node_id = repo.get("node_id")
        require(type(node_id) is str and re.fullmatch(r"[A-Za-z0-9_+=/-]{1,256}", node_id) is not None,
                "REPOSITORY_NODE_ID")
        self.repository_id = node_id

    def _write(self, method, path, body, **kwargs):
        """Publicだけ各追加write前にidentityを再確認し、部分作用を自動回復しない。"""
        # 確認とwriteは原子的ではなく、renameの完全排他を保証しない。
        if self._public_target is not None:
            self.identity()
            # CAS引数はcallback等が変更した値でも承認済みnode以外を許可しない。
            if path == "graphql":
                require(body["variables"]["input"]["repositoryId"] == self.repository_id,
                        "PUBLIC_IDENTITY")
        return self.remote.api(method, path, body, **kwargs)

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
        # 公開済み索引は正式版/プレリリース双方を読み、分類を署名の信頼根拠へ流用しない。
        require(release.get("draft") is False and type(release.get("prerelease")) is bool and
                release.get("tag_name") == manifest["asset"]["tag"], "CURRENT_RELEASE")
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
        require(self._public_target is None or callable(self.anonymous), "PUBLIC_ANONYMOUS_TRANSPORT_REQUIRED")
        require(set(bundle) == ASSETS, "ASSET_ALLOWLIST")
        self.verify(bundle, historical=False)
        manifest, _ = unpack_envelope(bundle["manifest.json"])
        self.identity()
        head, previous, generation = self.current()
        if previous == bundle["manifest.json"]:
            if self.purpose == ACQUISITION_PURPOSE:
                self.verify(bundle, historical=False)
            return self._published(bundle, generation, head, manifest["asset"]["tag"], resumed=True)
        require(not readback_only, "CURRENT_CAS_OUTCOME_UNKNOWN")
        require(type(manifest["generation"]) is int and manifest["generation"] > generation, "REMOTE_GENERATION")
        tag = manifest["asset"]["tag"]
        try:
            release = self.release(tag)
        except Missing:
            release = self._write("POST", API + "/releases", {
                "tag_name": tag, "target_commitish": "main", "name": "DriverCrate " +
                    ("acquisition" if self.purpose == ACQUISITION_PURPOSE else "metadata") + " index " + str(manifest["generation"]),
                "body": ("Acquisition-descriptor public validation index." if self._public_target is not None else
                         "Acquisition-descriptor private validation index." if self.purpose == ACQUISITION_PURPOSE else
                         "Metadata-only private validation index.") + " No driver packages. DriverCrate metadata: Apache-2.0.",
                "draft": True, "prerelease": True, "make_latest": "false"})
        require(type(release.get("id")) is int and release["id"] > 0 and release.get("tag_name") == tag and
                release.get("prerelease") is True, "RELEASE_IDENTITY")
        identifier = release["id"]
        existing = self.release_bytes(release, complete=False)
        require(all(bundle[name] == raw for name, raw in existing.items()), "IMMUTABLE_ASSET_CONFLICT")
        for name in sorted(ASSETS - set(existing)):
            require(release.get("draft") is True, "PUBLISHED_ASSET_MISSING")
            self._write("POST", "https://uploads.github.com/" + API + f"/releases/{identifier}/assets?name=" + name,
                            bundle[name], content_type="application/gzip" if name.endswith(".gz") else "application/json")
        uploaded = self.remote.api("GET", API + f"/releases/{identifier}")
        readback = self.release_bytes(uploaded, complete=True)
        require(readback == bundle, "REMOTE_BYTE_MISMATCH")
        self.verify(readback, historical=False)
        if uploaded.get("draft") is True:
            self._write("PATCH", API + f"/releases/{identifier}", {
                "draft": False, "prerelease": True, "make_latest": "false"})
        published = self.remote.api("GET", API + f"/releases/{identifier}")
        require(published.get("draft") is False and published.get("prerelease") is True and
                published.get("tag_name") == tag, "RELEASE_NOT_PUBLISHED")
        self.identity()
        blob = self._write("POST", API + "/git/blobs", {
            "content": base64.b64encode(bundle["manifest.json"]).decode("ascii"), "encoding": "base64"})
        tree = self._write("POST", API + "/git/trees", {"tree": [{
            "path": "index/current.json", "mode": "100644", "type": "blob", "sha": blob["sha"]}]})
        commit = self._write("POST", API + "/git/commits", {
            "message": "Update " + ("acquisition" if self.purpose == ACQUISITION_PURPOSE else "metadata") +
                       " index generation " + str(manifest["generation"]),
            "tree": tree["sha"], "parents": [head] if head else []})
        # beforeOid is a true expected-head CAS, including branch nonexistence. Never force/retry.
        query = "mutation($input:UpdateRefsInput!){updateRefs(input:$input){clientMutationId}}"
        if self.before_cas is not None:
            self.before_cas()
        cas = self._write("POST", "graphql", {"query": query, "variables": {"input": {
            "repositoryId": self.repository_id, "refUpdates": [{"name": "refs/heads/driver-index",
                "beforeOid": head or "0" * 40, "afterOid": commit["sha"], "force": False}]}}})
        require(not cas.get("errors") and type(cas.get("data")) is dict and
                type(cas["data"].get("updateRefs")) is dict, "CURRENT_CAS_REJECTED_OR_UNKNOWN")
        confirmed = self.remote.api("GET", API + "/git/ref/heads/driver-index")
        require(confirmed["object"]["sha"] == commit["sha"], "CURRENT_CONFIRMATION_UNKNOWN")
        return self._published(bundle, manifest["generation"], commit["sha"], tag, resumed=False)

    def _published(self, bundle: dict, generation: int, commit: str, tag: str, *, resumed: bool) -> dict:
        """二つのPublic成功経路に同じ匿名確認を必須にし、元commitをUNKNOWNでも保持する。"""
        result = {"status": "PUBLISHED", "generation": generation, "commit": commit, "tag": tag, "resumed": resumed}
        if self._public_target is not None:
            observed = self.anonymous(bundle, commit, tag)
            require(type(observed) is PublicAnonymousObservation and observed.authority is _PUBLIC_ANONYMOUS_AUTHORITY and
                type(observed.value) is dict and observed.value.get("commit") == commit and
                observed.value.get("generation") == generation and observed.value.get("tag") == tag and
                observed.value.get("envelopeSha256") == sha(bundle["manifest.json"]) and
                observed.value.get("gzipSha256") == sha(bundle["index.json.gz"]) and
                observed.value.get("status") in {"VERIFIED", "UNKNOWN"}, "PUBLIC_ANONYMOUS_BINDING")
            result["publicAnonymousReadback"] = observed.value
            if observed.value["status"] != "VERIFIED":
                result.update(status="UNKNOWN", reason="PUBLIC_ANONYMOUS_CONFIRMATION_UNKNOWN")
        return result


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


def run_pipeline(config: dict, scope: dict, config_hash: str, *, budget=None, remote=None, public_history=None,
                 public_context=None, attempt_started=None) -> dict:
    """検証済みconfigと明示したPrivate/Public境界のもとで、一日分の索引処理を進める。

    呼出し側はload_configを通した入力を渡す。operation lockをwith終了まで保持し、
    実行済みreceiptと同一byteの中間物を残して再開する。HOLD/NO_NETWORKは公開せず返し、
    他の失敗は例外とする。署名・再取得検証後だけcurrentをCASし、途中のfileや
    remote変更は自動取消ししない。budget/remoteの注入はfake試験用の境界である。
    """
    # 未認証の履歴遷移をlock・Budget・start生成より前に閉じる。
    public = config.get("schema") == PUBLIC_CONFIG_SCHEMA
    require(not public or public_history is not None or public_context is not None, "PUBLIC_HISTORY_TRANSITION_REQUIRED")
    require(not (public_history is not None and public_context is not None), "PUBLIC_CONTEXT_REQUIRED")
    require(public or public_context is None, "PUBLIC_CONTEXT_REQUIRED")
    public_started = (time.monotonic() if attempt_started is None else attempt_started) if public else None
    root = public_context_record(config, scope, config_hash, public_context) if public_context is not None else None
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
        if root is not None:
            return run_public_cycle(config, scope, config_hash, public_context, directory, budget, remote,
                attempt_started=public_started, root=root)
        if public:
            return run_public_acquisition(config, scope, config_hash, public_history, directory, budget, remote,
                attempt_started=public_started)
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
    # Public専用の履歴認証とDisabled再bindが未接続の間は旧Task XMLを発行しない。
    require(config.get("schema") != PUBLIC_CONFIG_SCHEMA, "PUBLIC_HISTORY_TRANSITION_REQUIRED")
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
    # v3の原履歴を未認証の新operation結果として投影しない。
    require(config.get("schema") != PUBLIC_CONFIG_SCHEMA, "PUBLIC_HISTORY_TRANSITION_REQUIRED")
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


CANDIDATE_PUBLICATION_SCHEMA = "dc-distribution-candidate-publication-v1"
CANDIDATE_PUBLICATION_FIELDS = frozenset({"schema", "state", "purpose", "configSha256", "fingerprint", "keyId",
    "generation", "assetGeneration", "reservationFloor", "candidateHeadSha256", "candidateOutputs",
    "nativeReservation", "nativeInputsSha256", "publicHead", "publishedAtUtc", "expiresAtUtc", "outputs"})
CANDIDATE_OUTPUTS = frozenset({"index.json", "index.json.gz", "manifest.raw.json", "build-report.json", "provenance.json"})
CANDIDATE_PUBLICATION_OUTPUTS = frozenset({"index.json", "index.json.gz", "manifest.raw.json"})
PUBLICATION_MAX_GENERATION = 9007199254740991
HISTORY_FLOOR = "HISTORY_FLOOR"


def candidate_publication_now() -> datetime:
    """現在UTCが確認不能なら下限取得や署名へ進めず、固定診断で拒否する。"""
    now = utc()
    require(type(now) is datetime and now.tzinfo is not None and now.utcoffset() == timedelta(0) and
        0 < now.timestamp() < 4102444800, "CANDIDATE_TIME_UNKNOWN")
    return now


def candidate_publication_paths(directory: Path, generation: int) -> dict[str, Path]:
    """既存issuance世代と同じ名前空間の固定出力名だけを組み立てる。"""
    require(type(generation) is int and 0 < generation <= PUBLICATION_MAX_GENERATION, "CANDIDATE_GENERATION")
    prefix = directory / f"candidate-publication-{generation:016d}"
    return {name: Path(str(prefix) + "." + name) for name in
        (*sorted(CANDIDATE_PUBLICATION_OUTPUTS), "manifest.json", "ready.json", "signing-intent.json", "signing-result.json")}


def candidate_publication_runtime(config: dict, config_hash: str) -> None:
    """現在の保護runtimeの原byte pinを再確認し、鍵storeは開かない。"""
    require(config.get("schema") == PUBLIC_CONFIG_SCHEMA and config.get("purpose") == ACQUISITION_PURPOSE and
        public_sha(config_hash) and config.get("fingerprint") == projection.DISTRIBUTION_PUBLIC_FINGERPRINT,
        "CANDIDATE_PUBLICATION_CONFIG")
    for name, pin in (("signerExe", "signerSha256"), ("collectorExe", "collectorSha256"),
                      ("publicKeyFile", "fingerprint"), ("manifestFile", "manifestSha256")):
        path = normal_path(config[name])
        protected_path(path)
        require(public_sha(config[pin]) and sha(read(path)) == config[pin], "CANDIDATE_RUNTIME_PIN")
    require(Path(config["signerExe"]).name == "DriverCrateLocalIndexSigner.exe" and
        Path(config["collectorExe"]).name == "DriverCrateCollector.exe" and
        len(read(Path(config["publicKeyFile"]), 411)) == 411, "CANDIDATE_RUNTIME_KIND")


def candidate_publication_selection(head_path: Path | None, head_hash: str | None, native_inputs, *,
        diagnostic: str = "CANDIDATE_INPUT_SELECTION") -> None:
    """明示した一系統以上の完全なfile/hash対を、load/lock/外部作用前に検査する。"""
    require((head_path is None and head_hash is None) or
        (isinstance(head_path, Path) and public_sha(head_hash)), diagnostic)
    require(native_inputs is None or (type(native_inputs) is tuple and len(native_inputs) == 2 and
        isinstance(native_inputs[0], Path) and public_sha(native_inputs[1])), diagnostic)
    require(head_path is not None or native_inputs is not None, diagnostic)


def candidate_publication_input(head_path: Path | None, head_hash: str | None
        ) -> tuple[dict | None, dict[str, bytes] | None, Path | None]:
    """pinされた未署名headの閉出力を読む。私有観測や実行permitは構築しない。"""
    if head_path is None:
        require(head_hash is None, "CANDIDATE_INPUT_SELECTION")
        return None, None, None
    head_path = normal_path(str(head_path))
    protected_path(head_path)
    require(head_path.name == "candidate-head.json" and head_path.parent.name == "distribution" and
        public_sha(head_hash), "CANDIDATE_HEAD_LOCATION")
    raw = read(head_path, 1048576)
    require(sha(raw) == head_hash, "CANDIDATE_HEAD_PIN")
    head = cr.parse_json(raw)
    cr.fields(head, {"schema", "generation", "runId", "monitorIdentity", "inputHashes", "producerHashes",
        "packageManifestSha256", "seedManifestSha256", "includedCandidates", "outputs", "validationSha256",
        "signingGenerationFinalized"}, "CANDIDATE_HEAD_FIELDS")
    require(head["schema"] == "dc-collector-unsigned-candidate-head-v1" and
        type(head["generation"]) is int and 0 < head["generation"] < PUBLICATION_MAX_GENERATION and
        head["signingGenerationFinalized"] is False and type(head["runId"]) is str and
        re.fullmatch(r"run-[0-9a-f]{32}", head["runId"]) is not None, "CANDIDATE_HEAD_SCHEMA")
    cr.fields(head["outputs"], CANDIDATE_OUTPUTS, "CANDIDATE_HEAD_OUTPUT_SET")
    directory = head_path.parent / "runs" / head["runId"]
    protected_path(directory)
    require(read(directory / "build-commit.json", 1048576) == raw, "CANDIDATE_COMMIT_PIN")
    result = {}
    for name, digest in head["outputs"].items():
        require(public_sha(digest), "CANDIDATE_OUTPUT_PIN")
        result[name] = read(directory / name)
        require(sha(result[name]) == digest, "CANDIDATE_OUTPUT_PIN")
    validation_raw = read(directory / "unsigned-validation.json", 1048576)
    require(public_sha(head["validationSha256"]) and sha(validation_raw) == head["validationSha256"],
        "CANDIDATE_VALIDATION_PIN")
    validation = cr.parse_json(validation_raw)
    cr.fields(validation, {"schema", "runId", "outputs", "unsigned", "authenticated", "recordCount"},
        "CANDIDATE_VALIDATION_FIELDS")
    require(validation["schema"] == "dc-collector-unsigned-validation-v1" and
        validation["runId"] == head["runId"] and validation["outputs"] == head["outputs"] and
        validation["unsigned"] is True and validation["authenticated"] is False and
        type(validation["recordCount"]) is int and validation["recordCount"] > 0, "CANDIDATE_VALIDATION_BINDING")
    index = cr.parse_json(result["index.json"])
    cr.fields(index, {"schema", "assetGeneration", "sources", "records"}, "CANDIDATE_INDEX_FIELDS")
    require(index["schema"] == "driver-index-records-v2" and index["assetGeneration"] == head["generation"] and
        type(index["records"]) is list and len(index["records"]) == validation["recordCount"], "CANDIDATE_INDEX_BINDING")
    # 保存済み展開byteを再圧縮照合し、未認証GZipの無制限展開を行わない。
    require(candidate_publication_gzip(result["index.json"]) == result["index.json.gz"], "CANDIDATE_GZIP_PIN")
    for row in index["records"]:
        cr.fields(row, {"recordBytesBase64", "recordSha256"}, "CANDIDATE_RECORD_FIELDS")
        require(type(row["recordBytesBase64"]) is str and public_sha(row["recordSha256"]), "CANDIDATE_RECORD_PIN")
        body = base64.b64decode(row["recordBytesBase64"], validate=True)
        require(0 < len(body) <= 65536 and sha(body) == row["recordSha256"], "CANDIDATE_RECORD_PIN")
    return head, result, directory


def candidate_publication_gzip(raw: bytes) -> bytes:
    """collectorと同じmtime/OS固定のGZipを生成し、原record本文は解釈し直さない。"""
    packed = gzip.compress(raw, mtime=0)
    return packed[:9] + b"\xff" + packed[10:]


def candidate_publication_native_inputs(config: dict, selected, receipt_path: Path, receipt_hash: str,
        publication: datetime) -> dict[str, bytes] | None:
    """明示pinした六原fileを既存非I/O producerへ渡す。収集/内容検査やauthority発行はしない。"""
    if selected is None:
        return None
    require(type(selected) is tuple and len(selected) == 2 and isinstance(selected[0], Path) and
        public_sha(selected[1]), "CANDIDATE_NATIVE_INPUTS")
    path = normal_path(str(selected[0]))
    protected_path(path)
    raw = read(path, 65536)
    require(sha(raw) == selected[1], "CANDIDATE_NATIVE_INPUT_PIN")
    document = cr.parse_json(raw)
    cr.fields(document, {"schema", "inputs"}, "CANDIDATE_NATIVE_INPUT_FIELDS")
    require(document["schema"] == "dc-candidate-native-inputs-v1", "CANDIDATE_NATIVE_INPUT_SCHEMA")
    cr.fields(document["inputs"], {"scope", "evidence", "release", "inspection", "review", "script"},
        "CANDIDATE_NATIVE_INPUT_FIELDS")
    inputs = {}
    for name, pin in document["inputs"].items():
        cr.fields(pin, {"file", "sha256"}, "CANDIDATE_NATIVE_INPUT_FIELDS")
        require(public_sha(pin["sha256"]), "CANDIDATE_NATIVE_INPUT_PIN")
        source = normal_path(pin["file"])
        protected_path(source)
        inputs[name] = read(source, 65536 if name == "scope" else 1048576)
        require(sha(inputs[name]) == pin["sha256"], "CANDIDATE_NATIVE_INPUT_PIN")
    require(inputs["scope"] == read(Path(config["scopeFile"]), 65536) and
        sha(inputs["scope"]) == config["scopeSha256"] and
        inputs["evidence"] == read(normal_path(str(receipt_path)), 1048576) and
        sha(inputs["evidence"]) == receipt_hash, "CANDIDATE_NATIVE_CURRENT_INPUTS")
    documents = {name: cr.parse_json(body) for name, body in inputs.items()}
    expanded, packed, manifest, _ = projection.project_daily_distribution_acquisition(
        *(documents[name] for name in ("scope", "evidence", "release", "inspection", "review", "script")),
        publication, terms_review_mode=config["termsReviewMode"])
    unsigned = canonical({"schema": "driver-index-envelope-v1", "keyId": projection.DISTRIBUTION_KEY_ID,
        "manifestBytesBase64": base64.b64encode(manifest).decode("ascii"),
        "signatureBase64": base64.b64encode(bytes(384)).decode("ascii")})
    audit_daily_distribution_acquisition_bundle({"manifest.json": unsigned, "index.json.gz": packed},
        inputs, {name: sha(body) for name, body in inputs.items()}, generation=documents["evidence"]["generation"],
        published_at=publication, now=candidate_publication_now().replace(microsecond=0),
        terms_review_mode=config["termsReviewMode"])
    # 原投影recordは再serializeせず、GZip headerだけ共通決定形へそろえる。
    require(gzip.decompress(packed) == expanded, "CANDIDATE_NATIVE_PROJECTION")
    return {"index.json": expanded, "index.json.gz": packed, "manifest.raw.json": manifest}


def candidate_publication_merge(raw: dict[str, bytes] | None, native: dict[str, bytes] | None) -> dict[str, bytes]:
    """既存二producerの原wrapper/sourceを合成する。Public履歴や期限切れrecordを補完しない。"""
    require(raw is not None or native is not None, "CANDIDATE_INPUT_SELECTION")
    if raw is None:
        return native
    if native is None:
        return raw
    index = cr.parse_json(raw["index.json"])
    additional = cr.parse_json(native["index.json"])
    sources, identities, entries = {}, set(), []
    for origin in (index, additional):
        require(origin.get("schema") == "driver-index-records-v2", "CANDIDATE_SET_SCHEMA")
        for source in origin["sources"]:
            identity = source["sourceId"]
            require(identity not in sources or sources[identity] == source, "CANDIDATE_SET_SOURCE_CONFLICT")
            sources[identity] = source
        for row in origin["records"]:
            cr.fields(row, {"recordBytesBase64", "recordSha256"}, "CANDIDATE_RECORD_FIELDS")
            body = base64.b64decode(row["recordBytesBase64"], validate=True)
            require(0 < len(body) <= 65536 and sha(body) == row["recordSha256"], "CANDIDATE_RECORD_PIN")
            record = cr.parse_json(body)
            identity = (record["sourceId"], record["recordId"])
            require(identity not in identities and identity[0] in sources, "CANDIDATE_SET_RECORD_CONFLICT")
            identities.add(identity)
            entries.append(row)
    require(0 < len(entries) <= 32768 and 0 < len(sources) <= 4096, "CANDIDATE_SET_LIMIT")
    index.update(sources=list(sources.values()), records=entries)
    expanded = cr.json_bytes(index)
    require(len(expanded) <= MAX_FILE, "CANDIDATE_SET_LIMIT")
    packed = candidate_publication_gzip(expanded)
    manifest = cr.parse_json(raw["manifest.raw.json"])
    native_manifest = cr.parse_json(native["manifest.raw.json"])
    manifest.update(publishedAtUtc=max(manifest["publishedAtUtc"], native_manifest["publishedAtUtc"]),
        expiresAtUtc=min(manifest["expiresAtUtc"], native_manifest["expiresAtUtc"]))
    manifest["asset"].update(tag="index-v1-" + parse_time(manifest["publishedAtUtc"]).strftime("%Y%m%d") +
        "-" + sha(packed), sizeBytes=len(packed), sha256=sha(packed))
    manifest["quality"] = {"sourceCount": len(sources), "recordCount": len(entries), "metadataOnlyCount": 0,
        "contentInspectedCount": len(entries), "unconfirmedCount": 0}
    return dict(raw, **{"index.json": expanded, "index.json.gz": packed, "manifest.raw.json": cr.json_bytes(manifest)})


def candidate_publication_validity(raw: dict[str, bytes]) -> None:
    """実現在の原有効性を検査し、週次の運用目標で未失効の束を拒否しない。

    期限を延長せず、短いrecordを除外しない。署名/収集/公開を開始せず、既存束のbyteも変更しない。
    """
    checked_now = candidate_publication_now()
    manifest = cr.parse_json(raw["manifest.raw.json"])
    index = cr.parse_json(raw["index.json"])
    expiries = []
    for row in index["records"]:
        body = base64.b64decode(row["recordBytesBase64"], validate=True)
        require(sha(body) == row["recordSha256"], "CANDIDATE_RECORD_PIN")
        record = cr.parse_json(body)
        expiries.append(parse_time(record["acquisitionDescriptor"]["attestation"]["validUntilUtc"]))
    require(bool(expiries) and parse_time(manifest["expiresAtUtc"]) == min(expiries), "CANDIDATE_MINIMUM_EXPIRY")
    require(parse_time(manifest["publishedAtUtc"]) <= checked_now < min(expiries), "CANDIDATE_EXPIRED")


def candidate_publication_rebase(raw: dict[str, bytes], generation: int, publication: datetime) -> dict[str, bytes]:
    """headerだけを配布世代へそろえ、原record/base64/hash/sourceと各期限を保持する。"""
    index = cr.parse_json(raw["index.json"])
    manifest = cr.parse_json(raw["manifest.raw.json"])
    require(manifest.get("keyId") == projection.DISTRIBUTION_KEY_ID and
        manifest.get("generation") == manifest.get("assetGeneration") == index["assetGeneration"] and
        manifest.get("asset", {}).get("sha256") == sha(raw["index.json.gz"]) and
        manifest["asset"].get("sizeBytes") == len(raw["index.json.gz"]), "CANDIDATE_MANIFEST_BINDING")
    require(publication.tzinfo is not None and publication.microsecond == 0 and
        parse_time(manifest["publishedAtUtc"]) <= publication, "CANDIDATE_PUBLICATION_TIME")
    expiries = []
    for row in index["records"]:
        record = cr.parse_json(base64.b64decode(row["recordBytesBase64"], validate=True))
        attestation = record["acquisitionDescriptor"]["attestation"]
        checked = cr.timestamp(attestation["checkedAtUtc"]).replace(tzinfo=timezone.utc)
        expires = cr.timestamp(attestation["validUntilUtc"]).replace(tzinfo=timezone.utc)
        require(checked <= publication < expires, "CANDIDATE_ORIGINAL_EXPIRY")
        expiries.append(expires)
    require(bool(expiries) and parse_time(manifest["expiresAtUtc"]) == min(expiries), "CANDIDATE_MINIMUM_EXPIRY")
    index["assetGeneration"] = generation
    expanded = cr.json_bytes(index)
    packed = candidate_publication_gzip(expanded)
    manifest.update(generation=generation, assetGeneration=generation,
        publishedAtUtc=publication.strftime("%Y-%m-%dT%H:%M:%SZ"))
    manifest["asset"].update(tag=f"index-v1-{publication:%Y%m%d}-{sha(packed)}", sizeBytes=len(packed), sha256=sha(packed))
    return {"index.json": expanded, "index.json.gz": packed, "manifest.raw.json": cr.json_bytes(manifest)}


def candidate_publication_verify(config: dict, directory: Path, budget, bundle: dict[str, bytes], *,
                                 profile: str, historical: bool) -> None:
    """明示profileの既存native検証だけを使い、historyを現在の取得権限へ変換しない。"""
    require(profile in {"METADATA_ONLY", ACQUISITION_PURPOSE, HISTORY_FLOOR} and
        (historical or profile == ACQUISITION_PURPOSE) and set(bundle) == ASSETS, "CANDIDATE_VERIFY_PURPOSE")
    manifest, _ = unpack_envelope(bundle["manifest.json"])
    digest = sha(bundle["manifest.json"] + bundle["index.json.gz"])
    envelope_path, gzip_path = directory / ("candidate-verify-" + digest + ".manifest.json"), directory / (
        "candidate-verify-" + digest + ".index.json.gz")
    keep_exact(envelope_path, bundle["manifest.json"])
    keep_exact(gzip_path, bundle["index.json.gz"])
    mode = ("--distribution-verify-floor" if profile == HISTORY_FLOOR else
        "--distribution" + ("-acquisition" if profile == ACQUISITION_PURPOSE else "") + "-verify")
    argv = [config["signerExe"], mode + ("-history" if historical else ""), str(envelope_path), str(gzip_path),
        config["publicKeyFile"], config["fingerprint"]]
    if historical:
        publication = parse_time(manifest["publishedAtUtc"])
        require(publication <= candidate_publication_now(), "CANDIDATE_HISTORY_FUTURE")
        argv.append(str(int(publication.timestamp())))
    code, _, _ = budget.run(argv)
    require(type(code) is int and code == 0, "CANDIDATE_NATIVE_VERIFY")


def candidate_publication_current(config: dict, directory: Path, budget, remote, profile: str) -> dict:
    """Public identityと全原byteを認証し、正常不存在も初回世代0へ戻さない。"""
    def verify(bundle, *, historical):
        candidate_publication_verify(config, directory, budget, bundle, profile=profile, historical=historical)
    publisher = acquisition_publisher(config, remote or GitHub(config["ghExe"], budget), verify)
    publisher.identity()
    commit, envelope, generation = publisher.current()
    require(commit is not None and envelope is not None and type(generation) is int and
        0 < generation <= PUBLICATION_MAX_GENERATION, "CANDIDATE_PUBLIC_HEAD_UNKNOWN")
    manifest, _ = unpack_envelope(envelope)
    return {"commit": commit, "generation": generation, "envelopeSha256": sha(envelope),
        "gzipSha256": manifest["asset"]["sha256"], "rawManifestSha256": sha(unpack_envelope(envelope)[1]),
        "profile": profile}


def candidate_publication_reservation(config: dict, path: Path, digest: str, budget) -> dict:
    """現在namespaceの元予約receiptを保護native headへ照合し、旧client互換は提供しない。"""
    path = normal_path(str(path))
    protected_path(path)
    require(path.parent == Path(config["outputRoot"]) and public_sha(digest), "CANDIDATE_RESERVATION_LOCATION")
    raw = read(path, 1048576)
    require(sha(raw) == digest, "CANDIDATE_RESERVATION_PIN")
    return verify_reservation(config, path, raw, budget, "LEGACY_FENCE")


def validate_candidate_publication_claim(claim: dict) -> None:
    """不変prepare意図を閉schemaで検査する。署名成功や私有authorityは返さない。"""
    cr.fields(claim, CANDIDATE_PUBLICATION_FIELDS, "CANDIDATE_CLAIM_FIELDS")
    require(claim["schema"] == CANDIDATE_PUBLICATION_SCHEMA and claim["state"] == "PREPARED_UNSIGNED" and
        claim["purpose"] == ACQUISITION_PURPOSE and type(claim["generation"]) is int and
        type(claim["assetGeneration"]) is int and type(claim["reservationFloor"]) is int and
        0 < claim["generation"] == claim["assetGeneration"] <= PUBLICATION_MAX_GENERATION and
        0 < claim["reservationFloor"] == claim["generation"] - 1 and
        claim["fingerprint"] == projection.DISTRIBUTION_PUBLIC_FINGERPRINT and
        claim["keyId"] == projection.DISTRIBUTION_KEY_ID and public_sha(claim["configSha256"]), "CANDIDATE_CLAIM_SCHEMA")
    # 汎用未指定を原hash/出力の同時nullへ結び、native入力のない空発行を認めない。
    if claim["candidateHeadSha256"] is None:
        require(claim["candidateOutputs"] is None and public_sha(claim["nativeInputsSha256"]),
            "CANDIDATE_CLAIM_INPUTS")
    else:
        require(public_sha(claim["candidateHeadSha256"]), "CANDIDATE_CLAIM_INPUTS")
        cr.fields(claim["candidateOutputs"], CANDIDATE_OUTPUTS, "CANDIDATE_CLAIM_OUTPUTS")
        require(all(public_sha(value) for value in claim["candidateOutputs"].values()), "CANDIDATE_CLAIM_OUTPUTS")
    cr.fields(claim["outputs"], CANDIDATE_PUBLICATION_OUTPUTS, "CANDIDATE_CLAIM_OUTPUTS")
    require(all(public_sha(value) for value in claim["outputs"].values()), "CANDIDATE_CLAIM_OUTPUTS")
    reservation = cr.fields(claim["nativeReservation"], {"mode", "generation", "receiptSha256"}, "CANDIDATE_CLAIM_RESERVATION")
    head = cr.fields(claim["publicHead"], {"commit", "generation", "envelopeSha256", "gzipSha256",
        "rawManifestSha256", "profile"}, "CANDIDATE_CLAIM_HEAD")
    require(reservation["mode"] == "LEGACY_FENCE" and type(reservation["generation"]) is int and
        0 < reservation["generation"] <= claim["reservationFloor"] and public_sha(reservation["receiptSha256"]) and
        type(head["generation"]) is int and 0 < head["generation"] <= claim["reservationFloor"] and
        type(head["commit"]) is str and re.fullmatch(r"[0-9a-f]{40}", head["commit"]) is not None and
        all(public_sha(head[name]) for name in ("envelopeSha256", "gzipSha256", "rawManifestSha256")) and
        (claim["nativeInputsSha256"] is None or public_sha(claim["nativeInputsSha256"])) and
        head["profile"] in {"METADATA_ONLY", ACQUISITION_PURPOSE, HISTORY_FLOOR} and
        public_wire_time(claim["publishedAtUtc"]) and public_wire_time(claim["expiresAtUtc"]) and
        parse_time(claim["publishedAtUtc"]) < parse_time(claim["expiresAtUtc"]), "CANDIDATE_CLAIM_BINDING")


def candidate_publication_history(directory: Path, public_head: dict, reservation: dict) -> tuple[int, list[tuple[Path, dict]]]:
    """同じ既存公開rootの全予約を下限へ残し、壊れた履歴をfresh扱いしない。"""
    paths = sorted(directory.glob("issuance-*.claim.json"))
    require(len(paths) <= 4096, "CANDIDATE_HISTORY_LIMIT")
    maximum = max(public_head["generation"], reservation["generation"])
    generic = []
    generations = set()
    for path in paths:
        protected_path(path)
        raw = read(path, 65536)
        claim = cr.parse_json(raw)
        require(raw == canonical(claim), "CANDIDATE_HISTORY_CANONICAL")
        if claim.get("schema") == CANDIDATE_PUBLICATION_SCHEMA:
            validate_candidate_publication_claim(claim)
            raw_hash = claim["outputs"]["manifest.raw.json"]
            generic.append((path, claim))
        else:
            cr.fields(claim, CLAIM_FIELDS, "CANDIDATE_HISTORY_UNKNOWN")
            cr.fields(claim["inputPins"], {"scope", "evidence", "release", "inspection", "review", "script"},
                "CANDIDATE_HISTORY_UNKNOWN")
            cr.fields(claim["reservation"], {"mode", "generation", "receiptSha256"}, "CANDIDATE_HISTORY_UNKNOWN")
            cr.fields(claim["legacyReservationFence"], {"generation", "receiptSha256"}, "CANDIDATE_HISTORY_UNKNOWN")
            require(claim["schema"] == "dc-distribution-issuance-claim-v1" and claim["state"] == "SIGNING_INTENT" and
                claim["purpose"] == ACQUISITION_PURPOSE and type(claim["generation"]) is int and
                type(claim["assetGeneration"]) is int and 0 < claim["generation"] == claim["assetGeneration"] <=
                PUBLICATION_MAX_GENERATION and claim["fingerprint"] == projection.DISTRIBUTION_PUBLIC_FINGERPRINT and
                claim["keyId"] == projection.DISTRIBUTION_KEY_ID and all(public_sha(value) for value in
                claim["inputPins"].values()) and all(public_sha(claim[name]) for name in
                ("previousReceiptSha256", "rawManifestSha256", "gzipSha256", "scopeSha256", "legacyConfigSha256")) and
                claim["reservation"] == {"mode": "FRESH_INPUT", "generation": claim["generation"],
                    "receiptSha256": claim["inputPins"]["evidence"]} and claim["scopeSha256"] == claim["inputPins"]["scope"] and
                type(claim["legacyReservationFence"]["generation"]) is int and
                0 < claim["legacyReservationFence"]["generation"] < claim["generation"] and
                public_sha(claim["legacyReservationFence"]["receiptSha256"]) and
                public_wire_time(claim["publishedAtUtc"]) and public_wire_time(claim["expiresAtUtc"]) and
                parse_time(claim["publishedAtUtc"]) < parse_time(claim["expiresAtUtc"]) and
                claim["termsReviewMode"] in {projection.PINNED_STATIC_REVALIDATION_V1, projection.PINNED_STATIC_REVALIDATION_V2}, "CANDIDATE_HISTORY_UNKNOWN")
            raw_hash = claim["rawManifestSha256"]
        generation = claim["generation"]
        require(path.name == f"issuance-v1-{generation:016d}.claim.json" and generation not in generations,
            "CANDIDATE_HISTORY_NAME")
        require(generation != public_head["generation"] or raw_hash == public_head["rawManifestSha256"],
            "CANDIDATE_SAME_GENERATION_CONFLICT")
        generations.add(generation)
        maximum = max(maximum, generation)
    # claim消失後の署名出力/途中fileを新規rootへ読み替えない。
    for path in directory.glob("candidate-publication-*.*"):
        match = re.fullmatch(r"candidate-publication-([0-9]{16})\.(index\.json(?:\.gz)?|manifest(?:\.raw)?\.json|ready\.json|signing-intent\.json|signing-result\.json)", path.name)
        require(match is not None and int(match[1]) in generations, "CANDIDATE_ORPHAN_OUTPUT")
    return maximum, generic


def candidate_publication_unsigned(config: dict, paths: dict[str, Path], budget) -> None:
    """全recordを既存未署名共通codecへ渡し、認証済みreceiptは生成しない。"""
    code, _, _ = budget.run([config["signerExe"], "--validate-unsigned-index-candidate",
        str(paths["manifest.raw.json"]), str(paths["index.json.gz"])])
    require(type(code) is int and code == 0, "CANDIDATE_UNSIGNED_REJECTED")


def prepare_candidate_publication(config: dict, config_hash: str, head_path: Path | None, head_hash: str | None,
        receipt_path: Path, receipt_hash: str, *, head_profile: str, native_inputs=None,
        budget=None, remote=None, checkpoint=None) -> dict:
    """明示operator操作で世代を不変予約する。収集・鍵操作・署名・GitHub writeは行わない。"""
    candidate_publication_selection(head_path, head_hash, native_inputs)
    candidate_publication_now()
    require(head_profile in {"METADATA_ONLY", ACQUISITION_PURPOSE, HISTORY_FLOOR}, "CANDIDATE_VERIFY_PURPOSE")
    directory = operation_root(Path(config["outputRoot"]))
    protected_tree(directory)
    budget = budget or Budget()
    if isinstance(budget, Budget):
        budget.directory = directory
    with exclusive(directory / "pipeline.lock"):
        candidate_publication_runtime(config, config_hash)
        head, raw, source = candidate_publication_input(head_path, head_hash)
        if head is not None:
            candidate_publication_unsigned(config, {name: source / name for name in CANDIDATE_PUBLICATION_OUTPUTS}, budget)
        public_head = candidate_publication_current(config, directory, budget, remote, head_profile)
        reservation = candidate_publication_reservation(config, receipt_path, receipt_hash, budget)
        maximum, prior = candidate_publication_history(directory, public_head, reservation)
        matches = [(path, claim) for path, claim in prior if claim["configSha256"] == config_hash and
            claim["candidateHeadSha256"] == head_hash and claim["publicHead"] == public_head and
            claim["nativeReservation"] == reservation and
            claim["nativeInputsSha256"] == (native_inputs[1] if native_inputs else None)]
        require(len(matches) <= 1, "CANDIDATE_PREPARE_CONFLICT")
        if matches:
            claim_path, claim = matches[0]
            require(maximum == claim["generation"], "CANDIDATE_PREPARE_STALE")
        else:
            require(maximum < PUBLICATION_MAX_GENERATION, "CANDIDATE_GENERATION_OVERFLOW")
            publication = candidate_publication_now().replace(microsecond=0)
            selected = candidate_publication_merge(raw, candidate_publication_native_inputs(
                config, native_inputs, receipt_path, receipt_hash, publication))
            rebased = candidate_publication_rebase(selected, maximum + 1, publication)
            candidate_publication_validity(rebased)
            manifest = cr.parse_json(rebased["manifest.raw.json"])
            claim = {"schema": CANDIDATE_PUBLICATION_SCHEMA, "state": "PREPARED_UNSIGNED", "purpose": ACQUISITION_PURPOSE,
                "configSha256": config_hash, "fingerprint": config["fingerprint"], "keyId": projection.DISTRIBUTION_KEY_ID,
                "generation": maximum + 1, "assetGeneration": maximum + 1, "reservationFloor": maximum,
                "candidateHeadSha256": head_hash, "candidateOutputs": head["outputs"] if head is not None else None,
                "nativeReservation": reservation,
                "nativeInputsSha256": native_inputs[1] if native_inputs else None,
                "publicHead": public_head, "publishedAtUtc": manifest["publishedAtUtc"], "expiresAtUtc": manifest["expiresAtUtc"],
                "outputs": {name: sha(body) for name, body in rebased.items()}}
            validate_candidate_publication_claim(claim)
            claim_path = directory / f"issuance-v1-{claim['generation']:016d}.claim.json"
            write_new(claim_path, canonical(claim))
            require(read(claim_path, 65536) == canonical(claim), "CANDIDATE_CLAIM_READBACK")
        if checkpoint:
            checkpoint("CLAIM_RESERVED")
        require(parse_time(claim["publishedAtUtc"]) <= candidate_publication_now() < parse_time(claim["expiresAtUtc"]), "CANDIDATE_EXPIRED")
        selected = candidate_publication_merge(raw, candidate_publication_native_inputs(
            config, native_inputs, receipt_path, receipt_hash, parse_time(claim["publishedAtUtc"])))
        rebased = candidate_publication_rebase(selected, claim["generation"], parse_time(claim["publishedAtUtc"]))
        candidate_publication_validity(rebased)
        require(claim["candidateOutputs"] == (head["outputs"] if head is not None else None) and
            claim["outputs"] == {name: sha(body) for name, body in rebased.items()}, "CANDIDATE_PREPARE_CONFLICT")
        paths = candidate_publication_paths(directory, claim["generation"])
        for name, body in rebased.items():
            keep_exact(paths[name], body)
            require(read(paths[name]) == body, "CANDIDATE_OUTPUT_READBACK")
            if checkpoint:
                checkpoint(name)
        candidate_publication_unsigned(config, paths, budget)
        keep_exact(paths["ready.json"], canonical({"schema": "dc-candidate-publication-ready-v1",
            "claimSha256": sha(canonical(claim)), "outputs": claim["outputs"], "unsigned": True, "authenticated": False}))
        return {"status": "PREPARED_UNSIGNED", "generation": claim["generation"], "claimSha256": sha(canonical(claim)),
            "claimName": claim_path.name, "purpose": ACQUISITION_PURPOSE, "signingGenerationFinalized": True,
            "unsigned": True, "authenticated": False, "signed": False, "published": False}


def sign_candidate_publication(config: dict, config_hash: str, head_path: Path | None, head_hash: str | None,
        receipt_path: Path, receipt_hash: str, claim_path: Path, claim_hash: str, fingerprint: str, *,
        native_inputs=None, budget=None, remote=None, checkpoint=None) -> dict:
    """明示hash/pinの確定byteだけを既存native signerへ一回渡し、不確定な署名を再試行しない。"""
    candidate_publication_selection(head_path, head_hash, native_inputs)
    candidate_publication_now()
    require(fingerprint == config["fingerprint"] == projection.DISTRIBUTION_PUBLIC_FINGERPRINT and public_sha(claim_hash),
        "CANDIDATE_SIGN_FINGERPRINT")
    directory = operation_root(Path(config["outputRoot"]))
    protected_tree(directory)
    budget = budget or Budget()
    if isinstance(budget, Budget):
        budget.directory = directory
    with exclusive(directory / "pipeline.lock"):
        candidate_publication_runtime(config, config_hash)
        claim_path = normal_path(str(claim_path))
        require(claim_path.parent == directory, "CANDIDATE_CLAIM_LOCATION")
        claim_raw = read(claim_path, 65536)
        require(sha(claim_raw) == claim_hash, "CANDIDATE_CLAIM_PIN")
        claim = cr.parse_json(claim_raw)
        validate_candidate_publication_claim(claim)
        require(claim_raw == canonical(claim) and claim["configSha256"] == config_hash and
            claim["candidateHeadSha256"] == head_hash and claim["fingerprint"] == fingerprint,
            "CANDIDATE_SIGN_INPUTS")
        require(claim["nativeInputsSha256"] == (native_inputs[1] if native_inputs else None), "CANDIDATE_NATIVE_INPUT_PIN")
        head, raw, _ = candidate_publication_input(head_path, head_hash)
        current = candidate_publication_current(config, directory, budget, remote, claim["publicHead"]["profile"])
        reservation = candidate_publication_reservation(config, receipt_path, receipt_hash, budget)
        maximum, prior = candidate_publication_history(directory, current, reservation)
        require(current == claim["publicHead"] and reservation == claim["nativeReservation"] and
            maximum == claim["generation"] and any(path == claim_path and value == claim for path, value in prior),
            "CANDIDATE_SIGN_STALE")
        require(parse_time(claim["publishedAtUtc"]) <= candidate_publication_now() < parse_time(claim["expiresAtUtc"]), "CANDIDATE_EXPIRED")
        selected = candidate_publication_merge(raw, candidate_publication_native_inputs(
            config, native_inputs, receipt_path, receipt_hash, parse_time(claim["publishedAtUtc"])))
        rebased = candidate_publication_rebase(selected, claim["generation"], parse_time(claim["publishedAtUtc"]))
        paths = candidate_publication_paths(directory, claim["generation"])
        require((head["outputs"] if head is not None else None) == claim["candidateOutputs"] and claim["outputs"] ==
            {name: sha(body) for name, body in rebased.items()}, "CANDIDATE_SIGN_INPUTS")
        for name, body in rebased.items():
            require(read(paths[name]) == body, "CANDIDATE_SIGN_OUTPUT_PIN")
        require(read(paths["ready.json"], 65536) == canonical({"schema": "dc-candidate-publication-ready-v1",
            "claimSha256": claim_hash, "outputs": claim["outputs"], "unsigned": True, "authenticated": False}),
            "CANDIDATE_PREPARE_INCOMPLETE")
        candidate_publication_unsigned(config, paths, budget)
        intent = canonical({"schema": "dc-candidate-signing-intent-v1", "claimSha256": claim_hash,
            "fingerprint": fingerprint, "signerSha256": config["signerSha256"], "mode": "--distribution-acquisition-sign"})
        resumed = paths["signing-intent.json"].exists()
        previous_result = None
        if resumed:
            require(read(paths["signing-intent.json"], 65536) == intent and paths["manifest.json"].exists(),
                "CANDIDATE_SIGNING_OUTCOME_UNKNOWN")
            if paths["signing-result.json"].exists():
                previous_result = cr.parse_json(read(paths["signing-result.json"], 65536))
                cr.fields(previous_result, {"schema", "status", "claimSha256", "generation", "childExitCode", "envelopeSha256"},
                    "CANDIDATE_SIGNING_RESULT")
                require(previous_result["schema"] == "dc-candidate-signing-result-v1" and
                    previous_result["claimSha256"] == claim_hash and type(previous_result["generation"]) is int and
                    previous_result["generation"] == claim["generation"], "CANDIDATE_SIGNING_RESULT")
                status, code = previous_result["status"], previous_result["childExitCode"]
                require((status == "SIGNED_NOT_PUBLISHED" and type(code) is int and code == 0) or
                    (status == "SAVED_ENVELOPE_VERIFIED_ORIGINAL_EXIT_UNKNOWN" and code is None) or
                    (status == "UNKNOWN_NO_RE_SIGN" and (code is None or type(code) is int)), "CANDIDATE_SIGNING_RESULT")
                require((status == "UNKNOWN_NO_RE_SIGN" and previous_result["envelopeSha256"] is None) or
                    (status != "UNKNOWN_NO_RE_SIGN" and
                    sha(read(paths["manifest.json"], 98304)) == previous_result["envelopeSha256"]), "CANDIDATE_SIGNING_RESULT")
        else:
            require(not paths["signing-result.json"].exists() and not paths["manifest.json"].exists(),
                "CANDIDATE_SIGNING_ORPHAN")
            candidate_publication_runtime(config, config_hash)
            candidate_publication_validity(rebased)
            write_new(paths["signing-intent.json"], intent)
            require(read(paths["signing-intent.json"], 65536) == intent, "CANDIDATE_SIGNING_INTENT_READBACK")
            if checkpoint:
                checkpoint("SIGNING_INTENT")
            signing_code = None
            try:
                code, _, _ = budget.run([config["signerExe"], "--distribution-acquisition-sign",
                    str(paths["manifest.raw.json"]), str(paths["index.json.gz"]), str(paths["manifest.json"]), fingerprint])
                signing_code = code if type(code) is int else None
                require(type(code) is int and code == 0 and paths["manifest.json"].exists(), "CANDIDATE_SIGNING_OUTCOME_UNKNOWN")
                if checkpoint:
                    checkpoint("SIGNER_RETURNED")
            except Exception as failure:
                write_new(paths["signing-result.json"], canonical({"schema": "dc-candidate-signing-result-v1",
                    "status": "UNKNOWN_NO_RE_SIGN", "claimSha256": claim_hash, "generation": claim["generation"],
                    "childExitCode": signing_code, "envelopeSha256": None}))
                raise ValueError("CANDIDATE_SIGNING_OUTCOME_UNKNOWN") from failure
        bundle = {"manifest.json": read(paths["manifest.json"], 98304), "index.json.gz": read(paths["index.json.gz"])}
        require(unpack_envelope(bundle["manifest.json"])[1] == rebased["manifest.raw.json"], "CANDIDATE_SIGNED_MANIFEST_PIN")
        candidate_publication_verify(config, directory, budget, bundle, profile=ACQUISITION_PURPOSE, historical=False)
        if not resumed:
            write_new(paths["signing-result.json"], canonical({"schema": "dc-candidate-signing-result-v1",
                "status": "SIGNED_NOT_PUBLISHED", "claimSha256": claim_hash, "generation": claim["generation"],
                "childExitCode": 0, "envelopeSha256": sha(bundle["manifest.json"])}))
        elif previous_result is None:
            # 原exitや中断理由を補完せず、今回確認した保存artifactの認証だけを残す。
            write_new(paths["signing-result.json"], canonical({"schema": "dc-candidate-signing-result-v1",
                "status": "SAVED_ENVELOPE_VERIFIED_ORIGINAL_EXIT_UNKNOWN", "claimSha256": claim_hash,
                "generation": claim["generation"], "childExitCode": None, "envelopeSha256": sha(bundle["manifest.json"])}))
        original_known = not resumed or (previous_result is not None and previous_result["status"] == "SIGNED_NOT_PUBLISHED")
        return {"status": "SIGNED_NOT_PUBLISHED", "generation": claim["generation"], "claimSha256": claim_hash,
            "envelopeSha256": sha(bundle["manifest.json"]), "purpose": ACQUISITION_PURPOSE, "resumed": resumed,
            "originalSigningOutcomeKnown": original_known,
            "originalChildExitCode": 0 if not resumed else previous_result["childExitCode"] if previous_result else None,
            "published": False}


def publish_candidate_publication(config: dict, config_hash: str, head_path: Path | None, head_hash: str | None,
        receipt_path: Path, receipt_hash: str, claim_path: Path, claim_hash: str, fingerprint: str,
        envelope_hash: str, *, native_inputs=None, budget=None, remote=None, checkpoint=None) -> dict:
    """明示pin済み保存署名束だけを既存Publisherへ渡す。収集/再署名を一切起動しない。"""
    candidate_publication_selection(head_path, head_hash, native_inputs)
    candidate_publication_now()
    require(fingerprint == config["fingerprint"] == projection.DISTRIBUTION_PUBLIC_FINGERPRINT and
        public_sha(claim_hash) and public_sha(envelope_hash), "CANDIDATE_PUBLISH_PIN")
    directory = operation_root(Path(config["outputRoot"]))
    protected_tree(directory)
    with exclusive(directory / "pipeline.lock"):
        candidate_publication_runtime(config, config_hash)
        claim_path = normal_path(str(claim_path))
        require(claim_path.parent == directory, "CANDIDATE_CLAIM_LOCATION")
        claim_raw = read(claim_path, 65536)
        require(sha(claim_raw) == claim_hash, "CANDIDATE_CLAIM_PIN")
        claim = cr.parse_json(claim_raw)
        validate_candidate_publication_claim(claim)
        require(claim_raw == canonical(claim) and claim["configSha256"] == config_hash and
            claim["candidateHeadSha256"] == head_hash and claim["fingerprint"] == fingerprint and
            claim["nativeInputsSha256"] == (native_inputs[1] if native_inputs else None), "CANDIDATE_PUBLISH_INPUTS")
        paths = candidate_publication_paths(directory, claim["generation"])
        head, raw, _ = candidate_publication_input(head_path, head_hash)
        selected = candidate_publication_merge(raw, candidate_publication_native_inputs(
            config, native_inputs, receipt_path, receipt_hash, parse_time(claim["publishedAtUtc"])))
        rebased = candidate_publication_rebase(selected, claim["generation"], parse_time(claim["publishedAtUtc"]))
        require((head["outputs"] if head is not None else None) == claim["candidateOutputs"] and
            {name: sha(body) for name, body in rebased.items()} == claim["outputs"], "CANDIDATE_PUBLISH_INPUTS")
        for name, body in rebased.items():
            require(read(paths[name]) == body, "CANDIDATE_PUBLISH_OUTPUT_PIN")
        require(read(paths["ready.json"], 65536) == canonical({"schema": "dc-candidate-publication-ready-v1",
            "claimSha256": claim_hash, "outputs": claim["outputs"], "unsigned": True, "authenticated": False}),
            "CANDIDATE_PREPARE_INCOMPLETE")
        # 既存prepareのready schemaを原byteで確認し、成功ラベルだけは信用しない。
        require(read(paths["signing-intent.json"], 65536) == canonical({"schema": "dc-candidate-signing-intent-v1",
            "claimSha256": claim_hash, "fingerprint": fingerprint, "signerSha256": config["signerSha256"],
            "mode": "--distribution-acquisition-sign"}), "CANDIDATE_SIGNING_INTENT_PIN")
        signing = cr.parse_json(read(paths["signing-result.json"], 65536))
        cr.fields(signing, {"schema", "status", "claimSha256", "generation", "childExitCode", "envelopeSha256"},
            "CANDIDATE_SIGNING_RESULT")
        require(signing["schema"] == "dc-candidate-signing-result-v1" and signing["claimSha256"] == claim_hash and
            type(signing["generation"]) is int and signing["generation"] == claim["generation"] and
            ((signing["status"] == "SIGNED_NOT_PUBLISHED" and type(signing["childExitCode"]) is int and
                signing["childExitCode"] == 0 and signing["envelopeSha256"] == envelope_hash) or
             (signing["status"] == "SAVED_ENVELOPE_VERIFIED_ORIGINAL_EXIT_UNKNOWN" and
                signing["childExitCode"] is None and signing["envelopeSha256"] == envelope_hash) or
             (signing["status"] == "UNKNOWN_NO_RE_SIGN" and signing["envelopeSha256"] is None and
                (signing["childExitCode"] is None or type(signing["childExitCode"]) is int))), "CANDIDATE_SIGNING_RESULT")
        bundle = {"manifest.json": read(paths["manifest.json"], 98304), "index.json.gz": read(paths["index.json.gz"])}
        require(sha(bundle["manifest.json"]) == envelope_hash and
            unpack_envelope(bundle["manifest.json"])[1] == rebased["manifest.raw.json"], "CANDIDATE_SIGNED_MANIFEST_PIN")
        prefix = directory / f"candidate-publish-{claim['generation']:016d}"
        intent_path = Path(str(prefix) + ".intent.json")
        intent = canonical({"schema": "dc-candidate-publish-intent-v1", "configSha256": config_hash,
            "claimSha256": claim_hash, "envelopeSha256": envelope_hash,
            "gzipSha256": sha(bundle["index.json.gz"]), "generation": claim["generation"], "fingerprint": fingerprint})
        keep_exact(intent_path, intent)
        require(read(intent_path, 65536) == intent, "CANDIDATE_PUBLISH_INTENT_PIN")
        terminals = sorted(directory.glob(prefix.name + ".terminal-*.json"))
        require(len(terminals) < 32, "CANDIDATE_PUBLISH_ATTEMPT_LIMIT")
        inner_budget = budget or Budget()
        if isinstance(inner_budget, Budget):
            inner_budget.directory = directory
        operation_budget = PublicOperationBudget(inner_budget, prefix, sha(intent))
        transport = remote or GitHub(config["ghExe"], operation_budget)
        cas_path = Path(str(prefix) + ".cas-intent.json")
        cas_intent = canonical({"schema": "dc-candidate-publish-cas-v1", "intentSha256": sha(intent),
            "originalHead": claim["publicHead"], "envelopeSha256": envelope_hash})
        if cas_path.exists():
            require(read(cas_path, 65536) == cas_intent, "CANDIDATE_PUBLISH_CAS_PIN")
        def verify(candidate, *, historical):
            """現在の候補は全record検査、Public履歴は明示した下限profileだけを使う。"""
            if not historical:
                candidate_publication_validity(rebased)
            candidate_publication_verify(config, directory, operation_budget, candidate,
                profile=HISTORY_FLOOR if historical else ACQUISITION_PURPOSE,
                historical=historical)

        def recheck():
            """現在headとlocal全下限を再確認し、自身の同byte head以外の変化を拒否する。"""
            candidate_publication_runtime(config, config_hash)
            require(parse_time(claim["publishedAtUtc"]) <= candidate_publication_now() <
                parse_time(claim["expiresAtUtc"]), "CANDIDATE_EXPIRED")
            current = candidate_publication_current(config, directory, operation_budget, transport,
                HISTORY_FLOOR)
            reservation = candidate_publication_reservation(config, receipt_path, receipt_hash, operation_budget)
            maximum, prior = candidate_publication_history(directory, current, reservation)
            own_head = (current["generation"] == claim["generation"] and current["envelopeSha256"] == envelope_hash and
                current["gzipSha256"] == sha(bundle["index.json.gz"]) and
                current["rawManifestSha256"] == claim["outputs"]["manifest.raw.json"])
            require((current == dict(claim["publicHead"], profile=HISTORY_FLOOR) or own_head) and
                reservation == claim["nativeReservation"] and
                maximum == claim["generation"] and any(path == claim_path and value == claim for path, value in prior),
                "CANDIDATE_PUBLISH_STALE")
            verify(bundle, historical=False)

        def before_cas():
            """同headを直前確認し、CASの不確定意図をflush/readbackしてから一回だけ進める。"""
            candidate_publication_validity(rebased)
            recheck()
            write_new(cas_path, cas_intent)
            require(read(cas_path, 65536) == cas_intent, "CANDIDATE_PUBLISH_CAS_PIN")
            if checkpoint:
                checkpoint("CAS_INTENT")

        def terminal(value):
            """原UNKNOWN/非zeroを上書きせず、独立attemptの今回結果を新規保存する。"""
            value.update(claimSha256=claim_hash, envelopeSha256=envelope_hash, configSha256=config_hash,
                purpose=ACQUISITION_PURPOSE, originalSigningStatus=signing["status"],
                originalChildExitCode=signing["childExitCode"])
            write_new(Path(str(prefix) + f".terminal-{len(terminals):02d}.json"), canonical(value))
            return value

        try:
            recheck()
            anonymous = public_anonymous_callback(config, config_hash, prefix, operation_budget, verify, claim_hash,
                bundle_paths=(paths["manifest.json"], paths["index.json.gz"]))
            result = acquisition_publisher(config, transport, verify, before_cas=before_cas,
                anonymous=anonymous).publish(bundle, readback_only=cas_path.exists())
            return terminal(result)
        except Exception as failure:
            reason = str(failure) if re.fullmatch(r"[A-Z_]+", str(failure)) else "CANDIDATE_PUBLISH_EXCEPTION"
            terminal({"status": "UNKNOWN", "reason": reason, "generation": claim["generation"],
                "casIntentSaved": cas_path.exists(), "published": False})
            raise
        finally:
            operation_budget.save()


def pipeline_arguments(argv=None):
    """Publicの唯一の正規引数列をload/lock/外部作用より前に認証する。"""
    values = list(sys.argv[1:] if argv is None else argv)
    public_options = any(value.startswith("--public-") for value in values)
    if values and (values[0] == "run-public" or public_options):
        require(len(values) == 6 and values[0] == "run-public" and values[2] == "--public-context" and
            values[4] == "--public-context-sha256" and public_sha(values[5]) and
            not values[1].startswith("-") and not values[3].startswith("-"), "PUBLIC_CLI_ARGUMENTS")
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("mode", choices=("plan", "run", "run-public", "report", "task", "prepare-fresh-native", "prepare-candidate", "sign-candidate", "publish-candidate"))
    parser.add_argument("config", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--user-sid")
    parser.add_argument("--smoke", action="store_true")
    parser.add_argument("--public-context", type=Path)
    parser.add_argument("--public-context-sha256")
    parser.add_argument("--candidate-head", type=Path)
    parser.add_argument("--candidate-head-sha256")
    parser.add_argument("--reservation-receipt", type=Path)
    parser.add_argument("--reservation-receipt-sha256")
    parser.add_argument("--head-profile", choices=("METADATA_ONLY", ACQUISITION_PURPOSE, HISTORY_FLOOR))
    parser.add_argument("--native-inputs", type=Path)
    parser.add_argument("--native-inputs-sha256")
    parser.add_argument("--claim", type=Path)
    parser.add_argument("--claim-sha256")
    parser.add_argument("--fingerprint")
    parser.add_argument("--envelope-sha256")
    parser.add_argument("--fresh-receipt", type=Path)
    parser.add_argument("--maximum-payload-bytes", type=int)
    parser.add_argument("--terms-consent-not-after", type=int)
    parser.add_argument("--accept-pinned-terms", action="store_true")
    args = parser.parse_args(values)
    candidate_names = ("candidate_head", "candidate_head_sha256", "reservation_receipt", "reservation_receipt_sha256",
        "head_profile", "claim", "claim_sha256", "fingerprint", "native_inputs", "native_inputs_sha256", "envelope_sha256")
    fresh_names = ("fresh_receipt", "maximum_payload_bytes", "terms_consent_not_after")
    if args.mode == "prepare-fresh-native":
        require(all(getattr(args, name) is not None for name in fresh_names) and args.accept_pinned_terms and
            all(getattr(args, name) is None for name in candidate_names) and args.output is None and
            args.user_sid is None and args.smoke is False and args.public_context is None and
            args.public_context_sha256 is None, "FRESH_NATIVE_CLI_ARGUMENTS")
    else:
        require(all(getattr(args, name) is None for name in fresh_names) and not args.accept_pinned_terms,
            "FRESH_NATIVE_CLI_ARGUMENTS")
    if args.mode in {"prepare-candidate", "sign-candidate", "publish-candidate"}:
        native = (args.native_inputs, args.native_inputs_sha256) if (
            args.native_inputs is not None or args.native_inputs_sha256 is not None) else None
        candidate_publication_selection(args.candidate_head, args.candidate_head_sha256, native,
            diagnostic="CANDIDATE_CLI_ARGUMENTS")
        require(args.reservation_receipt is not None and public_sha(args.reservation_receipt_sha256) and
            args.output is None and args.user_sid is None and args.smoke is False and args.public_context is None and
            args.public_context_sha256 is None, "CANDIDATE_CLI_ARGUMENTS")
        require((args.mode == "prepare-candidate" and args.head_profile is not None and
            args.claim is None and args.claim_sha256 is None and args.fingerprint is None and args.envelope_sha256 is None) or
            (args.mode in {"sign-candidate", "publish-candidate"} and args.head_profile is None and args.claim is not None and
            public_sha(args.claim_sha256) and public_sha(args.fingerprint) and
            (public_sha(args.envelope_sha256) if args.mode == "publish-candidate" else args.envelope_sha256 is None)),
            "CANDIDATE_CLI_ARGUMENTS")
    else:
        require(all(getattr(args, name) is None for name in candidate_names), "CANDIDATE_CLI_ARGUMENTS")
    return args


def main() -> int:
    """明示modeを実行し、元の終了区分と固定codeに検証済み任意診断だけを添えて保存する。"""
    public_started = time.monotonic()
    args = pipeline_arguments()
    config, scope, config_hash = load_config(args.config.resolve())
    if args.mode == "prepare-fresh-native":
        try:
            result = prepare_fresh_daily_acquisition_inputs(config, args.fresh_receipt,
                maximum_bytes=args.maximum_payload_bytes, consent_not_after=args.terms_consent_not_after,
                accept_pinned_terms=args.accept_pinned_terms)
        except Exception as error:
            code = str(error) if re.fullmatch(r"[A-Z_]+", str(error)) else "FRESH_NATIVE_EXCEPTION"
            result = {"status": "FAILED", "reason": code, "prepared": False, "signed": False, "published": False}
        print(json.dumps(result))
        return 0 if result["status"] == "PREPARED_UNSIGNED" else 3 if result["status"] in {"HOLD", "NO_NETWORK"} else 2
    # 公開設定はplanと明示run-publicを許し、Task生成・reportの旧Private意味への流入を拒否する。
    require(config.get("schema") != PUBLIC_CONFIG_SCHEMA or args.mode in {"plan", "run-public", "prepare-candidate", "sign-candidate", "publish-candidate"},
            "PUBLIC_HISTORY_TRANSITION_REQUIRED")
    # 手動prepare/signは独立した明示入口で、通常TaskやPublisher.publishを起動しない。
    if args.mode in {"prepare-candidate", "sign-candidate", "publish-candidate"}:
        try:
            common = (config, config_hash, args.candidate_head, args.candidate_head_sha256,
                args.reservation_receipt, args.reservation_receipt_sha256)
            native = (args.native_inputs, args.native_inputs_sha256) if args.native_inputs is not None else None
            if args.mode == "prepare-candidate":
                result = prepare_candidate_publication(*common, head_profile=args.head_profile, native_inputs=native)
            elif args.mode == "publish-candidate":
                result = publish_candidate_publication(*common, args.claim, args.claim_sha256, args.fingerprint,
                    args.envelope_sha256, native_inputs=native)
            else:
                result = sign_candidate_publication(*common, args.claim, args.claim_sha256, args.fingerprint, native_inputs=native)
        except Exception as error:
            code = str(error) if re.fullmatch(r"[A-Z_]+", str(error)) else "CANDIDATE_PUBLICATION_EXCEPTION"
            result = {"status": "FAILED", "reason": code, "purpose": ACQUISITION_PURPOSE, "published": False}
        print(json.dumps(result))
        return 0 if result["status"] in {"PREPARED_UNSIGNED", "SIGNED_NOT_PUBLISHED", "PUBLISHED"} else 2
    if args.mode == "run-public":
        require(config.get("schema") == PUBLIC_CONFIG_SCHEMA, "PUBLIC_CONTEXT_REQUIRED")
        try:
            result = run_pipeline(config, scope, config_hash,
                public_context=(args.public_context, args.public_context_sha256), attempt_started=public_started)
        except Exception as error:
            code = str(error) if re.fullmatch(r"[A-Z_]+", str(error)) else "PIPELINE_EXCEPTION"
            result = {"status": "FAILED", "reason": code, "purpose": ACQUISITION_PURPOSE, "configSha256": config_hash}
        print(json.dumps(result))
        return 0 if result["status"] == "PUBLISHED" else 3 if result["status"] in {"HOLD", "NO_NETWORK"} else 2
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
        plan = {"schema": "dc-private-daily-plan-v1", "configSha256": config_hash,
            "repository": REPOSITORY, "privateRequired": True, "assetAllowlist": sorted(ASSETS),
            "stateRootInherited": True, "maximumSeconds": MAX_SECONDS, "maximumHoldWait": MAX_WAIT,
            "realOperations": 0, "taskName": TASK_NAME, "smokeLocal": config["smokeLocal"],
            "firstDailyLocal": config["firstDailyLocal"], "days": 7, "credentialRead": False}
        # 未接続を利用可能と表示せず、Task切替をこのplanから推定させない。
        if config.get("schema") == PUBLIC_CONFIG_SCHEMA:
            plan.update(schema="dc-public-daily-plan-v3", privateRequired=False, executable=False,
                        historyTransitionRequired=True, taskName=None)
        raw = canonical(plan)
    write_new(args.output, raw)
    print("DAILY_INDEX_PLAN_COMPLETED")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, OSError, KeyError, TypeError):
        print("DAILY_INDEX_INPUT_REJECTED")
        raise SystemExit(2)
