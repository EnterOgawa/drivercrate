"""PS7/CMake-Pの人工profileだけを検査する。EXE/鍵/実HTTPは実行しない。

source三fileはstat後の有限readだけ。生成物とguardの入力は専用temp内だけで、
許可childは絶対PS7の固定guardとCMakeの固定-Pに限定する。原child byteをbase64で報告する。
"""
from __future__ import annotations

import argparse
import base64
from contextlib import redirect_stdout
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import socket
import subprocess
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
GENERATOR = ROOT / "cmake/RecordIndexBuildProfile.cmake"
ORIGINAL_POPEN = subprocess.Popen
PS_VERSION_COMMAND = (
    "Write-Output ('DRIVERCRATE_PS7 ' + $PSVersionTable.PSEdition + ' ' + "
    "$PSVersionTable.PSVersion.ToString())"
)


class ToolResolutionError(ValueError):
    """tool未実行・不適合を試験成功と分離する固定診断。"""


@dataclass(frozen=True)
class ProfileTools:
    """固定probeを通過した開発用toolの絶対pathを試験中保持する。"""

    powershell: Path
    cmake: Path


def tool_path(explicit: str | None, basename: str) -> Path:
    """明示pathを優先し、未指定だけPATH検索する。command文字列と曖昧なpathは拒否する。"""
    candidate = explicit if explicit is not None else shutil.which(basename)
    if candidate is None:
        raise ToolResolutionError(basename + ": TOOL_NOT_FOUND")
    if not candidate or any(char in candidate for char in '\"<>|?*\r\n\x00'):
        raise ToolResolutionError(basename + ": TOOL_PATH_INVALID")
    path = Path(candidate)
    if (not path.is_absolute() or not re.fullmatch(r"[A-Za-z]:", path.drive)
            or ".." in path.parts or path.name.casefold() != basename):
        raise ToolResolutionError(basename + ": TOOL_PATH_INVALID")
    try:
        resolved = path.resolve(strict=True)
        if (not resolved.is_absolute() or not re.fullmatch(r"[A-Za-z]:", resolved.drive)
                or ".." in resolved.parts or resolved.name.casefold() != basename
                or any(char in str(resolved) for char in '\"<>|?*\r\n\x00')):
            raise ToolResolutionError(basename + ": TOOL_RESOLVED_PATH_INVALID")
        if not resolved.is_file() or resolved.name.casefold() != basename:
            raise ToolResolutionError(basename + ": TOOL_FILE_INVALID")
    except OSError as error:
        raise ToolResolutionError(basename + ": TOOL_FILE_UNAVAILABLE") from error
    return resolved


def fixed_popen(argv, expected: list[str], cwd: Path, args, kwargs):
    """exact argvと固定captureだけを元Popenへ通す。shell/executable/env置換も拒否する。"""
    if (not isinstance(argv, list) or argv != expected or args
            or kwargs != {"cwd": cwd, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}):
        raise AssertionError("CHILD_COMMAND_OR_OPTIONS_DENIED")
    return ORIGINAL_POPEN(argv, **kwargs)


def preflight(path: Path, basename: str) -> None:
    """一tool一回の固定版数probeを実行し、原byte/時刻を保存して互換性を検査する。"""
    tail = (["-NoLogo", "-NoProfile", "-NonInteractive", "-Command", PS_VERSION_COMMAND]
            if basename == "pwsh.exe" else ["--version"])
    argv = [str(path), *tail]
    started = datetime.now(timezone.utc).isoformat()
    record = {"tool": basename, "argv": argv, "startedUtc": started, "exit": None,
              "stdoutBase64": "", "stderrBase64": "", "error": None}
    try:
        with patch.object(socket, "socket", side_effect=AssertionError("NETWORK_DENIED")), \
                patch.object(socket, "getaddrinfo", side_effect=AssertionError("NETWORK_DENIED")), \
                patch.object(subprocess, "Popen", side_effect=lambda command, *args, **kwargs:
                             fixed_popen(command, argv, ROOT, args, kwargs)):
            result = subprocess.run(argv, cwd=ROOT, capture_output=True, timeout=10, check=False)
        record.update(exit=result.returncode, stdoutBase64=base64.b64encode(result.stdout).decode(),
                      stderrBase64=base64.b64encode(result.stderr).decode())
        if len(result.stdout) + len(result.stderr) > 16384 or result.returncode != 0:
            raise ToolResolutionError(basename + ": TOOL_PROBE_FAILED")
        output = result.stdout.decode("utf-8", errors="strict").strip()
        if basename == "pwsh.exe":
            if not re.fullmatch(r"DRIVERCRATE_PS7 Core 7\.[0-9]+\.[0-9]+", output):
                raise ToolResolutionError(basename + ": POWERSHELL_7_CORE_REQUIRED")
        else:
            version = re.match(r"cmake version ([0-9]+)\.([0-9]+)\.([0-9]+)(?:\r?\n|$)", output)
            if version is None or tuple(map(int, version.groups())) < (3, 28, 0):
                raise ToolResolutionError(basename + ": CMAKE_3_28_REQUIRED")
    except subprocess.TimeoutExpired as error:
        record.update(stdoutBase64=base64.b64encode(error.stdout or b"").decode(),
                      stderrBase64=base64.b64encode(error.stderr or b"").decode(), error="TimeoutExpired")
        raise ToolResolutionError(basename + ": TOOL_PROBE_TIMEOUT") from error
    except (OSError, UnicodeError) as error:
        record["error"] = type(error).__name__
        raise ToolResolutionError(basename + ": TOOL_PROBE_UNAVAILABLE") from error
    finally:
        record["endedUtc"] = datetime.now(timezone.utc).isoformat()
        print("P3_PREFLIGHT " + json.dumps(record), flush=True)


def resolve_tools(powershell: str | None, cmake: str | None) -> ProfileTools:
    """両pathを起動前に確定してから固定版数probeを各一回だけ行う。"""
    tools = ProfileTools(tool_path(powershell, "pwsh.exe"), tool_path(cmake, "cmake.exe"))
    preflight(tools.powershell, "pwsh.exe")
    preflight(tools.cmake, "cmake.exe")
    return tools


def bounded_read(path: Path, limit: int) -> bytes:
    """非秘密sourceをstat後limit+1まで読み所有byteを返す。過大/途中変更は拒否する。"""
    size = path.stat().st_size
    if size > limit:
        raise ValueError("profile fixture read limit")
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) != size or len(data) > limit:
        raise ValueError("profile fixture changed during read")
    return data


class IndexBuildProfileTests(unittest.TestCase):
    """偽EXEを起動せず厳密v2/固定policy/hashを検査し、各child原結果を保持する。"""

    tools: ProfileTools | None = None

    def setUp(self) -> None:
        """専用tempにsource guard/public定数と非実行byteを置き、network/任意childを拒否する。"""
        if self.tools is None:
            raise ToolResolutionError("Use the script CLI: P3_NOT_RUN methods=8 nativeCases=34")
        self.owner = tempfile.TemporaryDirectory(prefix="drivercrate-profile-p3-")
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name).resolve()
        (self.root / "scripts").mkdir()
        (self.root / "src/platform").mkdir(parents=True)
        self.guard = self.root / "scripts/index_build_profile.ps1"
        self.header = self.root / "src/platform/index_distribution_trust.h"
        self.guard.write_bytes(bounded_read(ROOT / "scripts/index_build_profile.ps1", 16384))
        self.header.write_bytes(bounded_read(ROOT / "src/platform/index_distribution_trust.h", 16384))
        source = bounded_read(self.header, 16384).decode("utf-8")
        self.fingerprint = re.search(r'PUBLIC_FINGERPRINT\s*=\s*"([0-9a-f]{64})"', source)[1]
        self.exe = self.root / "never-run.exe"
        self.exe.write_bytes(b"artificial executable bytes - NEVER RUN\n")
        self.sidecar = Path(str(self.exe) + ".index-profile.json")
        self.good = {"schema": "drivercrate-index-build-profile-v2", "localAcceptance": False,
                     "sha256": hashlib.sha256(bounded_read(self.exe, 1024)).hexdigest(),
                     "distributionFingerprint": self.fingerprint, "acquisitionPolicyRevision": 1}
        self.runner = self.root / "check.ps1"
        self.runner.write_text("param([string] $Executable)\n$ErrorActionPreference='Stop'\n"
                               ". (Join-Path $PSScriptRoot 'scripts/index_build_profile.ps1')\n"
                               "try { Assert-DistributableIndexBuild -Executable $Executable; 'PROFILE_OK' }\n"
                               "catch { [Console]::Error.WriteLine($_.Exception.Message); exit 1 }\n",
                               encoding="utf-8", newline="\n")
        for name in ("socket", "getaddrinfo"):
            guard = patch.object(socket, name, side_effect=AssertionError("NETWORK_DENIED"))
            guard.start()
            self.addCleanup(guard.stop)
        guard = patch.object(subprocess, "Popen", side_effect=self.allowed_popen)
        guard.start()
        self.addCleanup(guard.stop)

    def allowed_popen(self, argv, *args, **kwargs):
        """絶対PS7固定runnerかCMake固定-Pだけ許す。temp外出力/偽EXE/任意子は起動前拒否。"""
        if not isinstance(argv, list) or not argv or len(argv) > 16 or self.tools is None:
            raise AssertionError("CHILD_DENIED")
        if argv[0] == str(self.tools.powershell):
            if argv[1:] != ["-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(self.runner), str(self.exe)]:
                raise AssertionError("PS_COMMAND_DENIED")
        elif argv[0] == str(self.tools.cmake):
            if len(argv) != 7 or argv[1] != "-DEXECUTABLE=" + str(self.exe) or argv[-2:] != ["-P", str(GENERATOR)]:
                raise AssertionError("CMAKE_COMMAND_DENIED")
            if not argv[2].startswith("-DLOCAL_PROFILE=") or not argv[3].startswith("-DDISTRIBUTION_FINGERPRINT=") or not argv[4].startswith("-DACQUISITION_POLICY_REVISION="):
                raise AssertionError("CMAKE_ARGUMENT_DENIED")
        else:
            raise AssertionError("CHILD_DENIED")
        return fixed_popen(argv, argv, self.root, args, kwargs)

    def child(self, name: str, argv: list[str], accepted: bool) -> None:
        """固定childを最大10秒直列実行し、argv/exit/原byteと期待値をstdoutへ報告する。"""
        started = datetime.now(timezone.utc).isoformat()
        record = {"name": name, "argv": argv, "exit": None, "stdoutBase64": "",
                  "stderrBase64": "", "expectedAccepted": accepted, "startedUtc": started, "timeout": False}
        try:
            result = subprocess.run(argv, cwd=self.root, capture_output=True, timeout=10, check=False)
            record.update(exit=result.returncode, stdoutBase64=base64.b64encode(result.stdout).decode(),
                          stderrBase64=base64.b64encode(result.stderr).decode())
        except subprocess.TimeoutExpired as error:
            record.update(stdoutBase64=base64.b64encode(error.stdout or b"").decode(),
                          stderrBase64=base64.b64encode(error.stderr or b"").decode(), timeout=True)
            raise
        finally:
            record["endedUtc"] = datetime.now(timezone.utc).isoformat()
            print("P3_CASE " + json.dumps(record), flush=True)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 16384)
        self.assertEqual(result.returncode == 0, accepted, name)

    def guard_case(self, name: str, receipt, accepted: bool = False) -> None:
        """temp sidecarを一つ生成して固定guardへ渡す。文字列は不正文法/重複field試験に限る。"""
        raw = receipt if isinstance(receipt, str) else json.dumps(receipt, separators=(",", ":"))
        self.sidecar.write_text(raw, encoding="utf-8", newline="\n")
        self.child(name, [str(self.tools.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(self.runner), str(self.exe)], accepted)

    def generate(self, name: str, local: str = "OFF", fingerprint: str | None = None,
                 revision: str = "1", accepted: bool = True) -> None:
        """CMake-Pだけでtemp EXE隣へsidecarを生成する。buildtree/EXE実行/鍵処理なし。"""
        self.child(name, [str(self.tools.cmake), "-DEXECUTABLE=" + str(self.exe), "-DLOCAL_PROFILE=" + local,
                   "-DDISTRIBUTION_FINGERPRINT=" + (self.fingerprint if fingerprint is None else fingerprint),
                   "-DACQUISITION_POLICY_REVISION=" + revision, "-P", str(GENERATOR)], accepted)

    def test_p3_01_source_public_pin_and_drift(self) -> None:
        """411公開byte/完全hash/keyId一致と、source fingerprint単独drift拒否を確認する。"""
        source = bounded_read(self.header, 16384).decode()
        body = re.search(r"(?s)PUBLIC_BLOB\s*\{(.*?)\}\s*;", source)[1]
        public = bytes(int(x, 16) for x in re.findall(r"0x([0-9a-f]{2})U", body))
        self.assertEqual(len(public), 411)
        self.assertEqual(hashlib.sha256(public).hexdigest(), self.fingerprint)
        self.assertIn('"distribution-index-' + self.fingerprint[:32] + '"', source)
        self.header.write_text(source.replace(self.fingerprint, "f" * 64), encoding="utf-8")
        self.guard_case("P3-01-source-pin-drift", self.good)

    def test_p3_02_normal_generator_guard(self) -> None:
        """source正本由来の通常CMake-P出力をPS7 guardが受理する。"""
        self.generate("P3-02-cmake-normal")
        self.assertEqual(json.loads(bounded_read(self.sidecar, 1024)), self.good)
        self.guard_case("P3-02-generated-normal-guard", self.good, True)

    def test_p3_03_local_and_generator_policy(self) -> None:
        """localは配布fp空/revision0で生成できるが配布guardを通さず、引数driftも拒否する。"""
        self.generate("P3-03-cmake-local", "ON", "", "0")
        receipt = json.loads(bounded_read(self.sidecar, 1024))
        self.assertEqual((receipt["localAcceptance"], receipt["distributionFingerprint"], receipt["acquisitionPolicyRevision"]), (True, "", 0))
        self.guard_case("P3-03-local-not-distributable", receipt)
        self.generate("P3-03-cmake-fingerprint", fingerprint="0" * 64, accepted=False)
        self.generate("P3-03-cmake-revision", revision="2", accepted=False)
        self.generate("P3-03-cmake-local-type", local="false", accepted=False)

    def test_p3_05_schema_fields_types_bounds(self) -> None:
        """欠損/未知/重複field、旧schema、各型、非整数revision、容量とJSONを拒否する。"""
        for key in self.good:
            with self.subTest(missing=key):
                receipt = copy.deepcopy(self.good)
                del receipt[key]
                self.guard_case("P3-05-missing-" + key, receipt)
        cases = [("unknown", {**self.good, "extra": 0}), ("v1", {**self.good, "schema": "drivercrate-index-build-profile-v1"}),
                 ("schema-type", {**self.good, "schema": True}), ("local-type", {**self.good, "localAcceptance": 0}),
                 ("hash-type", {**self.good, "sha256": 1}), ("fingerprint-type", {**self.good, "distributionFingerprint": None}),
                 ("revision-string", {**self.good, "acquisitionPolicyRevision": "1"}),
                 ("revision-bool", {**self.good, "acquisitionPolicyRevision": True}),
                 ("revision-float", {**self.good, "acquisitionPolicyRevision": 1.0})]
        for name, receipt in cases:
            with self.subTest(case=name):
                self.guard_case("P3-05-" + name, receipt)
        raw = json.dumps(self.good, separators=(",", ":"))
        self.guard_case("P3-05-duplicate", raw[:-1] + ',"acquisitionPolicyRevision":1}')
        self.guard_case("P3-05-over1024", raw + " " * 1025)
        self.guard_case("P3-05-malformed", "{")

    def test_p3_06_fingerprint_revision(self) -> None:
        """normal識別だけでは足りず完全fpと独立整数revision1が必要なことを確認する。"""
        for name, key, value in (("fingerprint", "distributionFingerprint", "0" * 64),
                                 ("disabled", "acquisitionPolicyRevision", 0),
                                 ("future", "acquisitionPolicyRevision", 2),
                                 ("local", "localAcceptance", True)):
            with self.subTest(case=name):
                self.guard_case("P3-06-" + name, {**self.good, key: value})

    def test_p3_07_executable_binding(self) -> None:
        """hash一致の人工byteだけ受理し、stale/不正hash/sidecar欠損を拒否する。"""
        self.guard_case("P3-07-exact", self.good, True)
        self.exe.write_bytes(b"changed artificial bytes")
        self.guard_case("P3-07-stale", self.good)
        self.guard_case("P3-07-hash-shape", {**self.good, "sha256": "0" * 63})
        self.sidecar.unlink()
        self.child("P3-07-missing", [str(self.tools.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(self.runner), str(self.exe)], False)

    def test_p3_08_denied_runtime_and_network(self) -> None:
        """偽EXEや任意子/明示network呼出しは実起動前にdenyする。"""
        for argv in ([str(self.exe)], ["cmd.exe", "/c", "exit"]):
            with self.subTest(argv=argv), self.assertRaises(AssertionError):
                subprocess.run(argv, check=False)
        with self.assertRaisesRegex(AssertionError, "NETWORK_DENIED"):
            socket.socket()
        with self.assertRaisesRegex(AssertionError, "NETWORK_DENIED"):
            socket.getaddrinfo("example.invalid", 443)

    def test_p3_08_source_revision_shape(self) -> None:
        """guard自身もsource宣言の曖昧さ/非採用revisionを拒否し正本driftを隠さない。"""
        source = bounded_read(self.header, 16384).decode()
        changed, count = re.subn(r"(ACQUISITION_POLICY_REVISION\s*=\s*)1U", r"\g<1>2U", source)
        self.assertEqual(count, 1)
        self.header.write_text(changed, encoding="utf-8")
        self.guard_case("P3-08-source-revision", self.good)


class PackageBuildBindingTests(unittest.TestCase):
    """production helperとbuilder入口のsource/cache/output境界を合成入力で検査する。"""

    tools: ProfileTools | None = None

    def setUp(self) -> None:
        """所有tempに二つの通常cacheを作り、任意Python child/networkを拒否する。"""
        if self.tools is None:
            raise ToolResolutionError("Use --suite package: PACKAGE_NOT_RUN")
        self.owner = tempfile.TemporaryDirectory(prefix="drivercrate-package-binding-")
        self.addCleanup(self.owner.cleanup)
        self.root = Path(self.owner.name).resolve()
        self.source = self.root / "source 空白"
        scripts = self.source / "scripts"
        scripts.mkdir(parents=True)
        self.build = self.root / "build"
        self.build.mkdir()
        (self.source / "build").mkdir()
        for name in ("index_build_profile.ps1", "package-release.ps1", "package-collector.ps1",
                     "package-collector-installer.ps1", "test-collector-installer.ps1"):
            (scripts / name).write_bytes(bounded_read(ROOT / "scripts" / name, 65536))
        module = self.source / "packaging/collector/collector-setup.psm1"
        module.parent.mkdir(parents=True)
        module.write_bytes(bounded_read(ROOT / "packaging/collector/collector-setup.psm1", 65536))
        self.cache = {
            "CMAKE_HOME_DIRECTORY:INTERNAL": self.source.as_posix(),
            "CMAKE_GENERATOR:INTERNAL": "Ninja Multi-Config",
            "CMAKE_CONFIGURATION_TYPES:STRING": "Debug;Release",
            "DRIVERCRATE_BUILD_COLLECTOR:BOOL": "ON",
            **{key + ":BOOL": "OFF" for key in ("DRIVERCRATE_BUILD_LIVE_TESTS", "DRIVERCRATE_ENABLE_ANALYZE",
               "DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE", "DRIVERCRATE_LOCAL_INDEX_ACQUISITION")},
            "DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB:FILEPATH": "",
            "DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256:STRING": "",
            "DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH": "",
        }
        self.save_cache()
        self.save_cache(self.source / "build")
        self.runner = scripts / "binding-check.ps1"
        self.runner.write_text('''param([string]$Mode,[string]$Build,[string]$Output,[string]$Extra)
$ErrorActionPreference='Stop'
. (Join-Path $PSScriptRoot 'index_build_profile.ps1')
try {
    if ($Mode -eq 'restore') {
        Invoke-IndexPackageBuildAndRestore -Operation {
            if ($Extra -in @('primary','both')) { throw 'PRIMARY_SENTINEL' }; 'OPERATION_OK'
        } -Restore { if ($Extra -in @('restore','both')) { throw 'RESTORE_SENTINEL' } }
    } elseif ($Mode -eq 'overlap') {
        Assert-IndexPackageDistinctPaths -Paths @($Build,$Output)
    } else {
        if ($Mode -in @('reparse','dangling')) {
            function Get-Item {
                [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
                $item=Microsoft.PowerShell.Management\\Get-Item -LiteralPath $LiteralPath -Force
                if ($LiteralPath -eq $Build) {
                    return [pscustomobject]@{Attributes=[IO.FileAttributes]::ReparsePoint;PSIsContainer=$true}
                }; return $item
            }
            if ($Mode -eq 'dangling') {
                function Test-Path {
                    [CmdletBinding()]param([string]$LiteralPath)
                    if ($LiteralPath -eq $Build) { return $false }
                    return Microsoft.PowerShell.Management\\Test-Path -LiteralPath $LiteralPath
                }
            }
        }
        $context=Resolve-IndexPackageBuild -BuildDirectory $Build -RequireCollector:($Mode -eq 'collector')
        if ($Mode -eq 'output') { [void](Assert-IndexPackageOutput -Context $context -Path $Output -Fresh) }
        if ($Mode -eq 'executable') { Assert-IndexPackageExecutable -Executable $Output }
    }
    'PACKAGE_BINDING_OK'
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    if ($_.Exception -is [AggregateException]) {
        [Console]::Error.WriteLine('ORIGINAL_RECORDS=' + $_.Exception.Data.Count)
    }
    exit 1
}
''', encoding="utf-8", newline="\n")
        self.expected_argv = None
        for name in ("socket", "getaddrinfo"):
            block = patch.object(socket, name, side_effect=AssertionError("NETWORK_DENIED"))
            block.start()
            self.addCleanup(block.stop)
        block = patch.object(subprocess, "Popen", side_effect=self.allowed_popen)
        block.start()
        self.addCleanup(block.stop)

    def save_cache(self, build: Path | None = None, raw: str | None = None) -> None:
        """実CMakeを起動せず、所有temp内だけに有限cache fixtureを保存する。"""
        text = raw if raw is not None else "".join(key + "=" + value + "\n" for key, value in self.cache.items())
        ((build or self.build) / "CMakeCache.txt").write_text(text, encoding="utf-8", newline="\n")

    def allowed_popen(self, argv, *args, **kwargs):
        """当caseが固定したPS入口argv一件だけを許可する。偽EXE/CMakeは起動しない。"""
        if argv != self.expected_argv:
            raise AssertionError("PACKAGE_CHILD_DENIED")
        return fixed_popen(argv, self.expected_argv, self.root, args, kwargs)

    def child(self, name: str, accepted: bool, reason: str = "", *, mode: str = "build",
              build: Path | None = None, output: Path | None = None, extra: str = "none",
              builder: str | None = None) -> bytes:
        """実PS7 childを10秒で制限し、原byte/終了値と期待理由をcase名へ結合する。"""
        argv = [str(self.tools.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File"]
        if builder:
            argv += [str(self.source / "scripts" / builder), "-BuildDirectory", str(build or self.build)]
            if builder == "package-collector.ps1":
                argv += ["-RegistrySnapshot", str(self.root / "never-a-seed"),
                         "-PythonRuntimeArchive", str(self.root / "never-runtime.zip"),
                         "-PythonExecutable", str(self.root / "never-run.exe"),
                         "-DistributionDataBundle", str(self.root / "never-data")]
            elif builder == "package-collector-installer.ps1":
                argv += ["-PackageDirectory", str(self.root / "never-a-bundle"),
                         "-OutputDirectory", str(self.root / "out/new-installer")]
            elif builder == "test-collector-installer.ps1":
                argv += ["-PackageDirectory", str(self.root / "never-a-bundle"),
                         "-InstallerExecutable", str(self.root / "never-run.exe"),
                         "-FixtureRoot", str(self.root / "out/new-fixture")]
        else:
            argv += [str(self.runner), mode, str(build or self.build), str(output or self.root / "out/fresh"), extra]
        self.expected_argv = argv
        result = subprocess.run(argv, cwd=self.root, capture_output=True, timeout=10, check=False)
        self.assertLessEqual(len(result.stdout) + len(result.stderr), 16384)
        print("P3_PACKAGE_CASE " + json.dumps({"name": name, "exit": result.returncode,
              "expectedAccepted": accepted, "stdoutBase64": base64.b64encode(result.stdout).decode(),
              "stderrBase64": base64.b64encode(result.stderr).decode()}), flush=True)
        self.assertEqual(result.returncode == 0, accepted, name)
        if reason:
            self.assertIn(reason.encode(), result.stderr, name)
        return result.stderr

    def test_package_01_explicit_and_default_location(self) -> None:
        """source/buildと離れた唯一buildの両方を、同じsource/cacheで受理する。"""
        self.child("B01-external", True)
        self.child("B01-source-build", True, build=self.source / "build")

    def test_package_02_source_cache_contract(self) -> None:
        """HOMEの不一致/重複/type/欠損とgenerator/configuration違いを拒否する。"""
        original = dict(self.cache)
        variants = [
            ("private", "CMAKE_HOME_DIRECTORY:INTERNAL", self.root.as_posix(), "INDEX_PACKAGE_SOURCE_MISMATCH"),
            ("generator", "CMAKE_GENERATOR:INTERNAL", "Ninja", "INDEX_PACKAGE_CONFIGURATION_REJECTED"),
            ("configs", "CMAKE_CONFIGURATION_TYPES:STRING", "Release", "INDEX_PACKAGE_CONFIGURATION_REJECTED"),
            ("acceptance", "DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE:BOOL", "ON", "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED"),
            ("acquisition", "DRIVERCRATE_LOCAL_INDEX_ACQUISITION:BOOL", "ON", "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED"),
            ("live", "DRIVERCRATE_BUILD_LIVE_TESTS:BOOL", "ON", "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED"),
            ("analyze", "DRIVERCRATE_ENABLE_ANALYZE:BOOL", "ON", "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED"),
            ("public-blob", "DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB:FILEPATH", "not-empty", "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED"),
            ("public-pin", "DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256:STRING", "a" * 64, "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED"),
            ("embedded", "DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH", "unapproved", "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED"),
        ]
        for name, key, value, reason in variants:
            with self.subTest(name=name):
                self.cache = {**original, key: value}
                self.save_cache()
                self.child("B02-" + name, False, reason)
        for name, transform in (("missing", lambda value: value.replace("CMAKE_HOME_DIRECTORY:INTERNAL=", "OTHER:INTERNAL=")),
                                ("duplicate", lambda value: value + "CMAKE_HOME_DIRECTORY:INTERNAL=" + self.source.as_posix() + "\n"),
                                ("type", lambda value: value.replace("CMAKE_HOME_DIRECTORY:INTERNAL=", "CMAKE_HOME_DIRECTORY:STRING="))):
            self.cache = original
            self.save_cache(raw=transform("".join(key + "=" + value + "\n" for key, value in original.items())))
            self.child("B02-" + name, False, "INDEX_PACKAGE_CACHE_FIELD_REJECTED")

    def test_package_03_path_and_reparse(self) -> None:
        """存在しないbuild/通常file/relativeと合成reparse metadataを拒否する。"""
        self.child("B03-missing", False, "INDEX_PACKAGE_PATH_MISSING", build=self.root / "absent")
        self.child("B03-file", False, "INDEX_PACKAGE_PATH_REJECTED", build=self.build / "CMakeCache.txt")
        self.child("B03-relative", False, "INDEX_PACKAGE_PATH_REJECTED", build=Path("relative"))
        self.child("B03-reparse", False, "INDEX_PACKAGE_PATH_REJECTED", mode="reparse")
        self.child("B03-dangling", False, "INDEX_PACKAGE_PATH_REJECTED", mode="dangling")

    def test_package_04_output_and_overlap(self) -> None:
        """成分境界/既存先/入力包含を拒否し、source/outとworkspace/outの新規childを許す。"""
        self.child("B04-workspace", True, mode="output")
        self.child("B04-source", True, mode="output", output=self.source / "out/fresh")
        self.child("B04-prefix", False, "INDEX_PACKAGE_NEW_OUTPUT_REQUIRED", mode="output", output=self.root / "outside/fresh")
        existing = self.root / "out/existing"
        existing.mkdir(parents=True)
        self.child("B04-existing", False, "INDEX_PACKAGE_NEW_OUTPUT_REQUIRED", mode="output", output=existing)
        self.child("B04-overlap", False, "INDEX_PACKAGE_INPUT_OUTPUT_OVERLAP", mode="overlap", output=self.build / "child")

    def test_package_05_builders_fail_before_fallback(self) -> None:
        """正常なsource/buildがあっても、三builderは明示不一致cacheからfallbackしない。"""
        self.cache["CMAKE_HOME_DIRECTORY:INTERNAL"] = self.root.as_posix()
        self.save_cache()
        for builder in ("package-release.ps1", "package-collector.ps1", "package-collector-installer.ps1",
                        "test-collector-installer.ps1"):
            with self.subTest(builder=builder):
                self.child("B05-" + builder, False, "INDEX_PACKAGE_SOURCE_MISMATCH", builder=builder)
        self.assertFalse((self.root / "out").exists())
        self.assertFalse((self.build / "generated").exists())

    def test_package_06_original_and_restore_failures(self) -> None:
        """復帰は全経路で呼ばれ、二例外がある場合も両方と元ErrorRecordを保持する。"""
        self.child("B06-ok", True, mode="restore")
        self.child("B06-primary", False, "PRIMARY_SENTINEL", mode="restore", extra="primary")
        self.child("B06-restore", False, "RESTORE_SENTINEL", mode="restore", extra="restore")
        error = self.child("B06-both", False, "INSTALLER_BUILD_AND_RESTORE_FAILED", mode="restore", extra="both")
        self.assertIn(b"PRIMARY_SENTINEL", error)
        self.assertIn(b"RESTORE_SENTINEL", error)
        self.assertIn(b"ORIGINAL_RECORDS=2", error)

    def test_package_07_pe_hash_and_x64(self) -> None:
        """実行不能の合成PEを非実行で照合し、x86とhash driftを拒否する。"""
        header = self.source / "src/platform/index_distribution_trust.h"
        header.parent.mkdir(parents=True)
        header.write_bytes(bounded_read(ROOT / "src/platform/index_distribution_trust.h", 16384))
        fingerprint = re.search(r'PUBLIC_FINGERPRINT\s*=\s*"([0-9a-f]{64})"', header.read_text(encoding="utf-8"))[1]
        exe = self.source / "never-run.exe"
        raw = bytearray(512)
        raw[:2] = b"MZ"
        raw[60:64] = (128).to_bytes(4, "little")
        raw[128:132] = b"PE\0\0"
        raw[132:134] = (0x8664).to_bytes(2, "little")
        raw[152:154] = (0x20b).to_bytes(2, "little")
        sidecar = Path(str(exe) + ".index-profile.json")

        def image() -> None:
            """所有の非実行byteと、それへ結合したprofileだけを保存する。"""
            exe.write_bytes(raw)
            sidecar.write_text(json.dumps({"schema": "drivercrate-index-build-profile-v2", "localAcceptance": False,
                "sha256": hashlib.sha256(raw).hexdigest(), "distributionFingerprint": fingerprint,
                "acquisitionPolicyRevision": 1}), encoding="utf-8")

        image()
        self.child("B07-x64", True, mode="executable", output=exe)
        raw[132:134] = (0x14c).to_bytes(2, "little")
        image()
        self.child("B07-x86", False, "INDEX_PACKAGE_X64_REQUIRED", mode="executable", output=exe)
        raw[200] = 1
        exe.write_bytes(raw)
        self.child("B07-stale", False, "INDEX_BUILD_PROFILE_STALE_EXECUTABLE", mode="executable", output=exe)

    def test_package_08_app_only_cache(self) -> None:
        """未生成embedded一keyだけの限定互換とcollectorのON必須を検証する。"""
        self.cache["DRIVERCRATE_BUILD_COLLECTOR:BOOL"] = "OFF"
        del self.cache["DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH"]
        self.save_cache()
        self.child("B08-app-only-missing", True)
        self.child("B08-collector-required", False, "INDEX_PACKAGE_COLLECTOR_BUILD_REQUIRED", mode="collector")
        for builder in ("package-collector.ps1", "package-collector-installer.ps1", "test-collector-installer.ps1"):
            self.child("B08-" + builder, False, "INDEX_PACKAGE_COLLECTOR_BUILD_REQUIRED", builder=builder)
        self.cache["DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH"] = ""
        self.save_cache()
        self.child("B08-app-only-empty", True)
        self.cache["DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH"] = "not-approved"
        self.save_cache()
        self.child("B08-off-invalid-embedded", False, "INDEX_PACKAGE_NORMAL_PROFILE_REQUIRED")
        del self.cache["DRIVERCRATE_COLLECTOR_EMBEDDED_RESOURCES:PATH"]
        self.cache["DRIVERCRATE_BUILD_COLLECTOR:BOOL"] = "ON"
        self.save_cache()
        self.child("B08-on-missing", False, "INDEX_PACKAGE_CACHE_FIELD_REJECTED")
        self.cache["DRIVERCRATE_BUILD_COLLECTOR:BOOL"] = "UNKNOWN"
        self.save_cache()
        self.child("B08-unknown", False, "INDEX_PACKAGE_COLLECTOR_FLAG_REJECTED")
        raw = "".join(key + "=" + value + "\n" for key, value in self.cache.items())
        self.save_cache(raw=raw + "DRIVERCRATE_BUILD_COLLECTOR:BOOL=ON\n")
        self.child("B08-duplicate", False, "INDEX_PACKAGE_CACHE_FIELD_REJECTED")
        self.save_cache(raw=raw.replace("DRIVERCRATE_BUILD_COLLECTOR:BOOL=", "DRIVERCRATE_BUILD_COLLECTOR:STRING="))
        self.child("B08-type", False, "INDEX_PACKAGE_CACHE_FIELD_REJECTED")
        self.save_cache(raw=raw.replace("DRIVERCRATE_BUILD_COLLECTOR:BOOL=UNKNOWN\n", ""))
        self.child("B08-flag-missing", False, "INDEX_PACKAGE_CACHE_FIELD_REJECTED")


class ToolResolverTests(unittest.TestCase):
    """R01–R12の有限resolver契約だけをmockで検査し、native childは起動しない。"""

    def setUp(self) -> None:
        """mock負例の予期しないnative/network呼出しも拒否し、人工probe出力を隔離する。"""
        for target, name in ((socket, "socket"), (socket, "getaddrinfo")):
            guard = patch.object(target, name, side_effect=AssertionError("NETWORK_DENIED"))
            guard.start()
            self.addCleanup(guard.stop)
        guard = patch(__name__ + ".ORIGINAL_POPEN", side_effect=AssertionError("RESOLVER_NATIVE_DENIED"))
        guard.start()
        self.addCleanup(guard.stop)
        self.mock_output = io.StringIO()
        output = redirect_stdout(self.mock_output)
        output.__enter__()
        self.addCleanup(output.__exit__, None, None, None)

    def probe_result(self, stdout: bytes, returncode: int = 0):
        """実toolの代わりに有限な版数出力を返す。"""
        return subprocess.CompletedProcess([], returncode, stdout, b"")

    def test_r01_explicit_priority(self) -> None:
        """明示pathがPATH検索を呼ばず優先される。"""
        path = Path(r"C:\Tools\pwsh.exe")
        with patch.object(shutil, "which") as lookup, patch.object(Path, "resolve", return_value=path), \
                patch.object(Path, "is_file", return_value=True):
            self.assertEqual(tool_path(str(path), "pwsh.exe"), path)
            lookup.assert_not_called()

    def test_r02_path_hit(self) -> None:
        """PATHの絶対hitを解決後のpathへ固定する。"""
        path = Path(r"C:\Tools\cmake.exe")
        with patch.object(shutil, "which", return_value=str(path)) as lookup, \
                patch.object(Path, "resolve", return_value=path), patch.object(Path, "is_file", return_value=True):
            self.assertEqual(tool_path(None, "cmake.exe"), path)
            lookup.assert_called_once_with("cmake.exe")

    def test_r03_path_miss(self) -> None:
        """PATH不在を成功やskipへ数えない。"""
        with patch.object(shutil, "which", return_value=None), self.assertRaisesRegex(ToolResolutionError, "TOOL_NOT_FOUND"):
            tool_path(None, "pwsh.exe")

    def test_r04_spaces_unicode(self) -> None:
        """空白とUnicodeはcommand分割せず一つのpathとして保持する。"""
        path = Path(r"C:\開発 tool\PowerShell 7\pwsh.exe")
        with patch.object(Path, "resolve", return_value=path), patch.object(Path, "is_file", return_value=True):
            self.assertEqual(tool_path(str(path), "pwsh.exe"), path)

    def test_r05_ambiguous_paths(self) -> None:
        """相対/UNC/command文字列をfile照会やnative起動前に拒否する。"""
        cases = ["pwsh.exe", r"C:pwsh.exe", r"C:\tools\..\pwsh.exe", r"\\server\tools\pwsh.exe",
                 r"\\?\C:\tools\pwsh.exe", '"C:\\tools\\pwsh.exe"', r"C:\tools\pwsh.exe -Command exit", ""]
        with patch.object(Path, "resolve") as resolve:
            for value in cases:
                with self.subTest(path=value), self.assertRaises(ToolResolutionError):
                    tool_path(value, "pwsh.exe")
            resolve.assert_not_called()

    def test_r06_missing_directory(self) -> None:
        """不在とdirectoryをnative起動せず拒否する。"""
        path = Path(r"C:\tools\pwsh.exe")
        with patch.object(Path, "resolve", side_effect=FileNotFoundError), self.assertRaisesRegex(ToolResolutionError, "TOOL_FILE_UNAVAILABLE"):
            tool_path(str(path), "pwsh.exe")
        with patch.object(Path, "resolve", return_value=path), patch.object(Path, "is_file", return_value=False), \
                self.assertRaisesRegex(ToolResolutionError, "TOOL_FILE_INVALID"):
            tool_path(str(path), "pwsh.exe")

    def test_r07_wrong_tool(self) -> None:
        """入力名と解決後名の両方を検査しpowershell.exeや偽EXEを起動しない。"""
        for name in ("powershell.exe", "cmd.exe", "never-run.exe"):
            with self.subTest(name=name), self.assertRaises(ToolResolutionError):
                tool_path("C:\\tools\\" + name, "pwsh.exe")
        with patch.object(Path, "resolve", return_value=Path(r"C:\tools\never-run.exe")), \
                patch.object(Path, "is_file", return_value=True), self.assertRaises(ToolResolutionError):
            tool_path(r"C:\tools\pwsh.exe", "pwsh.exe")

    def test_r08_powershell_version(self) -> None:
        """Core7だけをmockで受理し、他版/不正文/非0/timeoutを拒否する。"""
        path = Path(r"C:\tools\pwsh.exe")
        with patch.object(subprocess, "run", return_value=self.probe_result(b"DRIVERCRATE_PS7 Core 7.6.7\r\n")) as run:
            preflight(path, "pwsh.exe")
            self.assertEqual(run.call_args.args[0], [str(path), "-NoLogo", "-NoProfile", "-NonInteractive", "-Command", PS_VERSION_COMMAND])
        for output in (b"DRIVERCRATE_PS7 Desktop 5.1.0", b"DRIVERCRATE_PS7 Core 6.2.0", b"DRIVERCRATE_PS7 Core 8.0.0", b"wrong"):
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=self.probe_result(output)), \
                    self.assertRaisesRegex(ToolResolutionError, "POWERSHELL_7_CORE_REQUIRED"):
                preflight(path, "pwsh.exe")
        with patch.object(subprocess, "run", return_value=self.probe_result(b"", 1)), self.assertRaisesRegex(ToolResolutionError, "TOOL_PROBE_FAILED"):
            preflight(path, "pwsh.exe")
        with patch.object(subprocess, "run", side_effect=subprocess.TimeoutExpired([], 10, output=b"partial")), \
                self.assertRaisesRegex(ToolResolutionError, "TOOL_PROBE_TIMEOUT"):
            preflight(path, "pwsh.exe")

    def test_r09_cmake_version(self) -> None:
        """CMake-Pの既存3.28最低版を維持し、不適合toolはmockだけで拒否する。"""
        path = Path(r"C:\tools\cmake.exe")
        for output in (b"cmake version 3.28.0\n", b"cmake version 4.1.2\n\nCMake suite maintained by Kitware"):
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=self.probe_result(output)) as run:
                preflight(path, "cmake.exe")
                self.assertEqual(run.call_args.args[0], [str(path), "--version"])
        for output, code in ((b"cmake version 3.27.9", 0), (b"wrong tool", 0), (b"cmake version 4.0.0", 1)):
            with self.subTest(output=output), patch.object(subprocess, "run", return_value=self.probe_result(output, code)), self.assertRaises(ToolResolutionError):
                preflight(path, "cmake.exe")

    def test_r10_fixed_probe_deny(self) -> None:
        """固定probe以外のargv/optionsが元Popenへ到達しない。"""
        argv = [r"C:\tools\cmake.exe", "--version"]
        kwargs = {"cwd": ROOT, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        with patch(__name__ + ".ORIGINAL_POPEN") as original:
            fixed_popen(argv, argv, ROOT, (), kwargs)
            original.assert_called_once_with(argv, **kwargs)
            original.reset_mock()
            for command, options in ((["cmd.exe"], kwargs), (argv + ["-P", "evil"], kwargs),
                                     (argv, {**kwargs, "shell": True}), (argv, {**kwargs, "executable": "cmd.exe"}),
                                     (argv, {**kwargs, "env": {}})):
                with self.subTest(command=command, options=options), self.assertRaises(AssertionError):
                    fixed_popen(command, argv, ROOT, (), options)
            original.assert_not_called()

    def test_r11_native_guard_deny(self) -> None:
        """認証済み固定runner/Pだけをmock seamへ通し、偽EXE/任意child/置換を拒否する。"""
        fixture = IndexBuildProfileTests("test_p3_08_denied_runtime_and_network")
        fixture.tools = ProfileTools(Path(r"C:\tools\pwsh.exe"), Path(r"C:\tools\cmake.exe"))
        fixture.root = Path(r"C:\artificial")
        fixture.exe = fixture.root / "never-run.exe"
        fixture.runner = fixture.root / "check.ps1"
        ps = [str(fixture.tools.powershell), "-NoLogo", "-NoProfile", "-NonInteractive", "-File", str(fixture.runner), str(fixture.exe)]
        cmake = [str(fixture.tools.cmake), "-DEXECUTABLE=" + str(fixture.exe), "-DLOCAL_PROFILE=OFF",
                 "-DDISTRIBUTION_FINGERPRINT=" + "0" * 64, "-DACQUISITION_POLICY_REVISION=1", "-P", str(GENERATOR)]
        kwargs = {"cwd": fixture.root, "stdout": subprocess.PIPE, "stderr": subprocess.PIPE}
        with patch(__name__ + ".ORIGINAL_POPEN") as original:
            fixture.allowed_popen(ps, **kwargs)
            fixture.allowed_popen(cmake, **kwargs)
            self.assertEqual(original.call_count, 2)
            original.reset_mock()
            for command in ([str(fixture.exe)], ["powershell.exe"], ["cmd.exe"], [], ps + ["extra"], cmake[:-1] + ["evil.cmake"]):
                with self.subTest(command=command), self.assertRaises(AssertionError):
                    fixture.allowed_popen(command, **kwargs)
            for extra in ({"shell": True}, {"executable": "cmd.exe"}, {"env": {}}):
                with self.subTest(options=extra), self.assertRaises(AssertionError):
                    fixture.allowed_popen(ps, **{**kwargs, **extra})
            original.assert_not_called()

    def test_r12_cli_not_run(self) -> None:
        """tool失敗時は元34件の未実行を非0表示し、resolver-onlyはtoolを解決しない。"""
        with patch(__name__ + ".resolve_tools", side_effect=ToolResolutionError("pwsh.exe: TOOL_NOT_FOUND")), \
                patch("builtins.print") as output, patch.object(unittest.TextTestRunner, "run") as runner:
            self.assertEqual(main(["--suite", "native"]), 2)
            report = json.loads(output.call_args.args[0].removeprefix("P3_NOT_RUN "))
            self.assertEqual((report["methods"], report["nativeCases"], report["status"]), (8, 34, "NOT_RUN"))
            runner.assert_not_called()
        with patch(__name__ + ".resolve_tools") as resolve, patch.object(unittest.TextTestRunner, "run") as runner:
            runner.return_value.wasSuccessful.return_value = True
            self.assertEqual(main(["--suite", "resolver"]), 0)
            resolve.assert_not_called()

    def test_r13_resolved_local_boundary(self) -> None:
        """local link解決は維持し、UNC/device/相対targetをfile照会と版数確認の前に拒否する。"""
        candidate = r"C:\input\pwsh.exe"
        local = Path(r"C:\resolved local\pwsh.exe")
        rejected = (("unc", Path(r"\\server\tools\pwsh.exe")),
                    ("device", Path(r"\\?\C:\tools\pwsh.exe")),
                    ("relative", Path("pwsh.exe")), ("drive-relative", Path("C:pwsh.exe")))
        with patch(__name__ + ".preflight") as probe, patch(__name__ + ".ORIGINAL_POPEN") as native:
            with patch.object(Path, "resolve", return_value=local), \
                    patch.object(Path, "is_file", return_value=True) as file_query:
                self.assertEqual(tool_path(candidate, "pwsh.exe"), local)
                file_query.assert_called_once_with()
            for name, target in rejected:
                with self.subTest(target=name), patch.object(Path, "resolve", return_value=target), \
                        patch.object(Path, "is_file") as file_query:
                    with self.assertRaisesRegex(ToolResolutionError, "TOOL_RESOLVED_PATH_INVALID"):
                        resolve_tools(candidate, r"C:\tools\cmake.exe")
                    file_query.assert_not_called()
            probe.assert_not_called()
            native.assert_not_called()


def main(argv: list[str] | None = None) -> int:
    """明示tool優先でsuiteを選び、tool未実行を非0と元34件の分母付きで報告する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--powershell", help="PowerShell 7 pwsh.exeの絶対path（省略時PATH）")
    parser.add_argument("--cmake", help="cmake.exeの絶対path（省略時PATH）")
    parser.add_argument("--suite", choices=("all", "native", "resolver", "package"), default="all")
    options = parser.parse_args(argv)
    suite = unittest.TestSuite()
    if options.suite != "resolver":
        try:
            IndexBuildProfileTests.tools = resolve_tools(options.powershell, options.cmake)
        except ToolResolutionError as error:
            if options.suite == "package":
                print("P3_PACKAGE_NOT_RUN " + json.dumps({"status": "NOT_RUN", "methods": 8,
                      "reason": str(error)}), flush=True)
                return 2
            print("P3_NOT_RUN " + json.dumps({"status": "NOT_RUN", "methods": 8, "nativeCases": 34,
                                           "additionalPackageMethods": 8 if options.suite == "all" else 0,
                                           "reason": str(error)}), flush=True)
            return 2
        if options.suite != "package":
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(IndexBuildProfileTests))
        if options.suite in {"all", "package"}:
            PackageBuildBindingTests.tools = IndexBuildProfileTests.tools
            suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(PackageBuildBindingTests))
    if options.suite in {"all", "resolver"}:
        suite.addTests(unittest.defaultTestLoader.loadTestsFromTestCase(ToolResolverTests))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
