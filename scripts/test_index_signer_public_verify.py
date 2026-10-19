"""公開byteだけの配布検証CLIをRAM人工鍵・実UTCで有限回帰する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0

実鍵操作・通信・導入を行わない。signerとRAM-only unitのpathは明示指定する。
全caseのargv/raw出力/結果を新規rootに保持し、失敗・NOT_RUNを分母から除外しない。
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import time

CASE_NAMES = (
    "F01-current-metadata", "F02-expired-current-refused", "F02-expired-exact-history",
    "F03-acquisition", "F05-future-history-refused", "F05-arbitrary-history-refused",
    "F04-metadata-pin", "F04-history-pin", "F04-acquisition-pin",
    "F04-metadata-pss", "F04-history-pss", "F04-acquisition-pss",
    "F04-metadata-asset", "F04-history-asset", "F04-acquisition-asset",
)
HISTORY_CASE_NAMES = (
    "AH01-current-history", "AH02-expired-history", "AH03-expired-current",
    "AH04-future-history", "AH05-arbitrary-publication", "AH06-metadata-purpose",
    "AH07-wrong-pin", "AH08-wrong-pss", "AH09-modified-gzip",
    "AH10-missing-publication", "AH11-invalid-publication", "AH12-public-cap",
)
MAX_FILE = 1024 * 1024
MAX_RETAINED = 16 * 1024 * 1024
PRIVATE_ATTRIBUTES = ("rsaBits=", "exportPolicy=", "usage=", "userKey=", "protectionVerified=")


class Evidence:
    """新規出力への保存前に各byte数を明示加算する有限recorder。"""

    def __init__(self, root: Path):
        """既存でないrootを作り、保存予算と直接launchのreceipt集合を所有する。

        rootの削除や保存量のrollbackはこのrecorderでは行わず、証拠を残す。
        """
        root.mkdir(parents=True, exist_ok=False)
        self.root = root
        self.reserved = 0
        self.receipts = []

    def save(self, name: str, data: bytes):
        """単file上限を通ったbyteを総予算へ先に加算し、新規fileへ保存する。

        総予算超過やxb書込みの失敗でも加算を戻さず、既存fileを上書きしない。
        """
        if len(data) > MAX_FILE:
            raise ValueError("ARTIFACT_SIZE_CAP")
        self.reserved += len(data)
        if self.reserved > MAX_RETAINED:
            raise ValueError("ARTIFACT_TOTAL_CAP")
        print(f"ARTIFACT_RESERVE name={name} bytes={len(data)} total={self.reserved}", flush=True)
        with (self.root / name).open("xb") as stream:
            stream.write(data)

    def document(self, name: str, value):
        self.save(name, (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))

    def launch(self, name: str, argv: list[str]):
        """明示argvを直列実行し、stderrを含む原byteと直接launchだけを記録する。"""
        start = time.monotonic()
        receipt = {"case": name, "argv": argv, "startedUtc": datetime.now(timezone.utc).isoformat(),
                   "timeoutSeconds": 180, "allProcessCount": None}
        try:
            result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, timeout=180)
            stdout, stderr, code = result.stdout, result.stderr, result.returncode
        except subprocess.TimeoutExpired as error:
            stdout, stderr, code = error.stdout or b"", error.stderr or b"", None
            receipt["failure"] = "TIMEOUT"
        receipt.update(exitCode=code, elapsedSeconds=time.monotonic() - start)
        self.save(name + ".stdout.raw", stdout)
        self.save(name + ".stderr.raw", stderr)
        self.document(name + ".receipt.json", receipt)
        self.receipts.append(receipt)
        return code, stdout, stderr


def success_errors(name, stdout, info, historical):
    """成功結果と既存prefix/公開facts/非保護確認の意味を完全なfield集合で確認する。"""
    errors = []
    lines = stdout.decode("utf-8", errors="strict").splitlines()
    expected = (f"LOCAL_INDEX_PUBLIC fingerprint={info['fingerprint']} keyId={info['keyId']}"
                " bytes=411 publicOnly=1 privateKeyQueried=0")
    if [line for line in lines if line.startswith("LOCAL_INDEX_PUBLIC ")] != [expected]:
        errors.append("PUBLIC_FACTS_MISMATCH")
    if any(attribute in stdout.decode("ascii") for attribute in PRIVATE_ATTRIBUTES):
        errors.append("PRIVATE_ATTRIBUTES_PRESENT")
    result = [line for line in lines if line.startswith("LOCAL_INDEX_RESULT ")]
    if len(result) != 1 or not result[0].startswith("LOCAL_INDEX_RESULT code=0x00000000 "):
        errors.append("RESULT_CONTRACT")
    if result and not result[0].endswith(" created=0 protected=0"):
        errors.append("PUBLIC_PROTECTION_NOT_QUERIED")
    history = [line for line in lines if line.startswith("LOCAL_INDEX_HISTORY_VERIFIED ")]
    if history != (["LOCAL_INDEX_HISTORY_VERIFIED freshness=0"] if historical else []):
        errors.append("HISTORY_FRESHNESS_CONTRACT")
    return errors


def run(signer: Path, unit: Path, output: Path) -> int:
    """人工fixtureを生成し、旧15件とhistory12件を固定分母のまま直列検査する。

    前提失敗でも未到達caseをNOT_RUNとして残し、個別失敗を全成功へ変えない。
    出力rootはEvidenceが保持し、process数は記録できた直接launchだけである。
    """
    evidence = Evidence(output)
    cases = [{"case": name, "status": "NOT_RUN", "errors": []}
             for name in CASE_NAMES + HISTORY_CASE_NAMES]
    fixture = output / "fixtures"
    try:
        code, _, _ = evidence.launch("fixture-generation", [str(unit), "--public-verify-history-fixtures", str(fixture)])
        if code != 0:
            raise ValueError("FIXTURE_GENERATION_FAILED")
        info = json.loads((fixture / "fixture-info.json").read_bytes())
        if info["protectedKeyOperations"] != 0 or info["artificialSignatures"] != 6:
            raise ValueError("FIXTURE_KEY_CONTRACT")
        if hashlib.sha256((fixture / "public.blob").read_bytes()).hexdigest() != info["fingerprint"]:
            raise ValueError("FIXTURE_PUBLIC_PIN")
        fixture_pins = []
        fixture_total = 0
        for path in sorted(fixture.iterdir()):
            raw = path.read_bytes()
            if len(raw) > MAX_FILE:
                raise ValueError("FIXTURE_SIZE_CAP")
            fixture_total += len(raw)
            fixture_pins.append({"name": path.name, "bytes": len(raw),
                                 "sha256": hashlib.sha256(raw).hexdigest()})
        if fixture_total > MAX_FILE or len(fixture_pins) != 18:
            raise ValueError("FIXTURE_CLOSED_SET")
        evidence.reserved += fixture_total  # Native generator reserved each file before creation.
        evidence.document("fixture-pins.json", fixture_pins)
        for prefix in ("current", "expired", "acquisition"):
            raw = (fixture / (prefix + ".manifest.raw.json")).read_bytes()
            envelope = json.loads((fixture / (prefix + ".manifest.json")).read_bytes())
            if base64.b64decode(envelope["manifestBytesBase64"], validate=True) != raw:
                raise ValueError("ORIGINAL_MANIFEST_BINDING")
        changed = bytearray((fixture / "current.index.json.gz").read_bytes())
        changed[-1] ^= 1
        evidence.save("metadata-modified.index.json.gz", bytes(changed))
        changed = bytearray((fixture / "acquisition.index.json.gz").read_bytes())
        changed[-1] ^= 1
        evidence.save("acquisition-modified.index.json.gz", bytes(changed))
        bad_acquisition = json.loads((fixture / "acquisition.manifest.json").read_bytes())
        signature = bytearray(base64.b64decode(bad_acquisition["signatureBase64"], validate=True))
        signature[0] ^= 1
        bad_acquisition["signatureBase64"] = base64.b64encode(signature).decode("ascii")
        evidence.document("acquisition-bad-pss.manifest.json", bad_acquisition)
        evidence.save("public-over-cap.blob", (fixture / "public.blob").read_bytes() + b"\0")
        for prefix in ("history-expired", "history-future"):
            raw = (fixture / (prefix + ".manifest.raw.json")).read_bytes()
            envelope = json.loads((fixture / (prefix + ".manifest.json")).read_bytes())
            if base64.b64decode(envelope["manifestBytesBase64"], validate=True) != raw:
                raise ValueError("HISTORY_ORIGINAL_MANIFEST_BINDING")

        def arguments(mode, manifest="current.manifest.json", packed="current.index.json.gz", pin=None, seconds=None):
            argv = [str(signer), mode, str(fixture / manifest), str(fixture / packed),
                    str(fixture / "public.blob"), pin or info["fingerprint"]]
            if seconds is not None:
                argv.append(str(seconds))
            return argv

        normal, history, acquisition = "--distribution-verify", "--distribution-verify-history", "--distribution-acquisition-verify"
        old_seconds = info["expiredPublishedSeconds"]
        planned = [
            (arguments(normal), True, False),
            (arguments(normal, "expired.manifest.json"), False, False),
            (arguments(history, "expired.manifest.json", seconds=old_seconds), True, True),
            (arguments(acquisition, "acquisition.manifest.json", "acquisition.index.json.gz"), True, False),
            (arguments(history, "expired.manifest.json", seconds=info["generatedSeconds"]+86400), False, False),
            (arguments(history, "expired.manifest.json", seconds=old_seconds+1), False, False),
        ]
        wrong_pin = "0" * 64 if info["fingerprint"] != "0" * 64 else "1" * 64
        for mode in (normal, history, acquisition):
            planned.append((arguments(mode, "acquisition.manifest.json" if mode == acquisition else "current.manifest.json",
                                      "acquisition.index.json.gz" if mode == acquisition else "current.index.json.gz",
                                      pin=wrong_pin, seconds=info["publishedSeconds"] if mode == history else None), False, False))
        planned.extend([
            (arguments(normal, "wrong-pss.manifest.json"), False, False),
            (arguments(history, "wrong-pss.manifest.json", seconds=info["publishedSeconds"]), False, False),
            ([str(signer), acquisition, str(output / "acquisition-bad-pss.manifest.json"),
              str(fixture / "acquisition.index.json.gz"), str(fixture / "public.blob"), info["fingerprint"]], False, False),
        ])
        for mode in (normal, history, acquisition):
            argv = arguments(mode, "acquisition.manifest.json" if mode == acquisition else "current.manifest.json",
                             seconds=info["publishedSeconds"] if mode == history else None)
            argv[3] = str(output / ("acquisition-modified.index.json.gz" if mode == acquisition else "metadata-modified.index.json.gz"))
            planned.append((argv, False, False))
        if len(planned) != len(CASE_NAMES):
            raise ValueError("FIXED_DENOMINATOR")
        evidence.document("plan-cases.json", [{"case": name, "argv": argv, "expectedSuccess": success,
                                             "expectedHistorical": historical}
                                            for name, (argv, success, historical) in zip(CASE_NAMES, planned)])
        acquisition_history = "--distribution-acquisition-verify-history"
        history_planned = [
            (arguments(acquisition_history, "acquisition.manifest.json", "acquisition.index.json.gz",
                       seconds=info["publishedSeconds"]), True, None),
            (arguments(acquisition_history, "history-expired.manifest.json", "history-expired.index.json.gz",
                       seconds=old_seconds), True, None),
            (arguments(acquisition, "history-expired.manifest.json", "history-expired.index.json.gz"), False, None),
            (arguments(acquisition_history, "history-future.manifest.json", "history-future.index.json.gz",
                       seconds=info["futurePublishedSeconds"]), False, b"LOCAL_INDEX_REJECTED code=0x00000057"),
            (arguments(acquisition_history, "acquisition.manifest.json", "acquisition.index.json.gz",
                       seconds=info["publishedSeconds"] + 1), False, b"LOCAL_INDEX_RESULT code=0x0000000d"),
            (arguments(acquisition_history, seconds=info["publishedSeconds"]), False,
             b"LOCAL_INDEX_RESULT code=0x0000000d"),
            (arguments(acquisition_history, "acquisition.manifest.json", "acquisition.index.json.gz",
                       pin=wrong_pin, seconds=info["publishedSeconds"]), False,
             b"LOCAL_INDEX_RESULT code=0x0000000d"),
        ]
        bad_pss = arguments(acquisition_history, "acquisition.manifest.json", "acquisition.index.json.gz",
                            seconds=info["publishedSeconds"])
        bad_pss[2] = str(output / "acquisition-bad-pss.manifest.json")
        bad_gzip = arguments(acquisition_history, "acquisition.manifest.json", "acquisition.index.json.gz",
                             seconds=info["publishedSeconds"])
        bad_gzip[3] = str(output / "acquisition-modified.index.json.gz")
        no_seconds = arguments(acquisition_history, "acquisition.manifest.json", "acquisition.index.json.gz")
        invalid_seconds = no_seconds + ["not-a-time"]
        oversized_public = arguments(acquisition_history, "acquisition.manifest.json", "acquisition.index.json.gz",
                                     seconds=info["publishedSeconds"])
        oversized_public[4] = str(output / "public-over-cap.blob")
        history_planned.extend([
            (bad_pss, False, None), (bad_gzip, False, None),
            (no_seconds, False, b"LOCAL_INDEX_REJECTED code=0x00000057"),
            (invalid_seconds, False, b"LOCAL_INDEX_REJECTED code=0x00000057"),
            (oversized_public, False, b"LOCAL_INDEX_REJECTED code=0x0000000d"),
        ])
        if len(history_planned) != len(HISTORY_CASE_NAMES):
            raise ValueError("HISTORY_FIXED_DENOMINATOR")
        evidence.document("history-plan-cases.json", [
            {"case": name, "argv": argv, "expectedSuccess": success,
             "expectedMarker": marker.decode("ascii") if marker else None}
            for name, (argv, success, marker) in zip(HISTORY_CASE_NAMES, history_planned)])
        for case, (argv, success, historical) in zip(cases, planned):
            try:
                code, stdout, stderr = evidence.launch(case["case"], argv)
                errors = []
                if code != (0 if success else 2):
                    errors.append("EXIT_CODE_MISMATCH")
                if stderr:
                    errors.append("UNEXPECTED_STDERR")
                if success:
                    errors += success_errors(case["case"], stdout, info, historical)
                elif b"LOCAL_INDEX_PUBLIC " in stdout or b"LOCAL_INDEX_HISTORY_VERIFIED " in stdout:
                    errors.append("FAILURE_EMITTED_SUCCESS")
                case.update(status="FAIL" if errors else "PASS", errors=errors)
            except (OSError, UnicodeError, ValueError) as error:
                case.update(status="FAIL", errors=[type(error).__name__ + ":" + str(error)])
        for case, (argv, success, marker) in zip(cases[len(CASE_NAMES):], history_planned):
            try:
                code, stdout, stderr = evidence.launch(case["case"], argv)
                errors = []
                if code != (0 if success else 2):
                    errors.append("EXIT_CODE_MISMATCH")
                if stderr:
                    errors.append("UNEXPECTED_STDERR")
                if success:
                    errors += success_errors(case["case"], stdout, info, True)
                    if b"LOCAL_INDEX_COMPLETED\r\n" not in stdout and b"LOCAL_INDEX_COMPLETED\n" not in stdout:
                        errors.append("MISSING_TERMINAL_MARKER")
                elif b"LOCAL_INDEX_PUBLIC " in stdout or b"LOCAL_INDEX_HISTORY_VERIFIED " in stdout:
                    errors.append("FAILURE_EMITTED_SUCCESS")
                if any(attribute.encode("ascii") in stdout for attribute in PRIVATE_ATTRIBUTES):
                    errors.append("PRIVATE_ATTRIBUTES_PRESENT")
                if marker is not None and marker not in stdout:
                    errors.append("EXPECTED_ERROR_MARKER_MISMATCH")
                case.update(status="FAIL" if errors else "PASS", errors=errors)
            except (OSError, UnicodeError, ValueError) as error:
                case.update(status="FAIL", errors=[type(error).__name__ + ":" + str(error)])
    except (OSError, ValueError, KeyError) as error:
        evidence.document("prerequisite-failure.json", {"error":type(error).__name__ + ":" + str(error)})
    result = {"schema":"public-verify-cli-regression-v1", "cases":cases,
              "passed":sum(case["status"] == "PASS" for case in cases), "fixedDenominator":len(cases),
              "legacyDenominator":len(CASE_NAMES), "historyDenominator":len(HISTORY_CASE_NAMES),
              "legacyPassed":sum(case["status"] == "PASS" for case in cases[:len(CASE_NAMES)]),
              "historyPassed":sum(case["status"] == "PASS" for case in cases[len(CASE_NAMES):]),
              "allPassed":all(case["status"] == "PASS" for case in cases),
              "knownDirectLaunches":len(evidence.receipts), "allProcessCount":None,
              "realSigningOperations":0, "protectedKeyOperations":0, "network":0}
    evidence.document("result.json", result)
    print(json.dumps(result, ensure_ascii=False), flush=True)
    return 0 if result["allPassed"] else 1


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--signer", type=Path, required=True)
    parser.add_argument("--fixture-unit", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    return run(args.signer.resolve(strict=True), args.fixture_unit.resolve(strict=True), args.output.resolve())


if __name__ == "__main__":
    raise SystemExit(main())

