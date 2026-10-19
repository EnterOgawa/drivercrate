"""保存済み監視exportを実CLIで移設し、通信しない初回確認を実行する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
HTTPは拒否するfakeに固定し、元snapshot・台帳・policyを変更しない。
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import sys

import collector_registry as cr
import registry_daily_monitor as dm


def verify(snapshot: Path, registry: Path, policy: Path, output: Path) -> dict:
    """新規解析root内だけでimport・同日待機・再export・上書き拒否を照合する。

    二つのCLI呼出しにはそれぞれtimeout=30を指定する。途中の不一致・拒否・I/O失敗は伝播し、
    新規解析root、部分移設先、再exportや報告を自動削除・rollbackしない。
    """
    original_state, original_content = dm.export_content(snapshot)
    cr.check_ancestors(output)
    cr.regular_path(output.parent, directory=True)
    cr.require(output.is_absolute() and not output.exists(), "OUTPUT_EXISTS")
    output.mkdir(exist_ok=False)
    destination = output / "移設 host & data"
    command = [sys.executable, "-X", "utf8", "-B", str(Path(__file__).with_name("registry_daily_monitor.py")),
               "import-export", str(snapshot.absolute()), str(destination), "--confirm-source-stopped"]
    result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    cr.require(result.returncode == 0 and json.loads(result.stdout) == {"result": "OK"}, "IMPORT_CLI_FAILED")
    cr.require(dm.verify_store(destination) == original_state, "IMPORT_STATE_CHANGED")
    copied = 0
    for name, raw in original_content.items():
        if name != "manifest.json":
            cr.require(dm.read_import_bytes(destination / name) == raw, "IMPORT_PAYLOAD_CHANGED")
            copied += 1
    calls = []

    def no_network(kind: str, url: str) -> dict:
        """実通信を絶対に開始せず、予期しない取得呼出しを数える。"""
        calls.append(kind)
        raise AssertionError("unexpected-http-call")

    report = dm.run_once(cr.read_json(registry), cr.read_json(policy), destination, transport=no_network)
    cr.require(not calls and report["counts"]["attempted"] == 0, "IMPORT_UNEXPECTED_HTTP")
    after = dm.verify_store(destination)
    cr.require(after["requests"] == original_state["requests"] and after["hosts"] == original_state["hosts"],
               "IMPORT_WAIT_CHANGED")
    exported = output / "after-import-export"
    dm.export_store(destination, exported)
    cr.require(dm.verify_export(exported) == after, "IMPORT_REEXPORT_FAILED")
    _, source_after = dm.export_content(snapshot)
    cr.require(source_after == original_content, "SOURCE_CHANGED")
    refused = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", timeout=30, check=False)
    cr.require(refused.returncode == 2 and json.loads(refused.stderr)["reason"] == "OUTPUT_EXISTS",
               "IMPORT_OVERWRITE_ACCEPTED")
    verification = {"result": "PASSED", "sourceManifestSha256": cr.digest(original_content["manifest.json"]),
                    "sourceFiles": len(original_content), "copiedPayloadFiles": copied,
                    "requests": len(original_state["requests"]), "hosts": len(original_state["hosts"]),
                    "firstRunCounts": report["counts"], "httpCalls": len(calls), "sourceUnchanged": True,
                    "existingOutputRejected": True, "tasksRegistered": 0, "driverDownloads": 0,
                    "driverInstalls": 0, "githubWrites": 0}
    dm.write_new_bytes(output / "verification.json", cr.json_bytes(verification))
    return verification


def main() -> int:
    """明示した保存済みexportだけを新規解析directoryで検査する。"""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("snapshot", type=Path)
    parser.add_argument("registry", type=Path)
    parser.add_argument("policy", type=Path)
    parser.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        print(json.dumps(verify(args.snapshot, args.registry, args.policy, args.output), sort_keys=True))
        return 0
    except (cr.RegistryError, OSError, ValueError, TypeError, KeyError, subprocess.TimeoutExpired) as error:
        code = str(error) if isinstance(error, cr.RegistryError) else type(error).__name__
        print(json.dumps({"result": "REJECTED", "reason": code}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
