"""実child/pipeの専用native試験用packageを自己所有tempへ作る。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
製品package builderではなく、実HTTP/Task/鍵/driverを起動しない試験utilityである。
"""
import ast
import base64
import copy
from datetime import datetime, timedelta, timezone
import gzip
import io
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import zipfile

import collector_collection_profiles as cp
import collector_distribution_pipeline as pipeline
import collector_distribution_data as data
import collector_locator_snapshot as snapshot
import collector_registry as cr
import collector_public_locators as pl
from test_collector_distribution_pipeline import Fixture
from test_collector_collection_profiles import AS_OF, fixture_inputs


def parsed_payload(prefix, rows):
    """架空INFの原本文と全参照fileを通常ZIP parser用に固定する。"""
    output = io.BytesIO()
    expected = []
    with zipfile.ZipFile(output, "w", zipfile.ZIP_STORED) as archive:
        for stem, models, identifier, version in rows:
            inf = (f'[Version]\r\nSignature="$Windows NT$"\r\nClass=Net\r\n'
                   'ClassGuid={4d36e972-e325-11ce-bfc1-08002be10318}\r\nProvider=%Vendor%\r\n'
                   f'DriverVer=10/22/2026,{version}\r\nCatalogFile={stem}.cat\r\n'
                   f'[Manufacturer]\r\n%Vendor%={models},NTamd64\r\n[{models}.NTamd64]\r\n'
                   f'%Device%=Install,{identifier}\r\n[Install]\r\nCopyFiles=Files\r\n'
                   f'[Files]\r\n{stem}.sys\r\n[DestinationDirs]\r\nFiles=12\r\n'
                   f'[SourceDisksNames]\r\n1="fixture"\r\n[SourceDisksFiles]\r\n{stem}.sys=1\r\n'
                   f'[Strings]\r\nVendor="{prefix} Synthetic Vendor"\r\nDevice="{stem}"\r\n')
            for suffix, raw in (("inf", inf.encode()), ("sys", (stem + " nonexecuting bytes").encode()),
                                ("cat", (stem + " unsigned synthetic catalog").encode())):
                name = stem + "." + suffix
                entry = zipfile.ZipInfo(name, (2026, 10, 22, 0, 0, 0))
                archive.writestr(entry, raw)
                expected.append({"name": name, "sha256": cr.digest(raw), "infOwner": stem + ".inf"})
    return output.getvalue(), expected


def prepare_existing_update(base, inputs, value, edits, a_files, b_files):
    """収集済みと同じB identityの新版を共通upsertで確認待ちへ移す。待機stateは扱わない。"""
    package = base / "package"
    updated_payload, updated_files = parsed_payload("Beta", [
        ("new-beta", "UpdatedBetaModels", "TESTBUS\\FRESH_BETA_0063", "7.8.9.10")])
    html = '<html><a href="driver-v2.zip">manually reviewed B update</a></html>'
    page_url = "https://maker-b.example.org/download/001/release-2/"
    registry, locators = copy.deepcopy(inputs["registry"]), copy.deepcopy(inputs["locators"])
    registry["revision"] = "fixture-b-update"
    registry["sources"][1]["officialPage"] = page_url
    record = registry["records"][1]
    record.update(packageVersion="2.0", driverVersion="7.8.9.10", downloadUrl=page_url + "driver-v2.zip",
                  publishedSha256=cr.digest(updated_payload))
    for observation in registry["observations"]:
        if observation["recordId"] == record["id"]:
            observation.update(evidenceUrl=page_url, evidenceSha256=cr.digest(html.encode()))
    for locator in locators["locators"]:
        if locator["sourceId"] == record["sourceId"]:
            locator["url"] = page_url if locator["purpose"] == "PAGE" else record["downloadUrl"]
            if locator["pageObservation"]:
                locator["pageObservation"].update(bodySha256=cr.digest(html.encode()), bodyBytes=len(html))
    locators.update(revision="locators-b-update", registry=pl.registry_binding(registry))
    updated_inputs = cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
    edit = copy.deepcopy(edits["profiles"][1])
    edit.update(revision="profile-b-update", href="driver-v2.zip")
    for review in edit["review"].values():
        review["evidence"]["bodySha256"] = cr.digest(html.encode())
        review["evidence"]["contentSha256"] = cp.page_content_sha256(html.encode())
    pending = cp.upsert_profiles(value, updated_inputs, {"schema": cp.EDIT_SCHEMA, "profiles": [edit]},
        revision="native-b-pending", as_of=AS_OF, previous_inputs=inputs, reviewed_profile_ids=(edit["id"],))
    cr.require(pending["profiles"][1]["reviewState"] == "REVIEW_REQUIRED", "FIXTURE_SAME_CALL_REVIEW")
    edit["revision"] = "profile-b-reviewed"
    review_edits = {"schema": cp.EDIT_SCHEMA, "profiles": [edit]}
    # 先行CURRENTを生成しても旧activeからの直接importは拒否されることを負例にする。
    early = cp.upsert_profiles(pending, updated_inputs, review_edits, revision="native-b-reviewed", as_of=AS_OF,
                               reviewed_profile_ids=(edit["id"],))
    for name, context, profiles in (("data-existing-first", inputs, value),
                                   ("data-update-pending", updated_inputs, pending),
                                   ("data-update-early-current", updated_inputs, early)):
        data.write_bundle(base / name, data.bundle_content({"registry": cr.json_bytes(context["registry"]),
            "locators": cr.json_bytes(context["locators"]), "profiles": cr.json_bytes(profiles)}))
    pipeline.save_json(base / "update-review-edits.json", review_edits)
    pipeline.save_json(package / "fixture-signature-files.json", {"a": a_files, "b": b_files, "bUpdated": updated_files},
                       replace=True)
    (package / "fixture-page-b-updated.txt").write_text(html, encoding="utf-8", newline="\n")
    (package / "fixture-payload-b-updated.bin").write_bytes(updated_payload)


def existing_update_stages(base, pins):
    """確認待ちの実import後に別の明示upsertを行い、同じEXE/moduleで更新Bを収集する。"""
    package, root = base / "package", base / "workspace"
    checkpoints = []

    def unchanged(stage):
        current = {member: cr.digest((package / member).read_bytes()) for member in pins}
        cr.require(current == pins, "FIXTURE_CODE_CHANGED_DURING_EXISTING_UPDATE")
        checkpoints.append({"stage": stage, "hashes": current})

    def run(stage, mode):
        result = subprocess.run([str(package / "DriverCrateCollectorSetup.exe"), str(package), str(root), mode],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, check=False)
        with (base / (stage + ".log")).open("xb") as stream:
            stream.write(result.stdout)
        print(result.stdout.decode("utf-8", errors="backslashreplace"), end="", flush=True)
        cr.require(result.returncode == 0, "FIXTURE_EXISTING_UPDATE_" + stage.upper())
        unchanged(stage)
        return result.stdout

    first = run("pending-import", "--existing-update-data-fixture")
    cr.require(b"DATA_B1_REVIEW_REQUIRED" in first, "FIXTURE_DIRECT_CURRENT_WRONG_REJECTION")
    pending = base / "data-update-pending"
    active = data.active_bundle(root)
    cr.require(active["sha256"] == data.verify_bundle(pending)["sha256"] and
               active["profiles"]["profiles"][1]["reviewState"] == "REVIEW_REQUIRED", "FIXTURE_PENDING_NOT_ACTIVE")
    # この独立した共通CLI呼出しは確認待ち世代がactiveになった事実を確認してから行う。
    reviewed = base / "reviewed-profiles.json"
    code = cp.main(["upsert", "--registry", str(pending / "registry.json"),
        "--locators", str(pending / "locators.json"), "--profiles", str(pending / "collection-profiles.json"),
        "--edits", str(base / "update-review-edits.json"), "--revision", "native-b-reviewed", "--as-of", AS_OF,
        "--review-profile", "profile-001", "--output", str(reviewed)])
    cr.require(code == 0, "FIXTURE_EXPLICIT_REVIEW")
    data.write_bundle(base / "data-update-current", data.bundle_content({**active["raw"], "profiles": cp.read_raw(reviewed)}))
    cr.require(data.active_bundle(root)["sha256"] == active["sha256"], "FIXTURE_REVIEW_CHANGED_ACTIVE")
    unchanged("separate-explicit-review")
    run("current-import-update", "--existing-update-complete-fixture")
    pipeline.save_json(base / "unchanged-code-hashes.json", {"before": pins, "checkpoints": checkpoints})
    inspect_existing_update(base)
    return 0


def inspect_existing_update(base):
    """原archive・実producer原byte・旧ledger・保持期限を独立に照合し、有限証拠を保存する。"""
    package, root = base / "package", base / "workspace"
    evidence = base / "update-evidence"
    store = root / "monitor/distribution"
    stages = {stage: {kind: cr.read_json(evidence / f"{stage}-{kind}.json") for kind in ("active", "head", "journal")}
              for stage in ("first", "rejected", "pending", "updated", "final")}
    first, pending, updated, final = (stages[stage] for stage in ("first", "pending", "updated", "final"))
    cr.require(stages["rejected"] == first, "FIXTURE_REJECTED_CHANGED_ACTIVE_HEAD_OR_LEDGER")
    for stage in (pending, updated, final):
        cr.require(all(stage["journal"]["requests"][key] == row for key, row in first["journal"]["requests"].items()),
                   "FIXTURE_OLD_URL_WAIT_OR_CHARGE_CHANGED")
    cr.require(len(first["journal"]["requests"]) == 4 and len(updated["journal"]["requests"]) == 6 and
               final["journal"]["requests"] == updated["journal"]["requests"], "FIXTURE_URL_LEDGER_COUNTS")
    cr.require(pending["head"] == first["head"] and final["head"] == updated["head"] and
               first["head"]["generation"] == 1 and updated["head"]["generation"] == 2, "FIXTURE_HEAD_HISTORY")
    journal = pipeline.verify_layout(store)
    run_sets = [set(stages[stage]["journal"]["runs"]) for stage in ("first", "pending", "updated", "final")]
    run_ids = [next(iter(run_sets[0])), *[next(iter(run_sets[index] - run_sets[index - 1])) for index in range(1, 4)]]
    runs = [journal["runs"][identifier] for identifier in run_ids]
    cr.require([len(run["jobs"]) for run in runs] == [2, 0, 1, 0], "FIXTURE_RUN_JOB_COUNTS")
    cr.require(any(row["profileId"] == "profile-001" and "REVIEW_REQUIRED" in row["reasons"]
                   for row in runs[1]["targets"]), "FIXTURE_PENDING_B_NOT_HELD")
    cr.require(all(any(row["profileId"] == "profile-000" and row["reasons"] == ["WAIT_24H"]
                       for row in run["targets"]) for run in runs[1:]), "FIXTURE_A_WAIT_NOT_PRESERVED")

    def candidates(head):
        rows = []
        for reference in head["includedCandidates"]:
            raw = cp.read_raw(store / "runs" / reference["runId"] / reference["member"])
            cr.require(cr.digest(raw) == reference["sha256"], "FIXTURE_CANDIDATE_HASH")
            rows.append(cr.parse_json(raw))
        return {row["job"]["recordId"]: row for row in rows}

    old_candidates, new_candidates = candidates(first["head"]), candidates(updated["head"])
    old_a, new_a = old_candidates["record-000"], new_candidates["record-000"]
    old_b, new_b = old_candidates["record-001"], new_candidates["record-001"]
    cr.require(old_a == new_a and len(new_a["records"]) == 2, "FIXTURE_A_CANDIDATE_OR_EXPIRY_CHANGED")
    cr.require(all(old_b["job"][name] == new_b["job"][name] for name in ("sourceId", "recordId", "products")),
               "FIXTURE_EXISTING_B_IDENTITY_CHANGED")
    for candidate, member, version, models in ((old_b, "fixture-payload-b.bin", "3.4.5.6", "NeverRegisteredBeta.NTamd64"),
                                              (new_b, "fixture-payload-b-updated.bin", "7.8.9.10", "UpdatedBetaModels.NTamd64")):
        raw = (package / member).read_bytes()
        record = candidate["records"][0]
        with zipfile.ZipFile(io.BytesIO(raw)) as archive:
            inf = archive.read("new-beta.inf")
        identity = record["publishedIdentityEvidence"]
        cr.require(record["version"]["value"] == version and identity["modelSection"] == models and
                   identity["pnpIds"] == [{"kind": "HARDWARE", "value": "TESTBUS\\FRESH_BETA_0063"}] and
                   identity["infIdentity"] == "new-beta.inf" and identity["evidenceSha256"] == cr.digest(inf) and
                   record["packageEvidence"]["calculatedHash"]["sha256"] == cr.digest(raw) and
                   f"DriverVer=10/22/2026,{version}".encode() in inf and models.encode() in inf,
                   "FIXTURE_B_ARCHIVE_INF_NOT_REFLECTED")
    cr.require(old_b["job"]["record"]["publishedSha256"] != new_b["job"]["record"]["publishedSha256"] and
               new_b["job"]["record"]["driverVersion"] == "7.8.9.10", "FIXTURE_B_UPDATE_NOT_MATERIAL")
    output = store / "runs" / updated["head"]["runId"]
    raw = {member: cp.read_raw(output / member) for member in updated["head"]["outputs"]}
    cr.require(all(cr.digest(content) == updated["head"]["outputs"][member] for member, content in raw.items()) and
               gzip.decompress(raw["index.json.gz"]) == raw["index.json"], "FIXTURE_PRODUCER_OUTPUT_BYTES")
    index, manifest = cr.parse_json(raw["index.json"]), cr.parse_json(raw["manifest.raw.json"])
    records = []
    for row in index["records"]:
        content = base64.b64decode(row["recordBytesBase64"], validate=True)
        cr.require(cr.digest(content) == row["recordSha256"], "FIXTURE_RECORD_HASH")
        records.append(cr.parse_json(content))
    cr.require(sorted(records, key=lambda row: row["recordId"]) == sorted(new_a["records"] + new_b["records"],
               key=lambda row: row["recordId"]) and len(records) == 3 and
               manifest["expiresAtUtc"] == min(row["validUntilUtc"] for row in new_candidates.values()) == old_a["validUntilUtc"],
               "FIXTURE_GENERATED_INDEX_OR_ORIGINAL_EXPIRY")
    active = data.active_bundle(root)
    cr.require(active["sha256"] == data.verify_bundle(base / "data-update-current")["sha256"] and
               len(list((root / "data/generations").iterdir())) == 3 and
               all(row["reviewState"] == "CURRENT" for row in active["profiles"]["profiles"]), "FIXTURE_FINAL_ACTIVE")
    pipeline.save_json(base / "existing-update-result.json", {"status": "PASS", "fixture": str(base),
        "runIds": run_ids, "jobCounts": [len(run["jobs"]) for run in runs], "firstGets": 4, "updatedBGets": 2,
        "pendingGets": 0, "aResends": 0, "nextGets": 0, "oldUrlLedgerEntriesUnchanged": 4,
        "sameBRecordAndProducts": True, "originalAUnchanged": True, "originalAExpiry": old_a["validUntilUtc"],
        "oldBArchiveSha256": old_b["job"]["record"]["publishedSha256"],
        "updatedBArchiveSha256": new_b["job"]["record"]["publishedSha256"],
        "updatedBInfSha256": new_b["records"][0]["publishedIdentityEvidence"]["evidenceSha256"],
        "updatedBVersion": "7.8.9.10", "manifest": str(output / "manifest.raw.json"),
        "gzip": str(output / "index.json.gz"), "outputHashes": updated["head"]["outputs"],
        "candidateRecords": len(records), "generation": 2, "dataGenerations": 3,
        "realNetwork": 0, "realTask": 0, "actualCatAccepted": False, "driverInstall": 0, "coverageIncrease": 0})


def main():
    """指定した専用test EXEと同じ実module/runtimeを新規fixtureへ固定する。"""
    binary = Path(sys.argv[1]).resolve(strict=True)
    if sys.argv[3:] == ["--hash-only"]:
        cases = [{"bytes": size, "sha256": cr.digest(b"x" * size), "accepted": size <= cr.MAX_JSON_BYTES}
                 for size in (1048576, 1048577, 8388608, 8388609, 16777216, 16777217)]
        files = []
        for name in ("registry.json", "locators.json"):
            path = Path(__file__).resolve().parents[1] / "data/collector-registry" / name
            raw = cp.read_raw(path)
            files.append({"path": str(path), "bytes": len(raw), "sha256": cr.digest(raw)})
        document = {"cases": cases, "files": files}
        manifest = Path(sys.argv[2]).resolve(strict=True) / "hash-fixture-expectations.json"
        if manifest.exists():
            cr.require(cr.read_json(manifest) == document, "HASH_EXPECTATIONS_CHANGED")
        else:
            pipeline.save_json(manifest, document)
        return subprocess.run([str(binary), "--hash-fixture", str(manifest)], check=False).returncode
    base = Path(tempfile.mkdtemp(prefix="dc-native-distribution-", dir=Path(sys.argv[2])))
    subprocess.run([str(binary), "--prepare-fixture", str(base)], check=True)
    package, root = base / "package", base / "workspace"
    mode = sys.argv[3:]
    fresh_weekly = "--fresh-weekly-evidence" in mode
    if fresh_weekly:
        mode = [value for value in mode if value != "--fresh-weekly-evidence"]
        cr.require(mode in (["--parsed-producer-fixture"], ["--nested-producer-fixture"]),
                   "WEEKLY_FIXTURE_MODE")
    fresh_now = datetime.now(timezone.utc).replace(microsecond=0)
    fresh_stamp = fresh_now.strftime("%Y-%m-%dT%H:%M:%SZ")
    parsed_mode = mode in (["--parsed-producer-fixture"], ["--parsed-producer-mutated-fixture"], ["--daily-data-fixture"],
                          ["--existing-update-data-fixture"], ["--nested-producer-fixture"])
    producer_mode = parsed_mode or mode in (["--producer-fixture"], ["--producer-partial-fixture"], ["--producer-failed-fixture"])
    if mode == ["--existing-update-data-fixture"]:
        source_inputs, source_value, _ = fixture_inputs()
    else:
        source = Fixture(same_page=not producer_mode)
        source_inputs, source_value = source.inputs, source.value
    registry = source_inputs["registry"]
    locators = source_inputs["locators"]
    html = ('<html><a href="driver.zip">new package</a></html>' if producer_mode else
            '<html><a href="driver-0.zip">A</a><a href="driver-1.zip">B</a></html>')
    payload = b"PK-fake-inspection-archive"
    other_payload = b"PK-other-fake-archive"
    if parsed_mode:
        mutated = mode == ["--parsed-producer-mutated-fixture"]
        payload, a_files = parsed_payload("Alpha", [
            ("fresh-alpha", "FreshAlphaModels", "TESTBUS\\FRESH_ALPHA_0091" if mutated else
             "TESTBUS\\FRESH_ALPHA_0041", "4.5.6.7" if mutated else "2.3.4.5"),
            ("unexpected-alpha", "UnregisteredAlphaModels", "TESTBUS\\FRESH_ALPHA_0052", "2.3.4.5")])
        other_payload, b_files = parsed_payload("Beta", [
            ("new-beta", "NeverRegisteredBeta", "TESTBUS\\FRESH_BETA_0063", "3.4.5.6")])
        if mode == ["--nested-producer-fixture"]:
            nested = io.BytesIO()
            with zipfile.ZipFile(nested, "w", zipfile.ZIP_STORED) as outer:
                outer.writestr(zipfile.ZipInfo("nested+release/package.zip", (2026, 10, 22, 0, 0, 0)), payload)
            payload = nested.getvalue()
        pipeline.save_json(package / "fixture-signature-files.json", {"a": a_files, "b": b_files})
    page_hash = cr.digest(html.encode())
    for index, record in enumerate(registry["records"]):
        record["publishedSha256"] = cr.digest(other_payload if producer_mode and index == 1 else payload)
        record["driverVersion"] = "0.9.0.0"
    for observation in registry["observations"]:
        observation["evidenceSha256"] = page_hash
        if producer_mode and observation["recordId"] == registry["records"][0]["id"]:
            observation["checkedAt"] = "2026-10-21T00:00:00Z"
        if fresh_weekly:
            observation["checkedAt"] = (fresh_now - timedelta(hours=int(
                observation["recordId"] == registry["records"][0]["id"]))).strftime("%Y-%m-%dT%H:%M:%SZ")
    if fresh_weekly:
        registry["asOf"] = locators["asOf"] = fresh_stamp
    for locator in locators["locators"]:
        if locator["pageObservation"]:
            locator["pageObservation"].update(bodySha256=page_hash, bodyBytes=len(html))
            if producer_mode and locator["sourceId"] == registry["records"][0]["sourceId"]:
                locator["pageObservation"]["checkedAt"] = "2026-10-21T00:00:00Z"
            if fresh_weekly:
                locator["pageObservation"]["checkedAt"] = (fresh_now - timedelta(hours=int(
                    locator["sourceId"] == registry["records"][0]["sourceId"]))).strftime("%Y-%m-%dT%H:%M:%SZ")
    locators["registry"] = pl.registry_binding(registry)
    inputs = cp.load_inputs(cr.json_bytes(registry), cr.json_bytes(locators))
    edits = {"schema": cp.EDIT_SCHEMA, "profiles": []}
    for profile in source_value["profiles"]:
        row = {key: profile[key] for key in cp.PROFILE_FIELDS}
        for review in row["review"].values():
            review["evidence"]["bodySha256"] = page_hash
            review["evidence"]["contentSha256"] = cp.page_content_sha256(html.encode())
            if producer_mode and row["recordId"] == registry["records"][0]["id"]:
                review["evidence"]["checkedAt"] = "2026-10-21T00:00:00Z"
            if fresh_weekly:
                review["evidence"]["checkedAt"] = (fresh_now - timedelta(hours=int(
                    row["recordId"] == registry["records"][0]["id"]))).strftime("%Y-%m-%dT%H:%M:%SZ")
        edits["profiles"].append(row)
    value = cp.upsert_profiles(None, inputs, edits, revision="native-01", as_of=fresh_stamp if fresh_weekly else AS_OF)
    if mode == ["--existing-update-data-fixture"]:
        prepare_existing_update(base, inputs, value, edits, a_files, b_files)
    if mode == ["--daily-data-fixture"]:
        old_registry = copy.deepcopy(registry)
        for key in ("sources", "records"):
            old_registry[key] = old_registry[key][:1]
        old_registry["products"] = [row for row in old_registry["products"] if row["recordIds"] == [registry["records"][0]["id"]]]
        old_registry["observations"] = [row for row in old_registry["observations"] if row["recordId"] == registry["records"][0]["id"]]
        old_locators = copy.deepcopy(locators)
        old_locators["locators"] = [row for row in old_locators["locators"] if row["sourceId"] == registry["sources"][0]["id"]]
        old_locators["registry"] = pl.registry_binding(old_registry)
        old_inputs = cp.load_inputs(cr.json_bytes(old_registry), cr.json_bytes(old_locators))
        old_value = cp.upsert_profiles(None, old_inputs, {"schema": cp.EDIT_SCHEMA, "profiles": edits["profiles"][:1]},
                                       revision="native-first", as_of=AS_OF)
        added_value = cp.upsert_profiles(old_value, inputs, {"schema": cp.EDIT_SCHEMA, "profiles": edits["profiles"][1:]},
            revision="native-added", as_of=AS_OF, previous_inputs=old_inputs)
        for name, registry_doc, locators_doc, profile_doc in (("data-first", old_registry, old_locators, old_value),
                                                            ("data-added", registry, locators, added_value)):
            data.write_bundle(base / name, data.bundle_content({"registry": cr.json_bytes(registry_doc),
                "locators": cr.json_bytes(locators_doc), "profiles": cr.json_bytes(profile_doc)}))
    (package / "seed/collector-data").mkdir(parents=True)
    for member, raw in snapshot.snapshot_content(registry, locators).items():
        target = package / "seed/collector-data" / member
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    data.write_bundle(package / "seed/distribution-data", data.bundle_content({
        "registry": cr.json_bytes(registry), "locators": cr.json_bytes(locators), "profiles": cr.json_bytes(value)}))
    (package / "config").mkdir()
    pipeline.save_json(package / "config/monitor-policy.json", {"schema": "dc-registry-monitor-policy-v1",
        "revision": "fixture", "heldSourceIds": []})
    pipeline.save_json(package / "config/targets.json", {"schema": "dc-collector-targets-v1",
        "targets": [{"source": "INTEL_ETHERNET_WINDOWS11", "publicModel": "", "operatingSystem": "Windows 11 64-bit", "category": ""}]})
    # 私有caller fixtureの最小結合だけを作る。製品の全package文法は通常setupで別検証する。
    pipeline.save_json(package / "package-manifest.json", {"schema": "dc-collector-package-v7",
        "mode": "EXPLICIT_DISTRIBUTION_DATA_DAILY"})
    pipeline.save_json(package / "install-receipt.json", {"schema": "dc-collector-install-receipt-v3",
        "packageManifestSha256": cr.digest((package / "package-manifest.json").read_bytes()),
        "installedUtc": "2026-10-23T00:00:00Z"})
    (package / "fixture-page.txt").write_text(html, encoding="utf-8", newline="\n")
    (package / "fixture-payload.bin").write_bytes(payload)
    (package / "fixture-payload-b.bin").write_bytes(other_payload)
    shutil.copyfile(binary, package / "DriverCrateCollectorSetup.exe")
    legacy_binary = binary.parent / "drivercrate_collector_setup_admission_tests.exe"
    legacy = base / "legacy-template"
    subprocess.run([str(legacy_binary), "--fixture", str(legacy)], check=True)
    for area in ("runs", "current"):
        for path in (legacy / area).iterdir():
            if path.suffix == ".json":
                target = package / "fixture-legacy" / area / path.name
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
    scripts = package / "scripts"
    scripts.mkdir()
    repository_scripts = Path(__file__).resolve().parent
    pending = ["collector_workspace", "collector_distribution_pipeline", "collector_collection_profiles"]
    copied = set()
    while pending:
        module = pending.pop()
        if module in copied:
            continue
        path = repository_scripts / (module + ".py")
        if not path.is_file():
            continue
        copied.add(module)
        shutil.copyfile(path, scripts / path.name)
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Import):
                pending.extend(alias.name.split(".")[0] for alias in node.names)
            elif isinstance(node, ast.ImportFrom) and node.module:
                pending.append(node.module.split(".")[0])
    runtime = package / "runtime"
    runtime.mkdir()
    python = Path(sys.base_prefix)
    for path in [python / "python.exe", *python.glob("*.dll"), *(python / "DLLs").glob("*.pyd"),
                 *(python / "DLLs").glob("*.dll")]:
        shutil.copyfile(path, runtime / path.name)
    with zipfile.ZipFile(runtime / "python313.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for path in (python / "Lib").rglob("*.py"):
            member = path.relative_to(python / "Lib")
            if not any(part in {"site-packages", "test", "tests", "idlelib", "tkinter", "ensurepip"} for part in member.parts):
                archive.write(path, member.as_posix())
    # Fixed isolated childでは外部site/環境を参照しない。
    (runtime / "python313._pth").write_text("python313.zip\n.\n", encoding="utf-8")
    import collector_workspace as workspace
    pipeline.save_json(root / "workspace.json", workspace.binding(package))
    pins_before = {str(path.relative_to(package)): cr.digest(path.read_bytes()) for path in
        [package / "DriverCrateCollectorSetup.exe", *sorted(scripts.glob("*.py"))]}
    if mode == ["--existing-update-data-fixture"]:
        for path in sorted(runtime.iterdir()):
            pins_before[str(path.relative_to(package))] = cr.digest(path.read_bytes())
        result = existing_update_stages(base, pins_before)
        print("NATIVE_EXISTING_UPDATE_FIXTURE", base, "exit", result, flush=True)
        return result
    result = subprocess.run([str(package / "DriverCrateCollectorSetup.exe"), str(package), str(root), *mode], check=False)
    if mode == ["--daily-data-fixture"] and result.returncode == 0:
        reference_bundle = base / "reference-data"
        active = data.active_bundle(root)
        data.write_bundle(reference_bundle, data.bundle_content(active["raw"], data.reference_content(root / "monitor")))
        cr.require(subprocess.run([str(package / "DriverCrateCollectorSetup.exe"), str(package), str(root),
            "--import-reference-fixture", str(reference_bundle)], check=False).returncode == 0, "FIXTURE_REFERENCE_IMPORT")
        cr.require(data.active_bundle(root)["manifest"]["includesReference"] is True, "FIXTURE_REFERENCE_NOT_IMPORTED")
    pins_after = {member: cr.digest((package / member).read_bytes()) for member in pins_before}
    cr.require(pins_before == pins_after, "FIXTURE_CODE_CHANGED_DURING_DATA_IMPORT")
    if result.returncode == 0 and mode in ([], ["--parsed-producer-fixture"],
            ["--page-mismatch-fixture"], ["--page-incomplete-fixture"], ["--page-oversize-fixture"]):
        journal = pipeline.verify_layout(root / "monitor/distribution")
        body_count = 0
        for run_id, run in journal["runs"].items():
            directory = root / "monitor/distribution/runs" / run_id
            for ordinal, row in enumerate(run["jobs"]):
                if row["resultSha256"] is None:
                    continue
                native = pipeline.read_hash(directory / row["resultMember"], row["resultSha256"])
                path = directory / f"page-{ordinal}.body"
                complete = native["pageTransfer"]["completion"] == "COMPLETE"
                cr.require(path.exists() == complete, "FIXTURE_PAGE_BODY_COMPLETENESS")
                if not complete:
                    continue
                expected = html.encode() + (b"<!-- same-response-change -->" if mode == ["--page-mismatch-fixture"] else b"")
                raw = path.read_bytes()
                cr.require(raw == expected and cr.digest(raw) == native["pageObservation"]["bodySha256"] and
                           len(raw) == native["pageObservation"]["bodyBytes"], "FIXTURE_PAGE_BODY_ORIGINAL_BYTES")
                body_count += 1
                for member in pipeline.BUILD_MEMBERS - {"build-plan.json", "unsigned-validation.json", "build-commit.json"}:
                    if (directory / member).exists():
                        exported = (directory / member).read_bytes()
                        cr.require(raw not in exported and path.name.encode() not in exported,
                                   "FIXTURE_PAGE_BODY_PUBLIC_LEAK")
        print("NATIVE_PAGE_BODY", "members", body_count, "public_body_members", 0, flush=True)
    if mode == ["--daily-data-fixture"]:
        pipeline.save_json(base / "unchanged-code-hashes.json", pins_before)
    if mode == ["--parent-death"]:
        cr.require(result.returncode == 73, "FIXTURE_PARENT_DID_NOT_DIE")
        import registry_daily_monitor as monitor
        with monitor.writer_lock(root / "monitor"):
            state = monitor.verify_store(root / "monitor")
            journal = pipeline.verify_layout(root / "monitor/distribution")
            pipeline.recover(root / "monitor", state, journal, monitor.utc_now())
            cr.require(journal["requests"] and all(row["phase"] == "SETTLED_MAXIMUM" for row in journal["requests"].values()),
                       "FIXTURE_PARENT_DEATH_RESERVATION_LOST")
        print("NATIVE_PARENT_DEATH maximum_charged=1 resend=0", base, flush=True)
        return 0
    print("NATIVE_FIXTURE", base, "exit", result.returncode, flush=True)
    return result.returncode


if __name__ == "__main__":
    raise SystemExit(main())
