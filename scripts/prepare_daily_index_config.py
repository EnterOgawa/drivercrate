"""配布公開blob取得後にだけローカル固定pin/scope/configを新規生成する（鍵照会なし）。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
収集・Task登録・GitHub操作を開始しない。既存stateRootを作成/変更しない。
"""
import argparse
from pathlib import Path
import shutil
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))
import daily_index_pipeline as pipeline

VERIFIED_UNSIGNED_ARGUMENTS = (
    "predecessor_presign_marker", "predecessor_presign_marker_sha256", "checkpoint_inspection_sha256",
    "checkpoint_script_sha256", "budget_witness", "budget_witness_sha256")
METADATA_INPUT_ARGUMENTS = ("acquisition_scope", "acquisition_scope_sha256", "original_body", "original_body_sha256") + tuple(
    name + suffix for name in ("original_release", "original_review", "original_script") for suffix in ("_sha256",)) + tuple(
    "binding_" + role + suffix for role in ("release", "body", "review", "script") for suffix in ("", "_sha256"))


def prepare_public_context(args) -> Path:
    """原v3/履歴/承認pinを構造認証し、同controlの固定rootだけをCREATE_NEWする。"""
    names = {"public_context_from_history", "public_history_sha256", "public_config", "public_config_sha256"}
    pipeline.require(all(getattr(args, name, None) is not None for name in names), "PUBLIC_CONTEXT_PREPARE_INPUTS")
    pipeline.require(all(value is None or name in names or
        (name == "selected_inf" and value == "PRO2500/Winx64/W11/e2fn.inf") for name, value in vars(args).items()),
        "PUBLIC_CONTEXT_PREPARE_MIXED_MODE")
    version = Path(pipeline.__file__).resolve().parent
    pipeline.require(Path(__file__).resolve() == version / "prepare_daily_index_config.py", "PROTECTED_PREPARER_LOCATION")
    config_path = pipeline.normal_path(str(args.public_config))
    history_path = pipeline.normal_path(str(args.public_context_from_history))
    pipeline.require(config_path.name == "config.json" and history_path == config_path.parent / "history.json" and
        pipeline.protected_root() / "control" in config_path.parents, "PUBLIC_CONTEXT_LOCATION")
    config, scope, digest = pipeline.load_config(config_path)
    pipeline.require(config.get("schema") == pipeline.PUBLIC_CONFIG_SCHEMA and digest == args.public_config_sha256 and
        pipeline.public_sha(args.public_history_sha256), "PUBLIC_CONTEXT_CONFIG")
    pipeline.protected_path(history_path)
    raw = pipeline.read(history_path, 65536)
    pipeline.require(pipeline.sha(raw) == args.public_history_sha256, "PUBLIC_HISTORY_PIN")
    history = pipeline.cr.parse_json(raw)
    pipeline.public_history_record(config, scope, digest, (history_path, args.public_history_sha256),
        operation_day=history["operationDay"])
    record = {"schema": "dc-public-daily-context-v1", "kind": "BOOTSTRAP_ANCHORED_PUBLIC_CYCLE",
        "publicConfigFile": str(config_path), "publicConfigSha256": digest,
        "bootstrapHistoryFile": str(history_path), "bootstrapHistorySha256": args.public_history_sha256,
        "publisherApprovalSha256": config["publicPublisherApprovalSha256"],
        "dayPolicy": "JST_NATIVE_RUN_DAY_V1", "scheduleSha256": pipeline.public_schedule_pin(config)}
    path = config_path.parent / "public-context.json"
    pipeline.write_new(path, pipeline.canonical(record))
    pipeline.public_context_record(config, scope, digest, (path, pipeline.sha(pipeline.canonical(record))))
    return path


def prepare_public_config(args) -> Path:
    """通常v2または明示歴史metadataの意味を保持し、新v3だけをCREATE_NEWする。実運用は開かない。"""
    required = ("public_config_from", "predecessor_config_sha256", "public_publisher_approval_sha256",
                "control_directory")
    pipeline.require(all(getattr(args, name, None) is not None for name in required), "PUBLIC_PREPARE_INPUTS")
    historical = getattr(args, "public_history_envelope", None) is not None
    pipeline.require(historical == (getattr(args, "public_history_envelope_sha256", None) is not None),
                     "PUBLIC_HISTORICAL_INPUTS")
    forbidden = ("public_key", "fingerprint", "smoke_local", "first_daily_local", "new_output_root",
        "inherit_config", "repair_config", "continue_presign_config", "manifest_file", "collector_exe", "signer_exe",
        "predecessor_start", "predecessor_start_sha256", "continuation_receipt", "continuation_receipt_sha256",
        "prior_native_calls", "prior_elapsed_seconds", "original_release", "original_review", "original_script",
        "archive", "legacy_receipt", "legacy_raw_manifest", "legacy_gzip", "legacy_envelope", "fence_receipt",
        "predecessor_repair_marker", "predecessor_repair_marker_sha256", "phase_evidence", "phase_evidence_sha256",
        "content_evidence", "content_evidence_sha256", "failure_terminal", "failure_terminal_sha256",
        "checkpoint_body_sha256", "checkpoint_release_sha256") + VERIFIED_UNSIGNED_ARGUMENTS
    forbidden = tuple(name for name in forbidden if not historical or name not in {"collector_exe", "signer_exe"})
    pipeline.require(all(getattr(args, name, None) is None for name in forbidden) and
        getattr(args, "selected_inf", None) in {None, "PRO2500/Winx64/W11/e2fn.inf"},
        "PUBLIC_PREPARE_MIXED_MODE")
    version = Path(pipeline.__file__).resolve().parent
    pipeline.require(Path(__file__).resolve() == version / "prepare_daily_index_config.py",
                     "PROTECTED_PREPARER_LOCATION")
    source = pipeline.normal_path(str(args.public_config_from))
    if historical:
        pipeline.require(args.collector_exe is not None and args.signer_exe is not None, "PUBLIC_HISTORICAL_INPUTS")
        old_raw = pipeline.read(source, 65536)
        old, digest = pipeline.cr.parse_json(old_raw), pipeline.sha(old_raw)
    else:
        old, _, digest = pipeline.load_config(source)
    pipeline.require(old["schema"] == "dc-private-daily-index-config-v2", "PUBLIC_PREDECESSOR_SCHEMA")
    pipeline.require(type(args.predecessor_config_sha256) is str and
                     args.predecessor_config_sha256 == digest, "PUBLIC_PREDECESSOR_PIN")
    config = dict(old, schema=pipeline.PUBLIC_CONFIG_SCHEMA, predecessorConfigFile=str(source),
        predecessorConfigSha256=digest, publicPublisherApprovalSha256=args.public_publisher_approval_sha256)
    if historical:
        config.update(collectorExe=str(pipeline.normal_path(str(args.collector_exe))),
            collectorSha256=pipeline.sha(pipeline.read(args.collector_exe)),
            signerExe=str(pipeline.normal_path(str(args.signer_exe))),
            signerSha256=pipeline.sha(pipeline.read(args.signer_exe)),
            pipelineSha256=pipeline.sha(pipeline.read(version / "daily_index_pipeline.py")),
            producerSha256=pipeline.sha(pipeline.read(version / "project_collected_native_index.py")),
            modulePins={name: pipeline.sha(pipeline.read(version / name)) for name in sorted(pipeline.MODULE_NAMES)},
            historicalPredecessor={"schema": "dc-public-historical-predecessor-v1",
                "envelopeFile": str(pipeline.normal_path(str(args.public_history_envelope))),
                "envelopeSha256": args.public_history_envelope_sha256})
    pipeline.validate_public_config(config)
    control = pipeline.normal_path(str(args.control_directory), exists=False)
    pipeline.require(pipeline.protected_root() / "control" in control.parents and not control.exists(),
                     "NEW_CONTROL_DIRECTORY")
    pipeline.protected_path(control.parent)
    # 全検査の後だけ新directoryを作り、既存config/scope/output/stateを変更しない。
    control.mkdir()
    path = control / "config.json"
    pipeline.write_new(path, pipeline.canonical(config))
    pipeline.load_config(path)
    return path


def continue_verified_unsigned_config(args, *, budget=None) -> Path:
    """既存明示入口だけで、旧preSignの四原fileを保持する一回caller更新を準備する。"""
    started = time.monotonic()
    pipeline.require(all(getattr(args, name, None) is None for name in
        ("public_key", "fingerprint", "smoke_local", "first_daily_local", "new_output_root", "inherit_config",
         "repair_config", "predecessor_start", "predecessor_start_sha256", "continuation_receipt",
         "continuation_receipt_sha256", "original_release", "original_review", "original_script", "archive",
         "legacy_receipt", "legacy_raw_manifest", "legacy_gzip", "legacy_envelope", "fence_receipt",
         "predecessor_repair_marker", "predecessor_repair_marker_sha256", "phase_evidence", "phase_evidence_sha256",
         "content_evidence", "content_evidence_sha256")), "VERIFIED_UNSIGNED_INPUTS")
    required = VERIFIED_UNSIGNED_ARGUMENTS + ("continue_presign_config", "predecessor_config_sha256",
        "checkpoint_body_sha256", "checkpoint_release_sha256", "failure_terminal", "failure_terminal_sha256",
        "prior_native_calls", "prior_elapsed_seconds", "control_directory", "collector_exe", "signer_exe")
    pipeline.require(all(getattr(args, name, None) is not None for name in required), "VERIFIED_UNSIGNED_INPUTS")
    old, scope, old_hash = pipeline.load_config(args.continue_presign_config, verified_unsigned_predecessor=True)
    pipeline.require(old_hash == args.predecessor_config_sha256, "VERIFIED_UNSIGNED_PIN")
    pipeline.require(pipeline.sha(pipeline.canonical(scope)) == old["scopeSha256"], "VERIFIED_UNSIGNED_SCOPE_BYTES")
    out = pipeline.operation_root(Path(old["outputRoot"]))
    control = pipeline.normal_path(str(args.control_directory), exists=False)
    pipeline.require(pipeline.protected_root() / "control" in control.parents and not control.exists(),
                     "NEW_CONTROL_DIRECTORY")
    pipeline.protected_path(control.parent)
    version = Path(pipeline.__file__).resolve().parent
    pipeline.require(Path(__file__).resolve() == version / "prepare_daily_index_config.py",
                     "PROTECTED_PREPARER_LOCATION")
    config = dict(old, scopeFile=str(control / "scope.json"), collectorExe=str(args.collector_exe),
        signerExe=str(args.signer_exe), modulePins={name: pipeline.sha(pipeline.read(version / name))
        for name in sorted(pipeline.MODULE_NAMES)},
        pipelineSha256=pipeline.sha(pipeline.read(version / "daily_index_pipeline.py")))
    config["preSignContinuation"] = {"schema": pipeline.VERIFIED_UNSIGNED_SCHEMA,
        "configFile": str(args.continue_presign_config), "configSha256": old_hash,
        "markerFile": str(args.predecessor_presign_marker), "markerSha256": args.predecessor_presign_marker_sha256,
        "bodySha256": args.checkpoint_body_sha256, "releaseSha256": args.checkpoint_release_sha256,
        "inspectionSha256": args.checkpoint_inspection_sha256, "scriptSha256": args.checkpoint_script_sha256,
        "failureTerminalFile": str(args.failure_terminal), "failureTerminalSha256": args.failure_terminal_sha256,
        "budgetWitnessFile": str(args.budget_witness), "budgetWitnessSha256": args.budget_witness_sha256,
        "priorNativeCalls": args.prior_native_calls, "priorElapsedSeconds": args.prior_elapsed_seconds,
        "preparationNativeCalls": 2, "preparationElapsedSeconds": 0}
    budget = budget or pipeline.Budget()
    if isinstance(budget, pipeline.Budget):
        budget.directory = out
    with pipeline.exclusive(out / "pipeline.lock"):
        pipeline.protected_tree(out)
        checkpoint = pipeline.validate_presign_continuation(config, initial=True)
        pipeline.carry_code_repair_budget(budget, args.prior_native_calls, args.prior_elapsed_seconds)
        pipeline.verify_reservation(config, checkpoint["path"], checkpoint["raw"], budget, "FRESH_INPUT")
        manifest, _ = pipeline.unpack_envelope(pipeline.read(Path(old["legacyMetadata"]["envelopeFile"]), 98304))
        code, _, _ = budget.run([config["signerExe"], "--distribution-verify-floor-history",
            old["legacyMetadata"]["envelopeFile"], old["legacyMetadata"]["gzipFile"], config["publicKeyFile"],
            config["fingerprint"], str(int(pipeline.parse_time(manifest["publishedAtUtc"]).timestamp()))])
        pipeline.require(code == 0, "LEGACY_METADATA_HISTORY_FAILED")
        config["preSignContinuation"]["preparationElapsedSeconds"] = time.monotonic() - started
        pipeline.validate_presign_continuation(config, initial=True)
        control.mkdir()
        pipeline.write_new(control / "scope.json", pipeline.canonical(scope))
        pipeline.write_new(control / "config.json", pipeline.canonical(config))
        pipeline.load_config(control / "config.json")
    return control / "config.json"


def continue_presign_config(args, *, budget=None) -> Path:
    """既存明示入口で二原file継承または閉じた四原file更新を準備する。"""
    if any(getattr(args, name, None) is not None for name in VERIFIED_UNSIGNED_ARGUMENTS):
        return continue_verified_unsigned_config(args, budget=budget)
    started = time.monotonic()
    pipeline.require(all(getattr(args, name, None) is None for name in
        ("public_key", "fingerprint", "smoke_local", "first_daily_local", "new_output_root", "inherit_config",
         "repair_config", "predecessor_start", "predecessor_start_sha256", "continuation_receipt",
         "continuation_receipt_sha256", "original_release", "original_review", "original_script", "archive",
         "legacy_receipt", "legacy_raw_manifest", "legacy_gzip", "legacy_envelope", "fence_receipt")),
        "PRESIGN_INPUTS")
    required = ("continue_presign_config", "predecessor_config_sha256", "predecessor_repair_marker",
        "predecessor_repair_marker_sha256", "checkpoint_body_sha256", "checkpoint_release_sha256",
        "phase_evidence", "phase_evidence_sha256", "content_evidence", "content_evidence_sha256",
        "failure_terminal", "failure_terminal_sha256", "prior_native_calls", "prior_elapsed_seconds",
        "control_directory", "collector_exe", "signer_exe")
    pipeline.require(all(getattr(args, name, None) is not None for name in required), "PRESIGN_INPUTS")
    old, scope, old_hash = pipeline.load_config(args.continue_presign_config, presign_predecessor=True)
    pipeline.require(old_hash == args.predecessor_config_sha256, "PRESIGN_PIN")
    out = pipeline.operation_root(Path(old["outputRoot"]))
    control = pipeline.normal_path(str(args.control_directory), exists=False)
    pipeline.require(pipeline.protected_root() / "control" in control.parents and not control.exists(),
                     "NEW_CONTROL_DIRECTORY")
    pipeline.protected_path(control.parent)
    version = Path(pipeline.__file__).resolve().parent
    pipeline.require(Path(__file__).resolve() == version / "prepare_daily_index_config.py", "PROTECTED_PREPARER_LOCATION")
    config = dict(old, scopeFile=str(control / "scope.json"), collectorExe=str(args.collector_exe),
        signerExe=str(args.signer_exe), modulePins={name: pipeline.sha(pipeline.read(version / name))
        for name in sorted(pipeline.MODULE_NAMES)}, pipelineSha256=pipeline.sha(pipeline.read(version / "daily_index_pipeline.py")))
    config["preSignContinuation"] = {"schema": "dc-daily-presign-continuation-v1",
        "configFile": str(args.continue_presign_config), "configSha256": old_hash,
        "markerFile": str(args.predecessor_repair_marker), "markerSha256": args.predecessor_repair_marker_sha256,
        "bodySha256": args.checkpoint_body_sha256, "releaseSha256": args.checkpoint_release_sha256,
        "phaseEvidenceFile": str(args.phase_evidence), "phaseEvidenceSha256": args.phase_evidence_sha256,
        "contentEvidenceFile": str(args.content_evidence), "contentEvidenceSha256": args.content_evidence_sha256,
        "failureTerminalFile": str(args.failure_terminal), "failureTerminalSha256": args.failure_terminal_sha256,
        "priorNativeCalls": args.prior_native_calls, "priorElapsedSeconds": args.prior_elapsed_seconds,
        "preparationNativeCalls": 2, "preparationElapsedSeconds": 0}
    budget = budget or pipeline.Budget()
    if isinstance(budget, pipeline.Budget):
        budget.directory = out
    with pipeline.exclusive(out / "pipeline.lock"):
        pipeline.protected_tree(out)
        checkpoint = pipeline.validate_presign_continuation(config, initial=True)
        pipeline.carry_code_repair_budget(budget, args.prior_native_calls, args.prior_elapsed_seconds)
        pipeline.verify_reservation(config, checkpoint["path"], checkpoint["raw"], budget, "FRESH_INPUT")
        manifest, _ = pipeline.unpack_envelope(pipeline.read(Path(old["legacyMetadata"]["envelopeFile"]), 98304))
        code, _, _ = budget.run([config["signerExe"], "--distribution-verify-floor-history",
            old["legacyMetadata"]["envelopeFile"], old["legacyMetadata"]["gzipFile"], config["publicKeyFile"],
            config["fingerprint"], str(int(pipeline.parse_time(manifest["publishedAtUtc"]).timestamp()))])
        pipeline.require(code == 0, "LEGACY_METADATA_HISTORY_FAILED")
        config["preSignContinuation"]["preparationElapsedSeconds"] = time.monotonic() - started
        pipeline.validate_presign_continuation(config, initial=True)
        control.mkdir()
        pipeline.write_new(control / "scope.json", pipeline.canonical(scope))
        pipeline.write_new(control / "config.json", pipeline.canonical(config))
        pipeline.load_config(control / "config.json")
    return control / "config.json"


def repair_config(args, *, budget=None) -> Path:
    """既存v2の旧code/start/receiptを保持し、現head確認後だけ新しいcode-only controlを作る。"""
    started = time.monotonic()
    pipeline.require(all(getattr(args, name, None) is None for name in
        ("public_key", "fingerprint", "smoke_local", "first_daily_local", "new_output_root", "inherit_config",
         "original_release", "original_review", "original_script", "archive", "legacy_receipt",
         "legacy_raw_manifest", "legacy_gzip", "legacy_envelope", "fence_receipt")), "CODE_REPAIR_INPUTS")
    required = ("repair_config", "predecessor_config_sha256", "predecessor_start", "predecessor_start_sha256",
                "continuation_receipt", "continuation_receipt_sha256", "prior_native_calls", "prior_elapsed_seconds",
                "control_directory", "collector_exe", "signer_exe")
    pipeline.require(all(getattr(args, name, None) is not None for name in required), "CODE_REPAIR_INPUTS")
    old, scope, old_hash = pipeline.load_config(args.repair_config, predecessor_v2=True)
    pipeline.require(old_hash == args.predecessor_config_sha256, "CODE_REPAIR_PIN")
    out = pipeline.operation_root(Path(old["outputRoot"]))
    control = pipeline.normal_path(str(args.control_directory), exists=False)
    pipeline.require(pipeline.protected_root() / "control" in control.parents and not control.exists(),
                     "NEW_CONTROL_DIRECTORY")
    pipeline.protected_path(control.parent)
    version = Path(pipeline.__file__).resolve().parent
    pipeline.require(Path(__file__).resolve() == version / "prepare_daily_index_config.py", "PROTECTED_PREPARER_LOCATION")
    config = dict(old, scopeFile=str(control / "scope.json"), collectorExe=str(args.collector_exe),
        signerExe=str(args.signer_exe), modulePins={name: pipeline.sha(pipeline.read(version / name))
        for name in sorted(pipeline.MODULE_NAMES)}, pipelineSha256=pipeline.sha(pipeline.read(version / "daily_index_pipeline.py")))
    config["codeRepair"] = {"schema": "dc-daily-code-only-repair-v1", "configFile": str(args.repair_config),
        "configSha256": old_hash, "startFile": str(args.predecessor_start),
        "startSha256": args.predecessor_start_sha256, "receiptFile": str(args.continuation_receipt),
        "receiptSha256": args.continuation_receipt_sha256, "priorNativeCalls": args.prior_native_calls,
        "priorElapsedSeconds": args.prior_elapsed_seconds, "preparationNativeCalls": 2, "preparationElapsedSeconds": 0}
    budget = budget or pipeline.Budget()
    if isinstance(budget, pipeline.Budget):
        budget.directory = out
    with pipeline.exclusive(out / "pipeline.lock"):
        pipeline.protected_tree(out)
        continuation = pipeline.validate_code_repair(config)
        pipeline.carry_code_repair_budget(budget, args.prior_native_calls, args.prior_elapsed_seconds)
        pipeline.verify_reservation(config, continuation["path"], continuation["raw"], budget, "FRESH_INPUT")
        manifest, _ = pipeline.unpack_envelope(pipeline.read(Path(old["legacyMetadata"]["envelopeFile"]), 98304))
        code, _, _ = budget.run([config["signerExe"], "--distribution-verify-floor-history",
            old["legacyMetadata"]["envelopeFile"], old["legacyMetadata"]["gzipFile"], config["publicKeyFile"],
            config["fingerprint"], str(int(pipeline.parse_time(manifest["publishedAtUtc"]).timestamp()))])
        pipeline.require(code == 0, "LEGACY_METADATA_HISTORY_FAILED")
        config["codeRepair"]["preparationElapsedSeconds"] = time.monotonic() - started
        pipeline.validate_code_repair(config)
        control.mkdir()
        pipeline.write_new(control / "scope.json", pipeline.canonical(scope))
        pipeline.write_new(control / "config.json", pipeline.canonical(config))
        pipeline.load_config(control / "config.json")
    return control / "config.json"


def inherit_acquisition_inputs(args, old: dict, old_scope: dict) -> tuple[dict, bytes, dict, str]:
    """明示scopeと原file/hashの閉集合を読み、旧authorityと新期待値を分離する。

    v2入力は保護root内の原byteだけを受理し、未知fieldや不完全role、hash不一致を
    書込・native呼出し前に拒否する。返すscope原byteを再整形しない。
    """
    supplied = any(getattr(args, name, None) is not None for name in METADATA_INPUT_ARGUMENTS)
    scope_path = getattr(args, "acquisition_scope", None)
    scope_hash = getattr(args, "acquisition_scope_sha256", None)
    # 新しい原body/hash入力だけを旧v1へ黙って落とさない。
    pipeline.require(not supplied or (scope_path is not None and scope_hash is not None),
                     "INHERIT_METADATA_SCOPE_REQUIRED")
    if scope_path is None:
        scope = dict(old_scope, schema="dc-fixed-distribution-acquisition-scope-v1",
            publicFingerprint=old["fingerprint"],
            projectionPolicyRevision=pipeline.projection.DISTRIBUTION_PROJECTION_POLICY_REVISION)
        selected_inf = getattr(args, "selected_inf", None) or "PRO2500/Winx64/W11/e2fn.inf"
        originals = {name: {"file": str(path), "sha256": pipeline.sha(pipeline.read(path))}
            for name, path in (("release", args.original_release), ("review", args.original_review),
                               ("script", args.original_script))}
        raw = pipeline.canonical(scope)
    else:
        path = pipeline.normal_path(str(scope_path))
        root = pipeline.protected_root()
        pipeline.require(root in path.parents, "PROTECTED_INPUT_LOCATION")
        pipeline.protected_path(path, root=root)
        raw = pipeline.read(path, 65536)
        pipeline.require(pipeline.public_sha(scope_hash) and pipeline.sha(raw) == scope_hash,
                         "INHERIT_ACQUISITION_SCOPE_PIN")
        scope = pipeline.cr.parse_json(raw)
        pipeline.projection._validate_distribution_scope(scope)
        pipeline.require(scope["schema"] == pipeline.projection.METADATA_BOUND_SCOPE,
                         "INHERIT_METADATA_SCOPE_REQUIRED")
        binding, _, _ = pipeline.projection.metadata_acquisition_binding(scope)
        selected_inf = binding["selectedInf"]
        pipeline.require(getattr(args, "selected_inf", None) in {None, selected_inf}, "INHERIT_INF_SELECTOR")
        originals = {}
        technical = any(getattr(args, "binding_" + role + suffix, None) is not None
            for role in ("release", "body", "review", "script") for suffix in ("", "_sha256"))
        roles = [(role, "original_" + role) for role in ("release", "body", "review", "script")]
        if technical:
            roles += [("binding" + role.capitalize(), "binding_" + role) for role in ("release", "body", "review", "script")]
        # 全roleの完全対を要求し、不完全な追加組を無視しない。
        for name, option in roles:
            entry_path, digest = getattr(args, option, None), getattr(args, option + "_sha256", None)
            pipeline.require(entry_path is not None and pipeline.public_sha(digest), "INHERIT_ORIGINAL_INPUT_PAIR")
            path = pipeline.normal_path(str(entry_path))
            pipeline.require(root in path.parents, "PROTECTED_INPUT_LOCATION")
            pipeline.protected_path(path, root=root)
            value = pipeline.read(path, 65536 if name in {"review", "bindingReview"} else 1048576)
            pipeline.require(pipeline.sha(value) == digest, "TERMS_REVALIDATION_PIN")
            originals[name] = {"file": str(path), "sha256": digest}
    pipeline.projection._validate_distribution_scope(scope)
    pipeline.require(scope["collectorManifestSha256"] == old["manifestSha256"] and
        scope["publicFingerprint"] == old["fingerprint"], "INHERIT_ACQUISITION_SCOPE_BINDING")
    return scope, raw, originals, selected_inf


def validate_inherit_terms(scope: dict, originals: dict[str, bytes]) -> None:
    """旧manualと任意技術reviewを各原bodyで再検査し、期待値との同一許諾を確認する。"""
    _, expected, _ = pipeline.projection.metadata_acquisition_binding(scope)
    release = pipeline.cr.parse_json(originals["release"])
    terms_fields = ("termsText", "termsTextUtf8Bytes", "termsTextSha256", "termsRevision", "htmlExtraction")
    for prefix in ("", "binding") if "bindingRelease" in originals else ("",):
        role = lambda name: name if not prefix else prefix + name.capitalize()
        reviewed = pipeline.cr.parse_json(originals[role("release")])
        pipeline.projection.release_binding(reviewed)
        pipeline.require(all(reviewed[name] == release[name] == expected[name] for name in terms_fields),
                         "TERMS_TEMPLATE_CHANGED_REVIEW_REQUIRED")
        body = originals[role("body")]
        pipeline.require(pipeline.sha(body) == reviewed["bodySha256"] and len(body) == reviewed["bodyBytes"],
                         "TERMS_REVALIDATION_PIN")
        pipeline.projection.confirm_terms_review(body, reviewed, pipeline.cr.parse_json(originals[role("review")]),
            pipeline.cr.parse_json(originals[role("script")]), pipeline.utc())


def inherit_config(args, *, budget=None) -> Path:
    """旧日程/同root/実境界を保持し、旧署名floor認証後に新v2 controlだけを準備する。"""
    pipeline.require(all(getattr(args, name) is None for name in
        ("public_key", "fingerprint", "smoke_local", "first_daily_local", "new_output_root")),
        "INHERIT_SCHEDULE_IMMUTABLE")
    old, old_scope, old_hash = pipeline.load_config(args.inherit_config, inherited_v1=True)
    out = pipeline.operation_root(Path(old["outputRoot"]))
    required = ("control_directory", "original_release", "original_review", "original_script", "archive",
                "legacy_receipt", "legacy_raw_manifest", "legacy_gzip", "legacy_envelope", "fence_receipt")
    pipeline.require(all(getattr(args, name) is not None for name in required), "INHERIT_INPUT_REQUIRED")
    scope, scope_raw, original_inputs, selected_inf = inherit_acquisition_inputs(args, old, old_scope)
    control = pipeline.normal_path(str(args.control_directory), exists=False)
    root = pipeline.protected_root()
    pipeline.require(root / "control" in control.parents and not control.exists(), "NEW_CONTROL_DIRECTORY")
    pipeline.protected_path(control.parent)
    budget = budget or pipeline.Budget()
    if isinstance(budget, pipeline.Budget):
        budget.directory = out
    with pipeline.exclusive(out / "pipeline.lock"):
        pipeline.protected_tree(out)
        binding = {"kind": "LEGACY_METADATA_BOUND", "configFile": str(args.inherit_config),
                   "configSha256": old_hash, "fenceReceiptFile": str(args.fence_receipt)}
        for name, path in (("receipt", args.legacy_receipt), ("rawManifest", args.legacy_raw_manifest),
                           ("gzip", args.legacy_gzip), ("envelope", args.legacy_envelope)):
            binding[name + "File"] = str(path)
            binding[name + "Sha256"] = pipeline.sha(pipeline.read(path))
        fence_raw = pipeline.read(args.fence_receipt, 1048576)
        generation = pipeline.cr.parse_json(fence_raw)["generation"]
        config = dict(old, schema="dc-private-daily-index-config-v2", purpose=pipeline.ACQUISITION_PURPOSE,
            termsReviewMode=(pipeline.projection.PINNED_STATIC_REVALIDATION_V2 if
                scope["schema"] == pipeline.projection.METADATA_BOUND_SCOPE else pipeline.projection.PINNED_STATIC_REVALIDATION_V1),
            scopeFile=str(control / "scope.json"), scopeSha256=pipeline.sha(scope_raw),
            collectorExe=str(args.collector_exe), signerExe=str(args.signer_exe),
            collectorSha256=pipeline.sha(pipeline.read(args.collector_exe)),
            signerSha256=pipeline.sha(pipeline.read(args.signer_exe)), archiveFile=str(args.archive),
            archiveBytes=40477087, archiveSha256="2cbff42aa02519e49f02d8e95a6572c44310e97fe67c42e299f2aba6ea9344f5",
            selectedInf=selected_inf, legacyMetadata=binding,
            legacyReservationFence={"generation": generation, "receiptSha256": pipeline.sha(fence_raw)})
        modules = (Path(pipeline.__file__).resolve(), Path(pipeline.projection.__file__).resolve(),
                   Path(pipeline.cr.__file__).resolve())
        pipeline.require(Path(__file__).resolve() == modules[0].parent / "prepare_daily_index_config.py",
                         "PROTECTED_PREPARER_LOCATION")
        config.update(modulePins={name: pipeline.sha(pipeline.read(modules[0].parent / name))
                                  for name in sorted(pipeline.MODULE_NAMES)},
            pipelineSha256=pipeline.sha(pipeline.read(modules[0])), producerSha256=pipeline.sha(pipeline.read(modules[1])))
        config["originalInputs"] = original_inputs
        pipeline.validate_v2_code(config)
        originals, _ = pipeline.acquisition_originals(config)
        if scope["schema"] == pipeline.projection.METADATA_BOUND_SCOPE:
            validate_inherit_terms(scope, originals)
        pipeline.validate_legacy_metadata(config)
        pipeline.verify_reservation(config, args.fence_receipt, fence_raw, budget, "LEGACY_FENCE")
        manifest, _ = pipeline.unpack_envelope(pipeline.read(args.legacy_envelope, 98304))
        code, _, _ = budget.run([config["signerExe"], "--distribution-verify-floor-history", str(args.legacy_envelope),
            str(args.legacy_gzip), config["publicKeyFile"], config["fingerprint"],
            str(int(pipeline.parse_time(manifest["publishedAtUtc"]).timestamp()))])
        pipeline.require(code == 0, "LEGACY_METADATA_HISTORY_FAILED")
        control.mkdir()
        pipeline.write_new(control / "scope.json", scope_raw)
        pipeline.write_new(control / "config.json", pipeline.canonical(config))
        pipeline.load_config(control / "config.json")
    return control / "config.json"


def preparation_arguments(argv=None):
    """省略・未知・重複optionを区別する正規CLIを解析する。file I/Oは行わない。"""
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--fingerprint")
    parser.add_argument("--smoke-local")
    parser.add_argument("--first-daily-local")
    parser.add_argument("--new-output-root", type=Path)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument("--inherit-config", type=Path)
    modes.add_argument("--repair-config", type=Path)
    modes.add_argument("--continue-presign-config", type=Path)
    modes.add_argument("--public-config-from", type=Path)
    modes.add_argument("--public-context-from-history", type=Path)
    parser.add_argument("--public-history-sha256")
    parser.add_argument("--public-config", type=Path)
    parser.add_argument("--public-config-sha256")
    parser.add_argument("--public-history-envelope", type=Path)
    parser.add_argument("--public-history-envelope-sha256")
    parser.add_argument("--public-publisher-approval-sha256")
    for name in ("predecessor-repair-marker", "phase-evidence", "content-evidence", "failure-terminal"):
        parser.add_argument("--" + name, type=Path)
        parser.add_argument("--" + name + "-sha256")
    for name in ("predecessor-presign-marker", "budget-witness"):
        parser.add_argument("--" + name, type=Path)
        parser.add_argument("--" + name + "-sha256")
    parser.add_argument("--checkpoint-inspection-sha256")
    parser.add_argument("--checkpoint-script-sha256")
    parser.add_argument("--checkpoint-body-sha256")
    parser.add_argument("--checkpoint-release-sha256")
    parser.add_argument("--predecessor-config-sha256")
    parser.add_argument("--predecessor-start", type=Path)
    parser.add_argument("--predecessor-start-sha256")
    parser.add_argument("--continuation-receipt", type=Path)
    parser.add_argument("--continuation-receipt-sha256")
    parser.add_argument("--prior-native-calls", type=int)
    parser.add_argument("--prior-elapsed-seconds", type=float)
    for name in ("acquisition-scope", "original-release", "original-body", "original-review", "original-script",
                 "binding-release", "binding-body", "binding-review", "binding-script"):
        parser.add_argument("--" + name, type=Path)
        parser.add_argument("--" + name + "-sha256")
    for name in ("archive", "legacy-receipt",
                 "legacy-raw-manifest", "legacy-gzip", "legacy-envelope", "fence-receipt"):
        parser.add_argument("--" + name, type=Path)
    parser.add_argument("--selected-inf")
    parser.add_argument("--control-directory", type=Path)
    parser.add_argument("--manifest-file", type=Path)
    parser.add_argument("--collector-exe", type=Path)
    parser.add_argument("--signer-exe", type=Path)
    argv = sys.argv[1:] if argv is None else argv
    options = [value.split("=", 1)[0] for value in argv if value.startswith("--")]
    pipeline.require(len(options) == len(set(options)), "PREPARE_ARGUMENT_DUPLICATE")
    args = parser.parse_args(argv)
    pipeline.require(not any(getattr(args, name) is not None for name in METADATA_INPUT_ARGUMENTS) or
        args.inherit_config is not None, "INHERIT_MODE_REQUIRED")
    return args


def main() -> None:
    """既存公開pinと保護入力から新controlだけを準備し、実行承認を発行しない。

    既存stateRootを変更せず、鍵照会・署名・収集・Task登録・GitHub操作を開始しない。
    I/O失敗は伝播し、部分作成済みfileは原失敗のまま保持する。
    """
    args = preparation_arguments()
    if args.public_context_from_history is not None:
        prepare_public_context(args)
        print("PUBLIC_CONTEXT_PREPARED_NO_TASK_NO_SIGN_NO_GITHUB")
        return
    pipeline.require(args.public_history_sha256 is None and args.public_config is None and
        args.public_config_sha256 is None, "PUBLIC_CONTEXT_PREPARE_MODE_REQUIRED")
    # Publicは独立した明示modeで、旧mode用の既定pathや署名前修復へ流入させない。
    if args.public_config_from is not None:
        prepare_public_config(args)
        print("PUBLIC_CONFIG_PREPARED_HISTORY_TRANSITION_REQUIRED_NO_TASK_NO_SIGN_NO_GITHUB")
        return
    pipeline.require(args.public_publisher_approval_sha256 is None and args.public_history_envelope is None and
                     args.public_history_envelope_sha256 is None, "PUBLIC_PREPARE_MODE_REQUIRED")
    workspace = pipeline.approved_workspace()
    args.manifest_file = args.manifest_file or workspace.repositoryRoot / "tests/fixtures/local_driver_collector_intel_live_v1.json"
    args.collector_exe = args.collector_exe or workspace.repositoryRoot / "build/Release/DriverCrateCollector.exe"
    args.signer_exe = args.signer_exe or workspace.repositoryRoot / "build/Release/DriverCrateLocalIndexSigner.exe"
    if args.continue_presign_config is not None:
        continue_presign_config(args)
        print("PRESIGN_CONTINUATION_CONFIG_PREPARED_NO_COLLECTION_NO_TASK_NO_SIGN_NO_GITHUB")
        return
    pipeline.require(all(getattr(args, name) is None for name in VERIFIED_UNSIGNED_ARGUMENTS +
        ("predecessor_repair_marker", "predecessor_repair_marker_sha256", "checkpoint_body_sha256",
         "checkpoint_release_sha256", "phase_evidence", "phase_evidence_sha256", "content_evidence",
         "content_evidence_sha256", "failure_terminal", "failure_terminal_sha256")), "PRESIGN_MODE_REQUIRED")
    if args.repair_config is not None:
        repair_config(args)
        print("CODE_ONLY_REPAIR_CONFIG_PREPARED_NO_COLLECTION_NO_TASK_NO_SIGN_NO_GITHUB")
        return
    pipeline.require(all(getattr(args, name) is None for name in
        ("predecessor_config_sha256", "predecessor_start", "predecessor_start_sha256", "continuation_receipt",
         "continuation_receipt_sha256", "prior_native_calls", "prior_elapsed_seconds")), "CODE_REPAIR_MODE_REQUIRED")
    if args.inherit_config is not None:
        inherit_config(args)
        print("INHERITED_ACQUISITION_CONFIG_PREPARED_NO_COLLECTION_NO_TASK_NO_SIGN_NO_GITHUB")
        return
    pipeline.require(all(getattr(args, name) is None for name in
        ("original_release", "original_review", "original_script", "archive", "legacy_receipt",
         "legacy_raw_manifest", "legacy_gzip", "legacy_envelope", "fence_receipt")), "INHERIT_MODE_REQUIRED")
    pipeline.require(all(getattr(args, name) is not None for name in
        ("public_key", "fingerprint", "smoke_local", "first_daily_local", "new_output_root")), "NEW_CONFIG_INPUT_REQUIRED")
    out = pipeline.normal_path(str(args.new_output_root), exists=False)
    pipeline.require(not out.exists(), "NEW_OPERATION_DIRECTORY")
    pipeline.operation_root(out, exists=False)
    pipeline.require(workspace.stateRoot.is_dir(), "EXISTING_STATE_ROOT_REQUIRED")
    public = pipeline.normal_path(str(args.public_key))
    pipeline.require(len(pipeline.read(public, 411)) == 411 and
                     pipeline.sha(pipeline.read(public, 411)) == args.fingerprint, "PUBLIC_PIN")
    manifest = pipeline.normal_path(str(args.manifest_file))
    pipeline.require(pipeline.protected_root() / "control" in manifest.parents, "PROTECTED_MANIFEST_COPY_REQUIRED")
    pipeline.protected_path(manifest)
    manifest_hash = pipeline.sha(pipeline.read(manifest))
    pipeline.require(manifest_hash == pipeline.MANIFEST_SHA256,
                     "EXISTING_MANIFEST_PIN")
    scope = {"schema": "dc-fixed-collector-native-index-scope-v1", "targetCount": 1,
        "source": pipeline.projection.SOURCE, "distributionPage": pipeline.projection.PAGE,
        "sourceId": "intel-ethernet-win11", "recordId": "intel-wired-31-2-2-win11",
        "collectorManifestSha256": manifest_hash, "keyId": "distribution-index-" + args.fingerprint[:32]}
    first, smoke = (pipeline.parse_time(value) for value in (args.first_daily_local, args.smoke_local))
    pipeline.require(smoke.date() < first.date() and smoke > pipeline.utc(), "FUTURE_SEPARATE_SMOKE")
    collector = pipeline.normal_path(str(args.collector_exe))
    signer = pipeline.normal_path(str(args.signer_exe))
    control = pipeline.normal_path(str(args.control_directory)) if args.control_directory else out
    pipeline.require(args.control_directory is None or control.is_dir(), "EXISTING_CONTROL_DIRECTORY")
    pipeline.require(pipeline.protected_root() / "control" in control.parents, "PROTECTED_CONTROL_DIRECTORY")
    pipeline.protected_path(control)
    gh = shutil.which("gh.exe")
    pipeline.require(gh is not None, "GH_REQUIRED")
    config = {"schema": "dc-private-daily-index-config-v1", "repositoryRoot": str(workspace.repositoryRoot),
        "stateRoot": str(workspace.stateRoot), "manifestFile": str(manifest), "manifestSha256": manifest_hash,
        "scopeFile": str(control / "scope.json"), "scopeSha256": pipeline.sha(pipeline.canonical(scope)),
        "collectorExe": str(collector), "collectorSha256": pipeline.sha(pipeline.read(collector)),
        "signerExe": str(signer), "signerSha256": pipeline.sha(pipeline.read(signer)),
        "publicKeyFile": str(public), "fingerprint": args.fingerprint, "pythonExe": sys.executable,
        "ghExe": str(Path(gh).resolve()), "outputRoot": str(out), "smokeLocal": args.smoke_local,
        "firstDailyLocal": args.first_daily_local,
        "pipelineSha256": pipeline.sha(pipeline.read(Path(pipeline.__file__).resolve())),
        "producerSha256": pipeline.sha(pipeline.read(Path(pipeline.projection.__file__).resolve()))}
    out.mkdir()
    pipeline.write_new(control / "scope.json", pipeline.canonical(scope))
    pipeline.write_new(control / "config.json", pipeline.canonical(config))
    pipeline.load_config(control / "config.json")
    print("LOCAL_CONFIG_PREPARED_NO_COLLECTION_NO_TASK_NO_GITHUB")


if __name__ == "__main__":
    main()
