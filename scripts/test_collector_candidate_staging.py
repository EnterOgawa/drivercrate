"""既存候補の非通信stagingと原観測・部分失敗保持を人工workspaceで確認する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実native lease、鍵、Task、HTTP、運用storeには接続しない。
"""
from datetime import timedelta
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import collector_distribution_pipeline as distribution
import collector_registry as cr
import collector_workspace as workspace
from test_collector_distribution_pipeline import CandidateBridge, Fixture
from test_collector_workspace import PackageSwitchTests


class CandidateStagingTests(unittest.TestCase):
    """公開boolを能力へ変えず、原journal/候補と保存先の境界を検査する。"""

    def source(self, *, partial=False):
        fixture = Fixture(count=2)
        failures = {fixture.inputs['registry']['sources'][1]['id']} if partial else set()
        fixture.run(CandidateBridge(fixture, failures=failures))
        document = fixture.context()
        document['operation'] = 'stage-candidate'
        admission = workspace.DistributionAdmission(document, parent_alive=lambda: True, identity=lambda path: '4' * 64)
        output = fixture.base / 'publication-stage'
        output.mkdir()
        return fixture, admission, output

    def test_uninstalled_current_package_is_staging_only_and_existing_bad_receipt_rejected(self):
        probe = PackageSwitchTests(methodName='runTest')
        probe.prepare()
        package = probe.package
        receipt = package / 'install-receipt.json'
        original = receipt.read_bytes()
        receipt.unlink()
        with self.assertRaises(OSError):
            workspace.binding(package)
        self.assertEqual(workspace.binding(package, require_receipt=False), probe.expected)
        wrong = cr.parse_json(original)
        wrong['packageManifestSha256'] = '0' * 64
        receipt.write_bytes(cr.json_bytes(wrong))
        with self.assertRaisesRegex(cr.RegistryError, 'WORKSPACE_RECEIPT'):
            workspace.binding(package, require_receipt=False)
        receipt.unlink()
        manifest = cr.read_json(package / 'package-manifest.json')
        manifest['schema'] = 'unknown-package-schema'
        (package / 'package-manifest.json').write_bytes(cr.json_bytes(manifest))
        with self.assertRaisesRegex(cr.RegistryError, 'WORKSPACE_PACKAGE_VERSION'):
            workspace.binding(package, require_receipt=False)

    def stage(self, fixture, admission, output, **options):
        with patch.object(workspace, 'binding', return_value=fixture.expected):
            return workspace.stage_candidate(fixture.package, fixture.root, output, admission,
                                             clock=lambda: fixture.now, **options)

    def test_partial_records_original_producer_and_all_bytes_are_retained(self):
        fixture, admission, output = self.source(partial=True)
        head_path = fixture.store / 'distribution/candidate-head.json'
        head_raw = head_path.read_bytes()
        head = cr.parse_json(head_raw)
        source = fixture.store / 'distribution/runs' / head['runId']
        original = {name: (source / name).read_bytes() for name in
                    set(head['outputs']) | {'build-commit.json', 'unsigned-validation.json'}}
        journal = (fixture.store / 'distribution/journal.json').read_bytes()
        state = (fixture.store / 'state.json').read_bytes()
        # 現callerのbyte変更を原producerへ上書きせず、原候補だけを受け渡す。
        (fixture.package / 'DriverCrateCollectorSetup.exe').write_bytes(b'changed-caller-not-the-original-producer')
        result = self.stage(fixture, admission, output)
        target = output / 'distribution/runs' / head['runId']
        self.assertEqual(result['records'], 1)
        self.assertFalse(result['signingGenerationFinalized'])
        self.assertFalse(result['freshObservationCreated'])
        self.assertEqual((output / 'distribution/candidate-head.json').read_bytes(), head_raw)
        self.assertEqual({name: (target / name).read_bytes() for name in original}, original)
        self.assertFalse(cr.parse_json(original['build-report.json'])['allTargetsSucceeded'])
        self.assertEqual(head['producerHashes']['native'], cr.digest(b'fixture-not-executable'))
        self.assertEqual((fixture.store / 'distribution/journal.json').read_bytes(), journal)
        self.assertEqual((fixture.store / 'state.json').read_bytes(), state)

    def test_wrong_operation_and_dead_parent_reject_before_copy(self):
        for kind in ('wrong-operation', 'dead-parent', 'used', 'wrong-identity'):
            with self.subTest(kind=kind):
                fixture, admission, output = self.source()
                if kind == 'wrong-operation':
                    admission.document['operation'] = 'verify'
                elif kind == 'dead-parent':
                    admission.parent_alive = lambda: False
                elif kind == 'used':
                    admission.used = True
                else:
                    admission.identity = lambda path: '5' * 64
                with self.assertRaises(cr.RegistryError):
                    self.stage(fixture, admission, output)
                self.assertFalse(any(output.iterdir()))

    def test_expired_or_nonfresh_observation_cannot_be_retimestamped(self):
        for delta, reason in ((timedelta(days=1, seconds=1), 'CANDIDATE_STAGE_NO_FRESH_OBSERVATION'),
                              (timedelta(days=8), 'CANDIDATE_STAGE_EXPIRED')):
            with self.subTest(reason=reason):
                fixture, admission, output = self.source()
                fixture.now += delta
                admission.document['issuedAtUtcMillis'] += int(delta.total_seconds() * 1000)
                with self.assertRaisesRegex(cr.RegistryError, reason):
                    self.stage(fixture, admission, output)
                self.assertFalse(any(output.iterdir()))

    def test_nonempty_and_overlapping_destination_rejected(self):
        fixture, admission, output = self.source()
        (output / 'unknown.bin').write_bytes(b'keep')
        with self.assertRaisesRegex(cr.RegistryError, 'CANDIDATE_STAGE_NOT_EMPTY'):
            self.stage(fixture, admission, output)
        self.assertEqual((output / 'unknown.bin').read_bytes(), b'keep')
        nested = fixture.root / 'package-switches'
        nested.mkdir()
        with self.assertRaisesRegex(cr.RegistryError, 'CANDIDATE_STAGE_OVERLAP'):
            self.stage(fixture, admission, nested)

    def test_changed_source_leaves_partial_outputs_without_head(self):
        fixture, admission, output = self.source()
        def change(stage, target):
            self.assertEqual(stage, 'OUTPUTS_SAVED')
            path = fixture.store / 'distribution/candidate-head.json'
            path.write_bytes(path.read_bytes() + b'\n')
        with self.assertRaisesRegex(cr.RegistryError, 'CANDIDATE_STAGE_SOURCE_CHANGED'):
            self.stage(fixture, admission, output, checkpoint=change)
        self.assertFalse((output / 'distribution/candidate-head.json').exists())
        self.assertTrue(any((output / 'distribution/runs').iterdir()))
        self.assertFalse(admission.used)

    def test_forged_provenance_with_repaired_public_hash_is_not_accepted(self):
        fixture, admission, output = self.source()
        head_path = fixture.store / 'distribution/candidate-head.json'
        head = cr.read_json(head_path)
        directory = fixture.store / 'distribution/runs' / head['runId']
        value = cr.read_json(directory / 'provenance.json')
        value['observations'][0]['observation']['records'][0]['recordId'] = 'forged-record'
        raw = cr.json_bytes(value)
        (directory / 'provenance.json').write_bytes(raw)
        head['outputs']['provenance.json'] = cr.digest(raw)
        validation = cr.read_json(directory / 'unsigned-validation.json')
        validation['outputs'] = head['outputs']
        raw = cr.json_bytes(validation)
        (directory / 'unsigned-validation.json').write_bytes(raw)
        head['validationSha256'] = cr.digest(raw)
        raw = cr.json_bytes(head)
        head_path.write_bytes(raw)
        (directory / 'build-commit.json').write_bytes(raw)
        with self.assertRaisesRegex(cr.RegistryError, 'CANDIDATE_STAGE_PROVENANCE'):
            self.stage(fixture, admission, output)
        self.assertFalse(any(output.iterdir()))

    def test_current_caller_difference_keeps_original_binding_but_unknown_source_is_rejected(self):
        fixture, admission, output = self.source()
        original = (fixture.root / 'workspace.json').read_bytes()
        changed = dict(fixture.expected, packageManifestSha256='c' * 64)
        admission.document['packageManifestSha256'] = changed['packageManifestSha256']
        with patch.object(workspace, 'binding', return_value=changed):
            result = workspace.stage_candidate(fixture.package, fixture.root, output, admission,
                                               clock=lambda: fixture.now)
        self.assertEqual(result['result'], 'STAGED_UNSIGNED')
        self.assertEqual((fixture.root / 'workspace.json').read_bytes(), original)
        for change, reason in (({'schema': 'unknown-old-schema'}, 'WORKSPACE_BINDING_SCHEMA'),
                               ({'packageManifestSha256': 'd' * 64}, 'CANDIDATE_STAGE_ORIGINAL_BINDING')):
            fixture, admission, output = self.source()
            value = dict(fixture.expected, **change)
            (fixture.root / 'workspace.json').write_bytes(cr.json_bytes(value))
            with self.assertRaisesRegex(cr.RegistryError, reason):
                self.stage(fixture, admission, output)
            self.assertFalse(any(output.iterdir()))


if __name__ == '__main__':
    unittest.main()
