"""可搬data/activeの正例、B1、閉集合と非通信を自己所有fixtureで検査する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
"""
import copy
import hashlib
import os
from pathlib import Path
import tempfile
import unittest

import collector_collection_profiles as cp
import collector_distribution_data as data
import collector_distribution_pipeline as pipeline
import collector_registry as cr
from test_collector_collection_profiles import fixture_inputs


class DataTests(unittest.TestCase):
    """package/実通信/Taskを使わず、原byteと旧世代保持を確認する。"""

    def tree_state(self):
        """自己所有の全fileの原byte指紋とdirectory集合を非変更で得る。"""
        result = {}
        for path in self.root.rglob('*'):
            if path.is_dir():
                result[path.relative_to(self.root).as_posix()] = None
            else:
                with path.open('rb') as stream:
                    result[path.relative_to(self.root).as_posix()] = (
                        path.stat().st_size, hashlib.file_digest(stream, 'sha256').hexdigest())
        return result

    def fill_workspace(self, total):
        """実fileを一file16MiB以内で追加し、自己所有rootの論理byte総量を指定値へ揃える。"""
        remaining = total - sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file())
        self.assertGreaterEqual(remaining, 0)
        directory = self.root / 'retained'
        directory.mkdir()
        ordinal = 0
        while remaining:
            size = min(remaining, cr.MAX_JSON_BYTES)
            with (directory / str(ordinal)).open('xb') as stream:
                stream.truncate(size)
            ordinal += 1
            remaining -= size

    def changed_bundle(self):
        """意味条件と元時刻を変えず、別hashの現行世代を作成する。"""
        current = data.active_bundle(self.root)
        value = copy.deepcopy(current['profiles'])
        value['revision'] = 'capacity-next'
        output = self.base / 'capacity-next'
        data.write_bundle(output, data.bundle_content({**current['raw'], 'profiles': cr.json_bytes(value)}))
        return output

    def rebind_profiles(self, raw):
        """人工padding後の原byteへ試験profileの入力hashだけを正式に結合する。"""
        value = cr.parse_json(raw['profiles'])
        value.update(cp.load_inputs(raw['registry'], raw['locators'])['bindings'])
        return {**raw, 'profiles': cr.json_bytes(value)}

    def test_retained_generations_over_64_mib_import_and_verify(self):
        """実byte合計72MiB超の三有効世代をimport/検証し、旧世代hashと通信非許可を保持する。"""
        self.assertEqual(data.MAX_WORKSPACE_TOTAL, 256 * 1024 * 1024)
        self.assertEqual(data.MAX_TOTAL, 64 * 1024 * 1024)
        original = data.verify_bundle(self.bundle())
        generations = []
        prior = {}
        for ordinal in range(3):
            value = copy.deepcopy(original['profiles'])
            value['revision'] = 'retained-' + str(ordinal)
            raw = {**original['raw'], 'profiles': cr.json_bytes(value)}
            for name in ('registry', 'locators'):
                raw[name] += b' ' * (12 * 1024 * 1024 - len(raw[name]))
            raw = self.rebind_profiles(raw)
            source = self.base / ('retained-' + str(ordinal))
            data.write_bundle(source, data.bundle_content(raw))
            result = data.import_data(self.root, source)
            self.assertEqual((result['result'], result['network'], result['tasks'], result['communicationAuthorized']),
                             ('DATA_IMPORTED_OFFLINE', 0, 0, False))
            current = data.active_bundle(self.root)
            self.assertEqual(current['raw'], raw)
            generations.append(current['sha256'])
            after = self.tree_state()
            self.assertTrue(all(after[key] == item for key, item in prior.items() if key != 'data/active.json'))
            prior = after
        total = sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file())
        self.assertGreater(total, 72 * 1024 * 1024)
        self.assertEqual({path.name for path in (self.root / 'data/generations').iterdir()}, set(generations))
        for generation in generations:
            self.assertEqual(data.verify_bundle(self.root / 'data/generations' / generation)['sha256'], generation)

    def test_import_peak_exact_limit_and_one_byte_over_before_commit(self):
        """旧activeとpendingが共存する256MiBの境界を許し、一byte超過を全byte不変で拒否する。"""
        source = self.bundle()
        data.import_data(self.root, source)
        changed = self.changed_bundle()
        value = data.verify_bundle(changed)
        pointer = cr.json_bytes({'schema': data.ACTIVE_SCHEMA, 'sha256': value['sha256']})
        increment = sum(map(len, value['content'].values())) + len(pointer)
        self.fill_workspace(data.MAX_WORKSPACE_TOTAL - increment + 1)
        before = self.tree_state()
        with self.assertRaisesRegex(cr.RegistryError, '^WORKSPACE_BYTE_LIMIT$'):
            data.import_data(self.root, changed)
        self.assertEqual(before, self.tree_state())
        self.assertFalse((self.root / 'data/generations' / value['sha256']).exists())
        self.assertFalse(list((self.root / 'data').glob('*.pending')))
        # 拒否された自己所有fillerだけを一byte縮め、実境界へ条件を変更する。
        filler = next(path for path in (self.root / 'retained').iterdir() if path.stat().st_size)
        with filler.open('r+b') as stream:
            stream.truncate(filler.stat().st_size - 1)
        data.import_data(self.root, changed)
        self.assertEqual(data.active_bundle(self.root)['sha256'], value['sha256'])
        self.assertEqual(sum(path.stat().st_size for path in self.root.rglob('*') if path.is_file()),
                         data.MAX_WORKSPACE_TOTAL - len(pointer))
        self.assertEqual(len(list((self.root / 'data/generations').iterdir())), 2)

    def test_existing_generation_reimport_only_reserves_pointer_pending(self):
        """世代増分0の再importでもpendingを数え、境界を許し超過時は全世代を保持する。"""
        source = self.bundle()
        data.import_data(self.root, source)
        pointer_size = (self.root / 'data/active.json').stat().st_size
        self.fill_workspace(data.MAX_WORKSPACE_TOTAL - pointer_size)
        before = self.tree_state()
        data.import_data(self.root, source)
        self.assertEqual(before, self.tree_state())
        (self.root / 'retained/extra-byte').write_bytes(b'x')
        before = self.tree_state()
        with self.assertRaisesRegex(cr.RegistryError, '^WORKSPACE_BYTE_LIMIT$'):
            data.import_data(self.root, source)
        self.assertEqual(before, self.tree_state())
        self.assertEqual(len(list((self.root / 'data/generations').iterdir())), 1)

    def test_initial_store_rejected_before_scaffolding_and_per_file_limit(self):
        """初期保存の増分超過と保持一file16MiB直後をdata作成前に拒否する。"""
        source = self.bundle()
        value = data.verify_bundle(source)
        pointer = cr.json_bytes({'schema': data.ACTIVE_SCHEMA, 'sha256': value['sha256']})
        increment = sum(map(len, value['content'].values())) + len(pointer) + 1
        self.fill_workspace(data.MAX_WORKSPACE_TOTAL - increment + 1)
        before = self.tree_state()
        with self.assertRaisesRegex(cr.RegistryError, '^WORKSPACE_BYTE_LIMIT$'):
            data.import_data(self.root, source)
        self.assertEqual(before, self.tree_state())
        self.assertFalse((self.root / 'data').exists())
        separate = self.base / 'oversized-workspace'
        separate.mkdir()
        with (separate / 'too-large').open('xb') as stream:
            stream.truncate(cr.MAX_JSON_BYTES + 1)
        with self.assertRaisesRegex(cr.RegistryError, '^WORKSPACE_BYTE_LIMIT$'):
            data.import_data(separate, source)
        self.assertFalse((separate / 'data').exists())

    def test_entry_peak_boundary_and_hardlink_rejected_before_generation(self):
        """実entry8192のピークを許し、一entry超過とhardlinkを世代変更前に拒否する。"""
        self.assertEqual(data.MAX_WORKSPACE_ENTRIES, 8192)
        source = self.bundle()
        data.import_data(self.root, source)
        changed = self.changed_bundle()
        directory = self.root / 'retained'
        directory.mkdir()
        existing = len(list(self.root.rglob('*')))
        new_entries = len(data.verify_bundle(changed)['content']) + 2  # 世代rootとactive pending。
        for ordinal in range(data.MAX_WORKSPACE_ENTRIES - existing - new_entries + 1):
            (directory / str(ordinal)).touch(exist_ok=False)
        before = self.tree_state()
        with self.assertRaisesRegex(cr.RegistryError, '^WORKSPACE_ENTRY_LIMIT$'):
            data.import_data(self.root, changed)
        self.assertEqual(before, self.tree_state())
        # 自己所有fixtureの余剰一entryだけを除いて実境界を確認する。
        (directory / '0').unlink()
        data.import_data(self.root, changed)
        self.assertEqual(len(list(self.root.rglob('*'))), data.MAX_WORKSPACE_ENTRIES - 1)
        os.link(directory / '1', directory / 'hardlink-alias')
        before = self.tree_state()
        with self.assertRaisesRegex(cr.RegistryError, '^WORKSPACE_OBJECT$'):
            data.import_data(self.root, changed)
        self.assertEqual(before, self.tree_state())

    def test_input_16_mib_and_64_mib_limits_remain(self):
        """保持256MiBを可搬inputの一file16MiB/総64MiBへ流用しない。"""
        original = data.verify_bundle(self.bundle())
        raw = dict(original['raw'])
        raw['registry'] += b' ' * (cr.MAX_JSON_BYTES - len(raw['registry']))
        raw = self.rebind_profiles(raw)
        data.bundle_content(raw)
        raw['registry'] += b' '
        with self.assertRaisesRegex(cr.RegistryError, '^JSON_SIZE$'):
            data.bundle_content(raw)
        # 研究索引の生成だけを隔離し、実5fileが既存64MiB総量を越える入口を検査する。
        from unittest.mock import patch
        padded = {name: value + b' ' * (cr.MAX_JSON_BYTES - len(value)) for name, value in original['raw'].items()}
        padded = self.rebind_profiles(padded)
        padded['profiles'] += b' ' * (cr.MAX_JSON_BYTES - len(padded['profiles']))
        with patch.object(cr, 'research_index', return_value={'padding': 'x' * (cr.MAX_JSON_BYTES - 4096)}):
            content = data.bundle_content(padded)
            self.assertLessEqual(sum(map(len, content.values())), data.MAX_TOTAL)
        with patch.object(cr, 'research_index', return_value={'padding': 'x' * (cr.MAX_JSON_BYTES - 100)}):
            with self.assertRaisesRegex(cr.RegistryError, '^DATA_TOTAL_LIMIT$'):
                data.bundle_content(padded)

    def test_retained_v1_is_audited_but_never_selected_for_current_run(self):
        """原v1 dataを非通信検査だけへ保持し、原byteを変えず新v2をimportする。"""
        source = self.bundle(suffix='current-v2')
        current = data.verify_bundle(source)
        old = copy.deepcopy(current['profiles'])
        old['schema'] = 'dc-collector-collection-profiles-v1'
        for row in old['profiles']:
            for item in row['review'].values():
                item['evidence'].pop('contentSha256')
        content = data.bundle_content({**current['raw'], 'profiles': cr.json_bytes(old)}, retained=True)
        retained = self.root / 'data'
        retained.mkdir()
        (retained / 'writer.lock').write_bytes(b'0')
        generation = cr.digest(content['manifest.json'])
        directory = retained / 'generations' / generation
        directory.mkdir(parents=True)
        for name, raw in content.items():
            (directory / name).write_bytes(raw)
        (retained / 'active.json').write_bytes(cr.json_bytes({'schema': data.ACTIVE_SCHEMA, 'sha256': generation}))
        before = {path.name: path.read_bytes() for path in directory.iterdir()}
        self.assertEqual(data.active_bundle(self.root, retained=True)['sha256'], generation)
        with self.assertRaises(cr.RegistryError):
            pipeline.inputs_at(self.base / 'missing-package', self.root)
        with self.assertRaises(cr.RegistryError):
            data.import_data(self.root, directory)
        data.import_data(self.root, source)
        self.assertEqual(data.active_bundle(self.root)['profiles']['schema'], cp.SCHEMA)
        self.assertEqual(before, {path.name: path.read_bytes() for path in directory.iterdir()})
        self.assertEqual(len(list((retained / 'generations').iterdir())), 2)
        (directory / 'research-index.json').write_bytes(b'{}')
        with self.assertRaises(cr.RegistryError):
            data.verify_bundle(directory, retained=True)

    def setUp(self):
        self.base = Path(tempfile.mkdtemp(prefix="dc-data-"))
        self.root = self.base / "workspace"
        self.root.mkdir()

    def bundle(self, count=2, suffix="one"):
        inputs, value, _ = fixture_inputs(count)
        raw = {"registry": inputs["raw"]["registry"], "locators": inputs["raw"]["locators"],
               "profiles": cr.json_bytes(value)} if "raw" in inputs else {
               "registry": cr.json_bytes(inputs["registry"]), "locators": cr.json_bytes(inputs["locators"]),
               "profiles": cr.json_bytes(value)}
        target = self.base / suffix
        data.write_bundle(target, data.bundle_content(raw))
        return target

    def test_import_and_original_bytes_without_package_or_authority(self):
        source = self.bundle()
        before = data.verify_bundle(source)
        result = data.import_data(self.root, source)
        self.assertEqual((result["network"], result["tasks"], result["communicationAuthorized"]), (0, 0, False))
        after = data.active_bundle(self.root)
        self.assertEqual(before["raw"], after["raw"])
        self.assertEqual(before["sha256"], after["sha256"])
        inputs, value, hashes = pipeline.inputs_at(self.base / "missing-package", self.root)
        self.assertEqual(hashes, before["manifest"]["inputHashes"])
        self.assertEqual(value, before["profiles"])
        self.assertEqual(inputs["registry"], before["inputs"]["registry"])

    def test_corrupt_unknown_secret_and_extra_preserve_active(self):
        source = self.bundle()
        data.import_data(self.root, source)
        pointer = (self.root / "data/active.json").read_bytes()
        for change in ("extra", "hash", "unknown", "secret"):
            other = self.bundle(suffix=change)
            if change == "extra":
                (other / "driver.sys").write_bytes(b"forbidden")
            elif change == "hash":
                (other / "registry.json").write_bytes(b"{}")
            else:
                value = cr.read_json(other / "manifest.json")
                value["cookie" if change == "secret" else "unknown"] = "forbidden"
                (other / "manifest.json").write_bytes(cr.json_bytes(value))
            with self.assertRaises(cr.RegistryError):
                data.import_data(self.root, other)
            self.assertEqual(pointer, (self.root / "data/active.json").read_bytes())
        self.assertEqual(len(list((self.root / "data/generations").iterdir())), 1)

    def test_b1_semantic_change_requires_hold_and_keeps_generations(self):
        source = self.bundle()
        data.import_data(self.root, source)
        old = data.verify_bundle(source)
        edits = {"schema": cp.EDIT_SCHEMA, "profiles": [copy.deepcopy({key: old["profiles"]["profiles"][0][key]
                 for key in cp.PROFILE_FIELDS})]}
        edits["profiles"][0]["maximumBytes"] //= 2
        edits["profiles"][0]["revision"] = "changed-2"
        value = cp.upsert_profiles(old["profiles"], old["inputs"], edits, revision="new-2", as_of=old["profiles"]["asOf"])
        self.assertEqual(value["profiles"][0]["reviewState"], "REVIEW_REQUIRED")
        changed = self.base / "changed"
        data.write_bundle(changed, data.bundle_content({**old["raw"], "profiles": cr.json_bytes(value)}))
        data.import_data(self.root, changed)
        self.assertEqual(len(list((self.root / "data/generations").iterdir())), 2)
        self.assertEqual(data.verify_bundle(source)["raw"], old["raw"])

    def test_broken_active_is_not_seed_fallback(self):
        source = self.bundle()
        result = data.import_data(self.root, source)
        path = self.root / "data/generations" / result["dataSha256"] / "locators.json"
        path.write_bytes(b"{}")
        with self.assertRaises(cr.RegistryError):
            pipeline.inputs_at(self.base / "missing-package", self.root)

    def test_reference_hash_unknown_form_and_forged_current_rejected_or_held(self):
        source = self.bundle()
        data.import_data(self.root, source)
        old = data.verify_bundle(source)
        pointer = (self.root / "data/active.json").read_bytes()
        broken = copy.deepcopy(old["profiles"])
        broken["profiles"][0]["referenceSha256"] = "0" * 64
        with self.assertRaises(cr.RegistryError):
            data.bundle_content({**old["raw"], "profiles": cr.json_bytes(broken)})
        edits = {"schema": cp.EDIT_SCHEMA, "profiles": [{key: copy.deepcopy(old["profiles"]["profiles"][0][key])
                 for key in cp.PROFILE_FIELDS}]}
        edits["profiles"][0].update(sourceFormat="UNKNOWN_FORMAT_V1", revision="unknown-2")
        changed = cp.upsert_profiles(old["profiles"], old["inputs"], edits, revision="unknown-2", as_of=old["profiles"]["asOf"])
        self.assertEqual(cp.plan_profiles(changed, old["inputs"])["targets"][0]["status"], "UNSUPPORTED_SOURCE_FORMAT")
        changed["profiles"][0]["reviewState"] = "CURRENT"
        target = self.base / "forged"
        data.write_bundle(target, data.bundle_content({**old["raw"], "profiles": cr.json_bytes(changed)}))
        with self.assertRaisesRegex(cr.RegistryError, "DATA_B1_REVIEW_REQUIRED"):
            data.import_data(self.root, target)
        self.assertEqual(pointer, (self.root / "data/active.json").read_bytes())

    def test_secret_fields_and_paths(self):
        for value in ({"cookie": "x"}, {"nested": {"command": "x"}}, "-----BEGIN PRIVATE KEY-----",
                      "C:\\private\\state", "https://example.org/?token=secret"):
            with self.assertRaises(cr.RegistryError):
                data.public_json(value)


if __name__ == "__main__":
    unittest.main()
