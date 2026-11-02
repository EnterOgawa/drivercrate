"""公開済み索引Releaseの分類と、既存byte/署名/世代境界を人工remoteで検査する。

作成者: Shunji Ogawa
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
実GitHub、永続鍵、Task、driver導入は使用しない。
"""
from pathlib import Path
import tempfile
import unittest

import daily_index_pipeline as pipeline
from test_candidate_publication import CandidateWorld
from test_candidate_publish_path import PublicationWorld


class PublishedIndexReleaseReaderTests(unittest.TestCase):
    """classificationだけを変えても他の正常認証と拒否が同じことを確認する。"""

    def world(self, *, publication=False):
        directory = Path(self.enterContext(tempfile.TemporaryDirectory(prefix='dc-release-reader-')))
        world = PublicationWorld(directory, include_native=False) if publication else CandidateWorld(directory)
        self.addCleanup(world.close)
        return world

    def release(self, world):
        return next(iter(world.remote.releases.values()))

    def test_full_and_prerelease_current_keep_original_verified_floor_and_next_generation(self):
        for prerelease in (False, True):
            with self.subTest(prerelease=prerelease):
                world = self.world()
                self.release(world)['prerelease'] = prerelease
                result = world.prepare()
                self.assertEqual(result['generation'], 9)
                self.assertTrue(any(call[1] == '--distribution-verify-history' for call in world.calls))
                self.assertTrue(all(event[0] == 'GET' for event in world.remote.events))
                self.assertFalse(any(call[1].endswith('-sign') for call in world.calls))

    def test_draft_invalid_classification_and_foreign_returned_tag_refuse_before_claim(self):
        for change in ({'draft': True}, {'draft': None}, {'prerelease': None}, {'prerelease': 0},
                       {'prerelease': 1}, {'prerelease': 'false'}, {'tag_name': 'v0.1.1'}):
            with self.subTest(change=change):
                world = self.world()
                self.release(world).update(change)
                with self.assertRaisesRegex(ValueError, 'CURRENT_RELEASE'):
                    world.prepare()
                self.assertFalse(list(world.out.glob('issuance-*.claim.json')))
                self.assertTrue(all(event[0] == 'GET' for event in world.remote.events))

    def test_full_release_does_not_bypass_assets_current_bytes_or_native_signature(self):
        for kind, reason in (('missing-asset', 'REMOTE_ASSETS_INCOMPLETE'),
                             ('changed-size', 'REMOTE_ASSET_SIZE'), ('foreign-name', 'REMOTE_ASSET_ALLOWLIST'),
                             ('signature-rejected', 'CANDIDATE_NATIVE_VERIFY')):
            with self.subTest(kind=kind):
                world = self.world()
                release = self.release(world)
                release['prerelease'] = False
                if kind == 'missing-asset':
                    release['assets'].pop()
                elif kind == 'changed-size':
                    world.remote.assets[2] = b'changed-size'
                elif kind == 'foreign-name':
                    release['assets'][0]['name'] = 'driver.zip'
                else:
                    world.fail_modes['--distribution-verify-history'] = 2
                with self.assertRaisesRegex(ValueError, reason):
                    world.prepare()
                self.assertFalse(list(world.out.glob('issuance-*.claim.json')))
                self.assertFalse(any(call[1].endswith('-sign') for call in world.calls))

    def test_new_release_writer_stays_prerelease_after_reading_full_release(self):
        world = self.world(publication=True)
        original = self.release(world)
        original['prerelease'] = False
        prepared = world.prepare()
        signed = world.sign(prepared)
        published = world.publish(prepared, signed)
        self.assertEqual(published['status'], 'PUBLISHED')
        self.assertFalse(original['prerelease'])
        new = world.remote.releases[published['tag']]
        self.assertIs(new['prerelease'], True)
        self.assertIs(new['draft'], False)


if __name__ == '__main__':
    unittest.main()
