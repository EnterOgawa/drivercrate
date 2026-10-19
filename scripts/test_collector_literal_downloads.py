"""公開literalの非実行導出・用途別queryと拒否境界を架空データで検証する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
vendor sourceをfixtureへ転用せず、network／JS／POSTを実行しない。
"""
from copy import deepcopy
import socket
import subprocess
import unittest
from unittest.mock import patch

import collector_literal_downloads as literal
import collector_public_locators as pl
import collector_registry as cr

PAGE = 'https://example.org/en/product_detail.php?pid=7'
ACTION = "download('driver','download/driver/2026/Synthetic_1.zip')"
URL = 'https://example.org/en/download.php?file=driver&file_link=download/driver/2026/Synthetic_1.zip'


def fixture():
    """自作の架空transfer grammar fixtureを返す。原vendor scriptではない。"""
    return ('function download($file,$file_link){$product_id="7";$product_name="Synthetic Adapter";'
        '$.post("recode_action.php?oper=download",{product_id:$product_id,product_name:$product_name,'
        'file:$file,file_link:$file_link},function(msg){location.href="download.php?file="+$file+'
        '"&file_link="+$file_link;});}')


class LiteralDownloadTests(unittest.TestCase):
    """純粋な意味抽出・導出とPAYLOAD専用profileを検証する。"""

    def test_synthetic_recognition(self):
        value = literal.recognize_transfer(fixture())
        self.assertEqual(value['productSelector'], '7')
        self.assertTrue(value['callbackRequiresPostSuccess'])

    def test_whitespace_comment(self):
        value = fixture().replace('{$product_id', '{\n// Synthetic fixture.\n$product_id')
        self.assertEqual(literal.recognize_transfer(value)['model'], 'Synthetic Adapter')

    def test_dynamic_argument(self):
        with self.assertRaises(cr.RegistryError):
            literal.recognize_transfer(fixture().replace('+$file_link;', '+encodeURIComponent($file_link);'))

    def test_extra_statement(self):
        for value in (fixture() + 'download=other;', 'eval(x);' + fixture(), fixture().replace(';});', ';alert(msg);});')):
            with self.subTest(value=value), self.assertRaises(cr.RegistryError):
                literal.recognize_transfer(value)

    def test_callback_condition(self):
        with self.assertRaises(cr.RegistryError):
            literal.recognize_transfer(fixture().replace('location.href=', 'if(msg){location.href='))

    def test_changed_endpoint(self):
        with self.assertRaises(cr.RegistryError):
            literal.recognize_transfer(fixture().replace('download.php?file=', 'https://other.example/download.php?file='))

    def test_duplicate_definition(self):
        with self.assertRaises(cr.RegistryError):
            literal.recognize_transfer(fixture() + fixture())

    def test_script_type_size(self):
        for value in (None, False, b'x', '', ' ' * 8193):
            with self.subTest(value=type(value)), self.assertRaises(cr.RegistryError):
                literal.recognize_transfer(value)

    def test_literal_derivation(self):
        self.assertEqual(literal.derive_url(PAGE, ACTION, literal.recognize_transfer(fixture())), URL)

    def test_non_literal_invocations(self):
        for value in (ACTION + ';alert(1)', ACTION.replace("'driver'", "'manual'"),
                ACTION.replace('Synthetic_1.zip', 'x.zip?token=1'), ACTION.replace("'driver'", 'kind')):
            with self.subTest(value=value), self.assertRaises(cr.RegistryError):
                literal.derive_url(PAGE, value, literal.recognize_transfer(fixture()))

    def test_page_selector_binding(self):
        with self.assertRaises(cr.RegistryError):
            literal.derive_url(PAGE.replace('pid=7', 'pid=8'), ACTION, literal.recognize_transfer(fixture()))

    def test_transfer_authority(self):
        for key in ('requestAuthorized', 'postExecuted', 'getExecuted'):
            value = deepcopy(literal.recognize_transfer(fixture()))
            value[key] = True
            with self.subTest(key=key), self.assertRaises(cr.RegistryError):
                literal.derive_url(PAGE, ACTION, value)

    def test_payload_profile(self):
        self.assertEqual(pl.public_locator_url(URL, profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD'), URL)

    def test_page_purpose_rejected(self):
        with self.assertRaises(cr.RegistryError):
            pl.public_locator_url(URL, profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAGE')

    def test_query_names_and_order(self):
        for value in (URL + '&pid=7', URL.replace('file=driver', 'file=manual'),
                URL.replace('file_link=', 'path='), URL.replace('file=driver&file_link=', 'file_link=driver&file=')):
            with self.subTest(value=value), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(value, profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD')

    def test_encoding_and_control(self):
        for value in (URL.replace('/driver/', '%2Fdriver%2F'), URL.replace('Synthetic', '%53ynthetic'),
                URL + '#fragment', URL.replace('Synthetic', 'Synthetic '), URL.replace('Synthetic', '%0ASynthetic')):
            with self.subTest(value=value), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(value, profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD')

    def test_traversal(self):
        for value in (URL.replace('Synthetic_1.zip', '../x.zip'), URL.replace('Synthetic_1.zip', 'x..zip'),
                URL.replace('Synthetic_1.zip', 'x/y.zip')):
            with self.subTest(value=value), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(value, profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD')

    def test_suffix(self):
        for suffix in ('exe', 'msi', 'cab', 'rar', '7z'):
            self.assertEqual(pl.public_locator_url(URL[:-3] + suffix,
                profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD'), URL[:-3] + suffix)
        with self.assertRaises(cr.RegistryError):
            pl.public_locator_url(URL[:-3] + 'pdf', profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD')

    def test_base_url_policy(self):
        for value in (URL.replace('https:', 'http:'), URL.replace('example.org', '127.0.0.1'),
                URL.replace('example.org', 'user@example.org')):
            with self.subTest(value=value), self.assertRaises(cr.RegistryError):
                pl.public_locator_url(value, profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD')

    def test_no_network_or_post(self):
        with patch.object(socket, 'getaddrinfo') as dns, patch.object(subprocess, 'run') as run:
            self.assertEqual(literal.derive_url(PAGE, ACTION, literal.recognize_transfer(fixture())), URL)
            dns.assert_not_called()
            run.assert_not_called()


if __name__ == '__main__':
    unittest.main()
