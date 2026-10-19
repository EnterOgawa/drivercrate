"""文書用途の正例・型／byte／宣言／構造拒否を非通信検証する。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空本文だけを使い、実HTTP・raw本文の永続保存を行わない。
"""
import unittest
from unittest.mock import patch
import collector_html_document as d
import collector_page_encoding as e

BODY = '<html><head><meta charset="windows-1252"></head><body>Intel® “driver” €</body></html>'.encode('cp1252')


def header(media='application/octet-stream', extra=b'', status=200):
    """最終headerの架空fixtureを組み立てる。"""
    return f'HTTP/1.1 {status} Status\r\nContent-Type: {media}\r\n'.encode()+extra+b'\r\n'


class HtmlDocumentTests(unittest.TestCase):
    """正規化は文書用途だけに限定し、原media typeを保持する。"""

    def parse(self, body=BODY, headers=None, purpose='HTML_DOCUMENT'):
        return d.decode_document(body, headers if headers is not None else header(), purpose=purpose)

    def test_01_explicit_octet_html(self):
        text, media = self.parse()
        self.assertEqual(text, BODY.decode('cp1252'))
        self.assertEqual(media, 'application/octet-stream')

    def test_02_html_types(self):
        for media in ('text/html', 'application/xhtml+xml'):
            self.assertEqual(self.parse(headers=header(media))[1], media)

    def test_03_header_charset_agreement(self):
        self.assertEqual(self.parse(headers=header('application/octet-stream; charset=windows-1252'))[0], BODY.decode('cp1252'))

    def test_04_wrong_purpose(self):
        for purpose in ('PAGE', 'PAYLOAD', None):
            with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_PURPOSE'):
                self.parse(purpose=purpose)

    def test_05_final_block_only(self):
        raw = b'HTTP/1.1 100 Continue\r\nContent-Type: text/plain\r\n\r\n'+header()
        self.assertEqual(self.parse(headers=raw)[1], 'application/octet-stream')

    def test_06_http_failures(self):
        for status in (301, 403, 429, 503):
            with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_HTTP_STATUS'):
                self.parse(headers=header(status=status))

    def test_07_duplicate_media(self):
        with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_CONTENT_TYPE'):
            self.parse(headers=header(extra=b'Content-Type: text/html\r\n'))

    def test_08_other_media_not_guessed(self):
        for media in ('text/plain', 'application/pdf', 'application/zip', 'application/json'):
            with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_CONTENT_TYPE'):
                self.parse(headers=header(media))

    def test_09_encoding_rejected(self):
        with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_CONTENT_ENCODING'):
            self.parse(headers=header(extra=b'Content-Encoding: gzip\r\n'))

    def test_10_lengths(self):
        self.parse(headers=header(extra=f'Content-Length: {len(BODY)}\r\n'.encode()))
        for extra in (b'Content-Length: 1\r\n', b'Content-Length: -1\r\n', b'Content-Length: 1\r\nContent-Length: 1\r\n'):
            with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_CONTENT_LENGTH'):
                self.parse(headers=header(extra=extra))

    def test_11_body_boundaries(self):
        for body in (b'', b'x'*(e.MAX_BODY_BYTES+1), 'html'):
            with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_BODY_SIZE'):
                self.parse(body=body)

    def test_12_binary_roots(self):
        for body in (b'MZexecutable', b'PKarchive', b'%PDF-1.7', b'<html>\x00</html>'):
            with self.assertRaises(d.DocumentError):
                self.parse(body=body)

    def test_13_incomplete_or_duplicate_structure(self):
        for body in (b'<html><body></body></html>', b'<html><head></head><body></body>',
                     b'<html><head></head><body></body><body></body></html>'):
            with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_HTML_STRUCTURE'):
                self.parse(body=body)

    def test_14_hidden_structure_not_adopted(self):
        body = b'<html><head></head><template><body></body></template></html>'
        with self.assertRaisesRegex(d.DocumentError, 'DOCUMENT_HTML_STRUCTURE'):
            self.parse(body=body)

    def test_15_doctype_and_utf8(self):
        text = '<!DOCTYPE html><html><head></head><body>架空</body></html>'
        self.assertEqual(self.parse(body=text.encode())[0], text)

    def test_16_charset_conflict_and_no_fallback(self):
        with self.assertRaisesRegex(e.PageEncodingError, 'CHARSET_CONFLICT'):
            self.parse(headers=header('application/octet-stream; charset=utf-8'))
        for body in (BODY.replace(b'windows-1252', b'cp1252'), BODY.replace(b'\x80', b'\x81')):
            with self.assertRaises(e.PageEncodingError):
                self.parse(body=body)

    def test_17_malformed_headers(self):
        for headers in (b'', b'x'*(d.MAX_HEADERS+1), header(extra=b'folded-line\r\n')):
            with self.assertRaises(d.DocumentError):
                self.parse(headers=headers)

    def test_18_pure_no_io(self):
        with patch('builtins.open') as opened, patch('socket.getaddrinfo') as dns, patch('subprocess.run') as run:
            self.parse()
            opened.assert_not_called()
            dns.assert_not_called()
            run.assert_not_called()
