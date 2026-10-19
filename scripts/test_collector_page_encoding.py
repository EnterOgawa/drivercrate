"""明示charsetと共通transportの決定的正例／拒否test（ADR 0303／0306）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
架空byteだけを使い、DNS・実HTTP・本文の永続保存を行わない。
"""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import collector_page_encoding as encoding
import collector_registry as cr
import registry_monitor_http as http

PAGE = 'https://vendor.example.org/drivers'
LINK = 'https://vendor.example.org/driver.zip'
# OS照会もPATH探索も行わず、fakeの実行役割を照合する架空の絶対path。
FIXTURE_CURL = r'C:\DriverCrateFixture\Windows\System32\curl.exe'


class PageEncodingTests(unittest.TestCase):
    """codec選択の正例と曖昧宣言／不正byteの拒否を検証する。"""

    def test_unlabelled_utf8_and_utf8_bom(self):
        text = '<html><body>架空ドライバー</body></html>'
        for body in (text.encode(), b'\xef\xbb\xbf'+text.encode()):
            self.assertEqual(encoding.decode_page(body,'text/html'),text)

    def test_all_utf8_aliases(self):
        for label in ('UTF-8','utf8'):
            self.assertIn('架空',encoding.decode_page('<html>架空</html>'.encode(),f'text/html; charset="{label}"'))

    def test_explicit_shiftjis_meta(self):
        for label in ('Shift_JIS','shift-jis','sjis'):
            text = f'<html><head><meta charset="{label}"></head><body>架空</body></html>'
            self.assertEqual(encoding.decode_page(text.encode('shift_jis'),'text/html'),text)

    def test_explicit_cp932_extensions(self):
        for label in ('cp932','windows-31j','ms932'):
            text = '<html>①</html>'
            self.assertEqual(encoding.decode_page(text.encode('cp932'),f'text/html; charset={label}'),text)

    def test_cp932_is_not_shiftjis_fallback(self):
        with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_INVALID_BYTES'):
            encoding.decode_page('<html>①</html>'.encode('cp932'),'text/html; charset=shift_jis')

    def test_http_equiv_with_quoted_charset(self):
        text = '<html><meta http-equiv="Content-Type" content="text/html; charset=Shift_JIS"><p>架空</p></html>'
        self.assertEqual(encoding.decode_page(text.encode('shift_jis'),'application/xhtml+xml'),text)

    def test_alias_agreement_not_string_agreement(self):
        text = '<html><meta charset="sjis">架空</html>'
        self.assertEqual(encoding.decode_page(text.encode('shift_jis'),'text/html; charset=shift-jis'),text)

    def test_http_and_meta_conflict(self):
        with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_CONFLICT'):
            encoding.decode_page(b'<html><meta charset="shift_jis"></html>','text/html; charset=utf-8')

    def test_multiple_meta_conflict(self):
        with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_CONFLICT'):
            encoding.decode_page(b'<meta charset="utf8"><meta charset="cp932">','text/html')

    def test_bom_conflict(self):
        with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_CONFLICT'):
            encoding.decode_page(b'\xef\xbb\xbf<html/>','text/html; charset=cp932')

    def test_unknown_declaration_even_ascii(self):
        for body, header in ((b'<html/>','text/html; charset=unknown'),
                             (b'<html><meta charset="unknown"></html>','text/html')):
            with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_UNSUPPORTED'):
                encoding.decode_page(body,header)

    def test_invalid_bytes_are_not_replaced(self):
        for body, header in ((b'<html>\xff</html>','text/html'),
                             (b'<html>\x81</html>','text/html; charset=cp932')):
            with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_INVALID_BYTES'):
                encoding.decode_page(body,header)

    def test_no_guess_for_unlabelled_japanese(self):
        with self.assertRaises(encoding.PageEncodingError):
            encoding.decode_page('<html>架空</html>'.encode('shift_jis'),'text/html')

    def test_unsupported_boms(self):
        for prefix in (b'\xff\xfe',b'\xfe\xff',b'\xff\xfe\x00\x00',b'\x00\x00\xfe\xff'):
            with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_UNSUPPORTED_BOM'):
                encoding.decode_page(prefix+b'<html/>','text/html')

    def test_hidden_meta_and_comment_are_not_declarations(self):
        for tag in sorted(encoding.MetaDeclarations.HIDDEN-{'plaintext'}):
            body = f'<html><{tag}><meta charset="unknown"></{tag}><p>ok</p></html>'.encode()
            self.assertEqual(encoding.decode_page(body,'text/html'),body.decode())
        body = b'<html><!-- <meta charset="unknown"> --><meta data-charset="unknown"></html>'
        self.assertEqual(encoding.decode_page(body,'text/html'),body.decode())

    def test_meta_after_head_or_body_not_adopted(self):
        for body in (b'<html><head></head><meta charset="unknown"></html>',
                     b'<html><body><meta charset="unknown"></body></html>'):
            self.assertEqual(encoding.decode_page(body,'text/html'),body.decode())

    def test_nested_inert_and_plaintext(self):
        for body in (b'<template><template></template><meta charset="unknown"></template>',
                     b'<plaintext><meta charset="unknown">'):
            self.assertEqual(encoding.decode_page(body,'text/html'),body.decode())

    def test_meta_window_is_bounded(self):
        body = b' ' * encoding.MAX_DECLARATION_BYTES + b'<html><meta charset="unknown"></html>'
        self.assertEqual(encoding.decode_page(body,'text/html'),body.decode())

    def test_duplicate_declaration_attributes(self):
        for tag in (b'<meta charset="utf8" charset="utf8">',
                    b'<meta http-equiv="Content-Type" http-equiv="Content-Type" content="text/html; charset=utf8">'):
            with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_DUPLICATE_ATTRIBUTE'):
                encoding.decode_page(tag,'text/html')

    def test_malformed_meta(self):
        for tag in (b'<meta charset>',b'<meta charset="utf8/unknown">',
                    b'<meta http-equiv="Content-Type">'):
            with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_META_SYNTAX'):
                encoding.decode_page(tag,'text/html')

    def test_malformed_header_parameter(self):
        for header in ('text/html; charset','text/html; charset=', 'text/html; charset="utf8',
                       'text/html; charset=utf8/extra','text/html; charset=utf8 trailing'):
            with self.assertRaises(encoding.PageEncodingError):
                encoding.decode_page(b'<html/>',header)

    def test_quoted_parameter_does_not_inject_charset(self):
        header = 'text/html; boundary="x;charset=unknown"; charset="utf8"'
        self.assertEqual(encoding.decode_page(b'<html/>',header),'<html/>')

    def test_duplicate_header_conflict(self):
        with self.assertRaisesRegex(encoding.PageEncodingError,'CHARSET_CONFLICT'):
            encoding.decode_page(b'<html/>','text/html; charset=utf8; charset=cp932')

    def test_sizes_types_and_html_type(self):
        for body, header in ((b'','text/html'),(b'x'*(encoding.MAX_BODY_BYTES+1),'text/html'),
                             ('<html/>','text/html'),(b'<html/>',None),(b'<html/>','text/plain'),
                             (b'<html/>','text/html;'+'x'*encoding.MAX_DECLARATION_BYTES)):
            with self.assertRaises(encoding.PageEncodingError):
                encoding.decode_page(body,header)

    def test_pure_decode_never_opens_file_or_network(self):
        with patch('builtins.open') as opened, patch('socket.getaddrinfo') as dns, patch('subprocess.run') as run:
            encoding.decode_page(b'<html/>','text/html')
            opened.assert_not_called()
            dns.assert_not_called()
            run.assert_not_called()

    def test_windows1252_explicit_header_and_case(self):
        text = '<html><body>Intel® “Driver” — € ™</body></html>'
        for label in ('windows-1252', 'WINDOWS-1252', 'Windows-1252'):
            self.assertEqual(encoding.decode_page(text.encode('cp1252'), f'text/html; charset={label}'), text)

    def test_windows1252_meta_and_http_equiv(self):
        for meta in ('<meta charset="windows-1252">',
                     '<meta http-equiv="Content-Type" content="text/html; charset=windows-1252">'):
            text = f'<html><head>{meta}</head><body>® “driver” €</body></html>'
            self.assertEqual(encoding.decode_page(text.encode('cp1252'), 'text/html'), text)

    def test_windows1252_agreement(self):
        text = '<html><meta charset="WINDOWS-1252"><body>© €</body></html>'
        self.assertEqual(encoding.decode_page(text.encode('cp1252'), 'text/html; charset=windows-1252'), text)

    def test_windows1252_undefined_bytes_strict(self):
        for value in (0x81, 0x8d, 0x8f, 0x90, 0x9d):
            with self.assertRaisesRegex(encoding.PageEncodingError, 'CHARSET_INVALID_BYTES'):
                encoding.decode_page(b'<html>'+bytes([value])+b'</html>', 'text/html; charset=windows-1252')

    def test_windows1252_unlabelled_not_guessed(self):
        with self.assertRaisesRegex(encoding.PageEncodingError, 'CHARSET_INVALID_BYTES'):
            encoding.decode_page('<html>“driver” €</html>'.encode('cp1252'), 'text/html')

    def test_windows1252_other_aliases_not_added(self):
        for label in ('cp1252', 'windows_1252', 'latin1', 'latin-1', 'iso-8859-1', 'iso8859-1', 'ascii'):
            with self.assertRaisesRegex(encoding.PageEncodingError, 'CHARSET_UNSUPPORTED'):
                encoding.decode_page(b'<html/>', f'text/html; charset={label}')

    def test_windows1252_conflicts_not_ignored(self):
        for label in ('utf-8', 'shift_jis', 'cp932'):
            with self.assertRaisesRegex(encoding.PageEncodingError, 'CHARSET_CONFLICT'):
                encoding.decode_page(b'<meta charset="windows-1252">', f'text/html; charset={label}')

    def test_windows1252_bom_conflict(self):
        with self.assertRaisesRegex(encoding.PageEncodingError, 'CHARSET_CONFLICT'):
            encoding.decode_page(b'\xef\xbb\xbf<html/>', 'text/html; charset=windows-1252')

    def test_windows1252_hidden_meta_does_not_enable_codec(self):
        for prefix in ('<!-- <meta charset="windows-1252"> -->',
                       '<script><meta charset="windows-1252"></script>',
                       '<template><meta charset="windows-1252"></template>',
                       '<head></head><meta charset="windows-1252">',
                       '<body><meta charset="windows-1252">'):
            with self.assertRaisesRegex(encoding.PageEncodingError, 'CHARSET_INVALID_BYTES'):
                encoding.decode_page((prefix+'€').encode('cp1252'), 'text/html')

    def test_windows1252_after_declaration_window_not_adopted(self):
        body = b' '*encoding.MAX_DECLARATION_BYTES+b'<meta charset="windows-1252">\x80'
        with self.assertRaisesRegex(encoding.PageEncodingError, 'CHARSET_INVALID_BYTES'):
            encoding.decode_page(body, 'text/html')

    def test_windows1252_pure_no_io(self):
        with patch('builtins.open') as opened, patch('socket.getaddrinfo') as dns, patch('subprocess.run') as run:
            self.assertEqual(encoding.decode_page(b'<html>\x80</html>', 'text/html; charset=windows-1252'), '<html>€</html>')
            opened.assert_not_called()
            dns.assert_not_called()
            run.assert_not_called()


class DeclaredEncodingTransportTests(unittest.TestCase):
    """同じ有限transportで宣言codecを使い、HTTP拒否を昇格しない。"""

    def fixture_route_arguments(self, url):
        """同梱packageを使わない現route子の固定bootstrapとURL一件を組み立てる。

        実行はせず、fakeが認める最初のargvを返す。Pythonは現在の試験runnerの
        executable、module探索先は読み取り中のhttp moduleのdirectoryへ固定する。
        """
        return [sys.executable, '-I', '-B', '-S', '-c',
                'import sys;sys.path.insert(0,sys.argv[1]);import registry_monitor_http as h;'
                'sys.exit(h.route_main(sys.argv[2:]))', str(Path(http.__file__).resolve().parent), url]

    def fixture_process(self, body, header, *, calls, status=200, returncode=0, kind='PAGE', prefix=b''):
        """route子一回と絶対curl一回だけへ応答する同期callbackを返す。

        body／header／prefixとcallsはcallback利用中だけ借用し、外部processやDNSは
        起動しない。認めたargvのcopyをcallsへ追加する。未知argv、順序違反、異なる
        executable／optionはAssertionErrorとし、成功したroute応答へ読み替えない。
        """
        self.assertIn(kind, ('PAGE', 'LINK'))
        url = PAGE if kind == 'PAGE' else LINK
        route_args = self.fixture_route_arguments(url)

        def fake_run(args, **options):
            """既知の役割と全optionを照合してから架空byteを返す／一時出力へ書く。

            借用byteはcurl役割の照合成功後だけ、その呼出し中の一時directoryへ書く。
            directoryの作成と削除はCurlTransportまたは直接試験のwith所有者が行う。
            """
            self.assertIs(type(args), list)
            # 最初の呼出しだけがroute解決役割を持ち、他のprocessを代用しない。
            if not calls:
                self.assertEqual(args, route_args)
                self.assertEqual(options, {'executable': route_args[0], 'stdout': subprocess.PIPE,
                    'stderr': subprocess.DEVNULL, 'timeout': 5, 'check': False})
                calls.append(args.copy())
                return subprocess.CompletedProcess(args, 0,
                    stdout=b'{"route":{"source":"SYSTEM","proxy":""},"addresses":["8.8.8.8"]}')

            # 二回目だけをcurlへ結合し、三回目や異なるPAGE／HEAD構成を拒否する。
            self.assertEqual(len(calls), 1)
            self.assertEqual(len(args), 29 if kind == 'PAGE' else 28)
            headers_path = Path(args[19])
            body_path = Path(args[21])
            self.assertTrue(headers_path.is_absolute())
            self.assertEqual(headers_path.name, 'headers')
            self.assertEqual(body_path, headers_path.parent / 'body')
            self.assertTrue(headers_path.parent.name.startswith('drivercrate-monitor-http-'))
            self.assertTrue(headers_path.parent.is_dir())
            expected = [FIXTURE_CURL, '-q', '--silent', '--fail', '--proto', '=https',
                '--max-redirs', '0', '--connect-timeout', '5', '--max-time', '20',
                '--proxy', '', '--noproxy', '', '--connect-to', 'vendor.example.org:443:8.8.8.8:443',
                '--dump-header', str(headers_path), '--output', str(body_path),
                '--write-out', '%{http_code}', '--user-agent', 'DriverCrate-maintenance-monitor/1']
            expected += ['--max-filesize', str(http.MAX_BODY)] if kind == 'PAGE' else ['--head']
            self.assertEqual(args, expected + [url])
            self.assertEqual(options, {'executable': FIXTURE_CURL, 'stdout': subprocess.PIPE,
                'stderr': subprocess.DEVNULL, 'timeout': 22, 'check': False})
            calls.append(args.copy())
            headers_path.write_bytes(prefix+header)
            body_path.write_bytes(body)
            return subprocess.CompletedProcess(args,returncode,stdout=str(status).encode())
        return fake_run

    def observed(self, body, header, *, status=200, returncode=0, kind='PAGE', prefix=b''):
        """借用byteをtyped routeと固定curl役割のfakeへ渡し、実transportの観測値を返す。

        body／header／prefixは同期呼出し中だけcallbackへ借用する。架空System32 pathと
        subprocess.runのpatchはこのwith内だけ有効であり、実route子／curlは起動しない。
        一時body／headerはCurlTransportのTemporaryDirectoryがwith終了時に後始末する。
        二回の既知呼出しとredirect禁止をassertし、本文／codec等の結果は各testへ返す。
        """
        calls = []
        fake_run = self.fixture_process(body, header, calls=calls, status=status,
            returncode=returncode, kind=kind, prefix=prefix)
        with patch.object(http, 'system_curl_path', return_value=FIXTURE_CURL), \
             patch.object(http.subprocess,'run',side_effect=fake_run):
            result = http.CurlTransport()(kind,PAGE if kind=='PAGE' else LINK)
        self.assertEqual(len(calls),2)
        self.assertNotIn('--location',calls[1])
        return result

    def test_transport_fixture_page_process_contract(self):
        """Q01: typed routeから絶対curlのPAGE GETへ進み、元byteとliteral linkを保持する。"""
        body = b'<html><a href="/driver.zip">driver</a></html>'
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
        self.assertEqual(self.observed(body, header),
            http.response(200, body=body, links=[cr.digest(LINK.encode())]))

    def test_transport_fixture_link_head_contract(self):
        """Q02: LINKは同じrouteを使ってHEADだけを構成し、本文をdecodeしない。"""
        with patch.object(encoding, 'decode_page') as decoded:
            self.assertEqual(self.observed(b'\xff', b'HTTP/1.1 200 OK\r\n\r\n', kind='LINK'),
                http.response(200))
            decoded.assert_not_called()

    def test_transport_fixture_rejects_unknown_process_role(self):
        """Q03: 四つの未知argvをroute成功へ昇格せず、呼出し記録も未受理のままにする。"""
        route_args = self.fixture_route_arguments(PAGE)
        wrong_bootstrap = route_args.copy()
        wrong_bootstrap[5] = 'import unrelated_worker'
        # 四入力を一度ずつ照合し、すべて最初の役割検査で拒否されることを確認する。
        for args in (['unknown.exe'], ['curl.exe'], wrong_bootstrap, route_args + ['extra']):
            with self.subTest(args=args):
                calls = []
                fake_run = self.fixture_process(b'', b'', calls=calls)
                with self.assertRaises(AssertionError):
                    fake_run(args, executable=args[0], stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=5, check=False)
                self.assertEqual(calls, [])

    def test_transport_fixture_rejects_curl_contract_mismatch(self):
        """Q04: curlの六つのargv／option違反と三回目呼出しを成功応答前に拒否する。"""
        # 直接fakeを呼ぶ試験の一時出力は、このwithが所有して成功・失敗時とも削除する。
        with tempfile.TemporaryDirectory(prefix='drivercrate-monitor-http-') as folder:
            body_path = Path(folder) / 'body'
            headers_path = Path(folder) / 'headers'
            route_args = self.fixture_route_arguments(PAGE)
            args = http.curl_command(FIXTURE_CURL, 'PAGE', PAGE,
                {'source': 'SYSTEM', 'proxy': ''}, '8.8.8.8', headers_path, body_path)
            options = {'executable': FIXTURE_CURL, 'stdout': subprocess.PIPE,
                'stderr': subprocess.DEVNULL, 'timeout': 22, 'check': False}
            mutations = ((['curl.exe'] + args[1:], options),
                (args + ['--location'], options), (args[:-3] + ['--head', PAGE], options),
                (args, dict(options, executable='curl.exe')), (args, dict(options, timeout=5)),
                (args, dict(options, check=True)))
            # 六違反を独立したroute受理後に一度ずつ試し、書込み前の拒否を確認する。
            for bad_args, bad_options in mutations:
                with self.subTest(args=bad_args, options=bad_options):
                    calls = []
                    fake_run = self.fixture_process(b'<html/>', b'', calls=calls)
                    fake_run(route_args, executable=route_args[0], stdout=subprocess.PIPE,
                        stderr=subprocess.DEVNULL, timeout=5, check=False)
                    with self.assertRaises(AssertionError):
                        fake_run(bad_args, **bad_options)
                    self.assertEqual(len(calls), 1)
                    self.assertFalse(body_path.exists())
                    self.assertFalse(headers_path.exists())
            calls = []
            fake_run = self.fixture_process(b'<html/>', b'', calls=calls)
            fake_run(route_args, executable=route_args[0], stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL, timeout=5, check=False)
            fake_run(args, **options)
            with self.assertRaises(AssertionError):
                fake_run(args, **options)
            self.assertEqual(len(calls), 2)

    def test_shiftjis_http_and_meta_cp932_utf8_transport(self):
        cases = (('shift_jis','text/html; charset=shift_jis',''),
                 ('shift_jis','text/html','<meta charset="shift_jis">'),
                 ('cp932','text/html; charset=windows-31j',''),
                 ('utf-8','text/html',''))
        for codec, content_type, meta in cases:
            text = f'<html><head>{meta}</head><body>架空<a href="/driver.zip">driver</a></body></html>'
            body = text.encode(codec)
            header = f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\n\r\n'.encode()
            result = self.observed(body,header)
            self.assertEqual(result, http.response(200,body=body,links=[cr.digest(LINK.encode())]))

    def test_original_bytes_and_redacted_text_encoding_failure(self):
        body = b'<html><meta charset="unknown"></html>'
        result = self.observed(body,b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n')
        self.assertEqual(result,http.response(200,'TEXT_ENCODING',body))

    def test_only_final_header_block_supplies_charset(self):
        body = '<html>架空</html>'.encode('shift_jis')
        prefix = b'HTTP/1.1 100 Continue\r\nContent-Type: text/html; charset=unknown\r\n\r\n'
        result = self.observed(body,b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=shift_jis\r\n\r\n',prefix=prefix)
        self.assertEqual(result['error'],'NONE')

    def test_failed_http_and_redirect_not_decoded(self):
        with patch.object(encoding,'decode_page') as decoded:
            for status in (301,403,429,503):
                result = self.observed(b'<html/>',b'HTTP/1.1 503 Unavailable\r\nRetry-After: 3600\r\n\r\n',
                    status=status,returncode=22 if status!=301 else 0)
                self.assertEqual(result['error'],'HTTP_ERROR')
                self.assertEqual(result['retryAfter'],'3600')
            decoded.assert_not_called()

    def test_content_and_size_rejection_happen_before_decode(self):
        with patch.object(encoding,'decode_page') as decoded:
            cases = ((b'<html/>',b'Content-Type: text/plain\r\n','CONTENT_TYPE'),
                     (b'<html/>',b'Content-Type: text/html\r\nContent-Type: text/html\r\n','CONTENT_TYPE'),
                     (b'<html/>',b'Content-Type: text/html\r\nContent-Encoding: gzip\r\n','CONTENT_ENCODING'),
                     (b'',b'Content-Type: text/html\r\n','BODY_SIZE'),
                     (b'x'*(http.MAX_BODY+1),b'Content-Type: text/html\r\n','BODY_SIZE'))
            for body, attributes, error in cases:
                self.assertEqual(self.observed(body,b'HTTP/1.1 200 OK\r\n'+attributes+b'\r\n')['error'],error)
            decoded.assert_not_called()

    def test_payload_head_not_decoded(self):
        with patch.object(encoding,'decode_page') as decoded:
            self.assertEqual(self.observed(b'',b'HTTP/1.1 200 OK\r\n\r\n',kind='LINK'),http.response(200))
            decoded.assert_not_called()

    def test_windows1252_transport_hash_and_literal_link(self):
        text = '<html><head><meta charset="windows-1252"></head><body>® “driver” €<a href="/driver.zip">get</a></body></html>'
        body = text.encode('cp1252')
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
        self.assertEqual(self.observed(body, header), http.response(200, body=body, links=[cr.digest(LINK.encode())]))

    def test_windows1252_final_header_only(self):
        prefix = b'HTTP/1.1 100 Continue\r\nContent-Type: text/html; charset=utf-8\r\n\r\n'
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=windows-1252\r\n\r\n'
        body = b'<html>\x80</html>'
        self.assertEqual(self.observed(body, header, prefix=prefix), http.response(200, body=body))

    def test_windows1252_transport_invalid_keeps_raw_hash(self):
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=windows-1252\r\n\r\n'
        body = b'<html>\x81</html>'
        self.assertEqual(self.observed(body, header), http.response(200, 'TEXT_ENCODING', body))

    def test_windows1252_transport_unlabelled_rejects(self):
        body = b'<html>\x80</html>'
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n'
        self.assertEqual(self.observed(body, header), http.response(200, 'TEXT_ENCODING', body))

    def test_windows1252_transport_conflict_rejects(self):
        body = b'<meta charset="windows-1252">'
        header = b'HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\n\r\n'
        self.assertEqual(self.observed(body, header), http.response(200, 'TEXT_ENCODING', body))

    def test_windows1252_http_failure_not_decoded(self):
        with patch.object(encoding, 'decode_page') as decoded:
            body = b'<meta charset="windows-1252">\x80'
            header = b'HTTP/1.1 403 Forbidden\r\nContent-Type: text/html; charset=windows-1252\r\n\r\n'
            self.assertEqual(self.observed(body, header, status=403, returncode=22)['error'], 'HTTP_ERROR')
            decoded.assert_not_called()
