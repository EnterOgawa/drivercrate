"""公式HTML文書用途だけの有限・strict解析（ADR 0307）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
通信・原transport変更・本文保存・script実行・driver取得許可を行わない。
"""
from html.parser import HTMLParser
import re
import collector_page_encoding as encoding

MAX_HEADERS = 128 * 1024


class DocumentError(ValueError):
    """本文・headerを含まない閉じた文書拒否codeを保持する。"""


def require(condition, code):
    """文書の拒否を診断codeだけで通知する。"""
    if not condition:
        raise DocumentError(code)


def final_headers(raw):
    """有限headerの最終HTTP200 blockから必要な三fieldだけをRAMへ読む。"""
    require(type(raw) is bytes and 0 < len(raw) <= MAX_HEADERS, 'DOCUMENT_HEADER_SIZE')
    blocks = [block for block in raw.split(b'\r\n\r\n') if block.startswith(b'HTTP/')]
    require(bool(blocks), 'DOCUMENT_HTTP_STATUS')
    lines = blocks[-1].split(b'\r\n')
    require(re.match(rb'HTTP/[0-9.]+ 200(?:\s|$)', lines[0]) is not None, 'DOCUMENT_HTTP_STATUS')
    values = {}
    for line in lines[1:]:
        key, separator, value = line.partition(b':')
        require(bool(separator) and re.fullmatch(rb'[A-Za-z0-9-]{1,64}', key) is not None, 'DOCUMENT_HEADER_SYNTAX')
        if key.lower() in {b'content-type', b'content-encoding', b'content-length'}:
            try:
                text = value.strip().decode('ascii', errors='strict')
            except UnicodeError as error:
                raise DocumentError('DOCUMENT_HEADER_SYNTAX') from error
            values.setdefault(key.lower(), []).append(text)
    return values


class RootStructure(HTMLParser):
    """raw text／inert内を除き、閉じた単一html／head／bodyだけを確認する。"""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.starts = dict(html=0, head=0, body=0)
        self.ends = dict(html=0, head=0, body=0)
        self.hidden = None
        self.depth = 0
        self.open_root = False
        self.invalid = False

    def handle_starttag(self, tag, attrs):
        if self.hidden is not None:
            if tag == self.hidden:
                self.depth += 1
            return
        if tag in encoding.MetaDeclarations.HIDDEN:
            self.hidden, self.depth = tag, 1
            return
        if tag in self.starts:
            self.starts[tag] += 1
            if tag == 'html':
                self.open_root = True
            elif not self.open_root:
                self.invalid = True

    def handle_endtag(self, tag):
        if self.hidden == tag and tag != 'plaintext':
            self.depth -= 1
            if self.depth == 0:
                self.hidden = None
            return
        if self.hidden is not None:
            return
        if tag in self.ends:
            self.ends[tag] += 1
            if not self.open_root:
                self.invalid = True
            if tag == 'html':
                self.open_root = False


def decode_document(body, headers, *, purpose):
    """明示文書用途とHTML構造を要求し、同じ共通decoderでstrict解析する。

    戻り値はtextと原media typeである。octet-streamの正規化は文書解析用
    引数だけに限定し、原headerやtransportの結果を変更しない。
    """
    require(purpose == 'HTML_DOCUMENT', 'DOCUMENT_PURPOSE')
    require(type(body) is bytes and 0 < len(body) <= encoding.MAX_BODY_BYTES, 'DOCUMENT_BODY_SIZE')
    require(b'\x00' not in body, 'DOCUMENT_BINARY')
    values = final_headers(headers)
    types = values.get(b'content-type', [])
    require(len(types) == 1, 'DOCUMENT_CONTENT_TYPE')
    media, separator, parameters = types[0].partition(';')
    media = media.strip().lower()
    require(media in {'text/html', 'application/xhtml+xml', 'application/octet-stream'}, 'DOCUMENT_CONTENT_TYPE')
    require(values.get(b'content-encoding', ['identity']) == ['identity'], 'DOCUMENT_CONTENT_ENCODING')
    lengths = values.get(b'content-length', [])
    require(not lengths or (len(lengths) == 1 and re.fullmatch(r'[0-9]{1,18}', lengths[0]) is not None
        and int(lengths[0]) == len(body)), 'DOCUMENT_CONTENT_LENGTH')
    prefix = body[:encoding.MAX_DECLARATION_BYTES]
    if prefix.startswith(b'\xef\xbb\xbf'):
        prefix = prefix[3:]
    require(re.match(rb'\s*(?:<!doctype\s+html[^>]{0,512}>\s*)?<html(?:\s|>)', prefix, re.I) is not None,
        'DOCUMENT_HTML_ROOT')
    parse_type = 'text/html'+(';' + parameters if separator else '') if media == 'application/octet-stream' else types[0]
    text = encoding.decode_page(body, parse_type)
    parser = RootStructure()
    parser.feed(text)
    parser.close()
    require(not parser.invalid and not parser.open_root and parser.hidden is None
        and all(value == 1 for value in (*parser.starts.values(), *parser.ends.values())), 'DOCUMENT_HTML_STRUCTURE')
    return text, media
