"""明示HTML文字コードを有限・strict解析する純粋decoder（ADR 0303／0306）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
通信・本文保存・script実行・codec推定／置換を行わない。
"""
from html.parser import HTMLParser
import re

MAX_BODY_BYTES = 2 * 1024 * 1024
MAX_DECLARATION_BYTES = 8192
CODECS = {'utf-8':'utf-8', 'utf8':'utf-8', 'shift_jis':'shift_jis',
          'shift-jis':'shift_jis', 'sjis':'shift_jis',
          'cp932':'cp932', 'windows-31j':'cp932', 'ms932':'cp932',
          'windows-1252':'cp1252'}


class PageEncodingError(ValueError):
    """値・本文を含まない有限解析の拒否codeを保持する。"""


def charset_parameters(value: str) -> list[str]:
    """引用符内のsemicolonを区切らず、明示charset parameterだけを読む。"""
    if type(value) is not str or len(value) > MAX_DECLARATION_BYTES:
        raise PageEncodingError('CHARSET_HEADER_SIZE')
    parts, start, quote, escaped = [], 0, None, False
    for index, char in enumerate(value):
        if escaped:
            escaped = False
        elif quote and char == '\\':
            escaped = True
        elif quote and char == quote:
            quote = None
        elif not quote and char in {'\"', "'"}:
            quote = char
        elif not quote and char == ';':
            parts.append(value[start:index])
            start = index + 1
    if quote or escaped:
        raise PageEncodingError('CHARSET_PARAMETER_SYNTAX')
    parts.append(value[start:])
    labels = []
    for part in parts[1:]:
        key, separator, label = part.partition('=')
        if key.strip().lower() != 'charset':
            continue
        label = label.strip()
        if label[:1] in {'\"', "'"}:
            label = label[1:-1] if len(label) >= 2 and label[-1] == label[0] else ''
        if not separator or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', label):
            raise PageEncodingError('CHARSET_PARAMETER_SYNTAX')
        labels.append(label.lower())
    return labels


class MetaDeclarations(HTMLParser):
    """先頭の宣言だけを読み、raw text／inert領域の偽metaを除く。"""

    HIDDEN = {'script','style','textarea','title','xmp','iframe','noembed',
              'noframes','noscript','template','svg','math','plaintext'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.labels = []
        self.hidden_tag = None
        self.hidden_depth = 0
        self.finished = False

    def handle_starttag(self, tag, attrs):
        if self.finished:
            return
        if self.hidden_tag is not None:
            if tag == self.hidden_tag:
                self.hidden_depth += 1
            return
        if tag in self.HIDDEN:
            self.hidden_tag, self.hidden_depth = tag, 1
            return
        if tag == 'body':
            self.finished = True
            return
        if tag != 'meta':
            return
        attributes = {}
        for name, value in attrs:
            if name in {'charset','http-equiv','content'}:
                if name in attributes:
                    raise PageEncodingError('CHARSET_DUPLICATE_ATTRIBUTE')
                attributes[name] = value
        if 'charset' in attributes:
            label = attributes['charset']
            if type(label) is not str or not re.fullmatch(r'[A-Za-z0-9_-]{1,48}', label):
                raise PageEncodingError('CHARSET_META_SYNTAX')
            self.labels.append(label.lower())
        if (attributes.get('http-equiv') or '').strip().lower() == 'content-type':
            content = attributes.get('content')
            if type(content) is not str:
                raise PageEncodingError('CHARSET_META_SYNTAX')
            self.labels.extend(charset_parameters(content))

    def handle_endtag(self, tag):
        if self.hidden_tag == tag and tag != 'plaintext':
            self.hidden_depth -= 1
            if self.hidden_depth == 0:
                self.hidden_tag = None
        elif self.hidden_tag is None and tag == 'head':
            self.finished = True


def decode_page(body: bytes, content_type: str) -> str:
    """一致する許容宣言だけをstrict decodeし、未宣言はUTF-8互換を維持する。

    最大2MiBの非空bodyとHTML型を要求する。失敗時は本文を含まない
    PageEncodingErrorを返し、他codecでの再試行を行わない。
    """
    if type(body) is not bytes or not 0 < len(body) <= MAX_BODY_BYTES:
        raise PageEncodingError('CHARSET_BODY_SIZE')
    if type(content_type) is not str or content_type.split(';',1)[0].strip().lower() not in {
            'text/html','application/xhtml+xml'}:
        raise PageEncodingError('CHARSET_CONTENT_TYPE')
    labels = charset_parameters(content_type)
    parser = MetaDeclarations()
    # Latin-1はASCII構造を一対一で読むためだけで、本文のdecodeには使わない。
    parser.feed(body[:MAX_DECLARATION_BYTES].decode('latin-1'))
    parser.close()
    labels.extend(parser.labels)
    if any(label not in CODECS for label in labels):
        raise PageEncodingError('CHARSET_UNSUPPORTED')
    codecs = {CODECS[label] for label in labels}
    if body.startswith((b'\xff\xfe',b'\xfe\xff',b'\x00\x00\xfe\xff')):
        raise PageEncodingError('CHARSET_UNSUPPORTED_BOM')
    if body.startswith(b'\xef\xbb\xbf'):
        codecs.add('utf-8')
    if len(codecs) > 1:
        raise PageEncodingError('CHARSET_CONFLICT')
    codec = next(iter(codecs)) if codecs else 'utf-8'
    try:
        return body.decode('utf-8-sig' if codec == 'utf-8' else codec, errors='strict')
    except UnicodeError as error:
        raise PageEncodingError('CHARSET_INVALID_BYTES') from error
