"""宣言と定義を各sourceで独立検査する有限のC++字句解析。未対応署名は診断する。

実挙動・例外・所有契約の正しさはbody reviewを要する。Doxygenのmerge結果は
代用しない。macro本体は展開せず、literal・型・field・lambdaを関数と数えない。
"""
import re
from bisect import bisect_left
from functools import lru_cache
from source_style import tokenize, IGNORED_KINDS
from source_comments import doxy_entries
from source_structure import bracket_pairs

def meaningless_reference_summary(text):
    text = text.strip()
    return bool(re.search('^(?:宣言(?:側)?の(?:契約|説明)|参照先の(?:契約|説明)|契約は|詳細は|説明は).*(?:正本|参照|見る|委ね)', text) or re.fullmatch('(?:参照先を?(?:見る|参照する|確認する)(?:だけ)?|[@\\\\](?:see|copydoc|copybrief|copydetails|inheritdoc)\\b.*)[。.]?', text))

def rename_parameter_text(text, old, new):
    protected = [m.span() for m in re.finditer('https?://\\S+|(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\\.(?:h|hpp|cpp|cc|cxx|md|py|ps1)\\b|\\b[A-Za-z_]\\w*(?:::[A-Za-z_]\\w*)+', text)]
    pattern = '(?<![A-Za-z0-9_])' + re.escape(old) + '(?![A-Za-z0-9_])'
    return re.sub(pattern, lambda m: m.group() if any((a <= m.start() < b for a, b in protected)) else new, text)

def split_arguments(tokens):
    parts = []
    start = 0
    stack = []
    angle = 0
    for i, t in enumerate(tokens):
        s = t.text
        if s in ['(', '[', '{']:
            stack.append(s)
        elif s in [')', ']', '}']:
            if not stack:
                raise ValueError('argument delimiter')
            stack.pop()
        elif not stack:
            if s == '<':
                angle += 1
            elif s in ['>', '>>'] and angle:
                angle = max(0, angle - len(s))
            elif s == ',' and angle == 0:
                parts.append(tokens[start:i])
                start = i + 1
    if tokens[start:]:
        parts.append(tokens[start:])
    return parts

def parameter(tokens):
    full = tokens
    stack = []
    angle = 0
    for i, t in enumerate(tokens):
        s = t.text
        if s in ['(', '[', '{']:
            stack.append(s)
        elif s in [')', ']', '}'] and stack:
            stack.pop()
        elif not stack:
            if s == '<':
                angle += 1
            elif s in ['>', '>>'] and angle:
                angle = max(0, angle - len(s))
            elif s == '=' and (not angle):
                tokens = tokens[:i]
                break
    if not tokens:
        return {'name': None, 'type': '', 'raw': ''}
    text = ' '.join((t.text for t in tokens))
    ptr = re.search('\\(\\s*[*&]\\s*(\\w+)\\s*\\)', text)
    name = ptr.group(1) if ptr else None
    name_index = None
    if ptr:
        name_index = next((i for i in range(2, len(tokens) - 1)
                           if tokens[i].text == name and tokens[i - 1].text in {'*', '&'}
                           and tokens[i - 2].text == '(' and tokens[i + 1].text == ')'), None)
    words = [(i, t.text) for i, t in enumerate(tokens) if t.kind == 'identifier' and t.text not in {'const', 'volatile', 'struct', 'class', 'enum', 'typename', 'void', 'bool', 'char', 'wchar_t', 'char8_t', 'char16_t', 'char32_t', 'short', 'int', 'long', 'float', 'double', 'signed', 'unsigned', 'auto', 'consteval', 'constexpr'}]
    if not name and words:
        i, candidate = words[-1]
        after = [t.text for t in tokens[i + 1:]]
        before = [t.text for t in tokens[:i]]
        if not (before and before[-1] == '::') and (not (after and after[0] in ['::', '<', '>', '>>', '&', '&&', '*'])) and (len(words) > 1 or any((t in before for t in ['int', 'char', 'bool', 'void', 'long', 'short', 'unsigned', 'signed', 'float', 'double', 'wchar_t', 'auto', 'typename', 'class']))):
            name = candidate
            name_index = i
    material = []
    for index, t in enumerate(tokens):
        if index == name_index:
            continue
        material.append(t.text)
    return {'name': name, 'type': ' '.join(material), 'raw': ' '.join((t.text for t in full))}

@lru_cache(maxsize=4)
def source_tokens(source):
    raw_tokens = tokenize(source)
    directives = []
    for token in raw_tokens:
        if token.kind != 'operator' or token.text != '#' or source[source.rfind('\n', 0, token.start) + 1:token.start].strip():
            continue
        end = source.find('\n', token.end)
        end = len(source) if end < 0 else end + 1
        while source[token.start:end].rstrip('\r\n').endswith('\\') and end < len(source):
            following = source.find('\n', end)
            end = len(source) if following < 0 else following + 1
        directives.append((token.start, end))
    tokens = []
    index = 0
    for t in raw_tokens:
        while index < len(directives) and directives[index][1] <= t.start:
            index += 1
        if t.kind in IGNORED_KINDS or (index < len(directives) and directives[index][0] <= t.start < directives[index][1]):
            continue
        tokens.append(t)
    return (tokens, [t.start for t in tokens])

@lru_cache(maxsize=4)
def class_contexts(source):
    tokens, _ = source_tokens(source)
    stack = []
    positions = [0]
    states = [False]
    pending = False
    previous = ''
    template_depth = 0
    await_template = False
    for token in tokens:
        value = token.text
        if value == 'template':
            await_template = True
        elif await_template and value == '<':
            template_depth = 1
            await_template = False
        elif template_depth:
            if value == '<':
                template_depth += 1
            elif value in ['>', '>>']:
                template_depth = max(0, template_depth - len(value))
        elif value in ['class', 'struct', 'union'] and previous != 'enum':
            pending = True
        elif value in ['(', ';', '=']:
            pending = False
        if value == '{':
            stack.append('class' if pending else 'block')
            pending = False
            positions.append(token.end)
            states.append(bool(stack and stack[-1] == 'class'))
        elif value == '}':
            if stack:
                stack.pop()
            pending = False
            positions.append(token.end)
            states.append(bool(stack and stack[-1] == 'class'))
        previous = value
    return (positions, states)

def in_class(source, offset):
    positions, states = class_contexts(source)
    return states[max(0, bisect_left(positions, offset + 1) - 1)]

def signature(source, start):
    all_tokens, starts = source_tokens(source)
    tokens = all_tokens[bisect_left(starts, start):][:2500]
    if not tokens:
        return {'kind': 'none'}
    if tokens[0].text == '#':
        return {'kind': 'preprocessor'}
    if tokens[0].text in ['namespace', 'struct', 'class', 'enum', 'union', 'using', 'typedef']:
        return {'kind': 'type', 'signature': ' '.join((t.text for t in tokens[:12]))}
    if tokens[0].text == 'template' and len(tokens) > 1 and (tokens[1].text == '<'):
        depth = 1
        after_template = 2
        while after_template < len(tokens) and depth:
            if tokens[after_template].text == '<':
                depth += 1
            elif tokens[after_template].text in {'>', '>>'}:
                depth -= len(tokens[after_template].text)
            after_template += 1
        if after_template < len(tokens) and tokens[after_template].text in {'class', 'struct', 'union', 'using'}:
            return {'kind': 'type', 'signature': ' '.join((t.text for t in tokens[:after_template + 2]))}
    stack = []
    pairs = {}
    for i, t in enumerate(tokens[:2500]):
        s = t.text
        if s in ['(', '[']:
            stack.append((i, s))
        elif s in [')', ']']:
            if not stack:
                return {'kind': 'unknown', 'reason': 'unbalanced signature'}
            j, op = stack.pop()
            pairs[j] = i
        if not stack and s in ['{', ';']:
            break
    angle = 0
    opening = None
    operator = None
    i = 0
    while i < len(tokens) and i < 2500:
        s = tokens[i].text
        if s in ['{', ';']:
            break
        if s == '[' and i in pairs:
            i = pairs[i] + 1
            continue
        if s == 'operator':
            operator = i
        if s == '<' and operator is None:
            angle += 1
        elif s in ['>', '>>'] and angle:
            angle = max(0, angle - len(s))
        if s == '(' and (not angle):
            if i not in pairs:
                return {'kind': 'unknown', 'reason': 'unclosed parameter list'}
            prev = tokens[i - 1].text if i else ''
            if prev in ['decltype', 'alignas', 'noexcept', 'requires']:
                i = pairs[i] + 1
                continue
            if operator is not None and i == operator + 1 and (pairs[i] == i + 1):
                i = pairs[i] + 1
                continue
            opening = i
            break
        i += 1
    if opening is None:
        return {'kind': 'nonmethod'}
    if operator is None and any((t.text == '=' for t in tokens[:opening])):
        return {'kind': 'lambda-or-expression'}
    end = pairs[opening]
    first = operator if operator is not None else opening - 1
    if first < 0:
        return {'kind': 'unknown', 'reason': 'unnamed callable'}
    if tokens[first].text == '>':
        return {'kind': 'unknown', 'reason': 'specialized function name'}
    if first and tokens[first - 1].text == '~':
        first -= 1
    while first >= 2 and tokens[first - 1].text == '::':
        first -= 2
    full = ''.join((t.text for t in tokens[first:opening]))
    name = full.split('::')[-1]
    if name == ']' or (operator is None and any((t.text == '=' for t in tokens[:opening]))):
        return {'kind': 'lambda-or-expression'}
    kept = []
    j = 0
    template_params = []
    while j < first:
        if tokens[j].text == '[' and j in pairs:
            j = pairs[j] + 1
            continue
        if tokens[j].text == 'template' and j + 1 < first and (tokens[j + 1].text == '<'):
            depth = 1
            j += 2
            template_start = j
            while j < first and depth:
                if tokens[j].text == '<':
                    depth += 1
                elif tokens[j].text in ['>', '>>']:
                    depth -= len(tokens[j].text)
                j += 1
            template_params.extend((parameter(p) for p in split_arguments(tokens[template_start:j - 1])))
            continue
        kept.append(tokens[j].text)
        j += 1
    prefix = ' '.join(kept)
    prefix = re.sub('\\b(?:virtual|static|inline|explicit|constexpr|consteval|friend|extern|CALLBACK|WINAPI)\\b', '', prefix).strip()
    params = split_arguments(tokens[opening + 1:end])
    if len(params) == 1 and len(params[0]) == 1 and (params[0][0].text == 'void'):
        params = []
    ps = [parameter(p) for p in params]
    if any((p and p[0].kind in {'number', 'character', 'string', 'raw'} for p in params)):
        return {'kind': 'nonmethod'}
    if name.startswith('operator') and (not prefix) and (name != 'operator()'):
        prefix = name[len('operator'):]
    tail = [t.text for t in tokens[end + 1:]]
    stop = next((i for i, v in enumerate(tail) if v in ['{', ';']), len(tail))
    tail = tail[:stop]
    if prefix == 'auto' and '->' in tail:
        prefix = ' '.join(tail[tail.index('->') + 1:])
    return {'kind': 'method', 'name': name, 'qualified': full, 'params': ps, 'return': prefix, 'returnsValue': bool(prefix) and prefix != 'void', 'signature': ' '.join((t.text for t in tokens[:end + 1])), 'deleted': 'delete' in tail, 'defaulted': 'default' in tail, 'templateParams': template_params, 'begin': tokens[0].start, 'argsEnd': tokens[end].end}


def _scope_kind(tokens):
    """template引数中のclassを宣言scopeと取り違えず、再帰するscopeを返す。"""
    depth = 0
    previous = ''
    for token in tokens:
        value = token.text
        if value == '<':
            depth += 1
        elif value in {'>', '>>'} and depth:
            depth = max(0, depth - len(value))
        elif not depth:
            if value == 'namespace':
                return 'namespace'
            if value == 'enum':
                return 'enum'
            if value in {'class', 'struct', 'union'}:
                return 'class'
        previous = value
    if tokens and tokens[0].text == 'extern' and any(t.kind == 'string' for t in tokens):
        return 'namespace'
    return 'block'


def declaration_signatures(source):
    """namespace/classの宣言列を走査し、関数body・initializer・macro定義へは潜らない。

    C++全構文のparserではない。delimiter不整合とsignatureのunknownは呼出側が
    不合格へ結ぶ。関数templateの特殊化等を推測で既知へ変換しない。
    """
    tokens, _ = source_tokens(source)
    pairs = bracket_pairs(tokens)
    result = []

    def walk(begin, end):
        index = begin
        while index < end:
            if tokens[index].text in {';', '}'}:
                index += 1
                continue
            if (tokens[index].text in {'public', 'protected', 'private'}
                    and index + 1 < end and tokens[index + 1].text == ':'):
                index += 2
                continue
            start = index
            cursor = index
            while cursor < end and tokens[cursor].text not in {';', '{'}:
                if tokens[cursor].text in {'(', '['}:
                    cursor = pairs[cursor]
                cursor += 1
            parsed = signature(source, tokens[start].start)
            parsed.setdefault('begin', tokens[start].start)
            if (parsed['kind'] in {'method', 'unknown'}
                    and parsed.get('name') not in {'static_assert', 'alignas', 'catch'}):
                result.append(parsed)
            if cursor == end:
                break
            if tokens[cursor].text == '{':
                closing = pairs[cursor]
                if _scope_kind(tokens[start:cursor]) in {'namespace', 'class'}:
                    walk(cursor + 1, closing)
                index = closing + 1
                # 即時lambdaの呼出しpostfixは同じinitializerであり、新しい宣言ではない。
                if any(t.text == '=' for t in tokens[start:cursor]):
                    while index < end and tokens[index].text == '(':
                        index = pairs[index] + 1
            else:
                index = cursor + 1

    walk(0, len(tokens))
    return result


def contract_errors(source, token, parsed=None):
    """単一のsource blockと直後の実署名を検査し、XMLの共有文書へ委ねない。"""
    parsed = signature(source, token.end) if parsed is None else parsed
    if parsed['kind'] != 'method':
        return ['unsupported method signature: ' + parsed.get('reason', parsed['kind'])]
    errors = []
    entries = doxy_entries(token.text)
    briefs = [v for k, v in entries if k == '@brief ']
    if (len(briefs) != 1 or not briefs[0].strip()
            or meaningless_reference_summary(briefs[0])):
        errors.append('independent @brief is missing or only refers to another contract')
    if any(k.strip() in {'@copydoc', '@copybrief', '@copydetails', '@inheritdoc'}
           for k, _ in entries):
        errors.append('inherited contract tags must be supplementary @see after a complete contract')
    lines = token.text.splitlines()
    if (lines[0].strip() != '/**' or lines[-1].strip() != '*/'
            or any(not re.fullmatch(r'[ \t]*\*(?:[ \t].*)?', line)
                   for line in lines[1:-1])):
        errors.append('method contract requires separate /**, * lines and */')
    if not in_class(source, token.start):
        before = source[:token.start].splitlines()[-2:]
        after = source[token.end:].splitlines()[:2]
        if not (any(re.fullmatch(r'[ \t]*//-{10,}[ \t]*', line) for line in before)
                and any(re.fullmatch(r'[ \t]*//-{10,}[ \t]*', line) for line in after)):
            errors.append('global declaration or out-of-class definition requires both separators')
    parameters = []
    for key, value in entries:
        if key.startswith('@param'):
            match = re.fullmatch(r'@param\[(in|out|in,out)\] (\w+) ', key)
            if match is None or not value.strip():
                errors.append('each @param requires direction, real name and description')
            else:
                parameters.append(match.group(2))
    names = [p['name'] for p in parsed['params'] if p['name']]
    if parameters != names:
        errors.append(f'@param names/order differ from this signature: expected {names}, got {parameters}')
    template_names = [p['name'] for p in parsed['templateParams'] if p['name']]
    documented_templates = [k.split()[1] for k, v in entries if k.startswith('@tparam ') and v]
    if template_names != documented_templates:
        errors.append(f'@tparam names/order differ: expected {template_names}, got {documented_templates}')
    if not parsed['deleted']:
        for index, parameter_info in enumerate(parsed['params'], 1):
            if parameter_info['name']:
                continue
            # 型の同一性は正規化したtoken列で比較し、架空の実名を要求しない。
            expected_type = re.sub(r'\s+', '', parameter_info['type'])
            notes = [v for k, v in entries if k == '@note ' and f'第{index}引数' in v]
            if not any(expected_type in re.sub(r'\s+', '', note)
                       and re.search(r'(?<![A-Za-z])(?:in,out|in|out)(?![A-Za-z])', note)
                       and re.search(r'無名|未使用|使用し|保持|役割', note) for note in notes):
                errors.append(f'unnamed argument {index} requires ordinal, type, direction and role in @note')
    returns = [v for k, v in entries if k.strip() in {'@return', '@returns'}]
    return_values = [v for k, v in entries if k.strip() == '@retval']
    if parsed['deleted'] or not parsed['returnsValue']:
        if returns or return_values:
            errors.append('void/constructor/destructor/deleted declaration must not have an empty return item')
    elif not returns or any(not value.strip() for value in returns):
        errors.append('non-void function requires its own @return description')
    return errors


def method_contract_nodes(source):
    """各raw契約とコメント無し関数を検査し、位置・署名・診断の所有listを返す。"""
    comments = [t for t in tokenize(source) if t.kind == 'block_comment'
                and t.text.startswith('/**') and '@file' not in t.text]
    code, code_starts = source_tokens(source)
    nodes = []
    covered = set()
    for token in comments:
        parsed = signature(source, token.end)
        if parsed['kind'] not in {'method', 'unknown'}:
            # 型/field等は対象外。ただし関数項目を持つ未解釈blockは明示拒否する。
            if (parsed['kind'] not in {'type', 'lambda-or-expression'}
                    and any(k.startswith(('@param', '@return', '@tparam'))
                            for k, _ in doxy_entries(token.text))):
                nodes.append({'line': source.count('\n', 0, token.start) + 1,
                              'signature': parsed, 'errors': ['unparsed callable contract']})
            continue
        errors = (['unsupported method signature: ' + parsed.get('reason', '')]
                  if parsed['kind'] == 'unknown' else contract_errors(source, token, parsed))
        covered.add(parsed.get('begin'))
        nodes.append({'line': source.count('\n', 0, token.start) + 1,
                      'signature': parsed, 'errors': errors})
    for parsed in declaration_signatures(source):
        if parsed.get('begin') in covered:
            continue
        nodes.append({'line': source.count('\n', 0, parsed.get('begin', 0)) + 1,
                      'signature': parsed,
                      'errors': ['method has no independent Doxygen contract']})
    return nodes
