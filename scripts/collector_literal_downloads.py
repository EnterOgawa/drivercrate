"""公開二literal引数と単純なcallback redirectを非実行で照合する（ADR 0301）。

作成者: Shunji Ogawa。
Copyright (c) 2026 EnterSystem CO.,LTD.
SPDX-License-Identifier: Apache-2.0
JS・POST・GET・公式性／request grant・同意・内容／適合を実行または発行しない。
"""
import re
from urllib.parse import urljoin, urlsplit

import collector_registry as cr
import collector_public_locators as pl

METHOD = 'LITERAL_TWO_ARGUMENT_CALLBACK_REDIRECT_V1'
# 観測済みの単純なstatement集合だけを照合し、未知のstatementを捨てて続行しない。
GRAMMAR = re.compile(r'''
    \s*function\s+download\s*\(\s*\$file\s*,\s*\$file_link\s*\)\s*\{\s*
    (?://[^\r\n]*[\r\n]+\s*)?
    \$product_id\s*=\s*"([0-9]{1,20})"\s*;\s*
    \$product_name\s*=\s*"([A-Za-z0-9][A-Za-z0-9 _.-]{0,95})"\s*;\s*
    \$\.post\s*\(\s*"recode_action\.php\?oper=download"\s*,\s*\{\s*
    product_id\s*:\s*\$product_id\s*,\s*product_name\s*:\s*\$product_name\s*,\s*
    file\s*:\s*\$file\s*,\s*file_link\s*:\s*\$file_link\s*\}\s*,\s*
    function\s*\(\s*msg\s*\)\s*\{\s*
    location\.href\s*=\s*"download\.php\?file="\s*\+\s*\$file\s*\+\s*
    "&file_link="\s*\+\s*\$file_link\s*;\s*\}\s*\)\s*;\s*\}\s*
    ''', re.VERBOSE)


def recognize_transfer(script):
    """完全一致したinline scriptから公開定数と非実行の意味だけを返す。"""
    cr.require(type(script) is str and 0 < len(script) <= 8192, 'LITERAL_SCRIPT_SIZE')
    match = GRAMMAR.fullmatch(script)
    cr.require(match is not None, 'LITERAL_TRANSFER_UNCONFIRMED')
    cr.label(match[2])
    return dict(method=METHOD, productSelector=match[1], model=match[2],
        scriptSha256=cr.digest(script.encode()), endpoint='download.php',
        queryNames=['file', 'file_link'], argumentEncoding='RAW_ASCII_LITERAL',
        preNavigationPost='recode_action.php?oper=download',
        callbackRequiresPostSuccess=True, callbackResponseUsed=False, requestAuthorized=False,
        postExecuted=False, getExecuted=False)


def derive_url(page, action, transfer):
    """同pageの二literalと確認済み意味を結合し、GET先の表現だけを返す。"""
    pl.public_locator_url(page, profile='PUBLIC_PRODUCT_PID', purpose='PAGE')
    cr.fields(transfer, {'method', 'productSelector', 'model', 'scriptSha256', 'endpoint', 'queryNames',
        'argumentEncoding', 'preNavigationPost', 'callbackRequiresPostSuccess', 'callbackResponseUsed',
        'requestAuthorized', 'postExecuted', 'getExecuted'}, 'LITERAL_TRANSFER_FIELDS')
    cr.require(transfer['method'] == METHOD and transfer['endpoint'] == 'download.php' and
        transfer['queryNames'] == ['file', 'file_link'] and transfer['argumentEncoding'] == 'RAW_ASCII_LITERAL' and
        transfer['preNavigationPost'] == 'recode_action.php?oper=download' and
        transfer['callbackRequiresPostSuccess'] is True and transfer['callbackResponseUsed'] is False and
        all(transfer[key] is False for key in ('requestAuthorized', 'postExecuted', 'getExecuted')),
        'LITERAL_TRANSFER_POLICY')
    cr.sha256(transfer['scriptSha256'])
    cr.require(transfer['scriptSha256'] is not None and urlsplit(page).query ==
        'pid=' + transfer['productSelector'], 'LITERAL_PAGE_SELECTOR')
    cr.require(type(action) is str and 0 < len(action) <= 2048, 'LITERAL_ACTION_SIZE')
    match = re.fullmatch(r"download\('driver','(download/driver/[0-9]{4}/[A-Za-z0-9][A-Za-z0-9_.-]{0,255})'\);?", action)
    cr.require(match is not None, 'LITERAL_ACTION_GRAMMAR')
    endpoint = urljoin(page, transfer['endpoint'])
    cr.public_url(endpoint)
    cr.require(urlsplit(endpoint).netloc == urlsplit(page).netloc, 'LITERAL_ORIGIN')
    value = endpoint + '?file=driver&file_link=' + match[1]
    return pl.public_locator_url(value, profile='PUBLIC_DOWNLOAD_FILE_PATH', purpose='PAYLOAD')
