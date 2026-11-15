# Third-Party Notices

この文書は現行DriverCrateソースと配布物で使用する第三者資産の条件を示します。
DriverCrateの自作部分はルートの [LICENSE](LICENSE)（Apache-2.0）に従います。
第三者sourceの原著作権・licenseを自作表示へ置き換えません。

## CPython 3.13.16（Collector runtime）

- Source: [公式Windows x64 embeddable archive](https://www.python.org/ftp/python/3.13.16/python-3.13.16-embed-amd64.zip)
- Archive: 11,439,094byte、SHA-256 `97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297`
- 原34fileの固定一覧: [python-runtime-manifest.json](packaging/collector/python-runtime-manifest.json)
- 原 `LICENSE.txt`: 33,861byte、SHA-256 `62bec384df47b0328307db41455ff6ea2559e5546b394ac69148561b21703120`

Collector packageは原34fileを変更せず`runtime/`へ含め、原`LICENSE.txt`全文を保持します。
native/stdlib/`python313._pth`を変更せず、pip追加やtrimも行いません。
PSF License Version 2、BeOpen/CNRI/CWI/Zero-Clause BSD、bzip2、libffi、OpenSSLのApache-2.0、
Tcl/Tk等の同梱条件とnotice、Microsoft Distributable Codeの追加条件も原文のまま配布します。
全fileのbyte/hashとPython native四fileのPSF Authenticodeをpackage検査で確認します。
Sigstore/GPG検証を実施済みとは表示しません。

通常の`DriverCrate.exe`と署名索引assetにPythonを含めません。
公開sourceにはruntime binaryを置かず、collector builderへ固定原archiveを明示入力します。

## miniz 3.1.2

- Upstream: [richgel999/miniz](https://github.com/richgel999/miniz)
- Source archive: [3.1.2](https://github.com/richgel999/miniz/archive/refs/tags/3.1.2.tar.gz)
- Archive SHA-256: `98468F8924934B723276680F85238B6C78BF1F8B49B4459CC9B7214A20E2E9FB`
- License: MIT

GZipと公式ZIPの展開にsourceから静的linkします。原権利表示とlicense全文は次のとおりです。

Copyright 2013-2014 RAD Game Tools and Valve Software
Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC

All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.

## LZMA SDK 26.03

- Upstream: [7-Zip SDK](https://www.7-zip.org/sdk.html)
- Source archive: [lzma2603.7z](https://github.com/ip7z/7zip/releases/download/26.03/lzma2603.7z)
- Archive SHA-256: `86C213F752520AB5325C310F50BEF63EC344B56DD1C80B0246D06DC6CEC953B2`
- Author: Igor Pavlov
- License: Public domain

原`DOC/lzma-sdk.txt`のLICENSE節を保持します。

> LZMA SDK is written and placed in the public domain by Igor Pavlov.
>
> Some code in LZMA SDK is based on public domain code from another developers:
> 1) PPMd var.H (2001): Dmitry Shkarin
> 2) SHA-256: Wei Dai (Crypto++ library)
>
> Anyone is free to copy, modify, publish, use, compile, sell, or distribute the
> original LZMA SDK code, either in source code form or as a compiled binary, for
> any purpose, commercial or non-commercial, and by any means.

固定archiveのC decoderと必要headerだけをcompileします。PPMd/AES/encoder、sample/tool/SFX binaryはlink・実行しません。
依存sourceはCMakeの固定URL/hashからbuild treeへ取得し、原sourceの権利表示を維持します。

## Windows APIと開発ツール

Win32、COM、Common Controls、Windows Update Agent、WinHTTP、SetupAPI/NewDevなどの
Windows標準APIを使います。Windows本体、SDK、Visual Studio Build ToolsやOS内のcurlを配布物へ複写しません。
各OS・開発ツールと、CPythonに含まれるMicrosoft Distributable Codeにはそれぞれの条件が適用されます。

## アイコンと配布対象外の資産

木箱アイコンは本project専用にOpenAIの画像生成機能で作成したassetです。
第三者icon setやSDIOのassetは転用していません。

DriverCrateはSDIOのforkではありません。参照用の旧SDIO source、binary、theme、language、
DriverPack index/archiveと、driver本体・OEM utilityはsource/Releaseへ含めません。
AI runtimeやmodel、旧試作の第三者sourceも現行build・公開集合へ含めません。
過去の試作・配布物の原noticeはその履歴で保持します。
