# Third-Party Notices

Collector明示v5はOSに既存のSystem32/curl.exeを実handleと共通署名検証へ固定して利用します。
Windows／curl binaryは同梱しません。CPython原runtimeと全文license／noticeは従来どおり保持します。

2026-10-15の監視PC専用配備では、[公式CPython3.13.16 Windows x64 embeddable](https://www.python.org/downloads/release/python-31316/)を別の保護runtimeとして使用しました。その配備時点ではDriverCrate.exe、repository、索引asset、Release packageへPython binaryを同梱していません。
元archiveとLICENSE.txtの全文・各組込みlicense/noticeを配備先へ保持しました。PSF License Version2と同梱第三者条件に従い、Python native/stdlibは変更せず、保護scripts参照だけを追加した._pthと変更noticeを配備しました。archiveの公開SHA-256一致とPython native四fileのAuthenticodeを確認し、Sigstore/GPGの検証は行っていません。保守側に保持する当時の配備境界と根拠はADR 0345（`docs/adr/0345-protected-daily-index-runtime.md`）です。

2026-10-16のcollector package v3は、上記保護runtimeとは別に公式原archiveを検証し、全34 fileを
`runtime/`へ同梱するローカル検証用packageです。SHA-256は
`97dae5274cc54867065e8d5a3226e48c35017ed332a0fdb0e27d5b5821961297`です。
原`LICENSE.txt`（SHA-256 `62bec384df47b0328307db41455ff6ea2559e5546b394ac69148561b21703120`）の
全文と、PSF/BeOpen/CNRI/CWI/Zero-Clause BSD、bzip2、libffi、OpenSSLのApache-2.0、
Tcl/Tk等の同梱条件・noticeを保持します。Microsoft Distributable Codeを含むWindows binaryの
追加条件も原文に保持し、Windows x64だけを対象にします。第三者の権利表示を上書きしません。
Python native/stdlib/`python313._pth`は一切変更せず、追加pip・trimもありません。
これは同梱と配置の工程でありruntimeや収集の実行を意味しません。通常DriverCrate.exeと索引assetへは
Pythonを追加しません。公開物へのlicense/notice最終監査と本人の公開承認は後続に残ります。
保守側に保持する当時のpackage境界の記録はADR 0353（`docs/adr/0353-collector-registry-runtime-package.md`）です。

DriverCrate 0.1.0 は、Dell Enterprise CatalogのGZip展開と公式ZIP packageの安全な展開用に
miniz 3.1.2をsourceから静的linkします。PE末尾7zの非実行展開用にはLZMA SDK 26.03の
C decoderだけをsourceから静的linkするCMake構成です。Release packageに第三者DLL、
driver package、driver index、LZMA SDKのsample／tool／SFX binaryは同梱しません。

2026-10-02のAI機能撤去により、llama.cpp／CUDAのbuild契約と自作patchを削除しました。
現行targetはこれらを取得・linkせず、model weightも同梱しません。後段のllama.cpp節は撤去前の
試作に使った由来・license・変更点の履歴です。残した旧build source／成果物・回復用archiveには
元の権利表示を維持します。保守側に保持する当時の決定記録はADR 0224（`docs/adr/0224-remove-ai-and-local-index-distribution.md`）です。

DriverCrate の木箱application iconは、本project専用にOpenAIの画像生成機能で作成したassetです。
既存の第三者icon setまたはSDIOのassetを転用していません。

アプリケーションは Windows が提供する Win32、COM、Common Controls、Windows Update Agent
API を動的に利用します。これらの Microsoft system component は DriverCrate の配布物には
含まれません。

ローカルに置かれた Snappy Driver Installer Origin（SDIO）の旧 source と成果物は、要件と
従来挙動を確認する参考資料としてのみ扱いました。DriverCrate は SDIO の fork ではなく、
SDIO の source、実行ファイル、theme、language file、DriverPack index、DriverPack archive を
repository または Release asset に含めません。

## LZMA SDK 26.03

- Upstream: https://www.7-zip.org/sdk.html
- Source archive: https://github.com/ip7z/7zip/releases/download/26.03/lzma2603.7z
- Archive SHA-256: `86C213F752520AB5325C310F50BEF63EC344B56DD1C80B0246D06DC6CEC953B2`
- Author: Igor Pavlov
- License: Public domain

LZMA SDK同梱の`DOC/lzma-sdk.txt`は、SDKがIgor Pavlovによりpublic domainへ置かれ、
source／binary形式および商用／非商用を問わず、複製、変更、公開、利用、compile、販売、
配布できると記載しています。

DriverCrateは固定hashの公式archiveから、`7zArcIn.c`、`7zBuf.c`、`7zCrc.c`、`7zCrcOpt.c`、
`7zDec.c`、`7zStream.c`、`Bcj2.c`、`Bra.c`、`Bra86.c`、`BraIA64.c`、`CpuArch.c`、
`Delta.c`、`Lzma2Dec.c`、`LzmaDec.c`と、それらが参照するheaderだけをcompile対象にします。
PPMd、AES、encoder、sample application、file出力処理、SFX module、precompiled binaryは
linkまたは実行しません。取得archiveはbuild tree内に限り、repositoryやRelease assetへ
複写しません。

## miniz 3.1.2

- Upstream: https://github.com/richgel999/miniz
- License: MIT

Copyright 2013-2014 RAD Game Tools and Valve Software

Copyright 2010-2014 Rich Geldreich and Tenacious Software LLC

All Rights Reserved.

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## llama.cpp 0.4.0（撤去前の試作・第三者由来の履歴）

- Upstream: https://github.com/ggml-org/llama.cpp
- Annotated tag: `0.4.0`
- Fixed commit: `5266f24da75dc449bd56cbed7addb9c8e4a6a73e`
- License: MIT
- Local patch ID: `cpu_validation_serial_v1`
- Local CUDA patch ID: `cuda_model_observation_v1`

試作を明示的に有効化した場合だけ、固定commitの`src/llama-model-loader.cpp`にある
`std::launch::async`二箇所を`std::launch::deferred`へ変更します。Tensor検査と既存の
`future.get()`は維持し、CPU検査を呼出しthread内で直列化します。原本byte数77881、原本SHA-256
`5ef07476310d4678df18a61a6ec0a1ebcbb58c7534ac3c624b9fe0f315a4ab01`、patch後SHA-256
`df2103b705c6f01b34a7b64200a13aed558f9113d2c549f6b607ae932fac1a7a`をbuild時に検証します。

GPU model専用optionでは、`cmake/patches/llama-cuda-observation-v1.patch`を追加適用します。
Patch自身のSHA-256は
`9dcb3f7cbc52673c184386dfb3949ab8cf32f6fd661031cf599cd84720eec05c`です。CUDAだけを共通
`ggml`のPUBLIC link／自動登録から外し、元のCUDA Runtime／Driver／cuBLAS codeを固定callbackへ
渡します。Device列挙、device buffer確保、必須memory照会を含むfatal経路、同期成功後のgraph counter、
実buffer配置snapshot、device allocation／scratch pool cache／VMM物理commitの4 GiB counterを
追加します。Pinned host確保はOOMの場合だけ既存CPU host fallbackを維持します。
次の7 sourceをbuild時に原本／適用済みhashで照合し、部分適用と未知byte列を拒否します。

| 固定source | 入力SHA-256 | CUDA patch適用後SHA-256 |
| --- | --- | --- |
| `ggml/src/CMakeLists.txt` | `38ddf053a1adfc14bb84b7722e3c4ec01909694f7e51e32013f36e7a324fa4f0` | `6a7f2b73d169ae918234b52fcd8af7fe0c5e285718eb962c3041db65ab7c1368` |
| `ggml/src/ggml-cuda/common.cuh` | `e67178a8dc94896cf658933b527dbf4b22e9c9701ea27f399b8a3e239180ced1` | `9d3f32a0b5f7a6ac6a43210684cd1443a764ba0bc140da528d35e0d033dc06f6` |
| `ggml/src/ggml-cuda/ggml-cuda.cu` | `dca99ae02645500ffe153f0705d8cff37764d906638998bf5a2418c0514a19bc` | `11d90e23af62a896ebcef82d389eb048ffdd34282a9e4a8c3096d143b584dea7` |
| `ggml/include/ggml-cuda.h` | `9cbfcea49f6da4d07f41dc22fa8dbf870825faaa2a68e34e65fe30ea6c41e042` | 同左 |
| `src/llama-context.cpp` | `e42d929c98b36ef6ed9360969073a63526f9bbb378341cec85d53abfca46d320` | 同左 |
| `src/llama-model.cpp` | `931a9229ffdb2a6e6832055abc7f3310adbafc57f0eb81a81d60790a5f3bc356` | 同左 |
| `src/llama-model-loader.cpp` | `df2103b705c6f01b34a7b64200a13aed558f9113d2c549f6b607ae932fac1a7a` | 同左 |

このCUDA patchは開発用の分離static targetに限られます。GPU model engineと専用起動所有権までは
接続しましたが、worker通信・監督・製品scan／driver取得／導入へは未接続です。
GPU推論合格や公開配布済みを意味しません。

Copyright (c) 2023-2026 The ggml authors

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and
associated documentation files (the "Software"), to deal in the Software without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or
substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT
NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT
OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

## Granite 4.0 Micro GGUF（利用者が明示取得する別pack）

- Upstream: https://huggingface.co/ibm-granite/granite-4.0-micro-GGUF
- Base model: https://huggingface.co/ibm-granite/granite-4.0-micro
- Fixed revision: `ec48475f0c811d812fbfb61975717a9c36eeb652`
- Selected file: `granite-4.0-micro-Q2_K.gguf`
- Publisher: IBM Granite
- License: Apache-2.0

Modelとmodel cardは通常build、source repository、Release assetに含めません。非導入probeは利用者の
明示操作で取得された固定revisionの別packを、組込みsize・SHA-256・有限manifestと照合します。
Apache-2.0本文はprojectの`LICENSE`で保持し、modelの由来をDriverCrateの自作著作権へ置き換えません。

GPU試験Cの追加候補は同じIBM repository／revisionの`granite-4.0-micro-Q4_K_M.gguf`、
2,099,502,528 byte、SHA-256 `97c417dcc0534b0737c74016fb2af083cb17c3b51eaac621192d23961b7024eb`です。
固定READMEのApache-2.0指定と帰属を保持します。保守側に保持する当時の記録ADR 0174（`docs/adr/0174-granite-q4-gpu-pack-and-comparison-contract.md`）
で取得・比較条件を確定しましたが、R3c1時点ではQ4実体は未取得、接続・実測も未実施です。
通常build／source／Releaseへmodelを同梱せず、Q2のpackを置換しません。

## SmolLM3-3B GGUF（利用者が明示取得する別pack、評価不採用）

- Upstream: https://huggingface.co/ggml-org/SmolLM3-3B-GGUF
- Base model: https://huggingface.co/HuggingFaceTB/SmolLM3-3B
- Fixed revision: `4965cb60b150737b68a0408c36aeefb65078f894`
- Selected file: `SmolLM3-Q4_K_M.gguf`
- Publisher: ggml-org / Hugging Face Smol Models Research
- License: Apache-2.0

Modelとmodel cardは通常build、source repository、Release assetに含めません。独立probeの固定比較契約は
組込みsize・SHA-256・有限manifestへ拘束します。開発機の60秒期限gateに不合格だったため製品採用せず、
実行時fallbackや自動取得に使用しません。原licenseと帰属は評価不採用後も維持します。

## Qwen2.5-0.5B-Instruct-GGUF（旧試作の履歴、能動利用禁止）

- Upstream: https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF
- Fixed revision: `9217f5db79a29953eb74d5343926648285ec7e67`
- Selected file: `qwen2.5-0.5b-instruct-q4_k_m.gguf`
- License: Apache-2.0

このartifactは旧試作の測定条件を再現する履歴として記録します。ADR 0147以降の能動model、fallback、
通常build、source repository、Release assetには使用しません。原LICENSEと帰属は履歴内でも維持します。
