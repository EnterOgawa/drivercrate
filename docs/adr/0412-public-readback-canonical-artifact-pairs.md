# ADR 0412: 匿名readbackの正規daily/candidate二file名契約

- 状態: 採用
- 日付: 2026-10-27

candidate publisherはcandidate-publication-{generation:016d}.manifest.jsonと
同stem.index.json.gzを渡すが、native入口は8桁day.acquisition名だけを受理していた。
公開/二asset/CAS後のINPUT/送信0/UNKNOWNを保持し、再publisherで回避しない。

匿名readback入口は既存二callerの正規pairだけを許可する。
dailyはASCII数字8桁+.acquisition.manifest.jsonと同8桁+.acquisition.index.json.gz、
candidateはcandidate-publication-とASCII数字16桁+.manifest.json、同stem+.index.json.gzとする。
candidate世代は既存formatterと同じ1..9007199254740991を要求する。
同parent/同family/同stemを完全一致させ、桁違い・overflow・追加文字・未知prefix・cross-family・
異世代・ADSを拒否する。filename検査を共通の非I/O関数へ置き、入口と人工回帰で共用する。

実fileは既存の同handle・固定ProgramData祖先/owner/DACL/通常file/単一link/reparse拒否と
有限readerをそのまま通す。任意filenameやURL、外部trust、用途変更、改名copyによるguard迂回を
認めない。匿名三resourceの時間/send/byte上限・固定trust・全codec/期限/hash検証と非保存を維持する。
read-only回復確認は新証拠として記録し、元publisherのUNKNOWNや欠測を書き換えない。
保護runtimeの更新・EXE署名・発行authorityのrebindはこの契約変更へ含めない。
