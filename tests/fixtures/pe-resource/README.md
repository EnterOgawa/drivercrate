# PE resource synthetic vectors

Windows SDK 10.0.26100.0 winnt.hのresource layoutを基準に作成した独立645の六blob。
各2048B、合計12KiB。中身はASCII markerのみでdriver/CAT/署名/実適合の証拠ではない。
原生成記録: out/pe-resource-vectors-645/portable-semantic-vectors645.json。
合法tuple/明示別言語、raw終端/RVA overflow/cycle/同tuple重複を検査する。
