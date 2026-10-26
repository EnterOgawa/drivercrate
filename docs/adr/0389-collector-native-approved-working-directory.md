# ADR 0389: native子の作業directoryを検証済み承認repositoryへ結合する

- 日付: 2026-10-20
- 状態: 採用。G13-I7r247vで実装・有限検証を受入れ、247d/rと242vで本PCの実再配置・一対象実収集を確認した。

## 背景

246の実prepareは成功したが、onceはnative --validateのexit2、state_error0、targets0で停止した。
固定setupはPythonのCWDをpackageへ固定し、LocalBudgetは子へcwdを指定していなかった。
native checkedStateRootはCWD/work/state直下とADR0209の存在を要求するため、既存承認repositoryの
stateと一致しない。これは保存した実byte・config・sourceからの原因推論であり、当該processの
CWDを直接計測した結果ではない。元失敗・分母1/成功0とretry0を保持する。

## 決定

loadは既存originが検証したWorkspaceBindingも返す。毎回のprotected approval原byte、固定
repository/state対応、origin marker内の実directory identityを照合したbinding.repositoryRootだけを
LocalBudgetへ渡し、固定native三commandのPopenでcwdへ明示する。configの9fieldへcwdを追加しない。
親CWDの継承、configからstateの親を推測する代替、任意cwd、別state作成・移設は採用しない。
既存normal_path・approval再検査・origin identity照合とnative storeの実handle検査を維持する。
load後のpath置換競合を新たに解消する変更ではなく、nativeによる再検査を引き続き要求する。

固定manifest、三command、最大3call・各300秒・全1800秒、同意、待機、排他、世代、FRESH_INPUT、
原出力と部分失敗保持を変更しない。日次pipeline、native collector、HTTP処理は変更しない。

## 検証と境界

既存13caseを保持し、人工の配置CWDと承認repositoryが異なる状態でcollectが選ぶcwdを
実CreateProcessへ渡す回帰を追加する。test内のPopen wrapperだけが固定native argvを
read-only Python cwd probeへ変換し、製品nativeや実HTTPは起動しない。この資格を実収集と呼ばない。
originの異なる実identityと不適格repository/stateの組が子起動前に拒否されることも確認する。
通常Debug/Release全target、関連native、既存単体installer有限fixtureを確認し、新しいoutへ生成する。
実配置・prepare・once・運用native・HTTP・Task・鍵・署名・GitHub・driver操作は今回の対象外。
実装段階の非通信検証と、後続247d/rの実再配置・実収集は別の証拠として扱う。

## 有限な実施結果

既存13caseと追加2caseの計15件、関連native Debug/Release各5件、通常と実resource込みの
両構成全targetが成功した。L14は配置先CWDから製品collectを呼び、test wrapperがnative argvを
read-only Python probeへ置換した実子のos.getcwdで承認repositoryを確認した。意図的exit2で
preflight停止させており、製品nativeの成功や実収集の証拠ではない。L15は実directory置換による
identity不一致と不適格repository/stateの組を子起動前に拒否した。
新しい未署名x64単体EXEの既存fixtureは379check/47process、77.1379952秒で成功した。
75file/40,923,070Bの旧package差分はlocal script、README、manifestの三fileだけで、
元runtime・license・8seedと旧EXEを保持した。Python二fileのsyntaxと二文書EOFを確認し、
C++は既存657source pin一致で245の品質資格を継承した。全Python216/全suite、実運用、
七日・別PC・公開品質を今回の合格へ含めない。247a/tでの実配置・prepare・once・運用native・HTTP等は0。

後続247d/rでは同じ既定先へ修正版を配置し、prepare/once各一回が成功した。固定Intel一対象の
NEW_200、FRESH_INPUT、世代5→6、四fileと結果のhash結合を242vで独立確認した。
未署名ローカルmetadata索引の有限受入であり、driver取得・端末適用性・導入・署名公開の合格ではない。
