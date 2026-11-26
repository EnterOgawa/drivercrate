//------------------------------------------------------------------------------
/**
 * @file signed_index_records.h
 * @brief 署名済み展開byteから読む配布record schema receiptを定義します
 * @version 01.25.01
 * @date 2026/10/24
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  v2の取得descriptorと現reader policy版を型付きで追加
 * Ver.01.02.00 Shunji Ogawa  2026/10/14  原pageと原文書・全文を区別する共通HTML許諾bindingを追加
 * Ver.01.02.01 Shunji Ogawa  2026/10/14  公表identifier役割とnative property指定の相違を明記
 * Ver.01.03.00 Shunji Ogawa  2026/10/24  現行nested member identityと原record完全tupleへ整合
 * Ver.01.03.01 Shunji Ogawa  2026/10/24  新規配布recordの週次更新用8日上限を共通化
 * Ver.01.04.00 Shunji Ogawa  2026/11/03  共通公式packageの手動索引と選択内容検査を接続
 * Ver.01.05.00 Shunji Ogawa  2026/11/03  有界large archiveと共有内容保持・標準serviceを接続
 * Ver.01.06.00 Shunji Ogawa  2026/11/03  署名原範囲の非実行resource内容を接続
 * Ver.01.07.00 Shunji Ogawa  2026/11/03  匿名CDNの同record二要求と有限予約を接続
 * Ver.01.08.00 Shunji Ogawa  2026/11/03  拡大recordと有限保持quotaを通常経路へ整合
 * Ver.01.09.00 Shunji Ogawa  2026/11/05  独立静的規約の原文書・公式リンクと既存同意を共通接続
 * Ver.01.10.00 Shunji Ogawa  2026/11/07  全公開ID入力総数と用途別共通容量の拒否を追加
 * Ver.01.10.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.10.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.11.00 Shunji Ogawa  2026/11/19  追加索引の独立した検査結果を定義
 * Ver.01.11.01 Shunji Ogawa  2026/11/19  追加欄と未署名候補の期限不一致の診断を明示
 * Ver.01.12.00 Shunji Ogawa  2026/11/19  追加欄の取得元を原byteで保持
 * Ver.01.13.00 Shunji Ogawa  2026/11/20  私有追加欄のCatalog対象条件を型付きで保持
 * Ver.01.14.00 Shunji Ogawa  2026/11/20  同じ元配布物とINFのCatalog対象競合を明示
 * Ver.01.15.00 Shunji Ogawa  2026/11/20  Catalog対象に対応する元ModelsのID位置を保持
 * Ver.01.16.00 Shunji Ogawa  2026/11/20  端末用追加欄の元領域と行を取得する読取契約を追加
 * Ver.01.17.00 Shunji Ogawa  2026/11/20  私有索引の機種別対象と元配布表を型付きで保持
 * Ver.01.18.00 Shunji Ogawa  2026/11/20  署名済み取得元から導出する機種型番の発行元を追加
 * Ver.01.19.00 Shunji Ogawa  2026/11/20  機種別配布表の必須ファームウェア群を型付きで保持
 * Ver.01.20.00 Shunji Ogawa  2026/11/20  同一端末の必須ファームウェア群の判定を追加
 * Ver.01.21.00 Shunji Ogawa  2026/11/22  専用欄の配布レコードに公式Modelsの元証拠を結合
 * Ver.01.22.00 Shunji Ogawa  2026/11/22  私有追加欄の規約メンバー証拠を型付きで保持
 * Ver.01.23.00 Shunji Ogawa  2026/11/22  公式配布ZIPの完全Hardware IDと確認条件を追加
 * Ver.01.24.00 Shunji Ogawa  2026/11/23  私有追加欄の署名付きWiX配布・規約証拠を型付きで保持
 * Ver.01.25.00 Shunji Ogawa  2026/11/23  WiXレコードに完全Hardware IDの端末照合を要求
 * Ver.01.25.01 Shunji Ogawa  2026/11/26  追加レコード検査の各戻り値を前置契約で説明
 * </pre>
 *
 * @note 保存前のschema receiptです。公式性・端末適合・導入許可を成立させません
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/index_capacity_limits.h"
#include "platform/official_resource_content.h"
#include "platform/official_cdn_token.h"

#include "platform/signed_index_asset_bytes.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {

namespace signed_index_detail {
struct CollectorScopedModelsEvidence ;
}

// 保護headの保存wire互換識別値。原byteは常に現readerで再認証し、この値を現reader版にしない
inline constexpr std::uint32_t	   INDEX_RECORD_SCHEMA_POLICY_VERSION = 1U ;
// 現codecの読取りpolicy版。保存head互換識別値やwire record v1／v2とは別です
inline constexpr std::uint32_t	   INDEX_RECORD_READER_POLICY_VERSION = 7U ;
// 新規recordの週次7日と発行fresh窓24hを合わせた上限。原期限を延長しません
inline constexpr std::chrono::days INDEX_ACQUISITION_MAX_VALIDITY{8} ;
// 一index内の有限source枠。製品全体の対応数ではありません
inline constexpr std::size_t	   INDEX_RECORD_SOURCE_MAX_COUNT = index_capacity::SOURCES ;
// 一index内の有限record枠
inline constexpr std::size_t	   INDEX_RECORD_MAX_COUNT = index_capacity::RECORDS ;
// Base64解除後の一record原byte上限
inline constexpr std::size_t	   INDEX_RECORD_MAX_BYTES = index_capacity::RECORD_BYTES ;
// 全recordのdecode原byte合計上限
inline constexpr std::size_t INDEX_RECORD_TOTAL_MAX_BYTES = index_capacity::TOTAL_RECORD_BYTES ;
// 一recordのメーカー公表側PnP ID件数上限
inline constexpr std::size_t INDEX_RECORD_PNP_MAX_COUNT = index_capacity::RECORD_IDS ;

/** @brief 元申告の既知値または明示UNKNOWN理由を保持します
 * @tparam Value 型付きの公開値。端末の観測ではありません
 */
template <class Value> struct IndexObservedValue {
	/// KNOWNだけに存在する公開値。UNKNOWNではnulloptです
	std::optional<Value> value ;
	/// UNKNOWNの非空理由。KNOWNでは空です
	std::string			 reason ;
} ;

/** @brief 元申告の対象OS分類です。端末の適合判定ではありません */
enum class IndexTargetOs {
	/// Windows 10の公開条件です
	WINDOWS_10,
	/// Windows 11の公開条件です
	WINDOWS_11,
	/// Windows Serverの公開条件です
	WINDOWS_SERVER
} ;

/** @brief 元申告のarchitecture条件です */
enum class IndexArchitecture {
	/// x64だけを既知条件として読みます
	X64
} ;

/** @brief 元申告の内容種別です。除外種別もrecordへ保持します */
enum class IndexDriverKind {
	/// 通常driverという元申告です
	NORMAL_DRIVER,
	/// Firmwareという元申告です。導入対象へ昇格しません
	FIRMWARE,
	/// Applicationという元申告です。導入対象へ昇格しません
	APPLICATION
} ;

/** @brief 元申告の取得／導入方式候補です。実行許可ではありません */
enum class IndexAcquisitionKind {
	/// 標準INF archiveという元申告です
	STANDARD_INF_ARCHIVE,
	/// 公式installerという元申告です。Scan中に起動しません
	OFFICIAL_INSTALLER
} ;

/** @brief 公開証拠の元申告があるか、不足を保持するかを区別します */
enum class IndexEvidenceState {
	/// 公開証拠の根拠が不足しています
	UNKNOWN,
	/// 発行側が公開証拠を申告しました。真正性を実証した値ではありません
	PUBLISHED
} ;

/** @brief 公式性に関する元申告の出典分類です */
enum class IndexOfficialEvidenceKind {
	/// 未確認の出典です
	UNKNOWN,
	/// 公式pageという元申告です
	OFFICIAL_PAGE,
	/// 公式catalogという元申告です
	OFFICIAL_CATALOG,
	/// 公式linkの手動確認記録です。HashはHTTP本文ではなく原review記録を指します
	OFFICIAL_LINK_REVIEW
} ;

/** @brief Sourceの公式性について発行側が申告した根拠です */
struct IndexOfficialEvidence {
	/// 発行側の申告状態。UNKNOWNを成功へ変換しません
	IndexEvidenceState				   state{IndexEvidenceState::UNKNOWN} ;
	/// 元申告の出典種別
	IndexOfficialEvidenceKind		   kind{IndexOfficialEvidenceKind::UNKNOWN} ;
	/// 静的出典URL。取得grantや期限付きpayload URLではありません
	std::string						   evidenceUrl ;
	/// 出典原byte hash。手動link reviewでは原review記録で、HTTP本文ではありません
	std::optional<IndexManifestSha256> evidenceSha256 ;
	/// UNKNOWNの非空理由。PUBLISHEDでは空です
	std::string						   reason ;
	/**
	 * @brief 同じsourceの元申告全体を比較します
	 * @param[in] other 比較先の元根拠です
	 * @return 全元項目が同じ場合trueです
	 */
	bool operator==( const IndexOfficialEvidence &other) const = default ;
} ;

/** @brief Index内で参照される公開sourceの申告です */
struct IndexRecordSource {
	/// ASCIIの一意なsource identity
	std::string			  sourceId ;
	/// 元申告の公式起点。UNKNOWNの場合だけ空を許可します
	std::string			  officialOrigin ;
	/// 元申告の配布page。UNKNOWNの場合だけ空を許可します
	std::string			  distributionPage ;
	/// 公式性についての元申告。URLや索引署名だけでは公式性を実証しません
	IndexOfficialEvidence officialEvidence ;
	/// 追加欄で保持する取得元JSONの原UTF-8です
	std::string			  originalBytes ;
	/**
	 * @brief 旧索引と追加欄に共通するsourceの元申告を比較します
	 * @param[in] other 比較先の型付き元sourceです
	 * @return 全元項目が同じ場合trueです
	 */
	bool				  operator==( const IndexRecordSource &other) const
	{
		return sourceId == other.sourceId && officialOrigin == other.officialOrigin &&
			   distributionPage == other.distributionPage &&
			   officialEvidence == other.officialEvidence ;
	}
} ;

/** @brief Hash値とその元申告の出典を別々に保持します */
struct IndexHashEvidence {
	/// KNOWNでだけ存在する対象byteのSHA-256
	std::optional<IndexManifestSha256> sha256 ;
	/// KNOWNの出典URL。UNKNOWNでは空です
	std::string						   evidenceUrl ;
	/// KNOWNの出典原byte hash。対象hashとは別の値です
	std::optional<IndexManifestSha256> evidenceSha256 ;
	/// UNKNOWNの非空理由。KNOWNでは空です
	std::string						   reason ;
} ;

/** @brief 公開hash、計算hash、sizeの元申告を区別します */
struct IndexPackageEvidence {
	/// メーカー公表hashの申告。不明は理由付きUNKNOWNです
	IndexHashEvidence				  publishedHash ;
	/// 発行側が計算したhashの申告。端末取得byteの実績ではありません
	IndexHashEvidence				  calculatedHash ;
	/// 発行側のbyte長。KNOWNは正、UNKNOWNはnulloptです
	IndexObservedValue<std::uint64_t> size ;
} ;

/** @brief メーカー公表側のPnP ID種別です */
enum class IndexPnpIdKind {
	/// メーカー公表側Hardware identifierの役割です。native property指定ではありません
	HARDWARE,
	/// メーカー公表側Compatible identifierの役割です。native property指定ではありません
	COMPATIBLE
} ;

/** @brief メーカー公表側IDだけを保持します。端末actual IDは入力しません */
struct IndexPublishedPnpId {
	/// 元申告のID種別
	IndexPnpIdKind kind{IndexPnpIdKind::HARDWARE} ;
	/// 大小文字を保持したASCII原公開ID。比較keyだけをcase非依存にします
	std::string	   value ;
} ;

/** @brief PnP identityを申告した出典分類です */
enum class IndexIdentityEvidenceKind {
	/// 出典不足です
	UNKNOWN,
	/// メーカー公表INFという元申告です
	INF,
	/// メーカー公表catalogという元申告です
	CATALOG
} ;

/** @brief 公開ID、ClassGUID、INF identityとmodel sectionを一出典へ結合します */
struct IndexPublishedIdentityEvidence {
	/// 全identityの元申告または理由付きUNKNOWNです
	IndexEvidenceState				   state{IndexEvidenceState::UNKNOWN} ;
	/// 元申告の出典種別
	IndexIdentityEvidenceKind		   kind{IndexIdentityEvidenceKind::UNKNOWN} ;
	/// 同じ出典に結合した有限な公開PnP ID群。UNKNOWNでは空です
	std::vector<IndexPublishedPnpId>   pnpIds ;
	/// Brace付きClassGUIDの原表記。UNKNOWNでは空です
	std::string						   classGuid ;
	/// 空はflat、非空はouter内一段nested archiveのslash相対member。実pathではありません
	std::string						   nestedArchiveIdentity ;
	/// Slash区切りのINF member。nested時はそのarchive内、flat時はouter内です
	std::string						   infIdentity ;
	/// 元INFのmodel section。端末の選択nodeではありません
	std::string						   modelSection ;
	/// 一identity証拠の出典URL。UNKNOWNでは空です
	std::string						   evidenceUrl ;
	/// 出典原byteの元申告hash。Record hashと区別します
	std::optional<IndexManifestSha256> evidenceSha256 ;
	/// UNKNOWNの理由。Metadata recordを削除せず保持します
	std::string						   reason ;
} ;

/** @brief 発行側の検査段階です。端末での検査実績ではありません */
enum class IndexInspectionStage {
	/// 未確認という元申告です
	UNCONFIRMED,
	/// Metadataだけという元申告です
	METADATA_ONLY,
	/// 内容検査という元申告です。端末検査へ昇格しません
	CONTENT_INSPECTED
} ;

/** @brief 取得descriptorの元申告状態です。取得能力ではありません */
enum class IndexDescriptorState {
	/// 根拠不足を理由付きで保持します
	UNKNOWN,
	/// 静的取得情報の元申告を保持します
	KNOWN
} ;

/** @brief 静的payload形式の元申告です。実byte検査とは別です */
enum class IndexPayloadFormat {
	/// 形式未確認です
	UNKNOWN,
	/// ZIP archiveという申告です
	ZIP,
	/// Cabinet archiveという申告です
	CABINET,
	/// Windows EXEという申告です。実行しません
	WINDOWS_EXE,
	/// Windows MSIという申告です。実行しません
	WINDOWS_MSI,
	/// 非実行で標準INFだけを選択するPE/7z SFXという申告です
	SEVEN_ZIP_SFX,
	/// 非実行で親hash結合したresource範囲を読む形式
	PE_RESOURCE_CONTAINER,
	/// 署名済みWiX配布からINFと規約を非実行で検査する形式です
	WIX_BURN_V3
} ;

/** @brief 取得routeの元申告根拠を区別します */
enum class IndexRouteKind {
	/// 公式配布pageの直接payload linkです
	OFFICIAL_PAYLOAD_LINK,
	/// 公式配布pageが委譲したCDN linkです
	OFFICIAL_CDN_LINK,
	/// 直前hopのHTTP redirectという申告です
	HTTP_REDIRECT
} ;

/** @brief 一つの静的route hopとその元証拠です */
struct IndexAcquisitionRouteHop {
	/// 原静的HTTPS URL。DNSや到達性は未検査です
	std::string			url ;
	/// 元申告の導線種別
	IndexRouteKind		kind{IndexRouteKind::OFFICIAL_PAYLOAD_LINK} ;
	/// 出典pageまたは直前hopの原URL
	std::string			evidenceUrl ;
	/// 出典原byteの申告hash。取得実績ではありません
	IndexManifestSha256 evidenceSha256{} ;
} ;

/** @brief 利用規約の申告状態です。利用者の同意状態ではありません */
enum class IndexTermsState {
	/// 規約を確認できていません
	UNKNOWN,
	/// 明示同意不要という元申告です
	CONFIRMED_NO_CONSENT,
	/// 全文の取得と利用者同意が別途必要です
	ACCEPTANCE_REQUIRED
} ;

/** @brief 公開revisionと取得全文からの算出revisionを区別します */
enum class IndexTermsRevisionKind {
	/// 公開revisionを持ちません
	NONE,
	/// 原公開revisionを保持します
	VENDOR_LITERAL,
	/// 本文取得後に算出します。Wire revisionは空です
	COMPUTED_UTF8_SHA256,
	/// 同じWiX配布にある言語別の元RTFハッシュで識別します
	WIX_RTF_SHA256
} ;

/** @brief 一つの静的HTML要素へ完全一致させる共通selectorです */
struct IndexHtmlTermsSelector {
	/// ASCII小文字の原tag名です
	std::string tag ;
	/// 一意な原属性名です。CSSやscriptを実行しません
	std::string attribute ;
	/// 原属性値の完全一致値です
	std::string value ;
} ;

/** @brief 原pageのprovenanceと、使用時に完全照合する一許諾文書を区別します */
struct IndexHtmlTermsExtraction {
	/// 閉じた共通抽出profileです
	std::string			   profile ;
	/// profileに対応する一意な原文書要素のselectorです
	IndexHtmlTermsSelector selector ;
	/// 許諾欄を包含する一意な元containerです
	IndexHtmlTermsSelector containerSelector ;
	/// 対象payloadの許諾操作を示す一意な元linkです
	IndexHtmlTermsSelector linkSelector ;
	/// 選択linkから原payload URLを読む属性名です
	std::string			   payloadAttribute ;
	/// 選択した完全原HTML文書または独立sectionのhashです
	IndexManifestSha256	   documentSha256{} ;
	/// 選択原HTML文書の正のexact UTF-8 byte数です
	std::uint64_t		   documentSizeBytes{} ;
	/// 共通抽出全文の完全UTF-8 hashです
	IndexManifestSha256	   textSha256{} ;
	/// 共通抽出全文の正のexact UTF-8 byte数です
	std::uint64_t		   textSizeBytes{} ;
	/// 監視側が確認したgateとcontainerの関連の公式根拠URLです
	std::string			   bindingEvidenceUrl ;
	/// 同じ非実行調査の原根拠bytehashです。端末でJSを実行しません
	IndexManifestSha256	   bindingEvidenceSha256{} ;
	/// 独立静的sectionだけの公式リンク根拠原byte数です。旧textareaでは0です
	std::uint64_t		   bindingEvidenceSizeBytes{} ;
} ;

/** @brief 原UTF-8規約の固定取得情報です。Codecは本文を取得しません */
struct IndexTermsTextDocument {
	/// 原静的HTTPS URL
	std::string								url ;
	/// Plainは使用時のexact原全文、HTMLは監視側原pageのprovenance hashです
	IndexManifestSha256						sha256{} ;
	/// 原wire byte数です。旧契約は256KiB、新static sectionだけ2MiB以内です
	std::uint64_t							sizeBytes{} ;
	/// UTF-8 plainまたは明示HTMLの固定申告形式です
	std::string								contentType ;
	/// HTMLだけに必須の原文書・全文・配布recordへの抽出bindingです
	std::optional<IndexHtmlTermsExtraction> htmlExtraction ;
} ;

/** @brief 取得済みZIPと審査済みの規約メンバーを結ぶ私有追加欄の原申告です */
struct IndexArchiveTermsNotice {
	/// 取得した元ZIPのbyte数です
	std::uint64_t		archiveSizeBytes{} ;
	/// 取得した元ZIP全体のSHA-256です
	IndexManifestSha256 archiveSha256{} ;
	/// 大文字小文字を保持した正規Windows相対名です
	std::string			memberPath ;
	/// 規約メンバーの展開後byte数です
	std::uint64_t		memberSizeBytes{} ;
	/// 文字変換する前の規約メンバー全体のSHA-256です
	IndexManifestSha256 memberSha256{} ;
	/// 原メンバーの先頭から規約指定文までのbyte位置です
	std::uint64_t		statementOffset{} ;
	/// 指定位置にある原ASCII規約指定文です
	std::string			statement ;
	/// 指定文中の原URLです。送信先としては使いません
	std::string			originalDocumentUrl ;
	/**
	 * @brief 共有・再利用時に入力の証拠全項目を比較します
	 * @param[in] other 同じ候補配布物と比較する規約証拠です
	 * @return 全項目が原値で一致した場合trueです
	 */
	[[nodiscard]] bool	operator==( const IndexArchiveTermsNotice &other) const = default ;
} ;

/** @brief 規約の根拠と本文取得情報だけを保持します */
struct IndexAcquisitionTerms {
	/// 元申告状態。UNKNOWNを同意不要へ補完しません
	IndexTermsState						   state{IndexTermsState::UNKNOWN} ;
	/// UNKNOWNの非空理由。既知では空です
	std::string							   reason ;
	/// 元規約根拠URL
	std::string							   evidenceUrl ;
	/// 既知根拠の原bytehash
	std::optional<IndexManifestSha256>	   evidenceSha256 ;
	/// 公開revisionと算出予定を区別する元申告
	IndexTermsRevisionKind				   revisionKind{IndexTermsRevisionKind::NONE} ;
	/// 原公開revision。算出方式では空です
	std::string							   revision ;
	/// 同意必須だけに存在する固定全文取得情報
	std::optional<IndexTermsTextDocument>  textDocument ;
	/// 私有追加欄のZIP規約だけに存在する同じ原配布の証拠です
	std::optional<IndexArchiveTermsNotice> archiveNotice ;
} ;

/** @brief 必須条件の申告種別です。確認やcommand実行はしません */
enum class IndexPrerequisiteKind {
	/// 利用者による個別確認が必要です
	USER_CONFIRMATION,
	/// 端末内の別検査が必要です
	LOCAL_CHECK,
	/// 分離不能firmwareの条件です。導入対象へ昇格しません
	INSEPARABLE_FIRMWARE
} ;

/** @brief 一つの具体的必須条件と出典の元申告です */
struct IndexAcquisitionPrerequisite {
	/// 確認すべき条件の元分類
	IndexPrerequisiteKind kind{IndexPrerequisiteKind::USER_CONFIRMATION} ;
	/// 元公開条件の説明
	std::string			  description ;
	/// 元条件の根拠URL
	std::string			  evidenceUrl ;
	/// 根拠原byteの申告hash
	IndexManifestSha256	  evidenceSha256{} ;
} ;

/** @brief 必須条件の既知集合または未知理由を保持します */
struct IndexAcquisitionPrerequisites {
	/// KNOWNは明示空集合も認めます
	IndexDescriptorState					  state{IndexDescriptorState::UNKNOWN} ;
	/// UNKNOWNの非空理由。既知では空です
	std::string								  reason ;
	/// 最大16件の元条件。UNKNOWNでは空です
	std::vector<IndexAcquisitionPrerequisite> items ;
} ;

/** @brief 監視PCが申告した公式導線確認方法です。端末での実証ではありません */
enum class IndexAuthorityMethod {
	/// 公式サイトの管理主体とlinkを確認したという申告です
	OFFICIAL_SITE_CONTROL_AND_LINK,
	/// Vendor catalog署名を確認したという監視PCの申告です
	VENDOR_CATALOG_SIGNATURE_VERIFIED
} ;

/** @brief 発行側が確認に責任を持つという有限な申告です。Grantではありません */
struct IndexAcquisitionAttestation {
	/// 手動確認記録による申告の場合true、自動collector HTTP観測はfalseです
	bool					 manualReview{} ;
	/// driver-index-acquisition-v1が要求する確認policy revisionです
	std::uint64_t			 policyRevision{} ;
	/// 元確認UTC。Manifest発行時刻へ更新しません
	std::chrono::sys_seconds checkedAtUtc{} ;
	/// 元確認の期限。最大8日です
	std::chrono::sys_seconds validUntilUtc{} ;
	/// 監視PCが申告する確認方法
	IndexAuthorityMethod	 authorityMethod{IndexAuthorityMethod::OFFICIAL_SITE_CONTROL_AND_LINK} ;
	/// 元公式主体の根拠URL
	std::string				 authorityEvidenceUrl ;
	/// 元公式主体の根拠bytehash
	IndexManifestSha256		 authorityEvidenceSha256{} ;
} ;

/** @brief 一payloadの取得情報を型付きで保持します。許可・候補・同意は発行しません */
struct IndexAcquisitionDescriptor {
	/// 静的取得情報の既知／未知
	IndexDescriptorState					   state{IndexDescriptorState::UNKNOWN} ;
	/// UNKNOWNの非空理由。既知では空です
	std::string								   reason ;
	/// 既知の原payload URL。単一公開cache版queryだけを追加受理します
	std::string								   payloadUrl ;
	/// 安全な原basename。保存pathには変換しません
	std::string								   fileName ;
	/// 元形式申告
	IndexPayloadFormat						   format{IndexPayloadFormat::UNKNOWN} ;
	/// 元HTTP content type申告
	std::string								   expectedContentType ;
	/// 正の有限取得byte上限。既知は最大128MiBです
	std::uint64_t							   maximumBytes{} ;
	/// 一payloadの原route。最大6hopです
	std::vector<IndexAcquisitionRouteHop>	   route ;
	/// 同意前の元規約情報
	IndexAcquisitionTerms					   terms ;
	/// 未確認を補完しない具体的必須条件
	IndexAcquisitionPrerequisites			   prerequisites ;
	/// 期待署名者の元申告。索引発行者を代入しません
	IndexObservedValue<std::string>			   publisher ;
	/// KNOWNに必須の元確認申告。製品のtrust権限とは別です
	std::optional<IndexAcquisitionAttestation> attestation ;
	/// 読んだdescriptor wire版。旧原byteの契約を保つ
	std::uint32_t							   schemaVersion{1U} ;
	/// v2だけに存在するSTATIC_URL/content計画。v1は空
	std::optional<OfficialResourceContentPlan> resourceContent ;
	/// v2の閉じた匿名解決。STATIC_URL/v1では空
	std::optional<OfficialAnonymousCdnPlan>	   anonymousCdn ;
} ;

/** @brief 同じCatalog詳細で確認した、元Modelsの範囲内の配布対象です */
struct IndexCatalogHardwareScope {
	/// 更新GUIDを含む固定の公式詳細URLです
	std::string				 detailsUrl ;
	/// 同詳細の原応答本文のSHA-256です
	IndexManifestSha256		 detailsSha256{} ;
	/// 配布対象を再確認した原応答のUTCです
	std::chrono::sys_seconds observedAtUtc{} ;
	/// 配布物全体の対象を公式表の表記と順序で保持します
	std::vector<std::string> packageHardwareIds ;
	/// 全対象のうち、この行の元Modelsに一致したHardware IDです
	std::vector<std::string> hardwareIds ;
	/// 行の照合対象に対応する元ModelsのID位置。昇順で保持する
	std::vector<std::size_t> hardwareIdIndices ;
} ;

/**
 * @brief 同じ公式配布ZIPの元ページで確認し、同じ元Modelsに結合した対象です
 */
struct IndexArchiveHardwareScope {
	/// 公式ZIPへの元リンクと導入前確認を示す配布ページです
	std::string				 pageUrl ;
	/// 元配布ページの原応答本文のSHA-256です
	IndexManifestSha256		 pageSha256{} ;
	/// 元配布ページの観測UTCです
	std::chrono::sys_seconds observedAtUtc{} ;
	/// 同じ元Modelsにある対象の完全Hardware IDを元表記と順序で保持します
	std::vector<std::string> hardwareIds ;
	/// 照合で導いた元ModelsのID位置です。昇順で保持します
	std::vector<std::size_t> hardwareIdIndices ;
} ;

/** @brief 同じ署名済みWiXマニフェストの元役割を保持します */
struct IndexWixMember {
	/// 元Payloadの識別子です
	std::string id ;
	/// 明示した元CAB内メンバー名です
	std::string cabinetMember ;
	/// マニフェストの相対名です。任意の保存先には使用しません
	std::string filePath ;
} ;

/** @brief 全MSIを元順で再照合するための一役割です */
struct IndexWixMsi {
	/// 元添付CABのMSIです
	IndexWixMember member ;
	/// 原Chain条件です。式を評価しません
	std::string	   installCondition ;
	/// AMD64の期待値です。falseは宣言済みX86です
	bool		   amd64{} ;
	/// MSIの非ゼロ言語番号です
	std::uint16_t  language{} ;
} ;

/** @brief 元規約ファイルを同じWiX配布と表示言語に結ぶ証拠です */
struct IndexWixLicense {
	/// 元起動用CABにあるRTFです
	IndexWixMember		member ;
	/// 元定義の言語・地域です
	std::string			locale ;
	/// 変換前のRTF全byte数です
	std::uint64_t		sizeBytes{} ;
	/// 変換前のRTF全体のSHA-256です
	IndexManifestSha256 sha256{} ;
} ;

/** @brief 内側CABから選んだ全ドライバーファイルの一件です */
struct IndexWixDriverFile {
	/// MSIのFileキーと同じ元CAB内名です
	std::string			cabinetMember ;
	/// 元内容検査で対応を確認した論理basenameです
	std::string			targetName ;
	/// 選択ファイルの実byte数です
	std::uint64_t		sizeBytes{} ;
	/// 選択ファイル全体のSHA-256です
	IndexManifestSha256 sha256{} ;
} ;

/** @brief 私有追加欄のWiX配布と元規約を結ぶ型付き申告です */
struct IndexWixContentEvidence {
	/// 元アンカーを掲載した公式ページです
	std::string						pageUrl ;
	/// 収集時に見た元ページのSHA-256です
	IndexManifestSha256				pageSha256{} ;
	/// 発行時刻に置き換えない元ページの観測UTCです
	std::chrono::sys_seconds		observedAtUtc{} ;
	/// 同じパスの一回の301で検証する元転送先です
	std::string						downloadUrl ;
	/// 元EXE検査の許可署名者です
	std::vector<std::string>		acceptedPublishers ;
	/// マニフェストと同じ順序の全MSI役割です
	std::vector<IndexWixMsi>		packages ;
	/// 元RTFの言語別の元証拠です
	std::vector<IndexWixLicense>	licenses ;
	/// 各AMD64 MSIにある内側CABの元ストリーム名です
	std::string						streamName ;
	/// 全AMD64で照合したドライバー閉包です
	std::vector<IndexWixDriverFile> driverFiles ;
} ;

/** @brief 署名済み配布元と端末の型番を結ぶ製造元の区分です */
enum class IndexPlatformMachineVendor {
	/// 型番の発行元または端末の製造元を確認できません
	UNKNOWN,
	/// 端末の製造元は確認できましたが、Lenovoではありません
	OTHER,
	/// Lenovoが発行する型番です
	LENOVO
} ;

/** @brief 同じ公式配布表で確認した機種、型番と元INFの対象条件です */
struct IndexPlatformDeviceScope {
	/// 同じ取得記述がZIPを結ぶ公式配布表のURLです
	std::string				   pageUrl ;
	/// 元配布表の原応答本文のSHA-256です
	IndexManifestSha256		   pageSha256{} ;
	/// 配布表の原観測UTCです
	std::chrono::sys_seconds   observedAtUtc{} ;
	/// 公式配布表と索引で一致した機種名です
	std::string				   model ;
	/// 公式配布表の全型番です
	std::vector<std::string>   machineTypes ;
	/// 同じZIPを指す元配布表とINFに結び付けた完全なHardware IDです
	std::vector<std::string>   packageHardwareIds ;
	/// 元Modelsの位置です。照合時だけ導出し昇順で保持します
	std::vector<std::size_t>   hardwareIdIndices ;
	/// 認証した同じ取得元から導出する型番の発行元です。元JSONには含みません
	IndexPlatformMachineVendor machineVendor{IndexPlatformMachineVendor::UNKNOWN} ;
} ;

/** @brief 同じ配布表が対象機器群に要求するファームウェアです */
struct IndexPlatformFirmwareGroup {
	/// 配布表の対象を示す8桁のPCI subsystemです
	std::vector<std::string> subsystemIds ;
	/// 公式配布表が指定する必須バージョンの元表記です
	std::string				 versionLabel ;
	/// 公式表が参照する元根拠です。取得経路には使用しません
	std::string				 evidenceUrl ;
} ;

/** @brief 同一端末のHardwareIdsが示す公式必須群の状態です */
enum class IndexPlatformFirmwareMatchState {
	/// 同じ端末の完全な観測又は元の対象条件を確認できません
	UNAVAILABLE,
	/// 元レコードが指定する完全なHardware IDがありません
	NO_MATCH,
	/// 一つの公式群に属する対象IDを一件以上確認しました
	UNIQUE,
	/// 異なる公式群に属する対象IDを確認しました
	AMBIGUOUS
} ;

/** @brief 同じ元レコード内で評価したファームウェア条件です */
struct IndexPlatformFirmwareMatch {
	/// 元対象との一致状態です
	IndexPlatformFirmwareMatchState state{IndexPlatformFirmwareMatchState::UNAVAILABLE} ;
	/// 一意の場合の元レコード内の群位置です
	std::optional<std::size_t>		groupIndex ;
} ;

/** @brief 原byteとhashに結合して読んだ一配布recordです */
struct IndexDistributionRecord {
	/// 読み取ったwire record版。現在のreader policy版とは別です
	std::uint32_t							  recordSchemaVersion{1U} ;
	/// v2以降の取得情報。v1から暗黙補完しません
	std::optional<IndexAcquisitionDescriptor> acquisitionDescriptor ;
	/// 私有追加欄v3又は公式Models専用欄v6のCatalog対象条件です
	std::optional<IndexCatalogHardwareScope>  catalogHardwareScope ;
	/// v6原レコードが署名範囲内で指定した元証拠のSHA-256です
	std::optional<IndexManifestSha256>		  scopedModelsEvidenceSha256 ;
	/// v6で原レコードと配布物・INF・元Modelsの全結合を照合した元証拠です
	std::shared_ptr<const signed_index_detail::CollectorScopedModelsEvidence> scopedModelsEvidence ;
	/// 私有追加欄のv4とv5にある機種・型番別の対象条件です
	std::optional<IndexPlatformDeviceScope>									  platformDeviceScope ;
	/// 私有追加欄のv5で保持する配布表の全必須条件です
	std::vector<IndexPlatformFirmwareGroup>		 platformFirmwareGroups ;
	/// 私有追加欄v7で保持する公式配布ZIPの機器別対象条件です
	std::optional<IndexArchiveHardwareScope>	 archiveHardwareScope ;
	/// 私有DCのv8で保持する元WiX配布と規約です
	std::optional<IndexWixContentEvidence>		 wixContentEvidence ;
	/// v1の取得情報不在の固定理由。v2では空です
	std::string									 acquisitionDescriptorUnavailableReason ;
	/// Decodeした原UTF-8 byte。空白・field順を保持します
	std::string									 originalBytes ;
	/// originalBytesだけの実SHA-256。Indexや圧縮hashではありません
	IndexManifestSha256							 recordSha256{} ;
	/// 必ず存在するsourceへの原identity参照
	std::string									 sourceId ;
	/// Source内で一意なrecord identity
	std::string									 recordId ;
	/// 元申告の製品表示名。適合条件に使いません
	std::string									 product ;
	/// 元申告のOS条件またはUNKNOWN理由
	IndexObservedValue<IndexTargetOs>			 targetOs ;
	/// 元申告のx64条件またはUNKNOWN理由
	IndexObservedValue<IndexArchitecture>		 architecture ;
	/// 元申告の内容種別またはUNKNOWN理由
	IndexObservedValue<IndexDriverKind>			 driverKind ;
	/// 原versionまたはUNKNOWN理由。Codecは比較しません
	IndexObservedValue<std::string>				 version ;
	/// 実在公開日またはUNKNOWN理由
	IndexObservedValue<std::string>				 publishedDate ;
	/// 元申告の方式またはUNKNOWN理由。導入許可ではありません
	IndexObservedValue<IndexAcquisitionKind>	 acquisition ;
	/// 公開／計算hash、sizeと出典の元申告
	IndexPackageEvidence						 packageEvidence ;
	/// 発行側の成功観測UTCまたはUNKNOWN理由
	IndexObservedValue<std::chrono::sys_seconds> lastSuccessfulObservationUtc ;
	/// 発行側の段階。署名qualityへ実件数として照合します
	IndexInspectionStage						 inspectionStage{IndexInspectionStage::UNCONFIRMED} ;
	/// 公開identityの元申告、または保持したUNKNOWN理由
	IndexPublishedIdentityEvidence				 publishedIdentityEvidence ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ元Modelsの一部に対象を限定する原レコードか判定します
 * @param[in] record 借用する型付き元レコードです
 * @return Catalog、機種別又は公式配布ZIPの対象条件がある場合trueです
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isIndexHardwareScoped( const IndexDistributionRecord &record) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 端末のHardwareIdsだけを照合する必要があるレコードを判定します
 * @param[in] record 認証済みの配布条件を保持する借用レコードです
 * @return 元Modelsの対象条件又は私有WiXの配布証拠がある場合trueです
 * @note 署名の確認や照合結果の発行は行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool requiresExactIndexHardwareMatch( const IndexDistributionRecord &record) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 元ModelsのIDがWiX配布の完全Hardware IDとして照合対象になるか判定します
 * @param[in] id 共通codecで構造を確認した元ModelsのIDです
 * @return Hardware ID種別であり、ワイルドカードのない場合trueです
 * @note 端末IDや接続機器は読み取りません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool isExactWixHardwareId( const IndexPublishedPnpId &id) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ端末の全HardwareIdsから元レコードの必須群を判定します
 * @param[in] record 署名と元Modelsの検査を通過した配布レコードです
 * @param[in] hardwareIds 同一PnPインスタンスの検証済みで大文字に正規化した全HardwareIdsです
 * @return 同一群の複数IDを一つの一致とし、異なる群の一致を競合とする判定です
 * @note 公式の完全対象IDだけを使います。互換属性や必須版の文字列で群を選びません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexPlatformFirmwareMatch classifyIndexPlatformFirmwareGroup(
	const IndexDistributionRecord &record, std::span<const std::wstring> hardwareIds) noexcept ;

struct IndexRecordsResult ;

/** @brief 全schema検査成功後にだけ構築する保存前の不変receiptです
 * @note 認証byteと原recordを所有します。原子保存・公式性実証・端末照合・導入許可ではありません
 */
class IndexRecordsSchemaReceipt final {
public:
	/**
	 * @brief 認証byte receiptを変更できない参照で借用します
	 * @return 本receiptの寿命まで有効なbyte receipt
	 */
	[[nodiscard]] const AuthenticatedIndexAssetBytes	  &assetBytes() const noexcept ;
	/**
	 * @brief 展開index原byteのhashを借用します
	 * @return 圧縮hashと各record hashから独立したdigest
	 */
	[[nodiscard]] const IndexManifestSha256				  &indexSha256() const noexcept ;
	/**
	 * @brief 元申告のsource集合を借用します
	 * @return 本receiptの寿命まで有効な不変span
	 */
	[[nodiscard]] std::span<const IndexRecordSource>	   sources() const noexcept ;
	/**
	 * @brief 原byteに結合したrecord集合を借用します
	 * @return 本receiptの寿命まで有効な不変span。端末適合は未評価です
	 */
	[[nodiscard]] std::span<const IndexDistributionRecord> records() const noexcept ;
	/**
	 * @brief 署名quality全fieldに一致した実件数を借用します
	 * @return 発行側の段階別件数。端末の実検査件数ではありません
	 */
	[[nodiscard]] const IndexManifestQuality			  &actualQuality() const noexcept ;
	/**
	 * @brief 読取りを実行した現codec policy版を返します
	 * @return 現reader revisionの2。保存head互換値とwire record版とは別です
	 */
	[[nodiscard]] std::uint32_t							   schemaPolicyVersion() const noexcept ;

private:
	/**
	 * @brief Schema・参照・hash・qualityの全成功後に値を所有します
	 * @param[in] asset 認証済みbyte receiptの所有copy
	 * @param[in] sources 検査した所有source
	 * @param[in] records 検査した所有record
	 * @param[in] quality 実source／record／stage件数
	 */
	IndexRecordsSchemaReceipt( AuthenticatedIndexAssetBytes		   asset,
							  std::vector<IndexRecordSource>	   sources,
							  std::vector<IndexDistributionRecord> records,
							  IndexManifestQuality				   quality) noexcept ;
	/**
	 * @brief 認証済みbyteだけから配布schema・原record hash・参照・qualityを読みます
	 * @note 第1引数（const AuthenticatedIndexAssetBytes &、in）はこの宣言では無名です。呼出し中不変で完全な前段byte receipt。DTOや未
	 *       認証byteは受理しません
	 * @note 第2引数（std :: optional < std :: chrono :: sys_seconds >、in）はこの宣言では無名です。信頼UTCの再確認。発行前・期限以上
	 *       ・確認不能は拒否します
	 * @return 全検査成功時だけschema receipt。拒否は理由と元診断を保持します
	 * @note 独立入力では同時呼出し可能です。Network・保存・highwater更新・端末ID・通常UI・導入は扱いません
	 */
	friend IndexRecordsResult readSignedIndexRecords(
		const AuthenticatedIndexAssetBytes &, std::optional<std::chrono::sys_seconds>) noexcept ;
	/// 原manifest・圧縮identity・展開原byteとhashの認証根拠を所有します
	AuthenticatedIndexAssetBytes		 asset_ ;
	/// 一意かつ全件参照されたsourceの元申告を所有します
	std::vector<IndexRecordSource>		 sources_ ;
	/// 原byte・hash・公開証拠／UNKNOWNを検査したrecordを所有します
	std::vector<IndexDistributionRecord> records_ ;
	/// 署名qualityと完全一致した実件数です
	IndexManifestQuality				 quality_ ;
} ;

/** @brief Schema読取りの成功と入力拒否・API障害を区別します */
enum class IndexRecordsStatus {
	/// Schema・原bytehash・参照・qualityが成功しました。保存と端末検査は別です
	SCHEMA_VALIDATED,
	/// Move元などで認証byteまたは必須manifest根拠が欠損しています
	INCOMPLETE_BYTE_RECEIPT,
	/// 信頼UTCを確認できません
	TIME_UNAVAILABLE,
	/// 発行前です
	NOT_YET_VALID,
	/// 署名期限以上です
	EXPIRED,
	/// Index原byteが空または128MiB枠を超えています
	INDEX_SIZE_LIMIT,
	/// IndexのJSON・schema・field・型・深さが不正です
	INVALID_INDEX,
	/// RecordのJSON・schema・field・型・深さが不正です
	INVALID_RECORD,
	/// 標準base64の文法・padding・未使用bitが不正です
	INVALID_BASE64,
	/// Decodeした一recordが512KiB枠を超えています
	RECORD_SIZE_LIMIT,
	/// Decode原record合計が64MiB枠を超えています
	TOTAL_RECORD_SIZE_LIMIT,
	/// Source／record／PnP件数の有限枠を超えています
	COUNT_LIMIT,
	/// 原record hashが申告digestへ一致しません
	RECORD_HASH_MISMATCH,
	/// Source identityが重複しています
	DUPLICATE_SOURCE,
	/// Sourceとrecord identityの組が重複しています
	DUPLICATE_RECORD,
	/// Recordが存在しないsourceを参照しました
	MISSING_SOURCE,
	/// 一件も参照されないsourceがあります
	UNREFERENCED_SOURCE,
	/// 実source／record／stage件数が署名qualityへ一致しません
	QUALITY_MISMATCH,
	/// Indexのasset世代と署名manifestが一致しません
	ASSET_GENERATION_MISMATCH,
	/// UNKNOWNと既知値、公開証拠・identityまたはhashが矛盾しています
	INVALID_EVIDENCE,
	/// 用途限定HTTPS URL形式が不成立です。v1 PAGE query制限も維持します
	INVALID_URL,
	/// 共通hash APIが失敗しました。元HRESULTを保持します
	CRYPTO_FAILURE,
	/// 確保失敗です。成功receiptを生成しません
	OUT_OF_MEMORY,
	/// 型不明の内部障害です。成功へ読み替えません
	INTERNAL_FAILURE,
	/// 全recordの公開ID入力総数が共通枠を超えています
	INPUT_COUNT_LIMIT,
	/// 追加欄又は対応する旧索引が現行の取得用途の前提を満たしません
	INVALID_SUPPLEMENT_PURPOSE,
	/// 追加欄又は候補manifestの期限が対象レコードの最短期限に一致しません
	SUPPLEMENT_EXPIRY_MISMATCH,
	/// 同じ元配布物・INF・適用OSに異なる対象条件やModelsの並びがあります
	CATALOG_SCOPE_CONFLICT,
	/// 同じ元配布物・INF・適用OSに異なる機種条件又は対象なしの行があります
	PLATFORM_DEVICE_SCOPE_CONFLICT,
	/// 同じ元配布物・INF・適用OSに異なるZIP対象条件又は対象なしの行があります
	ARCHIVE_HARDWARE_SCOPE_CONFLICT
} ;

/** @brief 全読取り成功時だけ保存前の不変receiptを持ちます */
struct IndexRecordsResult {
	/// 初期値は未検査を成功にしない拒否区分です
	IndexRecordsStatus						 status{IndexRecordsStatus::INVALID_INDEX} ;
	/// 共通APIの元HRESULT。それ以外の入力拒否は0です
	NativeError								 error{} ;
	/// Schema全成功時だけ存在します。AuthenticatedIndexSnapshotではありません
	std::optional<IndexRecordsSchemaReceipt> receipt ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 認証済みbyteだけから配布schema・原record hash・参照・qualityを読みます
 * @param[in] asset 呼出し中不変で完全な前段byte receipt。DTOや未認証byteは受理しません
 * @param[in] nowUtc 信頼UTCの再確認。発行前・期限以上・確認不能は拒否します
 * @return 全検査成功時だけschema receipt。拒否は理由と元診断を保持します
 * @note 独立入力では同時呼出し可能です。Network・保存・highwater更新・端末ID・通常UI・導入は扱いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexRecordsResult readSignedIndexRecords(
	const AuthenticatedIndexAssetBytes	   &asset,
	std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief 検査済み追加レコードの値です。保存・推薦・取得を許可する型ではありません */
struct IndexSupplementRecordsResult {
	/// 追加欄の運搬結果です
	IndexAssetSupplementStatus			 transportStatus{IndexAssetSupplementStatus::ABSENT} ;
	/// 構造と元根拠の結果です
	IndexRecordsStatus					 status{IndexRecordsStatus::INVALID_INDEX} ;
	/// 元APIの診断です
	NativeError							 error{} ;
	/// 全検査成功時の追加欄の取得元です
	std::vector<IndexRecordSource>		 sources ;
	/// 全検査成功時の元型付きレコードです
	std::vector<IndexDistributionRecord> records ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名済みassetから追加欄のレコードと旧索引との共通枠を検査します
 * @param[in] base 同assetの旧索引を検査した不変receiptです
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 現公開形式の追加欄の検査結果です。私有Catalog条件又は他の失敗では取得元と行を返しません
 * @pre Windows最低buildの根拠を含む追加欄は呼出しworkerのMTAで検査します
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexSupplementRecordsResult readSignedIndexSupplementRecords(
	const IndexRecordsSchemaReceipt &base, std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

/** @brief 認証済み追加欄から端末照合に引き継ぐ原レコードとその領域です */
struct IndexConsumerSupplementResult {
	/// 運搬・構造検査の結果と元取得元・原レコードです
	IndexSupplementRecordsResult contents ;
	/// 全検査成功時の元追加欄の展開SHA-256です
	IndexManifestSha256			 expandedSha256{} ;
	/// 全検査成功時の元追加欄の最短期限です
	std::chrono::sys_seconds	 expiresAtUtc{} ;
} ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名済みassetの追加欄を端末向けに検査し、元領域とレコードを取得します
 * @param[in] base 同じassetの旧本文を検査した不変receiptです
 * @param[in] nowUtc 確認済み現在UTCです
 * @return 両領域の参照・対象・上限と期限を満たした追加欄の元値、又は理由付きの空結果です
 * @pre Windows最低buildの根拠を含む追加欄は呼出しworkerのMTAで検査します
 * @note Catalog対象付き行も原領域に結合します。端末適合、取得、導入を許可する処理ではありません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexConsumerSupplementResult readSignedIndexConsumerSupplement(
	const IndexRecordsSchemaReceipt &base, std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

//------------------------------------------------------------------------------
/**
 * @brief 同じ署名済みassetのDM欄から元配布行と公式Models証拠を読み取ります
 * @param[in] base 同じassetの旧本文を検査した不変receiptです
 * @param[in] nowUtc 確認済みの現在UTCです
 * @return 旧本文との共通枠と結合を検査した元行・証拠又は理由付きの空結果です
 * @note 本文と独立に検査し、端末への適用や取得の権限は発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] IndexConsumerSupplementResult readSignedIndexScopedModels(
	const IndexRecordsSchemaReceipt &base, std::optional<std::chrono::sys_seconds> nowUtc) noexcept ;

} // namespace drivercrate
