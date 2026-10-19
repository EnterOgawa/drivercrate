//------------------------------------------------------------------------------
/**
 * @file scan_measurement_diagnostics.cpp
 * @brief 固定条件scanのprofile検証と非機密ASCII report構築。
 * @version 01.01.01
 * @date 2026/09/10
 * @author Shunji Ogawa
 * @copyright Copyright (c) 2026 EnterSystem CO.,LTD.
 *
 * @par ライセンス
 * SPDX-License-Identifier: Apache-2.0
 * 本ファイルには Apache License, Version 2.0 が適用されます。
 * ライセンス全文はプロジェクトルートの LICENSE を参照してください。
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * @par 会社名
 * EnterSystem
 *
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  固定profileと計測reportの出力境界を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  ReportのID照合と限定失敗診断を追加。
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  有効context集合の順序非依存照合と固定順出力を追加。
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  独立ファイル版と改訂コメント規約へ移行。
 * Ver.01.00.01 Shunji Ogawa  2026/09/12  情報検索の専用契約と通常経路の互換性を追加。
 * Ver.01.00.02 Shunji Ogawa  2026/09/15  組み込みProvider件数を更新。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  未承認で停止した公式探索状態の診断名を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/12  明示9件を維持し署名索引を含む31登録の固定境界を確認。
 * </pre>
 *
 * @note 全reportを1 MiB以下のmemory上で検証・構築してから一回だけ出力します。
 *       Network、device列挙、cache、準備、導入および復元APIを呼びません。
 * @see docs/adr/0140-read-only-scan-measurement-run.md
 */
//------------------------------------------------------------------------------

#include "scan_measurement_diagnostics.h"

#include "core/official_source_policy.h"
#include "core/provider_registry.h"
#include "core/scan_measurement.h"

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <ios>
#include <iterator>
#include <optional>
#include <ostream>
#include <set>
#include <span>
#include <streambuf>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>

namespace drivercrate::test {
namespace {

//------------------------------------------------------------------------------
// 固定profile定義。
//------------------------------------------------------------------------------

constexpr std::size_t EXPECTED_PROVIDER_COUNT = 31U ;	// 署名索引を含む登録済みProvider総数。

// 初回実測の明示Provider集合。Registry変更時に暗黙で追加せず再審査する。
constexpr std::array<std::wstring_view, 9> BASELINE_PROVIDER_IDS{WINDOWS_UPDATE_PROVIDER_ID,
																 DRIVER_STORE_PROVIDER_ID,
																 NVIDIA_PROVIDER_ID,
																 DELL_PROVIDER_ID,
																 DELL_POWER_EDGE_PROVIDER_ID,
																 LENOVO_PROVIDER_ID,
																 HP_PROVIDER_ID,
																 VAIO_PROVIDER_ID,
																 AMD_PROVIDER_ID} ;

//------------------------------------------------------------------------------
// 内部型定義。
//------------------------------------------------------------------------------

/** @brief 上限内のASCII断片だけを所有bufferへ連結する。 */
class AsciiReportBuilder				   final {
public:
	  /**
	 * @brief Report構築用bufferを空で開始する。
	 * @param[in] maximumBytes 完全reportへ許可する最大byte数。
	 */
	  explicit AsciiReportBuilder( const std::size_t maximumBytes) : maximumBytes_( maximumBytes)
	  {
		  data_.reserve( std::min( maximumBytes_, std::size_t{64U * 1024U})) ;
	  }

	  /**
	 * @brief 固定ASCII断片を上限内で追加する。
	 * @param[in] text 呼出し中だけ借用するASCII断片。
	 * @return 全byteを追加できた場合true。
	 */
	  [[nodiscard]] bool append( const std::string_view text)
	  {
		  // 一度失敗した構築と、加算前の残容量を超える断片を受理しない。
		  if( failed_ || text.size() > maximumBytes_ - data_.size()) {
			  failed_ = true ;
			  return false ;
		  }

		  data_.append( text) ;
		  return true ;
	  }

	  /**
	 * @brief Unsigned整数をlocale非依存の10進ASCIIで追加する。
	 * @param[in] value 変換する整数。
	 * @return 変換と追加が成功した場合true。
	 */
	  [[nodiscard]] bool appendUnsigned( const std::uint64_t value)
	  {
		  std::array<char, 32> digits{} ;	// 64-bit 10進値を終端なしで保持する領域。
		  const auto		   result =
			  // 有限変換結果。
			  std::to_chars( digits.data(), digits.data() + digits.size(), value) ;
		  // 標準変換が値を収容できない場合は不完全reportを破棄する。
		  if( result.ec != std::errc{}) {
			  failed_ = true ;
			  return false ;
		  }

		  return append(
			  std::string_view( digits.data(), static_cast<std::size_t>( result.ptr - digits.data()))) ;
	  }

	  /**
	 * @brief Wide stable IDを区切り安全なASCIIへ検証して追加する。
	 * @param[in] value 呼出し中だけ借用するregistry由来のIDまたは実行版。
	 * @return 空でなく許可文字だけを追加できた場合true。
	 */
	  [[nodiscard]] bool appendIdentifier( const std::wstring_view value)
	  {
		  // 空文字列を未公開値の代わりに出力せず、固定schemaを維持する。
		  if( value.empty()) {
			  failed_ = true ;
			  return false ;
		  }

		  // Wide値の全文字を確認し、改行やdelimiterを出力へ注入させない。
		  for( const wchar_t character : value) {
			  const bool lowercase = character >= L'a' && character <= L'z' ;	// ASCII小文字。
			  const bool uppercase = character >= L'A' && character <= L'Z' ;	// ASCII大文字。
			  const bool digit = character >= L'0' && character <= L'9' ;		// ASCII数字。
			  // Stable IDとversionに必要な区切り以外を拒否し、正規化しない。
			  if( !lowercase && !uppercase && !digit && character != L'-' && character != L'.' &&
				 character != L'_') {
				  failed_ = true ;
				  return false ;
			  }

			  const char byte = static_cast<char>( character) ;	// 上段でASCII範囲を確認した一文字。
			  // 一文字でも容量を超える場合は以後の構築を停止する。
			  if( !append( std::string_view( &byte, 1U))) {
				  return false ;
			  }
		  }

		  return true ;
	  }

	  /**
	 * @brief Native 32-bit値を符号拡張しない固定8桁16進で追加する。
	 * @param[in] value HRESULTまたは計測診断の32-bit bit pattern。
	 * @return 8桁を追加できた場合true。
	 */
	  [[nodiscard]] bool appendError( const NativeError value)
	  {
		  constexpr std::string_view HEX_DIGITS = "0123456789ABCDEF" ;	// 固定大文字16進表。
		  std::array<char, 8>		 digits{} ;							// 先行zeroを含む32-bit値の固定表現。
		  const auto bits = static_cast<std::uint32_t>( value) ;		// 符号を保持するbit pattern。
		  // 上位nibbleから8桁だけを生成し、localeとformat flagを参照しない。
		  for( std::size_t index = 0; index < digits.size(); ++index) {
			  const auto shift = static_cast<unsigned>( (digits.size() - index - 1U) *
																	   4U) ;	// 現在桁の32-bit内shift量。
			  digits[index] = HEX_DIGITS[(bits >> shift) & 0xFU] ;
		  }

		  return append( std::string_view( digits.data(), digits.size())) ;
	  }

	  /**
	 * @brief 完全構築した所有bufferを呼出し側へ移す。
	 * @return これまでに追加したASCII byte列。
	 */
	  [[nodiscard]] std::string release() noexcept
	  {
		  return std::move( data_) ;
	  }

private:
	  /// 完全検証後だけ外へ移すASCII report。
	  std::string data_ ;
	  /// 構築中も超えないbyte上限。
	  std::size_t maximumBytes_{} ;
	  /// trueの場合は後続追加を全て拒否する。
	  bool		  failed_{} ;
} ;

//------------------------------------------------------------------------------
// 内部変換関数定義。
//------------------------------------------------------------------------------

/**
 * @brief Provider descriptorの全registry fieldを完全一致で比較する。
 * @param[in] left Scan report側のdescriptor。
 * @param[in] right 組み込みregistry側のdescriptor。
 * @return 全fieldが一致する場合true。
 */
[[nodiscard]] bool sameDescriptor( const ProviderDescriptor &left,
								  const ProviderDescriptor &right) noexcept
{
	return left.id == right.id && left.displayName == right.displayName &&
		   left.capabilities == right.capabilities && left.selectionTier == right.selectionTier &&
		   left.discoveryBasis == right.discoveryBasis &&
		   left.installNotice == right.installNotice &&
		   left.enabledByDefault == right.enabledByDefault &&
		   left.officialSourcePolicyId == right.officialSourcePolicyId ;
}

/**
 * @brief 確定度を固定ASCII名へ変換する。
 * @param[in] extent 変換するenum値。
 * @return 定義済み値の名前。未知値は空。
 */
[[nodiscard]] std::string_view extentName( const MeasurementExtent extent) noexcept
{
	// 全定義値を明示mappingし、数値castによる未知値の出力を防ぐ。
	switch( extent) {
		// 未計測は値なしの固定名へ変換する。
		case MeasurementExtent::NOT_MEASURED:
			return "NOT_MEASURED" ;
		// 確定件数はEXACTへ変換する。
		case MeasurementExtent::EXACT:
			return "EXACT" ;
		// 確認済み下限はLOWER_BOUNDへ変換する。
		case MeasurementExtent::LOWER_BOUND:
			return "LOWER_BOUND" ;
		// 計測不能は値なしのUNAVAILABLEへ変換する。
		case MeasurementExtent::UNAVAILABLE:
			return "UNAVAILABLE" ;
	}

	return {} ;
}

/**
 * @brief Provider計測scopeを固定ASCII名へ変換する。
 * @param[in] scope 変換するenum値。
 * @return 定義済み値の名前。未知値は空。
 */
[[nodiscard]] std::string_view scopeName( const MeasurementScope scope) noexcept
{
	// 個別／system queryと従来未接続を区別する。
	switch( scope) {
		// 従来未接続を推測せず固定名へ変換する。
		case MeasurementScope::LEGACY_UNKNOWN:
			return "LEGACY_UNKNOWN" ;
		// Device別queryの証拠範囲を固定名へ変換する。
		case MeasurementScope::DEVICE_QUERY:
			return "DEVICE_QUERY" ;
		// System全体queryの証拠範囲を固定名へ変換する。
		case MeasurementScope::SYSTEM_QUERY:
			return "SYSTEM_QUERY" ;
	}

	return {} ;
}

/**
 * @brief OS区分を固定ASCII名へ変換する。
 * @param[in] kind 変換するenum値。
 * @return 定義済み値の名前。未知enumは空。
 */
[[nodiscard]] std::string_view osKindName( const MeasurementOsKind kind) noexcept
{
	// 取得不能、client、serverを推測せずそのまま区別する。
	switch( kind) {
		// 取得不能なOS区分をUNKNOWNへ変換する。
		case MeasurementOsKind::UNKNOWN:
			return "UNKNOWN" ;
		// Windows clientをCLIENTへ変換する。
		case MeasurementOsKind::CLIENT:
			return "CLIENT" ;
		// Windows ServerをSERVERへ変換する。
		case MeasurementOsKind::SERVER:
			return "SERVER" ;
	}

	return {} ;
}

/**
 * @brief Provider scan状態を固定ASCII名へ変換する。
 * @param[in] state 変換するenum値。
 * @return 定義済み値の名前。未知enumは空。
 */
[[nodiscard]] std::string_view providerStateName( const ProviderScanState state) noexcept
{
	// 正常0件と各拒否・失敗を同じ文字列へまとめない。
	switch( state) {
		// 無効Providerを未実行の固定名へ変換する。
		case ProviderScanState::DISABLED:
			return "DISABLED" ;
		// 対象外判定を固定名へ変換する。
		case ProviderScanState::NOT_APPLICABLE:
			return "NOT_APPLICABLE" ;
		// 成立した候補0件を固定名へ変換する。
		case ProviderScanState::NO_CANDIDATES:
			return "NO_CANDIDATES" ;
		// 候補ありを固定名へ変換する。
		case ProviderScanState::CANDIDATES_AVAILABLE:
			return "CANDIDATES_AVAILABLE" ;
		// Payloadを今回の検査用に取得しない正常状態を固定名へ変換する。
		case ProviderScanState::PAYLOAD_NOT_APPROVED:
			return "PAYLOAD_NOT_APPROVED" ;
		// 制限または状態不明回線の未許可を固定名へ変換する。
		case ProviderScanState::NETWORK_NOT_APPROVED:
			return "NETWORK_NOT_APPROVED" ;
		// 一般検索失敗を固定名へ変換する。
		case ProviderScanState::FAILURE:
			return "FAILURE" ;
		// Metadata拒否を固定名へ変換する。
		case ProviderScanState::METADATA_REJECTED:
			return "METADATA_REJECTED" ;
		// 取得元拒否を固定名へ変換する。
		case ProviderScanState::SOURCE_REJECTED:
			return "SOURCE_REJECTED" ;
		// 検査用取得失敗を固定名へ変換する。
		case ProviderScanState::DOWNLOAD_FAILED:
			return "DOWNLOAD_FAILED" ;
		// 内容監査拒否を固定名へ変換する。
		case ProviderScanState::CONTENT_REJECTED:
			return "CONTENT_REJECTED" ;
	}

	return {} ;
}

/**
 * @brief Operation outcomeを固定ASCII名へ変換する。
 * @param[in] outcome 変換するenum値。
 * @return 定義済み値の名前。未知enumは空。
 */
[[nodiscard]] std::string_view outcomeName( const OutcomeCode outcome) noexcept
{
	// 完了結果を未開始・実行中と区別した固定名へ変換する。
	switch( outcome) {
		// 未開始を固定名へ変換する。
		case OutcomeCode::NOT_STARTED:
			return "NOT_STARTED" ;
		// 実行中を固定名へ変換する。
		case OutcomeCode::IN_PROGRESS:
			return "IN_PROGRESS" ;
		// 全成功を固定名へ変換する。
		case OutcomeCode::SUCCESS:
			return "SUCCESS" ;
		// 個別失敗を含む成功を固定名へ変換する。
		case OutcomeCode::SUCCEEDED_WITH_ERRORS:
			return "SUCCEEDED_WITH_ERRORS" ;
		// 全失敗を固定名へ変換する。
		case OutcomeCode::FAILURE:
			return "FAILURE" ;
		// 明示中止を固定名へ変換する。
		case OutcomeCode::ABORTED:
			return "ABORTED" ;
	}

	return {} ;
}

/**
 * @brief 計測停止理由を固定ASCII名へ変換する。
 * @param[in] reason 変換するenum値。
 * @return 定義済み値の名前。未知enumは空。
 */
[[nodiscard]] std::string_view reasonName( const MeasurementReason reason) noexcept
{
	// 公開契約にある20種類だけを文字列化する。
	switch( reason) {
		// 設定無効の停止理由を固定名へ変換する。
		case MeasurementReason::DISABLED:
			return "DISABLED" ;
		// 対象外の停止理由を固定名へ変換する。
		case MeasurementReason::NOT_APPLICABLE:
			return "NOT_APPLICABLE" ;
		// 未着手の停止理由を固定名へ変換する。
		case MeasurementReason::NOT_STARTED:
			return "NOT_STARTED" ;
		// 属性欠損の停止理由を固定名へ変換する。
		case MeasurementReason::MISSING_ATTRIBUTE:
			return "MISSING_ATTRIBUTE" ;
		// Adapter未接続の停止理由を固定名へ変換する。
		case MeasurementReason::ADAPTER_UNCONNECTED:
			return "ADAPTER_UNCONNECTED" ;
		// 情報なしの停止理由を固定名へ変換する。
		case MeasurementReason::NO_INFORMATION:
			return "NO_INFORMATION" ;
		// Query失敗の停止理由を固定名へ変換する。
		case MeasurementReason::QUERY_FAILED:
			return "QUERY_FAILED" ;
		// 取得元拒否の停止理由を固定名へ変換する。
		case MeasurementReason::SOURCE_REJECTED:
			return "SOURCE_REJECTED" ;
		// Metadata拒否の停止理由を固定名へ変換する。
		case MeasurementReason::METADATA_REJECTED:
			return "METADATA_REJECTED" ;
		// 検査同意不足の停止理由を固定名へ変換する。
		case MeasurementReason::INSPECTION_CONSENT_REQUIRED:
			return "INSPECTION_CONSENT_REQUIRED" ;
		// Download失敗の停止理由を固定名へ変換する。
		case MeasurementReason::DOWNLOAD_FAILED:
			return "DOWNLOAD_FAILED" ;
		// 内容拒否の停止理由を固定名へ変換する。
		case MeasurementReason::CONTENT_REJECTED:
			return "CONTENT_REJECTED" ;
		// 適用性未確認の停止理由を固定名へ変換する。
		case MeasurementReason::APPLICABILITY_PENDING:
			return "APPLICABILITY_PENDING" ;
		// 適用性拒否の停止理由を固定名へ変換する。
		case MeasurementReason::APPLICABILITY_REJECTED:
			return "APPLICABILITY_REJECTED" ;
		// Local未照合の停止理由を固定名へ変換する。
		case MeasurementReason::UNMATCHED:
			return "UNMATCHED" ;
		// 複数一致の停止理由を固定名へ変換する。
		case MeasurementReason::AMBIGUOUS_MATCH:
			return "AMBIGUOUS_MATCH" ;
		// 照合不能の停止理由を固定名へ変換する。
		case MeasurementReason::MATCH_UNAVAILABLE:
			return "MATCH_UNAVAILABLE" ;
		// 明示中止の停止理由を固定名へ変換する。
		case MeasurementReason::ABORTED:
			return "ABORTED" ;
		// 有限上限到達の停止理由を固定名へ変換する。
		case MeasurementReason::LIMIT_REACHED:
			return "LIMIT_REACHED" ;
		// 不完全列挙の停止理由を固定名へ変換する。
		case MeasurementReason::INCOMPLETE:
			return "INCOMPLETE" ;
	}

	return {} ;
}

/**
 * @brief 理由件数の単位を固定ASCII名へ変換する。
 * @param[in] unit 変換するenum値。
 * @return 定義済み値の名前。未知enumは空。
 */
[[nodiscard]] std::string_view unitName( const MeasurementUnit unit) noexcept
{
	// Device、record、query、requestの数値を混同しない。
	switch( unit) {
		// Device単位を固定名へ変換する。
		case MeasurementUnit::DEVICE:
			return "DEVICE" ;
		// Record単位を固定名へ変換する。
		case MeasurementUnit::RECORD:
			return "RECORD" ;
		// Query単位を固定名へ変換する。
		case MeasurementUnit::QUERY:
			return "QUERY" ;
		// Request単位を固定名へ変換する。
		case MeasurementUnit::REQUEST:
			return "REQUEST" ;
	}

	return {} ;
}

/**
 * @brief Resourceの実取得区分を固定ASCII名へ変換する。
 * @param[in] acquisition 変換するenum値。
 * @return 定義済み値の名前。未知enumは空。
 */
[[nodiscard]] std::string_view acquisitionName( const MeasurementAcquisition acquisition) noexcept
{
	// Network本文、cache、未接続を観測値のまま区別する。
	switch( acquisition) {
		// 未接続の取得区分を固定名へ変換する。
		case MeasurementAcquisition::UNKNOWN:
			return "UNKNOWN" ;
		// 今回取得した本文を固定名へ変換する。
		case MeasurementAcquisition::NETWORK_BODY:
			return "NETWORK_BODY" ;
		// 有効期限内cacheを固定名へ変換する。
		case MeasurementAcquisition::FRESH_CACHE:
			return "FRESH_CACHE" ;
		// Origin再検証済みcacheを固定名へ変換する。
		case MeasurementAcquisition::REVALIDATED_CACHE:
			return "REVALIDATED_CACHE" ;
		// 複数resourceの混在区分を固定名へ変換する。
		case MeasurementAcquisition::MIXED:
			return "MIXED" ;
		// HTTP非該当の取得区分を固定名へ変換する。
		case MeasurementAcquisition::NOT_APPLICABLE:
			return "NOT_APPLICABLE" ;
	}

	return {} ;
}

/**
 * @brief 許可された失敗理由だけを固定ASCII名へ変換する。
 * @param[in] reason 本文書込み前に確定した拒否理由。
 * @return 既知理由の固定名。未知enumは空。
 */
[[nodiscard]] std::string_view failureReasonName( const ScanMeasurementFailureReason reason) noexcept
{
	// 拒否地点を固定名へ一対一に対応させ、任意文字列を出力しない。
	switch( reason) {
		// Eventとmessage受信の拒否を表す。
		case ScanMeasurementFailureReason::WORKER_EVENT_REJECTED:
			return "WORKER_EVENT_REJECTED" ;
		// 完了結果の欠落を表す。
		case ScanMeasurementFailureReason::SCAN_RESULT_MISSING:
			return "SCAN_RESULT_MISSING" ;
		// Controllerによる候補sessionの拒否を表す。
		case ScanMeasurementFailureReason::CONTROLLER_REJECTED:
			return "CONTROLLER_REJECTED" ;
		// 計測値が公開されていないことを表す。
		case ScanMeasurementFailureReason::MEASUREMENT_MISSING:
			return "MEASUREMENT_MISSING" ;
		// 公開snapshotの矛盾を表す。
		case ScanMeasurementFailureReason::PUBLISHED_MEASUREMENT_REJECTED:
			return "PUBLISHED_MEASUREMENT_REJECTED" ;
		// Export契約または容量による構築拒否を表す。
		case ScanMeasurementFailureReason::REPORT_CONTRACT_REJECTED:
			return "REPORT_CONTRACT_REJECTED" ;
	}

	return {} ;
}

//------------------------------------------------------------------------------
// 内部出力関数定義。
//------------------------------------------------------------------------------

/**
 * @brief 固定keyとASCII値を一行として追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 検証済み固定ASCII値。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendTextLine( AsciiReportBuilder &builder, const std::string_view key,
								  const std::string_view value)
{
	return builder.append( key) && builder.append( "=") && builder.append( value) &&
		   builder.append( "\n") ;
}

/**
 * @brief 固定keyとunsigned値を一行として追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 出力する整数。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendUnsignedLine( AsciiReportBuilder &builder, const std::string_view key,
									  const std::uint64_t value)
{
	return builder.append( key) && builder.append( "=") && builder.appendUnsigned( value) &&
		   builder.append( "\n") ;
}

/**
 * @brief 固定keyとbool値を0／1で一行追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 出力するbool。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendBoolLine( AsciiReportBuilder &builder, const std::string_view key,
								  const bool value)
{
	return appendTextLine( builder, key, value ? "1" : "0") ;
}

/**
 * @brief 固定keyと任意unsigned値を数値またはnullで一行追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 実測値。値なしはnullとして保持する。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendOptionalUnsignedLine( AsciiReportBuilder				&builder,
											  const std::string_view			 key,
											  const std::optional<std::uint64_t> value)
{
	// 未計測値は0へ変換せず、固定nullを出力する。
	if( !value.has_value()) {
		return appendTextLine( builder, key, "null") ;
	}

	return appendUnsignedLine( builder, key, value.value()) ;
}

/**
 * @brief 固定keyと任意32-bit unsigned値を数値またはnullで一行追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 実測値。値なしはnullとして保持する。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendOptionalRevisionLine( AsciiReportBuilder				&builder,
											  const std::string_view			 key,
											  const std::optional<std::uint32_t> value)
{
	// Parser／OS build未公開を0として推測しない。
	if( !value.has_value()) {
		return appendTextLine( builder, key, "null") ;
	}

	return appendUnsignedLine( builder, key, value.value()) ;
}

/**
 * @brief 固定keyと任意bool値を0／1／nullで一行追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 方針値。値なしは未公開を表す。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendOptionalBoolLine( AsciiReportBuilder &builder, const std::string_view key,
										  const std::optional<bool> value)
{
	// Cache方針未公開をfalseへ読み替えない。
	if( !value.has_value()) {
		return appendTextLine( builder, key, "null") ;
	}

	return appendBoolLine( builder, key, value.value()) ;
}

/**
 * @brief 固定keyとNative 32-bit診断を一行追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 出力するbit pattern。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendErrorLine( AsciiReportBuilder &builder, const std::string_view key,
								   const NativeError value)
{
	return builder.append( key) && builder.append( "=0x") && builder.appendError( value) &&
		   builder.append( "\n") ;
}

/**
 * @brief 固定keyとregistry由来wide IDを一行追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] value 検証して出力するstable IDまたはversion。
 * @return 行全体を追加できた場合true。
 */
[[nodiscard]] bool appendIdentifierLine( AsciiReportBuilder &builder, const std::string_view key,
										const std::wstring_view value)
{
	return builder.append( key) && builder.append( "=") && builder.appendIdentifier( value) &&
		   builder.append( "\n") ;
}

/**
 * @brief 件数を確定度と値の不可分な一行として追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] key 固定ASCII key。
 * @param[in] measurement 出力する件数と確定度。
 * @return 既知enumと値の組を一行追加できた場合true。
 */
[[nodiscard]] bool appendCountLine( AsciiReportBuilder &builder, const std::string_view key,
								   const CountMeasurement &measurement)
{
	const std::string_view extent = extentName( measurement.extent) ;	// 固定enum名。
	// 未知enumや確定度とoptional値の矛盾をreportへ出力しない。
	if( extent.empty() || !isCountMeasurementValid( measurement) || !builder.append( key) ||
	   !builder.append( "=") || !builder.append( extent) || !builder.append( ":")) {
		return false ;
	}

	// 値を持つ確定度だけを10進で出力し、未計測はnullのまま残す。
	if( measurement.value.has_value()) {
		// 数値または末尾改行のどちらかが失敗した場合はreport全体を拒否する。
		if( !builder.appendUnsigned( measurement.value.value())) {
			return false ;
		}
	} else {
		// NOT_MEASURED／UNAVAILABLEを0と区別する。
		if( !builder.append( "null")) {
			return false ;
		}
	}

	return builder.append( "\n") ;
}

/**
 * @brief T／Q／R／A／Iの五段階を指定prefixで追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] prefix `network.combined.`または`provider.`等の固定prefix。
 * @param[in] counts 出力する五段階件数。
 * @return 全五行を追加できた場合true。
 */
[[nodiscard]] bool appendStageCounts( AsciiReportBuilder &builder, const std::string_view prefix,
									 const StageDeviceCounts &counts)
{
	std::string key ;	// 固定prefixと一文字suffixから作る一時key。
	key.reserve( prefix.size() + 1U) ;
	// 同じ五段階を決められたT／Q／R／A／I順で出力する。
	const auto appendStage = [&builder, &key, prefix]( const char			  suffix,
													  const CountMeasurement &value) {
		key.assign( prefix) ;
		key.push_back( suffix) ;
		return appendCountLine( builder, key, value) ;
	} ; // 一時keyはlambda呼出し中だけ借用される。
	return appendStage( 'T', counts.eligibleDeviceCount) &&
		   appendStage( 'Q', counts.queryCompletedDeviceCount) &&
		   appendStage( 'R', counts.informationDeviceCount) &&
		   appendStage( 'A', counts.applicableUpdateDeviceCount) &&
		   appendStage( 'I', counts.installReadyUpdateDeviceCount) ;
}

/**
 * @brief 固定理由と単位の有限集計を指定prefixで追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] prefix `inventory.`または`provider.`の固定prefix。
 * @param[in] reasons 出力する一意な理由集計。
 * @return 全entryを固定enum名で追加できた場合true。
 */
[[nodiscard]] bool appendReasons( AsciiReportBuilder &builder, const std::string_view prefix,
								 const std::span<const MeasurementReasonCount> reasons)
{
	std::string key( prefix) ;	// Countとentryで再利用する固定ASCII key。
	key.append( "reason_count") ;
	// 理由総数を先に記録し、entry欠落を後から検出可能にする。
	if( !appendUnsignedLine( builder, key, static_cast<std::uint64_t>( reasons.size()))) {
		return false ;
	}

	key.assign( prefix) ;
	key.append( "reason") ;
	// Registry validatorで一意化された全理由を入力順のまま出力する。
	for( const MeasurementReasonCount &reason : reasons) {
		const std::string_view reasonText = reasonName( reason.reason) ;	// 固定理由名。
		const std::string_view unitText	  = unitName( reason.unit) ;		// 固定単位名。
		// 未知enumを数値化せず、部分的なreason recordも残さない。
		if( reasonText.empty() || unitText.empty() || !builder.append( key) || !builder.append( "=") ||
		   !builder.append( reasonText) || !builder.append( "|") || !builder.append( unitText) ||
		   !builder.append( "|") || !builder.appendUnsigned( reason.count) || !builder.append( "\n")) {
			return false ;
		}
	}

	return true ;
}

/**
 * @brief Providerの登録済みresource根拠を任意文字列なしで追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] resources 同一Providerの検証済みresource集合。
 * @return 全resourceを固定IDと固定enumだけで追加できた場合true。
 */
[[nodiscard]] bool appendResources( AsciiReportBuilder						 &builder,
								   const std::span<const MeasurementResource> resources)
{
	// Resource総数を先に記録し、0件をcache missと推測しない。
	if( !appendUnsignedLine( builder, "provider.resource_count",
						   static_cast<std::uint64_t>( resources.size()))) {
		return false ;
	}

	std::size_t index{} ;	// Registry順resource entryの0-based位置。
	// 各resourceを独立recordとして出力し、URLやorigin列を追加しない。
	for( const MeasurementResource &resource : resources) {
		const std::string_view acquisition =
			// 実取得区分の固定名。
			acquisitionName( resource.acquisition) ;
		// 未知取得区分は公開validatorをすり抜けた場合も出力前に拒否する。
		if( acquisition.empty() || !appendUnsignedLine( builder, "provider.resource.begin", index) ||
		   !appendIdentifierLine( builder, "provider.resource.policy_id", resource.policyId) ||
		   !appendIdentifierLine( builder, "provider.resource.resource_id", resource.resourceId) ||
		   !appendTextLine( builder, "provider.resource.branch",
						   resource.branchId.empty() ? "UNKNOWN" : "NOT_EXPORTED") ||
		   !appendOptionalRevisionLine( builder, "provider.resource.parser_revision",
									   resource.parserRevision) ||
		   !appendOptionalUnsignedLine( builder, "provider.resource.body_acquired_utc_seconds",
									   resource.bodyAcquiredUtcSeconds) ||
		   !appendOptionalUnsignedLine( builder, "provider.resource.origin_validated_utc_seconds",
									   resource.originValidatedUtcSeconds) ||
		   !appendOptionalBoolLine( builder, "provider.resource.cache_permitted",
								   resource.cachePermitted) ||
		   !appendTextLine( builder, "provider.resource.acquisition", acquisition) ||
		   !appendUnsignedLine( builder, "provider.resource.end", index)) {
			return false ;
		}

		++index ;
	}

	return true ;
}

/**
 * @brief Provider measurementの段階、理由、record、resourceを追加する。
 * @param[in,out] builder Report構築先。
 * @param[in] measurement 公開validatorを通過したProvider計測。
 * @return 全fieldを追加できた場合true。
 */
[[nodiscard]] bool appendProviderMeasurement( AsciiReportBuilder		   &builder,
											 const ProviderMeasurement &measurement)
{
	const std::string_view scope = scopeName( measurement.scope) ;	// 個別検索証拠の固定名。
	// 未知scopeを数値化せず、計測record全体を拒否する。
	if( scope.empty()) {
		return false ;
	}

	return appendBoolLine( builder, "provider.measurement_present", true) &&
		   appendTextLine( builder, "provider.scope", scope) &&
		   appendStageCounts( builder, "provider.", measurement.devices) &&
		   appendCountLine( builder, "provider.unmatched_candidate_count",
						   measurement.unmatchedCandidateCount) &&
		   appendCountLine( builder, "provider.information_record_count",
						   measurement.informationRecordCount) &&
		   appendCountLine( builder, "provider.unmatched_information_record_count",
						   measurement.unmatchedInformationRecordCount) &&
		   appendReasons( builder, "provider.", measurement.reasons) &&
		   appendErrorLine( builder, "provider.measurement_diagnostic", measurement.diagnostic) &&
		   appendResources( builder, measurement.resources) ;
}

/**
 * @brief 完全構築済みASCII payloadをstreamへ一回writeしてflushする。
 * @param[in,out] output 呼出し中だけ借用するstream。
 * @param[in] payload 既に容量検査した完全payload。
 * @return 全byteとflushが受理された場合true。
 */
[[nodiscard]] bool writeAsciiPayload( std::ostream &output, const std::string_view payload) noexcept
{
	bool succeeded{} ;	// 一回writeと明示flushの双方が成功した場合だけtrue。
	try {
		// 既に失敗したstreamや出力bufferのないstreamへ再送しない。
		if( !output.good() || output.rdbuf() == nullptr) {
			return false ;
		}

		std::streambuf *const buffer = output.rdbuf() ;						// 呼出し中だけ有効な非所有buffer。
		const auto count = static_cast<std::streamsize>( payload.size()) ;	// 1 MiB以下の長さ。
		succeeded		 = buffer->sputn( payload.data(), count) == count && buffer->pubsync() == 0 ;
	} catch( ...) {
		// I/O例外本文を別経路へ出力せず、下段でstream失敗とfalseへ変換する。
	}

	// 不完全writeまたはflush失敗をstream状態へ反映し、再試行を禁止する。
	if( !succeeded) {
		try {
			output.setstate( std::ios::badbit) ;
		} catch( ...) {
			// Exception maskによるbadbit再送出も公開境界から漏らさない。
			return false ;
		}
	}

	return succeeded ;
}

/**
 * @brief ScanOptionsが固定profileそのものか検証する。
 * @param[in] options Workerへ渡す候補設定。
 * @return 明示9 ID、同意false、file空およびregistry検証が成立する場合true。
 */
[[nodiscard]] bool isBaselineOptions( const ScanOptions &options) noexcept
{
	// 既定自動解決、個別file、inspection同意を初回実測へ混入させない。
	if( options.useDefaultProviders || !options.userSelectedFiles.empty() ||
	   options.prolificInspectionApproved || options.siliconLabsInspectionApproved ||
	   options.wchInspectionApproved || options.wchMultiInspectionApproved ||
	   options.enabledProviderIds.size() != BASELINE_PROVIDER_IDS.size()) {
		return false ;
	}

	// 明示集合の順序と内容を固定profileへ一件ずつ完全一致させる。
	for( std::size_t index = 0; index < BASELINE_PROVIDER_IDS.size(); ++index) {
		// 未知追加、欠落または並べ替えを別の比較条件として受理しない。
		if( options.enabledProviderIds[index] != BASELINE_PROVIDER_IDS[index]) {
			return false ;
		}
	}

	return validateScanOptions( options) ;
}

/**
 * @brief 公開contextの有効IDを固定profileへ順序非依存で一対一に照合する。
 * @param[in] providerIds 呼出し中だけ借用するID集合。元の順序と内容を変更しない。
 * @return 空・未知・重複・欠落・余剰がなく固定9 IDと一致する場合true。
 * @note 実行用ScanOptionsの固定順検証は別に維持し、contextの集合順だけを許容します。
 */
[[nodiscard]] bool matchesBaselineProviderSet(
	const std::span<const std::wstring> providerIds) noexcept
{
	// 件数差を重複排除で隠さず、割当てなしで先に拒否する。
	if( providerIds.size() != BASELINE_PROVIDER_IDS.size()) {
		return false ;
	}

	std::array<bool, BASELINE_PROVIDER_IDS.size()> matched{} ;	// 固定9位置の照合済み状態。
	// 各入力を一度だけ登録位置へ対応させ、入力をsortやdeduplicateしない。
	for( const std::wstring &providerId : providerIds) {
		const auto found = std::find( BASELINE_PROVIDER_IDS.begin(), BASELINE_PROVIDER_IDS.end(),
									 providerId) ;	// 一致した固定profile内の位置。
		// 空ID、未知ID、profile外の既知IDも別の実行対象として受理しない。
		if( found == BASELINE_PROVIDER_IDS.end()) {
			return false ;
		}

		const auto index = static_cast<std::size_t>(
			// 9件以内の照合位置。
			std::distance( BASELINE_PROVIDER_IDS.begin(), found)) ;
		// 同一IDの重複が別の固定IDの欠落を覆い隠すことを禁止する。
		if( matched[index]) {
			return false ;
		}

		matched[index] = true ;
	}

	// 9入力が異なる9位置に対応したため、固定集合の欠落も存在しない。
	return true ;
}

/**
 * @brief Scan resultと固定profileの公開前提をまとめて検証する。
 * @param[in] operationId Controllerが発行したoperation ID。
 * @param[in] applicationVersion 実行中CMake version。
 * @param[in] options Workerへ渡した固定profile。
 * @param[in] result Workerから受け取ったscan結果。
 * @param[out] orderedReports 成功時にregistry順で参照する借用report索引。失敗時は使用しない。
 * @return 全31 reportと公開計測が同じ条件へ拘束される場合true。
 */
[[nodiscard]] bool isExportableResult(
	const OperationId operationId, const std::wstring_view applicationVersion,
	const ScanOptions &options, const ScanResult &result,
	std::array<const ProviderScanReport *, EXPECTED_PROVIDER_COUNT> &orderedReports) noexcept
{
	const std::span descriptors = builtInProviderDescriptors() ;	// 現processのregistry正本。
	// Profile drift、scan失敗、計測欠落、未知の全体終端をreportへ変換しない。
	if( !isBaselineScanRegistryCompatible( descriptors) || !isBaselineOptions( options) ||
	   result.purpose != ScanPurpose::STANDARD || result.metadataSearch || !result.succeeded ||
	   !result.measurement.has_value() ||
	   (result.outcome != OutcomeCode::SUCCESS &&
		result.outcome != OutcomeCode::SUCCEEDED_WITH_ERRORS) ||
	   providerStateName( result.state).empty() || outcomeName( result.outcome).empty() ||
	   !isPublishedScanMeasurementValid( operationId, result) ||
	   result.providerReports.size() != descriptors.size()) {
		return false ;
	}

	const ScanMeasurementContext &measurementContext =
		result.measurement->context ;	// Workerが公開前に拘束した条件。
	// 実行版と明示設定を照合し、有効集合の順序だけを実行条件の差として扱わない。
	if( applicationVersion.empty() || measurementContext.applicationVersion != applicationVersion ||
	   measurementContext.usedDefaultProviders ||
	   !matchesBaselineProviderSet( measurementContext.enabledProviderIds) ||
	   osKindName( measurementContext.osKind).empty()) {
		return false ;
	}

	orderedReports.fill( nullptr) ;
	// 全31 reportをstable IDで照合し、配列順に依存しない借用索引を構築する。
	for( const ProviderScanReport &report : result.providerReports) {
		const auto found = std::find_if( descriptors.begin(), descriptors.end(),
										[&report]( const ProviderDescriptor &value) {
											return value.id == report.descriptor.id ;
										}) ; // 登録済みIDの位置。
		// 未知IDを別のProviderへ割り当てず、索引へ追加する前に拒否する。
		if( found == descriptors.end()) {
			return false ;
		}

		const std::size_t index = static_cast<std::size_t>(
			// 31件以内の登録位置。
			std::distance( descriptors.begin(), found)) ;
		// 同一IDの重複が別の欠落reportを補うことを禁止する。
		if( orderedReports[index] != nullptr) {
			return false ;
		}

		orderedReports[index]				 = &report ;
		const ProviderDescriptor &descriptor = *found ;					// 同じstable IDのregistry正本。
		const bool enabled = isProviderEnabled( options, descriptor) ;	// 固定profile内の状態。
		// Descriptor drift、coverage矛盾、未知enumまたは計測欠落を一件でも許可しない。
		if( !sameDescriptor( report.descriptor, descriptor) ||
		   !isValidProviderCoverage( report.coverage) || providerStateName( report.state).empty() ||
		   outcomeName( report.outcome).empty() || !report.coverage.measurement.has_value()) {
			return false ;
		}

		// 無効22登録は未実行、有効9登録は完了状態でなければならない。
		if( (!enabled && (report.state != ProviderScanState::DISABLED ||
						 report.outcome != OutcomeCode::NOT_STARTED)) ||
		   (enabled && (report.state == ProviderScanState::DISABLED ||
						(report.outcome == OutcomeCode::NOT_STARTED ||
						 report.outcome == OutcomeCode::IN_PROGRESS)))) {
			return false ;
		}
	}

	return true ;
}

} // namespace

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
ScanMeasurementCommand parseScanMeasurementArguments(
	const std::span<const std::wstring_view> arguments) noexcept
{
	// 引数なしは条件表示だけとし、実scanの暗黙開始を禁止する。
	if( arguments.empty()) {
		return ScanMeasurementCommand::DESCRIBE_BASELINE ;
	}

	// 一引数以外は重複optionまたは任意入力として開始前に拒否する。
	if( arguments.size() != 1U) {
		return ScanMeasurementCommand::REJECTED ;
	}

	// 明示した条件表示optionはworkerを構築しない分類へ固定する。
	if( arguments.front() == L"--describe-baseline") {
		return ScanMeasurementCommand::DESCRIBE_BASELINE ;
	}

	// 唯一の実行optionだけを一回scan分類として受理する。
	if( arguments.front() == L"--run-baseline") {
		return ScanMeasurementCommand::RUN_BASELINE ;
	}

	return ScanMeasurementCommand::REJECTED ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
std::span<const std::wstring_view> baselineScanProviderIds() noexcept
{
	return BASELINE_PROVIDER_IDS ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
bool isBaselineScanRegistryCompatible(
	const std::span<const ProviderDescriptor> descriptors) noexcept
{
	try {
		// 現契約の全31登録以外を自動的に初回実測へ採用しない。
		if( descriptors.size() != EXPECTED_PROVIDER_COUNT) {
			return false ;
		}

		std::set<std::wstring_view> ids ;				// Registry内の重複しないstable ID集合。
		std::size_t					defaultIndex{} ;	// 次に一致させる固定既定ID位置。
		bool signedIndexSeen{} ;						// 元の明示9件と別に確認する唯一の既定索引登録。
		// 全descriptorをscan capability、policy境界、既定集合へ照合する。
		for( const ProviderDescriptor &descriptor : descriptors) {
			const bool hasScan =
				(descriptor.capabilities & capabilityMask( ProviderCapability::SCAN)) !=
				0U ;	// 全登録に必要なscan capability。
			const bool official =
				(descriptor.capabilities & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) !=
				0U ;	// 公式network trust boundary。
			// 空・重複ID、scan不能、公式policyの有無がcapabilityと矛盾するregistryを拒否する。
			if( descriptor.id.empty() || !ids.insert( descriptor.id).second || !hasScan ||
			   official != !descriptor.officialSourcePolicyId.empty()) {
				return false ;
			}

			// 新索引は固定能力・由来・既定状態だけを許し、旧明示profileへ暗黙追加しない。
			if( descriptor.id == SIGNED_INDEX_PROVIDER_ID) {
				const auto expectedCapabilities =
					capabilityMask( ProviderCapability::SCAN) |
					capabilityMask( ProviderCapability::DOWNLOAD) |
					capabilityMask( ProviderCapability::INSTALL) |
					capabilityMask(
						ProviderCapability::SIGNED_INDEX_ACQUISITION) ;	// 索引専用の四能力。
				// Metadata専用能力や公式networkへの偽装を、同じ測定profileへ受理しない。
				if( !descriptor.enabledByDefault ||
				   descriptor.capabilities != expectedCapabilities ||
				   descriptor.discoveryBasis !=
					   CandidateDiscoveryBasis::SIGNED_INDEX_COLLECTOR_ATTESTATION ||
				   descriptor.selectionTier != ProviderSelectionTier::COMPONENT_OFFICIAL ||
				   descriptor.installNotice != InstallNoticeKind::NONE) {
					return false ;
				}

				signedIndexSeen = true ;
				continue ;
			}

			// 索引以外の既定有効登録を元の固定9 IDへregistry順で一致させる。
			if( descriptor.enabledByDefault) {
				// 追加既定Providerまたは固定IDとの差を暗黙採用しない。
				if( defaultIndex >= BASELINE_PROVIDER_IDS.size() ||
				   descriptor.id != BASELINE_PROVIDER_IDS[defaultIndex]) {
					return false ;
				}

				++defaultIndex ;
			}
		}

		// 明示9件と唯一の既定索引が過不足なく一致した場合だけ受理する。
		if( defaultIndex != BASELINE_PROVIDER_IDS.size() || !signedIndexSeen) {
			return false ;
		}

		const ProviderDescriptor &managed = descriptors[0] ;	// 固定順のWUA descriptor。
		const ProviderDescriptor &local	  = descriptors[1] ;	// 固定順のDriver Store descriptor。
		// 最初の二登録が管理serviceとlocal inventoryの信頼境界を維持することを確認する。
		if( managed.id != WINDOWS_UPDATE_PROVIDER_ID ||
		   (managed.capabilities & capabilityMask( ProviderCapability::MANAGED_SERVICE)) == 0U ||
		   local.id != DRIVER_STORE_PROVIDER_ID ||
		   (local.capabilities & capabilityMask( ProviderCapability::LOCAL_INVENTORY)) == 0U) {
			return false ;
		}

		// 固定集合の残り7登録は公式network capabilityを維持する必要がある。
		for( std::size_t index = 2U; index < BASELINE_PROVIDER_IDS.size(); ++index) {
			const auto descriptor = std::find_if(
				descriptors.begin(), descriptors.end(), [index]( const ProviderDescriptor &value) {
					return value.id == BASELINE_PROVIDER_IDS[index] ;
				}) ; // 固定IDへ完全一致したregistry行。
			// 欠落または公式networkでない変更を同じprofile revisionとして受理しない。
			if( descriptor == descriptors.end() ||
			   (descriptor->capabilities & capabilityMask( ProviderCapability::OFFICIAL_NETWORK)) ==
				   0U) {
				return false ;
			}
		}
	} catch( ...) {
		// 検証索引のallocation失敗時はprofileを開始せずfail-closedにする。
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
bool resolveBaselineScanOptions( ScanOptions &options) noexcept
{
	try {
		const std::span descriptors = builtInProviderDescriptors() ;	// 検証済み組み込みregistry。
		// Registry driftを検出した場合はScanOptions自体を公開しない。
		if( !isBaselineScanRegistryCompatible( descriptors)) {
			return false ;
		}

		ScanOptions resolved ;	// 全検証後だけ出力へ移す固定profile設定。
		resolved.useDefaultProviders = false ;
		resolved.enabledProviderIds.reserve( BASELINE_PROVIDER_IDS.size()) ;
		// 固定9 IDを再解決や表示名推測なしで明示集合へcopyする。
		for( const std::wstring_view providerId : BASELINE_PROVIDER_IDS) {
			resolved.enabledProviderIds.emplace_back( providerId) ;
		}

		// 既存registry validatorと有効状態を通らない設定をworkerへ渡さない。
		if( !isBaselineOptions( resolved)) {
			return false ;
		}

		// 全31登録の解決結果が明示9／無効22と一致することを最終確認する。
		for( const ProviderDescriptor &descriptor : descriptors) {
			const bool expected =
				std::find( BASELINE_PROVIDER_IDS.begin(), BASELINE_PROVIDER_IDS.end(),
						  descriptor.id) != BASELINE_PROVIDER_IDS.end() ;	// 固定集合内の有無。
			// Registry helperの解決結果に差がある場合は部分設定を返さない。
			if( isProviderEnabled( resolved, descriptor) != expected) {
				return false ;
			}
		}

		options = std::move( resolved) ;
	} catch( ...) {
		// Allocation失敗で既存出力設定を変更せず、scan開始前に拒否する。
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
bool buildBaselineScanDescription( std::string &description) noexcept
{
	try {
		ScanOptions options ;	// Registryとの一致を確認する固定profile設定。
		// 条件表示もregistry drift時は成功扱いにせず、再審査を要求する。
		if( !resolveBaselineScanOptions( options)) {
			return false ;
		}

		AsciiReportBuilder builder( SCAN_MEASUREMENT_REPORT_MAXIMUM_BYTES) ;	// 完全条件表示。
		// 固定profile、既存cache／観測副作用、禁止operationを明示する。
		if( !appendTextLine( builder, "record", "drivercrate_scan_measurement_baseline") ||
		   !appendTextLine( builder, "profile_id", SCAN_MEASUREMENT_PROFILE_ID) ||
		   !appendUnsignedLine( builder, "profile_revision", SCAN_MEASUREMENT_PROFILE_REVISION) ||
		   !appendUnsignedLine( builder, "report_revision", SCAN_MEASUREMENT_REPORT_REVISION) ||
		   !appendUnsignedLine( builder, "measurement_contract_revision", 1U) ||
		   !appendTextLine( builder, "mode", "describe_only") ||
		   !appendTextLine( builder, "run_option", "--run-baseline") ||
		   !appendBoolLine( builder, "use_default_providers", options.useDefaultProviders) ||
		   !appendUnsignedLine( builder, "explicit_provider_count",
							   static_cast<std::uint64_t>( options.enabledProviderIds.size())) ||
		   !appendTextLine( builder, "catalog_cache", "normal_provider_cache_enabled") ||
		   !appendTextLine( builder, "release_observation_store",
						   "existing_protected_store_may_update") ||
		   !appendTextLine( builder, "driver_install", "not_requested") ||
		   !appendTextLine( builder, "pnp_change", "not_requested") ||
		   !appendTextLine( builder, "restore_point", "not_requested") ||
		   !appendTextLine( builder, "preparation", "not_requested")) {
			return false ;
		}

		// 明示9 IDを固定順で表示し、残り22が自動実行されない条件を確認可能にする。
		for( const std::wstring &providerId : options.enabledProviderIds) {
			// Registry由来IDだけを一行ずつ出力する。
			if( !appendIdentifierLine( builder, "explicit_provider_id", providerId)) {
				return false ;
			}
		}

		description = builder.release() ;
	} catch( ...) {
		// 完全条件表示を構築できない場合は呼出し側の既存文字列を変更しない。
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
bool writeBaselineScanDescription( std::ostream &output) noexcept
{
	std::string description ;	// 一回write前に完全構築する条件表示。
	// Profile構築失敗ではstreamへ一byteも書き込まない。
	if( !buildBaselineScanDescription( description)) {
		return false ;
	}

	return writeAsciiPayload( output, description) ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
bool buildScanMeasurementReport( const OperationId		operationId,
								const std::wstring_view applicationVersion,
								const ScanOptions &options, const ScanResult &result,
								std::string &report) noexcept
{
	try {
		std::array<const ProviderScanReport *, EXPECTED_PROVIDER_COUNT>
			orderedReports{} ;	// 全31件の借用索引。
		// Snapshotと固定profileを全て検証してからreport bufferを構築する。
		if( !isExportableResult( operationId, applicationVersion, options, result, orderedReports)) {
			return false ;
		}

		const ScanMeasurement &measurement = result.measurement.value() ;	// 検証済み全体計測。
		const ScanMeasurementContext &measurementContext =
			measurement.context ;														// 同じoperationの実行条件。
		const std::string_view osKind	   = osKindName( measurementContext.osKind) ;	// 固定OS名。
		const std::string_view scanState   = providerStateName( result.state) ;			// 全体scan状態。
		const std::string_view scanOutcome = outcomeName( result.outcome) ;				// 全体終了区分。
		AsciiReportBuilder	   builder( SCAN_MEASUREMENT_REPORT_MAXIMUM_BYTES) ;		// 完全report。

		// Schema、profile、operation、OS、時刻を同じ固定headerへ記録する。
		if( !appendTextLine( builder, "record", "drivercrate_scan_measurement_report") ||
		   !appendUnsignedLine( builder, "report_revision", SCAN_MEASUREMENT_REPORT_REVISION) ||
		   !appendTextLine( builder, "profile_id", SCAN_MEASUREMENT_PROFILE_ID) ||
		   !appendUnsignedLine( builder, "profile_revision", SCAN_MEASUREMENT_PROFILE_REVISION) ||
		   !appendUnsignedLine( builder, "measurement_contract_revision",
							   measurementContext.contractRevision) ||
		   !appendUnsignedLine( builder, "operation_id", operationId) ||
		   !appendUnsignedLine( builder, "scan_session_id", result.scanSessionId) ||
		   !appendIdentifierLine( builder, "application_version", applicationVersion) ||
		   !appendTextLine( builder, "architecture", "x64") ||
		   !appendTextLine( builder, "os_kind", osKind) ||
		   !appendOptionalRevisionLine( builder, "os_build", measurementContext.osBuild) ||
		   !appendOptionalUnsignedLine( builder, "started_utc_seconds",
									   measurementContext.startedUtcSeconds) ||
		   !appendOptionalUnsignedLine( builder, "completed_utc_seconds",
									   measurementContext.completedUtcSeconds) ||
		   !appendBoolLine( builder, "used_default_providers",
						   measurementContext.usedDefaultProviders) ||
		   !appendTextLine( builder, "scan_state", scanState) ||
		   !appendTextLine( builder, "scan_outcome", scanOutcome) ||
		   !appendErrorLine( builder, "scan_error", result.error) ||
		   !appendUnsignedLine(
			   builder, "enabled_provider_count",
			   static_cast<std::uint64_t>( measurementContext.enabledProviderIds.size()))) {
			return false ;
		}

		// Workerの有効集合と一対一に一致した固定profileをregistry順で出力する。
		for( const std::wstring &providerId : options.enabledProviderIds) {
			// 任意表示名やProvider由来文字列を追加せず、IDだけを出力する。
			if( !appendIdentifierLine( builder, "enabled_provider_id", providerId)) {
				return false ;
			}
		}

		const DeviceInventoryMeasurement &inventory = measurement.inventory ;	// Local母数の根拠。
		// Inventoryの六件数、完了状態、理由と元errorを分離して記録する。
		if( !appendCountLine( builder, "inventory.enumerated_device_count",
							inventory.enumeratedDeviceCount) ||
		   !appendCountLine( builder, "inventory.represented_device_count",
							inventory.representedDeviceCount) ||
		   !appendCountLine( builder, "inventory.unrepresented_device_count",
							inventory.unrepresentedDeviceCount) ||
		   !appendCountLine( builder, "inventory.missing_manufacturer_count",
							inventory.missingManufacturerCount) ||
		   !appendCountLine( builder, "inventory.missing_class_count",
							inventory.missingClassCount) ||
		   !appendCountLine( builder, "inventory.missing_current_version_count",
							inventory.missingCurrentVersionCount) ||
		   !appendBoolLine( builder, "inventory.detailed_enumeration_complete",
						   inventory.detailedEnumerationComplete) ||
		   !appendReasons( builder, "inventory.", inventory.reasons) ||
		   !appendErrorLine( builder, "inventory.error", inventory.error)) {
			return false ;
		}

		// Managed、公式、両者和集合をdevice単位の五段階で個別に記録する。
		if( !appendStageCounts( builder, "network.combined.", measurement.network.combined) ||
		   !appendStageCounts( builder, "network.managed.", measurement.network.managed) ||
		   !appendStageCounts( builder, "network.official.", measurement.network.official) ||
		   !appendCountLine( builder, "network.unmatched_candidate_count",
							measurement.unmatchedCandidateCount) ||
		   !appendUnsignedLine( builder, "provider_count",
							   static_cast<std::uint64_t>( result.providerReports.size()))) {
			return false ;
		}

		std::size_t index{} ;	// Registry順Provider reportの0-based位置。
		// 全31 reportを無効状態も含めて固定順で出力する。
		for( const ProviderScanReport *const orderedReport : orderedReports) {
			const ProviderScanReport &providerReport =
				*orderedReport ;	// 全31既知IDの一対一照合済みreport。
			const bool enabled =
				// 実行状態。
				isProviderEnabled( options, providerReport.descriptor) ;
			const std::string_view state = providerStateName( providerReport.state) ;	// 固定状態名。
			const std::string_view outcome = outcomeName( providerReport.outcome) ;		// 固定終了名。
			// Legacy値と新計測を同一record内で区別し、表示名を出力しない。
			if( !appendUnsignedLine( builder, "provider.begin", index) ||
			   !appendIdentifierLine( builder, "provider.id", providerReport.descriptor.id) ||
			   !appendBoolLine( builder, "provider.enabled", enabled) ||
			   !appendTextLine( builder, "provider.state", state) ||
			   !appendTextLine( builder, "provider.outcome", outcome) ||
			   !appendErrorLine( builder, "provider.error", providerReport.error) ||
			   !appendUnsignedLine( builder, "provider.legacy_eligible_device_count",
								   providerReport.coverage.eligibleDeviceCount) ||
			   !appendUnsignedLine( builder, "provider.legacy_assessed_device_count",
								   providerReport.coverage.assessedDeviceCount) ||
			   !appendUnsignedLine( builder, "provider.candidate_count",
								   providerReport.candidateCount) ||
			   !appendProviderMeasurement( builder, providerReport.coverage.measurement.value()) ||
			   !appendUnsignedLine( builder, "provider.end", index)) {
				return false ;
			}

			++index ;
		}

		// 完全なrecordだけを終端marker付きで呼出し側へ移す。
		if( !appendTextLine( builder, "report_end", "1")) {
			return false ;
		}

		report = builder.release() ;
	} catch( ...) {
		// Allocationまたは変換失敗では呼出し側の既存reportを変更しない。
		return false ;
	}

	return true ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
ScanMeasurementReportStatus writeScanMeasurementReport( std::ostream			  &output,
													   const OperationId	   operationId,
													   const std::wstring_view applicationVersion,
													   const ScanOptions	  &options,
													   const ScanResult		  &result) noexcept
{
	std::string report ;	// 一回write前に1 MiB以下で完全構築するreport。
	// 契約違反または容量超過ではstreamへ一byteも書き込まない。
	if( !buildScanMeasurementReport( operationId, applicationVersion, options, result, report)) {
		return ScanMeasurementReportStatus::CONTRACT_REJECTED ;
	}

	// 一回writeまたはflushの失敗を有効なscan reportへ数えない。
	if( !writeAsciiPayload( output, report)) {
		return ScanMeasurementReportStatus::OUTPUT_FAILED ;
	}

	return result.outcome == OutcomeCode::SUCCESS ? ScanMeasurementReportStatus::SUCCESS
												  : ScanMeasurementReportStatus::PARTIAL_SUCCESS ;
}

//------------------------------------------------------------------------------
/** @see tests/support/scan_measurement_diagnostics.h 宣言側の契約を正本とする。 */
//------------------------------------------------------------------------------
bool writeScanMeasurementFailure( std::ostream					   &output,
								 const ScanMeasurementFailureReason reason) noexcept
{
	try {
		const std::string_view name = failureReasonName( reason) ;	// 固定enumからだけ得る理由名。
		// 未知enumは一byteも出力せずに拒否する。
		if( name.empty()) {
			return false ;
		}

		AsciiReportBuilder builder(
			SCAN_MEASUREMENT_FAILURE_MAXIMUM_BYTES) ;	// 最大1 KiBの完全record。
		// Snapshot由来のfieldを加えず、固定schemaの三行だけを構築する。
		if( !appendTextLine( builder, "record", "drivercrate_scan_measurement_failure") ||
		   !appendUnsignedLine( builder, "failure_revision", 1U) ||
		   !appendTextLine( builder, "failure_reason", name)) {
			return false ;
		}

		const std::string payload = builder.release() ;	// 一回write中に所有する完全ASCII。
		return writeAsciiPayload( output, payload) ;
	} catch( ...) {
		// 構築失敗は理由を推測して再出力せず、呼出し側へ失敗を返す。
		return false ;
	}
}

} // namespace drivercrate::test
