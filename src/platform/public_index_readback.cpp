//------------------------------------------------------------------------------
/**
 * @file public_index_readback.cpp
 * @brief 固定公開索引の原byte匿名照合を既存HTTPとnative codecへ接続します。
 * @version 01.01.00
 * @date 2026/10/20
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
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/10/20  保存を伴わない三resource匿名確認を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/27  Daily/candidateの正規二file名を共通検査。
 * </pre>
 * @note 全取得byteと期限付きCDN URLはRAMだけに保持し、永続storeを開きません。
 * @see docs/adr/0385-public-anonymous-index-readback.md
 */
//------------------------------------------------------------------------------
#include "platform/public_index_readback.h"
#include "platform/index_distribution_trust.h"
#include "platform/official_file_verifier.h"
#include "platform/signed_index_asset_bytes.h"
#include "platform/signed_index_records.h"
#include <algorithm>
#include <array>
#include <charconv>
#include <cstdio>
#include <stdexcept>
#include <system_error>
#include <utility>
#include <vector>

namespace drivercrate {
namespace {
// 親の現取得経路に一致する圧縮原byteの狭い上限です。
constexpr std::size_t	  MAXIMUM_GZIP_BYTES = 16U * 1024U * 1024U ;
/** @brief 元診断がない純粋拒否へ固定の非0 HRESULTを割当てます。
 * @param[in] error 元codecまたはHTTP診断です。
 * @return 元値またはERROR_INVALID_DATAです。
 */
[[nodiscard]] NativeError nonzero( const NativeError error) noexcept
{
	return error != 0U ? error : static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_DATA)) ;
}
/** @brief 原byteを文字変換せず共通hash/codecへ借用します。
 * @param[in] raw HTTPが所有する有限原byteです。
 * @return 呼出し元vectorの寿命までのviewです。
 */
[[nodiscard]] std::string_view bytesView( const std::vector<std::byte> &raw) noexcept
{
	return {reinterpret_cast<const char *>( raw.data()),
			// 原byteの非所有codec境界です。
			raw.size()} ;
}
/** @brief unsigned数値を最短十進で追加します。
 * @param[in,out] out 固定fieldだけの所有writerです。
 * @param[in] value 狭めない元値です。
 */
void number( std::string &out, const std::uint64_t value)
{
	std::array<char, 20U> buffer{} ;	// uint64最大値の十進容量です。
	const auto			  converted =
		// locale非依存です。
		std::to_chars( buffer.data(), buffer.data() + buffer.size(), value) ;
	// 容量障害を部分数値へ読み替えません。
	if( converted.ec != std::errc{}) {
		throw std::runtime_error( "readback number rejected") ;
	}

	out.append( buffer.data(), converted.ptr) ;
}
/** @brief 現在UTCだけを閉20byte文字列またはnullへ表します。
 * @param[in] value 同実行が観測したUTCです。
 * @return 引用符を含む固定ASCIIまたはnullです。
 */
[[nodiscard]] std::string timestamp( const std::optional<std::chrono::sys_seconds> value)
{
	// 時計不明を現在や公開時刻で補完しません。
	if( !value) {
		return "null" ;
	}

	const auto day = std::chrono::floor<std::chrono::days>( *value) ;	// UTC暦日です。
	const std::chrono::year_month_day date{day} ;						// 実在日をchronoから得ます。
	const std::chrono::hh_mm_ss		  time{*value - day} ;				// 秒精度の当日内時刻です。
	// 閉wireに入らない年を外部文字列へ変換しません。
	if( !date.ok() || int( date.year()) < 1970 || int( date.year()) > 9999) {
		throw std::runtime_error( "readback time rejected") ;
	}

	std::array<char, 23U> buffer{} ;	// 引用符二つ、UTC20byte、NULです。
	const int			  written = std::snprintf(
		buffer.data(), buffer.size(), "\"%04d-%02u-%02uT%02lld:%02lld:%02lldZ\"", int( date.year()),
		unsigned( date.month()), unsigned( date.day()), static_cast<long long>( time.hours().count()),
		static_cast<long long>( time.minutes().count()),
		// 外部textを含みません。
		static_cast<long long>( time.seconds().count())) ;
	// 切断や予期しない桁数ではreportを発行しません。
	if( written != 22) {
		throw std::runtime_error( "readback time rejected") ;
	}

	return {buffer.data(), 22U} ;
}
}

/** @see publicIndexReadbackArguments宣言側の契約を正本とします。 */
bool publicIndexReadbackArguments( const int count, wchar_t *const args[],
								  std::uint32_t &milliseconds) noexcept
{
	// 余剰URL、別mode、欠損はfile読取より先に拒否します。
	if( count != 5 || args == nullptr || args[1] == nullptr || args[2] == nullptr ||
	   args[3] == nullptr || args[4] == nullptr ||
	   std::wstring_view( args[1]) != L"--public-index-readback" ||
	   std::wstring_view( args[2]).empty() || std::wstring_view( args[3]).empty()) {
		return false ;
	}

	const std::wstring_view text{args[4]} ;	// 十進だけの非所有入力です。
	std::uint32_t			parsed{} ;		// 全文字成功までcallerを更新しません。
	// 空、符号、長すぎる表現を数値へ補正しません。
	if( text.empty() || text.size() > 5U) {
		return false ;
	}

	// ASCII数字だけを有限五文字まで走査します。
	for( const auto character : text) {
		// 空白と全角数字を許可しません。
		if( character < L'0' || character > L'9') {
			return false ;
		}

		parsed = parsed * 10U + static_cast<std::uint32_t>( character - L'0') ;
	}

	// 無限相当0と通常90秒を超す指定を拒否します。
	if( parsed == 0U || parsed > 90000U) {
		return false ;
	}

	milliseconds = parsed ;
	return true ;
}

/** @see publicIndexReadbackArtifactPair宣言側の契約を正本とします。 */
bool publicIndexReadbackArtifactPair( const std::filesystem::path &envelopePath,
									 const std::filesystem::path &gzipPath) noexcept
{
	try {
		// 別parentの入力を同じ保護jobのpairへ結び付けません。
		if( envelopePath.parent_path() != gzipPath.parent_path()) {
			return false ;
		}

		const auto name		= envelopePath.filename().native() ;	// 有限の原leaf名を所有します。
		const auto gzipName = gzipPath.filename().native() ;		// Directoryを補正せず比較します。
		constexpr std::wstring_view DAILY_SUFFIX =
			L".acquisition.manifest.json" ;	// 既存日次callerです。
		// 旧来の8桁dayと完全suffixだけを同じstemのgzipへ結びます。
		if( name.size() == 8U + DAILY_SUFFIX.size() && name.ends_with( DAILY_SUFFIX) &&
		   std::all_of( name.begin(), name.begin() + 8U,
					   []( const wchar_t c) { return c >= L'0' && c <= L'9' ; })) {
			return gzipName == name.substr( 0U, 8U) + L".acquisition.index.json.gz" ;
		}

		constexpr std::wstring_view PREFIX =
			L"candidate-publication-" ;								// 既存formatterの固定prefixです。
		constexpr std::wstring_view SUFFIX = L".manifest.json" ;	// Candidateだけの固定suffixです。
		constexpr std::uint64_t		MAXIMUM_GENERATION =
			9007199254740991ULL ;	// Publisherの既存上限です。
		// 未知prefix・桁違い・余剰文字を任意filenameへ緩和しません。
		if( name.size() != PREFIX.size() + 16U + SUFFIX.size() || !name.starts_with( PREFIX) ||
		   !name.ends_with( SUFFIX)) {
			return false ;
		}

		std::uint64_t generation{} ;	// 全16文字と上限の確認前には使用しません。
		// 既存formatterのASCII十進16桁だけを上限内で復元します。
		for( const auto digit : std::wstring_view{name}.substr( PREFIX.size(), 16U)) {
			// 非ASCII数字と上限超過は部分値やoverflowへ変換せず拒否します。
			if( digit < L'0' || digit > L'9' ||
			   generation > (MAXIMUM_GENERATION - static_cast<std::uint64_t>( digit - L'0')) / 10U) {
				return false ;
			}

			generation = generation * 10U + static_cast<std::uint64_t>( digit - L'0') ;
		}

		return generation > 0U &&
			   gzipName == name.substr( 0U, PREFIX.size() + 16U) + L".index.json.gz" ;
	} catch( ...) {
		// Path処理の確保等に失敗しても保護読取と通信を開始しません。
		return false ;
	}
}

/** @see Access宣言側の契約を正本とします。 */
PublicIndexReadbackReport public_index_readback_detail::Access::execute(
	OfficialHttpClient &client, const Services &services, const std::string_view envelope,
	const std::string_view gzip, const std::uint32_t milliseconds,
	const HttpCancellationCallback &cancellation) noexcept
{
	PublicIndexReadbackReport result ;								// 部分取得を保持する唯一のreportです。
	SignedIndexHttpControl	  control ;								// 三resource全体で一回だけ固定します。
	std::optional<std::chrono::steady_clock::time_point> started ;	// 不明を0へ補完しません。
	std::optional<std::chrono::sys_seconds>				 lastUtc ;	// UTC後退を拒否する高水位です。
	std::optional<std::chrono::sys_seconds> expires ;				// 全codec後の終了UTCにも同期限を適用します。
	std::optional<std::size_t> activeResource ;						// 例外でも部分取得の実差分を保持します。
	std::uint32_t			   resourceSendsBefore{} ;				// 同resource開始直前の実送信数です。
	std::uint64_t			   resourceBytesBefore{} ;				// 同resource開始直前のprobe込み受信量です。
	try {
		// 製品または完全fixtureの依存を満たすまで通信しません。
		if( !services.utcNow || !services.monotonicNow || services.trust.empty() ||
		   milliseconds == 0U || milliseconds > 90000U || envelope.empty() ||
		   envelope.size() > INDEX_ENVELOPE_MAX_BYTES || gzip.empty() ||
		   gzip.size() > MAXIMUM_GZIP_BYTES ||
		   services.operationStarted.has_value() != services.operationStartedAtUtc.has_value()) {
			return result ;
		}

		result.nativeError	= 0U ;
		result.failureStage = PublicIndexFailureStage::TIME ;
		started =
			services.operationStarted
				? services.operationStarted
				: std::optional<std::chrono::steady_clock::time_point>{services.monotonicNow()} ;
		control.monotonicNow = services.monotonicNow ;
		control.cancellation = cancellation ;
		control.deadline	 = *started + std::chrono::milliseconds{milliseconds} ;
		control.sendLimit_	 = 9U ;
		const auto now		 = [&]() {
			  const auto observed = services.utcNow() ;	// 各境界で取得する現在UTCです。
			  // 不明や後退を署名時刻へ差替えません。
			  if( !observed || (lastUtc && *observed < *lastUtc)) {
				  result.failureStage = PublicIndexFailureStage::TIME ;
				  result.nativeError  = HRESULT_FROM_WIN32( ERROR_INVALID_TIME) ;
				  return std::optional<std::chrono::sys_seconds>{} ;
			  }

			  lastUtc = observed ;
			  return observed ;
		} ; // 同実行内のUTCだけを確認します。
		const auto finish = [&]() {
			result.sends		  = control.sends ;
			result.receivedBytes  = control.receivedBytes ;
			result.completedAtUtc = services.utcNow() ;
			const auto ended	  = services.monotonicNow() ;	// 開始と同じ時計です。
			// 単調時計後退は成功にもelapsed0にも補完しません。
			if( ended >= *started) {
				result.elapsedMilliseconds = static_cast<std::uint64_t>(
					std::chrono::duration_cast<std::chrono::milliseconds>( ended - *started)
						.count()) ;
			}

			// 最後の時刻と同じ固定deadlineでも成功を再確認します。
			if( !result.completedAtUtc || (lastUtc && *result.completedAtUtc < *lastUtc) ||
			   (expires && *result.completedAtUtc >= *expires) || !result.elapsedMilliseconds ||
			   control.checkpoint() != 0U) {
				result.verified = false ;
				result.nativeError =
					nonzero( control.stopped != 0U
								? control.stopped
								: static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_INVALID_TIME))) ;
				result.failureStage =
					control.stopped == static_cast<NativeError>( HRESULT_FROM_WIN32( ERROR_CANCELLED))
						? PublicIndexFailureStage::CANCELLED
						: PublicIndexFailureStage::TIME ;
			}

			return result ;
		} ; // 各return直前の共有停止と時計確認です。
		result.startedAtUtc =
			services.operationStartedAtUtc ? services.operationStartedAtUtc : now() ;
		lastUtc = result.startedAtUtc ;
		// UTC欠損と送信前停止ではresourceを開始しません。
		if( !result.startedAtUtc || control.checkpoint() != 0U) {
			return finish() ;
		}

		result.failureStage = PublicIndexFailureStage::TRUST ;
		auto expected		= signed_index_detail::authenticateWithTrustKeys(
			  envelope, now(), std::nullopt,
			  services.trust) ;	// 自己申告trustを読みません。
		// 未認証tagと16MiBを超すassetではURLを導出しません。
		if( !expected.manifest || expected.manifest->data().asset.sizeBytes != gzip.size()) {
			result.nativeError = nonzero( expected.error) ;
			return finish() ;
		}

		expires = expected.manifest->data().expiresAtUtc ;
		std::vector<std::byte> raw ;	// 各resource終了時にだけ再利用するRAMです。
		// 三roleを固定順に取得し、最初の失敗で後続を未着手のまま残します。
		for( std::size_t index = 0U; index < result.resources.size(); ++index) {
			activeResource		   = index ;
			resourceSendsBefore	   = control.sends ;
			resourceBytesBefore	   = control.receivedBytes ;
			auto	  &resource	   = result.resources[index] ;	// 同じreport内の一観測です。
			const auto sendsBefore = control.sends ;			// resource差分の開始値です。
			const auto bytesBefore = control.receivedBytes ;	// probe込みの差分起点です。
			result.failureStage	   = index == 0U
										 ? PublicIndexFailureStage::CURRENT
										 : (index == 1U ? PublicIndexFailureStage::MANIFEST_ASSET
														: PublicIndexFailureStage::GZIP_ASSET) ;
			const auto error =
				index == 0U
					? client.getSignedIndexCurrent( control, raw, resource.httpStatus)
					: (index == 1U ? client.getSignedIndexManifestAsset( *expected.manifest, control,
																		raw, resource.httpStatus)
								   : client.getSignedIndexAsset(
										 *expected.manifest, control, raw,
										 resource.httpStatus)) ;	// 私有typed roleだけです。
			resource.sends		   = control.sends - sendsBefore ;
			resource.receivedBytes = control.receivedBytes - bytesBefore ;
			const auto wanted	   = index == 2U ? gzip : envelope ;	// 原二fileのbyteだけです。
			// HTTP成功だけや等価JSONでは原byte一致へ昇格しません。
			if( error != 0U || bytesView( raw) != wanted) {
				resource.state		 = PublicIndexResourceState::FAILED ;
				resource.nativeError = nonzero( error) ;
				result.nativeError	 = resource.nativeError ;
				return finish() ;
			}

			std::wstring digest ;	// 共通CNGが出力するASCII hexです。
			const auto	 hashError =
				// hash実装を複製しません。
				computeDriverContainerSha256( bytesView( raw), digest) ;
			// Hash障害を一致済み成功として発行しません。
			if( hashError != 0U) {
				resource.state		 = PublicIndexResourceState::FAILED ;
				resource.nativeError = nonzero( hashError) ;
				result.nativeError	 = resource.nativeError ;
				return finish() ;
			}

			std::string asciiDigest ;	// 共通hashの保証する小文字ASCIIだけを明示変換します。
			asciiDigest.reserve( digest.size()) ;
			// 全digest文字を狭める前に、共通契約のASCII範囲を確認します。
			for( const auto character : digest) {
				// 不正なhash表現をreportへ流しません。
				if( character > 0x7f) {
					result.nativeError	 = E_UNEXPECTED ;
					resource.state		 = PublicIndexResourceState::FAILED ;
					resource.nativeError = result.nativeError ;
					return finish() ;
				}

				asciiDigest.push_back( static_cast<char>( character)) ;
			}

			resource.sha256		  = std::move( asciiDigest) ;
			resource.state		  = PublicIndexResourceState::COMPLETE ;
			const auto currentUtc = now() ;	// HTTP待機後の現在時刻です。
			// 処理中期限、UTC後退、取消しを次resourceより先に拒否します。
			if( !currentUtc || *currentUtc >= expected.manifest->data().expiresAtUtc ||
			   control.checkpoint() != 0U) {
				result.nativeError	= nonzero( control.stopped) ;
				result.failureStage = PublicIndexFailureStage::TIME ;
				return finish() ;
			}

			// Currentと固定manifestを同じ署名codecへ通します。
			if( index != 2U) {
				const auto authenticated = signed_index_detail::authenticateWithTrustKeys(
					bytesView( raw), currentUtc, std::nullopt,
					services.trust) ;	// 同compiledまたはfixture trustです。
				// Byte一致後でも暗号検査を省略しません。
				if( !authenticated.manifest) {
					result.nativeError	= nonzero( authenticated.error) ;
					result.failureStage = PublicIndexFailureStage::TRUST ;
					return finish() ;
				}
			}
		}

		result.failureStage = PublicIndexFailureStage::CONTENT ;
		const auto asset	= authenticateIndexAssetBytes( *expected.manifest, raw,
														  // 原gzip/hash/展開検査です。
														  now()) ;
		// 元codecの拒否をHTTP200で上書きしません。
		if( !asset.receipt) {
			result.nativeError = nonzero( asset.error) ;
			return finish() ;
		}

		const auto records =
			// 原recordsの同codecです。
			readSignedIndexRecords( *asset.receipt, now()) ;
		// 未評価recordや壊れたschemaを確認成功へ変換しません。
		if( !records.receipt) {
			result.nativeError = nonzero( records.error) ;
			return finish() ;
		}

		const auto finalUtc = now() ;	// 全codec後に同じ期限を再確認します。
		// 最終期限ちょうどでも成功させません。
		if( !finalUtc || *finalUtc >= expected.manifest->data().expiresAtUtc) {
			result.nativeError	= HRESULT_FROM_WIN32( ERROR_INVALID_TIME) ;
			result.failureStage = PublicIndexFailureStage::TIME ;
			return finish() ;
		}

		result.verified		= true ;
		result.nativeError	= 0U ;
		result.failureStage = PublicIndexFailureStage::NONE ;
		return finish() ;
	} catch( ...) {
		result.verified		 = false ;
		result.nativeError	 = nonzero( result.nativeError) ;
		result.sends		 = control.sends ;
		result.receivedBytes = control.receivedBytes ;
		// 実送信後の例外でも未着手や合計0へ差し替えません。
		if( activeResource &&
		   result.resources[*activeResource].state != PublicIndexResourceState::COMPLETE) {
			auto &resource		   = result.resources[*activeResource] ;	// 例外を受けた一roleです。
			resource.state		   = PublicIndexResourceState::FAILED ;
			resource.sends		   = control.sends - resourceSendsBefore ;
			resource.receivedBytes = control.receivedBytes - resourceBytesBefore ;
			resource.nativeError   = result.nativeError ;
			resource.sha256.reset() ;
		}

		// 最終時計例外で成功用NONEを残しません。
		if( result.failureStage == PublicIndexFailureStage::NONE) {
			result.failureStage = PublicIndexFailureStage::TIME ;
		}

		try {
			result.completedAtUtc = services.utcNow() ;
			const auto ended	  = services.monotonicNow() ;	// 例外前と同じ時計で観測します。
			// 不明な開始と後退をelapsed0へ補完しません。
			if( started && ended >= *started) {
				result.elapsedMilliseconds = static_cast<std::uint64_t>(
					std::chrono::duration_cast<std::chrono::milliseconds>( ended - *started)
						.count()) ;
			}
		} catch( ...) {
			// 時計自体の例外は未知値を保持し、元の取得診断を失いません。
			result.completedAtUtc.reset() ;
			result.elapsedMilliseconds.reset() ;
		}

		return result ;
	}
}

/** @see Access宣言側の契約を正本とします。 */
PublicIndexReadbackReport public_index_readback_detail::Access::forTest(
	const Services &services, const std::string_view envelope, const std::string_view gzip,
	const std::uint32_t milliseconds, const HttpCancellationCallback &cancellation) noexcept
{
	// 完全fake tableまたはRAM trust欠損を実通信で補完しません。
	if( !services.transport || services.trust.empty()) {
		return {} ;
	}

	OfficialHttpClient client( *services.transport) ;	// 同じ完全fakeだけの非cache clientです。
	return execute( client, services, envelope, gzip, milliseconds, cancellation) ;
}
/** @see readbackFixedPublicIndex宣言側の契約を正本とします。 */
PublicIndexReadbackReport readbackFixedPublicIndex(
	const std::string_view envelope, const std::string_view gzip, const std::uint32_t milliseconds,
	const std::chrono::steady_clock::time_point operationStarted,
	const std::chrono::sys_seconds				operationStartedAtUtc) noexcept
{
	try {
		public_index_readback_detail::Services services ;	// 製品の固定依存だけです。
		services.trust				   = index_distribution_trust::TRUST_KEYS ;
		services.operationStarted	   = operationStarted ;
		services.operationStartedAtUtc = operationStartedAtUtc ;
		services.utcNow				   = []() {
			   return std::optional<std::chrono::sys_seconds>{
				   std::chrono::floor<std::chrono::seconds>( std::chrono::system_clock::now())} ;
		} ;
		services.monotonicNow = []() { return std::chrono::steady_clock::now() ; } ;
		OfficialHttpClient client( false) ;	// 永続cacheとProvider ledgerを使いません。
		return public_index_readback_detail::Access::execute( client, services, envelope, gzip,
															 milliseconds, {}) ;
	} catch( ...) {
		PublicIndexReadbackReport result ;	// 依存確保失敗でも例外をprocess境界へ漏らしません。
		result.nativeError = E_UNEXPECTED ;
		return result ;
	}
}
/** @see publicIndexReadbackJson宣言側の契約を正本とします。 */
std::string publicIndexReadbackJson( const PublicIndexReadbackReport &report)
{
	constexpr std::array<std::string_view, 3U>	ROLES{"CURRENT_ENVELOPE", "IMMUTABLE_ENVELOPE",
													  "IMMUTABLE_GZIP"} ;	// 固定順です。
	constexpr std::array<std::string_view, 3U>	STATES{"NOT_STARTED", "COMPLETE",
													   "FAILED"} ;	// 閉enumです。
	constexpr std::array<std::string_view, 10U> STAGES{
		"NONE",			  "ARGUMENTS",	"INPUT",   "TRUST",	   "TIME", "CURRENT",
		"MANIFEST_ASSET", "GZIP_ASSET", "CONTENT", "CANCELLED"} ;	// 不正値はatで拒否します。
	std::string out =
		"{\"schema\":\"dc-public-index-readback-result-v1\",\"outcome\":\"" ;	// 順序固定writerです。
	out += report.verified ? "VERIFIED" : "UNKNOWN" ;
	out += "\",\"startedAtUtc\":" + timestamp( report.startedAtUtc) +
		   ",\"completedAtUtc\":" + timestamp( report.completedAtUtc) + ",\"elapsedMilliseconds\":" ;
	// 不明な単調時計を0へ合成しません。
	if( report.elapsedMilliseconds) {
		number( out, *report.elapsedMilliseconds) ;
	} else {
		out += "null" ;
	}

	out += ",\"resources\":[" ;
	// 三resourceを欠損・並替えなしで閉field順へ生成します。
	for( std::size_t index = 0U; index < report.resources.size(); ++index) {
		const auto &resource = report.resources[index] ;	// 同実行の観測だけです。
		// 二件目以降だけ固定区切りを出します。
		if( index != 0U) {
			out += ',' ;
		}

		out += "{\"role\":\"" ;
		out += ROLES[index] ;
		out += "\",\"state\":\"" ;
		out += STATES.at( static_cast<std::size_t>( resource.state)) ;
		out += "\",\"httpStatus\":" ;
		number( out, resource.httpStatus) ;
		out += ",\"sends\":" ;
		number( out, resource.sends) ;
		out += ",\"receivedBytes\":" ;
		number( out, resource.receivedBytes) ;
		out += ",\"sha256\":" ;
		// 共通hashの閉ASCII以外はwriterへ流しません。
		if( resource.sha256) {
			// 欠損桁や任意textの注入を拒否します。
			if( resource.sha256->size() != 64U ||
			   !std::all_of( resource.sha256->begin(), resource.sha256->end(), []( const char c) {
				   return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ;
			   })) {
				throw std::runtime_error( "readback hash rejected") ;
			}

			out += '"' + *resource.sha256 + '"' ;
		} else {
			out += "null" ;
		}

		out += ",\"nativeError\":" ;
		number( out, static_cast<std::uint32_t>( resource.nativeError)) ;
		out += '}' ;
	}

	out += "],\"sends\":" ;
	number( out, report.sends) ;
	out += ",\"receivedBytes\":" ;
	number( out, report.receivedBytes) ;
	out += ",\"nativeError\":" ;
	number( out, static_cast<std::uint32_t>( report.nativeError)) ;
	out += ",\"failureStage\":\"" ;
	out += STAGES.at( static_cast<std::size_t>( report.failureStage)) ;
	out += "\"}" ;
	return out ;
}
} // namespace drivercrate
