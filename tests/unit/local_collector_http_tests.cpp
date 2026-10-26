//------------------------------------------------------------------------------
/**
 * @file local_collector_http_tests.cpp
 * @brief 有限DNS・共通HTTPの原値・終端・所有者回収を非通信検証します。
 * @version 01.61.00
 * @date 2026/09/29
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/27  有限DNS・共通HTTP制御接続を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/27  所有workerからv3保存までの非通信試験を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/27  原HTTP故障・精算と遅延Retry保存を検査。
 * Ver.01.03.00 Shunji Ogawa  2026/09/28  二source射影本文と304・失敗・一回性を偽HTTPで検査。
 * Ver.01.04.00 Shunji Ogawa  2026/09/28  本文消費から秘密値なし全対象射影までの偽HTTPを追加。
 * Ver.01.05.00 Shunji Ogawa  2026/09/29  専用workerの原失敗・COM回収・sealed移譲を検査。
 * Ver.01.06.00 Shunji Ogawa  2026/09/29  偽本文改変・配布URL拒否・共有edgeを専用workerで検査。
 * Ver.01.07.00 Shunji Ogawa  2026/09/29  本文の自己move・停止／seal後消費と追加GET拒否を検査。
 * Ver.01.08.00 Shunji Ogawa  2026/09/29  ASUS多record・部分拒否・0／16／17行を専用workerで検査。
 * Ver.01.09.00 Shunji Ogawa  2026/09/29  URL残余・組立途中の停止／OOM・CNG失敗を検査。
 * Ver.01.10.00 Shunji Ogawa  2026/09/29  本番指紋関係・ordinalと300対象16候補を検査。
 * Ver.01.11.00 Shunji Ogawa  2026/09/29  汎用件数の五境界と実配列合計を検査。
 * Ver.01.12.00 Shunji Ogawa  2026/09/29  実workerから全field metadata codecへ接続。
 * Ver.01.13.00 Shunji Ogawa  2026/09/29  元I/Oと応答v4の往復・故障検査を接続。
 * Ver.01.14.00 Shunji Ogawa  2026/09/29  初回親prepareの実予約・全join・改変と非保存を検査。
 * Ver.01.15.00 Shunji Ogawa  2026/09/29  成功履歴比較へ複数件数と元失敗の所有観測を渡す。
 * Ver.01.16.00 Shunji Ogawa  2026/09/29  予約前履歴固定・差替え拒否と応答／CACHE同時導出を検査。
 * Ver.01.17.00 Shunji Ogawa  2026/09/30  登録済み履歴の四role再計算・改変・非変更を検査。
 * Ver.01.18.00 Shunji Ogawa  2026/09/30  初回所有workerの成功保存と全四role保存窓を検査。
 * Ver.01.19.00 Shunji Ogawa  2026/09/30  初回世代完了の固定分母・保存窓・改変と容量を検査。
 * Ver.01.20.00 Shunji Ogawa  2026/09/30  初回完了履歴・他job破損・終了時変更の非変更拒否を検査。
 * Ver.01.21.00 Shunji Ogawa  2026/09/30  二完了世代・進んだCACHE・日次archiveを非通信検査。
 * Ver.01.22.00 Shunji Ogawa  2026/09/30  通常全完了再読込み・非保存／無送信と拒否を検査。
 * Ver.01.23.00 Shunji Ogawa  2026/09/30  明示次回開始・未応答末尾・履歴予約と保存窓を検査。
 * Ver.01.24.00 Shunji Ogawa  2026/09/30  次世代の所有履歴保存・減少保持・末尾完了を非通信検査。
 * Ver.01.25.00 Shunji Ogawa  2026/09/30  未登録次世代応答・準備像の非再送回復と拒否を検査。
 * Ver.01.25.01 Shunji Ogawa  2026/09/30  元予約の操作名導出と異値bool改変を試験へ使用。
 * Ver.01.26.00 Shunji Ogawa  2026/09/30  READY復旧・無起動と復旧中の原error保持を追加。
 * Ver.01.27.00 Shunji Ogawa  2026/09/30  登録済み四roleの全prefix回復・再中断と非変更拒否を検査。
 * Ver.01.27.01 Shunji Ogawa  2026/09/30  再起動fixtureの元監督借用を解放してから別監督を開始。
 * Ver.01.28.00 Shunji Ogawa  2026/10/01  未応答次世代の明示中断と全保存窓の独立fixtureを追加。
 * Ver.01.28.01 Shunji Ogawa  2026/10/01  新fixtureの再起動期待codeをDWORDへ統一。
 * Ver.01.28.02 Shunji Ogawa  2026/10/01  root監督時刻を元応答時計と分けて全byteを照合。
 * Ver.01.29.00 Shunji Ogawa  2026/10/01  実開始二prefix・中断全保存窓と改変拒否を追加。
 * Ver.01.29.01 Shunji Ogawa  2026/10/01  開始fixtureの予約を既存PermitPoolから発行。
 * Ver.01.29.02 Shunji Ogawa  2026/10/01  分岐意図と開始prefixの追加改変拒否を整備。
 * Ver.01.30.00 Shunji Ogawa  2026/10/01  日次切替の実保存全窓・後日再開・拒否と再中断を検査。
 * Ver.01.31.00 Shunji Ogawa  2026/10/01  復旧再登録時計・原保存拒否と公開入口の非流用を検査。
 * Ver.01.31.01 Shunji Ogawa  2026/10/01  既存日次四窓を固定復旧・旧byte保持の新契約へ照合。
 * Ver.01.32.00 Shunji Ogawa  2026/10/01  末尾完了の実五窓・再停止・元I/Oと拒否を検証。
 * Ver.01.32.01 Shunji Ogawa  2026/10/01  元ROOT本文読取りを既存store helperへ結合。
 * Ver.01.32.02 Shunji Ogawa  2026/10/01  reviewを解除せず翌日／翌々日の独立末尾条件へ修正。
 * Ver.01.32.03 Shunji Ogawa  2026/10/01  pointer改変拒否の注釈を未知値試験へ一致。
 * Ver.01.33.00 Shunji Ogawa  2026/10/01  重複なし300世代の全完了像と非変更上限拒否を追加。
 * Ver.01.33.01 Shunji Ogawa  2026/10/01  未登録CACHEの公開読取り拒否を既存契約へ訂正。
 * Ver.01.34.00 Shunji Ogawa  2026/10/01  本番予約・偽HTTPの299操作と未受領300枠を検査。
 * Ver.01.34.01 Shunji Ogawa  2026/10/01  private非変更照会を呼ばず保存CONTROLと68を照合。
 * Ver.01.34.02 Shunji Ogawa  2026/10/01  timeout原結果を残し二世代・未受領二枠の基礎試験へ分離。
 * Ver.01.34.03 Shunji Ogawa  2026/10/01  未受領時の通常1237待機と明示中断を分けて検査。
 * Ver.01.35.00 Shunji Ogawa  2026/10/01  本番codecの合成299操作と未受領上限の専用枠を追加。
 * Ver.01.35.01 Shunji Ogawa  2026/10/01  合成metadata時計変更後のhashを本番codecで再生成。
 * Ver.01.35.02 Shunji Ogawa  2026/10/01  再起動の単調二秒待機と300精算後の追加拒否を検査。
 * Ver.01.36.00 Shunji Ogawa  2026/10/01  操作境界だけ四要求・75世代と末尾新要求へ分離。
 * Ver.01.36.01 Shunji Ogawa  2026/10/01  末尾manifest変更時の全bindingを本番identityへ再結合。
 * Ver.01.37.00 Shunji Ogawa  2026/10/01  新requestのCACHE増加と未受領二枠の通常復旧を検査。
 * Ver.01.38.00 Shunji Ogawa  2026/10/01  合成新requestの段階閉包とraw容量診断を検査。
 * Ver.01.39.00 Shunji Ogawa  2026/10/01  完了世代単位の容量先着・通常起動と非変更を検査。
 * Ver.01.40.00 Shunji Ogawa  2026/10/02  全完了raw封印の全file反証と再照合を追加。
 * Ver.01.40.01 Shunji Ogawa  2026/10/02  fixtureの独立hashと元HRESULT期待を補修。
 * Ver.01.41.00 Shunji Ogawa  2026/10/02  source全field・全行順序と二世代／実I/O反証を追加。
 * Ver.01.42.00 Shunji Ogawa  2026/10/02  同親historyへ既存v3保存と個別readerを接続。
 * Ver.01.43.00 Shunji Ogawa  2026/10/02  元共有値／CACHE由来の結合と反証を追加。
 * Ver.01.44.00 Shunji Ogawa  2026/10/02  実根拠からの非保存切替準備を検査。
 * Ver.01.45.00 Shunji Ogawa  2026/10/02  実HTTP所有閉鎖と全所有解放を検査。
 * Ver.01.46.00 Shunji Ogawa  2026/10/02  同親hold・固定保存roleと独立容量境界を検査。
 * Ver.01.47.00 Shunji Ogawa  2026/10/02  切替準備保存窓と同一hold再開の独立試験を追加。
 * Ver.01.48.00 Shunji Ogawa  2026/10/02  私有新子69roleの保存窓・再開・改変拒否を追加。
 * Ver.01.49.00 Shunji Ogawa  2026/10/02  専用初期ROOTの実保存と元carry拒否を検査。
 * Ver.01.50.00 Shunji Ogawa  2026/10/02  元head保持記録・親head保存と停止窓を検査。
 * Ver.01.51.00 Shunji Ogawa  2026/10/02  実保存byte由来の回復decoderと有限枠を検査。
 * Ver.01.52.00 Shunji Ogawa  2026/10/03  保護実handleの初回切替回復と検査を追加。
 * Ver.01.53.00 Shunji Ogawa  2026/10/03  ROOT未保存の連続準備prefix回復と検査を追加。
 * Ver.01.54.00 Shunji Ogawa  2026/10/03  初回readyとcheckpointの再hash矛盾・有限枠を検査。
 * Ver.01.55.00 Shunji Ogawa  2026/10/03  同親非作成readerと寿命・直接raw反証を追加。
 * Ver.01.56.00 Shunji Ogawa  2026/10/03  全直接rawの最終差替えと私有handle故障を検査。
 * Ver.01.57.00 Shunji Ogawa  2026/10/03  実読取り容量の先払い停止と最終I/O故障を検査。
 * Ver.01.58.00 Shunji Ogawa  2026/10/03  有効容量・全参照再hashと旧入口／reparseを検査。
 * Ver.01.59.00 Shunji Ogawa  2026/10/03  全66再結合・file linkと実旧CLIを検査。
 * Ver.01.59.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * Ver.01.59.02   Shunji Ogawa  2026/10/16 型と関数の契約コメントを宣言と実装へ対応付ける。
 * Ver.01.59.03 Shunji Ogawa  2026/10/18  起動元errorを診断表示しworker欠損の失敗を安全に保持。
 * Ver.01.59.04 Shunji Ogawa  2026/10/18 一時path診断を除去し短絡期待と欠損guardを維持。
 * Ver.01.59.05 Shunji Ogawa  2026/10/18 既存fixture path helperを共用し削除・存在照会を補正。
 * Ver.01.59.06 Shunji Ogawa  2026/10/21 初回storeと親借用の元errorを連鎖失敗から分離表示。
 * Ver.01.60.00 Shunji Ogawa  2026/10/22 起動境界試験の元呼出し位置へ段階計時とflushを追加。
 * Ver.01.60.01 Shunji Ogawa  2026/10/24  必須解析に合わせ試験の所有・型・失敗制御を明示。
 * Ver.01.61.00 Shunji Ogawa  2026/10/26  Intel改訂指紋と公開hash/codecの限定回帰を追加。
 * </pre>
 *
 * @note 偽HTTP本文を公式parserへ渡し一時保護台帳だけを作成します。実通信・導入は実行しません。
 * @see docs/adr/0218-collector-controlled-http-lifetime.md
 */
//------------------------------------------------------------------------------
#include "platform/local_collector_http_client.h"
#include "platform/local_collector_metadata_projection.h"
#include "platform/local_collector_executor.h"
#include "platform/local_collector_http_observation.h"
#include "platform/local_collector_legacy.h"
#include "platform/local_collector_projected_input.h"
#include "platform/local_collector_projected_executor.h"
#include "platform/local_collector_projected_response.h"
#include "platform/local_collector_projected_cache.h"
#include "platform/local_collector_projected_start.h"
#include "platform/local_collector_recovery.h"
#include "platform/local_collector_completed_inventory.h"
#include "platform/local_collector_collection_store.h"
#include "platform/local_collector_shared_store.h"
#include "platform/local_collector_segment_inventory.h"
#include "platform/local_collector_segment_preparation.h"
#include "platform/local_collector_segment_storage.h"
#include "platform/local_collector_segment_recovery.h"
#include "platform/local_collector_segment_read.h"
#include "platform/local_collector_projected_json.h"
#include <fstream>
#include <iterator>
#include <iostream>
#include <type_traits>
#include <set>
#include "platform/local_collector_state_store.h"
#include "platform/official_file_verifier.h"
#include "platform/asus_catalog_parser.h"
#include "platform/asus_network_record_adapter.h"
#include "platform/asus_collector_target_assessment.h"
#include "platform/official_http_client.h"
#include "core/official_source_policy.h"
#include "local_collector_http_tests.h"
#include "local_collector_metadata_codec_tests.h"
#include "local_collector_projected_response_tests.h"
#include <winrt/Windows.Data.Json.h>
#include <winrt/Windows.Foundation.Collections.h>
#include <winrt/base.h>
#include <objbase.h>
#include <Windows.h>
#include <sddl.h>
#include <winioctl.h>
#include <algorithm>
#include <array>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstring>
#include <functional>
#include <filesystem>
#include <limits>
#include <map>
#include <memory>
#include <new>
#include <optional>
#include <mutex>
#include <stdexcept>
#include <system_error>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace drivercrate::test {
namespace {
/** @brief 自作fixtureの絶対pathだけを長いWindows pathへ渡します。
 * @param[in] path rootFactory由来の絶対path。
 * @return 区切りを維持するextended path。
 */
std::filesystem::path segmentFixturePath( const std::filesystem::path &path)
{
	return L"\\\\?\\" + std::filesystem::path( path).make_preferred().native() ;
}

/**
 * @brief JSON objectをWinRT参照で保持する。Copyは同じobjectを共有し、schema検証は利用側で行う。
 */
using JsonObject = winrt::Windows::Data::Json::JsonObject ;
/**
 * @brief JSON配列をWinRT参照で保持する。要素数と各要素のschema検証は利用側で行う。
 */
using JsonArray = winrt::Windows::Data::Json::JsonArray ;
/**
 * @brief JSON値をWinRT参照で保持する。所有byteの検証と型判定はreader側で行う。
 */
using JsonValue						  = winrt::Windows::Data::Json::JsonValue ;
constexpr std::uint64_t HTTP_TEST_UTC = 1790456400000ULL ;	// 実時計と無関係な固定UTC。
struct IoFixture ;
/** @brief Fake handleは生成threadのfixtureを借用します。 */
struct FixtureHandle {
	/// Handleの所有fixture。
	IoFixture *owner{} ;
	/// Session1・connection2・request3。
	int		   kind{} ;
} ;
/** @brief 一threadの独立したDNS／HTTP応答と観測です。 */
struct IoFixture {
	/// Claim後に作られる制御への借用pointer。
	std::shared_ptr<CollectorHttpControl>	  *control{} ;
	/// 同期API前後の固定二clock。
	CollectorHttpClockSample				   clock{HTTP_TEST_UTC, 0U} ;
	/// API別の実呼出し数。
	std::map<std::string, unsigned>			   calls ;
	/// 失敗させる固定API名。
	std::string								   failure ;
	/// 対象APIの何回目を失敗にするか。
	unsigned								   failAt{1U} ;
	/// 同期復帰前に取消すAPI名。
	std::string								   cancel ;
	/// 期限へ進めるAPI名。
	std::string								   expire ;
	/// UTCだけ巻戻すAPI名。
	std::string								   rollback ;
	/// Native原errorの固定試験値。
	DWORD									   error{12002U} ;
	/// HTTP status。
	DWORD									   status{200U} ;
	/// 有限同名header列。
	std::map<DWORD, std::vector<std::wstring>> headers{{WINHTTP_QUERY_ETAG, {L"\"revision1\""}}} ;
	/// 明示GETのheader。Fixture内だけ保持。
	std::wstring							   sentHeaders ;
	/// Raw本文。
	std::string								   body{"abc"} ;
	/// 本文の既読位置。
	std::size_t								   offset{} ;
	/// Queryで知らせる一回の量の上限。
	DWORD									   chunk{65536U} ;
	/// Queryが0でもreadで本文を返す場合true。
	bool									   queryZero{} ;
	/// 成功readの不正返却量を注入する場合true。
	bool									   invalidRead{} ;
	/// 別threadの取消しをread復帰前に挿入する場合true。
	bool									   threadedCancel{} ;
	/// DNS結果件数。
	std::size_t								   addressCount{1U} ;
	/// IPv6の正常結果へ切り替える場合true。
	bool									   ipv6{} ;
	/// 非public addressを混ぜる場合true。
	bool									   privateAddress{} ;
	/// 未知familyを返す場合true。
	bool									   unknownFamily{} ;
	/// 公開IPの架空応答list。
	std::array<ADDRINFOEXW, 65>				   addresses{} ;
	/// ListのIPv4 byte格納先。
	std::array<sockaddr_in, 65>				   ipv4Values{} ;
	/// ListのIPv6 byte格納先。
	std::array<sockaddr_in6, 65>			   ipv6Values{} ;
	/// 観測したDNS timeoutのmillisecond。
	std::uint32_t							   dnsMillis{} ;
	/// WSA／DNS解放の順序。
	std::vector<int>						   dnsRelease ;
	/// 所有fake handle。
	std::array<FixtureHandle, 3>			   handles{{{this, 1}, {this, 2}, {this, 3}}} ;
	/// Handleの解放順序。
	std::vector<int>						   closed ;
	/// OS・option・timeout・ownerの条件が一つでも崩れた場合false。
	bool									   valid{true} ;
	/// 生成threadとcloseの一致検証用。
	std::thread::id							   ownerThread{std::this_thread::get_id()} ;
	/// 要求した正数read量。
	std::vector<DWORD>						   reads ;
	/// 有限timeoutの観測値。
	std::vector<std::array<int, 4>>			   timeouts ;
	/** @brief API故障・停止・時計変化を同期復帰直前へ注入します。
	 * @param[in] name 固定API名。
	 * @return 指定故障以外はtrue。
	 */
	bool									   point( std::string_view name)
	{
		const unsigned count = ++calls[std::string( name)] ;	// 現APIの実呼出し番号。
		// 指定APIで取消しを先着させる。
		if( cancel == name && control != nullptr && *control) {
			(*control)->requestStop() ;
		}

		// 二clockを同じ元deadlineへ進める。
		if( expire == name) {
			clock.utcMillis	   = HTTP_TEST_UTC + 120000U ;
			clock.steadyMillis = 120000U ;
		}

		// UTC後退を経過0で補完させない。
		if( rollback == name) {
			clock.utcMillis = HTTP_TEST_UTC - 1U ;
		}

		// 偶然の別errorで合格させない固定故障。
		if( failure == name && count == failAt) {
			SetLastError( error) ;
			return false ;
		}

		return true ;
	}
} ;
// APIにcaptureを渡せないため、同thread・同scopeだけのfixtureを明示登録する。
thread_local IoFixture *activeFixture{} ;

/** @brief Fixtureを現在threadへ借用登録し必ず解除します。 */
class FixtureScope		final {
public:
	 /** @brief 再入を許さずthread別にfakeを登録します。
	 * @param[in,out] fixture Scopeより長い独立状態。
	 */
	 explicit FixtureScope( IoFixture &fixture)
	 {
		 // 重複したfake状態の上書きを拒否する。
		 if( activeFixture != nullptr) {
			 throw std::runtime_error( "nested HTTP fixture") ;
		 }

		 activeFixture = &fixture ;
	 }
	 /** @brief 寿命終了後の参照を防ぐため登録を解除します。 */
	 ~FixtureScope()
	 {
		 activeFixture = nullptr ;
	 }
	 /**
	  * @brief thread別fake登録の解除責務の二重管理を防ぐため、コピー構築を禁止する。
	  */
	 FixtureScope( const FixtureScope &) = delete ;
	 /**
	  * @brief thread別fake登録の解除責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	  */
	 FixtureScope &operator=( const FixtureScope &) = delete ;
} ;
/** @brief Handleから同じ生成元fixtureを取得します。
 * @param[in] handle Fakeだけの非null所有handle。
 * @return 同threadで生存する状態。
 */
IoFixture &stateOf( HINTERNET handle)
{
	auto &value = *static_cast<FixtureHandle *>( handle) ;	// Fixture型以外を注入しない。
	value.owner->valid =
		value.owner->valid && value.owner->ownerThread == std::this_thread::get_id() ;
	return *value.owner ;
}
/** @brief 全DNS依存を非通信callbackへ置換します。
 * @return 未指定native関数を含まない表。
 */
OfficialCollectorDnsApi fixtureDns()
{
	OfficialCollectorDnsApi api{} ;	// 欠損はnullの表。
	api.startup = []( WORD version, LPWSADATA) -> int {
		activeFixture->valid = activeFixture->valid && version == MAKEWORD( 2, 2) ;
		return activeFixture->point( "startup") ? 0 : static_cast<int>( activeFixture->error) ;
	} ;
	api.resolve = []( PCWSTR host, PCWSTR service, DWORD space, LPGUID id, const ADDRINFOEXW *hints,
					 PADDRINFOEXW *result, timeval *timeout, LPOVERLAPPED overlap,
					 LPLOOKUPSERVICE_COMPLETION_ROUTINE completion, LPHANDLE cancellation) -> int {
		auto &state = *activeFixture ;	// Scopeで登録した独立DNS状態。
		state.valid = state.valid && host != nullptr && std::wstring_view( service) == L"443" &&
					  space == NS_DNS && id == nullptr && hints->ai_family == AF_UNSPEC &&
					  hints->ai_socktype == SOCK_STREAM && hints->ai_protocol == IPPROTO_TCP &&
					  overlap == nullptr && completion == nullptr && cancellation == nullptr &&
					  timeout != nullptr && timeout->tv_sec >= 0 && timeout->tv_usec >= 0 &&
					  timeout->tv_usec < 1000000 ;
		state.dnsMillis =
			static_cast<std::uint32_t>( timeout->tv_sec * 1000 + timeout->tv_usec / 1000) ;
		// 最大65件のlistをscope内storageだけで返す。
		for( std::size_t index = 0U; index < state.addressCount; ++index) {
			auto &entry = state.addresses[index] ;	// 一つの結果。
			entry.ai_next =
				index + 1U < state.addressCount ? &state.addresses[index + 1U] : nullptr ;
			// IPv6も全address共通public判定を通す。
			if( state.ipv6) {
				auto &ip			   = state.ipv6Values[index] ;	// Network byte orderの格納先。
				ip.sin6_family		   = AF_INET6 ;
				ip.sin6_addr.u.Byte[0] = 0x26 ;
				ip.sin6_addr.u.Byte[1] = 0x06 ;
				ip.sin6_addr.u.Byte[2] = 0x47 ;
				ip.sin6_addr.u.Byte[3] = 0 ;
				// List最後だけprivateへ変更し、一部採用を拒否させる。
				if( state.privateAddress && index + 1U == state.addressCount) {
					ip.sin6_addr.u.Byte[0] = 0xfc ;
				}

				entry.ai_family	 = AF_INET6 ;
				entry.ai_addrlen = sizeof( ip) ;
				// Winsock ABIだけのcast。
				entry.ai_addr = reinterpret_cast<sockaddr *>( &ip) ;
			} else {
				auto &ip	  = state.ipv4Values[index] ;	// Publicの架空DNS応答。
				ip.sin_family = AF_INET ;
				ip.sin_addr.S_un.S_un_b.s_b1 =
					state.privateAddress && index + 1U == state.addressCount ? 10 : 8 ;
				ip.sin_addr.S_un.S_un_b.s_b2 = 8 ;
				ip.sin_addr.S_un.S_un_b.s_b3 = 8 ;
				ip.sin_addr.S_un.S_un_b.s_b4 = 8 ;
				entry.ai_family				 = state.unknownFamily ? AF_UNIX : AF_INET ;
				entry.ai_addrlen			 = sizeof( ip) ;
				// ABI内だけの借用。
				entry.ai_addr = reinterpret_cast<sockaddr *>( &ip) ;
			}
		}

		*result = state.addressCount == 0U ? nullptr : state.addresses.data() ;
		return state.point( "dns") ? 0 : static_cast<int>( state.error) ;
	} ;
	api.freeResult = []( PADDRINFOEXW result) {
		activeFixture->valid = activeFixture->valid && result == activeFixture->addresses.data() ;
		activeFixture->dnsRelease.push_back( 1) ;
		// 後始末で原API errorが変わる例。
		SetLastError( 999U) ;
	} ;
	api.cleanup = []() -> int {
		activeFixture->dnsRelease.push_back( 2) ;
		return activeFixture->point( "cleanup") ? 0 : SOCKET_ERROR ;
	} ;
	api.lastError = []() -> int { return static_cast<int>( activeFixture->error) ; } ;
	return api ;
}
/** @brief 全WinHTTP依存をhandle別の非通信callbackへ置換します。
 * @return 全使用関数がfakeの表。旧resolverを呼ぶことも許しません。
 */
OfficialHttpTransport fixtureHttp()
{
	OfficialHttpTransport api{} ;	// 全使用memberを下で明示置換する。
	api.open = []( LPCWSTR, DWORD proxy, LPCWSTR name, LPCWSTR bypass, DWORD flags) -> HINTERNET {
		auto &state = *activeFixture ;	// まだhandleのない入口だけthread-localを使う。
		state.valid = state.valid && proxy == WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY &&
					  name == nullptr && bypass == nullptr && flags == 0U ;
		return state.point( "open") ? &state.handles[0] : nullptr ;
	} ;
	api.connect = []( HINTERNET handle, LPCWSTR, INTERNET_PORT port, DWORD) -> HINTERNET {
		auto &state = stateOf( handle) ;	// 接続元session。
		state.valid = state.valid && port == INTERNET_DEFAULT_HTTPS_PORT ;
		return state.point( "connect") ? &state.handles[1] : nullptr ;
	} ;
	api.openRequest = []( HINTERNET handle, LPCWSTR verb, LPCWSTR, LPCWSTR, LPCWSTR referer,
						 LPCWSTR *, DWORD flags) -> HINTERNET {
		auto &state = stateOf( handle) ;	// 接続元connection。
		state.valid = state.valid && std::wstring_view( verb) == L"GET" && referer == nullptr &&
					  flags == WINHTTP_FLAG_SECURE ;
		return state.point( "request") ? &state.handles[2] : nullptr ;
	} ;
	api.setTimeouts = []( HINTERNET handle, int dns, int connect, int send, int receive) -> BOOL {
		auto &state = stateOf( handle) ;	// 同じ元clockから許可timeoutを検査する。
		state.timeouts.push_back( {dns, connect, send, receive}) ;
		const auto remaining =
			HTTP_TEST_UTC + 120000U - state.clock.utcMillis ;	// 期限内だけ呼ぶ前提。
		state.valid = state.valid && dns > 0 && dns <= 15000 && connect > 0 && connect <= 30000 &&
					  send > 0 && send <= 30000 && receive > 0 && receive <= 60000 &&
					  static_cast<std::uint64_t>( receive) <= remaining ;
		return state.point( "timeout") ? TRUE : FALSE ;
	} ;
	api.setOption = []( HINTERNET handle, DWORD option, LPVOID value, DWORD bytes) -> BOOL {
		auto	   &state	= stateOf( handle) ;				// 固定option検証。
		const DWORD setting = *static_cast<DWORD *>( value) ;	// DWORD限定。
		state.valid =
			state.valid && bytes == sizeof( DWORD) &&
			((option == WINHTTP_OPTION_REDIRECT_POLICY &&
			  setting == WINHTTP_OPTION_REDIRECT_POLICY_NEVER) ||
			 (option == WINHTTP_OPTION_AUTOLOGON_POLICY &&
			  setting == WINHTTP_AUTOLOGON_SECURITY_LEVEL_HIGH) ||
			 (option == WINHTTP_OPTION_DISABLE_FEATURE && setting == WINHTTP_DISABLE_COOKIES)) ;
		return state.point( "option") ? TRUE : FALSE ;
	} ;
	api.addHeaders = []( HINTERNET handle, LPCWSTR value, DWORD length, DWORD) -> BOOL {
		auto &state = stateOf( handle) ;	// 固定headerの観測。
		state.sentHeaders.append( value, length) ;
		return state.point( "add") ? TRUE : FALSE ;
	} ;
	api.sendRequest = []( HINTERNET handle, LPCWSTR, DWORD, LPVOID, DWORD, DWORD,
						 DWORD_PTR) -> BOOL {
		return stateOf( handle).point( "send") ? TRUE : FALSE ;
	} ;
	api.receiveResponse = []( HINTERNET handle, LPVOID) -> BOOL {
		return stateOf( handle).point( "receive") ? TRUE : FALSE ;
	} ;
	api.queryHeaders = []( HINTERNET handle, DWORD query, LPCWSTR, LPVOID output, LPDWORD bytes,
						  LPDWORD index) -> BOOL {
		auto &state = stateOf( handle) ;	// Header照会の独立状態。
		// Native失敗を通常のheader欠損へ置き換えない。
		if( !state.point( "headers")) {
			return FALSE ;
		}

		// 数値statusは固定長で返す。
		if( query == (WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER)) {
			*static_cast<DWORD *>( output) = state.status ;
			*bytes						  = sizeof( DWORD) ;
			return TRUE ;
		}

		const auto found  = state.headers.find( query) ;		// 同名header集合。
		const auto offset = index == nullptr ? 0U : *index ;	// 本呼出しの列挙位置。
		// 欠損はWinHTTPの元codeで表す。
		if( found == state.headers.end() || offset >= found->second.size()) {
			SetLastError( ERROR_WINHTTP_HEADER_NOT_FOUND) ;
			return FALSE ;
		}

		const auto &value = found->second[offset] ;	// 一つの有限値。
		const auto	required =
			// NUL込み容量。
			static_cast<DWORD>( (value.size() + 1U) * sizeof( wchar_t)) ;
		// Buffer probeは原ERROR_INSUFFICIENT_BUFFER。
		if( output == nullptr || *bytes < required) {
			*bytes = required ;
			SetLastError( ERROR_INSUFFICIENT_BUFFER) ;
			return FALSE ;
		}

		std::memcpy( output, value.c_str(), required) ;
		*bytes = required - sizeof( wchar_t) ;
		// 実値照会だけでindexを前進させる。
		if( index != nullptr) {
			++*index ;
		}

		return TRUE ;
	} ;
	api.queryAvailable = []( HINTERNET handle, LPDWORD available) -> BOOL {
		auto &state = stateOf( handle) ;	// 本文の残量。
		// 故障時のavailableは根拠にしない。
		if( !state.point( "query")) {
			return FALSE ;
		}

		*available = state.queryZero ? 0U
									 : static_cast<DWORD>( std::min<std::size_t>(
										   state.chunk, state.body.size() - state.offset)) ;
		return TRUE ;
	} ;
	api.readData = []( HINTERNET handle, LPVOID output, DWORD requested, LPDWORD received) -> BOOL {
		auto &state = stateOf( handle) ;	// 同threadでscope存続する本文。
		state.reads.push_back( requested) ;
		// 失敗read後にcountを使わせない。
		if( !state.point( "read")) {
			*received = 77U ;
			return FALSE ;
		}

		const auto count =
			std::min<std::size_t>( requested, state.body.size() - state.offset) ;	// 容量内copy。
		std::memcpy( output, state.body.data() + state.offset, count) ;
		state.offset += count ;
		*received = state.invalidRead ? requested + 1U : static_cast<DWORD>( count) ;
		// 別threadの停止中もread成功量を取りこぼさない。
		if( state.threadedCancel) {
			std::jthread stopper(
				[&state] { (*state.control)->requestStop() ; }) ;	// Joinまで借用は有効。
			stopper.join() ;
		}

		return TRUE ;
	} ;
	api.closeHandle = []( HINTERNET handle) -> BOOL {
		auto &state = stateOf( handle) ;	// 所有thread一致も検査する。
		state.closed.push_back( static_cast<FixtureHandle *>( handle)->kind) ;
		const bool success = state.point( "close") ;	// 元errorを上書きしない順序。
		// 成功closeでもLastErrorが変わる環境を模擬する。
		if( success) {
			SetLastError( 999U) ;
		}

		return success ? TRUE : FALSE ;
	} ;
	api.resolveDestination = []( std::wstring_view,
								std::vector<OfficialResolvedNetworkAddress> &) -> NativeError {
		activeFixture->valid = false ;
		return static_cast<NativeError>( E_FAIL) ;
	} ;
	return api ;
}
/** @brief 元targetの公開fieldをcanonical化し、公式builderを通します。
 * @param[out] request 成功した共通request。
 * @return 架空製品名で同じ公式route検証を通したtarget。
 */
LocalCollectorTarget fixtureTarget( LocalCollectorRequest &request)
{
	LocalCollectorTarget target{L"ASUS_CATALOG", L"sample-board", L"Windows 11 64-bit", L"LAN",
								L""} ;	// 公開架空値。
	// 旧schemaのcanonicalを固定し、本番builderに再照合させる。
	if( computeBytesSha256( "ASUS_CATALOG\nsample-board\nWindows 11 64-bit\nLAN\n",
						  target.keySha256) != 0 ||
	   !makeLocalCollectorRequest( target, request)) {
		throw std::runtime_error( "HTTP fixture target") ;
	}

	return target ;
}
/** @brief 一つの公開requestに結合した保護予約入力を作ります。
 * @param[in] request 共通builderの結果。
 * @param[in] maximum 予約する本文上限。
 * @return 実際のmanifest parser・台帳予約を通す入力。
 */
CollectorRecoveryInput fixtureInput( const LocalCollectorRequest &request, std::uint64_t maximum)
{
	const std::wstring hash( 64U, L'a') ;	// 架空plan／artifact。
	JsonObject		   manifest ;			// 評価planではなく開発用実行schema。
	manifest.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-manifest-v1")) ;
	manifest.Insert( L"campaignId", JsonValue::CreateStringValue( L"http-fixture")) ;
	manifest.Insert( L"planSha256", JsonValue::CreateStringValue( hash)) ;
	manifest.Insert( L"os", JsonValue::CreateStringValue( L"WINDOWS_11_X64")) ;
	JsonObject target ;	// 一つの架空公開製品。
	target.Insert( L"id", JsonValue::CreateStringValue( L"sample")) ;
	target.Insert( L"maker", JsonValue::CreateStringValue( L"Sample")) ;
	target.Insert( L"model", JsonValue::CreateStringValue( L"Sample Board")) ;
	target.Insert( L"kind", JsonValue::CreateStringValue( L"MAINBOARD")) ;
	target.Insert( L"purpose", JsonValue::CreateStringValue( L"network")) ;
	JsonArray targets ;	// 固定分母一件。
	targets.Append( target) ;
	manifest.Insert( L"targets", targets) ;
	JsonObject job ;	// 一つのmetadata job。
	job.Insert( L"source", JsonValue::CreateStringValue( request.source)) ;
	job.Insert( L"resource", JsonValue::CreateStringValue( request.resource)) ;
	job.Insert( L"locator", JsonValue::CreateStringValue( L"sample-board")) ;
	job.Insert( L"locale", JsonValue::CreateStringValue( L"en-US")) ;
	job.Insert( L"page", JsonValue::CreateNumberValue( 1)) ;
	JsonArray references ;	// 対象製品参照。
	references.Append( JsonValue::CreateStringValue( L"sample")) ;
	job.Insert( L"targets", references) ;
	JsonArray jobs ;	// 共有job一件。
	jobs.Append( job) ;
	manifest.Insert( L"jobs", jobs) ;
	CollectorRecoveryInput input ;	// Caller固定sourceと実request key。
	input.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	input.sources		= {
		  {request.source, request.resource, request.group, L"fixture-parser-v1", maximum}} ;
	input.artifactSha256 = hash ;
	input.requestKeys	 = {request.requestKey} ;
	input.cacheBindings	 = {hash} ;
	return input ;
}
/** @brief 親writerの元hash envelopeから本文を読みます。
 * @param[in,out] store 試験専用store。
 * @param[in] name 固定相対名。
 * @return 欠測を補完しない元本文。
 */
std::string httpSavedBody( LocalCollectorStateStore &store, const std::wstring &name)
{
	std::string raw ;		// 親threadだけが読む実byte。
	bool		found{} ;	// 欠測と空本文を区別する。
	// 試験前提の読取り失敗を合格値へ変換しない。
	if( store.read( name, raw, found) != 0U || !found) {
		throw std::runtime_error( "HTTP fixture saved body") ;
	}

	return winrt::to_string( JsonObject::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
}

/**
 * @brief 固定ASUS公開modelと一行LAN配布を同一Nuxt storeへ置きます。
 * @param[in] path 架空配布URLのpathとして埋め込む試験文字列。同期中だけ借用する。
 * @return 同じstoreへmodelと一件のLAN配布を置いた所有fixture HTML。
 */
[[nodiscard]] std::wstring projectedAsusHtml( const std::wstring_view path)
{
	std::wstring html =
		LR"(<html><script type="application/json" id="__NUXT_DATA__">)" ;	// 固定Nuxt入口。
	html +=
		LR"([["ShallowReactive",1],{"pinia":2},["Reactive",3],{"pdSupportStore":4},{"productSupportCheckModelExist":5,"productSupportOS":9,"productSupportDriver":13},{"model":6,"productId":7,"downloadUrl":8},"ProArt X870E-CREATOR WIFI",123,"",[10],{"Id":11,"Name":12},"52","Windows 11 64-bit",{"Model":6,"Count":14,"Obj":15},1,[16],{"Name":17,"Count":14,"Files":18,"IsDescShow":19},"LAN",[20],false,{"Id":21,"Version":22,"Title":23,"FileSize":24,"ReleaseDate":25,"DownloadUrl":26,"sha256":28},"1@66@7@8@52@5@DRV_LAN_Fixture.zip","1125.27.50.919","Fictional ASUS LAN Driver","14.67 MB","2025/12/31",{"Global":27},")" ;
	html += path ;
	html +=
		LR"(","DEF73029462651E78B30791C9E6EDB2E99F86755B2334F942612A50467761CB5"]</script></html>)" ;
	return html ;
}

/** @brief 同一ASUS公開modelの有限LAN行を一つのNuxt storeへ組み立てます。
 * @param[in] count 公開行数。試験では0、2、16、17のみ。
 * @param[in] badSecondHash 二行目の公開hash形式だけを不正にする。
 * @return 対象model・OS・配布行を同一本文に保持した偽HTML。
 */
[[nodiscard]] std::wstring projectedAsusRowsHtml( const std::size_t count,
												 const bool		   badSecondHash = false)
{
	std::wstring html =
		LR"(<html><script type="application/json" id="__NUXT_DATA__">)" ;	// 一つのNuxt入口。
	html +=
		LR"([["ShallowReactive",1],{"pinia":2},["Reactive",3],{"pdSupportStore":4},{"productSupportCheckModelExist":5,"productSupportOS":9,"productSupportDriver":13},{"model":6,"productId":7,"downloadUrl":8},"ProArt X870E-CREATOR WIFI",123,"",[10],{"Id":11,"Name":12},"52","Windows 11 64-bit",{"Model":6,"Count":14,"Obj":15},)" ;
	html += std::to_wstring( count) +
			LR"(,[16],{"Name":17,"Count":14,"Files":18,"IsDescShow":19},"LAN",[)" ;
	// 各公開行の9 slotを元順序でFilesへ参照します。
	for( std::size_t index = 0U; index < count; ++index) {
		// 二行目以降にだけJSON separatorを追加します。
		if( index != 0U) {
			html += L"," ;
		}

		html += std::to_wstring( 20U + index * 9U) ;
	}

	html += L"],false" ;
	// 配布basename、元opaque ID、URLは各行で完全一致させます。
	for( std::size_t index = 0U; index < count; ++index) {
		const auto slot = 20U + index * 9U ;										// 独立した一行の先頭slot。
		const auto file = L"DRV_LAN_Fixture_" + std::to_wstring( index) + L".zip" ;	// 架空basename。
		// 二行目だけ不正hash形式にして、全体拒否と部分拒否を区別します。
		const auto hash =
			badSecondHash && index == 1U
				? std::wstring( L"xyz")
				: std::wstring( L"DEF73029462651E78B30791C9E6EDB2E99F86755B2334F942612A50467761CB5") ;
		html +=
			L",{\"Id\":" + std::to_wstring( slot + 1U) + L",\"Version\":" +
			std::to_wstring( slot + 2U) + L",\"Title\":" + std::to_wstring( slot + 3U) +
			L",\"FileSize\":" + std::to_wstring( slot + 4U) + L",\"ReleaseDate\":" +
			std::to_wstring( slot + 5U) + L",\"DownloadUrl\":" + std::to_wstring( slot + 6U) +
			L",\"sha256\":" + std::to_wstring( slot + 8U) + L"},\"1@66@7@8@52@5@" + file +
			L"\",\"1125.27.50.919\",\"Fictional ASUS LAN Driver\",\"1 MB\",\"2025/12/31\",{\"Global\":" +
			std::to_wstring( slot + 7U) + L"},\"/pub/ASUS/mb/04LAN/" + file + L"\",\"" + hash +
			L"\"" ;
	}

	return html + L"]</script></html>" ;
}

/** @brief 配布hero・許諾・同一本文の公開一覧を持つIntel固定形です。 */
[[nodiscard]] std::wstring projectedIntelHtml()
{
	return LR"(<html><head><meta charset="utf-8"><link rel="canonical" href="https://www.intel.com/content/www/us/en/download/727998/intel-network-adapter-driver-for-microsoft-windows-11.html"></head><body>)"
		   LR"(<main id="primary-content"><div data-bundle-id="downloadcenter.components.content.dcPageBanner" class="dc-page-banner">)"
		   LR"(<div class="dc-page-banner-actions-action-id"><label class="dc-page-banner-actions-action__label">ID</label>)"
		   LR"(<span class="dc-page-banner-actions-action__value">727998</span></div></div>)"
		   LR"(<div data-bundle-id="downloadcenter.components.content.dcPageContainer" class="dc-page-container container">)"
		   LR"(<div class="dc-page-container__body"><div class="dc-page-container__body--left-panel">)"
		   LR"(<div class="dc-page-available-downloads-hero">)"
		   LR"(<h1>Intel® Network Adapter Driver for Microsoft Windows 11*</h1>)"
		   LR"(<p>Intel requires an accepted license agreement in order to download this file.</p>)"
		   LR"(<textarea id="content-raw" class="license-modal-content_body_license-text-raw" tabindex="0"><html lang="en"><head><title>Intel Fixture License Agreement [v2030.01.02]</title></head><body><table><tbody><tr><td style="width: 50.0%;"><p><b>Fixture terms.</b></p><p>&quot;Alpha&quot; &amp; Beta &#169;</p></td><td><div>Second cell.<br />Final clause.</div></td></tr></tbody></table></body></html></textarea>)"
		   LR"(<h2>Available Downloads</h2>)"
		   LR"(<button class="dc-page-available-downloads-hero-button__cta" data-modal-id="1" data-href="https://downloadmirror.intel.com/900011/Wired_driver_31.2.2_x64.zip">Wired_driver_31.2.2_x64.zip</button>)"
		   LR"(<li>Windows 11 Family*</li><li>Size: 38.6 MB</li>)"
		   LR"(<li>SHA256: 2CBFF42AA02519E49F02D8E95A6572C44310E97FE67C42E299F2ABA6EA9344F5</li>)"
		   LR"(<h2>Detailed Description</h2><p><strong>Driver Package:</strong> Wired_driver_31.2.2_x64.zip</p>)"
		   LR"(<h2>This download is valid for the product(s) listed below.</h2><a>Intel® Ethernet Network Adapter E610-XT2</a>)"
		   LR"(</div><div data-bundle-id="downloadcenter.components.content.dcPageOtherValidProducts" class="dc-page-detailed-other-valid-products">)"
		   LR"(<h2 class="dc-page-detailed-other-valid-products__title">This download is valid for the product(s) listed below.</h2>)"
		   LR"(<ul class="dc-page-detailed-other-valid-products-panel">)"
		   LR"(<li class="dc-page-detailed-other-valid-products-panel__product"><a class="dc-page-detailed-other-valid-products-panel__product--fixed" href="/content/www/us/en/products/sku/900001/fixture-adapter/downloads.html">Fixture® Adapter X1</a></li>)"
		   LR"(</ul></div></div></div></div></main></body></html>)" ;
}

/** @brief 元通常goldenと同じ32 byteの値を表示用小文字hexへ変換します。 */
[[nodiscard]] std::string projectedFingerprintHex(
	const OfficialStableRecordFingerprint &fingerprint)
{
	constexpr std::string_view digits = "0123456789abcdef" ;	// 固定16進桁。
	std::string				   result ;							// URLではない32 byte識別子。
	result.reserve( fingerprint.bytes.size() * 2U) ;
	// 元byte順を変えず二桁ずつ追加します。
	for( const auto byte : fingerprint.bytes) {
		const auto value = std::to_integer<unsigned>( byte) ;	// 現byteの0～255値。
		result.push_back( digits[value >> 4U]) ;
		result.push_back( digits[value & 0xFU]) ;
	}

	return result ;
}
/** @brief 本番が使用する非所有の指紋関係とordinal解決を公開fieldごと検査します。 */
void projectedRelationChecks( TestContext &context)
{
	using collector_projection_detail::RecordRelation ;
	using collector_projection_detail::compareRecords ;
	using collector_projection_detail::resolveOrdinal ;
	OfficialCollectorRecordProjection prior ;	// 保存許可を持たない比較専用の公開値。
	prior.stableFingerprint.bytes.fill( std::byte{0x5a}) ;
	prior.parserId		  = L"parser" ;
	prior.parserRevision  = 1U ;
	prior.recordRoute	  = L"route" ;
	prior.recordKey		  = L"key" ;
	prior.productFamily	  = L"family" ;
	prior.driverCategory  = L"LAN" ;
	prior.operatingSystem = L"Windows 11" ;
	prior.architecture	  = OfficialDistributionArchitecture::WINDOWS_X64 ;
	prior.packageVersion  = L"1.0" ;
	prior.publishedDate	  = L"2026-09-29" ;
	prior.terms			  = OfficialDistributionTerms::ACCEPTANCE_REQUIRED ;
	prior.eulaRevision	  = L"revision" ;
	prior.dependencies	  = {L"first", L"second"} ;
	prior.payloads.push_back( {L"payload", 0U, OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE,
							  L"driver.zip", 123U, L"sha256", L"sha512", L"publisher",
							  L"application/zip"}) ;
	const auto original = prior ;	// 一field差分を独立させる元値。
	DRIVERCRATE_EXPECT( context, compareRecords( prior, L"slice", original, L"slice") ==
									RecordRelation::EQUIVALENT) ;
	auto distinct						= original ;	// 指紋が異なれば公開値が等しくても別record。
	distinct.stableFingerprint.bytes[0] = std::byte{0x5b} ;
	DRIVERCRATE_EXPECT( context, compareRecords( prior, L"slice", distinct, L"slice") ==
									RecordRelation::DISTINCT) ;
	DRIVERCRATE_EXPECT( context, compareRecords( prior, L"slice", original, L"other-slice") ==
									RecordRelation::CONFLICT) ;

	using Mutation = std::function<void( OfficialCollectorRecordProjection &)> ;
	const std::vector<std::pair<const char *, Mutation>> changedFields{
		{"parserId", []( auto &row) { row.parserId = L"different" ; }},
		{"parserRevision", []( auto &row) { row.parserRevision = 2U ; }},
		{"recordRoute", []( auto &row) { row.recordRoute = L"different" ; }},
		{"recordKey", []( auto &row) { row.recordKey = L"different" ; }},
		{"productFamily", []( auto &row) { row.productFamily = L"different" ; }},
		{"driverCategory", []( auto &row) { row.driverCategory = L"different" ; }},
		{"operatingSystem", []( auto &row) { row.operatingSystem = L"different" ; }},
		{"architecture",
		 []( auto &row) { row.architecture = static_cast<OfficialDistributionArchitecture>( 1U) ; }},
		{"packageVersion", []( auto &row) { row.packageVersion = L"different" ; }},
		{"publishedDate", []( auto &row) { row.publishedDate = L"different" ; }},
		{"terms", []( auto &row) { row.terms = OfficialDistributionTerms::CONFIRMED_NO_CONSENT ; }},
		{"eulaRevision", []( auto &row) { row.eulaRevision = L"different" ; }},
		{"dependenciesValue", []( auto &row) { row.dependencies[0] = L"different" ; }},
		{"dependenciesOrder",
		 []( auto &row) { std::swap( row.dependencies[0], row.dependencies[1]) ; }},
		{"payloadCount", []( auto &row) { row.payloads.push_back( row.payloads[0]) ; }},
		{"resourceId", []( auto &row) { row.payloads[0].resourceId = L"different" ; }},
		{"payloadOrdinal", []( auto &row) { row.payloads[0].payloadOrdinal = 1U ; }},
		{"kind",
		 []( auto &row) {
			 row.payloads[0].kind = OfficialDistributionPayloadKind::OFFICIAL_INSTALLER ;
		 }},
		{"fileDisplayName", []( auto &row) { row.payloads[0].fileDisplayName = L"other.zip" ; }},
		{"publishedSizeBytes", []( auto &row) { row.payloads[0].publishedSizeBytes = 124U ; }},
		{"publishedSha256", []( auto &row) { row.payloads[0].publishedSha256 = L"other" ; }},
		{"publishedSha512", []( auto &row) { row.payloads[0].publishedSha512 = L"other" ; }},
		{"publisher", []( auto &row) { row.payloads[0].publisher = L"other" ; }},
		{"expectedContentType",
		 []( auto &row) { row.payloads[0].expectedContentType = L"other/type" ; }},
	} ; // 一条件だけを変え、fingerprint byteは固定する。
	// 保存公開fieldの各差分を本番関係helperへ渡します。
	for( const auto &[name, mutate] : changedFields) {
		auto changed = original ;	// 成功recordやdigestをworkerへ注入しない。
		mutate( changed) ;
		context.expect( compareRecords( prior, L"slice", changed, L"slice") ==
						   RecordRelation::CONFLICT,
					   name, __FILE__, __LINE__) ;
	}

	const std::array<std::size_t, 3U> mapped{1U, 0U, 1U} ;	// 二ordinalが同一recordを参照。
	DRIVERCRATE_EXPECT( context, resolveOrdinal( 0U, mapped, 2U) == 1U &&
									resolveOrdinal( 1U, mapped, 2U) == 0U &&
									resolveOrdinal( 2U, mapped, 2U) == 1U) ;
	DRIVERCRATE_EXPECT( context,
					   !resolveOrdinal( 0U, {}, 2U) && !resolveOrdinal( 3U, mapped, 2U) &&
						   !resolveOrdinal( std::numeric_limits<std::uint32_t>::max(), mapped, 2U) &&
						   !resolveOrdinal( 0U, mapped, 0U)) ;
	const std::array<std::size_t, 2U> invalid{
		2U, std::numeric_limits<std::size_t>::max()} ;	// 二種類の参照先欠損。
	DRIVERCRATE_EXPECT( context,
					   !resolveOrdinal( 0U, invalid, 2U) && !resolveOrdinal( 1U, invalid, 2U)) ;
}

/** @brief 五つの汎用数値上限と実配列からの合計判定を検査します。 */
void projectedCountChecks( TestContext &context)
{
	using collector_projection_detail::CountResult ;
	using collector_projection_detail::checkCounts ;
	using collector_projection_detail::withinCountLimits ;
	constexpr auto maximum = std::numeric_limits<std::size_t>::max() ;	// 加算overflow入力。
	DRIVERCRATE_EXPECT( context, withinCountLimits( 0U, 0U, 0U, 0U, 0U) &&
									withinCountLimits( 16U, 32U, 16U, 3'000U, 16U)) ;
	// 一種類だけ上限を越える5条件と極大値を、成功条件とは独立に確認する。
	const std::array<std::array<std::size_t, 5U>, 10U> rejected{{
		{17U, 0U, 0U, 0U, 0U},
		{0U, 33U, 0U, 0U, 0U},
		{0U, 0U, 17U, 0U, 0U},
		{0U, 0U, 0U, 3'001U, 0U},
		{0U, 0U, 0U, 0U, 17U},
		{maximum, 0U, 0U, 0U, 0U},
		{0U, maximum, 0U, 0U, 0U},
		{0U, 0U, maximum, 0U, 0U},
		{0U, 0U, 0U, maximum, 0U},
		{0U, 0U, 0U, 0U, maximum},
	}} ;
	// 数値の上限超過を切詰め成功へしません。
	for( const auto &counts : rejected) {
		DRIVERCRATE_EXPECT(
			context, !withinCountLimits( counts[0], counts[1], counts[2], counts[3], counts[4])) ;
	}

	std::vector<CollectorProjectedRecord>	  records( 16U) ;	// 各record二payloadで合計32。
	std::vector<CollectorProjectedSliceScope> slices( 16U) ;	// 汎用件数だけの比較用。
	std::vector<CollectorProjectedEdge>		  edges( 3'000U) ;	// 現profileの成功応答ではない。
	// 公開値と観測側の件数を一致させて配列由来の境界を試す。
	for( auto &record : records) {
		record.value.payloads.resize( 2U) ;
		record.payloads.resize( 2U) ;
	}

	// 一edgeの参照配列にも独立上限を適用する。
	for( auto &edge : edges) {
		edge.recordFingerprints.resize( 16U) ;
	}

	DRIVERCRATE_EXPECT( context, checkCounts( records, slices, edges) == CountResult::WITHIN_LIMIT) ;
	// 17 record。
	records.emplace_back() ;
	DRIVERCRATE_EXPECT( context, checkCounts( records, slices, edges) == CountResult::LIMIT_EXCEEDED) ;
	records.pop_back() ;
	// 合計33 payload。
	records.front().value.payloads.emplace_back() ;
	records.front().payloads.emplace_back() ;
	DRIVERCRATE_EXPECT( context, checkCounts( records, slices, edges) == CountResult::LIMIT_EXCEEDED) ;
	records.front().value.payloads.pop_back() ;
	records.front().payloads.pop_back() ;
	// 17 slice。
	slices.emplace_back() ;
	DRIVERCRATE_EXPECT( context, checkCounts( records, slices, edges) == CountResult::LIMIT_EXCEEDED) ;
	slices.pop_back() ;
	// 3,001 edge。
	edges.emplace_back() ;
	DRIVERCRATE_EXPECT( context, checkCounts( records, slices, edges) == CountResult::LIMIT_EXCEEDED) ;
	edges.pop_back() ;
	// 一edge17参照。
	edges.front().recordFingerprints.emplace_back() ;
	DRIVERCRATE_EXPECT( context, checkCounts( records, slices, edges) == CountResult::LIMIT_EXCEEDED) ;
	edges.front().recordFingerprints.pop_back() ;
	// 二つのpayload配列長が異なる。
	records.front().payloads.pop_back() ;
	DRIVERCRATE_EXPECT( context, checkCounts( records, slices, edges) == CountResult::INVALID_SHAPE) ;
}

/** @brief 親prepare前後で全保存byteが不変か確認するため列挙します。
 * @param[in,out] context 集計。
 * @param[in,out] store 保護済みfixtureだけ。
 * @return 固定二directoryの相対名と元byte。
 */
std::map<std::wstring, std::string> projectedStoreSnapshot( TestContext				&context,
														   LocalCollectorStateStore &store)
{
	std::map<std::wstring, std::string> result ;	// 非保存境界の比較値。
	// 既知二directoryの実fileだけを読む。
	for( const bool runs : {false, true}) {
		std::vector<std::wstring> names ;	// 保護handle経由で列挙する。
		DRIVERCRATE_EXPECT(
			context, (runs ? store.listRunNames( names) : store.listCurrentNames( names)) == 0U) ;
		// 最大4096件の有限なfixture集合。
		for( const auto &name : names) {
			const std::wstring path =
				// 固定相対名。
				std::wstring( runs ? L"runs/" : L"current/") + name ;
			std::string body ;		// 元保存byte。
			bool		found{} ;	// 欠損は一致成功としない。
			DRIVERCRATE_EXPECT( context, store.read( path, body, found) == 0U && found) ;
			result.emplace( path, std::move( body)) ;
		}
	}

	return result ;
}

/** @brief 起動境界試験だけの固定段階と単調経過時間を出力します。
 * @note 親threadで借用し、元の処理を一回だけ呼びます。例外時のendや成功は補いません。
 */
class CacheStartupObservation final {
public:
	/** @brief 起動境界modeだけで有効な時計を作ります。
	 * @param[in] enabled 固定段階を出力する場合true。
	 */
	explicit CacheStartupObservation( const bool enabled)
		: enabled_( enabled), started_( enabled ? std::chrono::steady_clock::now()
											  : std::chrono::steady_clock::time_point{})
	{
	}

	/** @brief 元処理の直前にbeginをflushし、段階開始時計を返します。
	 * @param[in] stage 静的寿命の固定段階名。
	 * @param[in] generations 確定した世代数。準備前は0。
	 * @param[in] requests 確定した要求数。準備前は0。
	 * @return 段階の単調開始時計。無効時は既定値。
	 */
	[[nodiscard]] std::chrono::steady_clock::time_point begin( const char	   *stage,
															  const std::size_t generations,
															  const std::size_t requests) const
	{
		// 他の容量modeへ時計照会と追加出力を持ち込みません。
		if( !enabled_) {
			return {} ;
		}

		const auto now = std::chrono::steady_clock::now() ;	// flush前の観測時計。
		std::cout << "Cache startup stage=" << stage << " edge=begin generations=" << generations
				  << " requests=" << requests << " elapsedMs="
				  << std::chrono::duration_cast<std::chrono::milliseconds>( now - started_).count()
				  << " stageMs=0" << std::endl ;
		return now ;
	}

	/** @brief 実際に戻った元処理だけのendと確定数値をflushします。
	 * @param[in] stage beginと同じ固定段階名。
	 * @param[in] generations 確定した世代数。
	 * @param[in] requests 確定した要求数。
	 * @param[in] since 対応するbeginの単調時計。
	 * @param[in] code 元呼出しが返したcode。未観測時は不在。
	 * @param[in] items 元戻り値で確定した件数。未観測時は不在。
	 */
	void end( const char *stage, const std::size_t generations, const std::size_t requests,
			 const std::chrono::steady_clock::time_point since,
			 const std::optional<DWORD>					 code  = {},
			 const std::optional<std::size_t>			 items = {}) const
	{
		// 他modeの処理と結果表示は元のままにします。
		if( !enabled_) {
			return ;
		}

		const auto now = std::chrono::steady_clock::now() ;	// 元処理が戻った後の時計。
		std::cout << "Cache startup stage=" << stage << " edge=end generations=" << generations
				  << " requests=" << requests << " elapsedMs="
				  << std::chrono::duration_cast<std::chrono::milliseconds>( now - started_).count()
				  << " stageMs="
				  << std::chrono::duration_cast<std::chrono::milliseconds>( now - since).count() ;
		// 未観測のcodeを成功値で埋めません。
		if( code) {
			std::cout << " code=" << *code ;
		}

		// 元戻り値が持つ件数だけを出し、追加読取りを行いません。
		if( items) {
			std::cout << " items=" << *items ;
		}

		std::cout << std::endl ;
	}

	/** @brief 元条件式が到達した位置でsnapshotを一回だけ取得します。
	 * @param[in] stage 固定段階名。
	 * @param[in] generations 確定した世代数。
	 * @param[in] requests 確定した要求数。
	 * @param[in,out] context 元の検査集計。
	 * @param[in,out] store 元の保護fixture。
	 * @return 元snapshotの全相対名とbyte。出力には件数だけを使います。
	 */
	[[nodiscard]] std::map<std::wstring, std::string> snapshot(
		const char *stage, const std::size_t generations, const std::size_t requests,
		TestContext &context, LocalCollectorStateStore &store) const
	{
		const auto since = begin( stage, generations, requests) ;		// 元呼出し到達後だけの開始。
		auto	   value = projectedStoreSnapshot( context, store) ;	// 追加照会のない元一回分。
		end( stage, generations, requests, since, {}, value.size()) ;
		return value ;
	}

	/** @brief 元の初期化を一回だけ行い、そのcodeをそのまま返します。
	 * @param[in] stage 固定段階名。
	 * @param[in] generations 確定した世代数。
	 * @param[in] requests 確定した要求数。
	 * @param[in,out] recovery 元の監督object。
	 * @param[in,out] store 元の保護fixture。
	 * @param[in] definition 元の定義。
	 * @param[in] utcMillis 元の検査時計。単位はms。
	 * @return 元initializeProjectedのcode。
	 */
	[[nodiscard]] DWORD initialize( const char *stage, const std::size_t generations,
								   const std::size_t requests, LocalCollectorRecovery &recovery,
								   LocalCollectorStateStore					  &store,
								   const CollectorProjectedCampaignDefinition &definition,
								   const std::uint64_t						   utcMillis) const
	{
		const auto since = begin( stage, generations, requests) ;	// constructor後の元呼出し位置。
		const auto code =
			// 元codeを保持します。
			recovery.initializeProjected( store, definition, utcMillis, 0U) ;
		end( stage, generations, requests, since, code) ;
		return code ;
	}

private:
	/// 起動境界modeのときだけ追加観測を有効にする不変区分。
	const bool									enabled_ ;
	/// 初回fixture準備直前の単調時計。無効時は既定値。
	const std::chrono::steady_clock::time_point started_ ;
} ;

/** @brief 実hashを再計算した改変fixtureを保存します。
 * @param[in,out] context 集計。
 * @param[in,out] store 保護済みfixtureだけ。
 * @param[in] path 元fileの相対名。
 * @param[in] mutate 元本文を一要因変更するcallback。
 */
void mutateProjectedStore( TestContext &context, LocalCollectorStateStore &store,
						  const std::wstring &path, const std::function<void( JsonObject &)> &mutate)
{
	std::string stored ;	// 原envelope。
	bool		found{} ;	// 欠損で架空本文を補完しない。
	DRIVERCRATE_EXPECT( context, store.read( path, stored, found) == 0U && found) ;
	auto envelope = JsonObject::Parse( winrt::to_hstring( stored)) ;		// 試験対象の元包み。
	auto body	  = JsonObject::Parse( envelope.GetNamedString( L"body")) ;	// 元field順。
	mutate( body) ;
	const auto	 encoded = winrt::to_string( body.Stringify()) ;	// 改変後の実byte。
	std::wstring hash ;												// 正当なhashでも関係不一致で拒否する。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( encoded, hash) == 0U) ;
	envelope.Insert( L"body", JsonValue::CreateStringValue( body.Stringify())) ;
	envelope.Insert( L"sha256", JsonValue::CreateStringValue( hash)) ;
	DRIVERCRATE_EXPECT( context, store.write( path, winrt::to_string( envelope.Stringify())) == 0U) ;
}

/** @brief 読取り専用検証のfixtureへ元hash envelopeを保存します。
 * @param[in,out] context 親threadの集計。
 * @param[in,out] store 試験専用store。稼働保存経路ではありません。
 * @param[in] name 固定相対名。
 * @param[in] body 検査対象の元本文。
 */
void saveRegisteredHistoryFixture( TestContext &context, LocalCollectorStateStore &store,
								  const std::wstring &name, const std::string_view body)
{
	std::wstring hash ;	// 実本文hash。架空の検証済み値で代用しません。
	DRIVERCRATE_EXPECT( context, computeBytesSha256( body, hash) == 0U) ;
	JsonObject envelope ;	// 既存外側形式の試験保存。
	envelope.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-envelope-v1")) ;
	envelope.Insert( L"body", JsonValue::CreateStringValue( winrt::to_hstring( body))) ;
	envelope.Insert( L"sha256", JsonValue::CreateStringValue( hash)) ;
	DRIVERCRATE_EXPECT( context, store.write( name, winrt::to_string( envelope.Stringify())) == 0U) ;
}

/** @brief 元fake workerの観測から閉じた四role保存fixtureを作ります。
 * @param[in,out] context 親threadの集計。
 * @param[in,out] store 新規試験専用store。初期化済みです。
 * @param[in] definition 元二source定義。
 * @param[in] startDay 元予約JST日。
 * @param[in] utc 元予約UTC。
 * @param[in] scenario 0は完全二行、1は部分一行、2は元read失敗、3は予約だけ残して中断。
 * @param[in] prior 前回の全根拠context。初回はnull。
 * @return 同じ元保存入力へ結合した全job。
 * @note 稼働accept／commitを実装済みとするfixtureではありません。
 */
std::shared_ptr<const CollectorPreparedProjectedCampaign> makeRegisteredHistoryFixture(
	TestContext &context, LocalCollectorStateStore &store,
	const CollectorProjectedCampaignDefinition &definition, const std::wstring_view startDay,
	const std::uint64_t utc, const unsigned scenario,
	const CollectorRegisteredProjectedHistory *prior = nullptr)
{
	const auto identityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;								// 同じscopeだけで大きなfixtureを所有する。
	auto &identity = *identityOwner ;										// 実元manifestから生成します。
	std::shared_ptr<const CollectorPreparedProjectedCampaign> prepared ;	// workerと同じ不変入力。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, startDay, identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, prepared)) ;
	LocalCollectorRecovery recovery ;	// 通常初回予約・非保存prepareを共用します。
	DRIVERCRATE_EXPECT( context, recovery.initializeProjected( store, definition, utc, 0U) == 0U) ;
	const auto fixturesOwner =
		std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
	auto &fixtures	 = *fixturesOwner ;					// native factoryを呼ばない偽HTTP。
	fixtures[0].body = winrt::to_string( winrt::hstring( projectedIntelHtml())) ;
	fixtures[1].body = winrt::to_string( winrt::hstring( projectedAsusRowsHtml( 2U, scenario == 1U))) ;
	// 原read失敗を元I/Oのまま保存し、成功履歴を消さないことを検査します。
	if( scenario == 2U) {
		fixtures[1].failure = "read" ;
	}

	CollectorProjectedExecutorDependencies dependencies ;	// この関数内のfixtureだけを借用します。
	dependencies.campaign = prepared ;
	dependencies.clock	  = [utc] {
		   return activeFixture ? activeFixture->clock : CollectorHttpClockSample{utc, 0U} ;
	} ;
	dependencies.createClient = [] {
		return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
	} ;
	std::size_t next{} ;	// 親threadだけで更新します。
	dependencies.start = [&]( std::function<void()> worker) {
		const auto slot = next++ ;	// Threadへ所有copyするslot。
		return std::thread( [&, slot, worker = std::move( worker)] {
			fixtures[slot].ownerThread = std::this_thread::get_id() ;
			fixtures[slot].clock	   = {utc, 0U} ;
			FixtureScope scope( fixtures[slot]) ;	// Joinまで存続する所有fixture。
			worker() ;
		}) ;
	} ;
	LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 同じ予約の二worker。
	DRIVERCRATE_EXPECT( context,
					   executor.startNext( recovery) == 0U && executor.startNext( recovery) == 0U) ;
	const auto report = executor.join() ;	// 元所有結果を読む前に全joinします。
	DRIVERCRATE_EXPECT( context, report.joined == 2U && report.notified == 2U) ;
	const auto updateOwner = std::make_unique<
		CollectorProjectedPreparedUpdate>() ;	// 大きなfixtureを元scopeだけで所有します。
	auto &update = *updateOwner ;				// 通常初回親入口は非保存のままです。
	DRIVERCRATE_EXPECT( context, recovery.prepareInitialProjectedUpdate( executor, 1U, utc + 125000U,
																	   125000U, update) == 0U) ;
	const auto *oldJob = prepared->job( 1U) ;	// ASUSの全scopeを所有します。
	// 中断fixtureは稼働の元予約だけを残し、作った非保存候補を破棄します。
	if( scenario == 3U) {
		return prepared ;
	}

	// 既存履歴最終化を、検証済みcontextの元byteへ接続した試験fixtureだけに使います。
	if( prior) {
		const auto finalizedOwner = std::make_unique<
			CollectorProjectedHistoryFinalization>() ;	// 大きなfixtureを元scopeだけで所有します。
		auto &finalized = *finalizedOwner ;				// 旧成功との減少を再計算します。
		DRIVERCRATE_EXPECT( context, finalizeCollectorProjectedHistory( *oldJob, *executor.result( 1U),
																	  utc + 125000U,
																	  prior->slices(), finalized)
											.status == collector_projected_json::Status::OK) ;
		DRIVERCRATE_EXPECT( context, encodeCollectorProjectedResponse(
										oldJob->value(), finalized.response, update.response)
											.result.status == collector_projected_json::Status::OK) ;
		CollectorProjectedCache cache ;	// 旧成功保持とvalidator解除を含む次値。
		DRIVERCRATE_EXPECT( context,
						   deriveCollectorProjectedCache( oldJob->value(), update.response.envelope,
														 &prior->cache(), cache)
								   .status == collector_projected_json::Status::OK) ;
		DRIVERCRATE_EXPECT( context, encodeCollectorProjectedCache( cache, update.cache).status ==
											collector_projected_json::Status::OK &&
										computeBytesSha256( update.cache, update.cacheSha256) == 0U) ;
	}

	const auto	&value = update.response.value ;	// 元v4を保ったまま四roleを試験保存します。
	std::wstring op ;								// 稼働と同じ元G／job算法。
	DRIVERCRATE_EXPECT( context,
					   computeBytesSha256( "response-v2\n" + winrt::to_string( value.generation) +
											  "\n" + winrt::to_string( value.job) + "\n",
										  op) == 0U) ;
	const auto stateName =
		L"current/campaign-state-v3-" + identity.generationKey + L".json" ;	// 固定世代名。
	const std::array<std::wstring, 3U> destinations = {
		L"current/campaign-controls-v1.json", stateName,
		L"current/campaign-budget-v1.json"} ;										// 三role。
	const std::array<std::wstring, 3U> roles = {L"control", L"job", L"budget"} ;	// Effectの固定順。
	std::array<std::string, 3U>		   before ;										// 同じ予約後の更新前像。
	// 原予約の全三roleを保存前に読み取ります。
	for( std::size_t role = 0U; role < 3U; ++role) {
		before[role] = httpSavedBody( store, destinations[role]) ;
	}

	const auto controlOwner =
		std::make_unique<CollectorWaitSnapshot>() ;	// 大きなfixtureを元scopeだけで所有します。

	auto	  &control = *controlOwner ;	// 元開始intentと待機。
	const auto settledOwner =
		std::make_unique<CollectorWaitSnapshot>() ;	// 大きなfixtureを元scopeだけで所有します。
	auto &settled = *settledOwner ;					// 同じ元I/Oで導出した待機更新後像。
	DRIVERCRATE_EXPECT(
		context,
		parseCollectorWaitSnapshot( before[0], control) &&
			prepareCollectorWaitSettlement(
				control,
				{oldJob->value().source.rateLimitGroup, value.request, value.generation, value.job},
				{value.state == CollectorMetadataOutcome::FETCHED, value.status, value.retryAfter,
				 value.review, value.challenge},
				value.started, value.finished, value.accepted, value.accepted, false, settled)) ;
	std::array<std::string, 3U> after ;	// 全更新後本文。
	DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( settled, after[0])) ;
	auto state = JsonObject::Parse( winrt::to_hstring( before[1])) ;	// 当該行だけを終端へ変更します。
	auto row   = state.GetNamedArray( L"jobs").GetObjectAt( 1U) ;		// 元ASUS行。
	row.Insert( L"state", JsonValue::CreateStringValue(
							 value.state == CollectorMetadataOutcome::FETCHED ? L"FETCHED"
							 : value.state == CollectorMetadataOutcome::HELD  ? L"HELD"
																			  : L"FAILED")) ;
	row.Insert( L"response", JsonValue::CreateStringValue( update.response.responseSha256)) ;
	row.Insert( L"operation", JsonValue::CreateStringValue( op)) ;
	after[1] = winrt::to_string( state.Stringify()) ;
	const auto budgetOwner =
		std::make_unique<CollectorBudgetSnapshot>() ;	// 同じscopeだけで大きなfixtureを所有する。
	auto &budget = *budgetOwner ;						// 未精算の最大予約。
	DRIVERCRATE_EXPECT( context, parseCollectorBudgetSnapshot( before[2], budget)) ;
	// 元Gとjobの一予約だけを観測量で精算します。
	for( auto &reservation : budget.reservations) {
		// 別workerの未精算予約を勝手に終了させません。
		if( reservation.campaign == value.generation && reservation.job == value.job) {
			reservation.phase	= 1U ;
			reservation.charged = value.bytes.value_or( reservation.maximum) ;
		}
	}

	budget.lastUtc = std::max( budget.lastUtc, value.accepted / 1000U) ;
	DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( budget, after[2])) ;
	// 各四roleの元更新前後像を試験専用storeへ保存します。
	for( std::size_t role = 0U; role < 3U; ++role) {
		saveRegisteredHistoryFixture(
			context, store, L"runs/campaign-effect-v2-" + op + L"-before-" + roles[role] + L".json",
			before[role]) ;
		saveRegisteredHistoryFixture(
			context, store, L"runs/campaign-effect-v2-" + op + L"-" + roles[role] + L".json",
			after[role]) ;
		saveRegisteredHistoryFixture( context, store, destinations[role], after[role]) ;
	}

	// 初回はbefore-CACHEが不在であることも検査対象です。
	if( prior) {
		std::string priorBody ;	// 検証した前回CACHEを同じcanonical codecで固定します。
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorProjectedCache( prior->cache(), priorBody).status ==
							   collector_projected_json::Status::OK) ;
		saveRegisteredHistoryFixture(
			context, store, L"runs/campaign-effect-v2-" + op + L"-before-cache.json", priorBody) ;
	}

	saveRegisteredHistoryFixture( context, store, L"runs/campaign-effect-v2-" + op + L"-cache.json",
								 update.cache) ;
	saveRegisteredHistoryFixture(
		context, store, L"current/campaign-cache-v1-" + value.request + L".json", update.cache) ;
	DRIVERCRATE_EXPECT( context, store.write( L"runs/campaign-response-v4-" + op + L".json",
											update.response.envelope) == 0U) ;
	auto	   root = JsonObject::Parse( winrt::to_hstring(
		  // 最新登録だけを追加します。
		  httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
	JsonObject cacheRegistration ;	// 実hashへ結合した登録。
	cacheRegistration.Insert( L"request", JsonValue::CreateStringValue( value.request)) ;
	cacheRegistration.Insert( L"hash", JsonValue::CreateStringValue( update.cacheSha256)) ;
	root.GetNamedArray( L"cacheInventory").Append( cacheRegistration) ;
	root.Insert( L"lastUtcMillis",
				JsonValue::CreateNumberValue( static_cast<double>( value.accepted))) ;
	saveRegisteredHistoryFixture( context, store, L"current/campaign-root-v2.json",
								 winrt::to_string( root.Stringify())) ;
	DRIVERCRATE_EXPECT( context, fixtures[0].calls["send"] == 1U && fixtures[1].calls["send"] == 1U) ;
	return prepared ;
}

/** @brief 元workerから初回v4保存入口を通す非通信fixtureです。
 * @param[in,out] context 集計。
 * @param[in,out] store 新規fixtureの保護store。
 * @param[in] definition 固定二source定義。
 * @param[in] prepared 元入力の所有scope。
 * @param[in] scenario 完全0、部分1、read失敗2、空3、上限4、親hash縮退5、応答hash拒否6、OOM7、一行8。
 * @param[in] stop 保存窓の任意停止。正常時は空。
 * @param[out] expected 独立最終化した二workerの原v4。親hash縮退以外のbyte比較用。
 * @param[in] utc 元世代の固定予約UTC。従来呼出しは元試験時計を維持します。
 * @param[out] workers 任意の所有結果copy。履歴付き組立fixtureでだけ使用します。
 * @return ASUS初回保存の元結果。正常時は続けてIntelも保存します。
 * @throws std::runtime_error 元worker欠損時は失敗EXPECTを保持してfixtureを停止します。
 */
DWORD initialProjectedStorageFixture(
	TestContext &context, LocalCollectorStateStore &store,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared,
	const unsigned scenario, const std::function<bool( CollectorRecoveryCheckpoint)> &stop,
	std::array<CollectorProjectedResponseBytes, 2U> &expected,
	const std::uint64_t								 utc	 = HTTP_TEST_UTC,
	std::array<CollectorProjectedWorkerResult, 2U>	*workers = nullptr)
{
	LocalCollectorRecovery recovery ;	// 通常保存・回復の親監督。
	DRIVERCRATE_EXPECT( context,
					   recovery.initializeProjected( store, definition, utc, 0U, stop) == 0U) ;
	const auto fixturesOwner =
		std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
	auto &fixtures	 = *fixturesOwner ;					// 実native factoryなしの所有worker依存。
	fixtures[0].body = winrt::to_string( winrt::hstring( projectedIntelHtml())) ;
	fixtures[1].body = winrt::to_string( winrt::hstring( projectedAsusRowsHtml( scenario == 3U	  ? 0U
																			 : scenario == 4U ? 17U
																			 : scenario == 8U ? 1U
																							  : 2U,
																			 scenario == 1U))) ;
	// 原通信失敗を親成功へ変換しません。
	if( scenario == 2U) {
		fixtures[1].failure = "read" ;
	}

	CollectorProjectedExecutorDependencies dependencies ;	// Joinまでこの関数が依存を所有します。
	dependencies.campaign = prepared ;
	dependencies.clock	  = [utc] {
		   return activeFixture ? activeFixture->clock : CollectorHttpClockSample{utc, 0U} ;
	} ;
	dependencies.createClient = [] {
		return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
	} ;
	std::size_t next{} ;	// Parent writerだけで更新します。
	dependencies.start = [&]( std::function<void()> worker) {
		const auto slot = next++ ;	// Threadへ所有copyします。
		return std::thread( [&, slot, worker = std::move( worker)] {
			fixtures[slot].ownerThread = std::this_thread::get_id() ;
			fixtures[slot].clock	   = {utc, 0U} ;
			FixtureScope scope( fixtures[slot]) ;	// Thread別fake APIだけを借用します。
			worker() ;
		}) ;
	} ;
	LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 元予約と全所有結果。
	DRIVERCRATE_EXPECT( context,
					   executor.startNext( recovery) == 0U && executor.startNext( recovery) == 0U) ;
	const auto report = executor.join() ;	// 保存前に全threadを回収します。
	DRIVERCRATE_EXPECT( context, report.error == 0U && report.joined == 2U && report.reserved == 2U) ;
	// 正答や任意DTOを保存入口へ渡さず、元workerから独立に比較byteだけ生成します。
	for( std::size_t slot = 0U; slot < 2U; ++slot) {
		const auto *worker = executor.result( slot) ;	// 同じ元所有観測。
		DRIVERCRATE_EXPECT( context, worker && worker->io.sealed && worker->io.nativeReleased) ;
		// 元の失敗EXPECTを保持し、欠損結果の派生null参照ではなくfixture失敗で停止します。
		if( !worker) {
			throw std::runtime_error( "initial projected storage worker missing") ;
		}

		// Join済みcopyだけを組立fixtureへ渡し、稼働保存の結果注入には使いません。
		if( workers && worker) {
			(*workers)[slot] = *worker ;
		}

		const auto finalizedOwner = std::make_unique<
			CollectorProjectedHistoryFinalization>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto &finalized = *finalizedOwner ;	// 保存権を持たない比較値。
		DRIVERCRATE_EXPECT( context, finalizeCollectorProjectedHistory( *prepared->job( slot), *worker,
																	  utc + 125000U, {}, finalized)
											.status == collector_projected_json::Status::OK) ;
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorProjectedResponseWithFallback(
							   prepared->job( slot)->value(), finalized.response, expected[slot])
								   .result.status == collector_projected_json::Status::OK) ;
	}

	const auto before = projectedStoreSnapshot( context, store) ;	// 準備失敗時の非保存比較。
	const auto probe  = [scenario]( CollectorProjectedHashStage stage) -> std::int32_t {
		 // OOMでは縮退成功へ変換しません。
		 if( scenario == 7U) {
			 throw std::bad_alloc{} ;
		 }

		 return ((scenario == 5U && stage == CollectorProjectedHashStage::METADATA) ||
				 (scenario == 6U && stage == CollectorProjectedHashStage::RESPONSE))
					? E_ACCESSDENIED
					: 0 ;
	} ; // 成功は必ず本番CNGです。
	const auto accepted =
		recovery.acceptInitialProjected( executor, 1U, utc + 125000U, 125000U,
										probe) ;	// ASUSを先に保存しjob順と完了順を分けます。
	// 正常終了だけで次slotを保存します。部分・失敗応答も保存成功とは区別します。
	if( accepted == 0U) {
		DRIVERCRATE_EXPECT(
			context, recovery.acceptInitialProjected( executor, 0U, utc + 125000U, 125000U) == 0U &&
						 recovery.terminalJobs() == 2U) ;
		const auto complete = projectedStoreSnapshot( context, store) ;	// 二度目保存前の全byte。
		DRIVERCRATE_EXPECT( context, recovery.acceptInitialProjected( executor, 1U, utc + 125000U,
																	125000U) == ERROR_INVALID_DATA) ;
		DRIVERCRATE_EXPECT( context, complete == projectedStoreSnapshot( context, store)) ;
	} else {
		const auto failed =
			// 第一失敗を保存物とともに保持します。
			projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT( context, recovery.lastError() == accepted &&
										recovery.acceptInitialProjected( executor, 0U, utc + 126000U,
																		126000U) == accepted) ;
		DRIVERCRATE_EXPECT( context, failed == projectedStoreSnapshot( context, store)) ;
		// Hash／OOMの準備拒否では応答もeffectも保存しません。
		if( scenario == 6U || scenario == 7U) {
			DRIVERCRATE_EXPECT( context, before == failed &&
											accepted == (scenario == 6U
															 ? static_cast<DWORD>( E_ACCESSDENIED)
															 : static_cast<DWORD>( E_OUTOFMEMORY))) ;
		}
	}

	DRIVERCRATE_EXPECT( context, fixtures[0].calls["send"] == 1U &&
									fixtures[1].calls["send"] == 1U &&
									// 保存・回復は追加HTTPなし。
									executor.join().joined == 2U) ;
	return accepted ;
}

/** @brief 初回v4成功・全保存窓・再起動一回精算を確認します。
 * @param[in,out] context 集計。
 * @param[in] rootFactory 試験専用の新保護store。
 * @param[in] definition 二sourceの固定定義。
 * @param[in] prepared 同じ元入力から構築済みの所有job。
 */
void initialProjectedStorageChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	std::map<std::wstring, std::string> complete ;				// 正常二slotの全byteを改変試験へ固定します。
	std::array<CollectorProjectedResponseBytes, 2U> original ;	// 原workerから独立生成した比較値。
	std::map<std::wstring, std::string> registered ;			// 未反映のroot登録窓を改変試験へ固定します。
	// 完全・部分・原失敗・非採用・上限・親hash縮退と保存前の第一hash／OOMを分けます。
	for( unsigned scenario = 0U; scenario < 8U; ++scenario) {
		LocalCollectorStateStore store ;	// 各条件を独立した保護fixtureへ保存します。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		std::array<CollectorProjectedResponseBytes, 2U> expected ;	// 元workerの独立比較byte。
		const auto										accepted =
			initialProjectedStorageFixture( context, store, definition, prepared, scenario, {},
										   expected) ;	// 通常公開保存入口を通します。
		DRIVERCRATE_EXPECT( context, scenario < 6U ? accepted == 0U : accepted != 0U) ;
		{										// 一回目のwriter借用を解放してから二度目の再起動を検査します。
			LocalCollectorRecovery recovered ;	// 再起動時は元応答なしだけをv2中断へ戻します。
			const auto			   reopened =	// 元数値を診断へ保持します。
				recovered.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U, 0U) ;
			context.expect( reopened == 0U && recovered.terminalJobs() == 2U,
						   "initial storage scenario=" + std::to_string( scenario) +
							   " recovery=" + std::to_string( reopened),
						   __FILE__, __LINE__) ;
			// 不成立storeを成功のように後続parseしません。
			if( reopened != 0U) {
				continue ;
			}

			// 原workerから生成したresponseと保存byteをsource別に比較します。
			for( std::size_t index = 0U; index < 2U; ++index) {
				std::wstring op ;	// 本番と同じ操作key。
				DRIVERCRATE_EXPECT(
					context,
					computeBytesSha256(
						"response-v2\n" + winrt::to_string( expected[index].value.generation) +
							"\n" + winrt::to_string( expected[index].value.job) + "\n",
						op) == 0U) ;
				// Hash縮退は別応答を保存するためこの比較を成功へ補完しません。
				if( scenario < 5U) {
					std::string raw ;		// 再起動後も原byteで比較します。
					bool		found{} ;	// 不在を空で補完しません。
					DRIVERCRATE_EXPECT( context,
									   store.read( L"runs/campaign-response-v4-" + op + L".json",
												  raw, found) == 0U &&
										   found && raw == expected[index].envelope) ;
				}
			}

			CollectorBudgetSnapshot budget ;	// 実受信量と未観測の最大量を区別します。
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 httpSavedBody( store, L"current/campaign-budget-v1.json"), budget) &&
							 budget.reservations.size() == 2U) ;
			// 予約の元byteを0へ丸めず、応答の有無と同じphaseへ精算します。
			for( std::size_t index = 0U; index < budget.reservations.size(); ++index) {
				DRIVERCRATE_EXPECT( context,
								   budget.reservations[index].phase == (scenario < 6U ? 1U : 2U)) ;
				// 親縮退後も元I/Oのbyteを使います。
				if( scenario < 6U) {
					DRIVERCRATE_EXPECT( context, budget.reservations[index].charged ==
													expected[index].value.bytes.value_or(
														budget.reservations[index].maximum)) ;
				}
			}

			std::shared_ptr<const CollectorRegisteredProjectedHistory>
				history ;	// 稼働保存を読取り閉包へ結合します。
			DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
											store, *prepared->job( 1U), definition.sources,
											HTTP_TEST_UTC + 126000U, history) == 0U &&
											history) ;
			// 型だけの成功ではなく採用参照を確認します。
			if( history) {
				DRIVERCRATE_EXPECT(
					context, history->operations() == 1U &&
								 history->cache().slices.size() == (scenario < 2U ? 1U : 0U) &&
								 history->cache().original200.has_value() == (scenario == 0U)) ;
			}
		}
		const auto after = projectedStoreSnapshot( context, store) ;	// 再読込で精算を繰り返しません。
		LocalCollectorRecovery again ;									// 同じUTCでroot時刻も変えません。
		DRIVERCRATE_EXPECT( context, again.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U &&
										after == projectedStoreSnapshot( context, store)) ;
		// 完全成功だけを独立改変試験の基準へ保存します。
		if( scenario == 0U) {
			complete = after ;
			original = expected ;
		}
	}

	const std::array<std::pair<CollectorRecoveryCheckpoint, unsigned>, 15U> windows = {
		{{CollectorRecoveryCheckpoint::RESPONSE, 1U},
		 {CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT, 1U},
		 {CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT, 2U},
		 {CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT, 3U},
		 {CollectorRecoveryCheckpoint::PROJECTED_EFFECT, 1U},
		 {CollectorRecoveryCheckpoint::PROJECTED_EFFECT, 2U},
		 {CollectorRecoveryCheckpoint::PROJECTED_EFFECT, 3U},
		 {CollectorRecoveryCheckpoint::PROJECTED_EFFECT, 4U},
		 {CollectorRecoveryCheckpoint::EFFECTS, 1U},
		 {CollectorRecoveryCheckpoint::REGISTERED, 1U},
		 {CollectorRecoveryCheckpoint::APPLIED, 1U},
		 {CollectorRecoveryCheckpoint::APPLIED, 2U},
		 {CollectorRecoveryCheckpoint::APPLIED, 3U},
		 {CollectorRecoveryCheckpoint::APPLIED, 4U},
		 {CollectorRecoveryCheckpoint::COMPLETED, 1U}}} ;	// 応答先行の全固定保存窓。
	// 各異なる保存prefixを独立に一度ずつ観測します。
	for( std::size_t index = 0U; index < windows.size(); ++index) {
		LocalCollectorStateStore store ;	// 全窓を独立fixtureで観測します。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		unsigned   observed{} ;	// 指定checkpointだけの回数。
		const auto stop = [&]( CollectorRecoveryCheckpoint point) {
			return point == windows[index].first && ++observed == windows[index].second ;
		} ; // Parent受領の一回だけを明示停止します。
		std::array<CollectorProjectedResponseBytes, 2U> expected ;	// 原byteの固定比較値。
		DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition,
																   prepared, 0U, stop, expected) ==
										ERROR_OPERATION_ABORTED) ;
		// 登録済みcommitの全像検査を、正常回復とは別に確認します。
		if( index == 9U) {
			registered = projectedStoreSnapshot( context, store) ;
		}

		{										// 再起動fixtureは同時に二つのwriterを借用しません。
			LocalCollectorRecovery recovered ;	// 追加worker／GETなしの回復。
			const auto			   result =		// 回復の元結果を保持します。
				recovered.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U, 0U) ;
			context.expect( result == 0U && recovered.terminalJobs() == 2U,
						   "initial storage window=" + std::to_string( index) +
							   " recovery=" + std::to_string( result),
						   __FILE__, __LINE__) ;
			// 拒否を後続の架空成功parseへ流しません。
			if( result != 0U) {
				continue ;
			}

			CollectorBudgetSnapshot budget ;	// 保存済みASUSは観測量、未保存Intelは最大量。
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 httpSavedBody( store, L"current/campaign-budget-v1.json"), budget) &&
							 budget.reservations.size() == 2U) ;
			DRIVERCRATE_EXPECT(
				context, budget.reservations[0].phase == 2U &&
							 budget.reservations[0].charged == budget.reservations[0].maximum &&
							 budget.reservations[1].phase == 1U &&
							 budget.reservations[1].charged == *expected[1].value.bytes) ;
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
				history ;	// 成功を中断へ上書きしません。
			DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
											store, *prepared->job( 1U), definition.sources,
											HTTP_TEST_UTC + 126000U, history) == 0U &&
											history &&
											history->cache().attempt.response ==
												expected[1].responseSha256 &&
											history->cache().original200) ;
		}
		const auto settled = projectedStoreSnapshot( context, store) ;	// 二度目は完全byte不変。
		LocalCollectorRecovery again ;									// 同じUTCで二重適用を拒否します。
		DRIVERCRATE_EXPECT( context, again.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U &&
										settled == projectedStoreSnapshot( context, store)) ;
	}

	std::wstring op ;	// 正常ASUS操作の固定key。
	DRIVERCRATE_EXPECT( context,
					   computeBytesSha256( "response-v2\n" +
											  winrt::to_string( original[1].value.generation) +
											  "\n" + winrt::to_string( original[1].value.job) + "\n",
										  op) == 0U &&
						   !complete.empty()) ;
	// 欠損・三version併存・独立関係改変を元CNG hash再計算付きで確認します。
	for( unsigned mode = 0U; mode < 13U; ++mode) {
		LocalCollectorStateStore store ;	// 正常保存の全byteから一要因だけ変えます。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto missing = mode == 0U	  ? L"runs/campaign-response-v4-" + op + L".json"
							 : mode == 1U ? L"runs/campaign-effect-v2-" + op + L"-cache.json"
							 : mode == 2U
								 ? L"runs/campaign-effect-v2-" + op + L"-before-budget.json"
								 : std::wstring{} ;	// 実欠損。
		// 保護storeに存在した元保存物だけを複製します。
		for( const auto &entry : complete) {
			// 欠損を空fileへ置換しません。
			if( entry.first != missing) {
				DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
			}
		}

		// 有効外側envelopeでも同Oの旧保存名併存を拒否します。
		if( mode == 3U || mode == 4U) {
			DRIVERCRATE_EXPECT(
				context, store.write( std::wstring( mode == 3U ? L"runs/campaign-response-v2-"
															 : L"runs/campaign-response-v3-") +
										 op + L".json",
									 original[1].envelope) == 0U) ;
		}

		// 変更前CACHEの未知名は履歴あり初回へ変換しません。
		if( mode == 5U) {
			DRIVERCRATE_EXPECT( context,
							   store.write( L"runs/campaign-effect-v2-" + op + L"-before-cache.json",
										   original[1].envelope) == 0U) ;
		}

		// 元responseの関係違反は外側hashだけを合わせても専用codecで拒否します。
		if( mode == 6U || mode == 7U) {
			mutateProjectedStore( context, store, L"runs/campaign-response-v4-" + op + L".json",
								 [mode]( JsonObject &value) {
									 value.Insert(
										 mode == 6U ? L"request" : L"projection",
										 JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
								 }) ;
		}

		// Terminal開始intent、元前後像、登録hashをそれぞれ独立に変えます。
		if( mode >= 8U) {
			const auto name =
				mode == 8U	  ? L"current/campaign-state-v3-" + prepared->generationKey() + L".json"
				: mode == 9U  ? L"runs/campaign-effect-v2-" + op + L"-budget.json"
				: mode == 10U ? L"runs/campaign-effect-v2-" + op + L"-before-control.json"
				: mode == 11U
					? L"current/campaign-root-v2.json"
					: L"current/campaign-cache-v1-" + prepared->job( 1U)->value().requestKey +
						  L".json" ;	// 固定対象名。
			mutateProjectedStore( context, store, name, [mode]( JsonObject &value) {
				// 型を維持した別scopeのintentを拒否します。
				if( mode == 8U) {
					value.GetNamedArray( L"jobs").GetObjectAt( 1U).GetNamedObject( L"intent").Insert(
						L"scope", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 保存本文と不一致のCACHE登録を拒否します。
				if( mode == 11U) {
					value.GetNamedArray( L"cacheInventory")
						.GetObjectAt( 0U)
						.Insert( L"hash", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 元像または現CACHEのschemaを個別に変更します。
				if( mode == 9U || mode == 10U || mode == 12U) {
					value.Insert( L"schema", JsonValue::CreateStringValue( L"fixture-wrong-schema")) ;
				}
			}) ;
		}

		const auto before = projectedStoreSnapshot( context, store) ;	// 拒否前後の全rawを比較します。
		LocalCollectorRecovery recovered ;								// 自動補修・精算・追加GETをしません。
		const auto error = recovered.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U,
														 0U) ;	// 第一error。
		context.expect( error != 0U, "initial stored mutation=" + std::to_string( mode), __FILE__,
					   __LINE__) ;
		DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store)) ;
	}

	// 登録後の欠損／独立関係違反と不連続prefixは共有file変更より先に拒否します。
	for( unsigned mode = 0U; mode < 6U; ++mode) {
		LocalCollectorStateStore store ;	// 未反映の全四roleがある元byteから複製します。
		DRIVERCRATE_EXPECT( context,
						   store.initialize( rootFactory(), true) == 0U && !registered.empty()) ;
		const auto missing = mode == 0U ? L"runs/campaign-effect-v2-" + op + L"-cache.json"
										: std::wstring{} ;	// 登録後欠損。
		// 固定元保存集合だけを保護storeへ複製します。
		for( const auto &entry : registered) {
			// 登録後の欠損は準備前の作成可能窓に読み替えません。
			if( entry.first != missing) {
				DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
			}
		}

		// CONTROLなしでCACHEだけ、JOBなしでBUDGETだけを反映する逆順prefixを拒否します。
		if( mode == 1U || mode == 2U) {
			const auto role = mode == 1U ? L"cache" : L"budget" ;	// 固定二role。
			saveRegisteredHistoryFixture(
				context, store,
				mode == 1U ? L"current/campaign-cache-v1-" + prepared->job( 1U)->value().requestKey +
								 L".json"
						   : L"current/campaign-budget-v1.json",
				httpSavedBody( store, L"runs/campaign-effect-v2-" + op + L"-" + role + L".json")) ;
		}

		// CACHE後像と登録hashを同時に変更しても元応答からの再導出で拒否します。
		if( mode == 3U) {
			const auto name =
				L"runs/campaign-effect-v2-" + op + L"-cache.json" ;	// 固定immutable後像。
			mutateProjectedStore( context, store, name, []( JsonObject &cache) {
				cache.Insert( L"etag", JsonValue::CreateStringValue( L"\"fixture-other-tag\"")) ;
			}) ;
			std::wstring changed ;	// 改変本文の実hashも正しく計算します。
			DRIVERCRATE_EXPECT( context,
							   computeBytesSha256( httpSavedBody( store, name), changed) == 0U) ;
			mutateProjectedStore( context, store, L"current/campaign-root-v2.json",
								 [&]( JsonObject &root) {
									 root.GetNamedObject( L"commit")
										 .GetNamedArray( L"effects")
										 .GetObjectAt( 1U)
										 .Insert( L"after", JsonValue::CreateStringValue( changed)) ;
								 }) ;
		}

		// 旧kindへの格下げと原response hash差替えを分けます。
		if( mode == 4U || mode == 5U) {
			mutateProjectedStore( context, store, L"current/campaign-root-v2.json",
								 [mode]( JsonObject &root) {
									 root.GetNamedObject( L"commit").Insert(
										 mode == 4U ? L"kind" : L"response",
										 JsonValue::CreateStringValue(
											 mode == 4U ? L"RESPONSE" : std::wstring( 64U, L'f'))) ;
								 }) ;
		}

		const auto before = projectedStoreSnapshot( context, store) ;	// 拒否は全保存byte不変です。
		LocalCollectorRecovery recovered ;								// 更新後像の自動補完をしません。
		const auto			   result = recovered.initializeProjected(
			store, definition, HTTP_TEST_UTC + 126000U, 0U) ;	// 元回復errorを保持します。
		context.expect( result != 0U, "initial registered mutation=" + std::to_string( mode),
					   __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store)) ;
	}
}

/** @brief 初回完了の固定分母・五保存窓・欠損／改変と追加容量を検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立した保護fixture root。
 * @param[in] definition 元二source定義。
 * @param[in] prepared 所有workerへ渡す固定入力。
 */
void generationCompletionChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	std::map<std::wstring, std::string> base ;			// 初回成功保存の元fixture全byte。
	std::map<std::wstring, std::string> complete ;		// 完了登録後の全byte。
	std::map<std::wstring, std::string> intentOnly ;	// 固定intentだけ保存した準備窓。
	std::wstring						generation ;	// 同じfixtureを複製して全窓を原byte比較します。
	// 元所有workerの八条件を完了し、失敗／保留も対象分母へ残します。
	for( unsigned scenario = 0U; scenario < 8U; ++scenario) {
		LocalCollectorStateStore store ;	// 実GETなしの独立保護root。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		std::array<CollectorProjectedResponseBytes, 2U> expected ;	// 元応答の独立byte。
		const auto										accepted =
			initialProjectedStorageFixture( context, store, definition, prepared, scenario, {},
										   expected) ;	// 失敗時は次の初期化が中断回収します。
		DRIVERCRATE_EXPECT( context, scenario < 6U ? accepted == 0U : accepted != 0U) ;
		LocalCollectorRecovery recovery ;	// 前のfixture監督は既に借用解放済みです。
		DRIVERCRATE_EXPECT( context, recovery.initializeProjected(
										store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
										recovery.terminalJobs() == 2U) ;
		const auto before =
			// 精算や応答の変更を検出します。
			projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT( context,
						   recovery.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
		const auto g	   = recovery.generationKey() ;	// 正常Gからだけ完了名を導出します。
		const auto summary = JsonObject::Parse( winrt::to_hstring(
			httpSavedBody( store,
						  L"runs/campaign-summary-v1-" + g + L".json"))) ;	// 実保存された集計。
		const auto shard   = JsonObject::Parse( winrt::to_hstring(
			  httpSavedBody( store,
							L"runs/campaign-targets-v1-" + g + L".json"))) ;	// 元target順の全行。
		DRIVERCRATE_EXPECT( context, summary.GetNamedNumber( L"targetCount") == 27.0 &&
										summary.GetNamedNumber( L"jobCount") == 2.0 &&
										shard.GetNamedArray( L"targets").Size() == 27U &&
										summary.GetNamedNumber( L"metadataMatchedTargets") ==
											(scenario < 2U ? 1.0 : 0.0) &&
										summary.GetNamedNumber( L"metadataUnknownTargets") ==
											(scenario < 2U ? 26.0 : 27.0) &&
										summary.GetNamedNumber( L"matchedRecordReferences") ==
											(scenario == 0U	  ? 2.0
											 : scenario == 1U ? 1.0
															  : 0.0) &&
										summary.GetNamedNumber( L"unsupportedTargets") == 0.0 &&
										summary.GetNamedBoolean( L"researchOnly") &&
										!summary.GetNamedBoolean( L"publishable") &&
										!summary.GetNamedBoolean( L"downloadEligible")) ;
		const auto	 root = JsonObject::Parse( winrt::to_hstring(
			  // 登録も同じsummaryへ結合。
			  httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
		std::wstring summaryHash ;	// 保存本文の実SHAです。
		DRIVERCRATE_EXPECT(
			context,
			computeBytesSha256( winrt::to_string( summary.Stringify()), summaryHash) == 0U &&
				root.GetNamedString( L"activeGeneration").empty() &&
				root.GetNamedArray( L"generations").GetObjectAt( 0U).GetNamedString( L"summaryHash") ==
					summaryHash) ;
		const auto after = projectedStoreSnapshot( context, store) ;	// 二度目は時計も再保存しません。
		DRIVERCRATE_EXPECT( context,
						   recovery.finishInitialProjected( HTTP_TEST_UTC + 128000U, 2000U) == 0U &&
							   after == projectedStoreSnapshot( context, store)) ;
		// 完了済みでも両jobの登録履歴を元応答・全精算から検査し、保存byteを変更しません。
		for( std::size_t jobIndex = 0U; jobIndex < 2U; ++jobIndex) {
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
					   history ;	// 成功時だけ所有します。
			const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
				store, *prepared->job( jobIndex), definition.sources, HTTP_TEST_UTC + 128000U,
				history) ;	// 初回完了contextは次回予約tokenではありません。
			context.expect( code == 0U && history && history->operations() == 1U,
						   "completed history scenario=" + std::to_string( scenario) +
							   " job=" + std::to_string( jobIndex) + " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
			// 保留・失敗・中断から採用済み成功sliceを捏造しません。
			if( history) {
				DRIVERCRATE_EXPECT( context, history->slices().size() ==
													(jobIndex == 1U && scenario < 2U ? 1U : 0U) &&
												history->cache().original200.has_value() ==
													(jobIndex == 1U && scenario == 0U)) ;
			}

			DRIVERCRATE_EXPECT( context, after == projectedStoreSnapshot( context, store)) ;
		}

		// 完了保存は元応答・四role・台帳を一切変更しません。
		for( const auto &entry : before) {
			// Rootの最後の登録だけが既存fileの変更として許されます。
			if( entry.first != L"current/campaign-root-v2.json") {
				DRIVERCRATE_EXPECT( context, after.at( entry.first) == entry.second) ;
			}
		}

		// 正常元fixtureを全保存窓と独立改変に共用します。
		if( scenario == 0U) {
			base	   = before ;
			complete   = after ;
			generation = g ;
		}
	}

	const auto finishName =
		L"runs/campaign-finish-v1-" + generation + L".json" ;						// 固定Gの元intent。
	const auto shardName   = L"runs/campaign-targets-v1-" + generation + L".json" ;	// 同Gの全対象。
	const auto summaryName = L"runs/campaign-summary-v1-" + generation + L".json" ;	// 同Gのsummary。
	const auto responseEntry =
		std::find_if( complete.begin(), complete.end(), []( const auto &entry) {
			return entry.first.starts_with( L"runs/campaign-response-v4-") ;
		}) ; // 欠損試験で除く元応答一件だけを固定します。
	DRIVERCRATE_EXPECT( context, responseEntry != complete.end()) ;
	// 正常fixture自体が欠損している場合は架空の比較をしません。
	if( responseEntry == complete.end()) {
		return ;
	}

	const std::array<CollectorRecoveryCheckpoint, 5U> windows{
		CollectorRecoveryCheckpoint::FINISH_INTENT, CollectorRecoveryCheckpoint::FINISH_SHARD,
		CollectorRecoveryCheckpoint::FINISH_SUMMARY, CollectorRecoveryCheckpoint::FINISH_POINTER,
		CollectorRecoveryCheckpoint::FINISH_REGISTERED} ;	// 応答窓とは別の五保存窓。
	// 各保存窓を独立停止し、同じ元完了時刻・全byteへ回復します。
	for( std::size_t window = 0U; window < windows.size(); ++window) {
		LocalCollectorStateStore store ;	// 同じrootKeyの元保存byteだけを複製します。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 未完了の元保存集合を保護writeで複製します。
		for( const auto &entry : base) {
			DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
		}

		{
			LocalCollectorRecovery stopping ;	// この借用を解放してから再起動します。
			DRIVERCRATE_EXPECT(
				context, stopping.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U,
													  0U, [&]( CollectorRecoveryCheckpoint point) {
														  return point == windows[window] ;
													  }) == 0U) ;
			DRIVERCRATE_EXPECT( context,
							   stopping.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) ==
									   ERROR_OPERATION_ABORTED &&
								   stopping.lastError() == ERROR_OPERATION_ABORTED) ;
			const auto stopped = projectedStoreSnapshot( context, store) ;	// 第一失敗の固定保存物。
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
					   history ;	// 読取りでは回復しません。
			const auto historyCode = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
				store, *prepared->job( 1U), definition.sources, HTTP_TEST_UTC + 128000U,
				history) ;	// 全五保存窓。
			DRIVERCRATE_EXPECT( context, window == 4U ? historyCode == 0U && history
													 : historyCode != 0U && !history) ;
			DRIVERCRATE_EXPECT( context, stopped == projectedStoreSnapshot( context, store)) ;
			DRIVERCRATE_EXPECT( context,
							   stopping.finishInitialProjected( HTTP_TEST_UTC + 128000U, 2000U) ==
									   ERROR_OPERATION_ABORTED &&
								   stopped == projectedStoreSnapshot( context, store)) ;
			// Intentだけのprefixを改変試験へ保持します。
			if( window == 0U) {
				intentOnly = stopped ;
			}
		}
		{
			LocalCollectorRecovery resumed ;	// 完了intentの回復は新workerを起動しません。
			const auto			   error =
				resumed.initializeProjected( store, definition, HTTP_TEST_UTC + 129000U,
											0U) ;	// 元127秒を後日の129秒へ延長しません。
			context.expect( error == 0U && resumed.reason() == L"GENERATION_COMPLETE" &&
							   projectedStoreSnapshot( context, store) == complete,
						   "finish window=" + std::to_string( window) +
							   " code=" + std::to_string( error),
						   __FILE__, __LINE__) ;
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
				history ;	// 通常回復後だけ再検査します。
			DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
											store, *prepared->job( 1U), definition.sources,
											HTTP_TEST_UTC + 129000U, history) == 0U &&
											history) ;
			DRIVERCRATE_EXPECT( context, complete == projectedStoreSnapshot( context, store)) ;
		}
		LocalCollectorRecovery again ;	// 完了済みの初期化も保存byte不変です。
		DRIVERCRATE_EXPECT( context, again.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 130000U, 0U) == 0U &&
										complete == projectedStoreSnapshot( context, store)) ;
	}

	// 登録後欠損／自己一貫改変と準備中の逆順を、書込み前に拒否します。
	for( unsigned mode = 0U; mode < 15U; ++mode) {
		LocalCollectorStateStore store ;	// 改変は各条件一つの独立cloneです。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto &original = mode < 11U ? complete : intentOnly ;	// 登録と準備を区別します。
		const auto	missing	 = mode == 0U	? finishName
							   : mode == 1U ? shardName
							   : mode == 2U ? summaryName
							   : mode == 3U ? std::wstring( L"current/campaign-current-v2.json")
							   : mode == 4U ? responseEntry->first
											: std::wstring{} ;	// 一つの固定欠損。
		// 欠損対象を除いて元byteを複製し、実file削除は行いません。
		for( const auto &entry : original) {
			// 一つのv4応答欠損と、固定完了像の欠損を分けます。
			if( entry.first == missing) {
				continue ;
			}

			DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
		}

		// 完了時刻・summary件数・target行・pointer・root登録の改変を独立に注入します。
		if( mode >= 5U && mode <= 10U) {
			const auto name = mode == 5U				  ? finishName
							  : mode == 6U || mode == 10U ? summaryName
							  : mode == 7U				  ? shardName
							  : mode == 8U
								  ? L"current/campaign-current-v2.json"
								  : L"current/campaign-root-v2.json" ;	// 組み込み有限保存先だけ。
			mutateProjectedStore( context, store, name, [&]( JsonObject object) {
				// 同じ外側hash検査を通る有限改変を一要因ずつ選びます。
				switch( mode) {
					// 元完了時刻を別の有効UTCへ変更します。
					case 5U:
						object.Insert( L"closedUtcMillis",
									  JsonValue::CreateNumberValue( HTTP_TEST_UTC + 128000.0)) ;
						break ;

						// 構造だけ有効な成功件数を増やします。
					case 6U:
						// 全参照hashも後で再計算する別条件です。
					case 10U:
						object.Insert( L"metadataMatchedTargets", JsonValue::CreateNumberValue( 3.0)) ;
						break ;

						// 元target分母を減らします。
					case 7U:
						object.GetNamedArray( L"targets").RemoveAtEnd() ;
						break ;

						// 別generation pointerへ変更します。
					case 8U:
						object.Insert( L"generation",
									  JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
						break ;

						// Summary登録済みなのにactiveを維持します。
					default:
						object.Insert( L"activeGeneration",
									  JsonValue::CreateStringValue( generation)) ;
						break ;
				}
			}) ;
			// Summary／intent／rootのhashを全て再計算しても元応答との不一致を拒否します。
			if( mode == 10U) {
				std::wstring forged ;	// 改変summaryの実SHA。
				DRIVERCRATE_EXPECT(
					context, computeBytesSha256( httpSavedBody( store, summaryName), forged) == 0U) ;
				// 完了参照の全hashを有効値へ揃えます。
				for( const auto &componentName :
					{finishName, std::wstring( L"current/campaign-root-v2.json"),
					 std::wstring( L"current/campaign-current-v2.json")}) {
					mutateProjectedStore( context, store, componentName, [&]( JsonObject object) {
						// rootでは登録行、他の二像では直接fieldを更新します。
						if( componentName == L"current/campaign-root-v2.json") {
							object.GetNamedArray( L"generations")
								.GetObjectAt( 0U)
								.Insert( L"summaryHash", JsonValue::CreateStringValue( forged)) ;
						} else {
							object.Insert( L"summaryHash", JsonValue::CreateStringValue( forged)) ;
						}
					}) ;
				}

				std::wstring pointerHash ;	// 改変pointerの実hashもintentへ結合します。
				DRIVERCRATE_EXPECT(
					context,
					computeBytesSha256( httpSavedBody( store, L"current/campaign-current-v2.json"),
									   pointerHash) == 0U) ;
				mutateProjectedStore( context, store, finishName, [&]( JsonObject object) {
					object.Insert( L"pointerHash", JsonValue::CreateStringValue( pointerHash)) ;
				}) ;
			}
		}

		// Intent後の非連続prefix、早すぎる完了登録、未知保存名を別に検査します。
		if( mode >= 11U) {
			// Intentだけの状態へ後続像を先に置き、逆順を再現します。
			if( mode == 11U || mode == 12U) {
				const auto name =
					// 後続像。
					mode == 11U ? L"current/campaign-current-v2.json" : summaryName ;
				DRIVERCRATE_EXPECT( context, store.write( name, complete.at( name)) == 0U) ;
			}

			// 元像がないのにrootだけ完了済みにします。
			if( mode == 13U) {
				DRIVERCRATE_EXPECT(
					context, store.write( L"current/campaign-root-v2.json",
										 complete.at( L"current/campaign-root-v2.json")) == 0U) ;
			}

			// 未登録の新prefixを無言で無視しません。
			if( mode == 14U) {
				DRIVERCRATE_EXPECT( context,
								   store.write( L"runs/campaign-unknown-finish.json", "{}") == 0U) ;
			}
		}

		const auto before = projectedStoreSnapshot( context, store) ;	// 拒否は全byte不変です。
		LocalCollectorRecovery rejected ;								// 無言の補完・新世代・HTTPを許可しません。
		const auto error = rejected.initializeProjected( store, definition, HTTP_TEST_UTC + 130000U,
														0U) ;	// 原第一codeを診断します。
		context.expect( error != 0U && before == projectedStoreSnapshot( context, store),
					   "finish mutation=" + std::to_string( mode) + " code=" + std::to_string( error),
					   __FILE__, __LINE__) ;
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
			history ;	// 不正完了を履歴なしへ戻しません。
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
										store, *prepared->job( 1U), definition.sources,
										HTTP_TEST_UTC + 130000U, history) != 0U &&
										!history) ;
		DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store)) ;
	}

	LocalCollectorStateStore completedStore ;	// 正常完了cloneを次回の純検査へ渡します。
	DRIVERCRATE_EXPECT( context, completedStore.initialize( rootFactory(), true) == 0U) ;
	// 元完了byteを保存し、新世代や新workerを作りません。
	for( const auto &entry : complete) {
		DRIVERCRATE_EXPECT( context, completedStore.write( entry.first, entry.second) == 0U) ;
	}

	std::shared_ptr<const CollectorRegisteredProjectedHistory>
		completedHistory ;	// 全成功の所有slice。
	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
									completedStore, *prepared->job( 1U), definition.sources,
									HTTP_TEST_UTC + 130000U, completedHistory) == 0U &&
									completedHistory && completedHistory->slices().size() == 1U) ;
	// 正常contextなしでは後続のalias・異なる入力試験を行いません。
	if( !completedHistory || completedHistory->slices().empty()) {
		return ;
	}

	const auto intelOperation =
		// 非参照jobの元Oはjob入力へ追加せず、保存済み元stateの行から読みます。
		std::wstring( JsonObject::Parse( winrt::to_hstring( httpSavedBody(
										   completedStore,
										   L"current/campaign-state-v3-" + generation + L".json")))
						 .GetNamedArray( L"jobs")
						 .GetObjectAt( 0U)
						 .GetNamedString( L"operation")) ;
	const auto	intelRequest = prepared->job( 0U)->value().requestKey ;	// 非参照側の固定CACHE名。
	const auto *aliasedJob =
		// 旧出力だけが寿命を保持します。
		completedHistory->slices()[0].campaign->job( 1U) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
									completedStore, *aliasedJob, definition.sources,
									HTTP_TEST_UTC + 130000U, completedHistory) == 0U &&
									completedHistory) ;
	// 後日・別artifact・別scopeでも元履歴は元入力のまま検証でき、送信許可は与えません。
	for( unsigned mode = 0U; mode < 3U; ++mode) {
		auto nextDefinition = definition ;	// 固定元requestは変更しません。
		// 別binaryのhashを元履歴へ遡及適用しません。
		if( mode == 1U) {
			nextDefinition.artifactSha256 = std::wstring( 64U, L'd') ;
			DRIVERCRATE_EXPECT( context, nextDefinition.artifactSha256 != definition.artifactSha256) ;
		}

		// 公開対象名の変更は新scopeとして扱い、元成功を新対象の適合へ昇格しません。
		if( mode == 2U) {
			const auto nextManifest =
				// 元job群は保持。
				JsonObject::Parse( winrt::to_hstring( definition.manifestBytes)) ;
			nextManifest.GetNamedArray( L"targets")
				.GetObjectAt( 26U)
				.Insert( L"model", JsonValue::CreateStringValue( L"Fixture Alternative Board")) ;
			nextDefinition.manifestBytes = winrt::to_string( nextManifest.Stringify()) ;
		}

		CollectorProjectedCampaignIdentity nextIdentity ;	// 翌日の新入力。保存・予約はしません。
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			nextPrepared ;	// 次回比較の検査入力だけ。
		DRIVERCRATE_EXPECT(
			context,
			makeCollectorProjectedCampaignIdentity( nextDefinition, L"20260928", nextIdentity) &&
				prepareCollectorProjectedCampaign(
					nextIdentity.canonicalInput, nextIdentity.inputSha256,
					nextIdentity.generationKey, nextDefinition.artifactSha256,
					nextDefinition.sources, nextPrepared) &&
				nextPrepared &&
				nextPrepared->job( 1U)->value().requestKey ==
					prepared->job( 1U)->value().requestKey &&
				nextPrepared->generationKey() != prepared->generationKey()) ;
		// 準備失敗時に未生成のjobを参照しません。
		if( nextPrepared) {
			// 別scopeは別bindingに結合し、元成功sliceを新対象の成功へ読み替えません。
			if( mode == 2U) {
				DRIVERCRATE_EXPECT( context, nextPrepared->job( 1U)->value().cacheBinding !=
												prepared->job( 1U)->value().cacheBinding) ;
			}

			DRIVERCRATE_EXPECT(
				context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
							 completedStore, *nextPrepared->job( 1U), nextDefinition.sources,
							 HTTP_TEST_UTC + 86400000U + 130000U, completedHistory) == 0U &&
							 completedHistory &&
							 completedHistory->cache().attempt.generation == generation &&
							 completedHistory->slices()[0].campaign->generationKey() == generation) ;
		}

		DRIVERCRATE_EXPECT( context, complete == projectedStoreSnapshot( context, completedStore)) ;
	}

	LocalCollectorStateStore readOnly ;	// 既存監査専用modeは読取りAPIも有効にしません。
	DRIVERCRATE_EXPECT( context, readOnly.initialize( completedStore.root(), false) == 0U &&
									!readOnly.isWritable()) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorRecovery::inspectRegisteredProjectedHistory(
						   readOnly, *prepared->job( 1U), definition.sources,
						   HTTP_TEST_UTC + 130000U, completedHistory) == ERROR_INVALID_PARAMETER &&
						   !completedHistory) ;
	DRIVERCRATE_EXPECT( context, complete == projectedStoreSnapshot( context, completedStore)) ;

	// 他jobの保存物は今回requestの閉包外でも完了inventoryで検査します。
	for( unsigned mode = 0U; mode < 14U; ++mode) {
		LocalCollectorStateStore store ;	// 欠損・改変とsource不一致の独立clone。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto name =
			mode == 0U || mode == 6U ? L"runs/campaign-response-v4-" + intelOperation + L".json"
			: mode == 1U || mode == 7U
				? L"runs/campaign-effect-v2-" + intelOperation + L"-before-job.json"
			: mode == 2U || mode == 8U
				? L"runs/campaign-effect-v2-" + intelOperation + L"-control.json"
			: mode == 3U || mode == 9U
				? L"runs/campaign-effect-v2-" + intelOperation + L"-budget.json"
			: mode == 4U || mode == 10U
				? L"runs/campaign-effect-v2-" + intelOperation + L"-cache.json"
				: L"current/campaign-cache-v1-" + intelRequest + L".json" ;	// 元job0だけの保存名。
		// 欠損六条件以外では全byteを複製します。実fileは削除しません。
		for( const auto &entry : complete) {
			// 指定した保存物の一件だけを欠損にします。
			if( mode >= 6U || entry.first != name) {
				DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
			}
		}

		// 正しい外側hash付きの異なる像も元導出との不一致で拒否します。
		if( mode >= 6U && mode < 12U) {
			mutateProjectedStore( context, store, name, []( JsonObject object) {
				object.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
			}) ; // 未知fieldは補完／無視しません。
		}

		auto currentSources = definition.sources ;	// 保存sourceの自己申告は権限ではありません。
		// 参照しないIntel sourceだけ不一致にしても全完了検査で拒否します。
		if( mode == 12U) {
			currentSources[0].parserRevision = L"different-parser" ;
		}

		// Summary付き複数世代を初回一世代の例外へ混入させません。
		if( mode == 13U) {
			mutateProjectedStore( context, store, L"current/campaign-root-v2.json",
								 []( JsonObject object) {
									 object.GetNamedArray( L"generations")
										 .Append( object.GetNamedArray( L"generations").GetAt( 0U)) ;
								 }) ;
		}

		const auto before =
			// 呼出し中の補完・精算・書込みを拒否。
			projectedStoreSnapshot( context, store) ;
		std::shared_ptr<const CollectorRegisteredProjectedHistory> history =
			completedHistory ;	// 失敗時は空へ戻します。
		const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, *prepared->job( 1U), currentSources, HTTP_TEST_UTC + 130000U,
			history) ;	// ASUSの検査だけを要求。
		context.expect( code != 0U && !history && before == projectedStoreSnapshot( context, store),
					   "completed other job mode=" + std::to_string( mode) +
						   " code=" + std::to_string( code),
					   __FILE__, __LINE__) ;
	}

	// 全inventory後の変更・原hash／OOMは公開直前の再照合か原errorで拒否します。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		LocalCollectorStateStore store ;	// 終了時再照合と故障の独立clone。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 途中変更前に正常完了像を複製します。
		for( const auto &entry : complete) {
			DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
		}

		bool injected = false ;	// 元v4のhash診断で一回だけ作用させます。
		std::shared_ptr<const CollectorRegisteredProjectedHistory> history =
			completedHistory ;	// 失敗時の空出力を検査。
		const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, *prepared->job( 1U), definition.sources, HTTP_TEST_UTC + 130000U, history,
			[&]( CollectorProjectedHashStage stage) -> std::int32_t {
				// 全完了inventory後の主閉包で最初の原応答hashだけへ故障を注入します。
				if( injected || stage != CollectorProjectedHashStage::READ_RESPONSE) {
					return 0 ;
				}

				injected = true ;
				// 参照済みsummaryの変更は全raw再照合で拒否します。
				if( mode == 0U) {
					mutateProjectedStore( context, store, summaryName, []( JsonObject object) {
						object.Insert( L"metadataMatchedTargets", JsonValue::CreateNumberValue( 2.0)) ;
					}) ;
				}

				// 未参照名の追加は全保存名再照合で拒否します。
				if( mode == 1U) {
					DRIVERCRATE_EXPECT( context,
									   store.write( L"runs/campaign-late-unknown.json", "{}") == 0U) ;
				}

				// 原hashの数値失敗を一般拒否へ丸めません。
				if( mode == 2U) {
					return E_ACCESSDENIED ;
				}

				// OOMも原bit patternを保持します。保存物は変更しません。
				if( mode == 3U) {
					throw std::bad_alloc() ;
				}

				return 0 ;
			}) ; // 同期呼出しだけstoreとinjectedを借用します。
		context.expect( injected && !history &&
						   code == (mode < 2U	 ? ERROR_INVALID_DATA
									: mode == 2U ? static_cast<DWORD>( E_ACCESSDENIED)
												 : static_cast<DWORD>( E_OUTOFMEMORY)),
					   "completed history injected mode=" + std::to_string( mode) + " injected=" +
						   std::to_string( injected) + " code=" + std::to_string( code),
					   __FILE__, __LINE__) ;
		// 故障専用二条件では読取り入口による全byte不変も確認します。
		if( mode >= 2U) {
			DRIVERCRATE_EXPECT( context, complete == projectedStoreSnapshot( context, store)) ;
		}
	}

	// 0／1／300 jobの追加枠を直前・一致・超過で検査します。
	for( const std::size_t count : {0U, 1U, 300U}) {
		CollectorStoreUsage usage ;	// 合算枠の一致境界から開始します。
		usage.runEntries	 = 4096U - (9U * count + 16U) ;
		usage.currentEntries = 4096U - (count + 15U) ;
		usage.bytes =
			5ULL * 1024U * 1024U * 1024U - (7ULL * count * 2U * 1024U * 1024U +
											3ULL * count * 64U * 1024U + 60ULL * 1024U * 1024U) ;
		DRIVERCRATE_EXPECT( context,
						   checkCollectorProjectedCompletionCapacity( usage, count, count) == 0U) ;
		++usage.runEntries ;
		DRIVERCRATE_EXPECT( context, checkCollectorProjectedCompletionCapacity(
										usage, count, count) == ERROR_TOO_MANY_NAMES) ;
		--usage.runEntries ;
		++usage.currentEntries ;
		DRIVERCRATE_EXPECT( context, checkCollectorProjectedCompletionCapacity(
										usage, count, count) == ERROR_TOO_MANY_NAMES) ;
		--usage.currentEntries ;
		++usage.bytes ;
		DRIVERCRATE_EXPECT( context, checkCollectorProjectedCompletionCapacity(
										usage, count, count) == ERROR_TOO_MANY_NAMES) ;
	}

	DRIVERCRATE_EXPECT( context, checkCollectorProjectedCompletionCapacity( {}, 301U, 1U) ==
										ERROR_INVALID_PARAMETER &&
									checkCollectorProjectedCompletionCapacity( {}, 1U, 2U) ==
										ERROR_INVALID_PARAMETER) ;

	auto	   expanded = definition ;	// 300対象の固定分母を持つ未通信fixture。
	const auto manifest =
		// 元27対象。
		JsonObject::Parse( winrt::to_hstring( expanded.manifestBytes)) ;
	// 既存jobに登録されていない273対象も分母から落としません。
	for( std::size_t index = 27U; index < 300U; ++index) {
		JsonObject target ;	// 架空の公開製品条件。端末IDは保存しません。
		target.Insert( L"id", JsonValue::CreateStringValue( L"unlinked-" + std::to_wstring( index))) ;
		target.Insert( L"maker", JsonValue::CreateStringValue( L"Fixture Maker " +
															 std::to_wstring( (index - 27U) / 64U))) ;
		target.Insert( L"model",
					  JsonValue::CreateStringValue( L"Fixture Board " + std::to_wstring( index))) ;
		target.Insert( L"kind", JsonValue::CreateStringValue( L"MAINBOARD")) ;
		target.Insert( L"purpose", JsonValue::CreateStringValue( L"LAN")) ;
		manifest.GetNamedArray( L"targets").Append( target) ;
	}

	expanded.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	LocalCollectorStateStore unstarted ;	// 未予約のまま日付変更で二jobを閉じます。
	DRIVERCRATE_EXPECT( context, unstarted.initialize( rootFactory(), true) == 0U) ;
	{
		LocalCollectorRecovery pending ;	// 未終端の完了要求は非保存待ちです。
		DRIVERCRATE_EXPECT(
			context, pending.initializeProjected( unstarted, expanded, HTTP_TEST_UTC, 0U) == 0U) ;
		const auto before = projectedStoreSnapshot( context, unstarted) ;	// 未終端拒否の非変更比較。
		DRIVERCRATE_EXPECT( context,
						   pending.finishInitialProjected( HTTP_TEST_UTC, 0U) == ERROR_RETRY &&
							   pending.lastError() == 0U &&
							   before == projectedStoreSnapshot( context, unstarted)) ;
	}
	LocalCollectorRecovery closed ;	// 追加HTTPなしで元分母を完了します。
	DRIVERCRATE_EXPECT(
		context,
		closed.initializeProjected( unstarted, expanded, HTTP_TEST_UTC + 86400000U, 0U) == 0U &&
			closed.terminalJobs() == 2U &&
			closed.finishInitialProjected( HTTP_TEST_UTC + 86401000U, 1000U) == 0U) ;
	const auto summary = JsonObject::Parse(
		winrt::to_hstring( httpSavedBody( unstarted,
										L"runs/campaign-summary-v1-" + closed.generationKey() +
											L".json"))) ;	// 実保存された300対象。
	DRIVERCRATE_EXPECT( context, summary.GetNamedNumber( L"targetCount") == 300.0 &&
									summary.GetNamedNumber( L"unsupportedTargets") == 273.0 &&
									summary.GetNamedNumber( L"metadataUnknownTargets") == 27.0 &&
									summary.GetNamedNumber( L"metadataMatchedTargets") == 0.0) ;
}

/** @brief 独立初回証跡から進んだCACHEを持つ二完了世代の組立fixtureを作ります。
 * @param[in,out] context 親threadの集計。
 * @param[in,out] store 二番目の初回保存・完了済みstore。試験専用です。
 * @param[in] original 最初の完了世代の全raw snapshot。
 * @param[in] histories 最初の二requestを検査済みの所有context。
 * @param[in] campaign 二番目の元prepared入力。
 * @param[in] workers 二番目のjoin済み所有worker copy。
 * @param[in] utc 二番目の予約UTC。
 * @param[in] archived 元日の予算をarchiveへ結合する場合true。
 * @note 通常の新世代予約・保存を実装済みとするfixtureではありません。
 */
void assembleCompletedHistoryFixture(
	TestContext &context, LocalCollectorStateStore &store,
	const std::map<std::wstring, std::string>										 &original,
	const std::array<std::shared_ptr<const CollectorRegisteredProjectedHistory>, 2U> &histories,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign>					 &campaign,
	const std::array<CollectorProjectedWorkerResult, 2U> &workers, const std::uint64_t utc,
	const bool archived)
{
	// 元snapshotの外側から本文を取り出す試験専用同期lambda。originalの寿命内だけ借用します。
	const auto originalBody = [&]( const std::wstring &name) {
		return winrt::to_string(
			JsonObject::Parse( winrt::to_hstring( original.at( name))).GetNamedString( L"body")) ;
	} ;
	// このfixtureだけで実SHAを計算します。hash失敗を架空値で置換しません。
	const auto digest = [&]( const std::string_view body) {
		std::wstring result ;	// 各原byteの実hash。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( body, result) == 0U) ;
		return result ;
	} ;
	const auto g			   = campaign->generationKey() ;					// 二番目の実manifestによるG。
	const auto stateName	   = L"current/campaign-state-v3-" + g + L".json" ;	// 全job状態。
	const auto freshRoot	   = JsonObject::Parse( winrt::to_hstring(
		  // 二番目の初回完了登録。
		  httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
	auto	   root			   = JsonObject::Parse( winrt::to_hstring(
		 // 同じroot identityを保持します。
		 originalBody( L"current/campaign-root-v2.json"))) ;
	const auto firstGeneration = std::wstring( root.GetNamedArray( L"generations")
												  .GetObjectAt( 0U)
												  .GetNamedString( L"generation")) ;	// 最初の登録G。
	DRIVERCRATE_EXPECT( context, firstGeneration != g) ;
	// 最初のrun全証跡とstateだけを保持し、現在CACHE／pointerは二番目へ進めます。
	for( const auto &[name, raw] : original) {
		// 元root・共有現在値を先に上書きしません。
		if( name.starts_with( L"runs/") ||
		   name == L"current/campaign-state-v3-" + firstGeneration + L".json") {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}
	}

	DRIVERCRATE_EXPECT( context,
					   store.write( L"current/collector-campaign-mode-v1.json",
								   original.at( L"current/collector-campaign-mode-v1.json")) == 0U) ;

	std::array<CollectorProjectedResponseBytes, 2U>
		responses ;	// 同じ元workerを旧履歴で最終化します。
	// 二つの原workerは全根拠contextを通して減少・失敗を再計算し、応答を独立encodeします。
	for( std::size_t index = 0U; index < 2U; ++index) {
		CollectorProjectedHistoryFinalization finalized ;	// 旧成功を今回metadataへ複写しません。
		DRIVERCRATE_EXPECT( context, finalizeCollectorProjectedHistory(
										*campaign->job( index), workers[index], utc + 125000U,
										histories[index]->slices(), finalized)
											.status == collector_projected_json::Status::OK) ;
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorProjectedResponse( campaign->job( index)->value(),
															finalized.response, responses[index])
								   .result.status == collector_projected_json::Status::OK) ;
	}

	const auto firstOp =
		std::wstring( JsonObject::Parse( winrt::to_hstring( httpSavedBody( store, stateName)))
						 .GetNamedArray( L"jobs")
						 .GetObjectAt( 1U)
						 .GetNamedString( L"operation")) ;							// 二番目の初回acceptと同じASUS先行順。
	const auto beforePrefix = L"runs/campaign-effect-v2-" + firstOp + L"-before-" ;	// 元開始の三像。
	auto	   state		= JsonObject::Parse( winrt::to_hstring(
		 // 両jobが元RUNNINGの表。
		 httpSavedBody( store, beforePrefix + L"job.json"))) ;
	CollectorWaitSnapshot	control ;		// 新しい開始値と古い待機を共有します。
	CollectorWaitSnapshot	oldControl ;	// 旧完了観測を捨てません。
	CollectorBudgetSnapshot budget ;		// 二番目の未精算予約。
	CollectorBudgetSnapshot oldBudget ;		// 最初の閉鎖済み予算。
	DRIVERCRATE_EXPECT(
		context,
		parseCollectorWaitSnapshot( httpSavedBody( store, beforePrefix + L"control.json"), control) &&
			parseCollectorWaitSnapshot( originalBody( L"current/campaign-controls-v1.json"),
									   oldControl) &&
			parseCollectorBudgetSnapshot( httpSavedBody( store, beforePrefix + L"budget.json"),
										 budget) &&
			parseCollectorBudgetSnapshot( originalBody( L"current/campaign-budget-v1.json"),
										 oldBudget)) ;
	// 同一requestの開始値は二番目のまま、期限・完了・reviewだけを元履歴から後退させません。
	for( const auto &[name, row] : oldControl.controls) {
		auto &current	  = control.controls.at( name) ;	// 同じ二source・requestの保存行。
		current.observed  = std::max( current.observed, row.observed) ;
		current.completed = std::max( current.completed, row.completed) ;
		current.notBefore = std::max( current.notBefore, row.notBefore) ;
		current.review	  = current.review || row.review ;
	}

	// 同日の精算は旧予約も同じ共有台帳へ残します。別日は元day-roll証跡でarchiveへ結合します。
	if( !archived) {
		DRIVERCRATE_EXPECT( context, budget.day == oldBudget.day) ;
		budget.reservations.insert( budget.reservations.end(), oldBudget.reservations.begin(),
								   oldBudget.reservations.end()) ;
		std::stable_sort( budget.reservations.begin(), budget.reservations.end(),
						 []( const auto &a, const auto &b) { return a.started < b.started ; }) ;
	} else {
		const auto body = originalBody( L"current/campaign-budget-v1.json") ;	// 旧日の全閉鎖予約。
		const auto op =
			digest( "day-roll-v2\n" + winrt::to_string( root.GetNamedString( L"rootKey")) + "\n" +
				   winrt::to_string( oldBudget.day) + "\n" + winrt::to_string( budget.day) + "\n" +
				   // 通常切替と同じ元算法。
				   winrt::to_string( digest( body))) ;
		JsonObject intent ;	// 原時刻で固定した切替証跡。実日次収集ではありません。
		intent.Insert( L"schema", JsonValue::CreateStringValue( L"collector-campaign-day-roll-v2")) ;
		intent.Insert( L"rootKey", root.GetNamedValue( L"rootKey")) ;
		intent.Insert( L"oldDay", JsonValue::CreateStringValue( oldBudget.day)) ;
		intent.Insert( L"newDay", JsonValue::CreateStringValue( budget.day)) ;
		intent.Insert( L"accepted", JsonValue::CreateNumberValue( static_cast<double>( utc))) ;
		intent.Insert( L"budgetHash", JsonValue::CreateStringValue( digest( body))) ;
		intent.Insert( L"operation", JsonValue::CreateStringValue( op)) ;
		saveRegisteredHistoryFixture( context, store, L"runs/campaign-day-roll-v2-" + op + L".json",
									 winrt::to_string( intent.Stringify())) ;
		saveRegisteredHistoryFixture( context, store,
									 L"runs/campaign-budget-" + oldBudget.day + L".json", body) ;
		saveRegisteredHistoryFixture(
			context, store, L"runs/campaign-effect-v1-" + op + L"-before-budget.json", body) ;
		saveRegisteredHistoryFixture( context, store,
									 L"runs/campaign-effect-v1-" + op + L"-archive.json", body) ;
		std::string empty ;	// 元切替直後の空予算像。後続予約とは別です。
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorBudgetSnapshot( {budget.day, utc / 1000U, {}}, empty)) ;
		saveRegisteredHistoryFixture( context, store,
									 L"runs/campaign-effect-v1-" + op + L"-budget.json", empty) ;
		JsonObject registration ;	// 全原byteへ結合したarchive登録。
		registration.Insert( L"day", JsonValue::CreateStringValue( oldBudget.day)) ;
		registration.Insert( L"hash", JsonValue::CreateStringValue( digest( body))) ;
		registration.Insert( L"operation", JsonValue::CreateStringValue( op)) ;
		root.GetNamedArray( L"archives").Append( registration) ;
	}

	JsonArray cacheInventory ;	// 二requestの最新値だけをrootへ登録します。
	// ASUS→Intelの元受領順に全四roleをnative精算coreから再計算します。
	for( const auto index : {1U, 0U}) {
		const auto &response = responses[index] ;				// 旧履歴最終化済みの新応答。
		const auto &value	 = response.value ;					// 同じ元I/Oの観測。
		const auto &job		 = campaign->job( index)->value() ;	// 全scope・sourceを保持します。
		const auto	op		 = digest( "response-v2\n" + winrt::to_string( g) + "\n" +
									  // 元操作。
									  winrt::to_string( job.jobKey) + "\n") ;
		std::array<std::string, 3U> before ;	// 直前の全共有値・同Gの表。
		DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( control, before[0]) &&
										encodeCollectorBudgetSnapshot( budget, before[2])) ;
		before[1] = winrt::to_string( state.Stringify()) ;
		CollectorWaitSnapshot settled ;	// 本番と同じ待機精算。
		DRIVERCRATE_EXPECT( context,
						   prepareCollectorWaitSettlement(
							   control, {job.source.rateLimitGroup, value.request, g, job.jobKey},
							   {value.state == CollectorMetadataOutcome::FETCHED, value.status,
								value.retryAfter, value.review, value.challenge},
							   value.started, value.finished, value.accepted, value.accepted, false,
							   settled)) ;
		control	 = std::move( settled) ;
		auto row = state.GetNamedArray( L"jobs").GetObjectAt( index) ;	// 元行だけを終端へ更新します。
		row.Insert( L"state", JsonValue::CreateStringValue(
								 value.state == CollectorMetadataOutcome::FETCHED ? L"FETCHED"
								 : value.state == CollectorMetadataOutcome::HELD  ? L"HELD"
																				  : L"FAILED")) ;
		row.Insert( L"operation", JsonValue::CreateStringValue( op)) ;
		row.Insert( L"response", JsonValue::CreateStringValue( response.responseSha256)) ;
		// 元G／job予約だけを同じ観測量で精算します。他世代の予約を変更しません。
		for( auto &reservation : budget.reservations) {
			// 他jobの未精算予約も次の元受領まで保持します。
			if( reservation.campaign == g && reservation.job == job.jobKey) {
				reservation.phase	= 1U ;
				reservation.charged = value.bytes.value_or( reservation.maximum) ;
			}
		}

		budget.lastUtc = std::max( budget.lastUtc, value.accepted / 1000U) ;
		std::array<std::string, 3U> after ;	// 同じ三role更新後像。
		DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( control, after[0]) &&
										encodeCollectorBudgetSnapshot( budget, after[2])) ;
		after[1] = winrt::to_string( state.Stringify()) ;
		const std::array<std::wstring, 3U> roles{L"control", L"job", L"budget"} ;	// 固定保存role。
		// 元更新前後像の全byteを保存し、実装側で独立再導出できる証跡を作ります。
		for( std::size_t role = 0U; role < 3U; ++role) {
			saveRegisteredHistoryFixture( context, store,
										 L"runs/campaign-effect-v2-" + op + L"-before-" +
											 roles[role] + L".json",
										 before[role]) ;
			saveRegisteredHistoryFixture(
				context, store, L"runs/campaign-effect-v2-" + op + L"-" + roles[role] + L".json",
				after[role]) ;
		}

		DRIVERCRATE_EXPECT( context, store.write( L"runs/campaign-response-v4-" + op + L".json",
												response.envelope) == 0U) ;
		CollectorProjectedCache cache ;			// 旧成功保持と最新attemptを純粋coreから再計算します。
		std::string				priorCache ;	// 当requestの検査済み元CACHE全byte。
		std::string				nextCache ;		// 同じ有限canonical codecの更新後。
		DRIVERCRATE_EXPECT(
			context,
			deriveCollectorProjectedCache( job, response.envelope, &histories[index]->cache(), cache)
						.status == collector_projected_json::Status::OK &&
				encodeCollectorProjectedCache( histories[index]->cache(), priorCache).status ==
					collector_projected_json::Status::OK &&
				encodeCollectorProjectedCache( cache, nextCache).status ==
					collector_projected_json::Status::OK) ;
		saveRegisteredHistoryFixture(
			context, store, L"runs/campaign-effect-v2-" + op + L"-before-cache.json", priorCache) ;
		saveRegisteredHistoryFixture( context, store,
									 L"runs/campaign-effect-v2-" + op + L"-cache.json", nextCache) ;
		saveRegisteredHistoryFixture(
			context, store, L"current/campaign-cache-v1-" + job.requestKey + L".json", nextCache) ;
		JsonObject registration ;	// 元canonical最新CACHEの実hash。
		registration.Insert( L"request", JsonValue::CreateStringValue( job.requestKey)) ;
		registration.Insert( L"hash", JsonValue::CreateStringValue( digest( nextCache))) ;
		cacheInventory.Append( registration) ;
	}

	std::string controlBody ;										// 全job精算後の共有現在値。
	std::string budgetBody ;										// 旧日または当日予約を保持した精算先。
	const auto	stateBody = winrt::to_string( state.Stringify()) ;	// 新G全終端。
	DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( control, controlBody) &&
									encodeCollectorBudgetSnapshot( budget, budgetBody)) ;
	saveRegisteredHistoryFixture( context, store, L"current/campaign-controls-v1.json", controlBody) ;
	saveRegisteredHistoryFixture( context, store, L"current/campaign-budget-v1.json", budgetBody) ;
	saveRegisteredHistoryFixture( context, store, stateName, stateBody) ;

	const auto shardName = L"runs/campaign-targets-v1-" + g + L".json" ;	// 固定27対象の集計fixture。
	const auto summaryName =
		L"runs/campaign-summary-v1-" + g + L".json" ;	// native結果を期待値へ結合。
	auto shard =
		// 元対象順。
		JsonObject::Parse( winrt::to_hstring( httpSavedBody( store, shardName))) ;
	// ASUS新成功だけを新世代のMATCH件数へ集約し、旧CACHE成功を借用しません。
	const auto matched = responses[1].value.state == CollectorMetadataOutcome::FETCHED &&
						 responses[1].value.metadata.slices.front().disposition ==
							 CollectorMetadataDisposition::ACCEPTED ;
	const auto recordCount =
		matched ? responses[1].value.metadata.records.size() : 0U ;			// 旧成功は加算しません。
	auto asusTarget = shard.GetNamedArray( L"targets").GetObjectAt( 26U) ;	// 架空ASUS対象。
	asusTarget.Insert( L"metadataState",
					  JsonValue::CreateStringValue( matched ? L"MATCH" : L"UNKNOWN")) ;
	asusTarget.Insert( L"matchedRecords",
					  JsonValue::CreateNumberValue( static_cast<double>( recordCount))) ;
	const auto shardBody = winrt::to_string( shard.Stringify()) ;	// 全分母の原byte。
	auto	   summary =
		// 元完了時計不変。
		JsonObject::Parse( winrt::to_hstring( httpSavedBody( store, summaryName))) ;
	summary.Insert( L"stateHash", JsonValue::CreateStringValue( digest( stateBody))) ;
	summary.Insert( L"targetShardHash", JsonValue::CreateStringValue( digest( shardBody))) ;
	summary.Insert( L"metadataMatchedTargets", JsonValue::CreateNumberValue( matched ? 1.0 : 0.0)) ;
	summary.Insert( L"metadataUnknownTargets", JsonValue::CreateNumberValue( matched ? 26.0 : 27.0)) ;
	summary.Insert( L"matchedRecordReferences",
				   JsonValue::CreateNumberValue( static_cast<double>( recordCount))) ;
	const auto jobRows = state.GetNamedArray( L"jobs") ;	// 全count巡回中に同じ所有配列を保持します。
	// 五終端の元順を保ち、新responseの状態からだけ件数を数えます。
	for( const auto &entry : summary.GetNamedArray( L"jobOutcomes")) {
		auto	   outcome = entry.GetObject() ;	// 0件も保持する固定終端行。
		const auto count   = std::count_if( jobRows.begin(), jobRows.end(), [&]( const auto &row) {
			  return row.GetObject().GetNamedString( L"state") == outcome.GetNamedString( L"state") ;
		  }) ; // この同期lambdaだけでstateとoutcomeを借用します。
		outcome.Insert( L"count", JsonValue::CreateNumberValue( static_cast<double>( count))) ;
	}

	const auto summaryBody = winrt::to_string( summary.Stringify()) ;	// 固定集計のhash。
	auto	   pointer	   = JsonObject::Parse( winrt::to_hstring(
		  // 最新完了Gだけ。
		  httpSavedBody( store, L"current/campaign-current-v2.json"))) ;
	pointer.Insert( L"summaryHash", JsonValue::CreateStringValue( digest( summaryBody))) ;
	const auto pointerBody = winrt::to_string( pointer.Stringify()) ;	// 新Gの当時pointer。
	const auto finishName =
		L"runs/campaign-finish-v1-" + g + L".json" ;	// 全生成物に結合したintent。
	auto finish =
		// 元時刻を維持。
		JsonObject::Parse( winrt::to_hstring( httpSavedBody( store, finishName))) ;
	finish.Insert( L"rootKey", root.GetNamedValue( L"rootKey")) ;
	finish.Insert( L"stateHash", JsonValue::CreateStringValue( digest( stateBody))) ;
	finish.Insert( L"targetShardHash", JsonValue::CreateStringValue( digest( shardBody))) ;
	finish.Insert( L"summaryHash", JsonValue::CreateStringValue( digest( summaryBody))) ;
	finish.Insert( L"pointerHash", JsonValue::CreateStringValue( digest( pointerBody))) ;
	saveRegisteredHistoryFixture( context, store, finishName, winrt::to_string( finish.Stringify())) ;
	saveRegisteredHistoryFixture( context, store, shardName, shardBody) ;
	saveRegisteredHistoryFixture( context, store, summaryName, summaryBody) ;
	saveRegisteredHistoryFixture( context, store, L"current/campaign-current-v2.json", pointerBody) ;
	auto registration = freshRoot.GetNamedArray( L"generations").GetObjectAt( 0U) ;	// 新G登録行。
	registration.Insert( L"summaryHash", JsonValue::CreateStringValue( digest( summaryBody))) ;
	root.GetNamedArray( L"generations").Append( registration) ;
	root.Insert( L"cacheInventory", cacheInventory) ;
	root.Insert( L"lastUtcMillis", summary.GetNamedValue( L"closedUtcMillis")) ;
	saveRegisteredHistoryFixture( context, store, L"current/campaign-root-v2.json",
								 winrt::to_string( root.Stringify())) ;
}

/** @brief 全完了履歴の登録件数と再照合込みraw容量を元68で拒否する境界fixtureです。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立した保護fixture root。
 * @param[in] baseline 正常二完了世代の全raw。
 * @param[in] job 同requestの元prepared入力。
 * @param[in] sources 固定組み込みsource集合。
 * @param[in] utc 元履歴以降の固定検査時計。
 * @param[in] definition 通常起動の現在source契約と公開入力。
 */
void completedHistoryBoundaryChecks( TestContext									  &context,
									const std::function<std::filesystem::path()>  &rootFactory,
									const std::map<std::wstring, std::string>	  &baseline,
									const CollectorPreparedProjectedJob			  &job,
									const std::span<const CollectorCampaignSource> sources,
									const std::uint64_t							   utc,
									const CollectorProjectedCampaignDefinition	  &definition)
{
	// 登録数と最終raw再読取りを含む累積byteの上限だけを独立fixtureで変更します。
	for( unsigned boundary = 0U; boundary < 3U; ++boundary) {
		LocalCollectorStateStore store ;	// 元正常二世代から境界だけを変更します。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 同じ元byteを境界fixtureの専用rootへ固定します。
		for( const auto &[name, raw] : baseline) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		auto root = JsonObject::Parse( winrt::to_hstring(
			// 元登録簿の所有copy。
			httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
		// 世代とCACHEはともに最大300登録を反復前に拒否します。
		if( boundary < 2U) {
			auto	   rows = root.GetNamedArray( boundary == 0U ? L"generations"
																: L"cacheInventory") ;	// 対象登録。
			const auto copy = rows.GetObjectAt( 0U) ;									// 内容を検査する前の件数上限へ到達させます。
			// 301件だけへ固定し、重複検査を上限拒否の代用にしません。
			while( rows.Size() < 301U) {
				rows.Append( copy) ;
			}
		} else {
			const auto raw = std::string( "{\"raw\":\"") + std::string( 1024U * 1024U - 10U, 'x') +
							 "\"}" ;	// 一file上限以内。
			std::wstring hash ;			// 合成凍結fileの実raw hash。
			DRIVERCRATE_EXPECT( context, computeBytesSha256( raw, hash) == 0U) ;
			// 33 MiBのrawは一回読取りでは64 MiB未満、必須再照合を含むと超過します。
			for( unsigned index = 0U; index < 33U; ++index) {
				const auto name = L"current/campaign-boundary-" + std::to_wstring( index) +
								  L".json" ;	// 固定fixture名。
				DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
				JsonObject registration ;	// hash一致の凍結raw。実legacy移行の受入とは呼びません。
				registration.Insert( L"name", JsonValue::CreateStringValue( name)) ;
				registration.Insert( L"hash", JsonValue::CreateStringValue( hash)) ;
				root.GetNamedArray( L"legacyFiles").Append( registration) ;
			}

			root.Insert( L"legacyFileCount", JsonValue::CreateNumberValue( 33.0)) ;
		}

		saveRegisteredHistoryFixture( context, store, L"current/campaign-root-v2.json",
									 winrt::to_string( root.Stringify())) ;
		const auto before = projectedStoreSnapshot( context, store) ;	// 拒否でも全byte不変です。
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
				   history ;	// 上限拒否時は空のまま。
		const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, job, sources, utc, history) ;	// 読取り予算を拡張しません。
		context.expect( code == ERROR_TOO_MANY_NAMES && !history &&
						   before == projectedStoreSnapshot( context, store),
					   "all completed boundary=" + std::to_string( boundary) +
						   " code=" + std::to_string( code),
					   __FILE__, __LINE__) ;
		// 通常起動も同じ登録上限で止めます。合成legacyは実移行ではなく元digest不一致で先に拒否します。
		LocalCollectorRecovery normal ;	// 上限拒否から新規登録へ切り替えません。
		const auto			   normalError = normal.initializeProjected( store, definition, utc,
																		0U) ;	// 元68と元legacy拒否を区別します。
		const DWORD			   expectedError =
			   boundary < 2U ? ERROR_TOO_MANY_NAMES
									 : ERROR_INVALID_DATA ;	// Windows定数と元APIのcode型を一致させます。
		context.expect( normalError == expectedError &&
						   before == projectedStoreSnapshot( context, store),
					   "normal completed boundary=" + std::to_string( boundary) +
						   " code=" + std::to_string( normalError),
					   __FILE__, __LINE__) ;
	}
}

/** @brief 完了済みstoreの通常再読込み・完了再検査と追加worker開始0を検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in,out] store 完了済みの保護store。
 * @param[in] definition 今回の公開入力。元入力と異なっても保存しません。
 * @param[in] prepared 最新の元完了prepared。新世代を偽装しません。
 * @param[in] utc 現検査UTC。
 */
void normalCompletedInventoryFixture(
	TestContext &context, LocalCollectorStateStore &store,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared,
	const std::uint64_t												 utc)
{
	const auto before = projectedStoreSnapshot( context, store) ;	// 全台帳・元像の非変更正本。
	LocalCollectorRecovery recovery ;								// 通常入口だけで最新完了の元入力を再読込みします。
	const auto			   code =
		// 元errorも報告します。
		recovery.initializeProjected( store, definition, utc, 0U) ;
	context.expect( code == 0U && recovery.reason() == L"GENERATION_COMPLETE" &&
					   recovery.generationKey() == prepared->generationKey() &&
					   recovery.terminalJobs() == prepared->jobCount(),
				   "normal completed code=" + std::to_string( code), __FILE__, __LINE__) ;
	// 初期化失敗後に無関係な完了操作を重ねず、原byte比較だけを残します。
	if( code != 0U) {
		DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store)) ;
		return ;
	}

	DRIVERCRATE_EXPECT( context, recovery.finishInitialProjected( utc + 1000U, 1000U) == 0U &&
									recovery.finishInitialProjected( utc + 2000U, 2000U) == 0U &&
									recovery.lastError() == 0U &&
									before == projectedStoreSnapshot( context, store)) ;
	std::size_t clients{} ;									// 拒否時にfake factoryさえ起動しないことを確認します。
	std::size_t threads{} ;									// Worker受付0。万一起動しても実HTTPは使いません。
	CollectorProjectedExecutorDependencies dependencies ;	// この同期fixtureの寿命内だけ借用します。
	dependencies.campaign	  = prepared ;
	dependencies.clock		  = [utc] { return CollectorHttpClockSample{utc + 2000U, 2000U} ; } ;
	dependencies.createClient = [&] {
		++clients ;
		return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
	} ;
	dependencies.start = [&]( std::function<void()> worker) {
		++threads ;
		return std::thread( std::move( worker)) ;
	} ;
	LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 元完了世代の専用pool。
	DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == ERROR_RETRY) ;
	const auto report = executor.join() ;	// 未開始でも元有限回収APIを確認します。
	DRIVERCRATE_EXPECT( context, report.error == 0U && report.reserved == 0U &&
									report.started == 0U && report.joined == 0U && clients == 0U &&
									threads == 0U &&
									before == projectedStoreSnapshot( context, store)) ;
}

/** @brief 全DEFERREDでCACHEなしの完了を通常入口で再検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立した保護fixture root。
 * @param[in] definition 元二source定義。
 * @param[in] prepared 未予約世代の元入力。
 */
void completedEmptyCacheChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	LocalCollectorStateStore store ;	// 一度もworkerを予約しない保護fixture。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
	{
		LocalCollectorRecovery pending ;	// 初回入力だけを登録します。
		DRIVERCRATE_EXPECT( context,
						   pending.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
	}
	{
		LocalCollectorRecovery deferred ;	// 日付変更で元分母を保って未予約jobだけを閉じます。
		DRIVERCRATE_EXPECT(
			context,
			deferred.initializeProjected( store, definition, HTTP_TEST_UTC + 86400000U, 0U) == 0U &&
				deferred.finishInitialProjected( HTTP_TEST_UTC + 86401000U, 1000U) == 0U) ;
	}
	const auto root = JsonObject::Parse( winrt::to_hstring(
		// CACHEを捏造しない元完了登録。
		httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
	DRIVERCRATE_EXPECT( context, root.GetNamedArray( L"cacheInventory").Size() == 0U) ;
	normalCompletedInventoryFixture( context, store, definition, prepared,
									HTTP_TEST_UTC + 86402000U) ;

	const auto cacheName = L"current/campaign-cache-v1-" + prepared->job( 0U)->value().requestKey +
						   L".json" ;	// 未登録CACHEの混入だけを確認します。
	DRIVERCRATE_EXPECT( context, store.write( cacheName, "{}") == 0U) ;
	const auto before = projectedStoreSnapshot( context, store) ;	// 不正fileも補完・削除しません。
	LocalCollectorRecovery invalid ;								// CACHEなしを初回履歴なしへ読み替えない通常検査。
	DRIVERCRATE_EXPECT( context,
					   invalid.initializeProjected( store, definition, HTTP_TEST_UTC + 86403000U,
												   0U) == ERROR_INVALID_DATA &&
						   before == projectedStoreSnapshot( context, store)) ;
}

/** @brief 同storeの次世代所有結果を保存し、全履歴と末尾完了を非通信検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立保護storeの生成先。
 * @param[in] definition 元二source定義。
 * @param[in] prepared 初回元prepared入力。
 */
void nextProjectedStorageChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	LocalCollectorStateStore first ;	// fake所有workerで初回完了を作ります。
	DRIVERCRATE_EXPECT( context, first.initialize( rootFactory(), true) == 0U) ;
	const auto responsesOwner = std::make_unique<
		std::array<CollectorProjectedResponseBytes, 2U>>() ;	// 固定件数と型を保って所有する。
	auto &responses = *responsesOwner ;							// 初回元codec応答。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, first, definition, prepared,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery finish ;	// 元証跡を通常初回完了へ登録します。
		DRIVERCRATE_EXPECT(
			context,
			finish.initializeProjected( first, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				finish.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto original		= projectedStoreSnapshot( context, first) ;	// 全改変条件へ元rawを複製。
	const auto oldCacheName = L"current/campaign-cache-v1-" +
							  // ASUS元成功CACHE。
							  prepared->job( 1U)->value().requestKey + L".json" ;
	CollectorProjectedCache oldCache ;	// 旧成功を次回metadataへコピーしません。
	DRIVERCRATE_EXPECT(
		context,
		decodeCollectorProjectedCache( httpSavedBody( first, oldCacheName), oldCache).status ==
			collector_projected_json::Status::OK) ;
	// 成功・減少・失敗・新要求・改変・hash故障・空・部分未予約を独立storeで検査します。
	for( unsigned scenario = 0U; scenario < 8U; ++scenario) {
		LocalCollectorStateStore store ;	// 原正本から一つの次回だけを進める保護store。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 元外側rawをそのまま複製し、任意DTOによる次世代成功を作りません。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		auto next = definition ;	// 同artifactと次日で履歴bindingを維持します。
		// 新requestだけ公開製品locatorを変え、旧CACHE欠損を模擬しません。
		if( scenario == 3U) {
			const auto manifest =
				// 元定義copy。
				JsonObject::Parse( winrt::to_hstring( next.manifestBytes)) ;
			manifest.GetNamedArray( L"targets")
				.GetObjectAt( 26U)
				.Insert( L"model", JsonValue::CreateStringValue( L"Fixture Changed Public Model")) ;
			manifest.GetNamedArray( L"jobs").GetObjectAt( 1U).Insert(
				L"locator", JsonValue::CreateStringValue( L"Fixture Changed Public Model")) ;
			next.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		}

		const auto identityOwner = std::make_unique<
			CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto &identity = *identityOwner ;										// 次日の元G／scope。
		std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;	// 固定元executor入力。
		DRIVERCRATE_EXPECT(
			context, makeCollectorProjectedCampaignIdentity( next, L"20260928", identity) &&
						 prepareCollectorProjectedCampaign(
							 identity.canonicalInput, identity.inputSha256, identity.generationKey,
							 next.artifactSha256, next.sources, campaign)) ;
		const auto utc = HTTP_TEST_UTC + 86400000U ;	// 旧24時間待機後。
		bool	   saved{} ;							// 正常保存条件だけ後で独立監督から完了します。
		{
			LocalCollectorRecovery recovery ;	// 前回全完了から明示次回を開始。
			DRIVERCRATE_EXPECT( context, recovery.initializeProjected( store, next, utc, 0U) == 0U &&
											recovery.beginNextProjected( next, utc, 1000U) == 0U) ;
			const auto queued = projectedStoreSnapshot( context, store) ;	// 未終端完了の非変更比較。
			DRIVERCRATE_EXPECT( context,
							   recovery.finishNextProjected( utc + 1000U, 1000U) == ERROR_RETRY &&
								   queued == projectedStoreSnapshot( context, store)) ;
			const auto fixturesOwner =
				std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
			auto &fixtures	 = *fixturesOwner ;					// 依存とfake本文を全joinまで所有。
			fixtures[0].body = winrt::to_string( winrt::hstring( projectedIntelHtml())) ;
			fixtures[1].body =
				winrt::to_string( winrt::hstring( projectedAsusRowsHtml( scenario == 1U   ? 1U
																	  : scenario == 6U ? 0U
																					   : 2U))) ;
			// 原通信失敗は成功sliceの消去へ読み替えません。
			if( scenario == 2U) {
				fixtures[1].failure = "read" ;
			}

			CollectorProjectedExecutorDependencies dependencies ;	// 本番native factoryは渡しません。
			dependencies.campaign = campaign ;
			dependencies.clock	  = [utc] {
				   return activeFixture ? activeFixture->clock
										: CollectorHttpClockSample{utc + 3000U, 3000U} ;
			} ; // Thread内は同じ観測、親は固定予約時計。
			dependencies.createClient = [] {
				return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
			} ; // 全通信をfakeへ固定。
			std::size_t workers{} ;	// 親writerだけが有限slotを数えます。
			dependencies.start = [&]( std::function<void()> worker) {
				const auto slot = workers++ ;	// Threadへ元slotを所有copy。
				return std::thread( [&, slot, worker = std::move( worker)] {
					fixtures[slot].ownerThread = std::this_thread::get_id() ;
					fixtures[slot].clock	   = {utc + 3000U, 3000U} ;
					FixtureScope scope( fixtures[slot]) ;	// 全native動作をthread別にfake化。
					worker() ;
				}) ;
			} ;
			LocalCollectorProjectedExecutor executor(
				// 元所有tokenを借用。
				std::move( dependencies)) ;
			DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == 0U &&
											(scenario == 7U || executor.startNext( recovery) == 0U)) ;
			const auto joined = executor.join() ;	// 親受領前に全threadを回収。
			DRIVERCRATE_EXPECT( context, joined.error == 0U &&
											joined.reserved == (scenario == 7U ? 1U : 2U) &&
											joined.joined == joined.reserved) ;
			// 同requestの前像を予約後に変え、外側hashが正しくても受領を拒否します。
			if( scenario == 4U) {
				mutateProjectedStore( context, store, oldCacheName, []( const auto &cache) {
					cache.Insert( L"reusable", JsonValue::CreateBooleanValue( false)) ;
				}) ;
			}

			const auto before = projectedStoreSnapshot( context, store) ;	// 受領前の全raw。
			const auto probe  = [scenario]( CollectorProjectedHashStage) -> std::int32_t {
				 return scenario == 5U ? E_ACCESSDENIED : 0 ;
			} ; // 元CNG失敗だけを注入し成功hashは自作しません。
			const auto accepted =
				recovery.acceptNextProjected( executor, scenario == 7U ? 0U : 1U, utc + 4000U, 4000U,
											 probe) ;	// ASUSを先行。
			context.expect( accepted == (scenario == 4U	 ? ERROR_INVALID_DATA
										: scenario == 5U ? static_cast<DWORD>( E_ACCESSDENIED)
														 : 0U),
						   "next owned storage scenario=" + std::to_string( scenario) +
							   " code=" + std::to_string( accepted),
						   __FILE__, __LINE__) ;
			// 拒否は全byte不変で、後続slotにも第一errorを返します。
			if( scenario == 4U || scenario == 5U || accepted != 0U) {
				DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store) &&
												recovery.acceptNextProjected(
													executor, 0U, utc + 5000U, 5000U) == accepted) ;
				continue ;
			}

			const auto partial =
				// 他slotは元RUNNINGのまま。
				projectedStoreSnapshot( context, store) ;
			// 一枠だけの正常保存後、他jobが未予約の末尾をそのまま再読込みします。
			if( scenario == 7U) {
				LocalCollectorStateStore partialStore ;	// 元部分保存を独立保護rootへ保持。
				DRIVERCRATE_EXPECT( context, partialStore.initialize( rootFactory(), true) == 0U) ;
				// 全rawを複製し未予約jobへ応答や精算を補完しません。
				for( const auto &[name, raw] : partial) {
					DRIVERCRATE_EXPECT( context, partialStore.write( name, raw) == 0U) ;
				}

				LocalCollectorRecovery reload ;	// 元終端一件＋未予約一件の通常inventory。
				const auto code = reload.initializeProjected( partialStore, next, utc + 6000U,
															 0U) ;	// 非変更再読込み。
				context.expect( code == 0U && reload.reason() == L"NEXT_GENERATION_READY" &&
								   reload.terminalJobs() == 1U &&
								   reload.finishNextProjected( utc + 7000U, 1000U) == ERROR_RETRY &&
								   partial == projectedStoreSnapshot( context, partialStore),
							   "next pending reload code=" + std::to_string( code), __FILE__,
							   __LINE__) ;
				continue ;
			}

			const auto second = recovery.acceptNextProjected( executor, 0U, utc + 5000U,
															 5000U) ;	// 別slot前進を許容。
			context.expect( second == 0U && recovery.terminalJobs() == 2U,
						   "next second storage scenario=" + std::to_string( scenario) +
							   " code=" + std::to_string( second),
						   __FILE__, __LINE__) ;
			saved			 = second == 0U ;
			const auto state = JsonObject::Parse( winrt::to_hstring(
				httpSavedBody( store,
							  L"current/campaign-state-v3-" + identity.generationKey +
								  L".json"))) ;	// 元Oの参照だけ。
			const auto op =
				std::wstring( state.GetNamedArray( L"jobs").GetObjectAt( 1U).GetNamedString(
					L"operation")) ;	// ASUS操作。
			const auto cacheName = L"current/campaign-cache-v1-" +
								   // 現在値。
								   campaign->job( 1U)->value().requestKey + L".json" ;
			CollectorProjectedCache cache ;	// 現応答から実導出した値。
			DRIVERCRATE_EXPECT(
				context,
				decodeCollectorProjectedCache( httpSavedBody( store, cacheName), cache).status ==
					collector_projected_json::Status::OK) ;
			// 同requestの元前像はcanonical全byteで保存し、新requestだけ欠損を保持します。
			if( scenario != 3U) {
				DRIVERCRATE_EXPECT( context, httpSavedBody( store, L"runs/campaign-effect-v2-" + op +
																	 L"-before-cache.json") ==
												httpSavedBody( first, oldCacheName)) ;
			}

			// 件数減少／失敗は旧成功の参照を保存し、今回成功とは集計しません。
			if( scenario == 1U || scenario == 2U || scenario == 6U) {
				const auto current = JsonObject::Parse( winrt::to_hstring(
					// Codec検証済み現CACHEの参照値。
					httpSavedBody( store, cacheName))) ;
				const auto prior   = JsonObject::Parse( winrt::to_hstring(
					  // Codec検証済み旧成功参照。
					  httpSavedBody( first, oldCacheName))) ;
				DRIVERCRATE_EXPECT( context,
								   current.GetNamedValue( L"original200").Stringify() ==
										   prior.GetNamedValue( L"original200").Stringify() &&
									   current.GetNamedArray( L"slices").Stringify() ==
										   prior.GetNamedArray( L"slices").Stringify()) ;
			}

			// 部分精算とRUNNINGの再起動は、中断回復未接続として非変更で待機します。
			if( scenario == 0U) {
				LocalCollectorStateStore partialStore ;	// 部分snapshotだけを別rootへ複製。
				DRIVERCRATE_EXPECT( context, partialStore.initialize( rootFactory(), true) == 0U) ;
				// 故障窓を任意応答で補完しません。
				for( const auto &[name, raw] : partial) {
					DRIVERCRATE_EXPECT( context, partialStore.write( name, raw) == 0U) ;
				}

				LocalCollectorRecovery reload ;	// 部分末尾の全閉包を非変更検査。
				const auto code = reload.initializeProjected( partialStore, next, utc + 6000U,
															 0U) ;	// 元時計だけ進めます。
				context.expect(
					code == ERROR_RETRY && reload.reason() == L"HISTORY_ACCEPTANCE_PENDING" &&
						partial == projectedStoreSnapshot( context, partialStore),
					"next partial reload code=" + std::to_string( code), __FILE__, __LINE__) ;
				const auto complete =
					// 二重受領の非変更正本。
					projectedStoreSnapshot( context, store) ;
				DRIVERCRATE_EXPECT( context,
								   recovery.acceptNextProjected( executor, 1U, utc + 6000U, 6000U) ==
										   ERROR_INVALID_DATA &&
									   complete == projectedStoreSnapshot( context, store)) ;
			}
		}
		// 元保存失敗を新完了成功へ変換しません。
		if( !saved) {
			continue ;
		}

		LocalCollectorRecovery finish ;	// 精算済み末尾を全再検査して完了。
		const auto			   reloaded =
			// 全閉包の通常読込み。
			finish.initializeProjected( store, next, utc + 7000U, 0U) ;
		const auto finished = reloaded == 0U ? finish.finishNextProjected( utc + 8000U, 1000U)
											 : reloaded ;	// 失敗は保持。
		context.expect( finished == 0U,
					   "next finish scenario=" + std::to_string( scenario) +
						   " code=" + std::to_string( finished),
					   __FILE__, __LINE__) ;
		// 不成立後にcontextをdereferenceして成功を作りません。
		if( finished != 0U) {
			continue ;
		}

		const auto complete =
			// 完了時刻も二重保存しません。
			projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT( context, finish.finishNextProjected( utc + 9000U, 2000U) == 0U &&
										complete == projectedStoreSnapshot( context, store)) ;
		// 元run／stateの全byteを保ち、現在CACHEとpointer以外の過去像を書き換えません。
		for( const auto &[name, raw] : original) {
			// 更新所有範囲の現在値だけを除外します。
			if( name.starts_with( L"runs/") ||
			   name == L"current/campaign-state-v3-" + prepared->generationKey() + L".json") {
				DRIVERCRATE_EXPECT( context, complete.at( name) == raw) ;
			}
		}

		std::shared_ptr<const CollectorRegisteredProjectedHistory>
				   history ;	// 全完了後だけ公開context。
		const auto inspected = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, *campaign->job( 1U), next.sources, utc + 10000U, history) ;	// 同じ全有限core。
		context.expect( inspected == 0U && history &&
						   history->operations() == (scenario == 3U ? 1U : 2U) &&
						   complete == projectedStoreSnapshot( context, store),
					   "next completed history scenario=" + std::to_string( scenario) +
						   " code=" + std::to_string( inspected),
					   __FILE__, __LINE__) ;
		// 同じ完了監督から翌日の第三世代を明示開始し、元二世代を保ちます。
		if( scenario == 0U) {
			const auto third =
				// 同監督の継続。
				finish.beginNextProjected( next, utc + 86400000U, 3000U) ;
			context.expect( third == 0U && finish.reason() == L"NEXT_GENERATION_READY" &&
							   finish.terminalJobs() == 0U,
						   "next third generation code=" + std::to_string( third), __FILE__,
						   __LINE__) ;
		}
	}
}

/** @brief 元次世代workerの未登録応答・準備像を非再送で回復する保存窓を検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立保護fixture root。
 * @param[in] definition 元二source定義。
 * @param[in] prepared 初回の所有入力。
 */
void nextProjectedPreparedRecoveryChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	LocalCollectorStateStore first ;	// 同じ元workerから初回完了の正本を作ります。
	DRIVERCRATE_EXPECT( context, first.initialize( rootFactory(), true) == 0U) ;
	const auto initialOwner = std::make_unique<
		std::array<CollectorProjectedResponseBytes, 2U>>() ;	// 固定件数と型を保って所有する。
	auto &initial = *initialOwner ;								// 元専用codecの所有値。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, first, definition, prepared,
															   0U, {}, initial) == 0U) ;
	{
		LocalCollectorRecovery finish ;	// 初回の元集計を不変登録します。
		DRIVERCRATE_EXPECT(
			context,
			finish.initializeProjected( first, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				finish.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto original = projectedStoreSnapshot( context, first) ;	// 過去の全rawを各独立条件へ複製。
	const auto utc		= HTTP_TEST_UTC + 86400000U ;				// 翌日の元予約時計。
	// 既存request・新request・原通信失敗・減少・空・未予約残留を独立に検査します。
	for( unsigned scenario = 0U; scenario < 6U; ++scenario) {
		auto next = definition ;	// 新request以外は旧scopeを保ちます。
		// locatorを変える新requestだけはCACHE前像を持ちません。
		if( scenario == 1U) {
			const auto manifest =
				// 有限所有copy。
				JsonObject::Parse( winrt::to_hstring( next.manifestBytes)) ;
			manifest.GetNamedArray( L"targets")
				.GetObjectAt( 26U)
				.Insert( L"model", JsonValue::CreateStringValue( L"Fixture New Recovery Model")) ;
			manifest.GetNamedArray( L"jobs").GetObjectAt( 1U).Insert(
				L"locator", JsonValue::CreateStringValue( L"Fixture New Recovery Model")) ;
			next.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		}

		const auto identityOwner = std::make_unique<
			CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto &identity = *identityOwner ;										// 元日付・artifact・scopeの結合。
		std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;	// 次回専用の入力寿命。
		DRIVERCRATE_EXPECT(
			context, makeCollectorProjectedCampaignIdentity( next, L"20260928", identity) &&
						 prepareCollectorProjectedCampaign(
							 identity.canonicalInput, identity.inputSha256, identity.generationKey,
							 next.artifactSha256, next.sources, campaign)) ;
		LocalCollectorStateStore store ;	// 保存窓の元正常経路だけを進める独立store。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 元envelopeを全byteコピーし、次回成功を任意DTOで組み立てません。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		std::vector<std::map<std::wstring, std::string>> windows ;	// 未登録の元checkpoint全raw。
		std::vector<std::map<std::wstring, std::string>>
				   registered ;	// 論理前像から検査する登録・反映窓。
		const auto responseOwner = std::make_unique<
			CollectorProjectedResponseBytes>() ;		// 同じscopeだけで大きなfixtureを所有する。
		auto			 &response = *responseOwner ;	// 偽通信でも元workerの独立codec出力です。
		std::wstring	  op ;							// 元応答から取得する唯一の操作hash。
		std::size_t		  sends{} ;						// 回復中の再通信なしを元fixture計数で確認します。
		const std::size_t acceptIndex =
			// 未予約残留だけIntel一件を保存します。
			scenario == 5U ? 0U : 1U ;
		const std::size_t expectedWorkers = scenario == 5U ? 1U : 2U ;	// 全join分母は元予約数です。
		const DWORD		  expectedRestart =
			// RUNNING残留だけ待機です。
			scenario == 5U ? ERROR_SUCCESS : ERROR_RETRY ;
		bool armed{} ;	// 日次切替の同名checkpointを応答保存窓へ混同しません。
		{
			LocalCollectorRecovery recovery ;	// 元所有executorの親監督。
			const auto			   stop = [&]( const CollectorRecoveryCheckpoint point) {
				// 親応答受領後だけ保存直後の元rawを取得します。
				if( armed) {
					// 最初の二条件では未登録全窓、残りは実停止RESPONSEだけを保存します。
					if( point == CollectorRecoveryCheckpoint::RESPONSE ||
					   (scenario < 2U &&
						(point == CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT ||
						 point == CollectorRecoveryCheckpoint::PROJECTED_EFFECT ||
						 point == CollectorRecoveryCheckpoint::EFFECTS))) {
						windows.push_back( projectedStoreSnapshot( context, store)) ;
					}

					// 既存・新requestの登録と全四role反映の元byteを保持します。
					if( scenario < 2U && (point == CollectorRecoveryCheckpoint::REGISTERED ||
										 point == CollectorRecoveryCheckpoint::APPLIED)) {
						registered.push_back( projectedStoreSnapshot( context, store)) ;
					}
				}

				return armed && scenario >= 2U && point == CollectorRecoveryCheckpoint::RESPONSE ;
			} ; // 中断後の第一995を成功へ変更しません。
			DRIVERCRATE_EXPECT( context,
							   recovery.initializeProjected( store, next, utc, 0U, stop) == 0U &&
								   recovery.beginNextProjected( next, utc, 1000U) == 0U) ;
			const auto fixturesOwner =
				std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
			auto &fixtures	 = *fixturesOwner ;					// 二threadの独立fake HTTPのみ。
			fixtures[0].body = winrt::to_string( winrt::hstring( projectedIntelHtml())) ;
			fixtures[1].body =
				winrt::to_string( winrt::hstring( projectedAsusRowsHtml( scenario == 3U   ? 1U
																	  : scenario == 4U ? 0U
																					   : 2U))) ;
			// 原read errorを回復の成功codeで塗り替えません。
			if( scenario == 2U) {
				fixtures[1].failure = "read" ;
				fixtures[1].error	= ERROR_ACCESS_DENIED ;
			}

			CollectorProjectedExecutorDependencies dependencies ;	// 実native factoryを渡しません。
			dependencies.campaign = campaign ;
			dependencies.clock	  = [utc] {
				   return activeFixture ? activeFixture->clock
										: CollectorHttpClockSample{utc + 3000U, 3000U} ;
			} ; // 同じ元二時計。
			dependencies.createClient = [] {
				return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
			} ; // 偽HTTPだけ。
			std::size_t workers{} ;	// 起動順slotを親だけが数えます。
			dependencies.start = [&]( std::function<void()> worker) {
				const auto slot = workers++ ;	// 元slotをthreadへ所有copyします。
				return std::thread( [&, slot, worker = std::move( worker)] {
					fixtures[slot].ownerThread = std::this_thread::get_id() ;
					fixtures[slot].clock	   = {utc + 3000U, 3000U} ;
					FixtureScope scope( fixtures[slot]) ;	// 全joinまで依存を所有します。
					worker() ;
				}) ;
			} ;
			LocalCollectorProjectedExecutor executor(
				// 元所有tokenへの結合。
				std::move( dependencies)) ;
			DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == 0U &&
											(scenario == 5U || executor.startNext( recovery) == 0U)) ;
			const auto joined = executor.join() ;	// 保存前に二worker全回収。
			DRIVERCRATE_EXPECT( context, joined.error == 0U && joined.reserved == expectedWorkers &&
											joined.joined == expectedWorkers) ;
			armed			= true ;
			const auto code = recovery.acceptNextProjected( executor, acceptIndex, utc + 4000U,
														   4000U) ;	// ASUS応答だけ先行保存。
			context.expect( code == (scenario < 2U ? 0U : ERROR_OPERATION_ABORTED),
						   "prepared next source scenario=" + std::to_string( scenario) +
							   " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
			sends = fixtures[0].calls["send"] + fixtures[1].calls["send"] ;
			DRIVERCRATE_EXPECT( context, sends == expectedWorkers && !windows.empty()) ;
			// 中断の第一errorを同監督の再受領でも維持します。
			if( scenario >= 2U) {
				const auto interrupted =
					// 中断後の元全byte。
					projectedStoreSnapshot( context, store) ;
				DRIVERCRATE_EXPECT( context,
								   recovery.acceptNextProjected( executor, acceptIndex, utc + 5000U,
																5000U) == ERROR_OPERATION_ABORTED &&
									   interrupted == projectedStoreSnapshot( context, store)) ;
			}

			DRIVERCRATE_EXPECT(
				context,
				computeBytesSha256(
					"response-v2\n" + winrt::to_string( campaign->generationKey()) + "\n" +
						winrt::to_string( campaign->job( acceptIndex)->value().jobKey) + "\n",
					op) == 0U) ;
			std::string raw ;		// Stringifyを介さない保存済み元v4。
			bool		found{} ;	// 元応答の欠損を許可しません。
			DRIVERCRATE_EXPECT(
				context,
				store.read( L"runs/campaign-response-v4-" + op + L".json", raw, found) == 0U &&
					found &&
					decodeCollectorProjectedResponse( campaign->job( acceptIndex)->value(), raw,
													 response)
							.result.status == collector_projected_json::Status::OK) ;
			DRIVERCRATE_EXPECT( context,
							   response.value.error == (scenario == 2U ? ERROR_ACCESS_DENIED : 0U)) ;
		}
		DRIVERCRATE_EXPECT( context, windows.size() == (scenario == 0U	? 10U
													   : scenario == 1U ? 9U
																		: 1U)) ;
		// 固定応答から不足像を保存・精算し、再起動二回目は一byteも変更しません。
		for( std::size_t window = 0U; window < windows.size(); ++window) {
			LocalCollectorStateStore resumed ;	// 一つの保存窓だけを独立に回復します。
			DRIVERCRATE_EXPECT( context, resumed.initialize( rootFactory(), true) == 0U) ;
			// 保存直後の原全rawをそのまま再開入力にします。
			for( const auto &[name, raw] : windows[window]) {
				DRIVERCRATE_EXPECT( context, resumed.write( name, raw) == 0U) ;
			}

			{
				LocalCollectorRecovery restart ;	// 初回回収経路へ流用しません。
				const auto code = restart.initializeProjected( resumed, next, utc + 6000U,
															  0U) ;	// 未応答Intelは待機で残す。
				context.expect(
					code == expectedRestart && restart.terminalJobs() == 1U &&
						restart.reason() == (scenario == 5U ? L"NEXT_GENERATION_READY"
															: L"HISTORY_ACCEPTANCE_PENDING"),
					"prepared next recovery scenario=" + std::to_string( scenario) +
						" window=" + std::to_string( window) + " code=" + std::to_string( code),
					__FILE__, __LINE__) ;
				// 第一不成立を保持して、null／欠損の後続検査へ進みません。
				if( code != expectedRestart || restart.terminalJobs() != 1U) {
					continue ;
				}

				// RUNNINGを残す復旧からの開始はfactory・workerへ一度も進みません。
				if( scenario == 0U && window == 0U) {
					std::size_t							   clients{} ;		// 未呼出しのfactory計数。
					std::size_t							   starts{} ;		// 未呼出しのworker起動計数。
					CollectorProjectedExecutorDependencies dependencies ;	// 元所有入力だけ。
					dependencies.campaign = campaign ;
					dependencies.clock	  = [utc] {
						   return CollectorHttpClockSample{utc + 7000U, 1000U} ;
					} ; // 親時計のみ。
					dependencies.createClient = [&]() -> std::unique_ptr<LocalCollectorHttpClient> {
						++clients ;
						return {} ;
					} ; // 呼出しに到達すれば試験不成立です。
					dependencies.start = [&]( std::function<void()> worker) {
						++starts ;
						return std::thread( std::move( worker)) ;
					} ; // 必須factoryですが起動を許可しません。
					const auto before =
						// 原復旧後の全byte。
						projectedStoreSnapshot( context, resumed) ;
					LocalCollectorProjectedExecutor blocked(
						// 新executorも再送不可。
						std::move( dependencies)) ;
					DRIVERCRATE_EXPECT( context,
									   blocked.startNext( restart) == ERROR_RETRY &&
										   blocked.join().reserved == 0U && clients == 0U &&
										   starts == 0U &&
										   before == projectedStoreSnapshot( context, resumed)) ;
				}
			}
			const auto recovered = projectedStoreSnapshot( context, resumed) ;	// 一回精算後の全raw。
			const auto responseName =
				L"runs/campaign-response-v4-" + op + L".json" ;	// 元envelopeは不変。
			DRIVERCRATE_EXPECT( context,
							   recovered.at( responseName) == windows[window].at( responseName) &&
								   sends == expectedWorkers) ;
			const auto budgetOwner = std::make_unique<
				CollectorBudgetSnapshot>() ;	// 同じscopeだけで大きなfixtureを所有する。
			auto &budget = *budgetOwner ;		// Intelは未精算、ASUSだけphase1。
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 httpSavedBody( resumed, L"current/campaign-budget-v1.json"), budget) &&
							 budget.reservations.size() == expectedWorkers &&
							 std::count_if( budget.reservations.begin(), budget.reservations.end(),
										   []( const auto &row) { return row.phase == 1U ; }) == 1) ;
			// 全過去run・stateと完了pointerは応答回復でも不変です。
			for( const auto &[name, raw] : original) {
				// 共有台帳と更新対象CACHEだけは今回の元応答へ進めます。
				if( name.starts_with( L"runs/") || name.starts_with( L"current/campaign-state-") ||
				   name == L"current/campaign-current-v2.json") {
					DRIVERCRATE_EXPECT( context, recovered.at( name) == raw) ;
				}
			}

			LocalCollectorRecovery twice ;	// 同応答の再精算・待機延長はしません。
			DRIVERCRATE_EXPECT( context, twice.initializeProjected( resumed, next, utc + 7000U, 0U) ==
												expectedRestart &&
											twice.terminalJobs() == 1U &&
											recovered == projectedStoreSnapshot( context, resumed)) ;
		}

		DRIVERCRATE_EXPECT( context, registered.size() == (scenario < 2U ? 5U : 0U)) ;
		// 全前像検証後に残りのroleだけを精算し、反映済みprefixを二重保存しません。
		for( std::size_t window = 0U; window < registered.size(); ++window) {
			const auto &snapshot = registered[window] ;	// 登録直後と四roleの各反映直後。
			LocalCollectorStateStore resumed ;			// 元物理prefixを独立に再読込み。
			DRIVERCRATE_EXPECT( context, resumed.initialize( rootFactory(), true) == 0U) ;
			// 元登録・反映窓をそのままコピーします。
			for( const auto &[name, raw] : snapshot) {
				DRIVERCRATE_EXPECT( context, resumed.write( name, raw) == 0U) ;
			}

			std::size_t applied{} ;	// 未反映suffixだけの保存回数。
			const auto	observe = [&]( const CollectorRecoveryCheckpoint point) {
				 applied += point == CollectorRecoveryCheckpoint::APPLIED ? 1U : 0U ;
				 return false ;
			} ; // 偽通信・新予約は呼び出しません。
			{
				LocalCollectorRecovery restart ;	// 全物理rawを確認してから一回精算します。
				const auto code = restart.initializeProjected( resumed, next, utc + 6000U, 0U,
															  observe) ;	// 元prefixの回復。
				context.expect(
					code == ERROR_RETRY && restart.terminalJobs() == 1U && applied == 4U - window,
					"registered next recovery scenario=" + std::to_string( scenario) +
						" window=" + std::to_string( window) + " code=" + std::to_string( code),
					__FILE__, __LINE__) ;
				// 第一不成立を保持し、欠損値への後続アクセスを避けます。
				if( code != ERROR_RETRY || restart.terminalJobs() != 1U) {
					continue ;
				}
			}

			const auto recovered = projectedStoreSnapshot( context, resumed) ;	// 精算後の全原byte。
			// 固定証跡と過去完了pointerを巻き戻し・再構築しません。
			for( const auto &[name, raw] : snapshot) {
				// 今回の四現在台帳とrootだけが更新対象です。
				if( name.starts_with( L"runs/") || name == L"current/campaign-current-v2.json") {
					DRIVERCRATE_EXPECT( context, recovered.at( name) == raw) ;
				}
			}

			const auto budgetOwner = std::make_unique<
				CollectorBudgetSnapshot>() ;	// 同じscopeだけで大きなfixtureを所有する。

			auto &budget = *budgetOwner ;	// 元予約の精算を二重計上しません。
			DRIVERCRATE_EXPECT(
				context, parseCollectorBudgetSnapshot(
							 httpSavedBody( resumed, L"current/campaign-budget-v1.json"), budget) &&
							 budget.reservations.size() == 2U &&
							 std::count_if( budget.reservations.begin(), budget.reservations.end(),
										   []( const auto &row) { return row.phase == 1U ; }) == 1 &&
							 sends == expectedWorkers) ;
			LocalCollectorRecovery twice ;	// 再読込みで再保存を行いません。
			DRIVERCRATE_EXPECT( context, twice.initializeProjected( resumed, next, utc + 7000U, 0U) ==
												ERROR_RETRY &&
											twice.terminalJobs() == 1U &&
											recovered == projectedStoreSnapshot( context, resumed)) ;
		}

		// 登録済み窓の再中断と改変拒否を既存・新requestの両方で検査します。
		if( scenario < 2U) {
			// 復旧中の各APPLIED直後から、別監督は残りだけを精算します。
			for( std::size_t cut = 1U; cut <= 4U; ++cut) {
				LocalCollectorStateStore interrupted ;	// 登録だけ済んだ元prefixです。
				DRIVERCRATE_EXPECT( context, interrupted.initialize( rootFactory(), true) == 0U) ;
				// 回復以前の全rawを維持します。
				for( const auto &[name, raw] : registered.front()) {
					DRIVERCRATE_EXPECT( context, interrupted.write( name, raw) == 0U) ;
				}

				std::size_t applied{} ;	// 中断位置の元保存回数。
				const auto	stop = [&]( const CollectorRecoveryCheckpoint point) {
					 // 固定保存直後だけ、親取消しまたは原Win32失敗を注入します。
					 if( point == CollectorRecoveryCheckpoint::APPLIED && ++applied == cut) {
						 // 第二窓だけ取消しとは異なる原errorを保持します。
						 if( cut == 2U) {
							 throw DWORD{ERROR_ACCESS_DENIED} ;
						 }

						 return true ;
					 }

					 return false ;
				 } ; // 再通信の依存を一切渡しません。
				const DWORD expected =
					// 元第一error。
					cut == 2U ? ERROR_ACCESS_DENIED : ERROR_OPERATION_ABORTED ;
				{
					LocalCollectorRecovery stopped ;	// 同監督の再呼出しは原第一errorです。
					DRIVERCRATE_EXPECT( context,
									   stopped.initializeProjected( interrupted, next, utc + 6000U,
																   0U, stop) == expected &&
										   applied == cut) ;
					const auto before =
						// 停止後の物理prefix。
						projectedStoreSnapshot( context, interrupted) ;
					DRIVERCRATE_EXPECT( context,
									   stopped.initializeProjected( interrupted, next, utc + 7000U,
																   1000U) == expected &&
										   before == projectedStoreSnapshot( context, interrupted)) ;
				}
				applied			   = 0U ;
				const auto observe = [&]( const CollectorRecoveryCheckpoint point) {
					applied += point == CollectorRecoveryCheckpoint::APPLIED ? 1U : 0U ;
					return false ;
				} ; // 残りの保存だけを数えます。
				{
					LocalCollectorRecovery fresh ;	// 保存prefixを新監督で検証し直します。
					const auto code = fresh.initializeProjected( interrupted, next, utc + 8000U, 0U,
																observe) ;	// 論理前像の再検査。
					context.expect(
						code == ERROR_RETRY && fresh.terminalJobs() == 1U && applied == 4U - cut,
						"registered interrupted scenario=" + std::to_string( scenario) +
							" cut=" + std::to_string( cut) + " code=" + std::to_string( code),
						__FILE__, __LINE__) ;
				}
				const auto recovered =
					// 二回目の固定結果。
					projectedStoreSnapshot( context, interrupted) ;
				LocalCollectorRecovery twice ;	// 終了した原応答は再精算しません。
				DRIVERCRATE_EXPECT( context,
								   twice.initializeProjected( interrupted, next, utc + 9000U, 0U) ==
										   ERROR_RETRY &&
									   recovered == projectedStoreSnapshot( context, interrupted)) ;
			}

			// 正しい外側hashを持つ改変でも、全履歴と固定prefixの関係が不正なら書込み前に拒否します。
			for( unsigned mutation = 0U; mutation < 14U; ++mutation) {
				auto snapshot =
					registered[mutation == 8U ? 2U : 0U] ;				// 他request破損だけCACHE反映後です。
				const auto effect = L"runs/campaign-effect-v2-" + op ;	// 固定登録の元nameです。
				// 必須proofの欠損はコピー前の独立集合にだけ作ります。
				if( mutation < 3U) {
					snapshot.erase( mutation == 0U ? effect + L"-before-control.json"
								   : mutation == 1U
									   ? effect + L"-budget.json"
									   : L"runs/campaign-response-v4-" + op + L".json") ;
				}

				LocalCollectorStateStore rejected ;	// 各一要因改変を独立rootへ保持します。
				DRIVERCRATE_EXPECT( context, rejected.initialize( rootFactory(), true) == 0U) ;
				// 保存物を縮退させず元raw集合を複写します。
				for( const auto &[name, raw] : snapshot) {
					DRIVERCRATE_EXPECT( context, rejected.write( name, raw) == 0U) ;
				}

				// 元response結合・kind・role順・時刻・世代をそれぞれ改変します。
				if( (mutation >= 3U && mutation <= 6U) || mutation == 13U) {
					mutateProjectedStore(
						context, rejected, L"current/campaign-root-v2.json",
						[mutation]( auto &root) {
							auto commit =
								// 外側hashは正しく再作成されます。
								root.GetNamedObject( L"commit") ;
							// 別応答・別kind・別世代は元登録の代替になりません。
							if( mutation == 3U || mutation == 4U || mutation == 13U) {
								commit.Insert(
									mutation == 3U	 ? L"response"
									: mutation == 4U ? L"kind"
													 : L"generation",
									JsonValue::CreateStringValue(
										mutation == 4U ? L"DAY_ROLL" : std::wstring( 64U, L'f'))) ;
							}

							// 二roleの順序だけを独立に破ります。
							if( mutation == 5U) {
								// 二roleの並替えだけで元固定反映順を破ります。
								auto rows =
									// 登録順の有限四件。
									commit.GetNamedArray( L"effects") ;
								const auto first =
									// aliasでも元first値を保持します。
									rows.GetAt( 0U) ;
								rows.SetAt( 0U, rows.GetAt( 1U)) ;
								rows.SetAt( 1U, first) ;
							}

							// 正常な数値型のまま元accepted結合を破ります。
							if( mutation == 6U) {
								commit.Insert( L"accepted",
											  JsonValue::CreateNumberValue(
												  commit.GetNamedNumber( L"accepted") + 1.0)) ;
							}
						}) ;
				}

				// CONTROL前像のままJOBだけを後像にする逆順を拒否します。
				if( mutation == 7U) {
					saveRegisteredHistoryFixture( context, rejected,
												 L"current/campaign-state-v3-" +
													 campaign->generationKey() + L".json",
												 httpSavedBody( rejected, effect + L"-job.json")) ;
				}

				// 今回以外のCACHEも全履歴検査から除外しません。
				if( mutation == 8U || mutation == 10U) {
					const auto name =
						mutation == 8U ? L"current/campaign-cache-v1-" +
											 prepared->job( 0U)->value().requestKey + L".json"
									   : effect + L"-cache.json" ;	// 他requestまたは今回の準備後像。
					mutateProjectedStore( context, rejected, name, []( auto &cache) {
						cache.Insert( L"reusable", JsonValue::CreateBooleanValue(
													  !cache.GetNamedBoolean( L"reusable"))) ;
					}) ;
					// 改変後像とdescriptorのhashを自己一貫させても独立導出へ一致しません。
					if( mutation == 10U) {
						std::wstring changed ;	// 正しいCNGで改変後像のhashを再作成します。
						DRIVERCRATE_EXPECT(
							context,
							computeBytesSha256( httpSavedBody( rejected, name), changed) == 0U) ;
						mutateProjectedStore( context, rejected, L"current/campaign-root-v2.json",
											 [&changed]( auto &root) {
												 root.GetNamedObject( L"commit")
													 .GetNamedArray( L"effects")
													 .GetObjectAt( 1U)
													 .Insert( L"after",
															 JsonValue::CreateStringValue( changed)) ;
											 }) ;
					}
				}

				// 保存v4の開始時刻は元RUNNING予約と一致しなければなりません。
				if( mutation == 9U) {
					mutateProjectedStore(
						context, rejected, L"runs/campaign-response-v4-" + op + L".json",
						[utc]( auto &value) {
							value.Insert( L"started", JsonValue::CreateNumberValue(
														 static_cast<double>( utc + 2000U))) ;
						}) ;
				}

				// 物理値を前像／後像以外へ変更すると論理ビューを作りません。
				if( mutation == 11U) {
					mutateProjectedStore(
						context, rejected, L"current/campaign-controls-v1.json", []( auto &value) {
							value.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
						}) ;
				}

				// 新requestへの偽前像、既存requestへの未知proof追加も拒否します。
				if( mutation == 12U) {
					const auto name = scenario == 1U
										  ? effect + L"-before-cache.json"
										  : L"runs/campaign-effect-v2-" + std::wstring( 64U, L'f') +
												L"-cache.json" ;	// 未登録固定名。
					saveRegisteredHistoryFixture( context, rejected, name,
												 httpSavedBody( rejected, effect + L"-cache.json")) ;
				}

				const auto before =
					// 全拒否の非変更正本。
					projectedStoreSnapshot( context, rejected) ;
				LocalCollectorRecovery restart ;	// 値を修復して成功扱いにしません。
				const auto			   code =
					// 元形式拒否。
					restart.initializeProjected( rejected, next, utc + 6000U, 0U) ;
				context.expect( code == ERROR_INVALID_DATA &&
								   before == projectedStoreSnapshot( context, rejected),
							   "registered next reject scenario=" + std::to_string( scenario) +
								   " mutation=" + std::to_string( mutation) +
								   " code=" + std::to_string( code),
							   __FILE__, __LINE__) ;
			}
		}

		// 原成功条件の全準備像から、一要因の自己一貫改変／欠損を拒否します。
		if( scenario == 0U) {
			LocalCollectorStateStore stopped ;	// 復旧そのものの保存途中errorを別rootへ残します。
			DRIVERCRATE_EXPECT( context, stopped.initialize( rootFactory(), true) == 0U) ;
			// 元応答だけが保存された窓から一回の回復を開始します。
			for( const auto &[name, raw] : windows.front()) {
				DRIVERCRATE_EXPECT( context, stopped.write( name, raw) == 0U) ;
			}

			{
				LocalCollectorRecovery restart ;	// 元DWORDをHRESULTや13へ変えません。
				const auto failure = []( const CollectorRecoveryCheckpoint point) -> bool {
					// 固定CONTROL前像保存後だけ原errorを注入します。
					if( point == CollectorRecoveryCheckpoint::PROJECTED_BEFORE_EFFECT) {
						throw DWORD{ERROR_ACCESS_DENIED} ;
					}

					return false ;
				} ; // 再通信や値の変更ではない保存窓の故障です。
				DRIVERCRATE_EXPECT( context,
								   restart.initializeProjected( stopped, next, utc + 6000U, 0U,
															   failure) == ERROR_ACCESS_DENIED) ;
				const auto before =
					// 原失敗後の準備prefix。
					projectedStoreSnapshot( context, stopped) ;
				DRIVERCRATE_EXPECT( context,
								   restart.initializeProjected( stopped, next, utc + 7000U, 1000U) ==
										   ERROR_ACCESS_DENIED &&
									   before == projectedStoreSnapshot( context, stopped)) ;
			}
			{
				LocalCollectorRecovery fresh ;	// 別監督だけが原prefixを再検査して完了します。
				DRIVERCRATE_EXPECT( context, fresh.initializeProjected( stopped, next, utc + 8000U,
																	  0U) == ERROR_RETRY &&
												fresh.terminalJobs() == 1U) ;
			}
			// 外側hashが正しくても、古い他request／今回像／保存順／応答が不正なら保存を始めません。
			for( unsigned mutation = 0U; mutation < 8U; ++mutation) {
				auto snapshot = windows.back() ;	// 全八像を保存した未登録prefix。
				// prefixの穴と応答欠損は新しいfixtureを作る前にraw集合から除きます。
				if( mutation == 4U || mutation == 5U) {
					snapshot.erase( mutation == 4U
									   ? L"runs/campaign-effect-v2-" + op + L"-before-control.json"
									   : L"runs/campaign-response-v4-" + op + L".json") ;
				}

				LocalCollectorStateStore rejected ;	// 改変だけを持つ独立protected root。
				DRIVERCRATE_EXPECT( context, rejected.initialize( rootFactory(), true) == 0U) ;
				// 全rawを保持し、改変を失敗後に戻しません。
				for( const auto &[name, raw] : snapshot) {
					DRIVERCRATE_EXPECT( context, rejected.write( name, raw) == 0U) ;
				}

				// CACHE codecは正しいまま意味関係だけを変えます。
				if( mutation == 0U || mutation == 2U || mutation == 3U) {
					const auto name =
						mutation == 0U
							? L"current/campaign-cache-v1-" +
								  prepared->job( 0U)->value().requestKey + L".json"
							: L"runs/campaign-effect-v2-" + op +
								  (mutation == 2U ? L"-before-cache.json"
												  : L"-cache.json") ;	// 要求外または準備像。
					mutateProjectedStore( context, rejected, name, []( auto &cache) {
						cache.Insert( L"reusable", JsonValue::CreateBooleanValue(
													  !cache.GetNamedBoolean( L"reusable"))) ;
					}) ;
				}

				// 元v4のscopeや開始時刻だけを変えて外側hashを正しく作り直します。
				if( mutation == 1U || mutation == 6U) {
					mutateProjectedStore(
						context, rejected, L"runs/campaign-response-v4-" + op + L".json",
						[mutation, utc]( auto &value) {
							value.Insert( mutation == 1U ? L"request" : L"started",
										 mutation == 1U
											 ? JsonValue::CreateStringValue( std::wstring( 64U, L'f'))
											 : JsonValue::CreateNumberValue(
												   static_cast<double>( utc + 2000U))) ;
						}) ;
				}

				// 新保存名に旧schemaを置く併存も単一応答へ縮退しません。
				if( mutation == 7U) {
					DRIVERCRATE_EXPECT( context,
									   rejected.write( L"runs/campaign-response-v3-" + op + L".json",
													  snapshot.at( L"runs/campaign-response-v4-" +
																  op + L".json")) == 0U) ;
				}

				const auto before =
					// 全拒否の非変更正本。
					projectedStoreSnapshot( context, rejected) ;
				LocalCollectorRecovery restart ;	// 検査失敗後はcommitを作りません。
				const auto			   code =
					// 形式拒否は13。
					restart.initializeProjected( rejected, next, utc + 6000U, 0U) ;
				context.expect( code == ERROR_INVALID_DATA &&
								   before == projectedStoreSnapshot( context, rejected),
							   "prepared next reject mutation=" + std::to_string( mutation) +
								   " code=" + std::to_string( code),
							   __FILE__, __LINE__) ;
			}
		}
	}
}

/** @brief 明示次回開始・末尾再読込み・所有予約と原proof保持を非通信検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立した保護fixture root。
 * @param[in] definition 元二source公開定義。
 * @param[in] prepared 最初の元入力とscope。
 */
void nextProjectedGenerationChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	LocalCollectorStateStore first ;	// 所有fake workerから一つの完了正本を作る。
	DRIVERCRATE_EXPECT( context, first.initialize( rootFactory(), true) == 0U) ;
	const auto responsesOwner = std::make_unique<
		std::array<CollectorProjectedResponseBytes, 2U>>() ;	// 固定件数と型を保って所有する。
	auto &responses = *responsesOwner ;							// 初回の実codec出力。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, first, definition, prepared,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery complete ;	// 全終端から元完了像を登録する。
		DRIVERCRATE_EXPECT(
			context,
			complete.initializeProjected( first, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				complete.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto original		  = projectedStoreSnapshot( context, first) ;	// 全過去像を保持する正本。
	const auto intelOperation = std::wstring(
		JsonObject::Parse(
			winrt::to_hstring( httpSavedBody( first, L"current/campaign-state-v3-" +
													   prepared->generationKey() + L".json")))
			.GetNamedArray( L"jobs")
			.GetObjectAt( 0U)
			.GetNamedString( L"operation")) ;				// 保存元Oだけを参照する。
	std::map<std::wstring, std::string> queued ;			// 改変条件へ同じ新世代を複製する。
	std::map<std::wstring, std::string> newRequestQueued ;	// 未登録requestを持つ元登録正本。
	CollectorProjectedCampaignDefinition
		newRequestDefinition ;	// 予約直前の改変条件へ同じ定義を使う。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		 newRequestCampaign ;						// 全sourceを所有する入力。
	auto incoming					= definition ;	// 同日別artifactの有限新定義。
	incoming.artifactSha256			= std::wstring( 64U, L'b') ;
	const auto sameDayIdentityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;		// 同じscopeだけで大きなfixtureを所有する。
	auto &sameDayIdentity = *sameDayIdentityOwner ;	// 全改変条件へ固定する元G。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( incoming, L"20260927", sameDayIdentity)) ;
	const auto sameDayUtc = HTTP_TEST_UTC + 200000U ;	// 旧完了後の有限時刻。
	// 同日別artifact・次日・公開名変更による新requestを独立に検査する。
	for( unsigned trial = 0U; trial < 3U; ++trial) {
		auto	   next = trial == 1U ? definition : incoming ;						// 次日だけ同artifactを維持する。
		const auto utc	= trial == 1U ? HTTP_TEST_UTC + 86400000U : sameDayUtc ;	// 実JST日の変更。
		// ASUSの別公式locatorを新requestとし、表示名変更だけで旧待機を迂回しない。
		if( trial == 2U) {
			auto manifest =
				// 元定義の所有copy。
				JsonObject::Parse( winrt::to_hstring( next.manifestBytes)) ;
			manifest.GetNamedArray( L"targets")
				.GetObjectAt( 26U)
				.Insert( L"model", JsonValue::CreateStringValue( L"Fixture Changed Public Model")) ;
			manifest.GetNamedArray( L"jobs").GetObjectAt( 1U).Insert(
				L"locator", JsonValue::CreateStringValue( L"Fixture Changed Public Model")) ;
			next.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		}

		const auto identityOwner = std::make_unique<
			CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto &identity = *identityOwner ;	// 今回日付・artifact・scopeの元入力。
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			campaign ;	// 次回の専用executor入力。
		DRIVERCRATE_EXPECT( context, makeCollectorProjectedCampaignIdentity(
										next, trial == 1U ? L"20260928" : L"20260927", identity) &&
										prepareCollectorProjectedCampaign(
											identity.canonicalInput, identity.inputSha256,
											identity.generationKey, next.artifactSha256,
											next.sources, campaign)) ;
		DRIVERCRATE_EXPECT( context,
						   campaign && (campaign->job( 1U)->value().requestKey !=
										prepared->job( 1U)->value().requestKey) == (trial == 2U)) ;
		LocalCollectorStateStore store ;	// 原正本を別rootへ保護handleで複製する。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 原envelopeをそのまま保存し、組立による第二世代成功を作らない。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		{
			LocalCollectorRecovery recovery ;	// 従来の全完了再読込み後だけ明示開始する。
			DRIVERCRATE_EXPECT( context, recovery.initializeProjected( store, next, utc, 0U) == 0U &&
											recovery.reason() == L"GENERATION_COMPLETE") ;
			// 同日の既登録Gは待機とし、全byteを変更しない。
			if( trial != 1U) {
				DRIVERCRATE_EXPECT( context, recovery.beginNextProjected( definition, utc, 0U) ==
													ERROR_RETRY &&
												original == projectedStoreSnapshot( context, store)) ;
			}

			const auto code =
				// 新世代だけを登録する。
				recovery.beginNextProjected( next, utc, 1000U) ;
			context.expect( code == 0U && recovery.reason() == L"NEXT_GENERATION_READY" &&
							   recovery.generationKey() == identity.generationKey &&
							   recovery.terminalJobs() == 0U,
						   "next generation trial=" + std::to_string( trial) +
							   " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
			// 不成立後にworkerを開始せず、原失敗を残して次の独立条件へ進む。
			if( code != 0U) {
				continue ;
			}
		}
		const auto created = projectedStoreSnapshot( context, store) ;	// 新登録直後の全byte。
		// 過去run・stateと旧pointer／CACHEは全byte不変を維持する。
		for( const auto &[name, raw] : original) {
			// 共通root／予算だけが登録・日次archiveへ進む。
			if( name != L"current/campaign-root-v2.json" &&
			   name != L"current/campaign-budget-v1.json") {
				DRIVERCRATE_EXPECT( context, created.at( name) == raw) ;
			}
		}

		const auto budgetOwner =
			std::make_unique<CollectorBudgetSnapshot>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto &budget = *budgetOwner ;	// 当日の共有予約を0へ暗黙再作成しない。
		DRIVERCRATE_EXPECT( context,
						   parseCollectorBudgetSnapshot(
							   httpSavedBody( store, L"current/campaign-budget-v1.json"), budget) &&
							   budget.reservations.size() == (trial == 1U ? 0U : 2U)) ;
		// 同日新世代を改変条件の固定正本にする。
		if( trial == 0U) {
			queued = created ;
		}

		// 他requestの旧proof改変も新要求予約前に検査する固定条件を保持する。
		if( trial == 2U) {
			newRequestQueued	 = created ;
			newRequestDefinition = next ;
			newRequestCampaign	 = campaign ;
		}

		std::map<std::wstring, std::string> reserved ;	// 回収後のRUNNING再起動に同じ全byteを使う。
		{
			LocalCollectorRecovery resumed ;	// 全完了prefixとPENDING末尾を非変更で再読込みする。
			DRIVERCRATE_EXPECT( context,
							   resumed.initializeProjected( store, next, utc + 1000U, 0U) == 0U &&
								   resumed.reason() == L"NEXT_GENERATION_READY" &&
								   created == projectedStoreSnapshot( context, store)) ;
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
				publicHistory ;	// 公開入口の混在拒否を維持する。
			DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
											store, *campaign->job( 0U), next.sources, utc + 1000U,
											publicHistory) == ERROR_INVALID_DATA &&
											!publicHistory &&
											created == projectedStoreSnapshot( context, store)) ;
			const auto fixturesOwner =
				std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
			auto		 &fixtures = *fixturesOwner ;			// 固定fake本文だけ。実native APIを使わない。
			std::uint64_t elapsed  = 1000U ;					// 二秒待機前後を親threadだけで進める。
			CollectorProjectedExecutorDependencies
				dependencies ;	// このscopeが全joinまで依存を所有する。
			dependencies.campaign = campaign ;
			dependencies.clock	  = [&, utc] {
				   return activeFixture ? activeFixture->clock
										: CollectorHttpClockSample{utc + elapsed, elapsed} ;
			} ;
			dependencies.createClient = [] {
				return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
			} ;
			std::size_t workers{} ;	// 親だけが起動slotを数える。
			dependencies.start = [&]( std::function<void()> worker) {
				const auto slot = workers++ ;	// threadには固定数値を所有copyする。
				return std::thread( [&, slot, worker = std::move( worker)] {
					fixtures[slot].ownerThread = std::this_thread::get_id() ;
					fixtures[slot].clock	   = {utc + 3000U, 3000U} ;
					FixtureScope scope( fixtures[slot]) ;	// thread別fake APIのみ。
					worker() ;
				}) ;
			} ;
			LocalCollectorProjectedExecutor executor(
				// 元監督と同じ所有tokenへ結合する。
				std::move( dependencies)) ;
			DRIVERCRATE_EXPECT( context, executor.startNext( resumed) == ERROR_RETRY &&
											workers == 0U &&
											created == projectedStoreSnapshot( context, store)) ;
			elapsed				  = 3000U ;
			const auto firstCode  = executor.startNext( resumed) ;	// 元待機と全履歴検査を通る一予約。
			const auto secondCode = executor.startNext( resumed) ;	// 他groupの旧CACHEも再検査する。
			const auto expectedWorkers = trial == 0U   ? 0U
										 : trial == 1U ? 2U
													   : 1U ;	// 同日旧要求は24時間待つ。
			context.expect( firstCode == (expectedWorkers == 0U ? ERROR_RETRY : 0U) &&
							   secondCode == (expectedWorkers == 2U ? 0U : ERROR_RETRY),
						   "next reservation trial=" + std::to_string( trial) + " codes=" +
							   std::to_string( firstCode) + "/" + std::to_string( secondCode),
						   __FILE__, __LINE__) ;
			const auto report = executor.join() ;	// 結果を親受領へ渡す前に全回収する。
			DRIVERCRATE_EXPECT( context, report.error == 0U && report.reserved == expectedWorkers &&
											report.joined == expectedWorkers &&
											workers == expectedWorkers) ;
			reserved				= projectedStoreSnapshot( context, store) ;
			const auto refusedOwner = std::make_unique<
				CollectorProjectedPreparedUpdate>() ;	// 同じscopeだけで大きなfixtureを所有する。
			auto &refused = *refusedOwner ;				// 次回結果を旧初回受領へ読み替えない。
			DRIVERCRATE_EXPECT(
				context, resumed.prepareInitialProjectedUpdate( executor, 0U, utc + 4000U, 4000U,
															   refused) == ERROR_NOT_SUPPORTED &&
							 refused.response.envelope.empty() &&
							 reserved == projectedStoreSnapshot( context, store)) ;
			DRIVERCRATE_EXPECT( context,
							   resumed.acceptInitialProjected( executor, 0U, utc + 4000U, 4000U) ==
									   ERROR_NOT_SUPPORTED &&
								   reserved == projectedStoreSnapshot( context, store)) ;
		}
		{
			LocalCollectorRecovery
					   restarted ;	// RUNNING末尾は自動再送・中断CACHE化せず非変更で止める。
			const auto restartCode =
				// 同一元入力。
				restarted.initializeProjected( store, next, utc + 5000U, 0U) ;
			DRIVERCRATE_EXPECT( context, restartCode == (trial == 0U ? 0U : ERROR_RETRY) &&
											restarted.reason() ==
												(trial == 0U ? L"NEXT_GENERATION_READY"
															 : L"HISTORY_ACCEPTANCE_PENDING") &&
											reserved == projectedStoreSnapshot( context, store)) ;
			// RUNNING再起動は新しいexecutorへも開始許可を返さない。
			if( trial != 0U) {
				std::size_t							   clients{} ;		// 実factoryへ到達しない親側計数。
				CollectorProjectedExecutorDependencies dependencies ;	// 非通信拒否用の入力。
				dependencies.campaign = campaign ;
				dependencies.clock = [utc] { return CollectorHttpClockSample{utc + 6000U, 1000U} ; } ;
				dependencies.createClient = [&]() -> std::unique_ptr<LocalCollectorHttpClient> {
					++clients ;
					return {} ;
				} ; // client構築を試みたらこの試験は不成立。
				dependencies.start = []( std::function<void()> worker) {
					return std::thread( std::move( worker)) ;
				} ; // 必須の起動factoryを提供するが、予約拒否後は呼ばれない。
				LocalCollectorProjectedExecutor blocked(
					// 旧結果を渡さない。
					std::move( dependencies)) ;
				DRIVERCRATE_EXPECT( context, blocked.startNext( restarted) == ERROR_RETRY &&
												blocked.join().reserved == 0U && clients == 0U &&
												reserved == projectedStoreSnapshot( context, store)) ;
			}

			DRIVERCRATE_EXPECT( context, restarted.finishInitialProjected( utc + 6000U, 1000U) ==
												ERROR_NOT_SUPPORTED &&
											reserved == projectedStoreSnapshot( context, store)) ;
		}
		// 過去の元証跡とCACHEを予約中も保つ。結果保存はこの工程では行わない。
		for( const auto &[name, raw] : created) {
			// 元末尾のRUNNING・共有開始／予算／root以外を保持する。
			if( name != L"current/campaign-root-v2.json" &&
			   name != L"current/campaign-budget-v1.json" &&
			   name != L"current/campaign-controls-v1.json" &&
			   name != L"current/campaign-state-v3-" + identity.generationKey + L".json") {
				DRIVERCRATE_EXPECT( context, reserved.at( name) == raw) ;
			}
		}
	}

	// 初期検査後の旧CACHE改変は次回開始前に再検査し、登録や日次切替を行わない。
	{
		LocalCollectorStateStore store ;	// 元完了像を新しい保護rootへ複製する。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 初期全完了検査は正当な原byteだけで行う。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		LocalCollectorRecovery recovery ;	// 同一監督での再検査を省略させない。
		DRIVERCRATE_EXPECT( context,
						   recovery.initializeProjected( store, incoming, sameDayUtc, 0U) == 0U) ;
		mutateProjectedStore( context, store,
							 L"current/campaign-cache-v1-" + prepared->job( 0U)->value().requestKey +
								 L".json",
							 []( JsonObject &value) {
								 value.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
							 }) ;
		const auto before =
			// 元改変を保存処理で補完しない。
			projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT( context, recovery.beginNextProjected( incoming, sameDayUtc, 1000U) ==
											ERROR_INVALID_DATA &&
										before == projectedStoreSnapshot( context, store)) ;
	}

	// 新requestを選ぶ場合も、要求外の旧CACHEと旧応答を予約の書込み前に再検査する。
	for( unsigned fault = 0U; fault < 2U && !newRequestQueued.empty(); ++fault) {
		LocalCollectorStateStore store ;	// 未登録ASUS要求を持つ元PENDING正本。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 元input／marker／state／旧全履歴をそのまま複製する。
		for( const auto &[name, raw] : newRequestQueued) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		LocalCollectorRecovery recovery ;	// 改変前の全inventory検査を先に済ませる。
		DRIVERCRATE_EXPECT( context, recovery.initializeProjected( store, newRequestDefinition,
																 sameDayUtc + 1000U, 0U) == 0U) ;
		const auto name =
			fault == 0U
				? L"current/campaign-cache-v1-" + prepared->job( 0U)->value().requestKey + L".json"
				: L"runs/campaign-response-v4-" + intelOperation + L".json" ;	// 要求外Intel根拠。
		mutateProjectedStore( context, store, name, []( JsonObject &value) {
			value.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
		}) ; // 外側hashが一致しても内部契約は拒否する。
		const auto before = projectedStoreSnapshot( context, store) ;	// 先払い・開始controlも非変更。
		std::size_t							   clients{} ;				// factory未開始の独立計数。
		CollectorProjectedExecutorDependencies dependencies ;			// fake clientも開始させない。
		dependencies.campaign = newRequestCampaign ;
		dependencies.clock	  = [sameDayUtc] {
			   return CollectorHttpClockSample{sameDayUtc + 4000U, 3000U} ;
		} ;
		dependencies.createClient = [&]() -> std::unique_ptr<LocalCollectorHttpClient> {
			++clients ;
			return {} ;
		} ;
		dependencies.start = []( std::function<void()> worker) {
			return std::thread( std::move( worker)) ;
		} ; // 拒否条件でも依存契約を満たし、通信開始0を検査する。
		LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 全履歴拒否だけを測る。
		DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == ERROR_INVALID_DATA &&
										executor.join().reserved == 0U && clients == 0U &&
										before == projectedStoreSnapshot( context, store)) ;
	}

	// 旧proof・新入力・登録順・未知CACHE・余剰応答を独立に改変し、全byte不変拒否を確認する。
	for( unsigned fault = 0U; fault < 8U && !queued.empty(); ++fault) {
		LocalCollectorStateStore store ;	// 同じ正本から独立した改変条件を作る。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto missing =
			fault == 0U	  ? L"runs/campaign-summary-v1-" + prepared->generationKey() + L".json"
			: fault == 1U ? L"runs/campaign-marker-v3-" + sameDayIdentity.generationKey + L".json"
						  : std::wstring{} ;	// 欠損対象。
		// 元rawを欠損一件以外そのまま複製する。
		for( const auto &[name, raw] : queued) {
			// 欠損を空fileで補完しない。
			if( name != missing) {
				DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
			}
		}

		// 余剰新応答は取得成功へ解釈せず未知名として拒否する。
		if( fault == 2U || fault == 3U) {
			const auto name =
				fault == 2U ? L"runs/campaign-response-v4-" + std::wstring( 64U, L'f') + L".json"
							: L"current/campaign-cache-v1-" + std::wstring( 64U, L'f') +
								  L".json" ;	// 固定の未知名。
			DRIVERCRATE_EXPECT( context, store.write( name, "{}") == 0U) ;
		}

		// 自己一貫hashでも元登録順・旧完了像・新stateの矛盾は拒否する。
		if( fault >= 4U) {
			const auto name =
				fault == 4U ? L"runs/campaign-summary-v1-" + prepared->generationKey() + L".json"
				: fault == 5U
					? L"current/campaign-state-v3-" + sameDayIdentity.generationKey + L".json"
					: std::wstring( L"current/campaign-root-v2.json") ;	// 独立一要因の改変対象。
			mutateProjectedStore( context, store, name, [fault]( JsonObject &value) {
				// 未応答行を応答保存なしの終端へ変えない。
				if( fault == 5U) {
					value.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
						L"state", JsonValue::CreateStringValue( L"FETCHED")) ;
				}
				// 稼働末尾を全完了へ偽装しない。
				else if( fault == 6U) {
					value.Insert( L"activeGeneration", JsonValue::CreateStringValue( L"")) ;
				}
				// prefix内に未完了世代を挿入しない。
				else if( fault == 7U) {
					value.GetNamedArray( L"generations")
						.GetObjectAt( 0U)
						.Insert( L"summaryHash", JsonValue::CreateStringValue( L"")) ;
				} else {
					value.Insert( L"metadataMatchedTargets", JsonValue::CreateNumberValue( 27.0)) ;
				}
			}) ;
		}

		const auto before = projectedStoreSnapshot( context, store) ;	// 拒否前後の全名・raw。
		LocalCollectorRecovery rejected ;								// 回復・精算・新世代再作成をしない。
		DRIVERCRATE_EXPECT(
			context, rejected.initializeProjected( store, incoming, sameDayUtc + 1000U, 0U) != 0U &&
						 before == projectedStoreSnapshot( context, store)) ;
	}

	// 次回のinput／marker／state先行保存は未登録窓として保持し、root登録後だけ再読込する。
	for( const auto point : {CollectorRecoveryCheckpoint::PROJECTED_INPUT,
							CollectorRecoveryCheckpoint::PROJECTED_MARKER,
							CollectorRecoveryCheckpoint::PROJECTED_STATE,
							CollectorRecoveryCheckpoint::PROJECTED_REGISTERED}) {
		LocalCollectorStateStore store ;	// 原完了正本の独立copy。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 各保存窓を同じ不変履歴から始める。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		{
			LocalCollectorRecovery stopping ;	// 既存の有限checkpointだけを使う。
			DRIVERCRATE_EXPECT( context,
							   stopping.initializeProjected(
								   store, incoming, sameDayUtc, 0U,
								   [point]( const auto saved) { return saved == point ; }) == 0U &&
								   stopping.beginNextProjected( incoming, sameDayUtc, 1000U) ==
									   ERROR_OPERATION_ABORTED) ;
		}
		const auto before = projectedStoreSnapshot( context, store) ;	// 保存途中も削除・補完しない。
		LocalCollectorRecovery resumed ;								// 未登録orphanは拒否し、登録済みPENDINGだけ非変更で戻す。
		const auto			   code =
			// 元再開結果。
			resumed.initializeProjected( store, incoming, sameDayUtc + 1000U, 0U) ;
		DRIVERCRATE_EXPECT( context, (point == CollectorRecoveryCheckpoint::PROJECTED_REGISTERED
										 ? code == 0U
										 : code != 0U) &&
										before == projectedStoreSnapshot( context, store)) ;
	}

	// 次日の日次四窓は固定一切替だけ回復し、元完了群と新世代非作成を保ちます。
	for( const auto point :
		{CollectorRecoveryCheckpoint::EFFECTS, CollectorRecoveryCheckpoint::REGISTERED,
		 CollectorRecoveryCheckpoint::APPLIED, CollectorRecoveryCheckpoint::COMPLETED}) {
		LocalCollectorStateStore store ;	// 各日次保存窓へ独立した旧完了像を用意する。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 旧rawを全て保持し、成功archiveを試験側で注入しない。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		const auto utc = HTTP_TEST_UTC + 86400000U ;	// 別日の明示開始時刻。
		{
			LocalCollectorRecovery stopping ;	// 元day-rollの固定checkpointだけを利用する。
			DRIVERCRATE_EXPECT( context, stopping.initializeProjected( store, definition, utc, 0U,
																	 [point]( const auto saved) {
																		 return saved == point ;
																	 }) == 0U &&
											stopping.beginNextProjected( definition, utc, 1000U) ==
												ERROR_OPERATION_ABORTED) ;
		}
		const auto before =
			// 確定済み窓の非変更と元準備像の正本。
			projectedStoreSnapshot( context, store) ;
		LocalCollectorRecovery resumed ;	// 明示済みの一切替だけ回復します。
		const auto			   code =
			// 原再開値。
			resumed.initializeProjected( store, definition, utc + 1000U, 0U) ;
		const auto after = projectedStoreSnapshot( context, store) ;	// 元履歴と日次確定を分けます。
		DRIVERCRATE_EXPECT(
			context,
			code == 0U && (point != CollectorRecoveryCheckpoint::COMPLETED || before == after)) ;
		// 元完了群は共有root／budget以外全byte不変です。
		for( const auto &[name, raw] : original) {
			// 一切替だけが変更する二共有値を除きます。
			if( name != L"current/campaign-root-v2.json" &&
			   name != L"current/campaign-budget-v1.json") {
				DRIVERCRATE_EXPECT( context, after.at( name) == raw) ;
			}
		}

		// 元保存準備像も更新せず保持します。
		for( const auto &[name, raw] : before) {
			// 日次確定のroot／budget以外を全byte照合します。
			if( name != L"current/campaign-root-v2.json" &&
			   name != L"current/campaign-budget-v1.json") {
				DRIVERCRATE_EXPECT( context, after.at( name) == raw) ;
			}
		}

		const auto root = JsonObject::Parse( winrt::to_hstring( httpSavedBody(
			store, L"current/campaign-root-v2.json"))) ;	// 追加世代と二重切替は認めません。
		DRIVERCRATE_EXPECT( context, root.GetNamedArray( L"generations").Size() == 1U &&
										root.GetNamedArray( L"archives").Size() == 1U &&
										root.GetNamedString( L"activeGeneration").empty() &&
										root.GetNamedValue( L"commit").ValueType() ==
											winrt::Windows::Data::Json::JsonValueType::Null) ;
	}
}

/** @brief 二完了世代の旧集計・進んだCACHE・日次証跡と改変拒否を検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立した保護fixture root。
 * @param[in] definition 元二sourceの固定公開定義。
 * @param[in] prepared 最初の元scopeを所有するprepared入力。
 */
void allCompletedHistoryChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	LocalCollectorStateStore first ;	// 実HTTPを使わない最初の初回保存。
	DRIVERCRATE_EXPECT( context, first.initialize( rootFactory(), true) == 0U) ;
	std::array<CollectorProjectedResponseBytes, 2U> expected ;	// 所有workerからの原応答。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, first, definition, prepared,
															   0U, {}, expected) == 0U) ;
	{
		LocalCollectorRecovery recovery ;	// 最初だけ通常完了入口を使います。
		DRIVERCRATE_EXPECT(
			context,
			recovery.initializeProjected( first, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				recovery.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto original = projectedStoreSnapshot( context, first) ;	// 過去の全rawを不変に保ちます。
	std::array<std::shared_ptr<const CollectorRegisteredProjectedHistory>, 2U>
		histories ;	// 全元根拠。
	// 二requestの同じ元完了を非変更検査してから組立fixtureへ渡します。
	for( std::size_t index = 0U; index < 2U; ++index) {
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
										first, *prepared->job( index), definition.sources,
										HTTP_TEST_UTC + 128000U, histories[index]) == 0U &&
										histories[index]) ;
	}

	std::map<std::wstring, std::string>
								   baseline ;								// 日次・二完了の正常元byteを改変検査へ固定します。
	std::wstring				   laterGeneration ;						// 同じ基準世代を固定名へ使います。
	const auto					   laterUtc = HTTP_TEST_UTC + 86400000U ;	// 次のJST日を明示します。
	const std::array<unsigned, 6U> scenarios{0U, 1U, 2U, 3U,
											 8U, 0U} ;	// 完全・減少・失敗・空・一行・別artifact。
	// 五つの元日archive条件と同日別artifact条件を、独立初回証跡から構成します。
	for( std::size_t trial = 0U; trial < scenarios.size(); ++trial) {
		const auto archived = trial < 5U ;										// 同日条件は旧予約を当日予算に保持します。
		const auto utc		= archived ? laterUtc : HTTP_TEST_UTC + 200000U ;	// 旧受領後の有限時計。
		auto	   nextDefinition = definition ;								// 別artifact以外は同じsource／scopeを固定します。
		// 同日でも異なる実artifactの世代を、旧artifact成功へ読み替えず検査します。
		if( !archived) {
			nextDefinition.artifactSha256 = std::wstring( 64U, L'b') ;
			DRIVERCRATE_EXPECT( context, nextDefinition.artifactSha256 != definition.artifactSha256) ;
		}

		CollectorProjectedCampaignIdentity identity ;							// 元日と公開定義からGを再計算します。
		std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;	// 次の入力の全scope。
		DRIVERCRATE_EXPECT(
			context, makeCollectorProjectedCampaignIdentity(
						 nextDefinition, archived ? L"20260928" : L"20260927", identity) &&
						 prepareCollectorProjectedCampaign(
							 identity.canonicalInput, identity.inputSha256, identity.generationKey,
							 nextDefinition.artifactSha256, nextDefinition.sources, campaign)) ;
		LocalCollectorStateStore store ;	// 通常の二世代開始とは区別した組立用store。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		std::array<CollectorProjectedWorkerResult, 2U> workers ;	// 同じfake GETの所有結果copy。
		DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, nextDefinition,
																   campaign, scenarios[trial], {},
																   expected, utc, &workers) == 0U) ;
		{
			LocalCollectorRecovery recovery ;	// 組立前の独立初回完了を作ります。
			DRIVERCRATE_EXPECT(
				context,
				recovery.initializeProjected( store, nextDefinition, utc + 126000U, 0U) == 0U &&
					recovery.finishInitialProjected( utc + 127000U, 1000U) == 0U) ;
		}
		assembleCompletedHistoryFixture( context, store, original, histories, campaign, workers, utc,
										archived) ;
		const auto before = projectedStoreSnapshot( context, store) ;	// 全履歴検査の非変更正本。
		// 全CACHEを検証しつつ、要求したrequestだけの所有contextを返すことを確認します。
		for( std::size_t index = 0U; index < 2U; ++index) {
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
					   history ;	// 全検査後だけ出力します。
			const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
				store, *campaign->job( index), nextDefinition.sources, utc + 128000U,
				history) ;	// 新artifactも照合。
			context.expect( code == 0U && history && history->operations() == 2U,
						   "all completed trial=" + std::to_string( trial) +
							   " job=" + std::to_string( index) + " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
			// 失敗・減少では成功sliceだけが最初のGを保持し、最新attemptは二番目へ進みます。
			if( history) {
				DRIVERCRATE_EXPECT( context,
								   history->cache().attempt.generation == identity.generationKey &&
									   history->slices().size() == (index == 1U ? 1U : 0U)) ;
				// 元成功の所在を新世代の成功数に加算しません。
				if( index == 1U) {
					DRIVERCRATE_EXPECT( context, history->slices().front().generation ==
													((trial == 0U || trial == 5U)
														 ? identity.generationKey
														 : prepared->generationKey())) ;
				}
			}

			DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store)) ;
		}

		const auto summary = JsonObject::Parse( winrt::to_hstring( httpSavedBody(
			store,
			L"runs/campaign-summary-v1-" + identity.generationKey + L".json"))) ;	// 新Gだけの分母。
		DRIVERCRATE_EXPECT( context, summary.GetNamedNumber( L"targetCount") == 27.0 &&
										summary.GetNamedNumber( L"metadataMatchedTargets") ==
											(trial == 0U || trial == 5U ? 1.0 : 0.0) &&
										summary.GetNamedNumber( L"matchedRecordReferences") ==
											(trial == 0U || trial == 5U ? 2.0 : 0.0)) ;
		// 過去のinput／応答／effect／完了像とstateの原byteは新CACHE更新後も不変です。
		for( const auto &[name, raw] : original) {
			// 現在共有値・pointer・CACHE・rootだけが新世代へ進みます。
			if( name.starts_with( L"runs/") ||
			   name == L"current/campaign-state-v3-" + prepared->generationKey() + L".json") {
				DRIVERCRATE_EXPECT( context, before.at( name) == raw) ;
			}
		}

		// 同じ入力・別日・別artifact・別manifestでも、最新完了を非変更で返し新Gを作りません。
		for( unsigned change = 0U; change < 4U; ++change) {
			auto incoming = nextDefinition ;	// 今回入力は元完了入力を書き換える権限ではありません。
			// 明示したartifact変更を旧成功への再採点に使用しません。
			if( change == 2U) {
				incoming.artifactSha256 = std::wstring( 64U, L'e') ;
			}

			// 公開対象名が変わっても保存済み完了の元分母とscopeを維持します。
			if( change == 3U) {
				const auto changed = JsonObject::Parse(
					// 元manifestの所有copy。
					winrt::to_hstring( incoming.manifestBytes)) ;
				changed.GetNamedArray( L"targets")
					.GetObjectAt( 0U)
					.Insert( L"model",
							JsonValue::CreateStringValue( L"Fixture Changed Public Model")) ;
				incoming.manifestBytes = winrt::to_string( changed.Stringify()) ;
			}

			normalCompletedInventoryFixture( context, store, incoming, campaign,
											utc + 129000U + (change == 1U ? 86400000U : 0U)) ;
		}

		{
			CollectorRecoveryInput oldInput ;	// 正常な旧caller入力でも新保存版を回収しません。
			oldInput.manifestBytes	= nextDefinition.manifestBytes ;
			oldInput.sources		= nextDefinition.sources ;
			oldInput.artifactSha256 = nextDefinition.artifactSha256 ;
			// 同じ元共有jobのrequest／CACHE結合を旧callerにも正しく渡します。
			for( std::size_t index = 0U; index < campaign->jobCount(); ++index) {
				const auto &job = campaign->job( index)->value() ;	// 元入力順の正しい旧caller結合。
				oldInput.requestKeys.push_back( job.requestKey) ;
				oldInput.cacheBindings.push_back( job.cacheBinding) ;
			}

			LocalCollectorRecovery oldCaller ;	// 保存schemaによる拒否をcaller形式不良と区別します。
			DRIVERCRATE_EXPECT( context, oldCaller.initialize( store, oldInput, utc + 129000U, 0U) ==
												ERROR_INVALID_DATA &&
											before == projectedStoreSnapshot( context, store)) ;
		}
		// 正常日次fixtureを全欠損・改変へ同じ原byteで再使用します。
		if( trial == 0U) {
			baseline		= before ;
			laterGeneration = identity.generationKey ;
		}
	}

	// 旧集計・他request・CACHE前像・日次proof・登録順・余剰名を独立に改変します。
	for( unsigned fault = 0U; fault < 16U; ++fault) {
		LocalCollectorStateStore store ;	// 元正常二世代を毎回独立コピーします。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 未変更の原rawを先に固定します。
		for( const auto &[name, raw] : baseline) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		const auto root	 = JsonObject::Parse( winrt::to_hstring(
			 // 元固定登録。
			 httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
		const auto roll	 = std::wstring( root.GetNamedArray( L"archives")
											.GetObjectAt( 0U)
											.GetNamedString( L"operation")) ;	// 元日切替hash。
		const auto oldOp = histories[0]->cache().attempt.operation ;			// 今回要求しないIntelの旧操作。
		const std::array<std::wstring, 5U> missing{
			L"runs/campaign-summary-v1-" + prepared->generationKey() + L".json",
			L"runs/campaign-response-v4-" + oldOp + L".json",
			L"runs/campaign-day-roll-v2-" + roll + L".json",
			L"runs/campaign-effect-v1-" + roll + L"-before-budget.json",
			L"runs/campaign-effect-v1-" + roll + L"-archive.json"} ;	// 旧証跡の各欠損。
		// 必須登録物の欠損を初回履歴なしへ戻しません。
		if( fault < missing.size()) {
			const auto target =
				(store.root() / missing[fault]).lexically_normal() ;	// この独立fixtureの一file。
			DRIVERCRATE_EXPECT( context, target.parent_path() == store.root() / L"runs") ;
			std::error_code error ;	// fixtureの非再帰削除だけを行います。
			DRIVERCRATE_EXPECT(
				context, std::filesystem::remove( segmentFixturePath( target), error) && !error) ;
		}
		// 旧summary・intent・rootの全hashを揃えても元target分母との不一致を拒否します。
		else if( fault == 5U) {
			mutateProjectedStore(
				context, store, L"runs/campaign-summary-v1-" + prepared->generationKey() + L".json",
				[]( auto &body) {
					body.Insert( L"targetCount", JsonValue::CreateNumberValue( 26.0)) ;
				}) ;
			std::wstring summaryHash ;	// 改変後本文への自己一貫したhashを意図して作ります。
			DRIVERCRATE_EXPECT(
				context,
				computeBytesSha256( httpSavedBody( store, L"runs/campaign-summary-v1-" +
															prepared->generationKey() + L".json"),
								   summaryHash) == 0U) ;
			JsonObject
				pointer ;	// 当時pointerも改変後summaryへ揃え、現在pointerは最新Gのままにします。
			pointer.Insert( L"schema",
						   JsonValue::CreateStringValue( L"collector-campaign-current-v2")) ;
			pointer.Insert( L"generation", JsonValue::CreateStringValue( prepared->generationKey())) ;
			pointer.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
			std::wstring pointerHash ;	// 元応答から導いた正しいhashとは異なる参照です。
			DRIVERCRATE_EXPECT( context, computeBytesSha256( winrt::to_string( pointer.Stringify()),
														   pointerHash) == 0U) ;
			mutateProjectedStore(
				context, store, L"runs/campaign-finish-v1-" + prepared->generationKey() + L".json",
				[&]( auto &body) {
					body.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
					body.Insert( L"pointerHash", JsonValue::CreateStringValue( pointerHash)) ;
				}) ;
			mutateProjectedStore( context, store, L"current/campaign-root-v2.json", [&]( auto &body) {
				body.GetNamedArray( L"generations")
					.GetObjectAt( 0U)
					.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
			}) ;
		}
		// 日付切替の空更新後像も元時刻から再導出します。
		else if( fault == 6U) {
			mutateProjectedStore(
				context, store, L"runs/campaign-effect-v1-" + roll + L"-budget.json",
				[]( auto &body) {
					body.Insert( L"lastUtc", JsonValue::CreateNumberValue(
												body.GetNamedNumber( L"lastUtc") + 1.0)) ;
				}) ;
		}
		// pointerを以前の完了世代へ戻しても最新root順と一致させません。
		else if( fault == 7U) {
			DRIVERCRATE_EXPECT( context,
							   store.write( L"current/campaign-current-v2.json",
										   original.at( L"current/campaign-current-v2.json")) == 0U) ;
		}
		// 未登録の余剰effectは全名照合で拒否します。
		else if( fault == 8U) {
			DRIVERCRATE_EXPECT( context,
							   store.write( L"runs/campaign-extra-history.json", "{}") == 0U) ;
		}
		// 要求外の旧effectでも、外側hashを揃えた追加fieldを受理しません。
		else if( fault == 9U) {
			mutateProjectedStore(
				context, store, L"runs/campaign-effect-v2-" + oldOp + L"-budget.json",
				[]( auto &body) { body.Insert( L"extra", JsonValue::CreateNullValue()) ; }) ;
		}
		// 世代順・active・完了未登録・登録archive hashの改変は全完了契約で拒否します。
		else if( fault < 15U) {
			mutateProjectedStore( context, store, L"current/campaign-root-v2.json", [&]( auto &body) {
				// 登録順の逆転で元完了時計と最新pointerを変えません。
				if( fault == 10U) {
					const auto rows =
						// 元二行を別配列へ並べ替えます。
						body.GetNamedArray( L"generations") ;
					JsonArray reversed ;	// 意図した不正順の二行。
					reversed.Append( rows.GetObjectAt( 1U)) ;
					reversed.Append( rows.GetObjectAt( 0U)) ;
					body.Insert( L"generations", reversed) ;
				}
				// 稼働混在はこの非変更入口では未受入です。
				else if( fault == 11U) {
					body.Insert( L"activeGeneration", JsonValue::CreateStringValue( laterGeneration)) ;
				}
				// 生成物が揃っていてもrootの完了未登録を回復しません。
				else if( fault == 12U) {
					body.GetNamedArray( L"generations")
						.GetObjectAt( 1U)
						.Insert( L"summaryHash", JsonValue::CreateStringValue( L"")) ;
				}
				// 誤った元日archive登録hashを保存fileから上書き補完しません。
				else if( fault == 13U) {
					body.GetNamedArray( L"archives")
						.GetObjectAt( 0U)
						.Insert( L"hash", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				} else {
					body.GetNamedArray( L"cacheInventory")
						.GetObjectAt( 0U)
						.Insert( L"hash", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}
			}) ;
		}

		const auto before  = projectedStoreSnapshot( context, store) ;	// 不正状態も書き直しません。
		auto	   history = histories[1] ;								// 拒否時の旧所有出力を空へ戻します。
		auto	   sources = definition.sources ;						// 未参照sourceの契約相違も全世代で拒否します。
		// 今回要求外のIntelを保存source由来の新許可へ昇格させません。
		if( fault == 15U) {
			++sources[0].maximumResponseBytes ;
		}

		const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, *prepared->job( 1U), sources, laterUtc + 128000U,
			history) ;	// 要求はASUSだけ。
		context.expect( code != 0U && !history && before == projectedStoreSnapshot( context, store),
					   "all completed fault=" + std::to_string( fault) +
						   " code=" + std::to_string( code),
					   __FILE__, __LINE__) ;
		auto incoming	 = definition ;	// 正常型の現在sourceでも旧proofの拒否を省略しません。
		incoming.sources = sources ;
		LocalCollectorRecovery normal ;	// 通常起動も同じ元proofを検査します。
		const auto normalError = normal.initializeProjected( store, incoming, laterUtc + 128000U,
															0U) ;	// 第一errorを保持します。
		context.expect( normalError != 0U && normal.lastError() == normalError &&
						   normal.initializeProjected( store, incoming, laterUtc + 129000U, 0U) ==
							   normalError &&
						   before == projectedStoreSnapshot( context, store),
					   "normal completed fault=" + std::to_string( fault) +
						   " code=" + std::to_string( normalError),
					   __FILE__, __LINE__) ;
	}

	completedHistoryBoundaryChecks( context, rootFactory, baseline, *prepared->job( 1U),
								   definition.sources, laterUtc + 128000U, definition) ;
}

/** @brief 正常登録・全四role・欠損・改変・hash原値を保存非変更で検査します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 独立した保護fixture root。
 * @param[in] definition 元二source定義。
 */
void registeredProjectedHistoryChecks( TestContext								   &context,
									  const std::function<std::filesystem::path()> &rootFactory,
									  const CollectorProjectedCampaignDefinition   &definition)
{
	LocalCollectorStateStore source ;	// 全正常元byteを一度だけ作ります。
	DRIVERCRATE_EXPECT( context, source.initialize( rootFactory(), true) == 0U) ;
	const auto prepared = makeRegisteredHistoryFixture( context, source, definition, L"20260927",
													   HTTP_TEST_UTC, 0U) ;	// 完全二行200。
	std::shared_ptr<const CollectorRegisteredProjectedHistory>
			   accepted ;													// 成功時だけ構築できるcontext。
	const auto normalBefore = projectedStoreSnapshot( context, source) ;	// 読取りの非変更証跡。
	const auto firstCode	= LocalCollectorRecovery::inspectRegisteredProjectedHistory(
		   source, *prepared->job( 1U), definition.sources, HTTP_TEST_UTC + 125000U,
		   accepted) ;	// 通信なしの登録閉包検証。
	DRIVERCRATE_EXPECT( context, firstCode == 0U && accepted && accepted->operations() == 1U &&
									accepted->slices().size() == 1U) ;
	DRIVERCRATE_EXPECT( context, normalBefore == projectedStoreSnapshot( context, source)) ;
	// 元正常閉包の不成立を後続の架空成功で補完しません。
	if( !accepted) {
		throw std::runtime_error( "registered projected history positive fixture") ;
	}

	// 唯一の出力contextが所有するjobを入力へ借用しても、再検査中に解放しません。
	const auto *aliasedJob =
		// 旧出力だけの借用。
		accepted->slices()[0].campaign->job( accepted->slices()[0].jobIndex) ;
	DRIVERCRATE_EXPECT( context, aliasedJob &&
									LocalCollectorRecovery::inspectRegisteredProjectedHistory(
										source, *aliasedJob, definition.sources,
										HTTP_TEST_UTC + 125000U, accepted) == 0U &&
									accepted) ;
	DRIVERCRATE_EXPECT( context, normalBefore == projectedStoreSnapshot( context, source)) ;

	const auto op = accepted->cache().attempt.operation ;	// 固定名へ結合した元操作。
	const auto cacheName =
		L"current/campaign-cache-v1-" + accepted->cache().request + L".json" ;	// 根拠cache。
	const auto stateName =
		L"current/campaign-state-v3-" + prepared->generationKey() + L".json" ;	// 根拠state。
	LocalCollectorStateStore interruptedStore ;									// 通常中断回復の旧v2を専用検証へ渡します。
	DRIVERCRATE_EXPECT( context, interruptedStore.initialize( rootFactory(), true) == 0U) ;
	const auto interruptedPrepared =
		makeRegisteredHistoryFixture( context, interruptedStore, definition, L"20260927",
									 HTTP_TEST_UTC, 3U) ;	// 非保存候補を破棄。
	LocalCollectorRecovery recovered ;						// 新世代でも既存中断回復の契約を維持します。
	DRIVERCRATE_EXPECT( context,
					   recovered.initializeProjected( interruptedStore, definition,
													 HTTP_TEST_UTC + 125000U, 125000U) == 0U) ;
	const auto interruptedBefore =
		// 回復は検証前にだけ行います。
		projectedStoreSnapshot( context, interruptedStore) ;
	std::shared_ptr<const CollectorRegisteredProjectedHistory>
		interruptedContext ;	// 欠測中断に成功sliceを補いません。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
					 interruptedStore, *interruptedPrepared->job( 1U), definition.sources,
					 HTTP_TEST_UTC + 125000U, interruptedContext) == 0U &&
					 interruptedContext &&
					 interruptedContext->cache().reason == CollectorCacheReason::INTERRUPTED &&
					 interruptedContext->slices().empty()) ;
	DRIVERCRATE_EXPECT( context,
					   interruptedBefore == projectedStoreSnapshot( context, interruptedStore)) ;
	// 過去世代を参照する置換・減少・元失敗を独立fixtureで検査します。
	for( unsigned scenario = 0U; scenario < 4U; ++scenario) {
		LocalCollectorStateStore store ;	// 新しい日の元予約から閉じた二世代を組み立てます。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		auto secondDefinition = definition ;	// 別artifactでも旧根拠を省略しない比較用です。
		// 同じrequestのbindingだけを変え、古い成功を履歴として検査します。
		if( scenario == 3U) {
			secondDefinition.artifactSha256 = std::wstring( 64U, L'd') ;
		}

		const auto secondPrepared =
			makeRegisteredHistoryFixture( context, store, secondDefinition, L"20260928",
										 HTTP_TEST_UTC + 86400000U, scenario == 3U ? 0U : scenario,
										 // 旧成功は本番最終化coreで比較します。
										 accepted.get()) ;
		// 旧世代のimmutable根拠と元terminal表だけを新fixtureへ持ち込みます。
		for( const auto &entry : normalBefore) {
			// 共有root・mode・現在CACHE・予算・待機は新世代の値を維持します。
			if( entry.first.starts_with( L"runs/") || entry.first == stateName) {
				DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
			}
		}

		const auto archiveBody =
			// 旧日の元精算済み共有予算。
			httpSavedBody( source, L"current/campaign-budget-v1.json") ;
		std::wstring archiveHash ;	// Root登録と元archiveの結合。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( archiveBody, archiveHash) == 0U) ;
		saveRegisteredHistoryFixture( context, store, L"runs/campaign-budget-20260927.json",
									 archiveBody) ;
		const auto oldRoot = JsonObject::Parse( winrt::to_hstring(
			// 旧世代登録。
			httpSavedBody( source, L"current/campaign-root-v2.json"))) ;
		mutateProjectedStore(
			context, store, L"current/campaign-root-v2.json", [&]( JsonObject &root) {
				root.GetNamedArray( L"generations")
					.Append( oldRoot.GetNamedArray( L"generations").GetAt( 0U)) ;
				JsonObject archive ;	// 閉包検証用の有限archive登録。日次完了proofではありません。
				archive.Insert( L"day", JsonValue::CreateStringValue( L"20260927")) ;
				archive.Insert( L"hash", JsonValue::CreateStringValue( archiveHash)) ;
				archive.Insert( L"operation", JsonValue::CreateStringValue( std::wstring( 64U, L'a'))) ;
				root.GetNamedArray( L"archives").Append( archive) ;
			}) ; // 同期呼出し中だけ旧rootと実archive hashを借用します。
		const auto before = projectedStoreSnapshot( context, store) ;		// 元二世代fixture全byte。
		std::shared_ptr<const CollectorRegisteredProjectedHistory> result ;	// 成功時だけ生成します。
		const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, *secondPrepared->job( 1U), definition.sources,
			HTTP_TEST_UTC + 86400000U + 125000U,
			result) ;	// 全before-CACHEと旧成功の実参照を検証します。
		DRIVERCRATE_EXPECT( context, code == 0U && result && result->operations() == 2U &&
										result->slices().size() == 1U) ;
		DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store)) ;
		// 元成功は欠損時に新しい架空成功へしません。
		if( !result) {
			throw std::runtime_error( "registered projected multi-generation fixture: scenario=" +
									 std::to_string( scenario) + ", code=" + std::to_string( code)) ;
		}

		DRIVERCRATE_EXPECT( context,
						   result->cache().attempt.generation == secondPrepared->generationKey()) ;
		// 減少と原worker失敗は旧成功200・sliceをそのまま保持し、validatorを解除します。
		if( scenario == 1U || scenario == 2U) {
			DRIVERCRATE_EXPECT(
				context, !result->cache().reusable && !result->cache().etag &&
							 result->cache().original200 &&
							 result->cache().original200->generation == prepared->generationKey() &&
							 result->slices().front().generation == prepared->generationKey() &&
							 result->cache().reason ==
								 (scenario == 1U ? CollectorCacheReason::DECREASED
												 : CollectorCacheReason::WORKER_FAILURE)) ;
		}

		const auto secondOp = result->cache().attempt.operation ;	// 新更新前像と旧更新後像の結合。
		// 更新前CACHEの破損は旧成功が正当でも全体拒否します。
		mutateProjectedStore(
			context, store, L"runs/campaign-effect-v2-" + secondOp + L"-before-cache.json",
			[]( JsonObject &cache) {
				cache.Insert( L"binding", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
			}) ;
		const auto modified =
			// 正当な外側hash付き不正根拠。
			projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
										store, *secondPrepared->job( 1U), definition.sources,
										HTTP_TEST_UTC + 86400000U + 125000U, result) != 0U &&
										!result) ;
		DRIVERCRATE_EXPECT( context, modified == projectedStoreSnapshot( context, store)) ;
	}

	// 組み込みsource契約不一致を保存sourceの自己申告だけで受理しません。
	auto differentSources = definition.sources ;	// 同じ公開製品でもparser契約は元値へ固定します。
	// 全sourceを変え、保存sourceの値が実行中の契約と不一致になるfixtureです。
	for( auto &sourceEntry : differentSources) {
		sourceEntry.parserRevision = L"different-parser" ;
	}

	std::shared_ptr<const CollectorRegisteredProjectedHistory> sourceMismatch =
		accepted ;	// 失敗時に空へ戻すことを検査します。
	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectRegisteredProjectedHistory(
									source, *prepared->job( 1U), differentSources,
									HTTP_TEST_UTC + 125000U, sourceMismatch) != 0U &&
									!sourceMismatch) ;
	DRIVERCRATE_EXPECT( context, normalBefore == projectedStoreSnapshot( context, source)) ;
	// 外側hash一致でも不正な登録・役割・intent・原応答を受理しない28条件。
	for( unsigned mode = 0U; mode < 28U; ++mode) {
		LocalCollectorStateStore store ;	// 正常byteから一要因だけ変更する独立store。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		const auto missing = mode == 0U ? L"runs/campaign-response-v4-" + op + L".json"
							 : mode == 1U
								 ? L"runs/campaign-effect-v2-" + op + L"-before-control.json"
							 : mode == 2U ? L"runs/campaign-effect-v2-" + op + L"-cache.json"
										  : std::wstring{} ;	// 実不在を作る三条件。
		// 固定fixture集合を複製し、不在条件だけ元fileを省きます。
		for( const auto &entry : normalBefore) {
			// 不在を空byte fileへ置換しません。
			if( entry.first != missing) {
				DRIVERCRATE_EXPECT( context, store.write( entry.first, entry.second) == 0U) ;
			}
		}

		// 同Oの別version併存を成功v4から勝手に選別しません。
		if( mode == 3U || mode == 4U) {
			DRIVERCRATE_EXPECT(
				context, store.write( std::wstring( mode == 3U ? L"runs/campaign-response-v2-"
															 : L"runs/campaign-response-v3-") +
										 op + L".json",
									 "{}") == 0U) ;
		}

		// 登録hash・重複・summary・commit・mode・時刻を一要因だけ改変します。
		if( mode >= 5U && mode <= 10U) {
			mutateProjectedStore(
				context, store, L"current/campaign-root-v2.json", [mode]( JsonObject &root) {
					// 登録本文hashだけを元CACHEと不一致にします。
					if( mode == 5U) {
						root.GetNamedArray( L"cacheInventory")
							.GetObjectAt( 0U)
							.Insert( L"hash", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
					}

					// 世代登録の重複を拒否します。
					if( mode == 6U) {
						root.GetNamedArray( L"generations")
							.Append( root.GetNamedArray( L"generations").GetAt( 0U)) ;
					}

					// 未実装summaryを無言で読み飛ばしません。
					if( mode == 7U) {
						root.GetNamedArray( L"generations")
							.GetObjectAt( 0U)
							.Insert( L"summaryHash",
									JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
					}

					// 保存途中のrootを完了済みとして受理しません。
					if( mode == 8U) {
						root.Insert( L"commit", JsonObject{}) ;
					}

					// Future root時刻を拒否します。
					if( mode == 9U) {
						root.Insert( L"lastUtcMillis",
									JsonValue::CreateNumberValue(
										static_cast<double>( HTTP_TEST_UTC + 125001U))) ;
					}

					// Root登録なしを初回履歴へ変換しません。
					if( mode == 10U) {
						root.GetNamedArray( L"cacheInventory").Clear() ;
					}
				}) ;
		}

		// 同じrootKey以外のmodeを拒否します。
		if( mode == 11U) {
			mutateProjectedStore(
				context, store, L"current/collector-campaign-mode-v1.json", []( JsonObject &row) {
					row.Insert( L"rootKey", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}) ;
		}

		// 現terminalと元開始intentのいずれの差替えも拒否します。
		if( mode == 12U || mode == 13U) {
			mutateProjectedStore( context, store, stateName, [mode]( JsonObject &state) {
				const auto row = state.GetNamedArray( L"jobs").GetObjectAt( 1U) ;	// 同じ元ASUS行。
				// 元応答hashの差替えです。
				if( mode == 12U) {
					row.Insert( L"response", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 正しい開始intentを欠測へ変更します。
				if( mode == 13U) {
					row.Insert( L"intent", JsonValue::CreateNullValue()) ;
				}
			}) ;
		}

		// 全roleの更新後像を一つずつ不正本文へ変更します。
		if( mode >= 14U && mode <= 17U) {
			const std::array<std::wstring, 4U> roles = {L"control", L"job", L"budget",
														L"cache"} ;	// 全四role。
			saveRegisteredHistoryFixture(
				context, store,
				L"runs/campaign-effect-v2-" + op + L"-" + roles[mode - 14U] + L".json", "{}") ;
		}

		// 元markerの全byte結合を検査します。
		if( mode == 18U) {
			saveRegisteredHistoryFixture(
				context, store, L"runs/campaign-marker-v3-" + prepared->generationKey() + L".json",
				"{}") ;
		}

		// 未検査CACHEの破損を登録hashだけで見逃しません。
		if( mode == 19U) {
			saveRegisteredHistoryFixture( context, store, cacheName, "{}") ;
		}

		bool changed{} ;	// 読取り途中のroot差替えを一度だけ行うfixture。
		const CollectorProjectedHashProbe probe =
			[&]( CollectorProjectedHashStage stage) -> NativeError {
			// 元READ_RESPONSE失敗をそのまま返す診断です。
			if( mode == 20U && stage == CollectorProjectedHashStage::READ_RESPONSE) {
				return static_cast<NativeError>( 0x80090020U) ;
			}

			// 下位allocation故障を縮退成功へしません。
			if( mode == 21U) {
				throw std::bad_alloc{} ;
			}

			// 初読取り以後のroot変更は最終全raw照合で検出します。
			if( mode == 22U && !changed) {
				changed = true ;
				mutateProjectedStore(
					context, store, L"current/campaign-root-v2.json", []( JsonObject &root) {
						root.Insert( L"lastUtcMillis",
									JsonValue::CreateNumberValue(
										static_cast<double>( HTTP_TEST_UTC + 124999U))) ;
					}) ;
			}

			return 0 ;
		} ; // 同期呼出し中だけmode・store・changedを借用します。
		// 最新共有待機の後退を拒否します。
		if( mode == 23U) {
			saveRegisteredHistoryFixture( context, store, L"current/campaign-controls-v1.json",
										 "{}") ;
		}

		// 元世代のinput hash・保存版・CACHE一意性と300件境界を一要因ずつ検査します。
		if( mode >= 24U && mode <= 27U) {
			mutateProjectedStore(
				context, store, L"current/campaign-root-v2.json", [mode]( JsonObject &root) {
					// 元入力hashだけを不一致にします。
					if( mode == 24U) {
						root.GetNamedArray( L"generations")
							.GetObjectAt( 0U)
							.Insert( L"inputHash",
									JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
					}

					// 未知保存版を既知版へ読み替えません。
					if( mode == 25U) {
						root.GetNamedArray( L"generations")
							.GetObjectAt( 0U)
							.Insert( L"storageVersion", JsonValue::CreateNumberValue( 99U)) ;
					}

					// 同じrequestの二重登録を拒否します。
					if( mode == 26U) {
						root.GetNamedArray( L"cacheInventory")
							.Append( root.GetNamedArray( L"cacheInventory").GetAt( 0U)) ;
					}

					// 301世代は重複検査より先に容量拒否します。
					if( mode == 27U) {
						const auto rows =
							// 最大件数の境界専用fixture。
							root.GetNamedArray( L"generations") ;
						// 元一行に300行を加え、正規化で件数を縮めさせません。
						for( unsigned index = 0U; index < 300U; ++index) {
							rows.Append( rows.GetAt( 0U)) ;
						}
					}
				}) ;
		}

		const auto before = projectedStoreSnapshot( context, store) ;	// 一要因改変後の元byte。
		std::shared_ptr<const CollectorRegisteredProjectedHistory> result =
			accepted ;	// 失敗時の旧出力残存を検査します。
		const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, *prepared->job( 1U), definition.sources, HTTP_TEST_UTC + 125000U, result,
			probe) ;	// HTTP factoryなしの検査。
		DRIVERCRATE_EXPECT( context, code != 0U && !result) ;
		// 容量超過は一般破損13へ変換しません。
		if( mode == 27U) {
			DRIVERCRATE_EXPECT( context, code == ERROR_TOO_MANY_NAMES) ;
		}

		// CNG原値とOOMは関係拒否13へ潰しません。
		if( mode == 20U || mode == 21U) {
			DRIVERCRATE_EXPECT(
				context, code == (mode == 20U ? 0x80090020U : static_cast<DWORD>( E_OUTOFMEMORY))) ;
		}

		// 変更注入case以外は全保存名・byteがそのままです。
		if( mode != 22U) {
			DRIVERCRATE_EXPECT( context, before == projectedStoreSnapshot( context, store)) ;
		}
	}
}

/** @brief 予約より前の保存根拠差替えを追加書込み・HTTPなしで拒否します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 一caseごとの独立保護store。
 * @param[in] definition 元二source入力。
 * @param[in] prepared 元canonicalの変更不能入力。
 */
void projectedHistoryReservationChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	// 自己一貫したhash付き改変14件と、四roleの孤立前後像8件を検査します。
	for( unsigned mode = 1U; mode <= 22U; ++mode) {
		LocalCollectorStateStore store ;	// 保護済みfixtureだけを書き換えます。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 改変前の元登録を所有します。
		DRIVERCRATE_EXPECT(
			context, recovery.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
		const auto	&generation = prepared->generationKey() ;			// 予約前に確定したG。
		const auto	&job		= prepared->job( 0U)->value() ;			// 元indexの非可変job。
		std::wstring path		= L"current/campaign-root-v2.json" ;	// 既定は登録簿の一要因改変。
		// Root外の各根拠は別caseとし、複数fileを同時改変しません。
		if( mode == 6U) {
			path = L"current/collector-campaign-mode-v1.json" ;
		}
		// 入力と世代markerを独立に変更します。
		else if( mode == 7U || mode == 8U) {
			path = std::wstring( mode == 7U ? L"runs/campaign-input-v3-"
										   : L"runs/campaign-marker-v3-") +
				   generation + L".json" ;
		}
		// 未予約行だけの差替えも受付前に拒否します。
		else if( mode == 9U) {
			path = L"current/campaign-state-v3-" + generation + L".json" ;
		}

		// 既存fileは外側hashを再計算し、本文とprocess正本の関係を壊します。
		if( mode <= 10U) {
			mutateProjectedStore( context, store, path, [&]( JsonObject &body) {
				// Root自身とmode内のroot結合を個別に差し替えます。
				if( mode == 1U || mode == 6U) {
					body.Insert( L"rootKey", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 現世代を未知の有効hashへ変更します。
				if( mode == 2U) {
					body.Insert( L"activeGeneration",
								JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 登録の入力結合を実行中Gと不一致にします。
				if( mode == 3U) {
					body.GetNamedArray( L"generations")
						.GetObjectAt( 0U)
						.Insert( L"inputHash",
								JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 同じGで旧保存版を名乗る登録を受け入れません。
				if( mode == 4U) {
					body.GetNamedArray( L"generations")
						.GetObjectAt( 0U)
						.Insert( L"storageVersion", JsonValue::CreateNumberValue( 2)) ;
				}

				// FileのないCACHE登録も空履歴へ読み替えません。
				if( mode == 5U) {
					JsonObject row ;	// 単独の登録行。
					row.Insert( L"request", JsonValue::CreateStringValue( job.requestKey)) ;
					row.Insert( L"hash", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
					body.GetNamedArray( L"cacheInventory").Append( row) ;
				}

				// 入力形式だけを変更し、元hashを正しく作り直します。
				if( mode == 7U) {
					body.Insert( L"schema", JsonValue::CreateStringValue( L"fixture-wrong-schema")) ;
				}

				// Markerから元入力への結合を差し替えます。
				if( mode == 8U) {
					body.Insert( L"inputHash",
								JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 未予約行の偽完了を次job受付に利用しません。
				if( mode == 9U) {
					body.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
						L"state", JsonValue::CreateStringValue( L"DONE")) ;
				}

				// 保存途中のcommitを無視して次のHTTPを開始しません。
				if( mode == 10U) {
					body.Insert( L"commit", JsonObject{}) ;
				}
			}) ;
		} else {
			std::string original ;	// Hash付きの元inputを孤立fileとして用います。
			bool		found{} ;	// 未存在を成功にしません。
			DRIVERCRATE_EXPECT( context,
							   store.read( L"runs/campaign-input-v3-" + generation + L".json",
										  original, found) == 0U &&
								   found) ;
			std::wstring operation ;	// 本番と同じ決定的な応答slot。
			DRIVERCRATE_EXPECT( context,
							   computeBytesSha256( "response-v2\n" + winrt::to_string( generation) +
													  "\n" + winrt::to_string( job.jobKey) + "\n",
												  operation) == 0U) ;
			// CACHE実体だけが存在する場合も空履歴として開始しません。
			if( mode == 11U) {
				path = L"current/campaign-cache-v1-" + job.requestKey + L".json" ;
			}
			// 旧二版と新v4の応答slotを独立に占有します。
			else if( mode <= 14U) {
				path = L"runs/campaign-response-v" + std::to_wstring( mode - 10U) + L"-" +
					   operation + L".json" ;
			} else {
				const std::array<std::wstring, 4U> roles{L"control", L"cache", L"job",
														 L"budget"} ;	// 有限role。
				path = L"runs/campaign-effect-v2-" + operation + L"-" +
					   ((mode - 15U) % 2U == 0U ? L"before-" : L"") + roles[(mode - 15U) / 2U] +
					   L".json" ;
			}

			DRIVERCRATE_EXPECT( context, store.write( path, original) == 0U) ;
		}

		const auto before =
			// 改変後から予約による追加変更を監視します。
			projectedStoreSnapshot( context, store) ;
		std::size_t							   starts{} ;		// Thread開始依存に到達した回数。
		std::size_t							   clients{} ;		// HTTP依存に到達した回数。
		CollectorProjectedExecutorDependencies dependencies ;	// Native HTTPを一切用いません。
		dependencies.campaign = prepared ;
		dependencies.clock	  = [] {
			   return CollectorHttpClockSample{HTTP_TEST_UTC, 0U} ;
		} ; // 親の固定clock。
		dependencies.createClient = [&]() -> std::unique_ptr<LocalCollectorHttpClient> {
			++clients ;
			return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
		} ; // 呼ばれたら件数で拒否試験を失敗させます。
		dependencies.start = [&]( std::function<void()>) -> std::thread {
			++starts ;
			throw std::bad_alloc{} ;
		} ; // 不正受付時にも通信せず、元error差と開始件数で検出します。
		LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 元監督だけを渡します。
		const auto error  = executor.startNext( recovery) ;						// 予約前拒否を要求します。
		const auto report = executor.join() ;									// 起動0でも通常の所有回収を実行します。
		const auto label  = "history reservation mode=" + std::to_string( mode) +
						   " error=" + std::to_string( error) ;	// 失敗caseの識別。
		context.expect( error == ERROR_INVALID_DATA, label, __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context, clients == 0U && report.reserved == 0U &&
										report.started == 0U && report.joined == 0U &&
										report.notified == 0U) ;
		DRIVERCRATE_EXPECT( context, projectedStoreSnapshot( context, store) == before) ;
		DRIVERCRATE_EXPECT( context,
						   recovery.lastError() == error && recovery.reason() == L"STATE_ERROR") ;
	}
}

/** @brief 所有workerと実予約を親prepareへ渡し、一回性・改変・非保存を確認します。
 * @param[in,out] context 親threadの集計。
 * @param[in] rootFactory 各caseの独立保護store。
 * @param[in] definition 元二source入力。
 * @param[in] prepared 元canonical不変入力。
 */
void projectedParentChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	// 正常二jobと、所有者・時刻・各永続根拠・hash故障を一要因ずつ検査する。
	for( unsigned mode = 0U; mode < 39U; ++mode) {
		const auto fixturesOwner =
			std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
		auto &fixtures	 = *fixturesOwner ;					// Workerごとの独立fake資源。
		fixtures[0].body = winrt::to_string( winrt::hstring( projectedIntelHtml())) ;
		fixtures[1].body = winrt::to_string(
			winrt::hstring( projectedAsusHtml( L"/pub/ASUS/mb/04LAN/DRV_LAN_Fixture.zip"))) ;
		LocalCollectorStateStore store ;	// 試験専用の実writer。
		// 元read故障の保存候補と、そのmetadata hash二次故障を分離します。
		if( mode == 28U || mode == 29U) {
			fixtures[0].failure = "read" ;
		}

		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 所有identityを生成する監督。
		DRIVERCRATE_EXPECT(
			context, recovery.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
		CollectorProjectedExecutorDependencies dependencies ;	// Native factoryを使わない。
		dependencies.campaign = prepared ;
		dependencies.clock	  = [] {
			   return activeFixture ? activeFixture->clock
									: CollectorHttpClockSample{HTTP_TEST_UTC, 0U} ;
		} ; // 親とworkerのclockを明示的に分離する。
		dependencies.createClient = [&]() -> std::unique_ptr<LocalCollectorHttpClient> {
			// 元SETUP失敗の数値を親prepareへ維持する。
			if( mode == 19U) {
				throw std::bad_alloc{} ;
			}

			return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
		} ; // 各workerが自分のHTTPだけを所有する。
		std::size_t next{} ;	// 親だけが更新する固定slot。
		dependencies.start = [&]( std::function<void()> worker) {
			const auto slot = next++ ;	// Threadへ値copy。
			return std::thread( [&, slot, worker = std::move( worker)] {
				fixtures[slot].ownerThread = std::this_thread::get_id() ;
				// 実測0は有効なので、時刻拒否試験だけ実workerを1ms後にする。
				if( mode == 5U || mode == 27U) {
					fixtures[slot].clock = {HTTP_TEST_UTC + 1U, 1U} ;
				}

				FixtureScope scope( fixtures[slot]) ;	// Joinまでfixtureが存続する。
				worker() ;
			}) ;
		} ;
		LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 元所有結果を保持する。
		DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == 0U) ;
		// 正常caseだけ独立二groupを同時に予約する。
		if( mode == 0U) {
			DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == 0U) ;
		}

		const auto updateOwner = std::make_unique<
			CollectorProjectedPreparedUpdate>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto &update = *updateOwner ;		// 応答とCACHEの片方だけ残ることを禁止する。
		auto &output = update.response ;	// 旧APIと共通の応答を比較します。
		// 実threadが既に終了していても親の全join前は拒否する。
		if( mode == 1U) {
			DRIVERCRATE_EXPECT(
				context, recovery.prepareInitialProjected( executor, 0U, HTTP_TEST_UTC + 125000U,
														  125000U, output) == ERROR_INVALID_DATA) ;
		}

		const auto report = executor.join() ;	// 以降はconstな元workerだけを参照する。
		DRIVERCRATE_EXPECT( context,
						   report.joined == report.started && report.notified == report.reserved) ;
		const auto *worker = executor.result( 0U) ;	// 任意DTOの差込みなし。
		DRIVERCRATE_EXPECT( context, worker != nullptr) ;
		// 元結果欠損で試験を架空成功させない。
		if( !worker) {
			continue ;
		}

		const auto &binding = worker->binding ;	// 所有workerの元予約。
		const auto	statePath =
			L"current/campaign-state-v3-" + prepared->generationKey() + L".json" ;	// 対象行。
		std::wstring tamperPath ;													// 一case一file。
		// 予約後にmodeのroot結合だけを差し替えます。
		if( mode == 30U) {
			tamperPath = L"current/collector-campaign-mode-v1.json" ;
		}

		// 元rootの世代結合を変更する。
		if( mode == 6U || mode == 20U) {
			tamperPath = L"current/campaign-root-v2.json" ;
		}

		// 実行中状態とintentは同じstate内に保存される。
		if( mode == 7U || mode == 21U) {
			tamperPath = statePath ;
		}

		// 元input／markerの整合性を壊す。
		if( mode == 8U || mode == 9U) {
			tamperPath = std::wstring( mode == 8U ? L"runs/campaign-input-v3-"
												 : L"runs/campaign-marker-v3-") +
						 prepared->generationKey() + L".json" ;
		}

		// 未精算予約のphase・残量・存在を個別に壊す。
		if( mode == 10U || mode == 22U || mode == 23U) {
			tamperPath = L"current/campaign-budget-v1.json" ;
		}

		// Request intentの保存先だけを壊す。
		if( mode == 11U || mode == 24U) {
			tamperPath = L"current/campaign-controls-v1.json" ;
		}

		// 外側hashを正しく作り直し、単なるhash破損で試験を済ませない。
		if( !tamperPath.empty()) {
			mutateProjectedStore( context, store, tamperPath, [&]( JsonObject &body) {
				// 有効なhashでも別rootのmarkerは受け入れません。
				if( mode == 30U) {
					body.Insert( L"rootKey", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 有効schemaのままrequestだけの開始を変える。
				if( mode == 24U) {
					const auto rows = body.GetNamedArray( L"controls") ;	// Groupとrequestの固定行。
					// Requestの非空開始intentだけを変更する。
					for( const auto &entry : rows) {
						auto row = entry.GetObject() ;	// 一行の保存制御。
						// Group行の開始0は維持する。
						if( row.GetNamedNumber( L"started") != 0) {
							row.Insert( L"started", JsonValue::CreateNumberValue( static_cast<double>(
													   binding.startedUtcMillis - 1000U))) ;
						}
					}
				}

				// Schema改変も元hashを再計算して渡す。
				if( mode == 8U || mode == 9U || mode == 11U) {
					body.Insert( L"schema", JsonValue::CreateStringValue( L"fixture-wrong-schema")) ;
				}

				// 元rootと別世代へ差し替える。
				if( mode == 6U) {
					body.Insert( L"activeGeneration",
								JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
				}

				// 登録だけ増設した履歴を「履歴なし」にしない。
				if( mode == 20U) {
					JsonObject row ;	// 未存在cacheを指す登録。
					row.Insert( L"request", JsonValue::CreateStringValue( binding.requestKey)) ;
					row.Insert( L"hash", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
					body.GetNamedArray( L"cacheInventory").Append( row) ;
				}

				// RUNNINGの書換えと自己一貫したintent差替えを分離する。
				if( mode == 7U || mode == 21U) {
					auto row = body.GetNamedArray( L"jobs").GetObjectAt( 0U) ;	// 元共有job。
					// 完了済みへの変更を受け入れない。
					if( mode == 7U) {
						row.Insert( L"state", JsonValue::CreateStringValue( L"DONE")) ;
					} else {
						row.GetNamedObject( L"intent").Insert(
							L"scope", JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
					}
				}

				// 予算parseが可能でも原予約と一致しなければ拒否する。
				if( mode == 10U || mode == 22U || mode == 23U) {
					auto rows = body.GetNamedArray( L"reservations") ;	// 元予算一行。
					// 予約欠損を新しい予約として補完しない。
					if( mode == 23U) {
						rows.Clear() ;
					} else {
						rows.GetObjectAt( 0U).Insert( L"phase", JsonValue::CreateNumberValue( 1)) ;
						// 精算後の0 byteを未精算最大量へ戻さない。
						if( mode == 22U) {
							rows.GetObjectAt( 0U).Insert( L"charged",
														JsonValue::CreateNumberValue( 0)) ;
						}
					}
				}
			}) ;
		}

		// 孤立cacheと同一操作の先行responseを、壊れたfileでなく有効envelopeで挿入する。
		if( mode == 12U || mode == 13U || mode == 25U || mode == 26U || mode >= 31U) {
			std::string original ;	// 有効外側を持つ元inputのbyte。
			bool		found{} ;	// 元fileの存在確認。
			DRIVERCRATE_EXPECT( context, store.read( L"runs/campaign-input-v3-" +
													   prepared->generationKey() + L".json",
												   original, found) == 0U &&
											found) ;
			std::wstring operation ;	// 本番と同じ固定操作hash。
			DRIVERCRATE_EXPECT(
				context,
				computeBytesSha256( "response-v2\n" + winrt::to_string( binding.generationKey) +
									   "\n" + winrt::to_string( binding.jobKey) + "\n",
								   operation) == 0U) ;
			auto path = mode == 12U ? L"current/campaign-cache-v1-" + binding.requestKey + L".json"
									: std::wstring( mode == 25U	 ? L"runs/campaign-response-v2-"
												   : mode == 26U ? L"runs/campaign-response-v3-"
																 : L"runs/campaign-response-v4-") +
										  operation + L".json" ;	// 正式なslot名。
			// 四roleの前後像をそれぞれ独立に挿入します。
			if( mode >= 31U) {
				const std::array<std::wstring, 4U> roles{L"control", L"cache", L"job",
														 L"budget"} ;	// 固定role。
				path = L"runs/campaign-effect-v2-" + operation + L"-" +
					   ((mode - 31U) % 2U == 0U ? L"before-" : L"") + roles[(mode - 31U) / 2U] +
					   L".json" ;
			}

			DRIVERCRATE_EXPECT( context, store.write( path, original) == 0U) ;
		}

		LocalCollectorStateStore otherStore ;		// 同じ世代の別所有者を用意する。
		LocalCollectorRecovery	 otherRecovery ;	// 同じGだけでは同じ予約にならない。
		// 試験対象以外のstoreを不用意に作らない。
		if( mode == 3U) {
			DRIVERCRATE_EXPECT( context, otherStore.initialize( rootFactory(), true) == 0U) ;
			DRIVERCRATE_EXPECT( context, otherRecovery.initializeProjected( otherStore, definition,
																		  HTTP_TEST_UTC, 0U) == 0U) ;
		}

		auto	   &receiver = mode == 3U ? otherRecovery : recovery ;	// 受理する実監督。
		const auto	before = projectedStoreSnapshot( context, store) ;	// prepareはfileを更新しない。
		std::size_t hashCalls{} ;										// 再試行を計数する。
		const auto	probe = [&]( CollectorProjectedHashStage stage) -> std::int32_t {
			 ++hashCalls ;
			 // OOMは縮退保存せず、元HRESULTで全体停止する。
			 if( mode == 18U) {
				 throw std::bad_alloc{} ;
			 }

			 return (((mode == 14U || mode == 29U) &&
					  stage == CollectorProjectedHashStage::METADATA) ||
					 (mode == 15U && stage == CollectorProjectedHashStage::RESPONSE) ||
					 (mode == 16U && stage == CollectorProjectedHashStage::READ_METADATA) ||
					 (mode == 17U && stage == CollectorProjectedHashStage::READ_RESPONSE))
						? E_ACCESSDENIED
						: 0 ;
		} ; // 成功値は注入できず、0は実CNGへ進む。
		output.envelope	   = "stale" ;
		update.cache	   = "stale" ;
		update.cacheSha256 = L"stale" ;
		const auto error =
			receiver.prepareInitialProjectedUpdate( executor, mode == 2U ? 4U : 0U,
												   mode == 4U	 ? HTTP_TEST_UTC - 1U
												   : mode == 27U ? HTTP_TEST_UTC
																 : HTTP_TEST_UTC + 125000U,
												   mode == 5U ? 0U : 125000U, update,
												   probe) ;	// 親の元時計を明示する。
		const bool success =
			// 失敗候補も取得成功とは別に採点する。
			mode == 0U || mode == 14U || mode == 28U ;
		const auto label = "parent prepare mode=" + std::to_string( mode) +
						   " error=" + std::to_string( error) ;	// 診断だけ。
		context.expect( success ? error == 0U : error != 0U, label, __FILE__, __LINE__) ;
		// 成功時は元I/O・実hash・非保存を確認する。
		if( success) {
			CollectorProjectedCache derived ;		// 同じv4を独立に導出します。
			CollectorProjectedCache decoded ;		// 親からのCACHEを再読込みします。
			std::string				expected ;		// CACHE実byteの比較値。
			std::wstring			expectedHash ;	// 元byteから独立に計算します。
			DRIVERCRATE_EXPECT( context,
							   deriveCollectorProjectedCache( prepared->job( 0U)->value(),
															 output.envelope, nullptr, derived)
										   .status == collector_projected_json::Status::OK &&
								   encodeCollectorProjectedCache( derived, expected).status ==
									   collector_projected_json::Status::OK &&
								   expected == update.cache &&
								   computeBytesSha256( expected, expectedHash) == 0U &&
								   expectedHash == update.cacheSha256) ;
			DRIVERCRATE_EXPECT( context,
							   decodeCollectorProjectedCache( update.cache, decoded).status ==
									   collector_projected_json::Status::OK &&
								   decoded.attempt.response == output.responseSha256 &&
								   decoded.attempt.generation == binding.generationKey &&
								   decoded.request == binding.requestKey) ;
			DRIVERCRATE_EXPECT( context, !output.envelope.empty() && output.envelope != "stale" &&
											output.value.generation == binding.generationKey &&
											output.value.job == binding.jobKey &&
											output.value.io.finishedUtcMillis ==
												worker->io.finishedUtcMillis &&
											output.value.error == worker->io.error.code &&
											output.value.accepted == HTTP_TEST_UTC + 125000U &&
											!output.value.original200) ;
			// Metadata故障は元HTTP成功を保ち別理由で縮退する。
			if( mode == 14U) {
				DRIVERCRATE_EXPECT( context,
								   output.value.cacheDecision.reason ==
										   CollectorProjectedCacheReason::METADATA_HASH &&
									   output.value.projection.empty() &&
									   output.value.io.cause == CollectorIoCause::COMPLETE) ;
			}
			// 正常な二slotを独立に準備できることを確認する。
			else if( mode == 0U) {
				const auto secondOwner = std::make_unique<
					CollectorProjectedResponseBytes>() ;	// 同じscopeだけで大きなfixtureを所有する。
				auto &second = *secondOwner ;				// 同じ二workerの別slotは独立に受理する。
				DRIVERCRATE_EXPECT(
					context, recovery.prepareInitialProjected( executor, 1U, HTTP_TEST_UTC + 125000U,
															  125000U, second) == 0U &&
								 !second.envelope.empty()) ;
			}
		} else {
			DRIVERCRATE_EXPECT(
				context, output.envelope.empty() && update.cache.empty() &&
							 update.cacheSha256.empty() && receiver.lastError() == error &&
							 receiver.reason() == L"STATE_ERROR" && executor.join().error == error) ;
		}

		// 原hash／OOMの数値を一般拒否13へ潰さない。
		if( mode >= 15U && mode <= 19U) {
			DRIVERCRATE_EXPECT(
				context, error == static_cast<DWORD>( mode >= 18U ? E_OUTOFMEMORY : E_ACCESSDENIED)) ;
		}

		// Worker原失敗後のhash故障では元I/OをMETADATA_HASHへ上書きしない。
		if( mode == 28U || mode == 29U) {
			DRIVERCRATE_EXPECT( context,
							   worker->io.error.code == fixtures[0].error &&
								   worker->io.error.domain == CollectorIoErrorDomain::WIN32_ERROR &&
								   (mode != 29U || error == static_cast<DWORD>( E_ACCESSDENIED))) ;
		}

		const auto attempted = hashCalls ;	// 失敗後または同slot二回目はcodecを再実行しない。
		const auto repeated	 = receiver.prepareInitialProjectedUpdate(
			 executor, 0U, HTTP_TEST_UTC + 125001U, 125001U, update, probe) ;	// 二回目。
		DRIVERCRATE_EXPECT( context, repeated != 0U && output.envelope.empty() &&
										update.cache.empty() && update.cacheSha256.empty() &&
										hashCalls == attempted && (success || repeated == error) &&
										recovery.terminalJobs() == 0U) ;
		DRIVERCRATE_EXPECT( context, projectedStoreSnapshot( context, store) == before) ;
		// 親準備の有無で追加GETしない。
		if( mode != 1U && mode != 19U) {
			DRIVERCRATE_EXPECT( context, fixtures[0].calls["send"] == 1U && fixtures[0].valid) ;
		}
	}
}

/** @brief 偽HTTPから本番parser・実thread終端までを確認します。
 * @param[in,out] context 親threadだけが更新する集計。
 * @param[in] rootFactory 各caseの独立保護store。
 * @param[in] definition 元二source入力。
 * @param[in] prepared 元canonicalの不変入力。
 */
void projectedWorkerChecks(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &prepared)
{
	std::map<unsigned, CollectorProjectedWorkerResult>
										 historyWorkers ;					// 後日参照を合成する非保存fixture。
	CollectorProjectedCampaignDefinition statesDefinition = definition ;	// 三状態専用の元manifest。
	auto								 statesManifest =
		// 元二jobを保持。
		JsonObject::Parse( winrt::to_hstring( statesDefinition.manifestBytes)) ;
	auto statesTargets	  = statesManifest.GetNamedArray( L"targets") ;	// 元27対象へ二行だけ加える。
	auto statesReferences = statesManifest.GetNamedArray( L"jobs").GetObjectAt( 1U).GetNamedArray(
		L"targets") ;	// ASUS jobの参照順。
	// 元modelと比較等価だが実byteの異なる二製品名でmanifest重複を避けます。
	for( unsigned variant = 0U; variant < 2U; ++variant) {
		const auto id = variant == 0U ? L"board-unknown" : L"board-conflict" ;	// 固定公開ID。
		JsonObject target ;														// 個別の公開対象。端末IDは含みません。
		target.Insert( L"id", JsonValue::CreateStringValue( id)) ;
		target.Insert( L"maker", JsonValue::CreateStringValue( L"ASUS")) ;
		target.Insert( L"model",
					  JsonValue::CreateStringValue( variant == 0U ? L"proart x870e-creator wifi"
																 : L"PROART X870E-CREATOR WIFI")) ;
		target.Insert( L"kind", JsonValue::CreateStringValue( L"MAINBOARD")) ;
		// 一件目は未知用途、二件目は明示的な別用途です。
		target.Insert( L"purpose",
					  JsonValue::CreateStringValue( variant == 0U ? L"Other" : L"Wi-Fi")) ;

		statesTargets.Append( target) ;
		statesReferences.Append( JsonValue::CreateStringValue( id)) ;
	}

	statesDefinition.manifestBytes = winrt::to_string( statesManifest.Stringify()) ;
	const auto statesIdentityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;		// 同じscopeだけで大きなfixtureを所有する。
	auto &statesIdentity = *statesIdentityOwner ;	// 変更済み全scopeの専用世代。
	DRIVERCRATE_EXPECT(
		context,
		makeCollectorProjectedCampaignIdentity( statesDefinition, L"20260927", statesIdentity) &&
			statesIdentity.jobs.size() == 2U && statesIdentity.jobs[1].targets.size() == 3U) ;
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		statesPrepared ;	// 元保存byteを再検証。
	DRIVERCRATE_EXPECT( context, prepareCollectorProjectedCampaign(
									statesIdentity.canonicalInput, statesIdentity.inputSha256,
									statesIdentity.generationKey, statesDefinition.artifactSha256,
									statesDefinition.sources, statesPrepared) &&
									statesPrepared && statesPrepared->jobCount() == 2U &&
									statesPrepared->generationKey() != prepared->generationKey()) ;
	// 不成立の変種を有効な元campaignへ無言で戻しません。
	if( !statesPrepared || statesPrepared->jobCount() != 2U) {
		return ;
	}

	// 正常二worker・URL・read・OOM・起動・終端停止・上限・欠測・空clientを切り分けます。
	for( unsigned mode = 0U; mode < 28U; ++mode) {
		const bool	asusCase		 = mode >= 19U && mode <= 24U ;					// ASUS複数行の独立条件。
		const bool	stateCase		 = mode == 24U ;								// 同一公式pageの三対象だけ別世代にする。
		const auto &activeDefinition = stateCase ? statesDefinition : definition ;	// 保存元。
		const auto &activePrepared	 = stateCase ? statesPrepared : prepared ;		// 不変所有job。
		const auto	fixturesOwner =
			std::make_unique<std::array<IoFixture, 2U>>() ;			// 固定件数と型を保って所有する。
		auto					   &fixtures = *fixturesOwner ;		// 各threadの独立HTTP状態。
		std::array<std::size_t, 2U> postCloseSamples{} ;			// Parser到達clock数。
		std::array<bool, 2U>		mta{} ;							// Client構築時の明示MTA。
		std::array<bool, 2U>		finalClock{} ;					// COM解放後のfinish clock。
		std::array<bool, 2U>		returned{} ;					// Worker callbackの復帰。
		std::wstring				html = projectedIntelHtml() ;	// 元200本文。
		// 同じhero候補の危険pathを配布URL gateへ渡します。
		if( mode == 1U) {
			html.replace( html.find( L"/900011/Wired_driver_"), 8U, L"/900011/../") ;
		}

		// 一GETを共有する26対象のうち一件だけを元一覧へ掲載します。
		if( mode == 14U) {
			const auto marker = html.find( L"Fixture® Adapter X1") ;	// 元HTMLの唯一の公開一覧行。
			DRIVERCRATE_EXPECT( context, marker != html.npos) ;
			// 元行が存在する場合だけ変更し、欠損自体も試験失敗に残します。
			if( marker != html.npos) {
				html.replace( marker, std::wstring_view( L"Fixture® Adapter X1").size(),
							 L"Ethernet Product 0") ;
			}
		}

		// 見かけの許可host、userinfo、query、percentを元buttonだけへ注入します。
		if( mode >= 15U && mode <= 18U) {
			// 元HTMLの唯一の配布buttonから変更箇所を探します。
			const auto marker = html.find( L"https://downloadmirror.intel.com/900011/Wired_driver_") ;
			DRIVERCRATE_EXPECT( context, marker != html.npos) ;
			// 不明なHTMLへ架空URLを追加せず失敗として残します。
			if( marker != html.npos) {
				// Host偽装とuserinfoは別々のURLとして検証します。
				if( mode == 15U || mode == 16U) {
					html.replace( marker,
								 std::wstring_view( L"https://downloadmirror.intel.com").size(),
								 mode == 15U ? L"https://downloadmirror.intel.com.evil.example"
											 : L"https://downloadmirror.intel.com@evil.example") ;
				}
				// Query付きURLは許可済みhostでも配布候補としません。
				else if( mode == 17U) {
					const auto end = html.find( L".zip", marker) ;	// 元buttonの配布URL終端。
					DRIVERCRATE_EXPECT( context, end != html.npos) ;
					// 実際のbutton終端へだけqueryを追加します。
					if( end != html.npos) {
						html.insert( end + 4U, L"?mirror=untrusted") ;
					}
				} else {
					const auto path = html.find( L"/Wired_driver_", marker) ;	// 元file名の先頭。
					DRIVERCRATE_EXPECT( context, path != html.npos) ;
					// Percent表記による再解釈を許さない配布候補を作ります。
					if( path != html.npos) {
						html.replace( path, 2U, L"/%57") ;
					}
				}
			}
		}

		// Port・別basename・公開hash形式を一要因ずつ壊します。
		if( mode >= 25U) {
			const std::wstring_view before =
				mode == 25U	  ? L"https://downloadmirror.intel.com/"
				: mode == 26U ? L"/Wired_driver_31.2.2_x64.zip"
							  : L"SHA256: 2CBFF42A" ;	// 元本文中の一意な変更位置。
			const std::wstring_view after =
				mode == 25U	  ? L"https://downloadmirror.intel.com:444/"
				: mode == 26U ? L"/Other_driver_31.2.2_x64.zip"
							  : L"SHA256: ZCBFF42A" ;	// Hashは同じ長さの非hexへ変更。
			const auto marker = html.find( before) ;	// URL以外の表示名を変更しません。
			DRIVERCRATE_EXPECT( context, marker != html.npos) ;
			// Fixture前提の欠損を架空の拒否成功としません。
			if( marker != html.npos) {
				html.replace( marker, before.size(), after) ;
			}
		}

		// 公式一覧の1,025行を切詰め成功させません。
		if( mode == 9U) {
			// 固定fixtureの公式製品行を探します。
			const auto first =
				html.find( L"<li class=\"dc-page-detailed-other-valid-products-panel__product\"") ;
			const auto	 end = html.find( L"</li>", first) + 5U ;	// 固定fixtureの行終端。
			const auto	 row = html.substr( first, end - first) ;	// 同key同名の一行。
			std::wstring rows ;										// 有限追加分だけ。
			// 重複でも実走査の1,024行上限を適用します。
			for( unsigned count = 0U; count < 1024U; ++count) {
				rows += row ;
			}

			html.insert( end, rows) ;
		}

		fixtures[0].body =
			mode == 10U ? "<html>invalid metadata</html>" : winrt::to_string( winrt::hstring( html)) ;
		// ASUS側だけ複数行・部分拒否・空行へ切り替えます。
		const auto asusHtml = asusCase
								  ? projectedAsusRowsHtml( mode == 20U	? 16U
														  : mode == 21U ? 17U
														  : mode == 23U ? 0U
																		: 2U,
														  mode == 22U)
								  : projectedAsusHtml( L"/pub/ASUS/mb/04LAN/DRV_LAN_Fixture.zip") ;
		fixtures[1].body	= winrt::to_string( winrt::hstring( asusHtml)) ;
		// 原read errorと不明全量を発生させます。
		if( mode == 2U) {
			fixtures[0].failure = "read" ;
		}

		// Native解放失敗は構文拒否と別に全体停止させます。
		if( mode == 13U) {
			fixtures[0].failure = "close" ;
		}

		LocalCollectorStateStore store ;	// case専用の元予約。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 同じ監督へ別poolを混在させません。
		DRIVERCRATE_EXPECT( context, recovery.initializeProjected( store, activeDefinition,
																 HTTP_TEST_UTC, 0U) == 0U) ;
		LocalCollectorProjectedExecutor		  *executorPointer{} ;	// 構築後、全joinまで借用。
		std::size_t							   startIndex{} ;		// 親だけが更新するthread番号。
		CollectorProjectedExecutorDependencies dependencies ;		// 完全fakeと実threadを明示。
		dependencies.campaign = activePrepared ;
		dependencies.clock	  = [&] {
			   // 親clockはworkerの可変fixtureへアクセスしません。
			   if( activeFixture == nullptr) {
				   return CollectorHttpClockSample{HTTP_TEST_UTC, 0U} ;
			   }

			   const std::size_t index = activeFixture == &fixtures[0] ? 0U : 1U ;	// 自分の状態だけ。
			   // 当threadに割り当てた状態だけを借用します。
			   auto				&fixture = fixtures[index] ;
			   // 全HTTP handle解放後にだけparser・seal前の停止を注入します。
			   if( fixture.closed.size() == 3U) {
				   ++postCloseSamples[index] ;
				   APTTYPE			type{} ;		// COMの実thread分類。
				   APTTYPEQUALIFIER qualifier{} ;	// 暗黙MTAを明示init継続と混同しません。
				   // 明示初期化の実観測です。
				   const auto		apartment = CoGetApartmentType( &type, &qualifier) ;
				   // 暗黙MTAを明示初期化と区別します。
				   const bool		explicitMta = SUCCEEDED( apartment) && type == APTTYPE_MTA &&
											qualifier != APTTYPEQUALIFIER_IMPLICIT_MTA ;
				   // 本物のworkerがuninitした後、finishのclockでだけ停止します。
				   if( !explicitMta) {
					   finalClock[index] = true ;
					   // 完成済み暫定配列もseal前取消しで破棄します。
					   if( mode == 5U) {
						   executorPointer->requestStop() ;
					   }

					   // 同じ元二時計で期限に到達させます。
					   if( mode == 6U) {
						   fixture.clock = {HTTP_TEST_UTC + 120000U, 120000U} ;
					   }

					   // 巻戻りを終了時刻0へ補完させません。
					   if( mode == 7U) {
						   fixture.clock.utcMillis = HTTP_TEST_UTC - 1U ;
					   }
				   }

				   // Parser内へ到達してからの途中取消しを分離します。
				   if( mode == 8U && explicitMta && postCloseSamples[index] == 4U) {
					   executorPointer->requestStop() ;
				   }
			   }

			   return fixture.clock ;
		} ;
		dependencies.createClient = [&]() -> std::unique_ptr<LocalCollectorHttpClient> {
			const std::size_t index = activeFixture == &fixtures[0] ? 0U : 1U ;	// 自分のslot。
			APTTYPE			  type{} ;											// MTA内だけでclientを構築します。
			// Client構築時の明示初期化分類。
			APTTYPEQUALIFIER  qualifier{} ;
			mta[index] = SUCCEEDED( CoGetApartmentType( &type, &qualifier)) && type == APTTYPE_MTA &&
						 qualifier != APTTYPEQUALIFIER_IMPLICIT_MTA ;
			// 予約済みslotのOOMへ追加の成功DTOを生成しません。
			if( mode == 3U) {
				throw std::bad_alloc{} ;
			}

			// 空clientをnativeへ補完しません。
			if( mode == 11U) {
				return {} ;
			}

			return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
		} ;
		dependencies.start = [&]( std::function<void()> worker) -> std::thread {
			// Threadを開始する前のallocation失敗です。
			if( mode == 4U) {
				throw std::bad_alloc{} ;
			}

			// Thread APIの原Win32 errorを保持します。
			if( mode == 12U) {
				throw std::system_error( ERROR_ACCESS_DENIED, std::system_category()) ;
			}

			const auto index = startIndex++ ;	// 親だけがfixtureを割り当てます。
			// 各fixtureは全joinより長く存続します。
			return std::thread( [&, index, worker = std::move( worker)] {
				fixtures[index].ownerThread = std::this_thread::get_id() ;
				FixtureScope scope( fixtures[index]) ;
				worker() ;
				returned[index] = true ;
			}) ;
		} ;
		LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 通常factory未使用。
		executorPointer = &executor ;
		CollectorRecoveryReadiness legacyReadiness ;	// 新経路追加後も旧照会を拒否します。
		DRIVERCRATE_EXPECT( context, recovery.readiness( HTTP_TEST_UTC, 0U, legacyReadiness) ==
										ERROR_INVALID_PARAMETER) ;
		DRIVERCRATE_EXPECT( context, executor.result( 0U) == nullptr) ;
		const auto startError = executor.startNext( recovery) ;	// 実予約→実thread。
		DRIVERCRATE_EXPECT( context, startError == (mode == 4U	 ? static_cast<DWORD>( E_OUTOFMEMORY)
												   : mode == 12U ? ERROR_ACCESS_DENIED
																 : 0U)) ;
		// 独立二groupを起動し、保存前の再利用を拒否します。
		if( mode == 0U || asusCase) {
			DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == 0U) ;
			DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == ERROR_RETRY) ;
		}

		DRIVERCRATE_EXPECT( context, executor.result( 0U) == nullptr) ;
		const auto		  report   = executor.join() ;					// 親は全join後だけ結果を読みます。
		const std::size_t expected = mode == 0U || asusCase ? 2U : 1U ;	// 元共有jobで計数。
		// 実threadが存在しない二つの起動失敗。
		const bool		  startFailed = mode == 4U || mode == 12U ;
		DRIVERCRATE_EXPECT( context, report.reserved == expected && report.notified == expected &&
										report.started == (startFailed ? 0U : expected) &&
										report.joined == report.started &&
										recovery.terminalJobs() == 0U &&
										executor.result( expected) == nullptr) ;
		DRIVERCRATE_EXPECT( context, executor.join().notified == report.notified &&
										executor.startNext( recovery) != 0U) ;
		// 全slotの元bindingとsealed観測を照合します。
		for( std::size_t index = 0U; index < expected; ++index) {
			const auto *value = executor.result( index) ;	// 完了後の不変所有値。
			DRIVERCRATE_EXPECT( context, value != nullptr) ;
			// 欠損結果を参照せず試験失敗を保持します。
			if( !value) {
				continue ;
			}

			const auto &io = value->io ;	// 元workerの確定観測。
			// 同じ元scopeの正常1／2／16／0件・部分・上限とIntel失敗だけを保持します。
			if( (index == 1U && (mode == 0U || (mode >= 19U && mode <= 23U))) ||
			   (index == 0U && (mode == 0U || mode == 2U || mode == 10U || mode == 14U))) {
				historyWorkers.emplace( index == 0U ? 100U + mode : mode, *value) ;
			}

			// 失敗を含む元結果を非保存応答へ渡します。全体CLOCK／未回収は受入対象外です。
			if( io.finishedUtcMillis && io.elapsedMillis && io.nativeReleased &&
			   io.cause != CollectorIoCause::CLOCK) {
				runCollectorProjectedResponseChecks( context, activePrepared->job( index)->value(),
													*value) ;
			}

			// 全join後の元結果だけを非保存codecの往復へ渡します。
			if( value->reason == CollectorProjectedWorkerReason::NONE) {
				runCollectorMetadataCodecChecks( context, activePrepared->job( index)->value(),
												*value) ;
			}

			const auto label =
				"projected worker mode=" + std::to_string( mode) +
				" cause=" + std::to_string( static_cast<unsigned>( io.cause)) + " parser=" +
				std::to_string( value->parser ? static_cast<unsigned>( value->parser->status) : 99U) +
				" error=" + std::to_string( report.error) ;	// 非秘密診断。
			DRIVERCRATE_EXPECT(
				context,
				value->binding.generationKey == activePrepared->generationKey() &&
					value->binding.jobKey == activePrepared->job( index)->value().jobKey &&
					value->binding.scopeSha256 == activePrepared->job( index)->value().scopeSha256 &&
					io.sealed && fixtures[index].valid &&
					(startFailed || (mta[index] && returned[index]))) ;
			const bool sent = !startFailed && mode != 3U && mode != 11U ;	// Preflightは送信0。
			DRIVERCRATE_EXPECT( context, io.sends == (sent ? 1U : 0U) &&
											fixtures[index].calls["send"] == io.sends) ;
			// Native所有解放は結果通知より先です。
			if( sent) {
				DRIVERCRATE_EXPECT( context,
								   fixtures[index].closed == std::vector<int>( {3, 2, 1}) &&
									   fixtures[index].dnsRelease == std::vector<int>( {1, 2}) &&
									   finalClock[index]) ;
			}

			// 二sourceの正常本文→本番parser→全edgeを確認します。
			if( mode == 0U || mode == 14U || (asusCase && index == 0U)) {
				context.expect( report.error == 0U && io.cause == CollectorIoCause::COMPLETE &&
								   io.nativeReleased && value->parser &&
								   value->parser->status == CollectorParserStatus::COMPLETED &&
								   value->reason == CollectorProjectedWorkerReason::NONE &&
								   value->projection.records.size() == 1U &&
								   value->projection.edges.size() == (index == 0U ? 26U : 1U) &&
								   value->projection.bodySha256 == value->http.bodySha256,
							   label, __FILE__, __LINE__) ;
				// 書き換えた本文のraw hashだけを新edgeへ結合し、別対象の一致へ流用しません。
				if( mode == 14U && index == 0U && value->projection.records.size() == 1U) {
					std::wstring changedHash ;	// GETした実fixture byteから独立計算。
					std::wstring originalHash ;	// 改変前と異なることを確認する対照。
					DRIVERCRATE_EXPECT(
						context, computeBytesSha256( fixtures[index].body, changedHash) == 0U &&
									 computeBytesSha256(
										 winrt::to_string( winrt::hstring( projectedIntelHtml())),
										 originalHash) == 0U) ;
					DRIVERCRATE_EXPECT( context, value->http.bodySha256 == changedHash &&
													value->projection.bodySha256 == changedHash &&
													changedHash != originalHash &&
													value->projection.edges.size() == 26U) ;
					// 全26行は同一recordを参照するが、未掲載25件を非対応と断定しません。
					for( std::size_t target = 0U; target < value->projection.edges.size();
						++target) {
						const auto &edge =
							value->projection.edges[target] ;	// 元manifest順の一対象。
						DRIVERCRATE_EXPECT(
							context,
							edge.target.target.id == L"intel" + std::to_wstring( target) &&
								edge.bodySha256 == changedHash &&
								edge.recordFingerprints.size() == 1U &&
								edge.recordFingerprints[0].bytes ==
									value->projection.records[0].value.stableFingerprint.bytes &&
								edge.state == (target == 0U
												   ? CollectorProjectedTargetState::MATCH
												   : CollectorProjectedTargetState::UNKNOWN)) ;
					}
				}

				const auto ended = io.finishedUtcMillis ;	// Seal後の取消しは元成功を変更しません。
				executor.requestStop() ;
				DRIVERCRATE_EXPECT( context, value->io.cause == CollectorIoCause::COMPLETE &&
												value->io.finishedUtcMillis == ended &&
												value->projection.records.size() == 1U) ;
			}
			// 同一ASUS pageの候補数と部分拒否を、GET→workerの所有結果で確認します。
			else if( asusCase && index == 1U) {
				const auto &draft = value->projection ;	// Join後の秘密本文を含まない結果。
				// 17行は明示LIMITで全公開配列を破棄し、16行以下と区別します。
				if( mode == 21U) {
					context.expect(
						report.error == 0U && io.cause == CollectorIoCause::PARSER &&
							value->parser &&
							value->parser->status == CollectorParserStatus::LIMIT_EXCEEDED &&
							value->reason == CollectorProjectedWorkerReason::PROJECTION_LIMIT &&
							draft.status == CollectorProjectionDraftStatus::HELD &&
							draft.records.empty() && draft.edges.empty() && draft.slices.empty(),
						label, __FILE__, __LINE__) ;
					continue ;
				}

				// 同じ二recordを三対象が共有し、用途矛盾をUNKNOWNへ潰しません。
				if( mode == 24U) {
					context.expect( report.error == 0U && io.cause == CollectorIoCause::COMPLETE &&
									   io.nativeReleased && value->parser &&
									   value->parser->status == CollectorParserStatus::COMPLETED &&
									   draft.status == CollectorProjectionDraftStatus::FETCHED &&
									   draft.complete && draft.sourceSeen == 2U &&
									   draft.records.size() == 2U && draft.edges.size() == 3U &&
									   draft.bodySha256 == value->http.bodySha256,
								   label, __FILE__, __LINE__) ;
					const std::array states{
						CollectorProjectedTargetState::MATCH,
						CollectorProjectedTargetState::UNKNOWN,
						CollectorProjectedTargetState::NO_MATCH} ;	// 元manifest順。
					const std::array<std::wstring_view, 3U> ids{L"board", L"board-unknown",
																L"board-conflict"} ;	// 公開対象ID。
					// 欠損配列を成功値として参照しません。
					if( draft.records.size() == 2U && draft.edges.size() == 3U) {
						// 全対象は同じ二recordを参照し、状態・順序は個別に保持します。
						for( std::size_t target = 0U; target < ids.size(); ++target) {
							const auto &edge = draft.edges[target] ;	// 一対象・一sliceの所有結果。
							DRIVERCRATE_EXPECT( context, edge.target.target.id == ids[target] &&
															edge.state == states[target] &&
															edge.bodySha256 == draft.bodySha256 &&
															edge.recordFingerprints.size() == 2U) ;
							// 二recordのfingerprintを取り違えずに保持します。
							if( edge.recordFingerprints.size() == 2U) {
								DRIVERCRATE_EXPECT(
									context,
									edge.recordFingerprints[0U].bytes ==
											draft.records[0U].value.stableFingerprint.bytes &&
										edge.recordFingerprints[1U].bytes ==
											draft.records[1U].value.stableFingerprint.bytes) ;
							}
						}
					}

					continue ;
				}

				const std::size_t records = mode == 20U	  ? 16U
											: mode == 23U ? 0U
											: mode == 22U ? 1U
														  : 2U ;	// 元採用行数。
				context.expect(
					report.error == 0U && io.cause == CollectorIoCause::COMPLETE &&
						io.nativeReleased && value->parser &&
						value->parser->status == CollectorParserStatus::COMPLETED &&
						value->reason == CollectorProjectedWorkerReason::NONE &&
						draft.records.size() == records && draft.edges.size() == 1U &&
						draft.slices.size() == 1U && draft.bodySha256 == value->http.bodySha256 &&
						draft.sourceSeen == (mode == 23U   ? 0U
											 : mode == 20U ? 16U
														   : 2U) &&
						draft.complete == (mode == 19U || mode == 20U) &&
						draft.sourceStatus == static_cast<std::uint32_t>(
												  mode == 23U ? AsusCollectorSliceStatus::EMPTY
												  : mode == 22U
													  ? AsusCollectorSliceStatus::PARTIAL_REJECTED
													  : AsusCollectorSliceStatus::ACCEPTED) &&
						draft.status == (mode == 23U ? CollectorProjectionDraftStatus::HELD
													 : CollectorProjectionDraftStatus::FETCHED),
					label, __FILE__, __LINE__) ;
				// 状態を参照する前に一対象が保持されたことを確認します。
				if( draft.edges.size() != 1U) {
					continue ;
				}

				const auto &edge = draft.edges.front() ;	// 元board一対象の同一page参照。
				DRIVERCRATE_EXPECT(
					context,
					edge.target.target.id == L"board" && edge.bodySha256 == draft.bodySha256 &&
						edge.state == (mode == 23U ? CollectorProjectedTargetState::UNKNOWN
												   : CollectorProjectedTargetState::MATCH) &&
						edge.recordFingerprints.size() == records) ;
				// 二候補以上は同じedgeへ独立したfingerprintを重複なしで残します。
				for( std::size_t record = 0U; record < records && record < draft.records.size() &&
											 record < edge.recordFingerprints.size();
					++record) {
					DRIVERCRATE_EXPECT( context,
									   draft.records[record].payloads.size() == 1U &&
										   draft.records[record].payloads[0].payloadLinkValidated &&
										   edge.recordFingerprints[record].bytes ==
											   draft.records[record].value.stableFingerprint.bytes) ;
					// 同一指紋の二度付けを認めません。
					for( std::size_t prior = 0U; prior < record; ++prior) {
						DRIVERCRATE_EXPECT( context, edge.recordFingerprints[prior].bytes !=
														edge.recordFingerprints[record].bytes) ;
					}
				}
			}
			// 公式一覧も配布も欠ける本文は構造破損と断定せず、全対象UNKNOWNで保留します。
			else if( mode == 10U) {
				context.expect( io.cause == CollectorIoCause::COMPLETE && value->parser &&
								   value->parser->status == CollectorParserStatus::COMPLETED &&
								   value->projection.status ==
									   CollectorProjectionDraftStatus::HELD &&
								   value->reason == CollectorProjectedWorkerReason::NONE &&
								   value->projection.records.empty() &&
								   value->projection.edges.size() == 26U &&
								   value->projection.slices.size() == 1U && report.error == 0U,
							   label, __FILE__, __LINE__) ;
				// 欠測を明示不適合や架空一致へ変更しません。
				for( const auto &edge : value->projection.edges) {
					DRIVERCRATE_EXPECT( context,
									   edge.state == CollectorProjectedTargetState::UNKNOWN &&
										   edge.recordFingerprints.empty()) ;
				}
			}
			// 配布URL改変は公開候補・共有edgeへの昇格を拒否します。
			else if( (mode >= 15U && mode <= 18U) || mode >= 25U) {
				// 下位が候補を落とす場合も、URL gateが拒否する場合も公開候補は0です。
				context.expect(
					io.nativeReleased && io.sends == 1U && report.error == 0U &&
						value->projection.records.empty() &&
						(value->projection.status == CollectorProjectionDraftStatus::HELD ||
						 value->projection.status ==
							 CollectorProjectionDraftStatus::MINIMAL_FAILURE),
					label, __FILE__, __LINE__) ;
				// HELDなら全対象がUNKNOWN、拒否なら公開edgeは一件も残しません。
				if( value->projection.status == CollectorProjectionDraftStatus::HELD) {
					DRIVERCRATE_EXPECT( context, value->projection.edges.size() == 26U) ;
					// 未確定edge全件に指紋を付け足しません。
					for( const auto &edge : value->projection.edges) {
						DRIVERCRATE_EXPECT( context,
										   edge.state == CollectorProjectedTargetState::UNKNOWN &&
											   edge.recordFingerprints.empty()) ;
					}
				} else {
					DRIVERCRATE_EXPECT( context, value->projection.edges.empty()) ;
				}
			} else {
				DRIVERCRATE_EXPECT( context, value->projection.records.empty() &&
												value->projection.edges.empty() &&
												value->projection.slices.empty()) ;
				// 明示上限だけHELDとしOOMは最小失敗です。
				if( mode == 9U) {
					context.expect(
						value->parser &&
							value->parser->status == CollectorParserStatus::LIMIT_EXCEEDED &&
							value->reason == CollectorProjectedWorkerReason::PROJECTION_LIMIT &&
							value->projection.status == CollectorProjectionDraftStatus::HELD &&
							io.cause == CollectorIoCause::PARSER && report.error == 0U,
						label, __FILE__, __LINE__) ;
				} else {
					DRIVERCRATE_EXPECT(
						context, value->projection.status ==
										 CollectorProjectionDraftStatus::MINIMAL_FAILURE &&
									 value->reason == CollectorProjectedWorkerReason::IO_FAILURE) ;
				}

				// PARSE／PROJECT拒否をSETUPへ書き換えません。
				if( mode == 1U) {
					context.expect( io.cause == CollectorIoCause::PARSER && value->parser &&
									   value->parser->status == CollectorParserStatus::REJECTED &&
									   report.error == 0U &&
									   io.error.stage == value->parser->error.stage,
								   label, __FILE__, __LINE__) ;
				}

				// HTTP原値と未知全量を保持します。
				if( mode == 2U) {
					context.expect( io.cause == CollectorIoCause::HTTP && io.native &&
									   io.native->code == fixtures[index].error && !io.bytesKnown &&
									   !value->parser,
								   label, __FILE__, __LINE__) ;
				}

				// COM解放後の先着停止も完成配列を破棄します。
				if( mode >= 5U && mode <= 8U) {
					// 当caseで先着させる元原因。
					const auto cause = mode == 6U	? CollectorIoCause::DEADLINE
									   : mode == 7U ? CollectorIoCause::CLOCK
													: CollectorIoCause::CANCELLED ;
					context.expect( io.cause == cause &&
									   (mode == 7U ? !io.finishedUtcMillis &&
														 report.error == ERROR_INVALID_DATA
												   : io.finishedUtcMillis.has_value()),
								   label, __FILE__, __LINE__) ;
					// 親取消しを受けた二条件は全join後も停止signalを保持します。
					if( mode == 5U || mode == 8U) {
						DRIVERCRATE_EXPECT( context, report.cancellationRequested &&
														io.nativeReleased &&
														fixtures[index].closed.size() == 3U) ;
					}

					// 完成後と途中でparser観測を区別します。
					if( mode == 5U || mode == 6U || mode == 8U) {
						context.expect( value->parser &&
										   value->parser->status ==
											   (mode == 8U ? CollectorParserStatus::STOPPED
														   : CollectorParserStatus::COMPLETED),
									   label, __FILE__, __LINE__) ;
					}
				}

				// 起動・client allocationの原値を保持します。
				if( mode == 3U || startFailed || mode == 11U) {
					// 注入した原数値を再計算して照合します。
					const auto code = mode == 12U	? ERROR_ACCESS_DENIED
									  : mode == 11U ? static_cast<DWORD>( E_POINTER)
													: static_cast<DWORD>( E_OUTOFMEMORY) ;
					context.expect( io.cause == CollectorIoCause::SETUP && io.error.code == code &&
									   report.error == code && !value->parser &&
									   io.lowerBytes == 0U,
								   label, __FILE__, __LINE__) ;
				}

				// Native close失敗を解放成功へ偽装しません。
				if( mode == 13U) {
					context.expect( !io.nativeReleased && report.error != 0U && io.native &&
									   io.native->code == fixtures[index].error,
								   label, __FILE__, __LINE__) ;
				}
			}
		}
	}

	runCollectorProjectedHistoryChecks( context, definition, prepared, historyWorkers) ;
}

/** @brief 一GETの16候補を300対象へ射影し、301対象は受付前に拒否します。
 * @param[in,out] context 親threadの試験集計。
 * @param[in] rootFactory 条件ごとの独立保護store。
 * @param[in] original 元の二sourceを含む公開定義。
 */
void projectedLargeAsusWorkerChecks( TestContext									 &context,
									const std::function<std::filesystem::path()> &rootFactory,
									const CollectorProjectedCampaignDefinition	 &original)
{
	auto definition = original ;	// 組み込みsource registryとartifactは変更しない。
	auto manifest =
		// 元公開manifest。
		JsonObject::Parse( winrt::to_hstring( definition.manifestBytes)) ;
	JsonArray targets ;		// 5 makerそれぞれ60件でmaker別64件上限を避ける。
	JsonArray references ;	// 同じASUS公式GETが全300対象を参照する。
	// 先頭一件だけ公式製品に一致し、残りは明示製品差とする。
	for( std::size_t index = 0U; index < 300U; ++index) {
		const auto id = L"board" + std::to_wstring( index) ;	// 元順序の公開ID。
		JsonObject target ;										// 端末inventoryや正答URLを含めない。
		target.Insert( L"id", JsonValue::CreateStringValue( id)) ;
		target.Insert( L"maker",
					  JsonValue::CreateStringValue(
						  index < 60U ? L"ASUS" : L"Maker " + std::to_wstring( index / 60U))) ;
		target.Insert( L"model", JsonValue::CreateStringValue(
									index == 0U ? L"ProArt X870E-CREATOR WIFI"
												: L"Fictional Board " + std::to_wstring( index))) ;
		target.Insert( L"kind", JsonValue::CreateStringValue( L"MAINBOARD")) ;
		target.Insert( L"purpose", JsonValue::CreateStringValue( L"LAN")) ;
		targets.Append( target) ;
		references.Append( JsonValue::CreateStringValue( id)) ;
	}

	JsonArray jobs ;														// 元ASUS jobの公式locatorと契約を再利用する。
	auto	  asusJob = manifest.GetNamedArray( L"jobs").GetObjectAt( 1U) ;	// 既存ASUS job。
	asusJob.Insert( L"targets", references) ;
	jobs.Append( asusJob) ;
	manifest.Insert( L"targets", targets) ;
	manifest.Insert( L"jobs", jobs) ;
	definition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	CollectorProjectedCampaignIdentity identity ;	// 同じ保存v3入力を再準備する。
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
						   identity.jobs.size() == 1U && identity.jobs[0].targets.size() == 300U) ;
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		prepared ;	// 全対象を所有する不変入力。
	DRIVERCRATE_EXPECT( context,
					   prepareCollectorProjectedCampaign(
						   identity.canonicalInput, identity.inputSha256, identity.generationKey,
						   definition.artifactSha256, definition.sources, prepared) &&
						   prepared && prepared->jobCount() == 1U &&
						   prepared->job( 0U)->value().targets.size() == 300U) ;
	// 未準備で専用workerの結果を合成しません。
	if( !prepared || prepared->jobCount() != 1U) {
		return ;
	}

	IoFixture fixture ;	// 一GETのfake DNS／native HTTP状態。
	fixture.body = winrt::to_string( winrt::hstring( projectedAsusRowsHtml( 16U))) ;
	// 301件目は元makerの61件目にして、全体上限だけへ到達する。
	JsonObject extra ;
	extra.Insert( L"id", JsonValue::CreateStringValue( L"board300")) ;
	extra.Insert( L"maker", JsonValue::CreateStringValue( L"ASUS")) ;
	extra.Insert( L"model", JsonValue::CreateStringValue( L"Fictional Board 300")) ;
	extra.Insert( L"kind", JsonValue::CreateStringValue( L"MAINBOARD")) ;
	extra.Insert( L"purpose", JsonValue::CreateStringValue( L"LAN")) ;
	targets.Append( extra) ;
	references.Append( JsonValue::CreateStringValue( L"board300")) ;
	auto invalid		  = definition ;	// 成功300件の元manifest byteは維持する。
	invalid.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	CollectorProjectedCampaignIdentity rejected ;	// 予約前の入力拒否。
	DRIVERCRATE_EXPECT( context,
					   !makeCollectorProjectedCampaignIdentity( invalid, L"20260927", rejected) &&
						   rejected.canonicalInput.empty() && rejected.jobs.empty()) ;
	LocalCollectorStateStore rejectedStore ;	// 不正入力専用の保護store。
	DRIVERCRATE_EXPECT( context, rejectedStore.initialize( rootFactory(), true) == 0U) ;
	LocalCollectorRecovery rejectedRecovery ;	// 実受付も不正定義を拒否する。
	DRIVERCRATE_EXPECT( context, rejectedRecovery.initializeProjected( rejectedStore, invalid,
																	 HTTP_TEST_UTC, 0U) != 0U &&
									fixture.calls.empty()) ;

	LocalCollectorStateStore store ;	// 成功300件だけ独立の保護storeへ予約する。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
	LocalCollectorRecovery recovery ;	// 正常300件の予約監督。
	DRIVERCRATE_EXPECT( context,
					   recovery.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
	std::size_t							   hashCalls{} ;	// 成功値は差し替えず実CNGの直前だけ数える。
	bool								   returned{} ;		// 実worker callbackがjoin前に終了した印。
	CollectorProjectedExecutorDependencies dependencies ;	// 実workerへ渡す明示fake依存。
	dependencies.campaign	  = prepared ;
	dependencies.clock		  = [&] { return fixture.clock ; } ;
	dependencies.createClient = [&] {
		return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
	} ;
	dependencies.start = [&]( std::function<void()> worker) {
		return std::thread( [&, worker = std::move( worker)] {
			fixture.ownerThread = std::this_thread::get_id() ;
			FixtureScope scope( fixture) ;
			worker() ;
			returned = true ;
		}) ;
	} ;
	dependencies.diagnostics.beforeRecordHash = [&]( const std::size_t jobIndex,
													const std::size_t ordinal) -> std::int32_t {
		fixture.valid = fixture.valid && jobIndex == 0U && ordinal == hashCalls ;
		++hashCalls ;
		// 成功digestは実CNGだけが計算する。
		return 0 ;
	} ;
	LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 一jobの所有監督。
	DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == 0U) ;
	DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == ERROR_RETRY) ;
	const auto	report = executor.join() ;		// 秘密本文・native handle破棄後に結果を読む。
	const auto *value  = executor.result( 0U) ;	// Join後だけの公開結果。
	context.expect(
		report.error == 0U && report.reserved == 1U && report.started == 1U &&
			report.joined == 1U && report.notified == 1U && returned && fixture.valid &&
			fixture.calls["send"] == 1U && fixture.closed == std::vector<int>( {3, 2, 1}) &&
			fixture.dnsRelease == std::vector<int>( {1, 2}) && hashCalls == 16U &&
			recovery.terminalJobs() == 0U && value && value->parser && value->io.sealed &&
			value->io.nativeReleased && value->io.sends == 1U &&
			value->io.cause == CollectorIoCause::COMPLETE &&
			value->parser->status == CollectorParserStatus::COMPLETED &&
			value->reason == CollectorProjectedWorkerReason::NONE &&
			value->projection.status == CollectorProjectionDraftStatus::FETCHED &&
			value->projection.complete && value->projection.sourceSeen == 16U &&
			value->projection.records.size() == 16U && value->projection.edges.size() == 300U &&
			value->projection.slices.size() == 1U &&
			value->projection.bodySha256 == value->http.bodySha256,
		"300 targets and 16 records through one ASUS GET", __FILE__, __LINE__) ;
	// 同一GETの大集合は件数とbyte上限を別に検査します。
	if( value && value->reason == CollectorProjectedWorkerReason::NONE) {
		runCollectorMetadataCodecChecks( context, prepared->job( 0U)->value(), *value) ;
		runCollectorProjectedResponseChecks( context, prepared->job( 0U)->value(), *value) ;
	}

	// 失敗した配列を範囲外参照して成功数へ変えません。
	if( !value || value->projection.records.size() != 16U ||
	   value->projection.edges.size() != 300U) {
		return ;
	}

	// 一致一件・明示製品差299件の各edgeに16参照と元順序を保持する。
	for( std::size_t target = 0U; target < 300U; ++target) {
		const auto &edge = value->projection.edges[target] ;	// 元manifestの同位置。
		DRIVERCRATE_EXPECT(
			context, edge.target.index == target &&
						 edge.target.target.id == L"board" + std::to_wstring( target) &&
						 edge.state == (target == 0U ? CollectorProjectedTargetState::MATCH
													 : CollectorProjectedTargetState::NO_MATCH) &&
						 edge.sliceKey == value->projection.slices.front().key &&
						 edge.bodySha256 == value->projection.bodySha256 &&
						 edge.recordFingerprints.size() == 16U) ;
		// 候補元順のfingerprintを各対象で独立に参照し、先頭だけへ縮退させない。
		for( std::size_t record = 0U; record < 16U && record < edge.recordFingerprints.size();
			++record) {
			DRIVERCRATE_EXPECT( context,
							   edge.recordFingerprints[record].bytes ==
								   value->projection.records[record].value.stableFingerprint.bytes) ;
		}
	}
}

/** @brief 数値診断位置で停止・OOM・CNG失敗を実workerへ一回ずつ注入します。
 * @param[in,out] context 親threadだけが更新する集計。
 * @param[in] rootFactory 各条件の独立保護store。
 * @param[in] original 二sourceの元公開定義。
 */
void projectedFaultChecks( TestContext								   &context,
						  const std::function<std::filesystem::path()> &rootFactory,
						  const CollectorProjectedCampaignDefinition   &original)
{
	// 対象source以外への取消し競合を混ぜず、各条件を一jobで固定します。
	for( std::size_t source = 0U; source < 2U; ++source) {
		// 同じregistry・artifactで独立世代を作る。
		auto definition = original ;
		auto manifest = JsonObject::Parse( winrt::to_hstring( definition.manifestBytes)) ;	// 元byte。
		JsonArray jobs ;																	// 元対象集合を維持した一共有GET。
		jobs.Append( manifest.GetNamedArray( L"jobs").GetAt( static_cast<std::uint32_t>( source))) ;
		manifest.Insert( L"jobs", jobs) ;
		definition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		CollectorProjectedCampaignIdentity identity ;	// 元canonicalから再準備する専用G。
		DRIVERCRATE_EXPECT(
			context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity)) ;
		std::shared_ptr<const CollectorPreparedProjectedCampaign> prepared ;	// 不変入力。
		DRIVERCRATE_EXPECT( context, prepareCollectorProjectedCampaign(
										identity.canonicalInput, identity.inputSha256,
										identity.generationKey, definition.artifactSha256,
										definition.sources, prepared) &&
										prepared && prepared->jobCount() == 1U) ;
		// 未準備条件は元の二source入力へ戻さず失敗として保持します。
		if( !prepared || prepared->jobCount() != 1U) {
			continue ;
		}

		// 正常観測、adapter OOM二型、途中停止四型、hash失敗三型を分けます。
		for( unsigned mode = 0U; mode < 10U; ++mode) {
			IoFixture fixture ;	// 一workerだけが更新し、親はjoin後に読む。
			fixture.body = winrt::to_string(
				winrt::hstring( source == 0U ? projectedIntelHtml() : projectedAsusRowsHtml( 2U))) ;
			std::size_t				 adapterCalls{} ;	// 候補化完了の通知数。
			std::size_t				 recordCalls{} ;	// Record開始の通知数。
			std::size_t				 targetCalls{} ;	// Target開始の通知数。
			std::size_t				 hashCalls{} ;		// CNG直前通知。再試行を含めて計数する。
			bool					 injected{} ;		// 指定位置を実際に通過した証拠。
			bool					 returned{} ;		// 実callbackの有限復帰。
			bool					 lateCancel{} ;		// Parser失敗登録後の時計で取消しを発生させる。
			LocalCollectorStateStore store ;			// 一条件の元予約を所有する。
			DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
			LocalCollectorRecovery recovery ;	// 保存済み専用Gを読み込む。
			DRIVERCRATE_EXPECT(
				context, recovery.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
			LocalCollectorProjectedExecutor		  *executorPointer{} ;	// 全joinまで存続する借用先。
			CollectorProjectedExecutorDependencies dependencies ;		// 通常HTTPへの補完なし。
			dependencies.campaign = prepared ;
			dependencies.clock	  = [&] {
				   // 親threadからはworker専用の可変状態を読みません。
				   if( activeFixture == nullptr) {
					   return CollectorHttpClockSample{HTTP_TEST_UTC, 0U} ;
				   }

				   // 原hash失敗の登録後にだけ後発取消しを観測させます。
				   if( lateCancel) {
					   lateCancel = false ;
					   executorPointer->requestStop() ;
				   }

				   return fixture.clock ;
			} ;
			dependencies.createClient = [&] {
				return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
			} ;
			dependencies.start = [&]( std::function<void()> worker) {
				return std::thread( [&, worker = std::move( worker)] {
					fixture.ownerThread = std::this_thread::get_id() ;
					FixtureScope scope( fixture) ;	// Native fakeのthread限定所有。
					worker() ;
					returned = true ;
				}) ;
			} ;
			dependencies.diagnostics.checkpoint = [&]( const std::size_t				 jobIndex,
													  const CollectorProjectionPoint point,
													  const std::size_t				 ordinal) {
				fixture.valid = fixture.valid && jobIndex == 0U ;
				// 各位置の到達数で注入前の部分処理を確認します。
				if( point == CollectorProjectionPoint::ADAPTER_COMPLETE) {
					++adapterCalls ;
				}
				// 候補ごとの到達数を対象ごとの到達数と分けます。
				else if( point == CollectorProjectionPoint::RECORD) {
					++recordCalls ;
				} else {
					++targetCalls ;
				}

				const bool adapterFault = (mode == 1U || mode == 2U) &&
										  // 候補化後のOOM。
										  point == CollectorProjectionPoint::ADAPTER_COMPLETE ;
				const bool partialFault =
					mode >= 3U && mode <= 6U &&
					point == (source == 0U ? CollectorProjectionPoint::TARGET
										   : CollectorProjectionPoint::RECORD) &&
					// 部分配列が既にある位置。
					ordinal == (source == 0U ? 13U : 1U) ;
				// 指定外の位置には故障を追加しません。
				if( !adapterFault && !partialFault) {
					return ;
				}

				injected = true ;
				// 停止signalは同じ元controlの次checkpointで確定します。
				if( mode == 3U) {
					executorPointer->requestStop() ;
				}
				// 元二時計だけを期限まで進め、実待機は行いません。
				else if( mode == 4U) {
					fixture.clock = {HTTP_TEST_UTC + 120000U, 120000U} ;
				}
				// WinRT由来のOOMとC++ allocation失敗の両経路を区別します。
				else if( mode == 2U || mode == 6U) {
					throw winrt::hresult_error( E_OUTOFMEMORY) ;
				} else {
					throw std::bad_alloc{} ;
				}
			} ;
			dependencies.diagnostics.beforeRecordHash =
				[&]( const std::size_t jobIndex, const std::size_t ordinal) -> std::int32_t {
				fixture.valid = fixture.valid && jobIndex == 0U ;
				++hashCalls ;
				// ASUSは二件目まで進めてから失敗させ、先行recordも破棄させます。
				if( mode >= 7U && ordinal == source) {
					injected   = true ;
					lateCancel = mode == 9U ;
					// Hash境界のallocation例外もLIMITに読み替えません。
					if( mode == 8U) {
						throw std::bad_alloc{} ;
					}

					return static_cast<std::int32_t>( 0xc0000022U) ;
				}

				return 0 ;
			} ;
			LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 一回起動。
			executorPointer = &executor ;
			DRIVERCRATE_EXPECT( context, executor.startNext( recovery) == 0U) ;
			const auto	report = executor.join() ;		// 秘密資源破棄・sealの後にだけ観測する。
			const auto *value  = executor.result( 0U) ;	// 通知済み所有結果。
			const auto	label  = "projection fault source=" + std::to_string( source) +
							   " mode=" + std::to_string( mode) ;	// 固定数値だけの診断。
			context.expect( report.error == 0U && report.reserved == 1U && report.started == 1U &&
							   report.joined == 1U && report.notified == 1U && returned &&
							   fixture.valid && value && value->parser && value->io.sealed &&
							   value->io.nativeReleased && value->io.sends == 1U &&
							   fixture.calls["send"] == 1U &&
							   fixture.closed == std::vector<int>( {3, 2, 1}) &&
							   fixture.dnsRelease == std::vector<int>( {1, 2}),
						   label, __FILE__, __LINE__) ;
			// 欠損を成功値の参照に進めません。
			if( !value || !value->parser) {
				continue ;
			}

			// 通知だけを加えた正常経路も実CNGと全対象処理を通ります。
			runCollectorProjectedResponseChecks( context, prepared->job( 0U)->value(), *value) ;
			// 通知だけの正常経路と注入した原失敗を区別します。
			if( mode == 0U) {
				DRIVERCRATE_EXPECT( context, !injected && adapterCalls == 1U &&
												recordCalls == source + 1U &&
												hashCalls == source + 1U &&
												targetCalls == (source == 0U ? 26U : 1U) &&
												value->io.cause == CollectorIoCause::COMPLETE &&
												value->projection.records.size() == source + 1U &&
												value->projection.edges.size() == targetCalls) ;
				// 現parser revisionの通常record指紋と一致する場合だけprobeを成功扱いにします。
				if( source == 0U && value->projection.records.size() == 1U) {
					DRIVERCRATE_EXPECT(
						context,
						projectedFingerprintHex(
							value->projection.records[0].value.stableFingerprint) ==
							"7311bb9fa363bd94ae3ac18dce8077724c3ea7376e45f508e6daaa3b28860073") ;
					// 限定再確認でも実workerから作った同じmetadataをcodec正負へ渡します。
					runCollectorMetadataCodecChecks( context, prepared->job( 0U)->value(), *value) ;
				}

				continue ;
			}

			const bool stopped = mode == 3U || mode == 4U ;	// 外部停止と原API失敗を分離。
			// 同じ位置で注入した原原因を最終sealまで維持する期待値。
			const auto expectedCause = mode == 3U	? CollectorIoCause::CANCELLED
									   : mode == 4U ? CollectorIoCause::DEADLINE
													: CollectorIoCause::PARSER ;
			context.expect( injected && value->io.cause == expectedCause &&
							   value->parser->status == (stopped ? CollectorParserStatus::STOPPED
																 : CollectorParserStatus::FAILED) &&
							   value->io.error.stage == CollectorIoStage::PROJECT &&
							   value->reason == CollectorProjectedWorkerReason::IO_FAILURE &&
							   value->projection.status ==
								   CollectorProjectionDraftStatus::MINIMAL_FAILURE &&
							   value->projection.records.empty() &&
							   value->projection.edges.empty() && value->projection.slices.empty(),
						   label, __FILE__, __LINE__) ;
			// 途中故障の位置と前半処理を省略せず確認します。
			if( mode >= 3U && mode <= 6U) {
				DRIVERCRATE_EXPECT( context, hashCalls == 1U && (source == 0U ? targetCalls == 14U
																			 : recordCalls == 2U)) ;
			}

			// CNG再試行なしで元codeを維持します。
			if( !stopped) {
				const auto expectedCode =
					mode == 7U || mode == 9U
						? 0xd0000022U
						: static_cast<std::uint32_t>( E_OUTOFMEMORY) ;	// NTSTATUS→HRESULTの元値。
				DRIVERCRATE_EXPECT( context, value->io.error.code == expectedCode &&
												value->parser->error.code == expectedCode &&
												value->io.error.domain ==
													CollectorIoErrorDomain::HRESULT_ERROR &&
												hashCalls == (mode <= 2U   ? 0U
															  : mode >= 7U ? source + 1U
																		   : 1U)) ;
			}

			DRIVERCRATE_EXPECT( context, report.cancellationRequested == (mode == 3U || mode == 9U)) ;
		}
	}
}
/** @brief 架空新modelの本文を純粋parser・照合・指紋に通して合成応答へ結合します。
 * @param[in] job 本番identityで再計算した今回の公開要求。
 * @param[in,out] value 元初回の合成時計へ移動済みの所有応答。
 * @return 一record・一MATCHと全payload構文検査が成立した場合true。
 * @note HTTP証拠・grantを作らず、後続の非通信codec試験だけへ使用します。
 */
bool freshCapacityMetadata( const CollectorProjectedJobInput &job, CollectorProjectedResponse &value)
{
	auto body = winrt::to_string(
		// 元fake本文のUTF-8一行だけです。
		winrt::hstring( projectedAsusRowsHtml( 1U))) ;
	const auto position = body.find( "ProArt X870E-CREATOR WIFI") ;	// 元fakeの公開model位置です。
	// 別の本文構造を推測して試験の成功根拠にしません。
	if( position == body.npos || job.targets.size() != 1U || job.slices.size() != 1U ||
	   !value.metadata.binding.validatedUtc) {
		return false ;
	}

	body.replace( position, std::string_view( "ProArt X870E-CREATOR WIFI").size(),
				 winrt::to_string( job.publicLocator)) ;
	AsusSupportPageRequest	request ;										// 合成本文と同じ公開model・OSの要求です。
	AsusCollectorPageResult page ;											// 純粋公式parserの実結果です。
	std::vector<OfficialCollectorRecordCandidate> candidates ;				// URLはこのhelper内だけです。
	const auto validated = *value.metadata.binding.validatedUtc / 1000U ;	// 元合成の本文時計です。
	// 自己申告したrecordやMATCHでparser結果を補完しません。
	if( !makeAsusPublicModelSupportPageRequest( job.publicLocator, job.slices.front().operatingSystem,
											  request) ||
	   !parseAsusCollectorDriverPageHtml( winrt::to_hstring( body), request.model, request.osName,
										 job.slices.front().category, 128ULL * 1024ULL * 1024ULL,
										 page) ||
	   page.sliceStatus != AsusCollectorSliceStatus::ACCEPTED || page.entries.size() != 1U ||
	   !adaptAsusCollectorNetworkRecordCandidates( page, request, validated, candidates) ||
	   candidates.size() != 1U) {
		return false ;
	}

	const auto &scope = job.targets.front() ;	// 入力の対象fieldを省略しません。
	const std::array<AsusCollectorTargetQuery, 1U> queries{
		{{scope.target.id, scope.target.maker, scope.target.model, scope.target.kind,
		  scope.target.purpose, scope.operatingSystem, scope.architecture,
		  scope.chip}}} ;														// 純粋照合入力です。
	std::vector<AsusCollectorTargetAssessment> assessed ;						// 本文に基づく元三状態です。
	const auto &candidate = candidates.front() ;								// 同一合成本文からの一候補です。
	const auto *policy	  = officialSourcePolicyForProvider( job.providerId) ;	// 元組み込み契約です。
	// 同一本文のentry・URL・公開値を共通policyとsource規則へ結合します。
	if( !inspectAsusCollectorTargets( page, candidates, queries, assessed) || assessed.size() != 1U ||
	   assessed.front().state != AsusCollectorTargetState::MATCH ||
	   assessed.front().candidateOrdinals != std::vector<std::uint32_t>{0U} || policy == nullptr ||
	   policy->id != job.policyId || candidate.payloads.size() != 1U) {
		return false ;
	}

	const auto &payload = candidate.payloads.front() ;	// 検査する元一配布URLです。
	const auto *resource =
		// payload用途だけです。
		findOfficialSourceResource( *policy, payload.resourceId) ;
	const auto				 url   = payload.targetUrl.view() ;	// 外部へ保存しない借用値です。
	const auto				&entry = page.entries.front() ;		// sourceの元公開行です。
	const auto				 slash = url.find_last_of( L'/') ;	// 元basename境界です。
	CollectorProjectedRecord record ;							// 元canonicalから導出するURL非保持の一行です。
	// この既知fakeの限定構文を検査し、true観測だけを捏造しません。
	if( resource == nullptr || resource->kind != OfficialSourceResourceKind::PAYLOAD ||
	   validateOfficialHttpsUrl( url, resource->allowedHosts) != 0 ||
	   !url.starts_with( L"https://dlcdnets.asus.com/pub/ASUS/") || !url.ends_with( L".zip") ||
	   url.find_first_of( L"?#\\%") != url.npos || slash == url.npos || url != entry.downloadUrl ||
	   payload.fileDisplayName != url.substr( slash + 1U) || payload.payloadOrdinal != 0U ||
	   payload.kind != OfficialDistributionPayloadKind::STANDARD_INF_PACKAGE ||
	   payload.publishedSha256 != entry.sha256 ||
	   payload.maximumBytes != entry.maximumDownloadBytes ||
	   candidate.recordKey != job.publicLocator + L"|" + entry.opaqueId ||
	   candidate.driverCategory != entry.category || candidate.productFamily != entry.title ||
	   candidate.operatingSystem != job.slices.front().operatingSystem ||
	   projectOfficialCollectorRecord( candidate, job.policyId, job.source.resourceId, validated,
									  record.value) != 0 ||
	   computeBytesSha256( body, value.body) != 0U) {
		return false ;
	}

	record.sliceKey = job.slices.front().key ;
	record.payloads.push_back( {record.value.payloads.front(), true}) ;
	value.metadata.records = {std::move( record)} ;
	auto &edge		= value.metadata.edges.front() ;	// 元一MATCHの構造を今回の本番照合へ結合します。
	edge.target		= scope ;
	edge.bodySha256 = value.body ;
	edge.sourceProductId				= assessed.front().productId ;
	edge.sourceDisplayName				= assessed.front().displayModel ;
	edge.sourceComparisonName			= assessed.front().comparisonModel ;
	edge.reasonCode						= static_cast<std::uint32_t>( assessed.front().reason) ;
	edge.recordFingerprints				= {value.metadata.records.front().value.stableFingerprint} ;
	value.metadata.slices.front().scope = job.slices.front() ;
	value.metadata.binding.body			= value.body ;
	value.metadata.diagnostics.source->status = static_cast<std::uint32_t>( page.sliceStatus) ;
	value.metadata.diagnostics.source->seen	  = static_cast<std::uint32_t>( page.seen) ;
	// 元六分類のparser実観測を保持します。
	for( std::size_t index = 0U; index < 6U; ++index) {
		value.metadata.diagnostics.source->reasonCounts[index] =
			static_cast<std::uint32_t>( page.reasonCounts[index]) ;
	}

	value.bytes			= body.size() ;
	value.io.lowerBytes = body.size() ;
	return true ;
}

/** @brief 実初回四要求の保存形から合成299操作または大量新要求を作ります。
 * @param[in,out] context 親threadの検査集計。
 * @param[in,out] store 初回全四要求を完了し、監督借用を解放済みの試験専用store。
 * @param[in] definition 元の固定四要求・二source・artifact。
 * @param[in] firstCampaign 実初回の変更不能入力。
 * @param[in] freshRequests 別ASUS四要求ずつの段階容量を測る場合true。旧操作試験へ混入しません。
 * @param[in] startupBoundary 新要求の各完了世代境界と通常再起動を検査する場合true。
 * @param[in] startupObservation 起動境界modeの親時計。借用は本呼出し中だけ。不在時は観測しません。
 * @note 後続の応答と時計は合成です。実HTTPや300回の本番受領を示しません。
 */
void operationCapacityFixture(
	TestContext &context, LocalCollectorStateStore &store,
	const CollectorProjectedCampaignDefinition						&definition,
	const std::shared_ptr<const CollectorPreparedProjectedCampaign> &firstCampaign,
	const bool freshRequests = false, const bool startupBoundary = false,
	const CacheStartupObservation *startupObservation = nullptr)
{
	const CacheStartupObservation disabled( false) ;	// 他modeへ追加出力を持ち込みません。
	const auto					 &observation =
		  startupObservation ? *startupObservation : disabled ;		// 親時計の同期借用。
	const auto baseline = projectedStoreSnapshot( context, store) ;	// 初回全rawだけを所有します。
	// 新要求枠だけで任意診断の成功観測・失敗reset・非変更を先に検査します。
	if( freshRequests) {
		CollectorHistoryReadDiagnostics diagnostics ;	// 初回全完了の部分観測だけです。
		std::shared_ptr<const CollectorRegisteredProjectedHistory>
				   history ;	// 成功時だけの不変contextです。
		const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
			store, *firstCampaign->job( 0U), definition.sources, HTTP_TEST_UTC + 401000U, history,
			{}, &diagnostics) ;	// 同じ旧入口の全検査です。
		DRIVERCRATE_EXPECT( context, code == 0U && history && diagnostics.chargedBytes > 0U &&
										diagnostics.readCalls >= diagnostics.referencedNames &&
										diagnostics.recheckStarted &&
										diagnostics.capacity == CollectorHistoryCapacity::NONE) ;
		// 原拒否を正常初回として後続の合成履歴へ渡しません。
		if( code != 0U) {
			return ;
		}

		DRIVERCRATE_EXPECT( context,
						   LocalCollectorRecovery::inspectRegisteredProjectedHistory(
							   store, *firstCampaign->job( 0U), definition.sources, 0U, history, {},
							   &diagnostics) == ERROR_INVALID_DATA &&
							   !history && diagnostics.chargedBytes == 0U &&
							   diagnostics.attemptedBytes == 0U && diagnostics.readCalls == 0U &&
							   diagnostics.referencedNames == 0U && !diagnostics.recheckStarted &&
							   diagnostics.capacity == CollectorHistoryCapacity::NONE &&
							   baseline == projectedStoreSnapshot( context, store)) ;
	}

	// 元保存形の所有copyを作り、後続store更新から切り離します。
	const auto object = [&]( const std::wstring &name) {
		return JsonObject::Parse(
			JsonObject::Parse( winrt::to_hstring( baseline.at( name))).GetNamedString( L"body")) ;
	} ;
	// 保存する本文の実SHAを計算し、hash自己宣言で検査成功を捏造しません。
	const auto digest = [&]( const std::string_view body) {
		std::wstring result ;	// 一つの本文の実SHA-256。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( body, result) == 0U) ;
		return result ;
	} ;
	const auto firstKey = firstCampaign->generationKey() ;				// 実初回G。
	auto	   root		= object( L"current/campaign-root-v2.json") ;	// 元root identityと登録順。
	const auto stateTemplate =
		// 元全行。
		object( L"current/campaign-state-v3-" + firstKey + L".json") ;
	CollectorProjectedCampaignDefinition firstDefinition ;	// 開始codecの元定義。
	CollectorProjectedCampaignIdentity	 firstIdentity ;	// 実保存された元canonical。
	DRIVERCRATE_EXPECT(
		context,
		parseCollectorProjectedCampaignIdentity(
			winrt::to_string( object( L"runs/campaign-input-v3-" + firstKey + L".json").Stringify()),
			firstDefinition, firstIdentity)) ;
	std::array<CollectorProjectedResponseBytes, 4U> observations ;	// 実初回四要求の公開値だけです。
	std::array<CollectorRecoveryDispatch, 4U>		starts ;		// 元開始二時計・全source結合。
	std::array<CollectorProjectedCache, 4U>
		caches ;	// 各要求の直近CACHE、検査済み権限型ではありません。
	// 元四行の応答・intent・CACHEを本番codecから復号します。
	for( std::size_t index = 0U; index < 4U; ++index) {
		const auto row = stateTemplate.GetNamedArray( L"jobs").GetObjectAt(
			// 元固定順の一job。
			static_cast<std::uint32_t>( index)) ;
		const auto op	   = std::wstring( row.GetNamedString( L"operation")) ;	// 実保存操作。
		const auto decoded = decodeCollectorProjectedResponse(
			firstCampaign->job( index)->value(),
			baseline.at( L"runs/campaign-response-v4-" + op + L".json"),
			observations[index]) ;	// 元byte照合。
		DRIVERCRATE_EXPECT(
			context,
			decoded.result.status == collector_projected_json::Status::OK &&
				parseCollectorProjectedStart(
					firstIdentity, winrt::to_string( row.GetNamedObject( L"intent").Stringify()),
					starts[index]) &&
				decodeCollectorProjectedCache(
					httpSavedBody( store, L"current/campaign-cache-v1-" +
											 firstCampaign->job( index)->value().requestKey +
											 L".json"),
					caches[index])
						.status == collector_projected_json::Status::OK) ;
		// 不成立の元応答を正常上限の基準にしません。
		if( decoded.result.status != collector_projected_json::Status::OK) {
			return ;
		}
	}

	CollectorWaitSnapshot	control ;	// 旧24時間待機・reviewを全て保持します。
	CollectorBudgetSnapshot budget ;	// 完了初回の全精算済み予算。
	DRIVERCRATE_EXPECT( context,
					   parseCollectorWaitSnapshot(
						   httpSavedBody( store, L"current/campaign-controls-v1.json"), control) &&
						   parseCollectorBudgetSnapshot(
							   httpSavedBody( store, L"current/campaign-budget-v1.json"), budget)) ;
	auto		  tailDefinition = definition ;	// 末尾の新ASUS一要求だけを追加する所有定義。
	std::uint64_t lastUtc{} ;					// 最終合成世代の開始UTC。
	// 後続74世代を有限に組み立て、最後だけ三応答で299操作に止めます。
	for( std::size_t generation = 1U; generation < 75U; ++generation) {
		const auto utc =
			HTTP_TEST_UTC + generation * 2U * 86400000ULL ;	// 24時間待機を満たす合成時計。
		const auto delta = utc - HTTP_TEST_UTC ;			// 元I/O形の時刻だけを有限移動します。
		const auto date	 = std::chrono::year_month_day( std::chrono::floor<std::chrono::days>(
			 std::chrono::sys_time<std::chrono::milliseconds>( std::chrono::milliseconds( utc)) +
			 // 本番と同じJST日。
			 std::chrono::hours( 9))) ;
		wchar_t	   dayText[9]{} ;	// 固定YYYYMMDD。
		swprintf_s( dayText, L"%04d%02u%02u", static_cast<int>( date.year()),
				   static_cast<unsigned>( date.month()), static_cast<unsigned>( date.day())) ;
		CollectorProjectedCampaignIdentity identity ;	// 同じ要求と異なる日の本番G。
		// 最後だけ未登録ASUSを加え、元四対象のindexと旧CACHE bindingを維持します。
		if( generation == 74U && !freshRequests) {
			auto manifest =
				// 元四要求。
				JsonObject::Parse( winrt::to_hstring( definition.manifestBytes)) ;
			auto target = JsonObject::Parse(
				// 架空ASUS。
				manifest.GetNamedArray( L"targets").GetObjectAt( 0U).Stringify()) ;
			target.Insert( L"id", JsonValue::CreateStringValue( L"boundary-extra")) ;
			target.Insert( L"model",
						  JsonValue::CreateStringValue( L"Fictional Boundary Board extra")) ;
			manifest.GetNamedArray( L"targets").Append( target) ;
			auto job = JsonObject::Parse(
				// 元契約。
				manifest.GetNamedArray( L"jobs").GetObjectAt( 0U).Stringify()) ;
			job.Insert( L"locator", target.GetNamedValue( L"model")) ;
			JsonArray references ;	// 新しい一対象だけを参照します。
			references.Append( target.GetNamedValue( L"id")) ;
			job.Insert( L"targets", references) ;
			JsonArray jobs ;	// 三ASUS、新ASUS、Intelの予約順です。
			// 元三ASUSのscopeと固定順を保持します。
			for( std::uint32_t index = 0U; index < 3U; ++index) {
				jobs.Append( manifest.GetNamedArray( L"jobs").GetObjectAt( index)) ;
			}

			jobs.Append( job) ;
			jobs.Append( manifest.GetNamedArray( L"jobs").GetObjectAt( 3U)) ;
			manifest.Insert( L"jobs", jobs) ;
			tailDefinition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		}

		// 大量新要求だけは全modelとlocatorを変え、元四target ID・順序を保持します。
		if( freshRequests) {
			auto manifest = JsonObject::Parse(
				// 元四ASUSだけです。
				winrt::to_hstring( definition.manifestBytes)) ;
			// 別公開modelに対応する全input fieldは後続の本番identityへ再計算させます。
			for( std::uint32_t index = 0U; index < 4U; ++index) {
				const auto model = L"Fictional Capacity Board " + std::to_wstring( generation) +
								   L"-" + std::to_wstring( index) ;	// 架空locatorです。
				manifest.GetNamedArray( L"targets")
					.GetObjectAt( index)
					.Insert( L"model", JsonValue::CreateStringValue( model)) ;
				manifest.GetNamedArray( L"jobs").GetObjectAt( index).Insert(
					L"locator", JsonValue::CreateStringValue( model)) ;
			}

			tailDefinition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		}

		DRIVERCRATE_EXPECT( context,
						   makeCollectorProjectedCampaignIdentity(
							   freshRequests || generation == 74U ? tailDefinition : definition,
							   dayText, identity)) ;
		std::string oldBudget ;	// 元日の全精算をarchiveへ結合します。
		DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( budget, oldBudget)) ;
		const auto roll =
			digest( "day-roll-v2\n" + winrt::to_string( root.GetNamedString( L"rootKey")) + "\n" +
				   winrt::to_string( budget.day) + "\n" + winrt::to_string( dayText) + "\n" +
				   // 元日次操作名と同じ算法。
				   winrt::to_string( digest( oldBudget))) ;
		JsonObject rollIntent ;	// 本番固定順で同じ元archiveを参照します。
		rollIntent.Insert( L"schema",
						  JsonValue::CreateStringValue( L"collector-campaign-day-roll-v2")) ;
		rollIntent.Insert( L"rootKey", root.GetNamedValue( L"rootKey")) ;
		rollIntent.Insert( L"oldDay", JsonValue::CreateStringValue( budget.day)) ;
		rollIntent.Insert( L"newDay", JsonValue::CreateStringValue( dayText)) ;
		rollIntent.Insert( L"accepted", JsonValue::CreateNumberValue( static_cast<double>( utc))) ;
		rollIntent.Insert( L"budgetHash", JsonValue::CreateStringValue( digest( oldBudget))) ;
		rollIntent.Insert( L"operation", JsonValue::CreateStringValue( roll)) ;
		saveRegisteredHistoryFixture( context, store,
									 L"runs/campaign-day-roll-v2-" + roll + L".json",
									 winrt::to_string( rollIntent.Stringify())) ;
		// 日次archive・更新前予算・archive像は全て元精算の同じbyteです。
		for( const auto &name : {L"runs/campaign-budget-" + budget.day + L".json",
								L"runs/campaign-effect-v1-" + roll + L"-before-budget.json",
								L"runs/campaign-effect-v1-" + roll + L"-archive.json"}) {
			saveRegisteredHistoryFixture( context, store, name, oldBudget) ;
		}

		JsonObject archive ;	// 日付・実hash・操作を元rootへ登録します。
		archive.Insert( L"day", JsonValue::CreateStringValue( budget.day)) ;
		archive.Insert( L"hash", JsonValue::CreateStringValue( digest( oldBudget))) ;
		archive.Insert( L"operation", JsonValue::CreateStringValue( roll)) ;
		root.GetNamedArray( L"archives").Append( archive) ;
		budget = {dayText, utc / 1000U, {}} ;
		std::string emptyBudget ;	// 日次切替の元空予算像を後続予約と区別します。
		DRIVERCRATE_EXPECT( context, encodeCollectorBudgetSnapshot( budget, emptyBudget)) ;
		saveRegisteredHistoryFixture(
			context, store, L"runs/campaign-effect-v1-" + roll + L"-budget.json", emptyBudget) ;
		auto state = JsonObject::Parse( stateTemplate.Stringify()) ;	// 全四行を新Gの未予約にします。
		state.Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
		// 末尾だけ新ASUS行をIntelの前に追加し、全jobを元identityの順へ結合します。
		if( generation == 74U && !freshRequests) {
			const auto oldRows = state.GetNamedArray( L"jobs") ;	// 元四行の所有copy。
			JsonArray  rows ;										// 五行の新しい配列。
			// 旧三ASUS行を順序を変えず保持します。
			for( std::uint32_t index = 0U; index < 3U; ++index) {
				rows.Append( oldRows.GetObjectAt( index)) ;
			}

			auto extra =
				// 未予約へ戻す新行。
				JsonObject::Parse( oldRows.GetObjectAt( 0U).Stringify()) ;
			extra.Insert( L"job", JsonValue::CreateStringValue( identity.jobs[3U].jobKey)) ;
			rows.Append( extra) ;
			rows.Append( oldRows.GetObjectAt( 3U)) ;
			state.Insert( L"jobs", rows) ;
		}

		// 元jobの固定順を維持し、旧受領を新世代の観測として借用しません。
		for( const auto &entry : state.GetNamedArray( L"jobs")) {
			auto row = entry.GetObject() ;	// 独立所有copy内の未予約行。
			row.Insert( L"state", JsonValue::CreateStringValue( L"PENDING")) ;
			row.Insert( L"started", JsonValue::CreateNumberValue( 0.0)) ;
			row.Insert( L"response", JsonValue::CreateStringValue( L"")) ;
			row.Insert( L"operation", JsonValue::CreateStringValue( L"")) ;
			row.Insert( L"intent", JsonValue::CreateNullValue()) ;
		}

		// 新要求のjob keyもmanifest依存なので元行の古いkeyを保持しません。
		if( freshRequests) {
			// 本番identityの全四行へ同じ順序で再結合します。
			for( std::uint32_t index = 0U; index < 4U; ++index) {
				state.GetNamedArray( L"jobs").GetObjectAt( index).Insert(
					L"job", JsonValue::CreateStringValue( identity.jobs[index].jobKey)) ;
			}
		}

		auto marker =
			// 固定profileとartifact。
			object( L"runs/campaign-marker-v3-" + firstKey + L".json") ;
		marker.Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
		marker.Insert( L"inputHash", JsonValue::CreateStringValue( identity.inputSha256)) ;
		saveRegisteredHistoryFixture( context, store,
									 L"runs/campaign-input-v3-" + identity.generationKey + L".json",
									 identity.canonicalInput) ;
		saveRegisteredHistoryFixture(
			context, store, L"runs/campaign-marker-v3-" + identity.generationKey + L".json",
			winrt::to_string( marker.Stringify())) ;
		const std::size_t count =
			// 新要求は全世代完了にします。
			generation == 74U && !freshRequests ? 3U : 4U ;
		// 予約前後と受領前後を本番codec・精算関数から一件ずつ生成します。
		for( std::size_t index = 0U; index < count; ++index) {
			const auto &job		= identity.jobs[index] ;	// 本番inputで再構築した元scope。
			auto		start	= starts[index] ;			// 元形の二時計と有限deadlineを保持します。
			start.generationKey = identity.generationKey ;
			start.jobIndex		= index ;
			start.jobKey		= job.jobKey ;
			start.requestKey	= job.requestKey ;
			start.cacheBinding	= job.cacheBinding ;
			start.scopeSha256	= job.scopeSha256 ;
			start.source		= job.source ;
			start.startedUtcMillis += delta ;
			start.anchorUtcMillis += delta ;
			start.deadlineUtcMillis += delta ;
			std::string intent ;	// 新入力に完全結合した開始codecの本文。
			const bool	started =
				// 元input全field照合。
				encodeCollectorProjectedStart( identity, start, intent) ;
			DRIVERCRATE_EXPECT( context, started) ;
			// 空intentをJSONへ渡して後続の例外を作りません。
			if( !started) {
				return ;
			}

			budget.reservations.push_back(
				{identity.generationKey, job.jobKey, job.source.rateLimitGroup,
				 start.startedUtcMillis / 1000U, job.source.maximumResponseBytes,
				 job.source.maximumResponseBytes, 0U}) ;
			budget.lastUtc = start.anchorUtcMillis / 1000U ;
			auto &group =
				control.controls[L"g-" + job.source.rateLimitGroup] ;	// 旧group待機を保持します。
			group.group	   = job.source.rateLimitGroup ;
			group.observed = start.anchorUtcMillis ;
			auto &request =
				control.controls[L"r-" + job.requestKey] ;	// 旧requestの24時間期限を保持します。
			DRIVERCRATE_EXPECT( context,
							   !request.review && request.notBefore <= start.anchorUtcMillis) ;
			request.group	   = job.source.rateLimitGroup ;
			request.request	   = job.requestKey ;
			request.observed   = start.anchorUtcMillis ;
			request.generation = identity.generationKey ;
			request.job		   = job.jobKey ;
			request.started	   = start.startedUtcMillis ;
			control.lastUtc	   = start.anchorUtcMillis ;
			auto row		   = state.GetNamedArray( L"jobs").GetObjectAt(
				  // 元行だけ。
				  static_cast<std::uint32_t>( index)) ;
			row.Insert( L"state", JsonValue::CreateStringValue( L"RUNNING")) ;
			row.Insert( L"started",
					   JsonValue::CreateNumberValue( static_cast<double>( start.startedUtcMillis))) ;
			row.Insert( L"intent", JsonObject::Parse( winrt::to_hstring( intent))) ;
			std::array<std::string, 3U> before ;	// 元更新前CONTROL／JOB／BUDGET。
			DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( control, before[0]) &&
											encodeCollectorBudgetSnapshot( budget, before[2])) ;
			before[1] = winrt::to_string( state.Stringify()) ;
			auto value =
				observations[index].value ;	// 公開metadataとI/O形だけを合成時計へ結合します。
			value.generation			 = identity.generationKey ;
			value.job					 = job.jobKey ;
			value.request				 = job.requestKey ;
			value.cache					 = job.cacheBinding ;
			value.metadata.binding.scope = job.scopeSha256 ;
			value.metadata.binding.cache = job.cacheBinding ;
			value.day					 = dayText ;
			value.started += delta ;
			value.finished += delta ;
			value.accepted += delta ;
			value.io.deadlineUtcMillis += delta ;
			value.io.finishedUtcMillis = *value.io.finishedUtcMillis + delta ;
			// 元headerを欠測のまま保持し、存在するときだけ合成UTCへ移します。
			if( value.io.headerUtcMillis) {
				value.io.headerUtcMillis = *value.io.headerUtcMillis + delta ;
			}

			// 元metadataの検証時計も同じI/O形へ結合します。
			if( value.metadata.binding.validatedUtc) {
				value.metadata.binding.validatedUtc = *value.metadata.binding.validatedUtc + delta ;
			}

			// 大量新要求では元製品のmetadataを借用せず本文から全公開値を再計算します。
			if( freshRequests) {
				const bool projected =
					// 純粋parserと指紋の結果です。
					freshCapacityMetadata( job, value) ;
				DRIVERCRATE_EXPECT( context, projected) ;
				// 不成立を後続の合成正例へ保存しません。
				if( !projected) {
					return ;
				}
			}

			// 時計変更前のhashを保持せず、本番codecに合成metadataの実hashを生成させます。
			value.projection.clear() ;

			CollectorProjectedResponseBytes response ;	// 保存許可ではない本番codecの全byte。
			const auto						encoded =
				// 独立有限検査。
				encodeCollectorProjectedResponse( job, value, response) ;
			DRIVERCRATE_EXPECT( context,
							   encoded.result.status == collector_projected_json::Status::OK) ;
			// Codec拒否を正常な履歴へ保存しません。
			if( encoded.result.status != collector_projected_json::Status::OK) {
				return ;
			}

			const auto op =
				digest( "response-v2\n" + winrt::to_string( identity.generationKey) + "\n" +
					   // 元操作の本番算法。
					   winrt::to_string( job.jobKey) + "\n") ;
			CollectorWaitSnapshot settled ;	// 本番待機精算。旧reviewを解除しません。
			DRIVERCRATE_EXPECT(
				context,
				prepareCollectorWaitSettlement(
					control,
					{job.source.rateLimitGroup, job.requestKey, identity.generationKey, job.jobKey},
					{value.state == CollectorMetadataOutcome::FETCHED, value.status,
					 value.retryAfter, value.review, value.challenge},
					value.started, value.finished, value.accepted, value.accepted, false, settled)) ;
			control = std::move( settled) ;
			row.Insert(
				L"state",
				JsonObject::Parse( winrt::to_hstring( response.response)).GetNamedValue( L"state")) ;
			row.Insert( L"response", JsonValue::CreateStringValue( response.responseSha256)) ;
			row.Insert( L"operation", JsonValue::CreateStringValue( op)) ;
			budget.reservations.back().phase = 1U ;
			budget.reservations.back().charged =
				value.bytes.value_or( job.source.maximumResponseBytes) ;
			budget.lastUtc = std::max( budget.lastUtc, value.accepted / 1000U) ;
			std::array<std::string, 3U> after ;	// 同じ三roleの本番再導出対象。
			DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( control, after[0]) &&
											encodeCollectorBudgetSnapshot( budget, after[2])) ;
			after[1] = winrt::to_string( state.Stringify()) ;
			const std::array<std::wstring, 3U> roles{L"control", L"job", L"budget"} ;	// 固定保存名。
			// 三roleの前後全byteを保存し、履歴readerの独立再導出を要求します。
			for( std::size_t role = 0U; role < roles.size(); ++role) {
				saveRegisteredHistoryFixture( context, store,
											 L"runs/campaign-effect-v2-" + op + L"-before-" +
												 roles[role] + L".json",
											 before[role]) ;
				saveRegisteredHistoryFixture(
					context, store,
					L"runs/campaign-effect-v2-" + op + L"-" + roles[role] + L".json", after[role]) ;
			}

			std::string				priorCache ;	// 直前のCACHE全参照と全byteを捨てません。
			std::string				nextCache ;		// 本番CACHE導出・codecによる更新後像。
			CollectorProjectedCache next ;			// 全要求で別々の更新前鎖を保持します。
			// 新requestのCACHE前像は本当の不在であり、null本文fileを保存しません。
			if( freshRequests) {
				DRIVERCRATE_EXPECT(
					context,
					deriveCollectorProjectedCache( job, response.envelope, nullptr, next).status ==
							collector_projected_json::Status::OK &&
						encodeCollectorProjectedCache( next, nextCache).status ==
							collector_projected_json::Status::OK) ;
			} else {
				DRIVERCRATE_EXPECT(
					context,
					encodeCollectorProjectedCache( caches[index], priorCache).status ==
							collector_projected_json::Status::OK &&
						deriveCollectorProjectedCache( job, response.envelope, &caches[index], next)
								.status == collector_projected_json::Status::OK &&
						encodeCollectorProjectedCache( next, nextCache).status ==
							collector_projected_json::Status::OK) ;
			}

			caches[index] = std::move( next) ;
			DRIVERCRATE_EXPECT( context, store.write( L"runs/campaign-response-v4-" + op + L".json",
													response.envelope) == 0U) ;
			// 旧要求の更新前鎖だけが前CACHE fileを必要とします。
			if( !freshRequests) {
				saveRegisteredHistoryFixture(
					context, store, L"runs/campaign-effect-v2-" + op + L"-before-cache.json",
					priorCache) ;
			}

			saveRegisteredHistoryFixture(
				context, store, L"runs/campaign-effect-v2-" + op + L"-cache.json", nextCache) ;
			saveRegisteredHistoryFixture( context, store,
										 L"current/campaign-cache-v1-" + job.requestKey + L".json",
										 nextCache) ;
			// 元順序のCACHE登録一行だけを更新し、重複登録を増やしません。
			// 新要求は既存登録の置換ではなく、元全登録を残した追加です。
			if( freshRequests) {
				JsonObject registration ;	// 本番と同じ二fieldだけです。
				registration.Insert( L"request", JsonValue::CreateStringValue( job.requestKey)) ;
				registration.Insert( L"hash", JsonValue::CreateStringValue( digest( nextCache))) ;
				root.GetNamedArray( L"cacheInventory").Append( registration) ;
			}

			// 元順序の登録を保持し、当要求以外のhashへ触れません。
			for( const auto &entry : root.GetNamedArray( L"cacheInventory")) {
				auto registration = entry.GetObject() ;	// 当要求の実hashだけを置換します。
				// 他要求の登録を借用しません。
				if( registration.GetNamedString( L"request") == job.requestKey) {
					registration.Insert( L"hash", JsonValue::CreateStringValue( digest( nextCache))) ;
				}
			}
		}

		std::string controlBody ;										// 全request待機を保持した現在値。
		std::string budgetBody ;										// 当日全精算の現在値。
		const auto	stateBody = winrt::to_string( state.Stringify()) ;	// 元固定順の全state。
		DRIVERCRATE_EXPECT( context, encodeCollectorWaitSnapshot( control, controlBody) &&
										encodeCollectorBudgetSnapshot( budget, budgetBody)) ;
		saveRegisteredHistoryFixture( context, store, L"current/campaign-controls-v1.json",
									 controlBody) ;
		saveRegisteredHistoryFixture( context, store, L"current/campaign-budget-v1.json",
									 budgetBody) ;
		saveRegisteredHistoryFixture(
			context, store, L"current/campaign-state-v3-" + identity.generationKey + L".json",
			stateBody) ;
		auto registration = JsonObject::Parse(
			// 元登録形。
			root.GetNamedArray( L"generations").GetObjectAt( 0U).Stringify()) ;
		registration.Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
		registration.Insert( L"inputHash", JsonValue::CreateStringValue( identity.inputSha256)) ;
		registration.Insert( L"summaryHash", JsonValue::CreateStringValue( L"")) ;
		root.Insert( L"activeGeneration", JsonValue::CreateStringValue( identity.generationKey)) ;
		root.Insert( L"lastUtcMillis",
					JsonValue::CreateNumberValue( static_cast<double>( utc + 400000U))) ;
		// 全四終端の世代だけ元完了形を新しい実hashへ結合します。
		if( count == 4U) {
			auto shard =
				// 同じmetadata分母。
				object( L"runs/campaign-targets-v1-" + firstKey + L".json") ;
			auto summary =
				// 同じ元分類。
				object( L"runs/campaign-summary-v1-" + firstKey + L".json") ;
			auto finish =
				// 元固定順のintent。
				object( L"runs/campaign-finish-v1-" + firstKey + L".json") ;
			// 新しい入力・全state・対象像の実hashへ四完了像を結合します。
			for( auto *value : {&shard, &summary, &finish}) {
				value->Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
				value->Insert( L"inputHash", JsonValue::CreateStringValue( identity.inputSha256)) ;
			}

			const auto shardHash =
				// 全対象像の実hash。
				digest( winrt::to_string( shard.Stringify())) ;
			summary.Insert( L"stateHash", JsonValue::CreateStringValue( digest( stateBody))) ;
			summary.Insert( L"targetShardHash", JsonValue::CreateStringValue( shardHash)) ;
			summary.Insert( L"closedUtcMillis",
						   JsonValue::CreateNumberValue( static_cast<double>( utc + 400000U))) ;
			const auto summaryHash =
				// 完全集計の実hash。
				digest( winrt::to_string( summary.Stringify())) ;
			auto pointer = object( L"current/campaign-current-v2.json") ;	// 最新完了だけを指します。
			pointer.Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
			pointer.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
			finish.Insert( L"stateHash", JsonValue::CreateStringValue( digest( stateBody))) ;
			finish.Insert( L"targetShardHash", JsonValue::CreateStringValue( shardHash)) ;
			finish.Insert( L"closedUtcMillis", summary.GetNamedValue( L"closedUtcMillis")) ;
			finish.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
			finish.Insert( L"pointerHash", JsonValue::CreateStringValue(
											  digest( winrt::to_string( pointer.Stringify())))) ;
			// 全完了証跡と最新pointerを同じ元形で保存します。
			for( const auto &[name, value] : std::array<std::pair<std::wstring, JsonObject>, 4U>{
					std::pair{L"runs/campaign-targets-v1-" + identity.generationKey + L".json",
							  shard},
					std::pair{L"runs/campaign-summary-v1-" + identity.generationKey + L".json",
							  summary},
					std::pair{L"runs/campaign-finish-v1-" + identity.generationKey + L".json",
							  finish},
					std::pair{std::wstring( L"current/campaign-current-v2.json"), pointer}}) {
				saveRegisteredHistoryFixture( context, store, name,
											 winrt::to_string( value.Stringify())) ;
			}

			registration.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
			root.Insert( L"activeGeneration", JsonValue::CreateStringValue( L"")) ;
		}

		root.GetNamedArray( L"generations").Append( registration) ;
		saveRegisteredHistoryFixture( context, store, L"current/campaign-root-v2.json",
									 winrt::to_string( root.Stringify())) ;
		std::cout << "Operation capacity assembled=" << generation * 4U + count
				  << " generations=" << generation + 1U << std::endl ;
		// 早期八操作の正例を検査し、組立形の拒否を300操作まで隠しません。
		if( generation == 1U && !freshRequests) {
			LocalCollectorRecovery inspector ;	// 元writer借用は解放済みです。
			const auto			   code =
				// 本番全閉包。
				inspector.initializeProjected( store, definition, utc + 401000U, 0U) ;
			context.expect( code == 0U, "operation capacity 8 code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
			// 不正な正例を後続合格へ読み替えません。
			if( code != 0U) {
				return ;
			}
		}

		// 新要求の固定段階だけで全閉包を測り、毎応答の高価な親受領と区別します。
		if( freshRequests && (generation == 1U || (generation + 1U) % 8U == 0U ||
							 generation == 74U || (startupBoundary && generation >= 61U))) {
			std::shared_ptr<const CollectorPreparedProjectedCampaign>
					   campaign ;	// 現在manifestの変更不能入力です。
			const bool prepared = prepareCollectorProjectedCampaign(
				identity.canonicalInput, identity.inputSha256, identity.generationKey,
				tailDefinition.artifactSha256, tailDefinition.sources,
				campaign) ;	// 本番prepared codecです。
			DRIVERCRATE_EXPECT( context, prepared && campaign) ;
			// 入力不成立を容量拒否として採点しません。
			if( !prepared || !campaign) {
				return ;
			}

			const auto before = observation.snapshot( "checkpoint_snapshot_before", generation + 1U,
													 (generation + 1U) * 4U, context,
													 store) ;	// 検査前の元全raw正本です。
			CollectorStoreUsage usage ;							// 一回の保存量であり累積reader量ではありません。
			DRIVERCRATE_EXPECT( context, store.inspectUsage( usage) == 0U) ;
			CollectorHistoryReadDiagnostics
				diagnostics ;	// URL・本文・保存権限を持たない部分観測です。
			std::shared_ptr<const CollectorRegisteredProjectedHistory>
					   history ;	// 全成功時だけ受けるcontextです。
			const auto inspectStarted =
				observation.begin( "inspect", generation + 1U,
								  (generation + 1U) * 4U) ;	// 元公開検査の直前です。
			const auto code = LocalCollectorRecovery::inspectRegisteredProjectedHistory(
				store, *campaign->job( 0U), tailDefinition.sources, utc + 401000U, history, {},
				&diagnostics) ;	// 元全閉包をそのまま検査します。
			observation.end( "inspect", generation + 1U, (generation + 1U) * 4U, inspectStarted,
							code) ;
			DRIVERCRATE_EXPECT( context, before == observation.snapshot(
													  "checkpoint_snapshot_after", generation + 1U,
													  (generation + 1U) * 4U, context, store)) ;
			std::cout << "Cache capacity requests=" << (generation + 1U) * 4U << " code=" << code
					  << " charged=" << diagnostics.chargedBytes
					  << " attempted=" << diagnostics.attemptedBytes
					  << " names=" << diagnostics.referencedNames
					  << " reads=" << diagnostics.readCalls
					  << " recheck=" << diagnostics.recheckStarted
					  << " cause=" << static_cast<unsigned>( diagnostics.capacity)
					  << " runs=" << usage.runEntries << " current=" << usage.currentEntries
					  << " saved=" << usage.bytes << std::endl ;
			// 境界付近の全完了世代だけで通常監督を別objectとして起動します。
			if( startupBoundary && generation >= 61U) {
				DWORD	   normalCode{} ;	// 公開読取りのcodeを通常起動へ代入しません。
				const auto normalScope =
					observation.begin( "normal_scope", generation + 1U,
									  (generation + 1U) * 4U) ;	// constructorより前の時計です。
				{
					LocalCollectorRecovery normal ;	// 検査が済むまでの単一writer借用です。
					normalCode = observation.initialize( "normal_initialize", generation + 1U,
														(generation + 1U) * 4U, normal, store,
														tailDefinition, utc + 401000U) ;
					context.expect(
						normalCode == code && normal.lastError() == code &&
							before == observation.snapshot( "normal_snapshot", generation + 1U,
														   (generation + 1U) * 4U, context, store),
						"cache startup requests=" + std::to_string( (generation + 1U) * 4U) +
							" code=" + std::to_string( normalCode),
						__FILE__, __LINE__) ;
					// 容量拒否を同じ監督の再呼出しで消さず、保存を始めないことを確認します。
					if( normalCode != 0U) {
						DRIVERCRATE_EXPECT(
							context,
							observation.initialize( "repeat_initialize", generation + 1U,
												   (generation + 1U) * 4U, normal, store,
												   tailDefinition, utc + 402000U) == normalCode &&
								before == observation.snapshot( "repeat_snapshot", generation + 1U,
															   (generation + 1U) * 4U, context,
															   store)) ;
					}
				}
				observation.end( "normal_scope", generation + 1U, (generation + 1U) * 4U,
								normalScope, normalCode) ;

				const auto restartScope = observation.begin(
					"restart_scope", generation + 1U,
					(generation + 1U) * 4U) ;	// 前監督の破棄後、constructor前です。
				{
					LocalCollectorRecovery restarted ;	// 前監督の借用解放後だけ再起動します。
					const auto			   restartCode = observation.initialize(
						"restart_initialize", generation + 1U, (generation + 1U) * 4U, restarted,
						store, tailDefinition,
						utc + 402000U) ;	// 通常入口の独立実測です。
					DRIVERCRATE_EXPECT(
						context,
						restartCode == normalCode && restarted.lastError() == normalCode &&
							before == observation.snapshot( "restart_snapshot", generation + 1U,
														   (generation + 1U) * 4U, context, store)) ;
					std::cout << "Cache startup requests=" << (generation + 1U) * 4U
							  << " initialize=" << normalCode << " restart=" << restartCode
							  << " unchanged=1" << std::endl ;
				}
				observation.end( "restart_scope", generation + 1U, (generation + 1U) * 4U,
								restartScope) ;
			}

			// 生codeと元容量箇所が一致した時だけ容量拒否の系列停止を受け入れます。
			if( code != 0U) {
				DRIVERCRATE_EXPECT(
					context,
					code == ERROR_TOO_MANY_NAMES && !history &&
						(diagnostics.capacity == CollectorHistoryCapacity::RAW_BYTES ||
						 diagnostics.capacity == CollectorHistoryCapacity::REFERENCE_NAMES)) ;
				return ;
			}

			DRIVERCRATE_EXPECT( context,
							   history && diagnostics.capacity == CollectorHistoryCapacity::NONE &&
								   diagnostics.recheckStarted &&
								   diagnostics.chargedBytes <= 64U * 1024U * 1024U &&
								   diagnostics.referencedNames <= 6000U) ;
		}

		lastUtc = utc ;
	}

	// 新要求の段階系列は全完了だけで終え、旧未受領300枠の操作試験へ流用しません。
	if( freshRequests) {
		return ;
	}

	CollectorStoreUsage usage ;	// 他容量を踏まない現物保存量。
	DRIVERCRATE_EXPECT( context, store.inspectUsage( usage) == 0U &&
									checkCollectorProjectedCompletionCapacity( usage, 5U, 5U) == 0U) ;
	std::cout << "Operation capacity saved=299 cache=4 runs=" << usage.runEntries
			  << " current=" << usage.currentEntries << " bytes=" << usage.bytes << std::endl ;
	{
		const auto before = projectedStoreSnapshot( context, store) ;	// 正常299操作の全byte。
		LocalCollectorRecovery owner ;									// 本番全履歴検査の正常初期化を必須にします。
		const auto			   initialized =
			// 同日末尾。
			owner.initializeProjected( store, tailDefinition, lastUtc + 401000U, 0U) ;
		context.expect( initialized == 0U && before == projectedStoreSnapshot( context, store),
					   "operation capacity 299 code=" + std::to_string( initialized), __FILE__,
					   __LINE__) ;
		// 容量または形式拒否の正例で予約境界へ進みません。
		if( initialized != 0U) {
			return ;
		}

		CollectorHttpClockSample sample{lastUtc + 402000U, 3000U} ;		// 元二秒間隔と未受領期限内。
		CollectorHttpPermitPool	 pool( [&sample] { return sample ; }) ;	// HTTP依存を持ちません。
		CollectorHttpPermit		 pending ;								// ASUSの300番目の将来操作を保持します。
		const auto reserved = pool.reserveProjected( owner, pending) ;	// 本番予約・未受領一枠。
		context.expect( reserved == 0U && pending.present(),
					   "operation capacity pending code=" + std::to_string( reserved) +
						   " reason=" + winrt::to_string( owner.reason()),
					   __FILE__, __LINE__) ;
		// 正常な一枠がなければ上限拒否を採点しません。
		if( reserved != 0U) {
			return ;
		}

		const auto afterReservation = projectedStoreSnapshot( context, store) ;	// 未受領全開始像。
		sample						= {lastUtc + 403000U, 4000U} ;
		CollectorWaitSnapshot current ;	// 別groupの旧review／待機を元保存で検査します。
		DRIVERCRATE_EXPECT(
			context, parseCollectorWaitSnapshot(
						 httpSavedBody( store, L"current/campaign-controls-v1.json"), current)) ;
		const auto &intel =
			// 元Intel。
			current.controls.at( L"r-" + firstCampaign->job( 3U)->value().requestKey) ;
		DRIVERCRATE_EXPECT(
			context, !intel.review && intel.started == 0U && intel.notBefore <= sample.utcMillis &&
						 current.controls.at( L"g-intel").completed + 2000U <= sample.utcMillis) ;
		CollectorHttpPermit excess ;									// 別groupでも301番目の許可は空のままです。
		const auto rejected = pool.reserveProjected( owner, excess) ;	// 保存前の全操作＋RUNNING検査。
		DRIVERCRATE_EXPECT( context, rejected == ERROR_TOO_MANY_NAMES && !excess.present() &&
										owner.lastError() == ERROR_TOO_MANY_NAMES &&
										afterReservation == projectedStoreSnapshot( context, store)) ;
		DRIVERCRATE_EXPECT( context, pool.reserveProjected( owner, excess) == ERROR_TOO_MANY_NAMES &&
										!excess.present() &&
										afterReservation == projectedStoreSnapshot( context, store)) ;
		std::cout << "Operation capacity pending=1 reservation=" << rejected << " sends=0"
				  << std::endl ;
	}
	std::map<std::wstring, std::string> final ;	// 300操作の全raw正本。
	{
		const auto before = projectedStoreSnapshot( context, store) ;	// 通常起動は非変更で待ちます。
		LocalCollectorRecovery restarted ;								// 未受領slot所有を解放した別監督。
		const auto			   initialized =
			// 全旧閉包。
			restarted.initializeProjected( store, tailDefinition, lastUtc + 404000U, 0U) ;
		DRIVERCRATE_EXPECT( context, initialized == ERROR_RETRY && restarted.lastError() == 0U &&
										restarted.reason() == L"HISTORY_ACCEPTANCE_PENDING" &&
										before == projectedStoreSnapshot( context, store)) ;
		const auto recovered =
			initialized == ERROR_RETRY
				? restarted.recoverNextProjectedReservations( lastUtc + 405000U, 1000U)
				: initialized ;	// 一回・非再送。
		context.expect( recovered == 0U,
					   "operation capacity settlement=" + std::to_string( recovered), __FILE__,
					   __LINE__) ;
		// 原拒否を保存し、300操作の正常履歴へ読み替えません。
		if( recovered != 0U) {
			return ;
		}

		final = projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT(
			context, restarted.recoverNextProjectedReservations( lastUtc + 406000U, 2000U) == 0U &&
						 final == projectedStoreSnapshot( context, store)) ;
	}
	LocalCollectorRecovery twice ;	// 正常全履歴読込みも300操作で非変更です。
	DRIVERCRATE_EXPECT(
		context, twice.initializeProjected( store, tailDefinition, lastUtc + 407000U, 0U) == 0U &&
					 final == projectedStoreSnapshot( context, store)) ;
	const auto responses = std::count_if( final.begin(), final.end(), []( const auto &entry) {
		return entry.first.starts_with( L"runs/campaign-response-v4-") ||
			   entry.first.starts_with( L"runs/campaign-response-v2-") ;
	}) ; // 299合成／初回応答と一つの本番中断だけを数えます。
	DRIVERCRATE_EXPECT( context, responses == 300 && twice.terminalJobs() == 4U) ;
	CollectorHttpClockSample sample{lastUtc + 408000U, 3000U} ;		// 二回目起動の二秒間隔も満たします。
	CollectorHttpPermitPool	 pool( [&sample] { return sample ; }) ;	// 新しいHTTP送信は行いません。
	CollectorHttpPermit		 excess ;								// Intelが選択可能でも保存操作301番目は拒否します。
	DRIVERCRATE_EXPECT( context, pool.reserveProjected( twice, excess) == ERROR_TOO_MANY_NAMES &&
									!excess.present() &&
									twice.lastError() == ERROR_TOO_MANY_NAMES &&
									final == projectedStoreSnapshot( context, store)) ;
	std::cout << "Operation capacity closed=300 cache=5 missingResponse=1 sendsAfterBaseline=0"
			  << std::endl ;
}
} // namespace

/** @see local_collector_http_tests.h */
void runCollectorPartialStartRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto definition = definitionFactory() ;	// 元二sourceのfake成功だけを使います。
	CollectorProjectedCampaignIdentity identity ;	// 元の初回入力。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		prepared ;	// 初回fake workerの所有入力。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, prepared)) ;
	// 準備不成立を既知の期待状態で埋めません。
	if( !prepared) {
		return ;
	}

	LocalCollectorStateStore first ;	// 実保存coreへfake HTTPの成功を渡す保護root。
	DRIVERCRATE_EXPECT( context, first.initialize( rootFactory(), true) == 0U) ;
	std::array<CollectorProjectedResponseBytes, 2U> initial ;	// 独立codecの元v4。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, first, definition, prepared,
															   0U, {}, initial) == 0U) ;
	{
		LocalCollectorRecovery finish ;	// 元完了証跡を通常経路で確定します。
		DRIVERCRATE_EXPECT(
			context,
			finish.initializeProjected( first, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				finish.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto original = projectedStoreSnapshot( context, first) ;	// 全条件に共通する不変の旧履歴。
	const auto utc		= HTTP_TEST_UTC + 86400000U ;				// 元翌日の予約時計。
	// 既存一予約の二prefix、新request＋他RUNNINGの二prefixを独立に作ります。
	for( unsigned scenario = 0U; scenario < 4U; ++scenario) {
		auto	   next		   = definition ;		// source権限と上限は変えず公開scopeだけを変えます。
		const bool withRunning = scenario >= 2U ;	// 新ASUS requestの前にIntelのRUNNINGを残します。
		// 新requestは実機情報を使わず架空の公開製品表示名から導出します。
		if( withRunning) {
			const auto manifest =
				// 元公開入力。
				JsonObject::Parse( winrt::to_hstring( next.manifestBytes)) ;
			manifest.GetNamedArray( L"targets")
				.GetObjectAt( 26U)
				.Insert( L"model", JsonValue::CreateStringValue( L"Fixture Partial Start New Model")) ;
			manifest.GetNamedArray( L"jobs").GetObjectAt( 1U).Insert(
				L"locator", JsonValue::CreateStringValue( L"Fixture Partial Start New Model")) ;
			next.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		}

		CollectorProjectedCampaignIdentity nextIdentity ;	// 元の日付から保存名を再構築します。
		DRIVERCRATE_EXPECT( context,
						   makeCollectorProjectedCampaignIdentity( next, L"20260928", nextIdentity)) ;
		const std::size_t partialIndex = withRunning ? 1U : 0U ;	// 最後の予約だけが部分開始です。
		const auto		  checkpoint =
			   scenario % 2U == 0U
					   ? CollectorRecoveryCheckpoint::RESERVED
					   : CollectorRecoveryCheckpoint::STARTED ;	// BUDGETだけ、またはCONTROLも保存した二窓。
		const auto started =
			utc + 2000U + partialIndex * 1000U ;			// 元秒予約を期待値として保持します。
		LocalCollectorStateStore			store ;			// この開始停止条件だけの保護root。
		std::map<std::wstring, std::string> notStarted ;	// 同じ末尾の未予約状態も負例へ保持します。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 既存成功を直接再生成せず元rawをそのまま再利用します。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		{
			LocalCollectorRecovery owner ;		// 開始停止後も第一995を保持する元監督。
			unsigned			   observed{} ;	// 指定開始checkpointだけの回数。
			const auto			   stop = [&]( const CollectorRecoveryCheckpoint point) {
				return point == checkpoint && ++observed == partialIndex + 1U ;
			} ; // 全保存順の実checkpointから停止させます。
			DRIVERCRATE_EXPECT( context,
							   owner.initializeProjected( store, next, utc, 0U, stop) == 0U &&
								   owner.beginNextProjected( next, utc, 1000U) == 0U) ;
			notStarted = projectedStoreSnapshot( context, store) ;
			// 他groupの完全RUNNINGだけを先行し、最後の予約のJOB保存前に止めます。
			CollectorHttpClockSample sample{utc + 2000U, 2000U} ;	// 元監督と同じ非通信時計。
			CollectorHttpPermitPool	 pool(
				 [&sample] { return sample ; }) ;			// 既存所有予約入口だけを通します。
			std::array<CollectorHttpPermit, 2U> permits ;	// 未使用permitはHTTPへ渡しません。
			// 他groupの完全予約後、最後の保存途中で必ず停止します。
			for( std::size_t index = 0U; index <= partialIndex; ++index) {
				const DWORD expected = index == partialIndex ? ERROR_OPERATION_ABORTED
															 : ERROR_SUCCESS ;	// APIと同じcode型。
				sample				 = {utc + 2000U + index * 1000U, 2000U + index * 1000U} ;
				DRIVERCRATE_EXPECT( context,
								   pool.reserveProjected( owner, permits[index]) == expected &&
									   (index != partialIndex || !permits[index].present())) ;
			}

			const auto cut = projectedStoreSnapshot( context, store) ;	// 停止直後の全raw。
			DRIVERCRATE_EXPECT( context, owner.recoverNextProjectedReservations(
											utc + 4000U, 4000U) == ERROR_OPERATION_ABORTED &&
											cut == projectedStoreSnapshot( context, store)) ;
		}
		const auto interruptedStart = projectedStoreSnapshot( context, store) ;	// 二prefixの元正本。
		std::vector<std::map<std::wstring, std::string>> windows ;				// 部分開始の中断保存全窓だけ。
		std::size_t responses{} ;												// 部分開始を最初に精算した事実も確認します。
		{
			LocalCollectorRecovery recovered ;	// 借用と実行slotを持ち越さない再起動監督。
			const auto			   capture = [&]( const CollectorRecoveryCheckpoint point) {
				// 元の部分開始responseだけを保存窓の対象とします。
				if( point == CollectorRecoveryCheckpoint::RESPONSE) {
					++responses ;
				}

				// 第二のRUNNING中断を部分開始の試験へ混入しません。
				if( responses == 1U) {
					windows.push_back( projectedStoreSnapshot( context, store)) ;
				}

				return false ;
			} ; // HTTP／worker／executorは作りません。
			const auto initialized = recovered.initializeProjected( store, next, utc + 5000U, 0U,
																   capture) ;	// 非変更待機。
			context.expect( initialized == ERROR_RETRY &&
							   interruptedStart == projectedStoreSnapshot( context, store),
						   "partial start init scenario=" + std::to_string( scenario) +
							   " code=" + std::to_string( initialized),
						   __FILE__, __LINE__) ;
			const auto result =
				// 明示中断だけ。
				recovered.recoverNextProjectedReservations( utc + 6000U, 1000U) ;
			context.expect( result == 0U && recovered.terminalJobs() == partialIndex + 1U,
						   "partial start recovery scenario=" + std::to_string( scenario) +
							   " code=" + std::to_string( result),
						   __FILE__, __LINE__) ;
			// 失敗の保存物を期待値で補完せず、次の独立条件へ移ります。
			if( result != 0U) {
				continue ;
			}

			const auto stable = projectedStoreSnapshot( context, store) ;	// 精算後は非変更反復。
			DRIVERCRATE_EXPECT(
				context, recovered.recoverNextProjectedReservations( utc + 7000U, 2000U) == 0U &&
							 stable == projectedStoreSnapshot( context, store)) ;
		}
		DRIVERCRATE_EXPECT( context, windows.size() == (withRunning ? 15U : 16U)) ;
		std::wstring op ;	// 部分開始の元一操作hash。
		DRIVERCRATE_EXPECT(
			context, computeBytesSha256(
						 "response-v2\n" + winrt::to_string( nextIdentity.generationKey) + "\n" +
							 winrt::to_string( nextIdentity.jobs[partialIndex].jobKey) + "\n",
						 op) == 0U) ;
		const auto responseName = L"runs/campaign-response-v2-" + op + L".json" ;	// 固定中断保存名。
		const auto cacheName	= L"current/campaign-cache-v1-" +
							   nextIdentity.jobs[partialIndex].requestKey +
							   L".json" ;								// 同じ元scope。
		const auto final	= projectedStoreSnapshot( context, store) ;	// 元完走の不変証跡。
		const auto response = JsonObject::Parse(
			// 元canonical v2。
			winrt::to_hstring( httpSavedBody( store, responseName))) ;
		DRIVERCRATE_EXPECT(
			context, response.GetNamedString( L"state") == L"INTERRUPTED" &&
						 response.GetNamedNumber( L"started") == static_cast<double>( started) &&
						 response.GetNamedNumber( L"accepted") == static_cast<double>( utc + 6000U) &&
						 response.GetNamedValue( L"sends").ValueType() ==
							 winrt::Windows::Data::Json::JsonValueType::Null &&
						 response.GetNamedValue( L"bytes").ValueType() ==
							 winrt::Windows::Data::Json::JsonValueType::Null) ;
		const auto stateName = L"current/campaign-state-v3-" + nextIdentity.generationKey +
							   L".json" ;	// 元JOBを補完しません。
		const auto row =
			JsonObject::Parse( winrt::to_hstring( httpSavedBody( store, stateName)))
				.GetNamedArray( L"jobs")
				.GetObjectAt( static_cast<std::uint32_t>( partialIndex)) ;	// 中断後もnull intentです。
		DRIVERCRATE_EXPECT( context, row.GetNamedValue( L"intent").ValueType() ==
										winrt::Windows::Data::Json::JsonValueType::Null) ;
		CollectorBudgetSnapshot budget ;	// 全予約の欠測最大量精算を確認します。
		DRIVERCRATE_EXPECT( context,
						   parseCollectorBudgetSnapshot(
							   httpSavedBody( store, L"current/campaign-budget-v1.json"), budget)) ;
		// 未送信だと断定せず全phase0を最大量phase2へ固定します。
		for( const auto &reserved : budget.reservations) {
			DRIVERCRATE_EXPECT( context,
							   reserved.phase == 2U && reserved.charged == reserved.maximum) ;
		}

		const auto cache = JsonObject::Parse(
			// 元成功と最新試行は別軸。
			winrt::to_hstring( httpSavedBody( store, cacheName))) ;
		DRIVERCRATE_EXPECT( context, cache.GetNamedString( L"reason") == L"INTERRUPTED" &&
										!cache.GetNamedBoolean( L"reusable")) ;
		// 新requestは真の不在、既存は元成功参照を全byte保持します。
		if( withRunning) {
			DRIVERCRATE_EXPECT( context, cache.GetNamedArray( L"slices").Size() == 0U) ;
		} else {
			const auto old = JsonObject::Parse(
				// 元成功CACHE。
				winrt::to_hstring( httpSavedBody( first, cacheName))) ;
			// Slice／元200／検証日をそれぞれ独立に比較します。
			for( const auto field : {L"slices", L"original200", L"validated"}) {
				DRIVERCRATE_EXPECT( context, old.GetNamedValue( field).Stringify() ==
												cache.GetNamedValue( field).Stringify()) ;
			}
		}

		// 部分開始の中断RESPONSE・全準備・登録／四反映／確定を独立再読込みします。
		for( std::size_t window = 0U; window < windows.size(); ++window) {
			LocalCollectorStateStore resumed ;	// 一窓の実保存rawだけを使用します。
			DRIVERCRATE_EXPECT( context, resumed.initialize( rootFactory(), true) == 0U) ;
			// 期待後像を保存せず停止直後の元全rawだけを複製します。
			for( const auto &[name, raw] : windows[window]) {
				DRIVERCRATE_EXPECT( context, resumed.write( name, raw) == 0U) ;
			}

			{
				LocalCollectorRecovery fresh ;	// 保存済み中断だけを先行復旧します。
				const DWORD			   expected =
					   withRunning ? ERROR_RETRY : ERROR_SUCCESS ;	// 残RUNNINGは自動精算しません。
				const auto code = fresh.initializeProjected( resumed, next, utc + 9000U,
															0U) ;	// 元acceptedは6000です。
				context.expect( code == expected && fresh.terminalJobs() == 1U,
							   "partial saved window scenario=" + std::to_string( scenario) +
								   " window=" + std::to_string( window) +
								   " code=" + std::to_string( code),
							   __FILE__, __LINE__) ;
				// 別groupの残予約は別の明示入口からだけ中断します。
				if( withRunning && code == expected) {
					DRIVERCRATE_EXPECT( context, fresh.recoverNextProjectedReservations(
													utc + 10000U, 1000U) == 0U &&
													fresh.terminalJobs() == 2U) ;
				}
			}
			const auto recovered =
				// 元の部分中断証跡は不変です。
				projectedStoreSnapshot( context, resumed) ;
			// 残RUNNINGの新中断時計とROOT監督時計だけを元完走byteと区別します。
			for( const auto &[name, raw] : final) {
				// 全不変role、または元の部分中断に属する応答／全像／CACHEを比較します。
				if( name != L"current/campaign-root-v2.json" &&
				   (!withRunning || name == responseName || name == cacheName ||
					name.starts_with( L"runs/campaign-effect-v2-" + op))) {
					DRIVERCRATE_EXPECT( context,
									   recovered.contains( name) && recovered.at( name) == raw) ;
				}
			}

			// 旧完了・shard・summary・pointerを保存途中復旧でも変更しません。
			for( const auto &[name, raw] : original) {
				// 共有現在台帳は今回更新対象なので旧値比較の対象へ含めません。
				if( name.starts_with( L"runs/") || name.starts_with( L"current/campaign-state-v3-") ||
				   name == L"current/campaign-current-v2.json") {
					DRIVERCRATE_EXPECT( context,
									   recovered.contains( name) && recovered.at( name) == raw) ;
				}
			}

			{
				LocalCollectorRecovery twice ;	// 確定後の二回目起動は非変更です。
				DRIVERCRATE_EXPECT(
					context, twice.initializeProjected( resumed, next, utc + 12000U, 0U) == 0U &&
								 recovered == projectedStoreSnapshot( context, resumed)) ;
			}
		}

		// 部分開始なしで共有予算時計だけ先行した場合は、専用flagでも拒否します。
		{
			LocalCollectorStateStore unproven ;	// 未予約の元末尾だけを使う独立root。
			DRIVERCRATE_EXPECT( context, unproven.initialize( rootFactory(), true) == 0U) ;
			// 開始済みreservationやintentは一つも生成しません。
			for( const auto &[name, raw] : notStarted) {
				DRIVERCRATE_EXPECT( context, unproven.write( name, raw) == 0U) ;
			}

			mutateProjectedStore(
				context, unproven, L"current/campaign-budget-v1.json", [utc]( JsonObject &value) {
					value.Insert( L"lastUtc", JsonValue::CreateNumberValue(
												 static_cast<double>( (utc + 1000U) / 1000U))) ;
				}) ;
			const auto before =
				// 全byte非変更拒否の正本。
				projectedStoreSnapshot( context, unproven) ;
			LocalCollectorRecovery refusal ;	// 専用flagだけの無条件許可を検査します。
			const auto			   code =
				// 全閉包検査後の13。
				refusal.initializeProjected( unproven, next, utc + 9000U, 0U) ;
			context.expect( code == ERROR_INVALID_DATA &&
							   before == projectedStoreSnapshot( context, unproven),
						   "partial unproven clock scenario=" + std::to_string( scenario) +
							   " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
		}
		// 開始prefixの外側hashを再計算した改変も、通常起動で全保存前拒否します。
		for( unsigned mutation = 0U; mutation < 11U; ++mutation) {
			LocalCollectorStateStore rejected ;	// 各一要因は独立保護rootです。
			DRIVERCRATE_EXPECT( context, rejected.initialize( rootFactory(), true) == 0U) ;
			// 復旧前の部分開始だけを複製します。
			for( const auto &[name, raw] : interruptedStart) {
				DRIVERCRATE_EXPECT( context, rejected.write( name, raw) == 0U) ;
			}

			// 予算とPENDINGの関係、要求外CACHEと未知名を個別に破ります。
			if( mutation < 4U) {
				mutateProjectedStore(
					context, rejected, L"current/campaign-budget-v1.json",
					[mutation]( JsonObject &value) {
						const auto rows =
							// 最後の元予約だけを変更します。
							value.GetNamedArray( L"reservations") ;
						const auto row = rows.GetObjectAt( rows.Size() - 1U) ;	// 検査される一prefix。
						// 別groupは同じ元jobの予算として受理しません。
						if( mutation == 0U) {
							row.Insert( L"group",
									   JsonValue::CreateStringValue( L"fixture-other-group")) ;
						}
						// 最大量不一致を返金や成功精算へ読み替えません。
						else if( mutation == 1U) {
							row.Insert( L"maximum", JsonValue::CreateNumberValue( 1.0)) ;
						}
						// 元秒予約の最高時計を別時刻へ変更しません。
						else if( mutation == 2U) {
							value.Insert( L"lastUtc", JsonValue::CreateNumberValue(
														 value.GetNamedNumber( L"lastUtc") + 1.0)) ;
						} else {
							row.Insert( L"phase", JsonValue::CreateNumberValue( 1.0)) ;
						}
					}) ;
			}
			// PENDING以外の延期を部分開始として精算しません。
			else if( mutation == 4U) {
				mutateProjectedStore(
					context, rejected, stateName, [partialIndex]( JsonObject &value) {
						const auto row = value.GetNamedArray( L"jobs").GetObjectAt(
							// 元PENDING。
							static_cast<std::uint32_t>( partialIndex)) ;
						row.Insert( L"state", JsonValue::CreateStringValue( L"DEFERRED")) ;
						row.Insert( L"reason", JsonValue::CreateStringValue( L"DAY_CLOSED")) ;
					}) ;
			}
			// 当request以外の旧成功CACHEも検査対象です。
			else if( mutation == 5U) {
				mutateProjectedStore(
					context, rejected,
					L"current/campaign-cache-v1-" + identity.jobs[1].requestKey + L".json",
					[]( JsonObject &value) {
						value.Insert( L"reason", JsonValue::CreateStringValue( L"INTERRUPTED")) ;
					}) ;
			}
			// 未知campaign名を参照なしのまま無視しません。
			else if( mutation == 6U) {
				saveRegisteredHistoryFixture( context, rejected,
											 L"runs/campaign-partial-unknown.json", "{}") ;
			}
			// 二prefixの時計範囲より先の共有CONTROLは受理しません。
			else if( mutation == 7U) {
				mutateProjectedStore( context, rejected, L"current/campaign-controls-v1.json",
									 [started]( JsonObject &value) {
										 value.Insert( L"lastUtc",
													  JsonValue::CreateNumberValue(
														  static_cast<double>( started + 1001U))) ;
									 }) ;
			}
			// PENDINGの欠測時計を任意開始値へ補完した保存は拒否します。
			else if( mutation == 8U) {
				mutateProjectedStore( context, rejected, stateName,
									 [partialIndex]( JsonObject &value) {
										 value.GetNamedArray( L"jobs")
											 .GetObjectAt( static_cast<std::uint32_t>( partialIndex))
											 .Insert( L"started", JsonValue::CreateNumberValue( 1.0)) ;
									 }) ;
			}
			// 単一writerの保存順で生成できない複数部分開始を認めません。
			else if( mutation == 9U) {
				// 先行RUNNINGをPENDINGへ変更した場合も最終予約条件を維持します。
				if( withRunning) {
					mutateProjectedStore( context, rejected, stateName, []( JsonObject &value) {
						const auto row = value.GetNamedArray( L"jobs").GetObjectAt(
							0U) ;	// 先行予約を部分開始へ改変します。
						row.Insert( L"state", JsonValue::CreateStringValue( L"PENDING")) ;
						row.Insert( L"started", JsonValue::CreateNumberValue( 0.0)) ;
						row.Insert( L"intent", JsonValue::CreateNullValue()) ;
					}) ;
				} else {
					mutateProjectedStore(
						context, rejected, L"current/campaign-budget-v1.json",
						[&]( JsonObject &value) {
							const auto rows = value.GetNamedArray(
								L"reservations") ;	// 元の末尾に別PENDING予約を加えます。
							const auto row = JsonObject::Parse(
								// 型付き元fieldを保持します。
								rows.GetObjectAt( 0U).Stringify()) ;
							row.Insert( L"job",
									   JsonValue::CreateStringValue( nextIdentity.jobs[1].jobKey)) ;
							row.Insert( L"group", JsonValue::CreateStringValue(
													 next.sources[1].rateLimitGroup)) ;
							row.Insert( L"maximum", JsonValue::CreateNumberValue( static_cast<double>(
													   next.sources[1].maximumResponseBytes))) ;
							row.Insert( L"charged", row.GetNamedValue( L"maximum")) ;
							rows.Append( row) ;
						}) ;
				}
			} else {
				mutateProjectedStore( context, rejected, L"current/campaign-controls-v1.json",
									 [&]( JsonObject &value) {
										 // 旧reviewを解除して部分開始を許す経路は作りません。
										 for( const auto &entry : value.GetNamedArray( L"controls")) {
											 const auto row =
												 // 当groupの既存共有行だけを変更します。
												 entry.GetObject() ;
											 // 元group reviewを持つ開始prefixは通常選択でも生成できません。
											 if( row.GetNamedString( L"request").empty() &&
												row.GetNamedString( L"group") ==
													next.sources[partialIndex].rateLimitGroup) {
												 row.Insert( L"review",
															JsonValue::CreateBooleanValue( true)) ;
											 }
										 }
									 }) ;
			}

			const auto before = projectedStoreSnapshot( context, rejected) ;	// 拒否前の全byte。
			LocalCollectorRecovery refusal ;									// 全履歴検査が終わるまで共有保存を行いません。
			const auto			   code =
				// 原13。
				refusal.initializeProjected( rejected, next, utc + 9000U, 0U) ;
			context.expect(
				code == ERROR_INVALID_DATA && before == projectedStoreSnapshot( context, rejected),
				"partial start refusal scenario=" + std::to_string( scenario) +
					" mutation=" + std::to_string( mutation) + " code=" + std::to_string( code),
				__FILE__, __LINE__) ;
		}
	}
}

/** @see local_collector_http_tests.h */
void runCollectorCacheGrowthTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory,
	const bool capacityGrowth, const bool startupBoundary)
{
	// 独立の通常起動境界を旧小規模fixtureとして実行しません。
	if( startupBoundary && !capacityGrowth) {
		DRIVERCRATE_EXPECT( context, false) ;
		return ;
	}

	const CacheStartupObservation observation( startupBoundary) ;	// このmodeだけの親時計です。
	const auto					  caseStarted =
		// cleanup・process終端は含みません。
		observation.begin( "case_body", 0U, 0U) ;
	const auto fixtureStarted =
		// 初回四fake要求の準備前。
		observation.begin( "fixture_prepare", 0U, 0U) ;
	const auto original = definitionFactory() ;								// 元source・policy・artifactを維持します。
	LocalCollectorStateStore store ;										// この二世代だけの保護領域です。
	const auto storeInitialized = store.initialize( rootFactory(), true) ;	// 元の初期化codeです。
	context.expect( storeInitialized == 0U,
				   "cache growth store initialize=" + std::to_string( storeInitialized), __FILE__,
				   __LINE__) ;
	std::map<std::wstring, std::string> preserved ;	// 旧CACHEと応答の全rawを保持します。
	auto		  tailDefinition = original ;		// 未受領末尾の再起動に渡す元定義です。
	std::size_t	  sends{} ;							// Native HTTPではなくfake tableの呼出し数です。
	std::uint64_t lastUtc{} ;						// 二世代目の固定UTCです。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		firstCampaign ;	// 容量枠だけ初回の不変入力を保持します。
	// 別の四公開製品を各世代に用意し、旧requestを再利用しません。
	for( std::size_t generation = 0U; generation < 2U; ++generation) {
		auto definition = original ;	// 全source権限と予算は同じです。
		auto manifest =
			// 元schemaです。
			JsonObject::Parse( winrt::to_hstring( original.manifestBytes)) ;
		const auto asusTarget =
			// 元公開ASUS形です。
			manifest.GetNamedArray( L"targets").GetObjectAt( 26U) ;
		const auto asusJob = manifest.GetNamedArray( L"jobs").GetObjectAt( 1U) ;	// 元ASUS契約です。
		const auto intelTarget =
			// 固定Intel対象です。
			manifest.GetNamedArray( L"targets").GetObjectAt( 0U) ;
		const auto intelJob =
			// 727998以外を作りません。
			manifest.GetNamedArray( L"jobs").GetObjectAt( 0U) ;
		JsonArray		  targets ;									// この世代の公開対象を元順序で保持します。
		JsonArray		  jobs ;									// ASUS四件と次回だけ未受領二件を並べます。
		const std::size_t asusCount = generation == 0U ? 4U : 5U ;	// 最後の一件は送信しません。
		// 型番は全て架空で、実製品対応数へ加えません。
		for( std::size_t index = 0U; index < asusCount; ++index) {
			const auto id = L"growth" + std::to_wstring( generation) + L"-" +
							// 公開参照です。
							std::to_wstring( index) ;
			const auto model = L"Fictional Growth Board " + std::to_wstring( generation) + L"-" +
							   // 独立公開locatorです。
							   std::to_wstring( index) ;
			auto target = JsonObject::Parse( asusTarget.Stringify()) ;	// 元対象の独立copyです。
			target.Insert( L"id", JsonValue::CreateStringValue( id)) ;
			target.Insert( L"model", JsonValue::CreateStringValue( model)) ;
			targets.Append( target) ;
			auto job = JsonObject::Parse( asusJob.Stringify()) ;	// 元policyを維持します。
			job.Insert( L"locator", JsonValue::CreateStringValue( model)) ;
			JsonArray references ;	// 一jobと一公開対象だけを結びます。
			references.Append( JsonValue::CreateStringValue( id)) ;
			job.Insert( L"targets", references) ;
			jobs.Append( job) ;
		}

		// 別groupの二番目の未受領枠は既存Intel familyだけを使います。
		if( generation != 0U) {
			targets.Append( intelTarget) ;
			auto	  job = JsonObject::Parse( intelJob.Stringify()) ;	// 元Intel入力の独立copyです。
			JsonArray references ;										// 元一対象だけです。
			references.Append( intelTarget.GetNamedValue( L"id")) ;
			job.Insert( L"targets", references) ;
			jobs.Append( job) ;
		}

		manifest.Insert( L"targets", targets) ;
		manifest.Insert( L"jobs", jobs) ;
		definition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		const auto utc =
			HTTP_TEST_UTC + generation * 2U * 86400000ULL ;				// 旧24時間待機を満たします。
		const auto day = generation == 0U ? L"20260927" : L"20260929" ;	// 元固定時計と一致します。
		CollectorProjectedCampaignIdentity identity ;					// 本番inputを再構築します。
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
				   campaign ;	// 所有workerへ渡す不変入力です。
		const bool prepared =	// 元identity・sourceへ不変入力を結合した結果です。
			makeCollectorProjectedCampaignIdentity( definition, day, identity) &&
			prepareCollectorProjectedCampaign( identity.canonicalInput, identity.inputSha256,
											  identity.generationKey, definition.artifactSha256,
											  definition.sources, campaign) ;
		DRIVERCRATE_EXPECT( context, prepared && campaign && campaign->jobCount() == jobs.Size()) ;
		// 不成立入力を本番workerへ渡しません。
		if( !prepared || !campaign) {
			return ;
		}

		LocalCollectorRecovery owner ;	// 世代ごとに借用を解放する単一writerです。
		const auto			   initialized =
			// 元閉包を検査します。
			owner.initializeProjected( store, definition, utc, 0U) ;
		const auto begun = initialized == 0U && generation != 0U
							   ? owner.beginNextProjected( definition, utc, 1000U)
							   : initialized ;	// 初回は通常初期化です。
		context.expect( initialized == 0U && begun == 0U,
					   "cache growth generation=" + std::to_string( generation) + " initialize=" +
						   std::to_string( initialized) + " begin=" + std::to_string( begun),
					   __FILE__, __LINE__) ;
		// 元拒否を成功履歴へ読み替えません。
		if( initialized != 0U || begun != 0U) {
			return ;
		}

		// 先頭四件だけを予約・所有worker・公式parser・親受領で保存します。
		for( std::size_t index = 0U; index < 4U; ++index) {
			const auto offset = 3000U + index * 20000U ;	// 同groupの二秒待機を満たします。
			IoFixture  fixture ;							// Native DNS／HTTPを使わない明示依存です。
			fixture.clock = {utc + offset, offset} ;
			fixture.body  = winrt::to_string( winrt::hstring( projectedAsusRowsHtml( 1U))) ;
			const auto position =
				// 元fakeの公開modelです。
				fixture.body.find( "ProArt X870E-CREATOR WIFI") ;
			DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
			// 元本文の欠損を架空のparser成功へ補完しません。
			if( position == std::string::npos) {
				return ;
			}

			fixture.body.replace(
				position, std::string_view( "ProArt X870E-CREATOR WIFI").size(),
				winrt::to_string( jobs.GetObjectAt( static_cast<std::uint32_t>( index))
									 .GetNamedString( L"locator"))) ;
			CollectorProjectedExecutorDependencies dependencies ;	// Joinまでこのscopeが所有します。
			dependencies.campaign = campaign ;
			// 同じ二時計です。
			dependencies.clock		  = [&fixture] { return fixture.clock ; } ;
			dependencies.createClient = [] {
				return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
			} ; // Native factoryを呼びません。
			dependencies.start = [&]( std::function<void()> worker) {
				return std::thread( [&, worker = std::move( worker)] {
					fixture.ownerThread = std::this_thread::get_id() ;
					FixtureScope scope( fixture) ;	// 当workerだけのfake依存登録です。
					worker() ;
				}) ;
			} ; // Scope終了前に全workerを回収します。
			LocalCollectorProjectedExecutor executor(
				// 元所有予約経路です。
				std::move( dependencies)) ;
			const auto started = executor.startNext( owner) ;	// 本番全履歴照合後の予約です。
			const auto joined  = executor.join() ;				// 保存前に資源を回収します。
			const auto accepted =
				started == 0U
					? (generation == 0U ? owner.acceptInitialProjected(
											  executor, 0U, utc + offset + 1000U, offset + 1000U)
										: owner.acceptNextProjected(
											  executor, 0U, utc + offset + 1000U, offset + 1000U))
					: started ;	// 元所有値だけです。
			context.expect( started == 0U && accepted == 0U && joined.error == 0U &&
							   joined.joined == 1U && fixture.calls["send"] == 1U,
						   "cache growth receipt=" + std::to_string( sends) + " start=" +
							   std::to_string( started) + " accept=" + std::to_string( accepted),
						   __FILE__, __LINE__) ;
			// 失敗の以降を正常受領として進めません。
			if( started != 0U || accepted != 0U || joined.error != 0U) {
				return ;
			}

			sends += fixture.calls["send"] ;
		}

		const auto saved = projectedStoreSnapshot( context, store) ;	// この時点の全rawです。
		const auto root	 = JsonObject::Parse( winrt::to_hstring(
			 // 登録inventoryです。
			 httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
		DRIVERCRATE_EXPECT( context,
						   root.GetNamedArray( L"cacheInventory").Size() == (generation + 1U) * 4U) ;
		// 新requestの受領は旧CACHE／応答のbyteを変えません。
		for( const auto &[name, raw] : preserved) {
			DRIVERCRATE_EXPECT( context, saved.contains( name) && saved.at( name) == raw) ;
		}

		// 全八受領を後続の未受領精算から保護します。
		for( const auto &[name, raw] : saved) {
			// 当経路で旧受領として保持すべき二種類だけを所有します。
			if( name.starts_with( L"current/campaign-cache-v1-") ||
			   name.starts_with( L"runs/campaign-response-v4-")) {
				preserved.emplace( name, raw) ;
			}
		}

		// 初回だけ全jobを閉じ、次回は末尾二件を予約したまま解放します。
		if( generation == 0U) {
			DRIVERCRATE_EXPECT( context, owner.finishInitialProjected( utc + 400000U, 400000U) == 0U) ;
			// 容量枠は元writer借用をscope終了で解放してから合成履歴へ進みます。
			if( capacityGrowth) {
				firstCampaign  = campaign ;
				tailDefinition = definition ;
				break ;
			}
		} else {
			CollectorHttpClockSample sample{utc + 300000U, 300000U} ;	// 既存受領より後です。
			CollectorHttpPermitPool	 pool(
				 [&sample] { return sample ; }) ;			// HTTPへ渡さない予約入口です。
			std::array<CollectorHttpPermit, 2U> pending ;	// 異なるgroupの未受領二枠です。
			// 新ASUSと未登録Intelは正常な未受領requestとして保持します。
			for( std::size_t index = 0U; index < pending.size(); ++index) {
				sample = {utc + 300000U + index * 1000U, 300000U + index * 1000U} ;
				DRIVERCRATE_EXPECT( context, pool.reserveProjected( owner, pending[index]) == 0U &&
												pending[index].present()) ;
			}

			const auto waiting =
				// 全二開始intentの正本です。
				projectedStoreSnapshot( context, store) ;
			CollectorHttpPermit excess ;	// 両groupの稼働中は新しい許可を発行しません。
			DRIVERCRATE_EXPECT( context, pool.reserveProjected( owner, excess) == ERROR_RETRY &&
											!excess.present() && owner.lastError() == 0U &&
											sends == 8U &&
											waiting == projectedStoreSnapshot( context, store)) ;
			const auto pendingRoot = JsonObject::Parse( winrt::to_hstring( httpSavedBody(
				store, L"current/campaign-root-v2.json"))) ;	// CACHEを先行捏造しません。
			DRIVERCRATE_EXPECT( context, pendingRoot.GetNamedArray( L"cacheInventory").Size() == 8U) ;
			tailDefinition = definition ;
			lastUtc		   = utc ;
		}

		std::cout << "Cache growth received=" << sends << " cache=" << (generation + 1U) * 4U
				  << std::endl ;
	}

	// 既存八受領・二中断の分母へ容量枠を混入させません。
	if( capacityGrowth) {
		DRIVERCRATE_EXPECT( context, sends == 4U && firstCampaign) ;
		observation.end( "fixture_prepare", 1U, sends, fixtureStarted) ;
		operationCapacityFixture( context, store, tailDefinition, firstCampaign, true,
								 startupBoundary, &observation) ;
		// 旧段階試験の分母は増やさず、新枠だけで全送信数を再照合します。
		if( startupBoundary) {
			DRIVERCRATE_EXPECT( context, sends == 4U) ;
		}

		observation.end( "case_body", 0U, 0U, caseStarted) ;
		return ;
	}

	{
		const auto before = projectedStoreSnapshot( context, store) ;	// 未受領二枠の全rawです。
		LocalCollectorRecovery recovered ;								// 元借用を持たない再起動監督です。
		const auto			   initialized = recovered.initializeProjected(
			store, tailDefinition, lastUtc + 402000U, 0U) ;	// 通常起動は非変更待機です。
		DRIVERCRATE_EXPECT( context, initialized == ERROR_RETRY && recovered.lastError() == 0U &&
										recovered.reason() == L"HISTORY_ACCEPTANCE_PENDING" &&
										before == projectedStoreSnapshot( context, store)) ;
		const auto settled =
			initialized == ERROR_RETRY
				? recovered.recoverNextProjectedReservations( lastUtc + 403000U, 1000U)
				: initialized ;	// 明示中断だけです。
		context.expect( settled == 0U && recovered.terminalJobs() == 6U,
					   "cache growth settlement=" + std::to_string( settled), __FILE__, __LINE__) ;
		// 元拒否を正常CACHE増加へ変更しません。
		if( settled != 0U) {
			return ;
		}

		const auto stable = projectedStoreSnapshot( context, store) ;	// CACHE10件の精算済みrawです。
		const auto root	  = JsonObject::Parse( winrt::to_hstring(
			  // 実登録inventoryです。
			  httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
		DRIVERCRATE_EXPECT( context,
						   root.GetNamedArray( L"cacheInventory").Size() == 10U && sends == 8U) ;
		const auto v4 = std::count_if( stable.begin(), stable.end(), []( const auto &entry) {
			return entry.first.starts_with( L"runs/campaign-response-v4-") ;
		}) ; // 八成功の実保存だけを数えます。
		const auto v2 = std::count_if( stable.begin(), stable.end(), []( const auto &entry) {
			return entry.first.starts_with( L"runs/campaign-response-v2-") ;
		}) ; // 中断二件を成功へ合算しません。
		DRIVERCRATE_EXPECT( context, v4 == 8 && v2 == 2 &&
										recovered.recoverNextProjectedReservations(
											lastUtc + 404000U, 2000U) == 0U &&
										stable == projectedStoreSnapshot( context, store)) ;
		// 新中断の保存も元八CACHE／応答を更新しません。
		for( const auto &[name, raw] : preserved) {
			DRIVERCRATE_EXPECT( context, stable.contains( name) && stable.at( name) == raw) ;
		}
	}
	{
		LocalCollectorRecovery finished ;								// CACHE10件の正常全閉包を別監督で検査します。
		const auto before = projectedStoreSnapshot( context, store) ;	// 再起動前の正本です。
		const auto initialized =
			finished.initializeProjected( store, tailDefinition, lastUtc + 405000U,
										 0U) ;	// 再読込みは非変更です。
		DRIVERCRATE_EXPECT( context, initialized == 0U && finished.terminalJobs() == 6U &&
										before == projectedStoreSnapshot( context, store)) ;
		const auto closed = initialized == 0U
								? finished.finishNextProjected( lastUtc + 406000U, 1000U)
								: initialized ;	// 全末尾を閉じます。
		context.expect( closed == 0U, "cache growth finish=" + std::to_string( closed), __FILE__,
					   __LINE__) ;
		// 元完了の不成立を完了後の再読込みで隠しません。
		if( closed != 0U) {
			return ;
		}
	}
	const auto completed = projectedStoreSnapshot( context, store) ;	// 全末尾完了の正本です。
	LocalCollectorRecovery reread ;										// 完了writer借用を解放した別監督です。
	DRIVERCRATE_EXPECT(
		context, reread.initializeProjected( store, tailDefinition, lastUtc + 407000U, 0U) == 0U &&
					 completed == projectedStoreSnapshot( context, store)) ;
	// 全完了の再読込み後も旧八CACHE／応答のbyteを保持します。
	for( const auto &[name, raw] : preserved) {
		DRIVERCRATE_EXPECT( context, completed.contains( name) && completed.at( name) == raw) ;
	}

	CollectorStoreUsage usage ;	// 保存量でありreader累積量ではありません。
	DRIVERCRATE_EXPECT( context, store.inspectUsage( usage) == 0U) ;
	std::cout << "Cache growth cache=10 v4=8 v2=2 sends=" << sends << " runs=" << usage.runEntries
			  << " current=" << usage.currentEntries << " bytes=" << usage.bytes << std::endl ;
}

/** @see local_collector_http_tests.h */
void runCollectorOperationHistoryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory,
	const bool													 capacityBoundary)
{
	auto			  definition = definitionFactory() ;			// 二sourceの契約とartifactを保持します。
	const std::size_t asusCount	 = capacityBoundary ? 3U : 15U ;	// 上限枠だけ小さい固定集合です。
	const std::size_t jobCount	 = asusCount + 1U ;					// Intel一要求を末尾へ残します。
	const std::size_t intelIndex = asusCount ;						// 偽本文を元sourceに対応させる固定位置。
	auto			  manifest =
		// 元公開schema。
		JsonObject::Parse( winrt::to_hstring( definition.manifestBytes)) ;
	JsonArray targets ;	// 固定架空ASUS製品と一Intel製品だけです。
	JsonArray jobs ;	// ASUS groupを先にし、未受領時の別group候補を残します。
	// 既存ASUS sourceへ異なる固定数の公開製品を渡します。実製品対応数には加えません。
	for( std::size_t index = 0U; index < asusCount; ++index) {
		const auto id	  = L"boundary" + std::to_wstring( index) ;						// Manifest内参照。
		const auto model  = L"Fictional Boundary Board " + std::to_wstring( index) ;	// 架空公開名。
		auto	   target = JsonObject::Parse(
			  // 独立所有コピー。
			  manifest.GetNamedArray( L"targets").GetObjectAt( 26U).Stringify()) ;
		target.Insert( L"id", JsonValue::CreateStringValue( id)) ;
		target.Insert( L"model", JsonValue::CreateStringValue( model)) ;
		targets.Append( target) ;
		auto job = JsonObject::Parse(
			// 元ASUS契約。
			manifest.GetNamedArray( L"jobs").GetObjectAt( 1U).Stringify()) ;
		job.Insert( L"locator", JsonValue::CreateStringValue( model)) ;
		JsonArray references ;	// このjobの一製品だけを参照します。
		references.Append( JsonValue::CreateStringValue( id)) ;
		job.Insert( L"targets", references) ;
		jobs.Append( job) ;
	}

	targets.Append( manifest.GetNamedArray( L"targets").GetObjectAt( 0U)) ;
	auto	  intelJob = manifest.GetNamedArray( L"jobs").GetObjectAt( 0U) ;	// 同じ固定landing。
	JsonArray intelReferences ;													// 小さい一対象scopeで保存操作数と応答量を分けます。
	intelReferences.Append( JsonValue::CreateStringValue( L"intel0")) ;
	intelJob.Insert( L"targets", intelReferences) ;
	jobs.Append( intelJob) ;
	manifest.Insert( L"targets", targets) ;
	manifest.Insert( L"jobs", jobs) ;
	definition.manifestBytes = winrt::to_string( manifest.Stringify()) ;
	LocalCollectorStateStore store ;	// このfixtureだけの保護領域。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
	std::size_t	  sends{} ;		// 偽HTTPの実送信数。予約数とは別です。
	std::size_t	  received{} ;	// 本番受領入口で保存済みの操作数。
	std::uint64_t lastUtc{} ;	// 最終世代の固定時計。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		firstCampaign ;	// 合成境界だけが元入力を保持します。
	// 二日離した初回と次回だけを処理し、24時間待機やreviewを変更しません。
	for( std::size_t generation = 0U; generation < 2U; ++generation) {
		const auto utc	= HTTP_TEST_UTC + generation * 2U * 86400000ULL ;	// 秒単位の元予約時計。
		const auto date = std::chrono::year_month_day(
			std::chrono::floor<std::chrono::days>( std::chrono::sys_time<std::chrono::milliseconds>(
				// 本番と同じJST開始日。
				std::chrono::milliseconds( utc + 9U * 3600000ULL)))) ;
		const auto month	= static_cast<unsigned>( date.month()) ;	// 1～12。
		const auto day		= static_cast<unsigned>( date.day()) ;		// 実在日付。
		const auto startDay = std::to_wstring( static_cast<int>( date.year())) +
							  (month < 10U ? L"0" : L"") + std::to_wstring( month) +
							  (day < 10U ? L"0" : L"") + std::to_wstring( day) ;	// YYYYMMDD。
		CollectorProjectedCampaignIdentity identity ;								// 同じ16 request・異なる開始日。
		std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;		// 全job所有入力。
		const bool												  prepared =
			makeCollectorProjectedCampaignIdentity( definition, startDay, identity) &&
			prepareCollectorProjectedCampaign( identity.canonicalInput, identity.inputSha256,
											  identity.generationKey, definition.artifactSha256,
											  definition.sources, campaign) ;	// 本番builderの結果。
		DRIVERCRATE_EXPECT( context, prepared && campaign && campaign->jobCount() == jobCount) ;
		// 不成立入力を後続workerへ渡しません。
		if( !prepared || !campaign || campaign->jobCount() != jobCount) {
			return ;
		}

		LocalCollectorRecovery owner ;	// 一世代の単一writer。
		const auto			   initialized =
			// 全旧履歴を先行検査。
			owner.initializeProjected( store, definition, utc, 0U) ;
		const auto begun = initialized == 0U && generation != 0U
							   ? owner.beginNextProjected( definition, utc, 1000U)
							   : initialized ;	// 初回は通常初期化だけ。
		context.expect( initialized == 0U && begun == 0U,
					   "operation boundary generation=" + std::to_string( generation) +
						   " initialize=" + std::to_string( initialized) +
						   " begin=" + std::to_string( begun),
					   __FILE__, __LINE__) ;
		// 先行容量の拒否を操作上限の合格へ読み替えません。
		if( initialized != 0U || begun != 0U) {
			return ;
		}

		const std::size_t count =
			// 初回全件＋次回一件の本番受領。
			generation == 0U ? jobCount : 1U ;
		// 一jobずつ所有workerを回収・受領し、同group並行送信は行いません。
		for( std::size_t index = 0U; index < count; ++index) {
			const auto offset = 3000U + index * 20000U ;	// 二秒間隔以上かつbatch一時間未満。
			IoFixture  fixture ;							// 全HTTPとDNSの明示fake依存。
			fixture.clock = {utc + offset, offset} ;
			fixture.body  = winrt::to_string( winrt::hstring(
				 index == intelIndex ? projectedIntelHtml() : projectedAsusRowsHtml( 1U))) ;
			// 同じ偽本文内の公開modelを元ASUS locatorへ一致させます。
			if( index != intelIndex) {
				const auto position =
					// 元固定model一件。
					fixture.body.find( "ProArt X870E-CREATOR WIFI") ;
				DRIVERCRATE_EXPECT( context, position != std::string::npos) ;
				fixture.body.replace(
					position, std::string_view( "ProArt X870E-CREATOR WIFI").size(),
					winrt::to_string( jobs.GetObjectAt( static_cast<std::uint32_t>( index))
										 .GetNamedString( L"locator"))) ;
			}

			CollectorProjectedExecutorDependencies
				dependencies ;	// 全joinまでこのscopeが所有します。
			dependencies.campaign = campaign ;
			// 親とworkerの固定二時計。
			dependencies.clock		  = [&fixture] { return fixture.clock ; } ;
			dependencies.createClient = [] {
				return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
			} ; // Native factory未使用。
			dependencies.start = [&]( std::function<void()> worker) {
				return std::thread( [&, worker = std::move( worker)] {
					fixture.ownerThread = std::this_thread::get_id() ;
					FixtureScope scope( fixture) ;	// Thread別fakeを所有します。
					worker() ;
				}) ;
			} ; // このscope内の一workerだけに借用します。
			LocalCollectorProjectedExecutor executor(
				// 四slotの既存所有者。
				std::move( dependencies)) ;
			const auto started = executor.startNext( owner) ;	// 本番予約・全履歴検査後だけ起動。
			const auto joined  = executor.join() ;				// 全資源回収後だけ保存します。
			const auto accepted =
				started == 0U
					? (generation == 0U ? owner.acceptInitialProjected(
											  executor, 0U, utc + offset + 1000U, offset + 1000U)
										: owner.acceptNextProjected(
											  executor, 0U, utc + offset + 1000U, offset + 1000U))
					: started ;	// 元所有結果以外を渡しません。
			context.expect( started == 0U && accepted == 0U && joined.error == 0U &&
							   joined.joined == 1U && fixture.calls["send"] == 1U,
						   "operation boundary received=" + std::to_string( received) + " start=" +
							   std::to_string( started) + " accept=" + std::to_string( accepted),
						   __FILE__, __LINE__) ;
			// 元失敗を保持して以降の予約を停止します。
			if( started != 0U || accepted != 0U || joined.error != 0U) {
				return ;
			}

			sends += fixture.calls["send"] ;
			++received ;
		}

		// 既存の完了APIを通し、日次archiveと元完了像も全て保存します。
		if( generation == 0U) {
			const auto closed =
				generation == 0U
					? owner.finishInitialProjected( utc + 400000U, 400000U)
					: owner.finishNextProjected( utc + 400000U, 400000U) ;	// 同日・全job終端。
			DRIVERCRATE_EXPECT( context, closed == 0U) ;
			// 完了不成立の世代を次回開始へ流用しません。
			if( closed != 0U) {
				return ;
			}

			std::cout << "Operation history received=" << received
					  << " generations=" << generation + 1U << std::endl ;
			// 操作上限専用枠は初回完了だけを基準にし、writer借用を解放してから組み立てます。
			if( capacityBoundary) {
				firstCampaign = campaign ;
				break ;
			}

			continue ;
		}

		const auto root				 = JsonObject::Parse( winrt::to_hstring(
			 // 元登録簿。
			 httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
		const auto beforeReservation = projectedStoreSnapshot( context, store) ;	// 正常17操作全raw。
		DRIVERCRATE_EXPECT( context, received == 17U && sends == 17U &&
										root.GetNamedArray( L"cacheInventory").Size() == 16U) ;
		CollectorHttpClockSample sample{utc + 300000U, 300000U} ;		// 先行受領後かつ同日内。
		CollectorHttpPermitPool	 pool( [&sample] { return sample ; }) ;	// HTTPに渡さない予約専用。
		CollectorHttpPermit		 pending ;								// 未受領のASUS一枠。
		DRIVERCRATE_EXPECT( context,
						   pool.reserveProjected( owner, pending) == 0U && pending.present()) ;
		const auto firstReserved =
			// 未受領開始だけ保存した元byte。
			projectedStoreSnapshot( context, store) ;
		sample = {utc + 301000U, 301000U} ;
		CollectorWaitSnapshot
			controls ;	// 別groupの恒久待機・review・開始intentを元保存から確認します。
		DRIVERCRATE_EXPECT(
			context, parseCollectorWaitSnapshot(
						 httpSavedBody( store, L"current/campaign-controls-v1.json"), controls)) ;
		const auto &intelControl =
			// 元Intel要求。
			controls.controls.at( L"r-" + campaign->job( 15U)->value().requestKey) ;
		DRIVERCRATE_EXPECT( context, !intelControl.review && intelControl.started == 0U &&
										intelControl.notBefore <= sample.utcMillis &&
										controls.controls.at( L"g-intel").completed + 2000U <=
											sample.utcMillis) ;
		CollectorHttpPermit otherGroup ;	// 元ASUS枠を消さずIntel一枠を追加できます。
		DRIVERCRATE_EXPECT( context,
						   pool.reserveProjected( owner, otherGroup) == 0U && otherGroup.present()) ;
		const auto reserved = projectedStoreSnapshot( context, store) ;	// 未受領二枠の全開始証跡。
		CollectorHttpPermit waiting ;									// 両group稼働中は追加許可を発行しません。
		DRIVERCRATE_EXPECT( context, pool.reserveProjected( owner, waiting) == ERROR_RETRY &&
										!waiting.present() && owner.lastError() == 0U &&
										sends == 17U && beforeReservation != firstReserved &&
										firstReserved != reserved &&
										reserved == projectedStoreSnapshot( context, store)) ;
		lastUtc = utc ;
	}

	// 独立CTestだけで合成操作閉包を検査し、元二世代の基礎fixtureは変更しません。
	if( capacityBoundary) {
		DRIVERCRATE_EXPECT( context, firstCampaign && received == jobCount && sends == jobCount) ;
		operationCapacityFixture( context, store, definition, firstCampaign) ;
		return ;
	}

	std::map<std::wstring, std::string> settled ;	// 二枠中断後の正本を次の独立監督へ渡します。
	{
		LocalCollectorRecovery restarted ;								// 元permit／workerを持ち越さない別監督。
		const auto before = projectedStoreSnapshot( context, store) ;	// 通常初期化は非変更待機です。
		const auto initialized = restarted.initializeProjected(
			store, definition, lastUtc + 303000U, 0U) ;	// 全17操作・未受領二枠を先行検査。
		std::cout << "Operation history restart=" << initialized
				  << " reason=" << winrt::to_string( restarted.reason()) << std::endl ;
		DRIVERCRATE_EXPECT( context, initialized == ERROR_RETRY &&
										restarted.reason() == L"HISTORY_ACCEPTANCE_PENDING" &&
										restarted.lastError() == 0U &&
										before == projectedStoreSnapshot( context, store)) ;
		const auto recovered =
			initialized == ERROR_RETRY
				? restarted.recoverNextProjectedReservations( lastUtc + 304000U, 1000U)
				: initialized ;	// 一回・非再送。
		DRIVERCRATE_EXPECT( context, recovered == 0U && sends == 17U) ;
		// 元の失敗を保存し不成立台帳を正常境界としません。
		if( initialized != ERROR_RETRY || recovered != 0U) {
			return ;
		}

		settled = projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT(
			context, restarted.recoverNextProjectedReservations( lastUtc + 305000U, 2000U) == 0U &&
						 settled == projectedStoreSnapshot( context, store)) ;
	}

	// 正常二回目起動も非変更で、旧成功と二件の中断応答を再送しません。
	LocalCollectorRecovery twice ;	// 先のwriter借用を解放後だけ起動します。
	DRIVERCRATE_EXPECT( context,
					   twice.initializeProjected( store, definition, lastUtc + 306000U, 0U) == 0U &&
						   settled == projectedStoreSnapshot( context, store) && sends == 17U) ;
	const auto v4 = std::count_if( settled.begin(), settled.end(), []( const auto &entry) {
		return entry.first.starts_with( L"runs/campaign-response-v4-") ;
	}) ; // 元受領済み応答の不変な17操作だけを数えます。
	const auto v2 = std::count_if( settled.begin(), settled.end(), []( const auto &entry) {
		return entry.first.starts_with( L"runs/campaign-response-v2-") ;
	}) ; // 新中断二件を観測済み送信へ読み替えません。
	DRIVERCRATE_EXPECT( context, v4 == 17U && v2 == 2U && twice.terminalJobs() == 3U) ;
	CollectorStoreUsage usage ;	// 現物保存量と保守的追加枠を別に確認します。
	DRIVERCRATE_EXPECT( context,
					   store.inspectUsage( usage) == 0U &&
						   checkCollectorProjectedCompletionCapacity( usage, 16U, 16U) == 0U) ;
	std::cout << "Operation history saved=19 pending=0 cache=16 fakeSends=" << sends
			  << " runs=" << usage.runEntries << " current=" << usage.currentEntries
			  << " bytes=" << usage.bytes << std::endl ;
}

/** @see local_collector_http_tests.h */
void runCollectorGenerationBoundaryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto				 definition = definitionFactory() ;	// 基準の二source定義。
	LocalCollectorStateStore store ;							// 専用保護root。実HTTPは呼びません。
	DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
	{
		LocalCollectorRecovery pending ;	// 未予約の初回世代だけを実APIで作ります。
		DRIVERCRATE_EXPECT( context,
						   pending.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
	}
	auto changed		   = definition ;	// 同日のartifact変更で元分母をDEFERREDへ閉じます。
	changed.artifactSha256 = std::wstring( 64U, L'b') ;
	{
		LocalCollectorRecovery deferred ;	// 応答・CACHE・予約を捏造しない基準完了。
		DRIVERCRATE_EXPECT(
			context,
			deferred.initializeProjected( store, changed, HTTP_TEST_UTC + 1000U, 0U) == 0U &&
				deferred.finishInitialProjected( HTTP_TEST_UTC + 2000U, 1000U) == 0U) ;
	}
	const auto baseline = projectedStoreSnapshot( context, store) ;	// 元全rawを保存します。
	auto	   root		= JsonObject::Parse( winrt::to_hstring(
		  // 初回root identity。
		  httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
	const auto first	= root.GetNamedArray( L"generations").GetObjectAt( 0U) ;	// 元一世代の登録形。
	const auto firstKey = std::wstring( first.GetNamedString( L"generation")) ;		// 実API由来の元G。
	DRIVERCRATE_EXPECT( context, root.GetNamedArray( L"cacheInventory").Size() == 0U) ;
	// 基準本文だけを借用し、各新像は所有copyで生成します。
	const auto body = [&]( const std::wstring &name) {
		return JsonObject::Parse(
			JsonObject::Parse( winrt::to_hstring( baseline.at( name))).GetNamedString( L"body")) ;
	} ;
	// 保存する実本文からSHAを計算し、自己宣言値を検証済みと扱いません。
	const auto digest = [&]( const std::string_view value) {
		std::wstring result ;	// 一本文の実SHA-256。
		DRIVERCRATE_EXPECT( context, computeBytesSha256( value, result) == 0U) ;
		return result ;
	} ;
	JsonArray registrations ;	// 異なる300 Gだけを登録します。
	registrations.Append( first) ;
	auto latest = definition ;	// 元日と最後の入力で再登録待機を測ります。
	// 299個の合成世代を有限生成し、基準と合わせ300件の正常閉包を作ります。
	for( unsigned index = 1U; index < 300U; ++index) {
		latest				  = definition ;
		latest.artifactSha256 = digest( "generation-boundary-" + std::to_string( index)) ;
		CollectorProjectedCampaignIdentity identity ;	// 本番算法で元入力・Gを作ります。
		DRIVERCRATE_EXPECT( context,
						   makeCollectorProjectedCampaignIdentity( latest, L"20260927", identity)) ;
		auto marker = body( L"runs/campaign-marker-v3-" + firstKey + L".json") ;	// 元順序のmarker形。
		auto state =
			// 未予約DEFERREDの二行。
			body( L"current/campaign-state-v3-" + firstKey + L".json") ;
		auto shard =
			// 全27対象のUNKNOWN分母。
			body( L"runs/campaign-targets-v1-" + firstKey + L".json") ;
		auto summary = body( L"runs/campaign-summary-v1-" + firstKey + L".json") ;	// 元固定集計。
		auto pointer = body( L"current/campaign-current-v2.json") ;					// 最終世代だけのpointer。
		auto finish	 = body( L"runs/campaign-finish-v1-" + firstKey + L".json") ;	// 固定元完了時刻。
		// 元field順を維持し、新しいGと実input hashだけへ結合します。
		for( auto *value : {&marker, &shard, &summary, &finish}) {
			value->Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
			value->Insert( L"inputHash", JsonValue::CreateStringValue( identity.inputSha256)) ;
		}

		state.Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
		const auto stateHash =
			// 元二行を含む全state hash。
			digest( winrt::to_string( state.Stringify())) ;
		const auto shardHash = digest( winrt::to_string( shard.Stringify())) ;	// 全分母の実hash。
		summary.Insert( L"stateHash", JsonValue::CreateStringValue( stateHash)) ;
		summary.Insert( L"targetShardHash", JsonValue::CreateStringValue( shardHash)) ;
		const auto summaryHash =
			// 一世代の全集計hash。
			digest( winrt::to_string( summary.Stringify())) ;
		pointer.Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
		pointer.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
		finish.Insert( L"stateHash", JsonValue::CreateStringValue( stateHash)) ;
		finish.Insert( L"targetShardHash", JsonValue::CreateStringValue( shardHash)) ;
		finish.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
		finish.Insert( L"pointerHash",
					  JsonValue::CreateStringValue( digest( winrt::to_string( pointer.Stringify())))) ;
		saveRegisteredHistoryFixture( context, store,
									 L"runs/campaign-input-v3-" + identity.generationKey + L".json",
									 identity.canonicalInput) ;
		// 固定名とcanonical envelopeへ全五像を保存します。marker自己宣言だけでは受入しません。
		for( const auto &[name, value] : std::array<std::pair<std::wstring, JsonObject>, 5U>{
				std::pair{L"runs/campaign-marker-v3-" + identity.generationKey + L".json", marker},
				std::pair{L"current/campaign-state-v3-" + identity.generationKey + L".json", state},
				std::pair{L"runs/campaign-targets-v1-" + identity.generationKey + L".json", shard},
				std::pair{L"runs/campaign-summary-v1-" + identity.generationKey + L".json",
						  summary},
				std::pair{L"runs/campaign-finish-v1-" + identity.generationKey + L".json",
						  finish}}) {
			saveRegisteredHistoryFixture( context, store, name, winrt::to_string( value.Stringify())) ;
		}

		auto registration = JsonObject::Parse( first.Stringify()) ;	// 元登録形の所有copy。
		registration.Insert( L"generation", JsonValue::CreateStringValue( identity.generationKey)) ;
		registration.Insert( L"inputHash", JsonValue::CreateStringValue( identity.inputSha256)) ;
		registration.Insert( L"summaryHash", JsonValue::CreateStringValue( summaryHash)) ;
		registrations.Append( registration) ;
		// 先頭・途中・最大300だけを受入し、生成途中の合成履歴を実収集と呼びません。
		if( index == 1U || index == 148U || index == 299U) {
			root.Insert( L"generations", registrations) ;
			saveRegisteredHistoryFixture( context, store, L"current/campaign-root-v2.json",
										 winrt::to_string( root.Stringify())) ;
			saveRegisteredHistoryFixture( context, store, L"current/campaign-current-v2.json",
										 winrt::to_string( pointer.Stringify())) ;
			const auto before = projectedStoreSnapshot( context, store) ;	// 全閉包の非変更正本。
			LocalCollectorRecovery inspector ;								// 全過去像を本番coreで検査します。
			const auto code = inspector.initializeProjected( store, latest, HTTP_TEST_UTC + 3000U,
															0U) ;	// 現日を変えません。
			context.expect( code == 0U && inspector.reason() == L"GENERATION_COMPLETE" &&
							   before == projectedStoreSnapshot( context, store),
						   "generation boundary count=" + std::to_string( index + 1U) +
							   " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
			// 不正な正例を次の成功fixtureへ読み替えず、原因をそのまま残します。
			if( code != 0U) {
				return ;
			}
		}
	}

	CollectorStoreUsage usage ;	// 実保存名とraw量を検査し、他容量拒否と混同しません。
	DRIVERCRATE_EXPECT( context, store.inspectUsage( usage) == 0U && usage.runEntries == 1500U &&
									usage.currentEntries < 4096U &&
									usage.bytes < 32ULL * 1024U * 1024U) ;
	std::cout << "Generation boundary: registrations=300 operations=0 caches=0 runs="
			  << usage.runEntries << " current=" << usage.currentEntries << " bytes=" << usage.bytes
			  << "\n" ;
	const auto before = projectedStoreSnapshot( context, store) ;	// 300件到達後の全raw。
	CollectorProjectedCampaignIdentity finalIdentity ;				// 最終Gの公開読取り用入力。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		finalCampaign ;	// 元日と全scopeの所有入力。
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( latest, L"20260927", finalIdentity) &&
						   prepareCollectorProjectedCampaign(
							   finalIdentity.canonicalInput, finalIdentity.inputSha256,
							   finalIdentity.generationKey, latest.artifactSha256, latest.sources,
							   finalCampaign)) ;
	std::shared_ptr<const CollectorRegisteredProjectedHistory>
		history ;	// 未予約なので成功contextを補いません。
	DRIVERCRATE_EXPECT( context, finalCampaign &&
									LocalCollectorRecovery::inspectRegisteredProjectedHistory(
										store, *finalCampaign->job( 0U), latest.sources,
										HTTP_TEST_UTC + 4000U, history) == ERROR_INVALID_DATA &&
									!history && before == projectedStoreSnapshot( context, store)) ;
	LocalCollectorRecovery owner ;	// 同一Gの非変更待機後に301番目だけを拒否します。
	DRIVERCRATE_EXPECT( context,
					   owner.initializeProjected( store, latest, HTTP_TEST_UTC + 4000U, 0U) == 0U &&
						   owner.beginNextProjected( latest, HTTP_TEST_UTC + 4000U, 1000U) ==
							   ERROR_RETRY &&
						   before == projectedStoreSnapshot( context, store)) ;
	latest.artifactSha256 = digest( "generation-boundary-new-301") ;
	DRIVERCRATE_EXPECT( context, owner.beginNextProjected( latest, HTTP_TEST_UTC + 5000U, 2000U) ==
										ERROR_TOO_MANY_NAMES &&
									owner.lastError() == ERROR_TOO_MANY_NAMES &&
									before == projectedStoreSnapshot( context, store)) ;
	DRIVERCRATE_EXPECT( context, owner.beginNextProjected( definition, HTTP_TEST_UTC + 6000U,
														 3000U) == ERROR_TOO_MANY_NAMES &&
									before == projectedStoreSnapshot( context, store)) ;
}

/** @see local_collector_http_tests.h */
void runCollectorFinishRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto definition = definitionFactory() ;	// 元二sourceの公開入力です。
	CollectorProjectedCampaignIdentity identity ;	// 元日と固定artifactへの結合です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		prepared ;	// 初回fake workerの所有入力です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, prepared)) ;
	// 入力不成立を架空の成功fixtureへ補完しません。
	if( !prepared) {
		return ;
	}

	LocalCollectorStateStore first ;	// 初回成功は本番parserと偽HTTPから作ります。
	DRIVERCRATE_EXPECT( context, first.initialize( rootFactory(), true) == 0U) ;
	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 所有workerの元応答です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, first, definition, prepared,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 初回完了の旧集計正本です。
		DRIVERCRATE_EXPECT(
			context,
			owner.initializeProjected( first, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto initial = projectedStoreSnapshot( context, first) ;		// 両条件の不変な元成功です。
	const std::wstring rootName = L"current/campaign-root-v2.json" ;	// 最後に確定する共有rootです。
	const std::wstring pointerName =
		L"current/campaign-current-v2.json" ;	// 旧／新二値だけのpointerです。
	const std::array<CollectorRecoveryCheckpoint, 5U> checkpoints{
		CollectorRecoveryCheckpoint::FINISH_INTENT, CollectorRecoveryCheckpoint::FINISH_SHARD,
		CollectorRecoveryCheckpoint::FINISH_SUMMARY, CollectorRecoveryCheckpoint::FINISH_POINTER,
		CollectorRecoveryCheckpoint::FINISH_REGISTERED} ;	// 実保存順の五窓です。
	const auto settle = [&]( LocalCollectorStateStore &store, const std::uint64_t utc) {
		{
			LocalCollectorRecovery owner ;	// HTTP client／executorは作りません。
			DRIVERCRATE_EXPECT( context,
							   owner.initializeProjected( store, definition, utc, 0U) == 0U &&
								   owner.beginNextProjected( definition, utc, 1000U) == 0U) ;
			CollectorHttpPermitPool				pool( [utc] {
				return CollectorHttpClockSample{utc + 2000U, 2000U} ;
			}) ;								 // 元予約だけを有限時計で作ります。
			std::array<CollectorHttpPermit, 2U> permits ;	// 二sourceの保存予約です。
			// 所有者の解放前に二保存予約を作り、送信は一度も始めません。
			for( auto &permit : permits) {
				DRIVERCRATE_EXPECT( context, pool.reserveProjected( owner, permit) == 0U) ;
			}
		}
		LocalCollectorRecovery recovery ;	// 元予約を欠測中断へ明示精算します。
		DRIVERCRATE_EXPECT( context,
						   recovery.initializeProjected( store, definition, utc + 6000U, 0U) ==
								   ERROR_RETRY &&
							   recovery.recoverNextProjectedReservations( utc + 6000U, 1000U) == 0U) ;
	} ; // 保存済み成功と元日精算を持つ未完了末尾だけを作ります。
	// 翌日／翌々日開始の二世代と元日archiveを独立に検証します。
	for( unsigned scenario = 0U; scenario < 2U; ++scenario) {
		LocalCollectorStateStore store ;	// 完了保存checkpointの原正本です。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 旧元byteをそのままコピーし、外側hashを作り直しません。
		for( const auto &[name, raw] : initial) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		const auto utc = HTTP_TEST_UTC + (scenario + 1ULL) * 86400000U ;	// 今回の元予約日です。
		settle( store, utc) ;
		const auto before = projectedStoreSnapshot( context, store) ;	// 末尾全終端・未登録完了です。
		std::vector<std::map<std::wstring, std::string>>
												 windows ;	// 実保存直後の全raw像を保持します。
		std::vector<CollectorRecoveryCheckpoint> seen ;		// 五窓の実保存順を保持します。
		{
			LocalCollectorRecovery owner ;	// 元完了UTCで一度だけ保存します。
			const auto			   record = [&]( const CollectorRecoveryCheckpoint point) {
				windows.push_back( projectedStoreSnapshot( context, store)) ;
				seen.push_back( point) ;
				return false ;
			} ; // 原正本は完走し、各窓を独立storeへ再生します。
			DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, definition, utc + 7000U,
																  0U, record) == 0U &&
											owner.finishNextProjected( utc + 8000U, 1000U) == 0U) ;
		}
		DRIVERCRATE_EXPECT( context, seen == std::vector( checkpoints.begin(), checkpoints.end()) &&
										windows.size() == 5U) ;
		// 不成立の窓を推測の完了像で埋めません。
		if( windows.size() != 5U) {
			continue ;
		}

		const auto final = projectedStoreSnapshot( context, store) ;	// 元完了UTCの全byte正本です。
		const auto root =
			// 元ROOTです。
			JsonObject::Parse( winrt::to_hstring( httpSavedBody( store, rootName))) ;
		const auto tail =
			// 元末尾です。
			root.GetNamedArray( L"generations").GetObjectAt( 1U) ;
		const auto key = std::wstring( tail.GetNamedString( L"generation")) ;	// 固定保存名の元Gです。
		const std::array<std::wstring, 3U> names{L"runs/campaign-finish-v1-" + key + L".json",
												 L"runs/campaign-targets-v1-" + key + L".json",
												 L"runs/campaign-summary-v1-" + key +
													 L".json"} ;	// 新規三runです。
		// 完了が変更してよい旧fileはROOTとpointerだけです。
		for( const auto &[name, raw] : before) {
			// 元CACHE・CONTROL・予算・旧応答・旧集計は一切変更しません。
			if( name != rootName && name != pointerName) {
				DRIVERCRATE_EXPECT( context, final.at( name) == raw) ;
			}
		}

		// 同日と翌日再開でも固定末尾完了だけを復旧し、日次切替を開始しません。
		for( std::size_t window = 0U; window < windows.size(); ++window) {
			// 各時刻条件を別保護storeで独立再生します。
			for( unsigned later = 0U; later < 2U; ++later) {
				LocalCollectorStateStore replay ;	// 元停止窓を保存します。
				DRIVERCRATE_EXPECT( context, replay.initialize( rootFactory(), true) == 0U) ;
				// 元prefixはrawのまま保存します。
				for( const auto &[name, raw] : windows[window]) {
					DRIVERCRATE_EXPECT( context, replay.write( name, raw) == 0U) ;
				}

				const auto resumeUtc =
					utc + 90000U + later * 86400000ULL ;			// 元closedとは区別します。
				std::vector<CollectorRecoveryCheckpoint> written ;	// 実不足suffixだけの観測です。
				{
					LocalCollectorRecovery restart ;	// 保存済み末尾intentだけを復旧します。
					const auto			   record = [&]( const CollectorRecoveryCheckpoint point) {
						written.push_back( point) ;
						return false ;
					} ; // 保存した不足suffixだけを数えます。
					const auto code = restart.initializeProjected( replay, definition, resumeUtc, 0U,
																  record) ;	// 原数値です。
					context.expect( code == 0U && final == projectedStoreSnapshot( context, replay) &&
									   written == std::vector( checkpoints.begin() + window + 1U,
															  checkpoints.end()),
								   "finish replay scenario=" + std::to_string( scenario) +
									   " window=" + std::to_string( window) +
									   " code=" + std::to_string( code),
								   __FILE__, __LINE__) ;
					DRIVERCRATE_EXPECT(
						context, restart.reason() == L"GENERATION_COMPLETE" &&
									 restart.finishNextProjected( resumeUtc + 1000U, 1000U) == 0U &&
									 final == projectedStoreSnapshot( context, replay)) ;
				}
				LocalCollectorRecovery repeated ;	// 別監督の二回目も保存しません。
				DRIVERCRATE_EXPECT( context, repeated.initializeProjected(
												replay, definition, resumeUtc + 2000U, 0U) == 0U &&
												final == projectedStoreSnapshot( context, replay)) ;
			}
		}

		// 復旧中の全不足保存窓から995停止し、さらに別監督で元結果へ復旧します。
		for( std::size_t window = 0U; window < 4U; ++window) {
			// 既存prefixを再保存しないので停止点は後続だけです。
			for( std::size_t cut = window + 1U; cut < 5U; ++cut) {
				LocalCollectorStateStore replay ;	// 復旧再中断の独立像です。
				DRIVERCRATE_EXPECT( context, replay.initialize( rootFactory(), true) == 0U) ;
				// 元停止像を変更せず再生します。
				for( const auto &[name, raw] : windows[window]) {
					DRIVERCRATE_EXPECT( context, replay.write( name, raw) == 0U) ;
				}

				{
					LocalCollectorRecovery stopped ;	// 最初の995を保持します。
					DRIVERCRATE_EXPECT( context,
									   stopped.initializeProjected(
										   replay, definition, utc + 100000U, 0U,
										   [&, cut]( const CollectorRecoveryCheckpoint point) {
											   return point == checkpoints[cut] ;
										   }) == ERROR_OPERATION_ABORTED) ;
					const auto failed =
						// 第一停止直後の実像です。
						projectedStoreSnapshot( context, replay) ;
					DRIVERCRATE_EXPECT(
						context, failed == windows[cut] &&
									 stopped.lastError() == ERROR_OPERATION_ABORTED &&
									 stopped.beginNextProjected( definition, utc + 101000U, 1000U) ==
										 ERROR_OPERATION_ABORTED &&
									 failed == projectedStoreSnapshot( context, replay)) ;
				}
				LocalCollectorRecovery restart ;	// 元監督の借用を返してから復旧します。
				DRIVERCRATE_EXPECT( context, restart.initializeProjected( replay, definition,
																		utc + 110000U, 0U) == 0U &&
												final == projectedStoreSnapshot( context, replay)) ;
			}
		}

		// 公開履歴読取りでは未完了の四窓を全byte非変更で拒否します。
		for( std::size_t window = 0U; window < 4U; ++window) {
			LocalCollectorStateStore replay ;	// 通常復旧とは別の公開callerです。
			DRIVERCRATE_EXPECT( context, replay.initialize( rootFactory(), true) == 0U) ;
			// 同じ元窓だけを渡します。
			for( const auto &[name, raw] : windows[window]) {
				DRIVERCRATE_EXPECT( context, replay.write( name, raw) == 0U) ;
			}

			std::shared_ptr<const CollectorRegisteredProjectedHistory> history ;	// 失敗時は空です。
			DRIVERCRATE_EXPECT( context,
							   LocalCollectorRecovery::inspectRegisteredProjectedHistory(
								   replay, *prepared->job( 0U), definition.sources, utc + 90000U,
								   history) == ERROR_INVALID_DATA &&
								   !history &&
								   windows[window] == projectedStoreSnapshot( context, replay)) ;
		}

		// pointerとROOTの実置換I/Oを原Win32 5で停止し、属性を復元して再起動します。
		for( unsigned target = 0U; target < 2U; ++target) {
			LocalCollectorStateStore denied ;	// 専用自作root内だけで属性を変更します。
			DRIVERCRATE_EXPECT( context, denied.initialize( rootFactory(), true) == 0U) ;
			// Summary保存済み／pointer保存済みの元窓を使います。
			for( const auto &[name, raw] : windows[target + 2U]) {
				DRIVERCRATE_EXPECT( context, denied.write( name, raw) == 0U) ;
			}

			const auto file =
				// 確認済みの一fileです。
				denied.root() / (target == 0U ? pointerName : rootName) ;
			const DWORD attributes = GetFileAttributesW( file.c_str()) ;	// 元属性を必ず戻します。
			DRIVERCRATE_EXPECT( context, attributes != INVALID_FILE_ATTRIBUTES &&
											(attributes & FILE_ATTRIBUTE_READONLY) == 0U) ;
			const auto restore = [attributes, &context]( const wchar_t *name) {
				DRIVERCRATE_EXPECT( context, SetFileAttributesW( name, attributes) != FALSE) ;
			} ; // DACL／OS設定には触れません。
			std::unique_ptr<const wchar_t, decltype( restore)> guard(
				// 元属性への同期guardです。
				file.c_str(), restore) ;
			DRIVERCRATE_EXPECT(
				context,
				SetFileAttributesW( file.c_str(), attributes | FILE_ATTRIBUTE_READONLY) != FALSE) ;
			{
				LocalCollectorRecovery refusal ;	// 実保存codeを同じ監督に保持します。
				const auto code = refusal.initializeProjected( denied, definition, utc + 120000U,
															  0U) ;	// 原I/Oです。
				const auto failed =
					// stagingは別容量検査へ含めます。
					projectedStoreSnapshot( context, denied) ;
				DRIVERCRATE_EXPECT( context,
								   code == ERROR_ACCESS_DENIED && failed == windows[target + 2U] &&
									   refusal.lastError() == ERROR_ACCESS_DENIED &&
									   refusal.beginNextProjected( definition, utc + 121000U,
																  1000U) == ERROR_ACCESS_DENIED &&
									   failed == projectedStoreSnapshot( context, denied)) ;
			}
			guard.reset() ;
			DRIVERCRATE_EXPECT( context, GetFileAttributesW( file.c_str()) == attributes) ;
			LocalCollectorRecovery restart ;	// 残留stagingも数えた元保存枠で再開します。
			DRIVERCRATE_EXPECT(
				context, restart.initializeProjected( denied, definition, utc + 130000U, 0U) == 0U &&
							 final == projectedStoreSnapshot( context, denied)) ;
		}

		// 欠損・逆順・改変と要求外破損を独立に保存前拒否します。
		for( unsigned mutation = 0U; mutation < 19U; ++mutation) {
			LocalCollectorStateStore rejected ;	// 単一要因の非変更拒否です。
			DRIVERCRATE_EXPECT( context, rejected.initialize( rootFactory(), true) == 0U) ;
			const auto seed = mutation == 18U ? final : windows[3U] ;	// 登録後欠損も補完しません。
			const auto missing = mutation < 3U	   ? names[mutation]
								 : mutation == 3U  ? pointerName
								 : mutation == 18U ? names[2U]
												   : std::wstring{} ;	// 逆順／必須欠損です。
			// 一つの欠損以外の元外側byteを保持します。
			for( const auto &[name, raw] : seed) {
				// 欠損を不正な空本文へ置換しません。
				if( name != missing) {
					DRIVERCRATE_EXPECT( context, rejected.write( name, raw) == 0U) ;
				}
			}

			// 各保存本文と旧CACHEの追加fieldを外側hash再計算後も拒否します。
			if( mutation >= 4U && mutation <= 9U) {
				const auto name =
					mutation <= 6U	 ? names[mutation - 4U]
					: mutation == 7U ? pointerName
					: mutation == 8U
						? L"current/campaign-cache-v1-" + identity.jobs[0U].requestKey + L".json"
						: L"runs/campaign-summary-v1-" + identity.generationKey +
							  L".json" ;	// 要求外旧像も必須です。
				mutateProjectedStore( context, rejected, name, []( JsonObject &value) {
					value.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
				}) ;
			}

			// 元完了時計を現在未来／ROOTより前へ変更します。
			if( mutation == 10U || mutation == 11U) {
				mutateProjectedStore( context, rejected, names[0U], [&]( JsonObject &value) {
					value.Insert( L"closedUtcMillis",
								 JsonValue::CreateNumberValue( static_cast<double>(
									 mutation == 10U ? utc + 999000U : utc + 5000U))) ;
				}) ;
			}

			// 未終端行・別active・未知fileを完了提案へ読み替えません。
			if( mutation == 12U) {
				mutateProjectedStore( context, rejected,
									 L"current/campaign-state-v3-" + key + L".json",
									 []( JsonObject &value) {
										 value.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
											 L"state", JsonValue::CreateStringValue( L"RUNNING")) ;
									 }) ;
			}

			// 別active・登録summary偽装は元末尾完了の例外へ含めません。
			if( mutation == 13U || mutation == 14U) {
				mutateProjectedStore( context, rejected, rootName, [&]( JsonObject &value) {
					// 旧世代を稼働へ戻す操作は認めません。
					if( mutation == 13U) {
						value.Insert( L"activeGeneration",
									 JsonValue::CreateStringValue( identity.generationKey)) ;
					} else {
						value.GetNamedArray( L"generations")
							.GetObjectAt( 1U)
							.Insert( L"summaryHash",
									JsonValue::CreateStringValue( identity.inputSha256)) ;
					}
				}) ;
			}

			// 固定保存名集合にない記録を自己hashだけで許可しません。
			if( mutation == 15U) {
				saveRegisteredHistoryFixture( context, rejected,
											 L"runs/campaign-finish-v1-orphan.json", "{}") ;
			}

			// 先行二像があっても、元旧値／導出新値以外のpointerを許可しません。
			if( mutation == 16U || mutation == 17U) {
				const auto body = JsonObject::Parse( winrt::to_hstring(
					// 余剰fieldなしの未知値です。
					httpSavedBody( rejected, pointerName))) ;
				body.Insert( mutation == 16U ? L"generation" : L"summaryHash",
							JsonValue::CreateStringValue( identity.inputSha256)) ;
				saveRegisteredHistoryFixture( context, rejected, pointerName,
											 winrt::to_string( body.Stringify())) ;
			}

			const auto failed = projectedStoreSnapshot( context, rejected) ;	// 拒否前の全rawです。
			LocalCollectorRecovery refusal ;									// 一fileも変更する前に拒否します。
			const auto code = refusal.initializeProjected( rejected, definition, utc + 140000U,
														  0U) ;	// 原13を期待します。
			context.expect(
				code == ERROR_INVALID_DATA && failed == projectedStoreSnapshot( context, rejected),
				"finish refusal scenario=" + std::to_string( scenario) +
					" mutation=" + std::to_string( mutation) + " code=" + std::to_string( code),
				__FILE__, __LINE__) ;
		}
	}
}

/** @see local_collector_http_tests.h */
void runCollectorDayRollRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto definition = definitionFactory() ;							// 通信を行わない元二sourceの契約。
	CollectorProjectedCampaignIdentity						  identity ;	// 初回の固定元日。
	std::shared_ptr<const CollectorPreparedProjectedCampaign> prepared ;	// 本番codecへの元入力。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, prepared)) ;
	// 初回不成立を成功の保存fixtureへ補完しません。
	if( !prepared) {
		return ;
	}

	LocalCollectorStateStore initialStore ;	// 元成功は既存fake HTTPと本番parserから保存します。
	DRIVERCRATE_EXPECT( context, initialStore.initialize( rootFactory(), true) == 0U) ;
	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 初回所有workerの元結果。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, initialStore, definition,
															   prepared, 0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery finish ;	// 初回の全完了登録と固定summary。
		DRIVERCRATE_EXPECT( context,
						   finish.initializeProjected( initialStore, definition,
													  HTTP_TEST_UTC + 126000U, 0U) == 0U &&
							   finish.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto initial = projectedStoreSnapshot( context, initialStore) ;	// 二条件の独立正本。
	const std::wstring rootName	   = L"current/campaign-root-v2.json" ;		// 固定共有root。
	const std::wstring budgetName  = L"current/campaign-budget-v1.json" ;	// 元日を保存する台帳。
	const std::wstring controlName = L"current/campaign-controls-v1.json" ;	// 日次で解除しない待機。
	// 初回成功だけと、旧archive／二完了世代を持つ条件を別storeで検証します。
	for( unsigned scenario = 0U; scenario < 2U; ++scenario) {
		LocalCollectorStateStore store ;	// 実保存checkpointを採る元store。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 旧全byteをそのまま複製し、架空の完了像は作りません。
		for( const auto &[name, raw] : initial) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		// 二世代目は実予約・明示中断・通常末尾完了から作り、旧成功群を残します。
		if( scenario == 1U) {
			const auto nextUtc = HTTP_TEST_UTC + 86400000U ;	// 元二世代目の実予約日。
			{
				LocalCollectorRecovery owner ;	// HTTP clientもexecutorも作りません。
				DRIVERCRATE_EXPECT(
					context, owner.initializeProjected( store, definition, nextUtc, 0U) == 0U &&
								 owner.beginNextProjected( definition, nextUtc, 1000U) == 0U) ;
				CollectorHttpPermitPool				pool( [nextUtc] {
					return CollectorHttpClockSample{nextUtc + 2000U, 2000U} ;
				}) ;								 // 固定時計。
				std::array<CollectorHttpPermit, 2U> permits ;	// 既存二sourceの保存予約だけ。
				// 全予約を作ってから所有者を解放し、再起動相当の中断へ渡します。
				for( auto &permit : permits) {
					DRIVERCRATE_EXPECT( context, pool.reserveProjected( owner, permit) == 0U) ;
				}
			}
			LocalCollectorRecovery recovery ;	// 元二世代目の欠測を一回だけ精算します。
			DRIVERCRATE_EXPECT(
				context,
				recovery.initializeProjected( store, definition, nextUtc + 6000U, 0U) ==
						ERROR_RETRY &&
					recovery.recoverNextProjectedReservations( nextUtc + 6000U, 1000U) == 0U &&
					recovery.finishNextProjected( nextUtc + 7000U, 2000U) == 0U) ;
		}

		const auto original =
			// 完了した元日・旧履歴の正本。
			projectedStoreSnapshot( context, store) ;
		const auto utc =
			HTTP_TEST_UTC + (scenario + 1ULL) * 86400000U + 10000U ;	// 今回の切替固定UTC。
		const auto newDay =
			// 現在日への延長を許しません。
			scenario == 0U ? L"20260928" : L"20260929" ;
		const auto oldDay = scenario == 0U ? L"20260927" : L"20260928" ;	// 元日archiveの固定名。
		const auto archiveName =
			L"runs/campaign-budget-" + std::wstring( oldDay) + L".json" ;	// 実archive。
		std::vector<std::map<std::wstring, std::string>> windows ;			// 八つの実保存直後の全raw。
		std::vector<CollectorRecoveryCheckpoint>		 points ;			// checkpointを保存窓へ一対一対応。
		{
			LocalCollectorRecovery owner ;	// COMPLETEDで止め、新世代登録は行わせません。
			const auto			   stop = [&]( const CollectorRecoveryCheckpoint point) {
				// 実保存後だけ記録し、保存を伴わないEFFECTSは重複計数しません。
				if( point == CollectorRecoveryCheckpoint::DAY_ROLL_INTENT ||
				   point == CollectorRecoveryCheckpoint::DAY_ROLL_EFFECT ||
				   point == CollectorRecoveryCheckpoint::REGISTERED ||
				   point == CollectorRecoveryCheckpoint::APPLIED ||
				   point == CollectorRecoveryCheckpoint::COMPLETED) {
					windows.push_back( projectedStoreSnapshot( context, store)) ;
					points.push_back( point) ;
				}

				return point == CollectorRecoveryCheckpoint::COMPLETED ;
			} ; // 借用はownerの終了までです。
			DRIVERCRATE_EXPECT( context,
							   owner.initializeProjected( store, definition, utc, 0U, stop) == 0U &&
								   owner.beginNextProjected( definition, utc, 1000U) ==
									   ERROR_OPERATION_ABORTED) ;
			const auto stopped =
				// 第一995を消して継続しません。
				projectedStoreSnapshot( context, store) ;
			DRIVERCRATE_EXPECT( context, owner.beginNextProjected( definition, utc + 1000U, 2000U) ==
												ERROR_OPERATION_ABORTED &&
											stopped == projectedStoreSnapshot( context, store)) ;
		}
		DRIVERCRATE_EXPECT( context, windows.size() == 8U && points.size() == 8U) ;
		// 元保存が不成立なら以降の成功を作りません。
		if( windows.size() != 8U) {
			continue ;
		}

		const auto final		= windows.back() ;	// 元acceptedで完了した日次一切替の正本。
		const auto envelopeBody = []( const std::string &raw) {
			return winrt::to_string(
				JsonObject::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
		} ; // 全byteとschemaを本番で検査後、fixtureの公開fieldだけを確認します。
		const auto oldRoot =
			// 元登録数。
			JsonObject::Parse( winrt::to_hstring( envelopeBody( original.at( rootName)))) ;
		std::wstring intentName ;	// 今回追加された一intentだけを探します。
		// 元名集合になかった切替を一つだけ選びます。
		for( const auto &[name, raw] : final) {
			(void)raw ;
			// 旧archiveのintentは今回の分母へ含めません。
			if( name.starts_with( L"runs/campaign-day-roll-v2-") && !original.contains( name)) {
				DRIVERCRATE_EXPECT( context, intentName.empty()) ;
				intentName = name ;
			}
		}

		DRIVERCRATE_EXPECT( context,
						   !intentName.empty() && final.at( archiveName) == original.at( budgetName)) ;
		const auto intent = JsonObject::Parse(
			// 元時計正本。
			winrt::to_hstring( envelopeBody( final.at( intentName)))) ;
		const auto op = std::wstring( intent.GetNamedString( L"operation")) ;	// 固定準備像名。
		const std::array<std::wstring, 3U> effects{
			L"runs/campaign-effect-v1-" + op + L"-archive.json",
			L"runs/campaign-effect-v1-" + op + L"-before-budget.json",
			L"runs/campaign-effect-v1-" + op + L"-budget.json"} ;	// 実addEffectの元保存順。
		const auto verify = [&]( LocalCollectorStateStore &current) {
			const auto saved =
				// 新規世代や送信証跡を増やしません。
				projectedStoreSnapshot( context, current) ;
			DRIVERCRATE_EXPECT( context, saved.size() == final.size() &&
											saved.at( intentName) == final.at( intentName) &&
											saved.at( archiveName) == original.at( budgetName) &&
											saved.at( budgetName) == final.at( budgetName)) ;
			// 旧証跡は共有root／budget以外全byte不変です。controlも解除しません。
			for( const auto &[name, raw] : original) {
				// 変更対象は一切替のrootと当日予算だけです。
				if( name != rootName && name != budgetName) {
					DRIVERCRATE_EXPECT( context, saved.at( name) == raw) ;
				}
			}

			const auto root = JsonObject::Parse(
				// 旧登録保持。
				winrt::to_hstring( envelopeBody( saved.at( rootName)))) ;
			const auto budget = JsonObject::Parse(
				// 固定新日。
				winrt::to_hstring( envelopeBody( saved.at( budgetName)))) ;
			DRIVERCRATE_EXPECT(
				context, root.GetNamedArray( L"generations").Stringify() ==
								 oldRoot.GetNamedArray( L"generations").Stringify() &&
							 root.GetNamedArray( L"cacheInventory").Stringify() ==
								 oldRoot.GetNamedArray( L"cacheInventory").Stringify() &&
							 root.GetNamedArray( L"archives").Size() ==
								 oldRoot.GetNamedArray( L"archives").Size() + 1U &&
							 root.GetNamedString( L"activeGeneration").empty() &&
							 root.GetNamedValue( L"commit").ValueType() ==
								 winrt::Windows::Data::Json::JsonValueType::Null &&
							 budget.GetNamedString( L"day") == newDay &&
							 budget.GetNamedArray( L"reservations").Size() == 0U &&
							 budget.GetNamedNumber( L"lastUtc") == static_cast<double>( utc / 1000U)) ;
		} ; // 元intent・登録と旧rawを借用する同期oracleです。
		// 各八保存窓を、同じ新日と二日後の再開の両方で独立再生します。
		for( std::size_t index = 0U; index < windows.size(); ++index) {
			// 後日でも元新日への一切替だけです。
			for( unsigned later = 0U; later < 2U; ++later) {
				LocalCollectorStateStore resumed ;	// 別process相当の独立保護store。
				DRIVERCRATE_EXPECT( context, resumed.initialize( rootFactory(), true) == 0U) ;
				// 採取した元窓の全rawを複製します。
				for( const auto &[name, raw] : windows[index]) {
					DRIVERCRATE_EXPECT( context, resumed.write( name, raw) == 0U) ;
				}

				const auto now =
					utc + 10000U + later * 2ULL * 86400000U ;	// 元acceptedとは区別します。
				LocalCollectorRecovery recovery ;				// 無通信で一切替だけ確定します。
				const auto			   code = recovery.initializeProjected( resumed, definition, now,
																		   0U) ;	// 後日の未完了は1237。
				const DWORD			   expected = later == 1U && index + 1U < windows.size()
													  ? ERROR_RETRY
													  : ERROR_SUCCESS ;	// 完了窓は非変更。
				context.expect( code == expected,
							   "day roll scenario=" + std::to_string( scenario) + " window=" +
								   std::to_string( index) + " later=" + std::to_string( later) +
								   " code=" + std::to_string( code),
							   __FILE__, __LINE__) ;
				// 不成立後に保存結果を架空の成功として検査しません。
				if( code != expected) {
					continue ;
				}

				verify( resumed) ;
				const auto stable =
					// 二回目は全byte非変更です。
					projectedStoreSnapshot( context, resumed) ;
				{
					LocalCollectorStateStore copy ;	// 同じworkspaceの別監督借用を避けます。
					DRIVERCRATE_EXPECT( context, copy.initialize( rootFactory(), true) == 0U) ;
					// 確定した全byteから再起動します。
					for( const auto &[name, raw] : stable) {
						DRIVERCRATE_EXPECT( context, copy.write( name, raw) == 0U) ;
					}

					LocalCollectorRecovery repeat ;	// 日次追加切替も世代開始も行いません。
					DRIVERCRATE_EXPECT(
						context,
						repeat.initializeProjected( copy, definition, now + 1000U, 0U) == 0U &&
							stable == projectedStoreSnapshot( context, copy)) ;
				}
			}
		}

		// 登録窓から復旧自体を二反映／確定で実停止し、さらに後日の新監督で回復します。
		for( unsigned cut = 0U; cut < 3U; ++cut) {
			LocalCollectorStateStore interrupted ;	// 三つの独立した実995停止。
			DRIVERCRATE_EXPECT( context, interrupted.initialize( rootFactory(), true) == 0U) ;
			// 反映前の登録済み元窓を保ちます。
			for( const auto &[name, raw] : windows[4U]) {
				DRIVERCRATE_EXPECT( context, interrupted.write( name, raw) == 0U) ;
			}

			{
				unsigned			   applied{} ;	// 第一／第二反映を別の停止点として数えます。
				LocalCollectorRecovery stopped ;	// 元acceptedより新しい監督時計を持ちます。
				const auto			   stop = [&]( const CollectorRecoveryCheckpoint point) {
					// 二反映だけを順序通り数えます。
					if( point == CollectorRecoveryCheckpoint::APPLIED) {
						++applied ;
					}

					return cut < 2U ? point == CollectorRecoveryCheckpoint::APPLIED &&
										  applied == cut + 1U
												: point == CollectorRecoveryCheckpoint::COMPLETED ;
				} ; // stoppedの借用期間中だけ使います。
				DRIVERCRATE_EXPECT( context, stopped.initializeProjected( interrupted, definition,
																		utc + 20000U, 0U, stop) ==
												ERROR_OPERATION_ABORTED) ;
				const auto before = projectedStoreSnapshot( context, interrupted) ;	// 第一error保持。
				DRIVERCRATE_EXPECT( context,
								   stopped.beginNextProjected( definition, utc + 21000U, 1000U) ==
										   ERROR_OPERATION_ABORTED &&
									   before == projectedStoreSnapshot( context, interrupted)) ;
			}
			LocalCollectorRecovery restart ;	// 元intentを保持した再回復。
			const auto code = restart.initializeProjected( interrupted, definition, utc + 30000U,
														  0U) ;	// 原acceptedは不変。
			DRIVERCRATE_EXPECT( context, code == 0U) ;
			// 成功した物理結果だけを正本へ照合します。
			if( code == 0U) {
				verify( interrupted) ;
			}
		}

		// 未登録prefixの復旧で監督ROOT時計だけを進め、再登録／第一反映の実停止から再回復します。
		for( unsigned cut = 0U; cut < 2U; ++cut) {
			LocalCollectorStateStore interrupted ;	// 不足準備像を持つ未登録prefixの独立store。
			DRIVERCRATE_EXPECT( context, interrupted.initialize( rootFactory(), true) == 0U) ;
			// IntentとARCHIVE後像までの元実保存窓から始めます。
			for( const auto &[name, raw] : windows[1U]) {
				DRIVERCRATE_EXPECT( context, interrupted.write( name, raw) == 0U) ;
			}

			{
				LocalCollectorRecovery stopped ;	// 同じ元acceptedで登録し直す復旧監督。
				const auto			   stop = [cut]( const CollectorRecoveryCheckpoint point) {
					return point == (cut == 0U ? CollectorRecoveryCheckpoint::REGISTERED
														   : CollectorRecoveryCheckpoint::APPLIED) ;
				} ; // 一回目の登録か第一反映だけで実995停止します。
				DRIVERCRATE_EXPECT( context, stopped.initializeProjected( interrupted, definition,
																		utc + 50000U, 0U, stop) ==
												ERROR_OPERATION_ABORTED) ;
				const auto raw =
					// 元intentと進んだROOT。
					projectedStoreSnapshot( context, interrupted) ;
				const auto registeredRoot = JsonObject::Parse(
					// 監督時計だけを検査。
					winrt::to_hstring( envelopeBody( raw.at( rootName)))) ;
				DRIVERCRATE_EXPECT(
					context, raw.at( intentName) == final.at( intentName) &&
								 registeredRoot.GetNamedNumber( L"lastUtcMillis") ==
									 static_cast<double>( utc + 50000U) &&
								 registeredRoot.GetNamedObject( L"commit").GetNamedNumber(
									 L"accepted") == static_cast<double>( utc) &&
								 stopped.beginNextProjected( definition, utc + 51000U, 1000U) ==
									 ERROR_OPERATION_ABORTED &&
								 raw == projectedStoreSnapshot( context, interrupted)) ;
			}
			LocalCollectorRecovery restart ;	// 進んだ監督時計を元acceptedへ混同しません。
			const auto code = restart.initializeProjected( interrupted, definition, utc + 60000U,
														  0U) ;	// 元予算とintentで一回だけ確定。
			DRIVERCRATE_EXPECT( context, code == 0U) ;
			// 元固定結果の成功だけを検査します。
			if( code == 0U) {
				verify( interrupted) ;
			}
		}

		// 実保存拒否は専用fixtureの予算file属性だけで起こし、OSのDACLや設定は変更しません。
		{
			LocalCollectorStateStore denied ;	// 二反映前の登録済み像を所有します。
			DRIVERCRATE_EXPECT( context, denied.initialize( rootFactory(), true) == 0U) ;
			// 元日次登録窓のbyteを保存します。
			for( const auto &[name, raw] : windows[4U]) {
				DRIVERCRATE_EXPECT( context, denied.write( name, raw) == 0U) ;
			}

			const auto	budgetPath = denied.root() / budgetName ;				// 検証済み専用root内の一file。
			const DWORD attributes = GetFileAttributesW( budgetPath.c_str()) ;	// 元属性を保存。
			DRIVERCRATE_EXPECT( context, attributes != INVALID_FILE_ATTRIBUTES &&
											(attributes & FILE_ATTRIBUTE_READONLY) == 0U) ;
			const auto restore = [attributes, &context]( const wchar_t *path) {
				DRIVERCRATE_EXPECT( context, SetFileAttributesW( path, attributes) != FALSE) ;
			} ; // 不成立時も元属性へ戻し、借用pathの存続内で解放します。
			std::unique_ptr<const wchar_t, decltype( restore)> attributesGuard(
				// 属性変更だけの同期回収guard。
				budgetPath.c_str(), restore) ;
			DRIVERCRATE_EXPECT( context,
							   SetFileAttributesW( budgetPath.c_str(),
												  attributes | FILE_ATTRIBUTE_READONLY) != FALSE) ;
			{
				LocalCollectorRecovery refusal ;	// ARCHIVE反映後のBUDGET置換を原Win32 5で止めます。
				const auto code = refusal.initializeProjected( denied, definition, utc + 70000U,
															  0U) ;	// 偽I/O callbackは使いません。
				const auto raw =
					// 第一error直後の保存prefix。
					projectedStoreSnapshot( context, denied) ;
				DRIVERCRATE_EXPECT( context,
								   code == ERROR_ACCESS_DENIED &&
									   refusal.lastError() == ERROR_ACCESS_DENIED &&
									   raw.at( rootName) == windows[4U].at( rootName) &&
									   raw.at( budgetName) == original.at( budgetName) &&
									   raw.at( archiveName) == original.at( budgetName) &&
									   refusal.beginNextProjected( definition, utc + 71000U,
																  1000U) == ERROR_ACCESS_DENIED &&
									   raw == projectedStoreSnapshot( context, denied)) ;
			}
			attributesGuard.reset() ;
			DRIVERCRATE_EXPECT( context, GetFileAttributesW( budgetPath.c_str()) == attributes) ;
			LocalCollectorRecovery restart ;	// stagingを含む元容量境界のまま別監督で再開。
			const auto code = restart.initializeProjected( denied, definition, utc + 80000U,
														  0U) ;	// 元acceptedは延長しません。
			DRIVERCRATE_EXPECT( context, code == 0U) ;
			// 成功した固定日次結果だけを照合します。
			if( code == 0U) {
				verify( denied) ;
			}
		}

		// 通常公開読取りへ日次例外を流用せず、未登録／登録窓の双方を非変更拒否します。
		for( const std::size_t index : {0U, 4U}) {
			LocalCollectorStateStore publicStore ;	// 専用initializeとは別の公開caller。
			DRIVERCRATE_EXPECT( context, publicStore.initialize( rootFactory(), true) == 0U) ;
			// 実保存窓をそのまま渡します。
			for( const auto &[name, raw] : windows[index]) {
				DRIVERCRATE_EXPECT( context, publicStore.write( name, raw) == 0U) ;
			}

			std::shared_ptr<const CollectorRegisteredProjectedHistory>
				history ;	// 拒否時は空のまま。
			DRIVERCRATE_EXPECT( context,
							   LocalCollectorRecovery::inspectRegisteredProjectedHistory(
								   publicStore, *prepared->job( 0U), definition.sources,
								   utc + 90000U, history) == ERROR_INVALID_DATA &&
								   !history &&
								   windows[index] == projectedStoreSnapshot( context, publicStore)) ;
		}

		// 18の単一改変／欠損と未登録prefix三条件を、外側hash再計算後も保存前に拒否します。
		for( unsigned mutation = 0U; mutation < 21U; ++mutation) {
			LocalCollectorStateStore rejected ;	// 一要因だけを独立に破ります。
			DRIVERCRATE_EXPECT( context, rejected.initialize( rootFactory(), true) == 0U) ;
			const auto &seed =
				mutation >= 18U ? windows[2U] : windows[4U] ;	// 未登録は二準備像のprefix。
			const auto missing = mutation == 0U						? intentName
								 : mutation >= 1U && mutation <= 3U ? effects[mutation - 1U]
								 : mutation == 16U
									 ? std::wstring( L"current/campaign-controls-marker-v1.json")
								 : mutation == 18U ? effects[0U]
												   : std::wstring{} ;	// 欠損を空本文へ戻しません。
			// 固定欠損名以外の元byteをそのまま複製します。
			for( const auto &[name, raw] : seed) {
				// 欠損一件だけを省きます。
				if( name != missing) {
					DRIVERCRATE_EXPECT( context, rejected.write( name, raw) == 0U) ;
				}
			}

			// 予算先行、未登録archive、未登録予算更新は実保存順で生成できません。
			if( mutation == 4U || mutation == 20U) {
				DRIVERCRATE_EXPECT( context, rejected.write( budgetName, final.at( budgetName)) == 0U) ;
			}

			// 未登録のarchive反映も認めません。
			if( mutation == 19U) {
				DRIVERCRATE_EXPECT( context,
								   rejected.write( archiveName, final.at( archiveName)) == 0U) ;
			}

			// 不正archiveは前像の一致を満たしません。
			if( mutation == 5U) {
				saveRegisteredHistoryFixture( context, rejected, archiveName, "{}") ;
			}

			// CONTROLと要求外CACHEの破損は日次例外へ含めません。
			if( mutation == 6U || mutation == 7U) {
				const auto name = mutation == 6U ? controlName
												 : L"current/campaign-cache-v1-" +
													   prepared->job( 0U)->value().requestKey +
													   L".json" ;	// 要求外も全閉包で検査します。
				mutateProjectedStore( context, rejected, name, []( JsonObject &value) {
					value.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
				}) ;
			}

			// Commitの時刻・role逆順・active・余剰fieldを独立に変更します。
			if( mutation == 8U || mutation == 9U || mutation == 14U || mutation == 15U) {
				mutateProjectedStore(
					context, rejected, rootName, [mutation, &identity]( JsonObject &value) {
						const auto commit = value.GetNamedObject( L"commit") ;	// 一つの元登録。
						// 元intentとの時刻一致を破ります。
						if( mutation == 8U) {
							commit.Insert( L"accepted",
										  JsonValue::CreateNumberValue(
											  commit.GetNamedNumber( L"accepted") + 1.0)) ;
						}

						// 二roleの順序を反転します。
						if( mutation == 9U) {
							const auto rows	 = commit.GetNamedArray( L"effects") ;	// 元二role。
							const auto first = rows.GetAt( 0U) ;					// 順序変更用の元値。
							rows.SetAt( 0U, rows.GetAt( 1U)) ;
							rows.SetAt( 1U, first) ;
						}

						// 全完了と稼働末尾の併存を拒否します。
						if( mutation == 14U) {
							value.Insert( L"activeGeneration",
										 JsonValue::CreateStringValue( identity.generationKey)) ;
						}

						// 元登録形式以外のfieldを許可しません。
						if( mutation == 15U) {
							commit.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
						}
					}) ;
			}

			// 同じ名前で新日のみ変えてもintent再導出は一致しません。
			if( mutation == 10U) {
				mutateProjectedStore( context, rejected, intentName, []( JsonObject &value) {
					value.Insert( L"newDay", JsonValue::CreateStringValue( L"20261001")) ;
				}) ;
			}

			// 二つの未登録intentを一つへ黙って選択しません。
			if( mutation == 11U) {
				const auto secondOp = std::wstring( 64U, L'f') ;				// 架空の別操作。
				auto	   second = JsonObject::Parse( intent.Stringify()) ;	// 元fieldを維持します。
				second.Insert( L"operation", JsonValue::CreateStringValue( secondOp)) ;
				saveRegisteredHistoryFixture( context, rejected,
											 L"runs/campaign-day-roll-v2-" + secondOp + L".json",
											 winrt::to_string( second.Stringify())) ;
			}

			// 未知campaign名と不在ARCHIVE前像を独立に追加します。
			if( mutation == 12U || mutation == 17U) {
				const auto name = mutation == 12U ? L"runs/campaign-unknown-day-roll.json"
												  : L"runs/campaign-effect-v1-" + op +
														L"-before-archive.json" ;	// 固定一要因。
				saveRegisteredHistoryFixture( context, rejected, name, "{}") ;
			}

			// 元予算前像の自己一貫改変も登録hashだけで許可しません。
			if( mutation == 13U) {
				mutateProjectedStore( context, rejected, effects[1U], []( JsonObject &value) {
					value.Insert( L"unexpected", JsonValue::CreateBooleanValue( true)) ;
				}) ;
			}

			const auto before =
				// 全raw非変更を要求します。
				projectedStoreSnapshot( context, rejected) ;
			LocalCollectorRecovery refusal ;	// 一つの共有保存前に全検査します。
			const auto			   code =
				// 期待13。
				refusal.initializeProjected( rejected, definition, utc + 40000U, 0U) ;
			context.expect(
				code == ERROR_INVALID_DATA && before == projectedStoreSnapshot( context, rejected),
				"day roll refusal scenario=" + std::to_string( scenario) +
					" mutation=" + std::to_string( mutation) + " code=" + std::to_string( code),
				__FILE__, __LINE__) ;
		}
	}
}

/** @see local_collector_http_tests.h */
void runCollectorNextRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto						   definition = definitionFactory() ;	// 元二sourceの公開契約。
	CollectorProjectedCampaignIdentity identity ;							// 初回の元scope。
	std::shared_ptr<const CollectorPreparedProjectedCampaign> prepared ;	// 元fake worker専用入力。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, prepared)) ;
	// 初回生成不成立を架空成功で補完しません。
	if( !prepared) {
		return ;
	}

	LocalCollectorStateStore first ;	// 初回成功は既存fake HTTPの所有保存経路から作ります。
	DRIVERCRATE_EXPECT( context, first.initialize( rootFactory(), true) == 0U) ;
	std::array<CollectorProjectedResponseBytes, 2U> initial ;	// 元v4の実codec出力。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, first, definition, prepared,
															   0U, {}, initial) == 0U) ;
	{
		LocalCollectorRecovery finish ;	// 旧完了登録と集計の正本。
		DRIVERCRATE_EXPECT(
			context,
			finish.initializeProjected( first, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				finish.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto	 original = projectedStoreSnapshot( context, first) ;	// 全条件の独立旧正本。
	std::wstring initialOp ;											// 元Intel操作は応答内の未定義fieldから読みません。
	DRIVERCRATE_EXPECT(
		context, computeBytesSha256( "response-v2\n" + winrt::to_string( identity.generationKey) +
										"\n" + winrt::to_string( identity.jobs[0].jobKey) + "\n",
									initialOp) == 0U) ;
	const auto utc = HTTP_TEST_UTC + 86400000U ;	// 翌日の元予約日。
	// 既存二RUNNING、新requestを含む二RUNNING、未予約を残す一RUNNINGを独立測定します。
	for( unsigned scenario = 0U; scenario < 3U; ++scenario) {
		auto next = definition ;	// 型番DBを追加せず新requestだけ変えます。
		// 新requestだけ公開locatorと元対象名を一緒に変えます。
		if( scenario == 1U) {
			const auto manifest =
				// 元順序のcopy。
				JsonObject::Parse( winrt::to_hstring( next.manifestBytes)) ;
			manifest.GetNamedArray( L"targets")
				.GetObjectAt( 26U)
				.Insert( L"model", JsonValue::CreateStringValue( L"Fixture Unanswered New Model")) ;
			manifest.GetNamedArray( L"jobs").GetObjectAt( 1U).Insert(
				L"locator", JsonValue::CreateStringValue( L"Fixture Unanswered New Model")) ;
			next.manifestBytes = winrt::to_string( manifest.Stringify()) ;
		}

		CollectorProjectedCampaignIdentity nextIdentity ;	// 保存した末尾の元identity。
		DRIVERCRATE_EXPECT( context,
						   makeCollectorProjectedCampaignIdentity( next, L"20260928", nextIdentity)) ;
		LocalCollectorStateStore store ;	// 元二世代予約の専用root。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		// 旧全rawをそのまま複製してから通常の次回開始を使います。
		for( const auto &[name, raw] : original) {
			DRIVERCRATE_EXPECT( context, store.write( name, raw) == 0U) ;
		}

		const std::size_t reserved = scenario == 2U ? 1U : 2U ;	// 未予約を欠測中断へ数えません。
		{
			LocalCollectorRecovery owner ;	// 生存中の所有拒否も同じ予約で検査します。
			DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, next, utc, 0U) == 0U &&
											owner.beginNextProjected( next, utc, 1000U) == 0U) ;
			CollectorHttpPermitPool pool(
				[utc] { return CollectorHttpClockSample{utc + 2000U, 2000U} ; }) ;	// fake時計だけ。
			std::array<CollectorHttpPermit, 2U> permits ;							// 予約は実保存、HTTPは未実行です。
			// 元枠だけを予約し、executor／native clientは作りません。
			for( std::size_t slot = 0U; slot < reserved; ++slot) {
				DRIVERCRATE_EXPECT( context, pool.reserveProjected( owner, permits[slot]) == 0U) ;
			}

			const auto live = projectedStoreSnapshot( context, store) ;	// 所有中の拒否前正本。
			DRIVERCRATE_EXPECT(
				context,
				owner.recoverNextProjectedReservations( utc + 3000U, 3000U) == ERROR_BUSY &&
					owner.recoverNextProjectedReservations( utc + 4000U, 4000U) == ERROR_BUSY &&
					live == projectedStoreSnapshot( context, store)) ;
		}
		const auto running =
			// 応答未保存の元予約を保持します。
			projectedStoreSnapshot( context, store) ;
		std::vector<std::map<std::wstring, std::string>> windows ;	// 最後の中断の全保存窓。
		std::vector<CollectorRecoveryCheckpoint> points ;			// 窓と停止段階を一対一対応させます。
		std::size_t responseCount{} ;								// 先行中断と最後の中断を区別します。
		{
			LocalCollectorRecovery restart ;	// 新process相当の借用、所有slotは空です。
			const auto			   stop = [&]( const CollectorRecoveryCheckpoint point) {
				// 中断responseの保存回数だけを親で数えます。
				if( point == CollectorRecoveryCheckpoint::RESPONSE) {
					++responseCount ;
				}

				// 最後の予約のRESPONSEからCOMPLETEDまでを全て独立再読込みへ渡します。
				if( responseCount == reserved) {
					windows.push_back( projectedStoreSnapshot( context, store)) ;
					points.push_back( point) ;
				}

				return false ;
			} ; // 原正本は完走し、別rootで各停止直後を再生します。
			DRIVERCRATE_EXPECT( context, restart.initializeProjected( store, next, utc + 5000U, 0U,
																	stop) == ERROR_RETRY &&
											running == projectedStoreSnapshot( context, store)) ;
			const auto code =
				// 明示中断だけ。
				restart.recoverNextProjectedReservations( utc + 6000U, 1000U) ;
			context.expect( code == 0U && restart.terminalJobs() == reserved &&
							   restart.reason() == L"NEXT_RESERVATIONS_INTERRUPTED",
						   "unanswered settle scenario=" + std::to_string( scenario) +
							   " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
			// 第一失敗は保存し、後続の仮定を成功へ変更しません。
			if( code != 0U) {
				continue ;
			}

			const auto settled = projectedStoreSnapshot( context, store) ;	// 二重精算・再保存なし。
			DRIVERCRATE_EXPECT( context,
							   restart.recoverNextProjectedReservations( utc + 7000U, 2000U) == 0U &&
								   settled == projectedStoreSnapshot( context, store)) ;
		}
		DRIVERCRATE_EXPECT( context, windows.size() == (scenario == 1U ? 15U : 16U) &&
										responseCount == reserved &&
										points.size() == windows.size()) ;
		CollectorBudgetSnapshot budget ;	// 欠測byteは最大予約量でphase2に閉鎖します。
		DRIVERCRATE_EXPECT( context,
						   parseCollectorBudgetSnapshot(
							   httpSavedBody( store, L"current/campaign-budget-v1.json"), budget)) ;
		std::size_t closed{} ;	// 今回の中断数だけ。
		// 旧精算は不変、今回の予約だけ最大量・不明状態で閉鎖します。
		for( const auto &reservation : budget.reservations) {
			// 旧世代の予算を新しい欠測へ置換しません。
			if( reservation.campaign == nextIdentity.generationKey) {
				DRIVERCRATE_EXPECT( context, reservation.phase == 2U &&
												reservation.charged == reservation.maximum) ;
				++closed ;
			}
		}

		DRIVERCRATE_EXPECT( context, closed == reserved) ;
		// 中断responseの欠測と元成功群の全byte保持を別々に確認します。
		for( std::size_t index = 0U; index < reserved; ++index) {
			std::wstring op ;	// 元一操作の実hash。
			DRIVERCRATE_EXPECT(
				context, computeBytesSha256(
							 "response-v2\n" + winrt::to_string( nextIdentity.generationKey) + "\n" +
								 winrt::to_string( nextIdentity.jobs[index].jobKey) + "\n",
							 op) == 0U) ;
			const auto response = JsonObject::Parse( winrt::to_hstring(
				httpSavedBody( store,
							  L"runs/campaign-response-v2-" + op + L".json"))) ;	// 元canonical中断。
			DRIVERCRATE_EXPECT( context, response.GetNamedString( L"state") == L"INTERRUPTED" &&
											response.GetNamedValue( L"sends").ValueType() ==
												winrt::Windows::Data::Json::JsonValueType::Null &&
											response.GetNamedValue( L"bytes").ValueType() ==
												winrt::Windows::Data::Json::JsonValueType::Null &&
											response.GetNamedNumber( L"finished") ==
												static_cast<double>( utc + 6000U) &&
											response.GetNamedNumber( L"accepted") ==
												static_cast<double>( utc + 6000U)) ;
			const auto name = L"current/campaign-cache-v1-" + nextIdentity.jobs[index].requestKey +
							  L".json" ;	// 同requestのみ。
			const auto cache =
				// 実保存後像。
				JsonObject::Parse( winrt::to_hstring( httpSavedBody( store, name))) ;
			DRIVERCRATE_EXPECT( context, cache.GetNamedString( L"reason") == L"INTERRUPTED" &&
											!cache.GetNamedBoolean( L"reusable") &&
											cache.GetNamedValue( L"etag").ValueType() ==
												winrt::Windows::Data::Json::JsonValueType::Null) ;
			// 真の新requestだけ旧成功なしです。既存requestは旧参照群を一byteも変えません。
			if( scenario == 1U && index == 1U) {
				DRIVERCRATE_EXPECT( context,
								   cache.GetNamedArray( L"slices").Size() == 0U &&
									   cache.GetNamedValue( L"original200").ValueType() ==
										   winrt::Windows::Data::Json::JsonValueType::Null) ;
			} else {
				const auto old = JsonObject::Parse(
					// 不変の初回CACHE。
					winrt::to_hstring( httpSavedBody( first, name))) ;
				// 成功slice・元200・検証日は独立に元参照byteと比較します。
				for( const auto field : {L"slices", L"original200", L"validated"}) {
					DRIVERCRATE_EXPECT( context, cache.GetNamedValue( field).Stringify() ==
													old.GetNamedValue( field).Stringify()) ;
				}
			}
		}

		const auto final = projectedStoreSnapshot( context, store) ;	// 元完了像は不変です。
		// 現在台帳以外の全旧run／stateと最新完了pointerを保持します。
		for( const auto &[name, raw] : original) {
			// 旧履歴とpointerは中断精算の所有更新範囲へ含めません。
			if( name.starts_with( L"runs/") || name.starts_with( L"current/campaign-state-v3-") ||
			   name == L"current/campaign-current-v2.json") {
				DRIVERCRATE_EXPECT( context, final.at( name) == raw) ;
			}
		}

		// v2中断の応答・全準備像・登録・四反映・確定から非再送復旧します。
		for( std::size_t window = 0U; window < windows.size(); ++window) {
			LocalCollectorStateStore resumed ;	// 一つの固定中断直後。
			DRIVERCRATE_EXPECT( context, resumed.initialize( rootFactory(), true) == 0U) ;
			// 元checkpoint全rawをコピーし、期待後像は生成しません。
			for( const auto &[name, raw] : windows[window]) {
				DRIVERCRATE_EXPECT( context, resumed.write( name, raw) == 0U) ;
			}

			{
				LocalCollectorRecovery fresh ;	// 元監督の借用を持ち越しません。
				const auto			   code = fresh.initializeProjected( resumed, next, utc + 9000U,
																		0U) ;	// 保存v2だけを回収します。
				context.expect( code == 0U && fresh.terminalJobs() == reserved,
							   "unanswered window scenario=" + std::to_string( scenario) +
								   " window=" + std::to_string( window) +
								   " code=" + std::to_string( code),
							   __FILE__, __LINE__) ;
			}
			const auto recovered =
				// 元中断時刻を維持した全byte。
				projectedStoreSnapshot( context, resumed) ;
			DRIVERCRATE_EXPECT( context, recovered.size() == final.size()) ;
			// 元応答・全前後像・CACHE・旧履歴はroot以外を全byteで比較します。
			for( const auto &[name, raw] : final) {
				// rootだけは監督時計を以下で独立に検査します。
				if( name != L"current/campaign-root-v2.json") {
					DRIVERCRATE_EXPECT( context, recovered.at( name) == raw) ;
				}
			}

			const auto root			= JsonObject::Parse( winrt::to_hstring( httpSavedBody(
				resumed, L"current/campaign-root-v2.json"))) ;	// 復旧監督時計だけ別値です。
			const auto expectedRoot = JsonObject::Parse( winrt::to_hstring(
				// 元完走rootの全field。
				httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
			expectedRoot.Insert(
				L"lastUtcMillis",
				JsonValue::CreateNumberValue( static_cast<double>(
					points[window] == CollectorRecoveryCheckpoint::COMPLETED ? utc + 6000U
																			 : utc + 9000U))) ;
			DRIVERCRATE_EXPECT( context, root.Stringify() == expectedRoot.Stringify()) ;
			{
				LocalCollectorRecovery twice ;	// 確定後は通常再検査のみ。
				DRIVERCRATE_EXPECT(
					context, twice.initializeProjected( resumed, next, utc + 10000U, 0U) == 0U &&
								 recovered == projectedStoreSnapshot( context, resumed)) ;
			}
		}

		// 未登録中断の復旧が登録／四反映中に再度停止しても元応答時刻で復旧します。
		for( unsigned cut = 0U; cut < 5U; ++cut) {
			LocalCollectorStateStore interrupted ;	// 最後のRESPONSE保存窓からの復旧再中断。
			DRIVERCRATE_EXPECT( context, interrupted.initialize( rootFactory(), true) == 0U) ;
			// 実保存された元v2中断だけを再開入力へ複製します。
			for( const auto &[name, raw] : windows.front()) {
				DRIVERCRATE_EXPECT( context, interrupted.write( name, raw) == 0U) ;
			}

			{
				LocalCollectorRecovery stopped ;	// 登録後時計を持つ停止済み監督。
				unsigned			   applied{} ;	// 四roleの反映数だけを数えます。
				const auto			   stop = [&]( const CollectorRecoveryCheckpoint point) {
					// 登録直後と各反映後を分け、既定の保存順を保持します。
					if( point == CollectorRecoveryCheckpoint::APPLIED) {
						++applied ;
					}

					return cut == 0U
										   ? point == CollectorRecoveryCheckpoint::REGISTERED
										   : point == CollectorRecoveryCheckpoint::APPLIED && applied == cut ;
				} ; // 再停止も元995として返します。
				const auto code = stopped.initializeProjected( interrupted, next, utc + 11000U, 0U,
															  stop) ;	// 元時刻は6000です。
				context.expect( code == ERROR_OPERATION_ABORTED,
							   "unanswered repeated stop scenario=" + std::to_string( scenario) +
								   " cut=" + std::to_string( cut) + " code=" + std::to_string( code),
							   __FILE__, __LINE__) ;
			}
			{
				LocalCollectorRecovery fresh ;	// 登録／物理prefixを全再検査します。
				const auto code = fresh.initializeProjected( interrupted, next, utc + 12000U,
															0U) ;	// 第二復旧の現在時計。
				context.expect( code == 0U && fresh.terminalJobs() == reserved,
							   "unanswered repeated recovery scenario=" + std::to_string( scenario) +
								   " cut=" + std::to_string( cut) + " code=" + std::to_string( code),
							   __FILE__, __LINE__) ;
			}
		}

		// canonical v2中断以外の代用は、外側hashが再計算済みでも保存前に拒否します。
		for( unsigned mutation = 0U; mutation < 5U; ++mutation) {
			LocalCollectorStateStore rejected ;	// 正当な未登録v2中断からの一要因改変。
			DRIVERCRATE_EXPECT( context, rejected.initialize( rootFactory(), true) == 0U) ;
			// 応答と元予約・閉包の全rawを保存します。
			for( const auto &[name, raw] : windows.front()) {
				DRIVERCRATE_EXPECT( context, rejected.write( name, raw) == 0U) ;
			}

			std::wstring op ;	// 最後の元操作の固定hash。
			DRIVERCRATE_EXPECT(
				context, computeBytesSha256(
							 "response-v2\n" + winrt::to_string( nextIdentity.generationKey) + "\n" +
								 winrt::to_string( nextIdentity.jobs[reserved - 1U].jobKey) + "\n",
							 op) == 0U) ;
			mutateProjectedStore(
				context, rejected, L"runs/campaign-response-v2-" + op + L".json",
				[mutation]( JsonObject &response) {
					// 中断の固定表現・欠測・元scope以外を一つずつ変更します。
					switch( mutation) {
						// 通信成功状態を欠測中断に混入しません。
						case 0U:
							response.Insert( L"status", JsonValue::CreateNumberValue( 200.0)) ;
							break ;

						// 不明送信数を観測された0へ補完しません。
						case 1U:
							response.Insert( L"sends", JsonValue::CreateNumberValue( 0.0)) ;
							break ;

						// 元開始より過去のacceptedを許可しません。
						case 2U:
							response.Insert( L"accepted", JsonValue::CreateNumberValue( 0.0)) ;
							break ;

						// 別CACHE bindingへ読み替えません。
						case 3U:
							response.Insert( L"cache",
											JsonValue::CreateStringValue( std::wstring( 64U, L'f'))) ;
							break ;

						// v3 schemaは保存v2中断の代用になりません。
						default:
							response.Insert( L"schema", JsonValue::CreateStringValue(
														   L"collector-campaign-response-v3")) ;
							break ;
					}
				}) ;
			const auto before =
				// 改変後全byteの拒否正本。
				projectedStoreSnapshot( context, rejected) ;
			LocalCollectorRecovery refusal ;	// 規則を緩めずに通常回復を拒否します。
			const auto			   code =
				// 元13を要求します。
				refusal.initializeProjected( rejected, next, utc + 11000U, 0U) ;
			context.expect(
				code == ERROR_INVALID_DATA && before == projectedStoreSnapshot( context, rejected),
				"unanswered v2 refusal scenario=" + std::to_string( scenario) +
					" mutation=" + std::to_string( mutation) + " code=" + std::to_string( code),
				__FILE__, __LINE__) ;
		}

		// 最初の応答保存で本当に995を返し、同監督は継続せず元errorを保持します。
		{
			LocalCollectorStateStore aborted ;	// 未応答正本から独立の実停止。
			DRIVERCRATE_EXPECT( context, aborted.initialize( rootFactory(), true) == 0U) ;
			// 原RUNNING全rawを使い直し、元確定結果を成功へ変更しません。
			for( const auto &[name, raw] : running) {
				DRIVERCRATE_EXPECT( context, aborted.write( name, raw) == 0U) ;
			}

			{
				LocalCollectorRecovery stopped ;	// 停止後は全保存を禁止します。
				DRIVERCRATE_EXPECT(
					context, stopped.initializeProjected(
								 aborted, next, utc + 5000U, 0U,
								 []( CollectorRecoveryCheckpoint point) {
									 return point == CollectorRecoveryCheckpoint::RESPONSE ;
								 }) == ERROR_RETRY &&
								 stopped.recoverNextProjectedReservations( utc + 6000U, 1000U) ==
									 ERROR_OPERATION_ABORTED) ;
				const auto cut = projectedStoreSnapshot( context, aborted) ;	// 原995の保存物。
				DRIVERCRATE_EXPECT( context, stopped.recoverNextProjectedReservations(
												utc + 7000U, 2000U) == ERROR_OPERATION_ABORTED &&
												cut == projectedStoreSnapshot( context, aborted)) ;
			}
			{
				LocalCollectorRecovery resumed ;	// 保存済み一件を先行回収して残予約だけ中断します。
				const DWORD			   expected =
					// 元APIとcode型を一致させます。
					reserved == 1U ? ERROR_SUCCESS : ERROR_RETRY ;
				DRIVERCRATE_EXPECT(
					context,
					resumed.initializeProjected( aborted, next, utc + 9000U, 0U) == expected &&
						resumed.recoverNextProjectedReservations( utc + 10000U, 1000U) == 0U &&
						resumed.terminalJobs() == reserved) ;
			}
		}
		// 要求外proof、現在CACHE、開始control／予算、時計とstate差替えを保存前に拒否します。
		for( unsigned mutation = 0U; mutation < 7U; ++mutation) {
			LocalCollectorStateStore rejected ;	// 監督読込み後の一要因改変。
			DRIVERCRATE_EXPECT( context, rejected.initialize( rootFactory(), true) == 0U) ;
			// 元未応答の全正本だけを複製します。
			for( const auto &[name, raw] : running) {
				DRIVERCRATE_EXPECT( context, rejected.write( name, raw) == 0U) ;
			}

			LocalCollectorRecovery refusal ;	// 改変前は正当な非変更待機です。
			DRIVERCRATE_EXPECT( context, refusal.initializeProjected( rejected, next, utc + 5000U,
																	0U) == ERROR_RETRY) ;
			// それぞれ外側hashは再計算し、型／関係の拒否を要求します。
			switch( mutation) {
				// 要求外の元Intel応答も全閉包の対象です。
				case 0U:
					mutateProjectedStore(
						context, rejected, L"runs/campaign-response-v4-" + initialOp + L".json",
						[]( JsonObject &value) {
							value.Insert( L"status", JsonValue::CreateNumberValue( 201.0)) ;
						}) ;
					break ;

				// 現CACHEの登録hashに一致しない自己一貫像を拒否します。
				case 1U:
					mutateProjectedStore(
						context, rejected,
						L"current/campaign-cache-v1-" + identity.jobs[0].requestKey + L".json",
						[]( JsonObject &value) {
							value.Insert( L"reason", JsonValue::CreateStringValue( L"INTERRUPTED")) ;
						}) ;
					break ;

				// 待機controlを未結合の開始値へ差し替える変更を拒否します。
				case 2U:
					mutateProjectedStore( context, rejected, L"current/campaign-controls-v1.json",
										 []( JsonObject &value) {
											 value.GetNamedArray( L"controls")
												 .GetObjectAt( 0U)
												 .Insert( L"started",
														 JsonValue::CreateNumberValue( 1.0)) ;
										 }) ;
					break ;

				// 元予約上限の自己一貫差替えは許しません。
				case 3U:
					mutateProjectedStore( context, rejected, L"current/campaign-budget-v1.json",
										 []( JsonObject &value) {
											 value.GetNamedArray( L"reservations")
												 .GetObjectAt( 0U)
												 .Insert( L"maximum",
														 JsonValue::CreateNumberValue( 1.0)) ;
										 }) ;
					break ;

				// 元stateの外側hashが正しくても監督正本との差替えを拒否します。
				case 4U:
					mutateProjectedStore( context, rejected,
										 L"current/campaign-state-v3-" +
											 nextIdentity.generationKey + L".json",
										 []( JsonObject &value) {
											 value.GetNamedArray( L"jobs").GetObjectAt( 0U).Insert(
												 L"started", JsonValue::CreateNumberValue( 0.0)) ;
										 }) ;
					break ;

				// 未知名を既存許可集合へ加えません。
				case 5U:
					saveRegisteredHistoryFixture( context, rejected,
												 L"runs/campaign-unanswered-unknown.json", "{}") ;
					break ;

				// 時計条件だけの拒否は保存物を改変しません。
				default:
					break ;
			}

			const auto before = projectedStoreSnapshot( context, rejected) ;	// 拒否した元全byte。
			const auto code	  = refusal.recoverNextProjectedReservations(
				  // 巻戻しを別に検査します。
				  mutation == 6U ? utc + 4000U : utc + 6000U, 1000U) ;
			context.expect( code == ERROR_INVALID_DATA && refusal.lastError() == code &&
							   before == projectedStoreSnapshot( context, rejected),
						   "unanswered refusal scenario=" + std::to_string( scenario) +
							   " mutation=" + std::to_string( mutation) +
							   " code=" + std::to_string( code),
						   __FILE__, __LINE__) ;
		}
	}
}

/** @see local_collector_http_tests.h */
void runCollectorCompletedInventoryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	static_assert(
		!std::is_default_constructible_v<CollectorCompletedRootInventory::ConstructionKey> &&
		!std::is_default_constructible_v<
			CollectorCompletedRootInventory>) ;	// Callerの値だけで構築できません。
	const auto digest = [&context]( const std::string_view bytes) {
		std::wstring hash ;										// 本番封印encoderに依存しないCNGの実byte hashです。
		const auto	 error = computeBytesSha256( bytes, hash) ;	// Fixture準備の元errorです。
		DRIVERCRATE_EXPECT( context, error == 0U) ;
		// CNG失敗を内容拒否の成功fixtureへ読み替えません。
		if( error != 0U) {
			throw std::runtime_error( "completed inventory digest") ;
		}

		return hash ;
	} ; // 全byte照合の独立oracleです。
	const auto definition = definitionFactory() ;	// 元二sourceの架空公開入力です。
	DWORD	   missingNumber{} ;					// 欠損数値fieldの元WinRT errorを独立に得ます。
	try {
		(void)JsonObject::Parse( L"{}").GetNamedNumber( L"closedUtcMillis") ;
	} catch( const winrt::hresult_error &error) {
		missingNumber = static_cast<DWORD>( error.code().value) ;
	}

	DRIVERCRATE_EXPECT( context, missingNumber != 0U) ;
	const auto identityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。
	auto &identity = *identityOwner ;			// 本番codecで入力を固定します。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		prepared ;	// 偽worker専用の元所有入力です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, prepared)) ;
	// Fixture入力不成立を成功根拠にしません。
	if( !prepared) {
		return ;
	}

	LocalCollectorStateStore original ;	// 本番parser／偽HTTPから完了根拠を作ります。
	DRIVERCRATE_EXPECT( context, original.initialize( rootFactory(), true) == 0U) ;
	const auto responsesOwner = std::make_unique<
		std::array<CollectorProjectedResponseBytes, 2U>>() ;	// 固定件数と型を保って所有する。
	auto &responses = *responsesOwner ;							// 元200の所有結果です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, original, definition,
															   prepared, 0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 既存借用の競合を先に検査します。
		DRIVERCRATE_EXPECT( context, owner.initializeProjected( original, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
		std::shared_ptr<const CollectorCompletedRootInventory>
				   rejected ;												// 稼働中の偽造封印を許しません。
		const auto before = projectedStoreSnapshot( context, original) ;	// 全raw不変の正本です。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorRecovery::inspectCompletedRootInventory(
							   original, definition.sources, HTTP_TEST_UTC + 126000U, rejected) ==
								   ERROR_BUSY &&
							   !rejected && before == projectedStoreSnapshot( context, original)) ;
		DRIVERCRATE_EXPECT( context,
						   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto baseline = projectedStoreSnapshot( context, original) ;	// 全fileの独立元byteです。
	std::shared_ptr<const CollectorCompletedRootInventory> proof ;		// 全再照合後だけ発行されます。
	CollectorHistoryReadDiagnostics diagnostics ;						// raw課金と再照合開始の部分観測です。
	const auto						utc	  = HTTP_TEST_UTC + 128000U ;	// 完了後の固定検査UTCです。
	const auto						error = LocalCollectorRecovery::inspectCompletedRootInventory(
		 original, definition.sources, utc, proof, {}, &diagnostics) ;	// 元errorを保持します。
	context.expect( error == 0U && proof != nullptr,
				   "completed inventory code=" + std::to_string( error), __FILE__, __LINE__) ;
	// 不成立後の所有値へアクセスせず、元byte比較を保持します。
	if( !proof) {
		return ;
	}

	const auto &value = proof->evidence() ;	// Immutableの所有根拠です。
	DRIVERCRATE_EXPECT( context, value.files.size() == baseline.size() && value.generations == 1U &&
									value.operations == 2U && value.shards.size() == 1U &&
									value.inspectedUtcMillis == utc && diagnostics.recheckStarted &&
									diagnostics.chargedBytes >= value.fileBytes * 2U) ;
	std::uint64_t		   actualBytes{} ;	// Snapshotから独立集計する元raw量です。
	std::set<std::wstring> visited ;		// 重複・欠落を独立に拒否します。
	// 全fileの元byte量／hash／固定名を独立正本へ照合します。
	for( const auto &file : value.files) {
		const auto row = baseline.find( file.name) ;	// 元固定相対名です。
		DRIVERCRATE_EXPECT( context, row != baseline.end() && visited.insert( file.name).second) ;
		// 誤った名でmap参照を成功値にしません。
		if( row != baseline.end()) {
			actualBytes += row->second.size() ;
			DRIVERCRATE_EXPECT( context, file.bytes == row->second.size() &&
											file.sha256 == digest( row->second)) ;
		}
	}

	DRIVERCRATE_EXPECT( context,
					   actualBytes == value.fileBytes &&
						   value.rootSha256 ==
							   digest( httpSavedBody( original, L"current/campaign-root-v2.json")) &&
						   value.sealSha256 == digest( value.seal) &&
						   value.shards.front().sha256 == digest( value.shards.front().body)) ;
	const auto seal =
		// 独立に全主要結合を照合します。
		JsonObject::Parse( winrt::to_hstring( value.seal)) ;
	const auto shard =
		// 全行の元順序です。
		JsonObject::Parse( winrt::to_hstring( value.shards.front().body)) ;
	DRIVERCRATE_EXPECT(
		context,
		seal.GetNamedString( L"root") == value.rootSha256 &&
			seal.GetNamedString( L"budget") ==
				digest( httpSavedBody( original, L"current/campaign-budget-v1.json")) &&
			seal.GetNamedString( L"control") ==
				digest( httpSavedBody( original, L"current/campaign-controls-v1.json")) &&
			seal.GetNamedArray( L"inventory").GetStringAt( 0U) == value.shards.front().sha256 &&
			shard.GetNamedArray( L"files").Size() == value.files.size() &&
			baseline == projectedStoreSnapshot( context, original)) ;

	std::shared_ptr<const CollectorCompletedRootInventory> repeated =
		proof ;	// 旧出力の反復／失敗消去を検査します。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorRecovery::inspectCompletedRootInventory( original, definition.sources,
																	   utc, repeated) == 0U &&
					 repeated && repeated->evidence().seal == value.seal &&
					 repeated->evidence().shards.front().body == value.shards.front().body &&
					 baseline == projectedStoreSnapshot( context, original)) ;
	JsonArray sourceRows ;	// 本番封印encoderから独立した全sourceの元順序です。
	// 実検査契約の全fieldを独立にbyteへ組み立てます。
	for( const auto &source : definition.sources) {
		JsonObject row ;	// 元契約の全五fieldです。
		row.Insert( L"sourceId", JsonValue::CreateStringValue( source.sourceId)) ;
		row.Insert( L"resourceId", JsonValue::CreateStringValue( source.resourceId)) ;
		row.Insert( L"rateLimitGroup", JsonValue::CreateStringValue( source.rateLimitGroup)) ;
		row.Insert( L"parserRevision", JsonValue::CreateStringValue( source.parserRevision)) ;
		row.Insert( L"maximumResponseBytes",
				   JsonValue::CreateNumberValue( static_cast<double>( source.maximumResponseBytes))) ;
		sourceRows.Append( row) ;
	}

	const auto root = JsonObject::Parse( winrt::to_hstring(
		// 元ROOTの登録正本です。
		httpSavedBody( original, L"current/campaign-root-v2.json"))) ;
	DRIVERCRATE_EXPECT(
		context,
		seal.Size() == 14U &&
			seal.GetNamedString( L"schema") == L"collector-completed-root-seal-v1" &&
			seal.GetNamedString( L"rootKey") == root.GetNamedString( L"rootKey") &&
			seal.GetNamedNumber( L"rootUtc") == root.GetNamedNumber( L"lastUtcMillis") &&
			seal.GetNamedNumber( L"inspectedUtc") == static_cast<double>( utc) &&
			seal.GetNamedString( L"sources") == digest( winrt::to_string( sourceRows.Stringify())) &&
			seal.GetNamedString( L"cacheInventory") ==
				digest( winrt::to_string( root.GetNamedArray( L"cacheInventory").Stringify())) &&
			seal.GetNamedNumber( L"generations") == 1.0 &&
			seal.GetNamedNumber( L"operations") == 2.0 &&
			seal.GetNamedNumber( L"fileCount") == static_cast<double>( baseline.size()) &&
			seal.GetNamedNumber( L"fileBytes") == static_cast<double>( actualBytes) &&
			shard.GetNamedString( L"schema") == L"collector-completed-root-inventory-v1" &&
			shard.GetNamedString( L"rootKey") == value.rootKey &&
			shard.GetNamedString( L"root") == value.rootSha256 &&
			shard.GetNamedNumber( L"ordinal") == 0.0 &&
			shard.GetNamedNumber( L"fileCount") == static_cast<double>( baseline.size())) ;
	// 全行の名・byte・hashを元ordinalへ独立照合します。
	for( std::size_t index = 0U; index < value.files.size(); ++index) {
		const auto row = shard.GetNamedArray( L"files").GetObjectAt(
			// 元順序の一行です。
			static_cast<std::uint32_t>( index)) ;
		DRIVERCRATE_EXPECT( context, row.Size() == 3U &&
										row.GetNamedString( L"name") == value.files[index].name &&
										row.GetNamedNumber( L"bytes") ==
											static_cast<double>( value.files[index].bytes) &&
										row.GetNamedString( L"sha256") == value.files[index].sha256) ;
	}

	DRIVERCRATE_EXPECT( context,
					   LocalCollectorRecovery::inspectCompletedRootInventory(
						   original, definition.sources, utc + 86400000U, repeated) == 0U &&
						   repeated && repeated->evidence().seal != value.seal &&
						   repeated->evidence().rootSha256 == value.rootSha256 &&
						   repeated->evidence().shards.front().body == value.shards.front().body &&
						   baseline == projectedStoreSnapshot( context, original)) ;
	// 元errorを保持し、callbackが成功contextを代入することはありません。
	for( const DWORD fault : {ERROR_ACCESS_DENIED, ERROR_CANCELLED, ERROR_INVALID_DATA}) {
		repeated = proof ;
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
										original, definition.sources, utc, repeated,
										[fault] { return fault ; }) == fault &&
										!repeated &&
										baseline == projectedStoreSnapshot( context, original)) ;
	}

	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
									original, definition.sources, utc, repeated,
									[]() -> DWORD { throw std::bad_alloc{} ; }) ==
										static_cast<DWORD>( E_OUTOFMEMORY) &&
									!repeated) ;
	// 故障後も借用が返却され、全byteは保持されます。
	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
									original, definition.sources, utc, repeated) == 0U &&
									repeated &&
									baseline == projectedStoreSnapshot( context, original)) ;
	LocalCollectorStateStore uninitialized ;	// 非writerから証明を作りません。
	HANDLE blocked = INVALID_HANDLE_VALUE ;		// 最終ReadFile前の元sharing拒否だけを注入します。
	DRIVERCRATE_EXPECT(
		context,
		LocalCollectorRecovery::inspectCompletedRootInventory(
			original, definition.sources, utc, repeated,
			[&] {
				blocked = CreateFileW( (original.root() / L"current/campaign-root-v2.json").c_str(),
									  GENERIC_READ, 0U, nullptr, OPEN_EXISTING,
									  FILE_ATTRIBUTE_NORMAL, nullptr) ;
				return blocked == INVALID_HANDLE_VALUE ? GetLastError() : ERROR_SUCCESS ;
			}) == ERROR_SHARING_VIOLATION &&
			!repeated) ;
	// 自分が取得した故障用handleだけを閉じます。
	if( blocked != INVALID_HANDLE_VALUE) {
		const BOOL closed = CloseHandle( blocked) ;	// 自己所有の故障handleを一回だけ解放する。
		DRIVERCRATE_EXPECT( context, closed != FALSE) ;
	}

	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
									original, definition.sources, utc, repeated) == 0U &&
									repeated &&
									baseline == projectedStoreSnapshot( context, original)) ;
	repeated = proof ;
	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
									uninitialized, definition.sources, utc, repeated) ==
										ERROR_INVALID_PARAMETER &&
									!repeated) ;
	LocalCollectorStateStore readOnly ;	// 元保護rootを検査専用で開きます。
	DRIVERCRATE_EXPECT( context, readOnly.initialize( original.root(), false) == 0U) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
									readOnly, definition.sources, utc, repeated) ==
										ERROR_INVALID_PARAMETER &&
									!repeated) ;
	// 検査UTC／source不成立は元rawを変更しません。
	for( const auto invalidUtc : {0ULL, HTTP_TEST_UTC - 1ULL, 4102444800000ULL}) {
		repeated = proof ;
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
										original, definition.sources, invalidUtc, repeated) ==
											ERROR_INVALID_DATA &&
										!repeated) ;
	}

	DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
									original, {}, utc, repeated) == ERROR_INVALID_DATA &&
									!repeated) ;
	std::uint64_t remaining = 1U ;	// 保護handleの確保前拒否を独立確認します。
	std::string	  unpaid ;			// 失敗byteを成功根拠へ流用しません。
	bool		  found{} ;			// 先払い拒否は存在成功ではありません。
	DRIVERCRATE_EXPECT( context, original.read( L"current/campaign-root-v2.json", unpaid, found,
											  remaining) == ERROR_TOO_MANY_NAMES &&
									unpaid.empty() && !found && remaining == 1U) ;
	// 全存在fileを一つずつ、raw schema拒否と自己hash再計算付き本文拒否で反証します。
	for( const auto &[name, raw] : baseline) {
		// 二改変を独立rootに置き、前の失敗から再開しません。
		for( const bool recompute : {false, true}) {
			LocalCollectorStateStore altered ;	// 自作GUIDの別保護storeです。
			DRIVERCRATE_EXPECT( context, altered.initialize( rootFactory(), true) == 0U) ;
			// 元全fileを完全byteで複製します。
			for( const auto &[path, bytes] : baseline) {
				DRIVERCRATE_EXPECT( context, altered.write( path, bytes) == 0U) ;
			}

			std::string replacement = "{}" ;	// 外側schema不成立だけです。
			// 外側hashが正しくても元意味／関係が不成立なら拒否します。
			if( recompute) {
				auto envelope = JsonObject::Parse( winrt::to_hstring( raw)) ;	// 元外側field順です。
				envelope.SetNamedValue( L"body", JsonValue::CreateStringValue( L"{}")) ;
				envelope.SetNamedValue( L"sha256", JsonValue::CreateStringValue( digest( "{}"))) ;
				replacement = winrt::to_string( envelope.Stringify()) ;
			}

			DRIVERCRATE_EXPECT( context, altered.write( name, replacement) == 0U) ;
			const auto before =
				// 改変後の非変更正本です。
				projectedStoreSnapshot( context, altered) ;
			repeated			= proof ;
			const auto rejected = LocalCollectorRecovery::inspectCompletedRootInventory(
				altered, definition.sources, utc, repeated) ;	// 第一拒否を採点します。
			const DWORD expected =
				recompute && name.starts_with( L"runs/campaign-finish-v1-")
					? missingNumber
					: ERROR_INVALID_DATA ;	// 元closedUtcMillis参照の先着errorです。
			context.expect( rejected == expected && !repeated &&
							   before == projectedStoreSnapshot( context, altered),
						   "seal reject " + winrt::to_string( name) +
							   " code=" + std::to_string( rejected),
						   __FILE__, __LINE__) ;
		}
	}

	// 最終全raw／全名照合でのみ検出する変更を独立rootへ注入します。
	for( const bool addition : {false, true}) {
		LocalCollectorStateStore altered ;	// 終了直前だけを検査する別rootです。
		DRIVERCRATE_EXPECT( context, altered.initialize( rootFactory(), true) == 0U) ;
		// 同じ全完了元byteから開始します。
		for( const auto &[name, bytes] : baseline) {
			DRIVERCRATE_EXPECT( context, altered.write( name, bytes) == 0U) ;
		}

		std::map<std::wstring, std::string>
			changed ;	// callback変更以外の保存がないことを照合します。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorRecovery::inspectCompletedRootInventory(
							   altered, definition.sources, utc, repeated,
							   [&] {
								   const auto saved =
									   altered.write( addition ? L"current/unknown-seal-fixture.json"
															  : L"current/campaign-root-v2.json",
													 "{}") ;	// 元I/Oです。
								   changed = projectedStoreSnapshot( context, altered) ;
								   return saved ;
							   }) == ERROR_INVALID_DATA &&
							   !repeated && changed == projectedStoreSnapshot( context, altered)) ;
	}

	LocalCollectorStateStore unknown ;	// 無関係な未知fileも封印へ混入させません。
	DRIVERCRATE_EXPECT( context, unknown.initialize( rootFactory(), true) == 0U) ;
	// 元全fileを自作rootへ複製します。
	for( const auto &[name, bytes] : baseline) {
		DRIVERCRATE_EXPECT( context, unknown.write( name, bytes) == 0U) ;
	}

	DRIVERCRATE_EXPECT( context, unknown.write( L"current/unknown-seal-fixture.json", "{}") == 0U) ;
	const auto unknownBefore =
		// 元追加fileも削除しません。
		projectedStoreSnapshot( context, unknown) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorRecovery::inspectCompletedRootInventory(
						   unknown, definition.sources, utc, repeated) == ERROR_INVALID_DATA &&
						   !repeated && unknownBefore == projectedStoreSnapshot( context, unknown)) ;
	LocalCollectorStateStore pending ;	// 未完了履歴を封印しません。
	DRIVERCRATE_EXPECT( context, pending.initialize( rootFactory(), true) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 入力登録だけで終えます。
		DRIVERCRATE_EXPECT( context,
						   owner.initializeProjected( pending, definition, HTTP_TEST_UTC, 0U) == 0U) ;
	}
	const auto pendingBefore = projectedStoreSnapshot( context, pending) ;	// 未完了のまま保持します。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorRecovery::inspectCompletedRootInventory(
						   pending, definition.sources, utc, repeated) == ERROR_INVALID_DATA &&
						   !repeated && pendingBefore == projectedStoreSnapshot( context, pending)) ;
	{
		LocalCollectorRecovery deferred ;	// 未予約jobを元日に全DEFERREDで閉じます。
		DRIVERCRATE_EXPECT(
			context, deferred.initializeProjected( pending, definition, HTTP_TEST_UTC + 86400000U,
												  0U) == 0U &&
						 deferred.finishInitialProjected( HTTP_TEST_UTC + 86401000U, 1000U) == 0U) ;
	}
	const auto deferredBefore =
		// CACHEを捏造しない完了です。
		projectedStoreSnapshot( context, pending) ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorRecovery::inspectCompletedRootInventory(
					 pending, definition.sources, HTTP_TEST_UTC + 86402000U, repeated) == 0U &&
					 repeated && repeated->evidence().operations == 0U &&
					 repeated->evidence().generations == 1U &&
					 deferredBefore == projectedStoreSnapshot( context, pending)) ;
	auto nextDefinition			  = definition ;	// 同じ公開対象で別artifactの二世代目を固定します。
	nextDefinition.artifactSha256 = digest( "completed-inventory-second-generation") ;
	{
		LocalCollectorRecovery next ;	// 初回全完了の元根拠からだけ明示開始します。
		DRIVERCRATE_EXPECT(
			context,
			next.initializeProjected( pending, definition, HTTP_TEST_UTC + 86402000U, 0U) == 0U &&
				next.beginNextProjected( nextDefinition, HTTP_TEST_UTC + 86403000U, 1000U) == 0U) ;
	}
	const auto waitingBefore =
		// 未予約末尾は後日も自動完了しません。
		projectedStoreSnapshot( context, pending) ;
	{
		LocalCollectorRecovery deferred ;	// 別日の入力を元次世代へ受け付けず非変更待機します。
		DRIVERCRATE_EXPECT( context, deferred.initializeProjected( pending, nextDefinition,
																 HTTP_TEST_UTC + 172800000U,
																 0U) == ERROR_RETRY &&
										deferred.reason() == L"HISTORY_ACCEPTANCE_PENDING" &&
										waitingBefore == projectedStoreSnapshot( context, pending)) ;
	}
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorRecovery::inspectCompletedRootInventory(
						   pending, nextDefinition.sources, HTTP_TEST_UTC + 172802000U, repeated) ==
							   ERROR_INVALID_DATA &&
						   !repeated && waitingBefore == projectedStoreSnapshot( context, pending)) ;
	const auto nextIdentityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。
	auto &nextIdentity = *nextIdentityOwner ;	// 真の二世代目は元日に偽HTTPで閉じます。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
			   nextCampaign ;							// 元次世代の所有入力です。
	const auto nextUtc = HTTP_TEST_UTC + 86400000U ;	// 元予算archiveを作る翌日のUTCです。
	DRIVERCRATE_EXPECT(
		context,
		makeCollectorProjectedCampaignIdentity( nextDefinition, L"20260928", nextIdentity) &&
			prepareCollectorProjectedCampaign(
				nextIdentity.canonicalInput, nextIdentity.inputSha256, nextIdentity.generationKey,
				nextDefinition.artifactSha256, nextDefinition.sources, nextCampaign)) ;
	// 所有入力不成立を架空worker成功へ補完しません。
	if( !nextCampaign) {
		return ;
	}

	{
		LocalCollectorRecovery owner ;	// 同じ元成功rootの明示次世代です。
		DRIVERCRATE_EXPECT( context,
						   owner.initializeProjected( original, nextDefinition, nextUtc, 0U) == 0U &&
							   owner.beginNextProjected( nextDefinition, nextUtc, 1000U) == 0U) ;
		const auto fixturesOwner =
			std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
		auto &fixtures	 = *fixturesOwner ;					// 実HTTPを使わない二所有workerです。
		fixtures[0].body = winrt::to_string( winrt::hstring( projectedIntelHtml())) ;
		fixtures[1].body = winrt::to_string( winrt::hstring( projectedAsusRowsHtml( 2U))) ;
		CollectorProjectedExecutorDependencies dependencies ;	// 全依存はこのscope内だけ借用します。
		dependencies.campaign = nextCampaign ;
		dependencies.clock	  = [nextUtc] {
			   return activeFixture ? activeFixture->clock
									: CollectorHttpClockSample{nextUtc + 3000U, 3000U} ;
		} ;
		dependencies.createClient = [] {
			return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
		} ;
		std::size_t workers{} ;	// 有限二slotを親threadだけが数えます。
		dependencies.start = [&]( std::function<void()> worker) {
			const auto slot = workers++ ;	// 元ordinalをthreadへ所有copyします。
			return std::thread( [&, slot, worker = std::move( worker)] {
				fixtures[slot].ownerThread = std::this_thread::get_id() ;
				fixtures[slot].clock	   = {nextUtc + 3000U, 3000U} ;
				FixtureScope scope( fixtures[slot]) ;	// 全native依存をfakeへ固定します。
				worker() ;
			}) ;
		} ;
		LocalCollectorProjectedExecutor executor( std::move( dependencies)) ;	// 本番所有poolです。
		DRIVERCRATE_EXPECT( context,
						   executor.startNext( owner) == 0U && executor.startNext( owner) == 0U) ;
		const auto joined = executor.join() ;	// 受領前に全workerを回収します。
		DRIVERCRATE_EXPECT( context,
						   joined.error == 0U && joined.started == 2U && joined.joined == 2U) ;
		DRIVERCRATE_EXPECT(
			context, owner.acceptNextProjected( executor, 1U, nextUtc + 4000U, 4000U) == 0U &&
						 owner.acceptNextProjected( executor, 0U, nextUtc + 5000U, 5000U) == 0U &&
						 owner.finishNextProjected( nextUtc + 6000U, 6000U) == 0U) ;
	}
	const auto twoGenerations =
		// 全元日archiveを含む元byteです。
		projectedStoreSnapshot( context, original) ;
	const auto secondError = LocalCollectorRecovery::inspectCompletedRootInventory(
		original, nextDefinition.sources, nextUtc + 7000U, repeated) ;	// 元errorです。
	context.expect( secondError == 0U && repeated && repeated->evidence().generations == 2U &&
					   repeated->evidence().operations == 4U &&
					   twoGenerations == projectedStoreSnapshot( context, original) &&
					   JsonObject::Parse( winrt::to_hstring( httpSavedBody(
											 original, L"current/campaign-root-v2.json")))
							   .GetNamedArray( L"archives")
							   .Size() > 0U,
				   "two-generation seal code=" + std::to_string( secondError), __FILE__, __LINE__) ;
}

/** @see local_collector_http_tests.h */
void runCollectorHistoryLayoutV3Tests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceの架空公開条件です。
	const std::wstring collectionKey( 64U, L'1') ;					// 実端末identityを使いません。
	const std::wstring segmentKey( 64U, L'2') ;						// v3 ROOT keyとは別の配置identityです。
	const auto		   location = rootFactory() / collectionKey ;	// 自身の生成領域内だけです。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元保存時計と検査時計を分けます。
	std::shared_ptr<const CollectorCompletedRootInventory>
		proof ;	// 全v3 raw再検査後だけ発行します。
	std::shared_ptr<const CollectorSharedRootInventory>
										shared ;	// 個別共有根拠であり結合sealではありません。
	std::map<std::wstring, std::string> baseline ;	// v3個別根拠の非変更像です。
	{
		LocalCollectorCollectionStore parent ;	// Leaseより後に解放する元writerです。
		DRIVERCRATE_EXPECT( context, parent.initialize( location, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 同じ親だけの固定履歴を所有します。
		DRIVERCRATE_EXPECT( context, parent.borrowHistorySegment( segmentKey, true, lease) == 0U &&
										lease && lease->history()) ;
		// Fixture準備失敗を後続assertionへ見せかけません。
		if( !lease || !lease->history()) {
			throw std::runtime_error( "history layout v3 lease") ;
		}

		auto &store = *lease->history() ;	// 専用固定pathのwriterだけを借用します。
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
										store, definition.sources, utc, proof) == 13U &&
										!proof) ;
		CollectorProjectedCampaignIdentity identity ;	// 元identity算法を変更しません。
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			prepared ;	// 所有した入力をworker終了まで保持します。
		DRIVERCRATE_EXPECT(
			context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
						 prepareCollectorProjectedCampaign(
							 identity.canonicalInput, identity.inputSha256, identity.generationKey,
							 definition.artifactSha256, definition.sources, prepared)) ;
		// 未準備入力から成功履歴を作りません。
		if( !prepared) {
			throw std::runtime_error( "history layout v3 input") ;
		}

		std::array<CollectorProjectedResponseBytes, 2U>
			responses ;	// 実worker／fake HTTPの元200です。
		DRIVERCRATE_EXPECT( context,
						   initialProjectedStorageFixture( context, store, definition, prepared, 0U,
														  {}, responses) == 0U) ;
		{
			LocalCollectorRecovery owner ;	// 同一storeの監督借用中は読取り封印を拒否します。
			DRIVERCRATE_EXPECT( context, owner.initializeProjected(
											store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
			DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
											store, definition.sources, utc, proof) == 170U &&
											!proof) ;
			DRIVERCRATE_EXPECT( context,
							   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
		}
		baseline = projectedStoreSnapshot( context, store) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
										store, definition.sources, utc, proof) == 0U &&
										proof) ;
		DRIVERCRATE_EXPECT( context, proof && proof->evidence().generations == 1U &&
										proof->evidence().operations == 2U &&
										proof->evidence().files.size() == baseline.size()) ;
		DRIVERCRATE_EXPECT( context, baseline == projectedStoreSnapshot( context, store)) ;
		CollectorSharedLedgerSnapshot
			snapshot ;	// 配置だけの独立共有値。v3予算との一致は要求しません。
		snapshot.collection	   = collectionKey ;
		snapshot.lastUtcMillis = HTTP_TEST_UTC ;
		snapshot.budget		   = {L"20260927", HTTP_TEST_UTC / 1000U, {}} ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSharedStore::inspectSharedRootInventory(
										parent, *lease, utc, shared) == 0U &&
										shared) ;
		DRIVERCRATE_EXPECT( context,
						   shared && shared->evidence().snapshot.budget.reservations.empty()) ;
		DRIVERCRATE_EXPECT( context, baseline == projectedStoreSnapshot( context, store)) ;
		DRIVERCRATE_EXPECT( context, parent.close() == 170U) ;
	}
	{
		LocalCollectorCollectionStore reopened ;	// 旧leaseを完全解放後に新ownerで開きます。
		DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 非作成だけの再借用です。
		DRIVERCRATE_EXPECT( context, reopened.borrowHistorySegment( segmentKey, false, lease) == 0U &&
										lease && lease->history()) ;
		// 復帰不成立では旧proofを新鮮な根拠として使用しません。
		if( !lease || !lease->history()) {
			throw std::runtime_error( "history layout v3 reopen") ;
		}

		std::shared_ptr<const CollectorCompletedRootInventory> fresh ;	// 同UTCの新実handle根拠です。
		DRIVERCRATE_EXPECT( context, LocalCollectorRecovery::inspectCompletedRootInventory(
										*lease->history(), definition.sources, utc, fresh) == 0U &&
										fresh) ;
		DRIVERCRATE_EXPECT( context,
						   fresh && proof && fresh->evidence().seal == proof->evidence().seal) ;
		std::shared_ptr<const CollectorSharedRootInventory>
			freshShared ;	// 親と子をfresh再検査します。
		DRIVERCRATE_EXPECT( context, LocalCollectorSharedStore::inspectSharedRootInventory(
										reopened, *lease, utc, freshShared) == 0U &&
										freshShared) ;
		DRIVERCRATE_EXPECT( context, shared && freshShared &&
										shared->evidence().seal == freshShared->evidence().seal) ;
		DRIVERCRATE_EXPECT( context, baseline == projectedStoreSnapshot( context, *lease->history())) ;
	}
}

namespace {
/** @brief 自身の新階層fixtureの全名／全保存byteを独立に保持します。
 * @param[in] root 自身のGUID領域に置いたcollection。
 * @return 排他lockだけを除いた相対名と元byte。
 * @throws std::runtime_error Fixture読取りに失敗した場合。
 */
std::map<std::wstring, std::string> segmentFixtureImage( const std::filesystem::path &root)
{
	std::map<std::wstring, std::string> result ;		// 全三scopeの非変更正本です。
	const auto absolute = segmentFixturePath( root) ;	// 同じfixtureだけの長いpathです。
	// 自作fixtureだけを全階層で列挙し、未知fileも拒否像へ保持します。
	for( const auto &entry : std::filesystem::recursive_directory_iterator( absolute)) {
		// 排他lockの共有readだけは行いません。
		if( entry.is_regular_file() && entry.path().filename() != L"collector.lock") {
			std::ifstream stream( entry.path(),
								 std::ios::binary) ;	// fixtureだけの独立raw readerです。
			// 欠測を空byteの成功像として扱いません。
			if( !stream.good()) {
				throw std::runtime_error( "segment fixture read") ;
			}

			result.emplace( entry.path().lexically_relative( absolute).generic_wstring(),
						   std::string( std::istreambuf_iterator<char>( stream), {})) ;
		}
	}

	return result ;
}
/** @brief 自身の既知fixture fileだけを反証または元byteへ戻します。
 * @param[in] path 自作GUID領域内の明示file。
 * @param[in] raw 故意の変更byteまたは元byte。
 * @throws std::runtime_error Fixture保存に失敗した場合。
 */
void alterSegmentFixture( const std::filesystem::path &path, const std::string_view raw)
{
	std::ofstream stream( segmentFixturePath( path),
						 std::ios::binary | std::ios::trunc) ;	// ACLと階層は変更しません。
	stream.write( raw.data(), static_cast<std::streamsize>( raw.size())) ;
	// 故障注入失敗を製品の変更検出成功として数えません。
	if( !stream.good()) {
		throw std::runtime_error( "segment fixture write") ;
	}
}
/** @brief 自作fixtureだけへ元正規fileまたはdirectoryのDACLを複製します。
 * @param[in] model 同じfixtureで同じ種類の元検査済みfileまたはdirectory。
 * @param[in] target 同じfixtureで同じ種類の自作fileまたはdirectory。
 * @throws std::runtime_error FixtureのACL取得／設定に失敗した場合。
 * @note 製品の修復処理ではありません。不正ACL拒否と未知名拒否を分離します。
 */
void copySegmentFixtureDacl( const std::filesystem::path &model, const std::filesystem::path &target)
{
	DWORD required{} ;	// 元file DACLだけの有限descriptor長です。
	(void)GetFileSecurityW( segmentFixturePath( model).c_str(), DACL_SECURITY_INFORMATION, nullptr,
						   0U, &required) ;
	// 取得前の必要量照会以外の故障をfixture成功へ変えません。
	if( GetLastError() != ERROR_INSUFFICIENT_BUFFER || required == 0U || required > 8192U) {
		throw std::runtime_error( "segment fixture DACL size") ;
	}

	std::vector<std::byte> descriptor( required) ;	// 自己相対descriptorを呼出し中だけ所有します。
	// 元fileと同じ保護DACLだけを適用し、ownerやOS policyを変更しません。
	if( !GetFileSecurityW( segmentFixturePath( model).c_str(), DACL_SECURITY_INFORMATION,
						 descriptor.data(), required, &required) ||
	   !SetFileSecurityW( segmentFixturePath( target).c_str(),
						 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
						 descriptor.data())) {
		throw std::runtime_error( "segment fixture DACL copy") ;
	}
}
/** @brief 自作の故障fixtureだけへ広すぎるDACLを設定します。
 * @param[in] path 自作GUID配下で変更を許可したfileまたはdirectory。
 * @param[in] directory OICI付きのdirectory用DACLならtrueです。
 * @throws std::runtime_error 故障注入に失敗した場合。
 * @note OS設定を変更せず、試験callerが正規fixtureからDACLを復元します。
 */
void broadenSegmentFixtureDacl( const std::filesystem::path &path, const bool directory)
{
	PSECURITY_DESCRIPTOR raw{} ;	// 故障fixtureだけの一時descriptorです。
	// 注入不能を製品の保護拒否として数えません。
	if( !ConvertStringSecurityDescriptorToSecurityDescriptorW( directory ? L"D:P(A;OICI;FA;;;WD)"
																	   : L"D:P(A;;FA;;;WD)",
															 SDDL_REVISION_1, &raw, nullptr)) {
		throw std::runtime_error( "segment fixture broad DACL") ;
	}

	const std::unique_ptr<void, decltype( &LocalFree)> descriptor(
		raw, &LocalFree) ;	// 設定中だけ所有します。
	// 自分のfixtureだけへDACLを設定し、ownerやOS policyを変更しません。
	if( !SetFileSecurityW( segmentFixturePath( path).c_str(),
						 DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
						 descriptor.get())) {
		throw std::runtime_error( "segment fixture DACL set") ;
	}
}
/** @brief 故意のcanonical本文から実CNG付きの試験envelopeを作ります。
 * @param[in] body 同期呼出し中だけ借用する有限の試験本文です。
 * @return 本文の実hashを含むcanonical envelopeです。能力ではありません。
 * @throws std::runtime_error CNGまたはfixture構築に失敗した場合。
 */
std::string segmentFixtureEnvelope( const std::string_view body)
{
	std::wstring hash ;	// callerが仮定したhashでなく実本文のhashです。
	// CNG失敗から正常な故障fixtureを補完しません。
	if( computeCollectorMetadataSha256( body, hash) != 0) {
		throw std::runtime_error( "segment fixture envelope hash") ;
	}

	collector_projected_json::Writer writer( 2U * 1024U * 1024U) ;	// 元raw上限を維持します。
	writer.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	writer.text( body) ;
	writer.append( ",\"sha256\":") ;
	writer.wideText( hash) ;
	writer.append( "}") ;
	return writer.take() ;
}
/** @brief 元canonical fieldの位置だけを保って試験値へ差し替えます。
 * @param[in] body 元順を保持する試験本文です。
 * @param[in] key 最初の出現を対象にする固定field名です。
 * @param[in] value Canonical JSONの置換値です。
 * @return 元field順を保った試験本文です。
 * @throws std::runtime_error 元fieldが欠損している場合です。
 */
std::string replaceSegmentFixtureField( std::string body, const std::string_view key,
									   const std::string_view value)
{
	const auto prefix = "\"" + std::string( key) + "\":" ;	// 固定fixture fieldだけです。
	const auto offset = body.find( prefix) ;				// 元値を知らずに無関係な位置へ書きません。
	// Fixture不成立を製品の内容拒否へ読み替えません。
	if( offset == std::string::npos) {
		throw std::runtime_error( "segment fixture field") ;
	}

	const auto						 start = offset + prefix.size() ;		// 元値の完全先頭です。
	collector_projected_json::Reader reader( body, 2U * 1024U * 1024U) ;	// 全字句を先に検査します。
	reader.literal( std::string_view( body).substr( 0U, start)) ;
	const auto original = reader.value() ;	// 値全体の長さを用い、nested fieldを壊しません。
	body.replace( start, original.size(), value) ;
	return body ;
}
/** @brief 自作の空directoryだけへ実junctionを設定します。
 * @param[in] path 自身が作成しDACLを複製した空directoryです。
 * @param[in] target 同じGUID内で元directoryを一時退避した参照先です。
 * @throws std::runtime_error 故障注入が成立しなかった場合です。
 * @note 元storeの全handle解放後に呼び、OSの権限やpolicyを変更しません。
 */
void junctionSegmentFixture( const std::filesystem::path &path, const std::filesystem::path &target)
{
	const auto file = CreateFileW(
		segmentFixturePath( path).c_str(), GENERIC_WRITE, 0U, nullptr, OPEN_EXISTING,
		FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, nullptr) ;	// 自作nodeだけです。
	// 注入不能を製品のreparse拒否成功へ数えません。
	if( file == INVALID_HANDLE_VALUE) {
		throw std::runtime_error( "segment fixture junction handle") ;
	}

	const std::unique_ptr<void, decltype( &CloseHandle)> handle(
		file, &CloseHandle) ;										// 例外でも回収します。
	const std::wstring substitute = L"\\??\\" + target.native() ;	// 有限NT mount point表現です。
	const std::wstring print	  = target.native() ;				// 同じ自作の参照先です。
	/** @brief Win32 mount pointの固定16 byte headerです。 */
	struct Header {
		/// Mount pointの固定tagです。
		DWORD tag ;
		/// Header先頭8 byte以外の実長です。
		WORD  bytes ;
		/// 予約値0です。
		WORD  reserved ;
		/// Substitute文字列のoffsetです。
		WORD  offset ;
		/// Substituteのbyte長です。
		WORD  length ;
		/// Print文字列のoffsetです。
		WORD  printOffset ;
		/// Printのbyte長です。
		WORD  printLength ;
	} ;
	static_assert( sizeof( Header) == 16U) ;
	std::vector<BYTE> buffer( 16U + (substitute.size() + print.size() + 2U) *
									   // 有限wireです。
									   sizeof( wchar_t)) ;
	// WORD narrowingより前にWin32の有限上限を検査します。
	if( buffer.size() >= MAXIMUM_REPARSE_DATA_BUFFER_SIZE) {
		throw std::runtime_error( "segment fixture junction size") ;
	}

	const Header header{IO_REPARSE_TAG_MOUNT_POINT, static_cast<WORD>( buffer.size() - 8U), 0U, 0U,
						static_cast<WORD>( substitute.size() * sizeof( wchar_t)),
						static_cast<WORD>( (substitute.size() + 1U) * sizeof( wchar_t)),
						// OSのwireだけに変換します。
						static_cast<WORD>( print.size() * sizeof( wchar_t))} ;
	std::memcpy( buffer.data(), &header, sizeof( header)) ;
	std::memcpy( buffer.data() + 16U, substitute.c_str(),
				(substitute.size() + 1U) * sizeof( wchar_t)) ;
	std::memcpy( buffer.data() + 16U + header.printOffset, print.c_str(),
				(print.size() + 1U) * sizeof( wchar_t)) ;
	DWORD returned{} ;	// 実FSCTLの完了量です。
	// 保護参照先へ書かず、空の自作nodeだけをreparseにします。
	if( !DeviceIoControl( handle.get(), FSCTL_SET_REPARSE_POINT, buffer.data(),
						static_cast<DWORD>( buffer.size()), nullptr, 0U, &returned, nullptr)) {
		throw std::runtime_error( "segment fixture junction set") ;
	}
}
/** @brief 明示した同構成collectorだけを自作workspaceで起動します。
 * @param[in] executable Native試験の隣に置いた実collector EXEです。
 * @param[in] command 固定の--validateまたは--onceです。
 * @param[in] manifest 自作の正規公開target manifestです。
 * @param[in] state 自作GUID内の既存状態または非作成の正例pathです。
 * @param[in] workspace 自作GUID内のmini workspaceです。
 * @return 実process終了codeと最大4096 byteの標準出力です。
 * @throws std::runtime_error Process起動・30秒待機・有限出力の取得が不成立の場合です。
 * @note Nativeの明示opt-inだけで使い、Task・実driver導入・公開を行いません。
 */
std::pair<DWORD, std::string> runSegmentFixtureCli( const std::filesystem::path &executable,
												   const std::wstring_view		command,
												   const std::filesystem::path &manifest,
												   const std::filesystem::path &state,
												   const std::filesystem::path &workspace)
{
	HANDLE				readRaw{} ;		// 非継承の親側読取りhandleへ変えます。
	HANDLE				writeRaw{} ;	// 子の標準出力だけを受け取るpipeです。
	SECURITY_ATTRIBUTES security{sizeof( SECURITY_ATTRIBUTES), nullptr,
								 TRUE} ;	// 自作pipeの継承です。
	// pipe注入不成立をCLIの入力拒否へ数えません。
	if( !CreatePipe( &readRaw, &writeRaw, &security, 0U)) {
		throw std::runtime_error( "segment CLI pipe") ;
	}

	const std::unique_ptr<void, decltype( &CloseHandle)> read( readRaw, &CloseHandle) ;	// 親だけです。
	std::unique_ptr<void, decltype( &CloseHandle)>		write( writeRaw,
															  &CloseHandle) ;	// 起動後に閉じます。
	// 子へ親のread側を継承させず、出力のEOFを成立させます。
	if( !SetHandleInformation( read.get(), HANDLE_FLAG_INHERIT, 0U)) {
		throw std::runtime_error( "segment CLI pipe inheritance") ;
	}

	std::wstring arguments = L"\"" + executable.native() + L"\" " + std::wstring( command) + L" \"" +
							 manifest.native() + L"\" \"" + state.native() +
							 L"\"" ;	// 自作pathだけの固定argvです。
	STARTUPINFOW startup{} ;			// 見えるwindowや対話入力を作りません。
	startup.cb		   = sizeof( startup) ;
	startup.dwFlags	   = STARTF_USESTDHANDLES ;
	startup.hStdInput  = GetStdHandle( STD_INPUT_HANDLE) ;
	startup.hStdOutput = write.get() ;
	startup.hStdError  = write.get() ;
	PROCESS_INFORMATION process{} ;	// 起動成功後だけhandleを所有します。
	// 任意programやshellを経由せず明示EXEを起動します。
	if( !CreateProcessW( executable.c_str(), arguments.data(), nullptr, nullptr, TRUE,
					   CREATE_NO_WINDOW, nullptr, workspace.c_str(), &startup, &process)) {
		throw std::runtime_error( "segment CLI create") ;
	}

	const std::unique_ptr<void, decltype( &CloseHandle)> processHandle(
		process.hProcess, &CloseHandle) ;	// 子完了を待ちます。
	const std::unique_ptr<void, decltype( &CloseHandle)> threadHandle(
		process.hThread, &CloseHandle) ;	// 起動threadです。
	write.reset() ;
	// 診断用の子を30秒以内に確認し、無条件の強制終了は行いません。
	if( WaitForSingleObject( processHandle.get(), 30000U) != WAIT_OBJECT_0) {
		throw std::runtime_error( "segment CLI wait") ;
	}

	DWORD exitCode{} ;	// processの実返却値です。
	// 終了code取得不成立を期待した拒否値にしません。
	if( !GetExitCodeProcess( processHandle.get(), &exitCode)) {
		throw std::runtime_error( "segment CLI exit") ;
	}

	std::string output ;	// 一行の非機密結果だけを保持します。
	// 子完了後のpipeをEOFまで読み、4096 byteを超える出力は成功へ数えません。
	for( ;;) {
		std::array<char, 512U> buffer{} ;	// 一readだけの有限bufferです。
		DWORD				   count{} ;	// 実受信byteです。
		// EOF以外のpipe故障を破棄しません。
		if( !ReadFile( read.get(), buffer.data(), static_cast<DWORD>( buffer.size()), &count,
					 nullptr)) {
			// 終了した子の全出力を受信した場合だけ反復を終えます。
			if( GetLastError() == ERROR_BROKEN_PIPE) {
				break ;
			}

			throw std::runtime_error( "segment CLI output") ;
		}

		// 空readで停止し、部分出力を無限に待ちません。
		if( count == 0U) {
			break ;
		}

		// 出力の有限上限を追加前に検査します。
		if( count > 4096U - output.size()) {
			throw std::runtime_error( "segment CLI output size") ;
		}

		output.append( buffer.data(), count) ;
	}

	return {exitCode, std::move( output)} ;
}
/** @brief 検査contextではなく元保存本文から一致する共有fixtureを作ります。
 * @param[in,out] context Assertion集計。
 * @param[in,out] store 実fake workerが完了したhistory。
 * @param[in] collection 架空の配置identity。
 * @param[in] segment 架空の現区間identity。
 * @return 元codecで読み取った全値。通常製品のbootstrap移行ではありません。
 */
CollectorSharedLedgerSnapshot matchingSegmentFixture( TestContext			  &context,
													 LocalCollectorStateStore &store,
													 const std::wstring		  &collection,
													 const std::wstring		  &segment)
{
	CollectorSharedLedgerSnapshot result ;	// 期待値は新結合encoderから導出しません。
	result.collection	 = collection ;
	const auto root		 = JsonObject::Parse( winrt::to_hstring(
		 // 元登録だけです。
		 httpSavedBody( store, L"current/campaign-root-v2.json"))) ;
	result.lastUtcMillis = static_cast<std::uint64_t>( root.GetNamedNumber( L"lastUtcMillis")) ;
	DRIVERCRATE_EXPECT(
		context, parseCollectorBudgetSnapshot(
					 httpSavedBody( store, L"current/campaign-budget-v1.json"), result.budget)) ;
	CollectorWaitSnapshot controls ;	// 元controlの全fieldを既存codecで読みます。
	DRIVERCRATE_EXPECT( context,
					   parseCollectorWaitSnapshot(
						   httpSavedBody( store, L"current/campaign-controls-v1.json"), controls)) ;
	// Group／requestを元型どおりに分け、待機・reviewを更新しません。
	for( const auto &[key, control] : controls.controls) {
		// Group行はrequest参照を持ちません。
		if( key.starts_with( L"g-")) {
			result.groups.emplace( control.group, control) ;
		} else {
			result.requests.emplace( control.request, CollectorSharedRequestState{control, {}}) ;
		}
	}

	// 登録された全CACHEを元本文から読み、実際のbindingへ結合します。
	for( const auto &value : root.GetNamedArray( L"cacheInventory")) {
		const auto				row = value.GetObject() ;					// 元一登録です。
		const std::wstring		request( row.GetNamedString( L"request")) ;	// 完全hashです。
		CollectorProjectedCache cache ;										// 元latest CACHEの型です。
		DRIVERCRATE_EXPECT(
			context,
			decodeCollectorProjectedCache(
				httpSavedBody( store, L"current/campaign-cache-v1-" + request + L".json"), cache)
					.status == collector_projected_json::Status::OK) ;
		result.requests.at( request).cache = CollectorSharedCacheReference{
			segment, std::wstring( row.GetNamedString( L"hash")), cache.binding} ;
	}

	return result ;
}
} // namespace

/** @see local_collector_http_tests.h */
void runCollectorSegmentPreparationRecoveryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;					// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;							// 架空collectionです。
	const std::wstring segmentKey( 64U, L'2') ;								// 架空旧区間です。
	const std::wstring nextKey( 64U, L'3') ;								// 架空新区間です。
	const auto		   location = rootFactory() / collectionKey ;			// 自作GUID祖先内だけです。
	LocalCollectorCollectionStore				parent ;					// 元fresh所有を保存後に全解放します。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;						// 元完了historyの実能力です。
	const auto initialized = parent.initialize( location, collectionKey) ;	// 親の元errorです。
	const auto borrowed	   = initialized == 0U
								 ? parent.borrowHistorySegment( segmentKey, true, lease)
								 : initialized ;	// 未初期化親の二次errorで最初の失敗を失いません。
	context.expect( initialized == 0U && borrowed == 0U && lease && lease->history(),
				   "preparation recovery initialize=" + std::to_string( initialized) +
					   " borrow=" + std::to_string( borrowed),
				   __FILE__, __LINE__) ;
	// 不成立fixtureを後続保存の成功へ補完しません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "preparation recovery lease") ;
	}

	auto &store = *lease->history() ;				// Fake workerから元完了を保存します。
	CollectorProjectedCampaignIdentity identity ;	// 元公開入力のidentityです。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// Workerより長く保持します。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でfake workerを起動しません。
	if( !campaign) {
		throw std::runtime_error( "preparation recovery campaign") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実保存した架空応答です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 完了保存後に元監督借用を返します。
		DRIVERCRATE_EXPECT(
			context,
			owner.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	// 実完了本文と共有台帳の全fieldを結合します。
	const auto snapshot = matchingSegmentFixture( context, store, collectionKey, segmentKey) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 元fresh準備所有です。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::prepare( parent, *lease, definition.sources, nextKey,
													   HTTP_TEST_UTC + 128000U, pending) == 0U &&
					 pending) ;
	// 未発行予約をcapture成功へ格上げしません。
	if( !pending) {
		throw std::runtime_error( "preparation recovery fresh") ;
	}

	const auto originalDraft = pending->draft() ;					// 能力解放後も保持する独立期待値です。
	const auto begin = originalDraft.intent.inventory.size() + 2U ;	// 新子以前の旧準備数です。
	const auto roles = std::vector<CollectorSegmentStorageRole>(
		// 元固定名と期待rawです。
		pending->roles().begin(), pending->roles().end()) ;
	std::vector<std::map<std::wstring, std::string>> oldFrames(
		begin) ;			// 全旧prefixの実captureです。
	std::size_t saved{} ;	// 最後の検査済みprefixです。
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::savePreparation(
									pending, saved,
									[&]( const std::size_t current) {
										oldFrames.at( current - 1U) = segmentFixtureImage( location) ;
										return DWORD{0U} ;
									}) == 0U &&
									saved == begin && begin == 3U) ;
	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent.close() == 0U) ;
	const auto model	= location / L"current/shared-budget-v1.json" ;	// 不変の保護fileです。
	const auto rolePath = [&]( const std::size_t index) {
		const auto &role = roles.at( index) ;	// 自作固定roleだけです。
		return role.scope == CollectorSegmentStorageScope::PARENT
				   ? location / role.name
				   : location / L"segments" /
						 (role.scope == CollectorSegmentStorageScope::OLD_SEGMENT ? segmentKey
																				  : nextKey) /
						 role.name ;
	} ; // 元roleと自作GUID領域は全故障窓より長く生存します。
	const auto restoreOld = [&]( const std::size_t prefix) {
		// 旧準備の固定suffixだけを自作fixture内で欠損へ戻します。
		for( std::size_t n = 0U; n < begin; ++n) {
			const auto path = rolePath( n) ;	// Scopeに結合した固定自己所有pathです。
			// Capture済みprefixだけを元保護DACLとともに復元します。
			if( n < prefix) {
				alterSegmentFixture( path, roles[n].raw) ;
				copySegmentFixtureDacl( model, path) ;
			} else {
				(void)std::filesystem::remove( segmentFixturePath( path)) ;
			}
		}
	} ; // 再作成fileのfixture DACLを製品側の拒否緩和で代替しません。
	// Intentのみを含む全旧prefixから、前所有を共有せず非保存で再取得します。
	for( std::size_t prefix = 1U; prefix <= begin; ++prefix) {
		restoreOld( prefix) ;
		LocalCollectorCollectionStore reopened ;	// 各prefix独立の実writerです。
		DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::recoverPreparation(
						 reopened, originalDraft.intentHash, definition.sources, pending) == 0U &&
						 pending && segmentFixtureImage( location) == oldFrames[prefix - 1U]) ;
		// 再取得の失敗を後続保存へ伝播する前に原codeを残します。
		if( !pending) {
			throw std::runtime_error( "preparation recovery old prefix " + std::to_string( prefix)) ;
		}

		DRIVERCRATE_EXPECT( context, pending->draft().intentBytes == originalDraft.intentBytes &&
										pending->draft().images == originalDraft.images &&
										pending->cost()[0].bytes == 0U) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
						 saved == 0U) ;
		pending.reset() ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
	}

	restoreOld( begin) ;
	{
		LocalCollectorCollectionStore invalidOld ;	// 旧非prefixを新子作成前に拒否します。
		DRIVERCRATE_EXPECT( context, invalidOld.initialize( location, collectionKey) == 0U &&
										std::filesystem::remove( segmentFixturePath( rolePath( 1U)))) ;
		const auto broken = segmentFixtureImage( location) ;	// Intentとseal間の穴は補完しません。
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::recoverPreparation(
										invalidOld, originalDraft.intentHash, definition.sources,
										pending) == 13U &&
										!pending && segmentFixtureImage( location) == broken) ;
		DRIVERCRATE_EXPECT( context, invalidOld.close() == 0U) ;
	}
	restoreOld( 1U) ;
	LocalCollectorCollectionStore reopened ;	// 途中保存後に明示的にclose／再初期化します。
	DRIVERCRATE_EXPECT(
		context, reopened.initialize( location, collectionKey) == 0U &&
					 LocalCollectorSegmentStorage::recoverPreparation(
						 reopened, originalDraft.intentHash, definition.sources, pending) == 0U &&
					 pending) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::savePreparation(
									pending, saved,
									[]( const std::size_t current) {
										return current == 2U ? DWORD{1223U} : DWORD{0U} ;
									}) == 1223U &&
									saved == 2U && segmentFixtureImage( location) == oldFrames[1]) ;
	pending.reset() ;
	DRIVERCRATE_EXPECT(
		context, reopened.close() == 0U && reopened.initialize( location, collectionKey) == 0U &&
					 LocalCollectorSegmentStorage::recoverPreparation(
						 reopened, originalDraft.intentHash, definition.sources, pending) == 0U &&
					 pending) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U &&
						   saved == begin && segmentFixtureImage( location) == oldFrames.back()) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveNewSegmentPreparation(
						   pending, saved, []( std::size_t) { return DWORD{1223U} ; }) == 1223U &&
						   saved == 1U) ;
	const auto firstNew = segmentFixtureImage( location) ;	// Markerだけの新準備停止窓です。
	pending.reset() ;
	DRIVERCRATE_EXPECT(
		context, reopened.close() == 0U && reopened.initialize( location, collectionKey) == 0U &&
					 LocalCollectorSegmentStorage::recoverPreparation(
						 reopened, originalDraft.intentHash, definition.sources, pending) == 0U &&
					 pending && segmentFixtureImage( location) == firstNew) ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 0U &&
					 saved == 69U) ;
	const auto complete = segmentFixtureImage( location) ;	// 全240準備rawを実保存からcaptureします。
	pending.reset() ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U && complete.size() == 240U) ;
	const auto childPrefix = L"segments/" + nextKey + L"/" ;	// 固定新子相対名です。
	// 専用初期ROOTの固定自己所有pathです。
	const auto rootPath = location / childPrefix / L"history/current/segment-history-root-v1.json" ;
	// 同intentの元head記録だけを故障窓へ戻します。
	const auto activationName =
		L"runs/segment-switch-activation-" + originalDraft.intentHash + L".json" ;
	const auto restoreNew = [&]( const std::size_t prefix) {
		(void)std::filesystem::remove( segmentFixturePath( rootPath)) ;
		(void)std::filesystem::remove( segmentFixturePath( location / activationName)) ;
		alterSegmentFixture( location / L"current/collection-head-v1.json",
							complete.at( L"current/collection-head-v1.json")) ;
		// 自作新準備69roleだけを、directory／lockを保った連続prefixへ復元します。
		for( std::size_t n = 0U; n < 69U; ++n) {
			const auto path = rolePath( begin + n) ;	// 元captureの固定名だけです。
			// 元prefixを完全raw／保護DACLで戻し、未保存suffixだけを除きます。
			if( n < prefix) {
				alterSegmentFixture( path, complete.at( childPrefix + roles[begin + n].name)) ;
				copySegmentFixtureDacl( model, path) ;
			} else {
				(void)std::filesystem::remove( segmentFixturePath( path)) ;
			}
		}
	} ; // 固定fileだけを復元し、保護directoryやlockを削除しません。
	// 全69prefixの実handle再取得は一byteも保存しないことを全captureで測ります。
	for( std::size_t prefix = 1U; prefix <= 69U; ++prefix) {
		restoreNew( prefix) ;
		const auto before = segmentFixtureImage( location) ;	// 同じ停止窓の全byteです。
		DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
		const auto code = LocalCollectorSegmentStorage::recoverPreparation(
			reopened, originalDraft.intentHash, definition.sources,
			pending) ;	// 第一実入口codeです。
		DRIVERCRATE_EXPECT( context, code == 0U && pending &&
										segmentFixtureImage( location) == before &&
										before.size() == complete.size() - 69U + prefix) ;
		// 失敗prefixを全prefix合格として継続しません。
		if( !pending) {
			throw std::runtime_error( "preparation recovery new prefix " + std::to_string( prefix) +
									 " code " + std::to_string( code)) ;
		}

		pending.reset() ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
	}

	std::map<std::wstring, std::string> finalFrame ;	// 四境界の親head完了期待値です。
	// 選択した四境界で不足保存・再停止・全解放後再回復を実行します。
	for( const std::size_t prefix : {1U, 33U, 68U, 69U}) {
		restoreNew( prefix) ;
		DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U &&
										LocalCollectorSegmentStorage::recoverPreparation(
											reopened, originalDraft.intentHash, definition.sources,
											pending) == 0U &&
										pending) ;
		std::size_t callbacks{} ;											// 完了済み69地点だけは診断を呼びません。
		std::shared_ptr<const CollectorSegmentStorageReservation> denied ;	// 再入出力は空です。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
						 pending, saved,
						 [&]( const std::size_t current) {
							 ++callbacks ;
							 DRIVERCRATE_EXPECT(
								 context, current == prefix + 1U && reopened.close() == 170U &&
											  LocalCollectorSegmentStorage::recoverPreparation(
												  reopened, originalDraft.intentHash,
												  definition.sources, denied) == 170U &&
											  !denied) ;
							 return DWORD{1223U} ;
						 }) == (prefix == 69U ? 0U : 1223U) &&
						 saved == (prefix == 69U ? 69U : prefix + 1U) &&
						 callbacks == (prefix == 69U ? 0U : 1U)) ;
		pending.reset() ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 0U &&
										reopened.initialize( location, collectionKey) == 0U &&
										LocalCollectorSegmentStorage::recoverPreparation(
											reopened, originalDraft.intentHash, definition.sources,
											pending) == 0U &&
										pending) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
										pending, saved) == 0U &&
										saved == 69U && segmentFixtureImage( location) == complete) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveInitialHistoryRoot(
							   pending, saved, []( std::size_t) { return DWORD{1223U} ; }) == 1223U &&
							   saved == 1U) ;
		pending.reset() ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 0U &&
										reopened.initialize( location, collectionKey) == 0U) ;
		const auto rooted = segmentFixtureImage( location) ;	// ROOT保存済み別入口の拒否は非変更です。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::recoverPreparation(
						 reopened, originalDraft.intentHash, definition.sources, pending) == 13U &&
						 !pending && segmentFixtureImage( location) == rooted) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::recover( reopened, originalDraft.intentHash,
														   definition.sources, pending) == 0U &&
						 pending) ;
		DRIVERCRATE_EXPECT(
			context,
			LocalCollectorSegmentStorage::savePreparation( pending, saved) == 87U && saved == 0U &&
				LocalCollectorSegmentStorage::saveParentHeads( pending, saved) == 0U && saved == 3U) ;
		// 初回実完了の全byteを後続三境界と比較します。
		if( finalFrame.empty()) {
			finalFrame = segmentFixtureImage( location) ;
		}

		DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == finalFrame &&
										finalFrame.size() == 242U) ;
		pending.reset() ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
	}

	restoreNew( 69U) ;
	DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
	const auto reject = [&]( const DWORD expected, const std::function<DWORD()> &diagnostic = {}) {
		const auto before = segmentFixtureImage( location) ;	// 故意な改変自体は保持します。
		const auto code	  = LocalCollectorSegmentStorage::recoverPreparation(
			  reopened, originalDraft.intentHash, definition.sources, pending,
			  diagnostic) ;	// 元数値codeです。
		DRIVERCRATE_EXPECT( context, code == expected && !pending) ;
		// 第一不成立を後続の故障窓へ混入させません。
		if( code != expected || pending) {
			throw std::runtime_error( "preparation rejection expected " + std::to_string( expected) +
									 " actual " + std::to_string( code)) ;
		}

		DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == before) ;
	} ; // Captureと実writerは同期拒否検査より長く存続します。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::recover( reopened, originalDraft.intentHash,
															 definition.sources, pending) == 13U &&
						   !pending && segmentFixtureImage( location) == complete) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::recoverPreparation(
						   reopened, originalDraft.intentHash, definition.sources, pending) == 0U &&
						   pending) ;
	alterSegmentFixture( rolePath( begin + 1U), "{}") ;
	const auto changedNew = segmentFixtureImage( location) ;	// 発行後の新像改変も旧入口で拒否します。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 13U &&
						   saved == 0U && segmentFixtureImage( location) == changedNew) ;
	pending.reset() ;
	alterSegmentFixture( rolePath( begin + 1U), roles[begin + 1U].raw) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( rolePath( begin - 1U)))) ;
	reject( 13U) ;
	alterSegmentFixture( rolePath( begin - 1U), roles[begin - 1U].raw) ;
	copySegmentFixtureDacl( model, rolePath( begin - 1U)) ;
	// 全240実rawを一件ずつ破損させ、古い履歴・全像と準備を個別再検査します。
	for( const auto &[name, raw] : complete) {
		alterSegmentFixture( location / name, "{}") ;
		reject( 13U) ;
		alterSegmentFixture( location / name, raw) ;
	}

	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( rolePath( begin + 1U)))) ;
	reject( 13U) ;
	alterSegmentFixture( rolePath( begin + 1U), roles[begin + 1U].raw) ;
	copySegmentFixtureDacl( model, rolePath( begin + 1U)) ;
	// 三scopeの未知名を保護fileとして注入し、未知名無視を禁止します。
	for( const auto &name :
		{std::wstring( L"runs/unknown.json"), L"segments/" + segmentKey + L"/runs/unknown.json",
		 childPrefix + L"history/current/unknown.json"}) {
		alterSegmentFixture( location / name, "{}") ;
		copySegmentFixtureDacl( model, location / name) ;
		reject( 13U) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( location / name))) ;
	}

	alterSegmentFixture( location / activationName, finalFrame.at( activationName)) ;
	copySegmentFixtureDacl( model, location / activationName) ;
	reject( 13U) ;
	DRIVERCRATE_EXPECT( context,
					   std::filesystem::remove( segmentFixturePath( location / activationName))) ;
	alterSegmentFixture( location / L"current/collection-head-v1.json",
						finalFrame.at( L"current/collection-head-v1.json")) ;
	reject( 13U) ;
	alterSegmentFixture( location / L"current/collection-head-v1.json",
						complete.at( L"current/collection-head-v1.json")) ;
	const auto stagingPath =
		// 製品と同じ固定intentの残留stagingです。
		rolePath( 0U).native() + L".tmp" ;
	alterSegmentFixture( stagingPath, "{}") ;
	copySegmentFixtureDacl( model, stagingPath) ;
	reject( 13U) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( stagingPath))) ;
	const auto invalidPath = rolePath( 0U).native() + L".stage" ;	// 固定stagingではない不正名です。
	alterSegmentFixture( invalidPath, "{}") ;
	copySegmentFixtureDacl( model, invalidPath) ;
	reject( 123U) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( invalidPath))) ;
	// 三fileの排他I/Oは内容13へ潰さず第一sharing32を保持します。
	for( const auto &path :
		{location / L"current/collection-head-v1.json", rolePath( 0U), rolePath( begin + 1U)}) {
		const auto before = segmentFixtureImage( location) ;	// Sharing注入前の全byteです。
		const auto handle =
			CreateFileW( segmentFixturePath( path).c_str(), GENERIC_READ, 0U, nullptr, OPEN_EXISTING,
						FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 自作fileだけです。
		// 故障注入の失敗を共有拒否の合格にしません。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "preparation sharing fixture") ;
		}

		std::unique_ptr<void, decltype( &CloseHandle)> locked( handle,
															 &CloseHandle) ;	// 各窓で返します。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::recoverPreparation(
						 reopened, originalDraft.intentHash, definition.sources, pending) == 32U &&
						 !pending) ;
		locked.reset() ;
		DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == before) ;
	}

	auto invalidSources = definition.sources ;	// 元閉包のsource欠損です。
	invalidSources.pop_back() ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::recoverPreparation(
						   reopened, originalDraft.intentHash, invalidSources, pending) == 13U &&
						   !pending && segmentFixtureImage( location) == complete) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::recoverPreparation(
									reopened, L"invalid", definition.sources, pending) == 87U &&
									!pending) ;
	reject( 1223U, [] { return DWORD{1223U} ; }) ;
	reject( 8U, []() -> DWORD { throw std::bad_alloc{} ; }) ;
	reject( 13U, []() -> DWORD { throw std::runtime_error( "preparation diagnostic") ; }) ;
	std::map<std::wstring, std::string> afterDiagnostic ;	// 診断による故意変更だけを保持します。
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::recoverPreparation(
									reopened, originalDraft.intentHash, definition.sources, pending,
									[&] {
										alterSegmentFixture( rolePath( begin + 1U), "{}") ;
										afterDiagnostic = segmentFixtureImage( location) ;
										return DWORD{0U} ;
									}) == 13U &&
									!pending && segmentFixtureImage( location) == afterDiagnostic) ;
	alterSegmentFixture( rolePath( begin + 1U), roles[begin + 1U].raw) ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
	{
		auto wrapper =
			std::make_unique<LocalCollectorCollectionStore>() ;	// Caller外殻解放を測ります。
		DRIVERCRATE_EXPECT( context, wrapper->initialize( location, collectionKey) == 0U &&
										LocalCollectorSegmentStorage::recoverPreparation(
											*wrapper, originalDraft.intentHash, definition.sources,
											pending) == 0U &&
										pending) ;
		wrapper.reset() ;
		LocalCollectorCollectionStore competing ;	// 回復所有だけが親排他を維持します。
		DRIVERCRATE_EXPECT( context, competing.initialize( location, collectionKey) == 32U) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
										pending, saved) == 0U &&
										saved == 69U && segmentFixtureImage( location) == complete) ;
		pending.reset() ;
		DRIVERCRATE_EXPECT( context, competing.initialize( location, collectionKey) == 0U &&
										competing.close() == 0U) ;
	}
	const auto lockPath =
		location / childPrefix / L"history/collector.lock" ;	// 固定自己所有lockだけです。
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( lockPath)) &&
									reopened.initialize( location, collectionKey) == 0U) ;
	const auto missingLock =
		// Lockはcapture外、欠損のまま保持します。
		segmentFixtureImage( location) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::recoverPreparation(
						   reopened, originalDraft.intentHash, definition.sources, pending) == 2U &&
						   !pending && !std::filesystem::exists( segmentFixturePath( lockPath)) &&
						   segmentFixtureImage( location) == missingLock) ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
	alterSegmentFixture( lockPath, "") ;
	copySegmentFixtureDacl( model, lockPath) ;
}
/** @see local_collector_http_tests.h */
void runCollectorSegmentRecoveryStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空collectionです。
	const std::wstring segmentKey( 64U, L'2') ;						// 架空旧区間です。
	const std::wstring nextKey( 64U, L'3') ;						// 架空新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID内の専用領域です。
	LocalCollectorCollectionStore				parent ;			// 最終capture後に元writerを完全解放します。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;				// 唯一旧historyの実能力です。
	DRIVERCRATE_EXPECT( context, parent.initialize( location, collectionKey) == 0U &&
									parent.borrowHistorySegment( segmentKey, true, lease) == 0U &&
									lease && lease->history()) ;
	// 初期化失敗から成功fixtureを作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "recovery storage lease") ;
	}

	auto	  &store		 = *lease->history() ;	// 元fake workerと完了保存を結合します。
	const auto identityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。
	auto &identity = *identityOwner ;			// 元公開入力identityです。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// Workerより長い元入力です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でfake workerを起動しません。
	if( !campaign) {
		throw std::runtime_error( "recovery storage campaign") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 元workerの保存応答です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 完了保存後に監督借用を返します。
		DRIVERCRATE_EXPECT(
			context,
			owner.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot =
		// 元実本文です。
		matchingSegmentFixture( context, store, collectionKey, segmentKey) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 元fresh予約です。
	std::size_t												  saved{} ;	// 実保存の検査済み件数です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 予約未発行なら保存byte互換を合格にしません。
	if( !pending) {
		throw std::runtime_error( "recovery storage reservation") ;
	}

	const auto originalDraft = pending->draft() ;					// Capability解放後も期待値だけを保持します。
	const auto begin = originalDraft.intent.inventory.size() + 2U ;	// 新子markerの固定境界です。
	const auto roles = std::vector<CollectorSegmentStorageRole>(
		// 元固定名です。
		pending->roles().begin(), pending->roles().end()) ;
	DRIVERCRATE_EXPECT(
		context,
		LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U && saved == begin &&
			LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 0U &&
			saved == 69U &&
			LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 0U &&
			saved == 1U) ;
	std::array<std::map<std::wstring, std::string>, 4U> frames ;	// 各保存地点の独立所有byteです。
	frames[0] = segmentFixtureImage( location) ;
	// 元head保持記録・登録head・最終headの三地点を実保存からcaptureします。
	for( std::size_t prefix = 1U; prefix <= 3U; ++prefix) {
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads(
										pending, saved,
										[prefix]( const std::size_t current) {
											return current == prefix ? DWORD{1223U} : DWORD{0U} ;
										}) == 1223U &&
										saved == prefix) ;
		frames[prefix] = segmentFixtureImage( location) ;
	}

	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent.close() == 0U && frames[0].size() == 241U &&
									frames[3].size() == 242U) ;

	const auto activationName =
		L"runs/segment-switch-activation-" + originalDraft.intentHash + L".json" ;	// 元固定名です。

	const auto headPath =
		location / L"current/collection-head-v1.json" ;		// 自作固定headだけを故障窓へ戻します。
	const auto activationPath = location / activationName ;	// 同intentの自作記録だけです。
	const auto fixtureDaclModel =
		location / L"current/shared-budget-v1.json" ;	// 不変の保護fileです。
	const auto restore = [&]( const std::size_t prefix) {
		alterSegmentFixture( headPath, frames[prefix].at( L"current/collection-head-v1.json")) ;
		// 元の未保存記録だけを自作fixtureから取り除きます。
		if( prefix == 0U) {
			(void)std::filesystem::remove( segmentFixturePath( activationPath)) ;
		} else {
			alterSegmentFixture( activationPath, frames[prefix].at( activationName)) ;
			copySegmentFixtureDacl( fixtureDaclModel, activationPath) ;
		}
	} ; // 元frameと自作GUID pathは全検証中存続します。
	// 元全能力の解放後に、四状態からそれぞれ実fileを再読して回復します。
	for( std::size_t prefix = 0U; prefix < frames.size(); ++prefix) {
		restore( prefix) ;
		LocalCollectorCollectionStore reopened ;	// 前予約と共有しない新writerです。
		DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
		std::shared_ptr<const CollectorSegmentStorageReservation>
					recovered ;		// 実回復入口だけが発行します。
		std::size_t inspections{} ;	// 私有意味検査の診断到達数だけを記録します。
		const auto	code = LocalCollectorSegmentStorage::recover( reopened, originalDraft.intentHash,
																 definition.sources, recovered, [&] {
																	 ++inspections ;
																	 return DWORD{0U} ;
																 }) ; // 第一実I/O結果です。
		DRIVERCRATE_EXPECT( context, code == 0U && recovered &&
										segmentFixtureImage( location) == frames[prefix]) ;
		// 未発行を後続のhead保存成功へ補完しません。
		if( !recovered) {
			throw std::runtime_error( "recovery storage reservation code " + std::to_string( code) +
									 " inspected " + std::to_string( inspections)) ;
		}

		DRIVERCRATE_EXPECT( context, recovered->draft().intentBytes == originalDraft.intentBytes &&
										recovered->draft().images == originalDraft.images &&
										recovered->cost()[0].bytes == 0U) ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 170U) ;
		LocalCollectorCollectionStore competing ;	// 最後の回復所有まで親排他が残ります。
		DRIVERCRATE_EXPECT( context, competing.initialize( location, collectionKey) == 32U) ;
		std::unique_ptr<LocalCollectorSegmentLease> denied ;	// 公開leaseへ回復handleを漏らしません。
		DRIVERCRATE_EXPECT(
			context, reopened.borrowHistorySegment( segmentKey, false, denied) == 170U && !denied) ;
		std::shared_ptr<const CollectorSegmentStorageReservation> reentered ;	// 別回復は拒否します。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::recover( reopened, originalDraft.intentHash,
														   definition.sources, reentered) == 170U &&
						 !reentered) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::savePreparation( recovered, saved) == 87U &&
							   saved == 0U) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
										recovered, saved) == 87U &&
										saved == 0U) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveInitialHistoryRoot(
										recovered, saved) == 87U &&
										saved == 0U) ;
		std::size_t callbacks{} ;	// 完了済み地点では保存診断を呼びません。
		const auto	stopped = LocalCollectorSegmentStorage::saveParentHeads(
			 recovered, saved, [&]( const std::size_t stage) {
				 ++callbacks ;
				 DRIVERCRATE_EXPECT( context, stage == prefix + 1U && reopened.close() == 170U) ;
				 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::recover(
												 reopened, originalDraft.intentHash,
												 definition.sources, reentered) == 170U &&
												 !reentered) ;
				 return DWORD{1223U} ;
			 }) ; // 自作fixtureの実保存後に一回停止します。
		DRIVERCRATE_EXPECT( context, stopped == (prefix == 3U ? 0U : 1223U) &&
										saved == (prefix == 3U ? 3U : prefix + 1U) &&
										callbacks == (prefix == 3U ? 0U : 1U)) ;
		recovered.reset() ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 0U &&
										reopened.initialize( location, collectionKey) == 0U) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::recover( reopened, originalDraft.intentHash,
														   definition.sources, recovered) == 0U &&
						 recovered) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveParentHeads( recovered, saved) == 0U &&
							   saved == 3U && segmentFixtureImage( location) == frames[3]) ;
		callbacks = 0U ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveParentHeads( recovered, saved,
																		 [&]( std::size_t) {
																			 ++callbacks ;
																			 return DWORD{0U} ;
																		 }) == 0U &&
							   saved == 3U && callbacks == 0U &&
							   segmentFixtureImage( location) == frames[3]) ;
		recovered.reset() ;
		DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
	}

	LocalCollectorCollectionStore checkedParent ;	// 改変は全て同じ保護parentで非変更拒否します。
	DRIVERCRATE_EXPECT( context, checkedParent.initialize( location, collectionKey) == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation>
			   rejected ;	// 失敗時に能力を残しません。
	const auto reject = [&]( const DWORD expected, const std::function<DWORD()> &diagnostic = {}) {
		const auto changed = segmentFixtureImage( location) ;	// 故意な故障をそのまま保存します。
		const auto code	   = LocalCollectorSegmentStorage::recover(
			   checkedParent, originalDraft.intentHash, definition.sources, rejected,
			   diagnostic) ;	// 実入口結果です。
		DRIVERCRATE_EXPECT( context, code == expected && !rejected) ;
		// 数値結果の不一致を後続故障へ混入させず、元I/O codeだけを残します。
		if( code != expected || rejected) {
			throw std::runtime_error( "recovery rejection expected " + std::to_string( expected) +
									 " actual " + std::to_string( code)) ;
		}

		DRIVERCRATE_EXPECT( context, changed == segmentFixtureImage( location)) ;
	} ; // Captureとparentは同期拒否検査より長く生存します。
	// 全242保存rawを一件ずつ破損させ、旧履歴・元台帳・準備の欠損補完を禁止します。
	for( const auto &[name, raw] : frames[3]) {
		alterSegmentFixture( location / name, "{}") ;
		reject( 13U) ;
		alterSegmentFixture( location / name, raw) ;
	}

	// 四用途の必須fileを欠損させ、回復による再作成がないことを測ります。
	for( const auto &name :
		{activationName, std::wstring( L"current/collection-head-v1.json"),
		 L"segments/" + nextKey + L"/history/current/segment-history-root-v1.json",
		 L"segments/" + nextKey + L"/" + roles[begin + 1U].name}) {
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( location / name))) ;
		reject( 13U) ;
		alterSegmentFixture( location / name, frames[3].at( name)) ;
		copySegmentFixtureDacl( fixtureDaclModel, location / name) ;
	}

	// 選択した三scopeの未知名は列挙から捨てず拒否します。
	for( const auto &name :
		{std::wstring( L"runs/unknown.json"), L"segments/" + segmentKey + L"/runs/unknown.json",
		 L"segments/" + nextKey + L"/history/current/unknown.json"}) {
		alterSegmentFixture( location / name, "{}") ;
		copySegmentFixtureDacl( fixtureDaclModel, location / name) ;
		reject( 13U) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( location / name))) ;
	}

	auto invalidSources = definition.sources ;	// 元二sourceの閉包欠損です。
	// 親head・固定intent・初期ROOTの共有拒否は内容13へ潰しません。
	for( const auto &target :
		{headPath,
		 location / L"runs" / (L"segment-switch-intent-" + originalDraft.intentHash + L".json"),
		 location / L"segments" / nextKey / L"history/current/segment-history-root-v1.json"}) {
		const auto unchanged = segmentFixtureImage( location) ;	// Lock前の自作fixture全byteです。
		const auto handle =
			CreateFileW( segmentFixturePath( target).c_str(), GENERIC_READ, 0U, nullptr,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 注入だけです。
		// 故障注入の不成立を共有拒否の合格へ数えません。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "recovery sharing fixture") ;
		}

		std::unique_ptr<void, decltype( &CloseHandle)> locked( handle,
															 &CloseHandle) ;	// 各窓で返します。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::recover( checkedParent, originalDraft.intentHash,
														   definition.sources, rejected) == 32U &&
						 !rejected) ;
		locked.reset() ;
		DRIVERCRATE_EXPECT( context, unchanged == segmentFixtureImage( location)) ;
	}

	invalidSources.pop_back() ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::recover( checkedParent, originalDraft.intentHash,
													   invalidSources, rejected) == 13U &&
					 !rejected && segmentFixtureImage( location) == frames[3]) ;
	reject( 1223U, [] { return DWORD{1223U} ; }) ;
	reject( 8U, []() -> DWORD { throw std::bad_alloc{} ; }) ;
	reject( 13U, []() -> DWORD { throw std::runtime_error( "recovery diagnostic") ; }) ;
	const auto changedName = roles[begin + 1U].name ;		// 新像の診断後変更も発行前に拒否します。
	std::map<std::wstring, std::string> afterDiagnostic ;	// 自作診断による変更だけを保持します。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::recover(
					 checkedParent, originalDraft.intentHash, definition.sources, rejected,
					 [&] {
						 alterSegmentFixture( location / L"segments" / nextKey / changedName, "{}") ;
						 afterDiagnostic = segmentFixtureImage( location) ;
						 return DWORD{0U} ;
					 }) == 13U &&
					 !rejected && afterDiagnostic == segmentFixtureImage( location)) ;
	alterSegmentFixture( location / L"segments" / nextKey / changedName,
						frames[3].at( L"segments/" + nextKey + L"/" + changedName)) ;
	DRIVERCRATE_EXPECT( context, checkedParent.close() == 0U) ;
	{
		auto wrapper =
			std::make_unique<LocalCollectorCollectionStore>() ;	// caller wrapper解放も検査します。
		DRIVERCRATE_EXPECT( context, wrapper->initialize( location, collectionKey) == 0U &&
										LocalCollectorSegmentStorage::recover(
											*wrapper, originalDraft.intentHash, definition.sources,
											rejected) == 0U &&
										rejected) ;
		wrapper.reset() ;
		LocalCollectorCollectionStore competing ;	// 回復所有だけで親lockを保持します。
		DRIVERCRATE_EXPECT( context, competing.initialize( location, collectionKey) == 32U) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveParentHeads( rejected, saved) == 0U &&
							   saved == 3U && segmentFixtureImage( location) == frames[3]) ;
		rejected.reset() ;
		DRIVERCRATE_EXPECT( context, competing.initialize( location, collectionKey) == 0U &&
										competing.close() == 0U) ;
	}
}
/** @see local_collector_http_tests.h */
void runCollectorSegmentReadContextTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	static_assert( !std::is_default_constructible_v<CollectorSegmentReadContext> &&
				  !std::is_copy_constructible_v<CollectorSegmentReadContext> &&
				  !std::is_move_constructible_v<CollectorSegmentReadContext>) ;
	const auto		   definition = definitionFactory() ;				// 元二sourceのfake入力です。
	const std::wstring collectionKey( 64U, L'1') ;						// 架空collectionです。
	const std::wstring oldKey( 64U, L'2') ;								// 元同親区間です。
	const std::wstring newKey( 64U, L'3') ;								// 同親の初回新区間です。
	const auto		   location = rootFactory() / collectionKey ;		// 自作GUID内だけです。
	auto parent = std::make_unique<LocalCollectorCollectionStore>() ;	// Wrapper寿命を独立させます。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;					// Fixture準備だけの元能力です。
	DRIVERCRATE_EXPECT( context, parent->initialize( location, collectionKey) == 0U &&
									parent->borrowHistorySegment( oldKey, true, lease) == 0U &&
									lease && lease->history()) ;
	// 未準備能力から後続成功を作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "read context fixture lease") ;
	}

	auto							  &store = *lease->history() ;			// Fake workerの元保存先です。
	CollectorProjectedCampaignIdentity identity ;							// 元入力の再導出です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign> campaign ;	// 元入力の強所有です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// Fixture不成立を独立nativeの成功へ数えません。
	if( !campaign) {
		throw std::runtime_error( "read context fixture campaign") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 偽HTTPの実保存応答です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 完了後に元監督借用を返します。
		DRIVERCRATE_EXPECT(
			context,
			owner.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot =
		// 元全値です。
		matchingSegmentFixture( context, store, collectionKey, oldKey) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( *parent, *lease, snapshot) == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 実保存だけの能力です。
	std::size_t												  saved{} ;	// 実保存完了数です。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources, newKey,
													   HTTP_TEST_UTC + 128000U, pending) == 0U &&
					 pending) ;
	// 元保存不成立からreaderの能力を作りません。
	if( !pending) {
		throw std::runtime_error( "read context fixture reservation") ;
	}

	const auto draft = pending->draft() ;	// 能力なしの期待値です。
	const auto roles = std::vector<CollectorSegmentStorageRole>( pending->roles().begin(),
																// 実writer由来の固定名です。
																pending->roles().end()) ;
	DRIVERCRATE_EXPECT(
		context,
		LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U &&
			LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 0U &&
			saved == 69U &&
			LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 0U &&
			saved == 1U) ;
	std::array<std::map<std::wstring, std::string>, 4U> frames ;	// 四保存地点の独立実像です。
	frames[0] = segmentFixtureImage( location) ;
	// 元head保持／登録head／最終headをそれぞれ実保存で停止します。
	for( std::size_t prefix = 1U; prefix <= 3U; ++prefix) {
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads(
										pending, saved,
										[prefix]( const std::size_t current) {
											return current == prefix ? DWORD{1223U} : DWORD{0U} ;
										}) == 1223U &&
										saved == prefix) ;
		frames[prefix] = segmentFixtureImage( location) ;
	}

	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent->close() == 0U) ;
	parent.reset() ;
	const auto oldPrefix = L"segments/" + oldKey + L"/" ;	// 自作旧子名です。
	const auto newPrefix = L"segments/" + newKey + L"/" ;	// 自作新子名です。
	const auto activationName =
		L"runs/segment-switch-activation-" + draft.intentHash + L".json" ;	// 元固定名です。
	const auto model =
		location / L"current/shared-budget-v1.json" ;	// 正しいfixture DACLのコピー元です。
	std::set<std::wstring> direct ;						// Readerが参照する全固定rawを独立に数えます。
	// 親現在／runsと新子・新historyの全rawを現在集合へ登録します。
	for( const auto &[name, raw] : frames[3]) {
		(void)raw ;
		// 旧payloadはreaderの直接根拠へ含めません。
		if( !name.starts_with( L"segments/") || name.starts_with( newPrefix)) {
			direct.insert( name) ;
		}
	}

	direct.insert( oldPrefix + L"current/collector-campaign-mode-v1.json") ;
	// 旧子からは実準備roleのseal／inventoryだけを参照します。
	for( const auto &role : roles) {
		// 保存scopeの定義からだけ直接根拠を選びます。
		if( role.scope == CollectorSegmentStorageScope::OLD_SEGMENT) {
			direct.insert( oldPrefix + role.name) ;
		}
	}

	const auto expectedCalls = direct.size() ;	// 初回一passの重複なし全rawです。
	DRIVERCRATE_EXPECT( context, expectedCalls == 143U && frames[3].size() == 242U) ;
	auto reopened =
		std::make_unique<LocalCollectorCollectionStore>() ;	// 元所有を完全解放した別起動相当です。
	DRIVERCRATE_EXPECT( context, reopened->initialize( location, collectionKey) == 0U) ;
	std::shared_ptr<const CollectorSegmentReadContext> proof ;		// Callerから構築できない実能力です。
	CollectorSegmentReadDiagnostics					   diagnostic ;	// 実I/Oの部分数値です。
	const auto inspect = [&]( const std::function<DWORD()> &callback = {}) {
		return LocalCollectorSegmentReader::inspect( *reopened, draft.intentHash, proof, diagnostic,
													callback) ;
	} ; // 同writer threadに限定した元親と空出力だけです。
	const auto firstCode = inspect( [&] {
		std::shared_ptr<const CollectorSegmentReadContext> nested ;	// 別出力の再入です。
		CollectorSegmentReadDiagnostics nestedDiagnostics ;			// 再入はread前に停止します。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentReader::inspect( *reopened, draft.intentHash, nested,
																nestedDiagnostics) == 170U &&
							   !nested && nestedDiagnostics.sharedReadCalls == 0U &&
							   reopened->close() == 170U) ;
		return DWORD{0U} ;
	}) ; // 全検査成功後の診断だけです。
	context.expect( firstCode == 0U && proof,
				   "read context acceptance code=" + std::to_string( firstCode), __FILE__, __LINE__) ;
	// 原不成立を後続getterで隠しません。
	if( !proof) {
		throw std::runtime_error( "read context acceptance") ;
	}

	std::uint64_t sharedBytes{} ;	// 元実像からの一pass独立合算です。
	std::uint64_t segmentBytes{} ;	// Markerも含む直接根拠の合算です。
	// 全scope付き元rawを独立に用途別合算します。
	for( const auto &name : direct) {
		// 親currentだけを16 MiB枠へ分類します。
		if( name.starts_with( L"current/")) {
			sharedBytes += frames[3].at( name).size() ;
		} else {
			segmentBytes += frames[3].at( name).size() ;
		}
	}

	DRIVERCRATE_EXPECT(
		context, diagnostic.sharedNames == 68U && diagnostic.segmentNames == 75U &&
					 diagnostic.sharedReadCalls == 136U && diagnostic.segmentReadCalls == 150U &&
					 diagnostic.finalReadCalls == expectedCalls &&
					 diagnostic.sharedBytes == sharedBytes * 2U &&
					 diagnostic.segmentBytes == segmentBytes * 2U &&
					 diagnostic.oldPayloadReads == 0U && diagnostic.collectionChecks == 2U &&
					 diagnostic.directoryChecks == 12U && proof->state().recovery.saved == 3U &&
					 proof->state().recovery.draft.intent == draft.intent &&
					 proof->state().recovery.carried.lastUtcMillis == snapshot.lastUtcMillis &&
					 proof->state().files.size() == 168U &&
					 segmentFixtureImage( location) == frames[3]) ;
	std::cout << "Segment reader I/O: sharedNames=" << diagnostic.sharedNames
			  << " segmentNames=" << diagnostic.segmentNames
			  << " sharedBytes=" << diagnostic.sharedBytes
			  << " segmentBytes=" << diagnostic.segmentBytes
			  << " sharedReadCalls=" << diagnostic.sharedReadCalls
			  << " segmentReadCalls=" << diagnostic.segmentReadCalls
			  << " finalReadCalls=" << diagnostic.finalReadCalls
			  << " oldPayloadReads=" << diagnostic.oldPayloadReads << '\n' ;
	auto originalProof = proof ;	// 同じ生存能力だけの追加参照です。
	DRIVERCRATE_EXPECT( context, inspect() == 170U && proof == originalProof &&
									diagnostic.sharedReadCalls == 0U && reopened->close() == 170U) ;
	proof.reset() ;
	DRIVERCRATE_EXPECT( context, reopened->close() == 170U) ;
	originalProof.reset() ;
	DRIVERCRATE_EXPECT(
		context, reopened->close() == 0U && reopened->initialize( location, collectionKey) == 0U &&
					 inspect() == 0U && proof && segmentFixtureImage( location) == frames[3]) ;
	proof.reset() ;
	// 二回起動の読取りで元byteや制御値を変更しません。
	DRIVERCRATE_EXPECT( context, inspect() == 0U && proof && diagnostic.oldPayloadReads == 0U &&
									segmentFixtureImage( location) == frames[3]) ;
	proof.reset() ;
	LocalCollectorCollectionStore uninitialized ;	// 未取得の親です。
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentReader::inspect(
									uninitialized, draft.intentHash, proof, diagnostic) == 87U &&
									!proof && diagnostic.sharedReadCalls == 0U) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentReader::inspect(
									*reopened, L"../untrusted.json", proof, diagnostic) == 87U &&
									!proof && diagnostic.sharedReadCalls == 0U) ;
	const std::wstring otherKey( 64U, L'4') ;						// 元intentとは異なる架空collectionです。
	const auto		   otherLocation = rootFactory() / otherKey ;	// 別自作GUIDの非混用fixtureです。
	LocalCollectorCollectionStore otherParent ;						// 同じbyteでも別親の能力を取得しません。
	DRIVERCRATE_EXPECT( context, otherParent.initialize( otherLocation, otherKey) == 0U) ;
	const auto intentName =
		L"runs/segment-switch-intent-" + draft.intentHash + L".json" ;	// 実本文hash名です。
	alterSegmentFixture( otherLocation / intentName, frames[3].at( intentName)) ;
	copySegmentFixtureDacl( otherLocation / L"current/collector-campaign-mode-v1.json",
						   otherLocation / intentName) ;
	// 読取りの必須headを元rawから置き、別collectionの参照だけを反証します。
	alterSegmentFixture( otherLocation / L"current/collection-head-v1.json",
						frames[3].at( L"current/collection-head-v1.json")) ;
	copySegmentFixtureDacl( otherLocation / L"current/collector-campaign-mode-v1.json",
						   otherLocation / L"current/collection-head-v1.json") ;
	const auto otherBefore = segmentFixtureImage( otherLocation) ;	// 別親へ子を追加しない正本です。
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentReader::inspect( otherParent, draft.intentHash,
																	 proof, diagnostic) == 87U &&
									!proof && otherBefore == segmentFixtureImage( otherLocation) &&
									otherParent.close() == 0U) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentReader::inspect(
									*reopened, std::wstring( 64U, L'f'), proof, diagnostic) == 2U &&
									!proof && segmentFixtureImage( location) == frames[3]) ;
	// 各実保存地点0～2を初回readyへ補完・回復しません。
	for( std::size_t frame = 0U; frame < 3U; ++frame) {
		alterSegmentFixture( location / L"current/collection-head-v1.json",
							frames[frame].at( L"current/collection-head-v1.json")) ;
		// 未保存activationだけを故意の欠損にし、回復を暗黙に呼びません。
		if( frame == 0U) {
			DRIVERCRATE_EXPECT(
				context, std::filesystem::remove( segmentFixturePath( location / activationName))) ;
		} else {
			alterSegmentFixture( location / activationName, frames[frame].at( activationName)) ;
			copySegmentFixtureDacl( model, location / activationName) ;
		}

		const auto before = segmentFixtureImage( location) ;	// 元不完全保存状態です。
		const auto code	  = inspect() ;							// 必須欠損2と元head／登録head内容13を分けます。
		DRIVERCRATE_EXPECT( context, code == (frame == 0U ? 2U : 13U) && !proof &&
										segmentFixtureImage( location) == before) ;
	}

	alterSegmentFixture( location / L"current/collection-head-v1.json",
						frames[3].at( L"current/collection-head-v1.json")) ;
	// 全直接rawの各個別改変と各個別欠損を非作成・非修復で拒否します。
	for( const auto &name : direct) {
		const auto	path = location / name ;		// 自作固定fixtureだけの反証対象です。
		const auto &raw	 = frames[3].at( name) ;	// 元独立保存byteです。
		alterSegmentFixture( path, "{}") ;
		const auto altered = segmentFixtureImage( location) ;	// 故意の差替えを保持する像です。
		DRIVERCRATE_EXPECT( context,
						   inspect() == 13U && !proof && segmentFixtureImage( location) == altered) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( path))) ;
		const auto missing = segmentFixtureImage( location) ;	// 必須欠損を残す像です。
		DRIVERCRATE_EXPECT( context,
						   inspect() == 2U && !proof && segmentFixtureImage( location) == missing) ;
		alterSegmentFixture( path, raw) ;
		// コピー元を削除した反証でも、元復元後の同じDACLを維持します。
		copySegmentFixtureDacl( location / L"current/collector-campaign-mode-v1.json" == path
								   ? location / L"current/shared-groups-v1.json"
								   : location / L"current/collector-campaign-mode-v1.json",
							   path) ;
	}

	// 診断の第一数値・OOM・例外を内容補完や自動retryへ変更しません。
	for( const DWORD expected : {DWORD{534U}, DWORD{8U}, DWORD{13U}}) {
		const auto callback = [expected]() -> DWORD {
			// 確保失敗を容量68へ変更しません。
			if( expected == 8U) {
				throw std::bad_alloc() ;
			}

			// その他例外を無言に破棄しません。
			if( expected == 13U) {
				throw std::runtime_error( "read context diagnostic") ;
			}

			return expected ;
		} ; // 同期入口だけの故障注入です。
		DRIVERCRATE_EXPECT( context, inspect( callback) == expected && !proof &&
										diagnostic.finalReadCalls == 0U &&
										segmentFixtureImage( location) == frames[3]) ;
	}

	// 各scopeの診断後変更を最終集合／同raw再検査で拒否します。
	for( const auto &name : {std::wstring( L"current/collection-head-v1.json"), activationName,
							oldPrefix + L"current/segment-seal-v1.json",
							newPrefix + L"current/segment-shared-base-v1.json",
							newPrefix + L"history/current/segment-history-root-v1.json"}) {
		DRIVERCRATE_EXPECT( context, inspect( [&] {
										alterSegmentFixture( location / name, "{}") ;
										return DWORD{0U} ;
									}) == 13U &&
										!proof) ;
		const auto changed = segmentFixtureImage( location) ;	// 診断の変更を製品が修復していません。
		DRIVERCRATE_EXPECT( context, changed.at( name) == "{}") ;
		alterSegmentFixture( location / name, frames[3].at( name)) ;
	}

	// 全直接143rawを一件ずつ同sizeに差替え、属性一致だけで発行しないことを検査します。
	for( const auto &name : direct) {
		auto sameSize	= frames[3].at( name) ;	// 名とusageを変えない故意の一byte差です。
		sameSize.back() = sameSize.back() == ' ' ? '!' : ' ' ;
		DRIVERCRATE_EXPECT( context, inspect( [&] {
										alterSegmentFixture( location / name, sameSize) ;
										return DWORD{0U} ;
									}) == 13U &&
										!proof && diagnostic.finalReadCalls > 0U) ;
		const auto changedSameSize =
			// 最終raw差替えを製品が修復していません。
			segmentFixtureImage( location) ;
		DRIVERCRATE_EXPECT( context,
						   changedSameSize.at( name) == sameSize &&
							   changedSameSize.at( name).size() == frames[3].at( name).size()) ;
		alterSegmentFixture( location / name, frames[3].at( name)) ;
	}

	std::cout << "Segment reader final same-size cases: " << direct.size() << '\n' ;

	// 現在集合の未知名とstagingを残したまま非変更で拒否します。
	for( const auto &name : {std::wstring( L"runs/unregistered-reader.json"),
							newPrefix + L"current/unregistered-reader.json",
							newPrefix + L"runs/unregistered-reader.json.tmp",
							newPrefix + L"history/runs/unregistered-reader.json"}) {
		alterSegmentFixture( location / name, "{}") ;
		copySegmentFixtureDacl( model, location / name) ;
		const auto changed = segmentFixtureImage( location) ;	// 故意の追加を含む像です。
		DRIVERCRATE_EXPECT( context,
						   inspect() == 13U && !proof && changed == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( location / name))) ;
	}

	// 未知名が二件なら固定directory列挙枠を超え、本文を追加で読まず68を保持します。
	const auto extraOne =
		newPrefix + L"history/runs/unregistered-reader-one.json" ;	// 自作追加名です。
	const auto extraTwo =
		newPrefix + L"history/runs/unregistered-reader-two.json" ;	// 二件目の上限反証です。
	alterSegmentFixture( location / extraOne, "{}") ;
	alterSegmentFixture( location / extraTwo, "{}") ;
	copySegmentFixtureDacl( model, location / extraOne) ;
	copySegmentFixtureDacl( model, location / extraTwo) ;
	const auto twoExtra = segmentFixtureImage( location) ;	// 68でも追加像を修復しない正本です。
	DRIVERCRATE_EXPECT( context, inspect() == 68U && !proof && diagnostic.finalReadCalls == 0U &&
									twoExtra == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context,
					   std::filesystem::remove( segmentFixturePath( location / extraOne)) &&
						   std::filesystem::remove( segmentFixturePath( location / extraTwo))) ;

	// 四scopeのhard linkを実file属性で拒否し、同byteでも証明を発行しません。
	for( const auto &name : {std::wstring( L"current/collection-head-v1.json"),
							oldPrefix + L"current/segment-seal-v1.json",
							newPrefix + L"current/segment-shared-base-v1.json",
							newPrefix + L"history/current/segment-history-root-v1.json"}) {
		const auto alias =
			// 自作GUID内だけの別名です。
			location.parent_path() / L"reader-hardlink-alias.json" ;
		// 必須file自身のlink数だけを反証し、currentの未知名拒否へ混同しません。
		if( !CreateHardLinkW( segmentFixturePath( alias).c_str(),
							segmentFixturePath( location / name).c_str(), nullptr)) {
			throw std::runtime_error( "segment reader hardlink fixture") ;
		}

		DRIVERCRATE_EXPECT( context, inspect() == 5U && !proof &&
										segmentFixtureImage( location) == frames[3] &&
										std::filesystem::exists( alias)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( alias))) ;
	}

	// 四scopeの必須fileへ広いACLを注入し、読取り中のDACL修復がないことを検査します。
	for( const auto &name : {std::wstring( L"current/collection-head-v1.json"),
							oldPrefix + L"current/segment-seal-v1.json",
							newPrefix + L"current/segment-shared-base-v1.json",
							newPrefix + L"history/current/segment-history-root-v1.json"}) {
		broadenSegmentFixtureDacl( location / name, false) ;
		DRIVERCRATE_EXPECT( context,
						   inspect() == 5U && !proof && segmentFixtureImage( location) == frames[3]) ;
		// 同じ不正ACLを二回拒否することも確認し、自動修復と区別します。
		DRIVERCRATE_EXPECT( context, inspect() == 5U && !proof) ;
		copySegmentFixtureDacl( model, location / name) ;
	}

	// 子と新historyのlock欠損は非作成入口で保持し、空lockを作って成功させません。
	for( const auto &name : {oldPrefix + L"collector.lock", newPrefix + L"collector.lock",
							newPrefix + L"history/collector.lock"}) {
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( location / name))) ;
		DRIVERCRATE_EXPECT( context, inspect() == 2U && !proof &&
										!std::filesystem::exists( location / name) &&
										segmentFixtureImage( location) == frames[3]) ;
		alterSegmentFixture( location / name, "") ;
		copySegmentFixtureDacl( model, location / name) ;
	}

	const auto historyRuns =
		location / newPrefix / L"history/runs" ;	// 元空directoryの欠損だけです。
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( historyRuns))) ;
	DRIVERCRATE_EXPECT( context, inspect() == 2U && !proof &&
									!std::filesystem::exists( historyRuns) &&
									segmentFixtureImage( location) == frames[3]) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::create_directory( segmentFixturePath( historyRuns))) ;
	copySegmentFixtureDacl( location / newPrefix / L"history/current", historyRuns) ;

	// 私有history directory自身の広いACLも本文の正当性へ読み替えません。
	broadenSegmentFixtureDacl( historyRuns, true) ;
	DRIVERCRATE_EXPECT( context,
					   inspect() == 5U && !proof && segmentFixtureImage( location) == frames[3]) ;
	DRIVERCRATE_EXPECT( context, inspect() == 5U && !proof) ;
	copySegmentFixtureDacl( location / newPrefix / L"history/current", historyRuns) ;

	const auto thirdChild =
		location / L"segments" / std::wstring( 64U, L'5') ;	// 元二子にない自作区間です。
	DRIVERCRATE_EXPECT( context, std::filesystem::create_directory( segmentFixturePath( thirdChild))) ;
	copySegmentFixtureDacl( location / newPrefix, thirdChild) ;
	DRIVERCRATE_EXPECT( context, inspect() == 13U && !proof &&
									std::filesystem::exists( segmentFixturePath( thirdChild)) &&
									segmentFixtureImage( location) == frames[3]) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( thirdChild))) ;

	// 旧history modeの混入を旧監督へfallbackせず、元追加byteを残して拒否します。
	const auto mixedMode =
		newPrefix + L"history/current/collector-campaign-mode-v1.json" ;	// 元専用ROOTに無い名です。
	alterSegmentFixture(
		location / mixedMode,
		frames[3].at( oldPrefix + L"history/current/collector-campaign-mode-v1.json")) ;
	copySegmentFixtureDacl( model, location / mixedMode) ;
	const auto mixedBefore = segmentFixtureImage( location) ;	// 故意の混在byteを保持する正本です。
	DRIVERCRATE_EXPECT( context,
					   inspect() == 13U && !proof && mixedBefore == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( location / mixedMode))) ;

	{
		auto laterIntent	= draft.intent ;	// 本番型で後続ordinalだけを変更します。
		laterIntent.ordinal = 2U ;
		std::string	 laterBody ;	// 本番encoderが生成したcanonical本文です。
		std::wstring laterHash ;	// 新本文自身の実CNG hashです。
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorSegmentSwitchIntent( laterIntent, laterBody) == 0U &&
							   computeCollectorMetadataSha256( laterBody, laterHash) == 0) ;
		const auto laterName =
			L"runs/segment-switch-intent-" + laterHash + L".json" ;	// 元固定命名規則です。
		alterSegmentFixture( location / laterName, segmentFixtureEnvelope( laterBody)) ;
		copySegmentFixtureDacl( model, location / laterName) ;
		const auto laterBefore = segmentFixtureImage( location) ;	// 非対応で全byteを保持します。
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentReader::inspect(
										*reopened, laterHash, proof, diagnostic) == 50U &&
										!proof && diagnostic.collectionChecks == 0U &&
										laterBefore == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context,
						   std::filesystem::remove( segmentFixturePath( location / laterName))) ;
	}
	DRIVERCRATE_EXPECT( context,
					   inspect() == 0U && proof && segmentFixtureImage( location) == frames[3]) ;
	proof.reset() ;

	std::vector<std::wstring> currentNames ;	// 元保存像の予算／group／全requestの順です。
	std::vector<std::wstring> carryNames ;		// 同じ66像の新子固定名です。
	std::uint64_t			  carryBytes{} ;	// 元carryの一pass長を独立合算します。
	// 元frameの辞書順を使い、製品の部分計数から期待byteを導出しません。
	for( const auto &[name, raw] : frames[3]) {
		// 親の全66像だけを有限枠の反証対象へ登録します。
		if( name.starts_with( L"current/shared-")) {
			currentNames.push_back( name) ;
		}

		// 新子の全carryだけを元固定ordinal順へ登録します。
		if( name.starts_with( newPrefix + L"runs/segment-switch-image-")) {
			carryNames.push_back( name) ;
			carryBytes += raw.size() ;
		}
	}

	DRIVERCRATE_EXPECT( context, currentNames.size() == 66U && carryNames.size() == 66U &&
									segmentBytes > carryBytes) ;
	// 異なるfixtureを容量拒否の成功へ読み替えません。
	if( currentNames.size() != 66U || carryNames.size() != 66U || segmentBytes <= carryBytes) {
		throw std::runtime_error( "segment reader capacity fixture shape") ;
	}

	constexpr std::uint64_t RAW_BYTES = 2U * 1024U * 1024U ;	// 共通readの実file上限です。
	const auto				sharedPrefixBytes =
		frames[3].at( L"current/collector-campaign-mode-v1.json").size() +
		frames[3].at( L"current/collection-head-v1.json").size() ;	// 親の二必須rawです。
	const auto segmentPrefixBytes = segmentBytes - carryBytes ;		// carry前の全必須直接根拠です。
	// 二つの実scopeと上限ちょうど／一byte残余の四ケースを独立に測ります。
	for( const bool shared : {true, false}) {
		// 次のrawが残枠0または1を超えることを同handleで検査します。
		for( const std::uint64_t residual : {0U, 1U}) {
			const auto limit  = (shared ? 16U : 64U) * 1024U * 1024U ;	// 本番の固定枠です。
			const auto filled = shared ? 8U : 32U ;						// 末尾調整付き2 MiB rawの件数です。
			const auto prefix =
				shared ? sharedPrefixBytes : segmentPrefixBytes ;		// 元制御rawの一pass長です。
			const auto &names = shared ? currentNames : carryNames ;	// 一方のscopeだけを改変します。
			// 末尾rawの調整量を正の共通file上限内へ限定します。
			if( prefix + residual >= RAW_BYTES) {
				throw std::runtime_error( "segment reader capacity fixture prefix") ;
			}

			// 最後の一rawだけを短縮し、元制御rawを含む総byteを正確に枠へ合わせます。
			for( std::size_t n = 0U; n < filled; ++n) {
				const auto bytes = n + 1U == filled ? RAW_BYTES - prefix - residual
													: RAW_BYTES ;	// 独立の予定sizeです。
				alterSegmentFixture( location / names[n],
									std::string( static_cast<std::size_t>( bytes), 'x')) ;
			}

			const auto before = segmentFixtureImage( location) ;	// 故意の大rawを含む非変更正本です。
			bool	   callbackCalled{} ;							// 内容decode前の停止と成功後診断を分離します。
			const auto code = inspect( [&] {
				callbackCalled = true ;
				return DWORD{0U} ;
			}) ; // 容量拒否時はこの診断を呼んではいけません。
			DRIVERCRATE_EXPECT(
				context, code == 68U && !proof && !callbackCalled &&
							 diagnostic.finalReadCalls == 0U && diagnostic.directoryChecks == 0U &&
							 diagnostic.collectionChecks == 1U && diagnostic.oldPayloadReads == 0U) ;
			std::uint64_t otherBytes =
				shared ? segmentPrefixBytes
					   : sharedPrefixBytes ;	// 改変していないscopeの独立合計です。
			// 失敗する現在readより先のcarry、または失敗carryより先の現在readだけを合算します。
			for( std::size_t n = 0U; n < filled + (shared ? 1U : 0U); ++n) {
				otherBytes += frames[3].at( shared ? carryNames[n] : currentNames[n]).size() ;
			}

			const auto expectedSegmentCalls =
				// 最後の未課金試行も含みます。
				draft.intent.inventory.size() + 8U + filled + 1U ;
			const auto expectedSharedCalls =
				2U + filled + (shared ? 1U : 0U) ;	// 親markerとheadを含みます。
			DRIVERCRATE_EXPECT(
				context, diagnostic.sharedBytes == (shared ? limit - residual : otherBytes) &&
							 diagnostic.segmentBytes == (shared ? otherBytes : limit - residual) &&
							 diagnostic.sharedReadCalls == expectedSharedCalls &&
							 diagnostic.sharedNames == expectedSharedCalls &&
							 diagnostic.segmentReadCalls == expectedSegmentCalls &&
							 diagnostic.segmentNames == expectedSegmentCalls) ;
			DRIVERCRATE_EXPECT( context, before == segmentFixtureImage( location)) ;
			std::cout << "Segment reader capacity stop: scope=" << (shared ? "shared" : "segment")
					  << " limit=" << limit << " residual=" << residual
					  << " charged=" << (shared ? diagnostic.sharedBytes : diagnostic.segmentBytes)
					  << " code=" << code << '\n' ;
			// 次のケースへ製品ではなくfixture callerが元保存byteだけを復元します。
			for( std::size_t n = 0U; n < filled; ++n) {
				alterSegmentFixture( location / names[n], frames[3].at( names[n])) ;
			}

			DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == frames[3]) ;
		}
	}

	{
		LocalCollectorStateStore rawStore ;					// aggregateとは別の同handle個別境界fixtureです。
		const auto				 rawRoot = rootFactory() ;	// 自作GUIDの保護専用領域です。
		const std::string		 raw( static_cast<std::size_t>( RAW_BYTES),
									 'x') ;	// 内容合格ではなくraw readの上限です。
		DRIVERCRATE_EXPECT( context, rawStore.initialize( rawRoot, true) == 0U &&
										rawStore.write( L"runs/reader-boundary.json", raw) == 0U) ;
		// 実2 MiB rawに対するbudgetの直前／ちょうど／直後を分けて測ります。
		for( const std::uint64_t budget : {RAW_BYTES - 1U, RAW_BYTES, RAW_BYTES + 1U}) {
			auto		remaining = budget ;	// 成否に応じた残枠を独立に比較します。
			std::string bytes	  = "stale" ;	// 失敗時の出力消去も確認します。
			bool		found	  = true ;		// 失敗時はfalseへ戻る必要があります。
			const auto	code	  = rawStore.read( L"runs/reader-boundary.json", bytes, found,
												  remaining) ;	// 同一保護fileです。
			DRIVERCRATE_EXPECT( context, budget < RAW_BYTES ? code == 68U && bytes.empty() &&
																 !found && remaining == budget
														   : code == 0U && bytes == raw && found &&
																 remaining == budget - RAW_BYTES) ;
		}

		std::uint64_t emptyBudget{} ;	// 使い切り後に自動補充しません。
		std::string	  bytes = "stale" ;	// 次の拒否でも消去します。
		bool		  found = true ;	// 予算不足からfoundを推測しません。
		DRIVERCRATE_EXPECT( context, rawStore.read( L"runs/reader-boundary.json", bytes, found,
												  emptyBudget) == 68U &&
										bytes.empty() && !found && emptyBudget == 0U) ;
		// 空fileと個別上限超過はbudget不足68ではなく実size拒否13です。
		for( const std::size_t size : {std::size_t{0U}, static_cast<std::size_t>( RAW_BYTES + 1U)}) {
			alterSegmentFixture( rawRoot / L"runs/reader-boundary.json", std::string( size, 'x')) ;
			auto remaining = RAW_BYTES + 1U ;	// size拒否時に先払いしない枠です。
			DRIVERCRATE_EXPECT( context, rawStore.read( L"runs/reader-boundary.json", bytes, found,
													  remaining) == 13U &&
											bytes.empty() && !found && remaining == RAW_BYTES + 1U) ;
		}
	}

	// 初回検査後のsharingは本文read、現在名欠損は名監査で停止する位置を区別します。
	for( const auto &name : {std::wstring( L"current/collection-head-v1.json"),
							oldPrefix + L"current/segment-seal-v1.json",
							newPrefix + L"current/segment-shared-base-v1.json",
							newPrefix + L"history/current/segment-history-root-v1.json"}) {
		const bool		  old = name.starts_with( oldPrefix) ;	// 旧scopeは全名監査をしません。
		const std::size_t expectedFinalReads = old											? 10U
											   : name == L"current/collection-head-v1.json" ? 2U
											   : name.ends_with( L"segment-shared-base-v1.json")
												   ? 8U
												   : 7U ;	// 固定raw登録順の独立期待値です。
		const auto		  scope				 = old						  ? "old-seal"
											   : expectedFinalReads == 2U ? "parent-head"
											   : expectedFinalReads == 8U ? "new-base"
																		  : "new-root" ;	// pathを出さない試験区分です。
		std::unique_ptr<void, decltype( &CloseHandle)> locked(
			nullptr, &CloseHandle) ;	// 診断終了後も故障を保持します。
		const auto sharingCode = inspect( [&] {
			const auto handle = CreateFileW(
				segmentFixturePath( location / name).c_str(), GENERIC_READ, 0U, nullptr,
				OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 自作fileだけの排他です。
			// 排他注入不成立を製品の32成功へ読み替えません。
			if( handle == INVALID_HANDLE_VALUE) {
				throw std::runtime_error( "segment reader final sharing fixture") ;
			}

			locked.reset( handle) ;
			return DWORD{0U} ;
		}) ; // 最終検査が終わるまで元handleを解放しません。
		std::cout << "Segment reader final sharing: scope=" << scope << " code=" << sharingCode
				  << " finalReads=" << diagnostic.finalReadCalls
				  << " expected=" << expectedFinalReads << '\n' ;
		DRIVERCRATE_EXPECT( context, sharingCode == 32U && !proof &&
										diagnostic.finalReadCalls == expectedFinalReads) ;
		locked.reset() ;
		DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == frames[3]) ;
		const auto missingCode = inspect( [&] {
			DRIVERCRATE_EXPECT( context,
							   std::filesystem::remove( segmentFixturePath( location / name))) ;
			return DWORD{0U} ;
		}) ; // 固定directory自体を作成・修復しない個別欠損です。
		DRIVERCRATE_EXPECT( context, missingCode == (old ? 2U : 13U) && !proof &&
										diagnostic.finalReadCalls == (old ? 10U : 0U)) ;
		auto missing = frames[3] ;	// 独立に一fileだけを欠く期待像です。
		missing.erase( name) ;
		DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == missing) ;
		alterSegmentFixture( location / name, frames[3].at( name)) ;
		copySegmentFixtureDacl( model, location / name) ;
	}

	// 診断後に追加した現在名とstagingも、最終raw読取り前に拒否します。
	for( const auto &name :
		{std::wstring( L"runs/late-reader.json"), newPrefix + L"current/late-reader.json",
		 newPrefix + L"history/runs/late-reader.json.tmp"}) {
		const auto code = inspect( [&] {
			alterSegmentFixture( location / name, "{}") ;
			copySegmentFixtureDacl( model, location / name) ;
			return DWORD{0U} ;
		}) ; // 同threadの故障注入だけでHTTPは発行しません。
		DRIVERCRATE_EXPECT( context, code == 13U && !proof && diagnostic.finalReadCalls == 0U) ;
		auto added = frames[3] ;	// 独立に一fileだけを加えた期待像です。
		added.emplace( name, "{}") ;
		DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == added) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( location / name))) ;
	}

	DRIVERCRATE_EXPECT( context, inspect() == 0U && proof && diagnostic.oldPayloadReads == 0U &&
									segmentFixtureImage( location) == frames[3]) ;
	proof.reset() ;

	// 保護本文readの第一sharing32をscope別に保持します。
	for( const auto &name : {std::wstring( L"current/collection-head-v1.json"),
							oldPrefix + L"current/segment-seal-v1.json",
							newPrefix + L"current/segment-shared-base-v1.json",
							newPrefix + L"history/current/segment-history-root-v1.json"}) {
		const auto handle =
			CreateFileW( segmentFixturePath( location / name).c_str(), GENERIC_READ, 0U, nullptr,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 故障注入だけの排他です。
		// 注入不成立を製品の第一error合格へ数えません。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "read context sharing fixture") ;
		}

		const std::unique_ptr<void, decltype( &CloseHandle)> locked(
			handle, &CloseHandle) ;	// 元threadで返します。
		DRIVERCRATE_EXPECT( context, inspect() == 32U && !proof) ;
	}

	// 正規ASCII行の固定上界は実読取り予算より小さく、初回shapeの有効最終不足を作れません。
	constexpr std::uint64_t IMAGE_BOUND = 2U * 768U * 1024U + 256U + 2U * (20U * 1024U + 512U) +
										  256U + 4096U * (1024U + 128U) +
										  64U * (2U * 512U + 64U + 256U) ;	// 66像の保守上界です。
	constexpr std::uint64_t SHARED_BOUND =
		2U * (IMAGE_BOUND + 2U * 256U * 1024U + 256U + 1024U) ;	// headとmarker込みです。
	constexpr std::uint64_t SEGMENT_BOUND =
		2U * (IMAGE_BOUND + 2U * 1024U + 5U * (2U * 16U * 1024U + 256U) + 2U * 256U * 1024U + 256U +
			  16U * (2U * 256U * 1024U + 256U)) ;	// 16shardと全制御込みです。
	static_assert( IMAGE_BOUND == 6419968U && SHARED_BOUND == 13891072U &&
				  SEGMENT_BOUND == 31008768U && SHARED_BOUND < 16U * 1024U * 1024U &&
				  SEGMENT_BOUND < 64U * 1024U * 1024U) ;
	std::cout << "Segment reader valid bounds: shared=" << SHARED_BOUND
			  << " segment=" << SEGMENT_BOUND << " sharedNames=68 segmentNames=90\n" ;
	const auto bodyOf = []( const std::string &raw) {
		return winrt::to_string( JsonObject::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
	} ; // 自作fixtureの独立JSON readerだけです。
	const auto hashOf = []( const std::string_view raw) {
		std::wstring hash ;	// 仮定したhashを実CNGへ混入させません。
		// FixtureのCNG不成立を製品の意味拒否へ数えません。
		if( computeCollectorMetadataSha256( raw, hash) != 0) {
			throw std::runtime_error( "segment rebound hash") ;
		}

		return hash ;
	} ; // 同期呼出し中だけ元byteを借用します。
	const auto quote = []( const std::wstring_view text) {
		return "\"" + winrt::to_string( text) + "\"" ;
	} ; // 完全ASCII hashだけの試験JSON値です。
	const auto sealName = oldPrefix + L"current/segment-seal-v1.json" ;	// 固定旧checkpointです。
	const auto rootName =
		newPrefix + L"history/current/segment-history-root-v1.json" ;	// 固定新ROOTです。
	std::vector<std::string> originalInventories ;						// 実writerが保存したordinal順の本文です。
	// 元保存roleからだけ旧inventoryを独立に集めます。
	for( const auto &role : roles) {
		// 旧scopeの固定inventory以外を名前から開きません。
		if( role.scope == CollectorSegmentStorageScope::OLD_SEGMENT &&
		   role.name.starts_with( L"runs/segment-inventory-")) {
			originalInventories.push_back( bodyOf( frames[3].at( oldPrefix + role.name))) ;
		}
	}

	const auto originalSeal = bodyOf( frames[3].at( sealName)) ;	// 元22fieldの順序です。
	const auto rebound =
		[&]( const CollectorSharedLedgerSnapshot &carried, const std::vector<std::string> &bodies,
			std::string												  seal,
			const std::optional<std::pair<std::size_t, std::string>> &imageOverride =
				std::nullopt) {
			CollectorSegmentSwitchRequest request ;	// Hashや入力から能力を構築しません。
			request.oldSegment	= draft.intent.oldSegment ;
			request.newSegment	= draft.intent.newSegment ;
			request.oldHead		= draft.intent.oldHead ;
			request.oldRoot		= draft.intent.oldRoot ;
			request.accepted	= draft.intent.accepted ;
			request.observation = {true, true, true, 0U, 0U, false} ;
			collector_projected_json::Writer hashes( 4096U) ;	// 元順で最大16参照を結合します。
			hashes.append( "[") ;
			// 正しいCNGでも意味矛盾を検査できるように全上位参照を結合します。
			for( const auto &body : bodies) {
				// 先頭以外へ固定delimiterを入れます。
				if( !request.inventory.empty()) {
					hashes.append( ",") ;
				}

				request.inventory.push_back( hashOf( body)) ;
				hashes.wideText( request.inventory.back()) ;
			}

			hashes.append( "]") ;
			seal		 = replaceSegmentFixtureField( std::move( seal), "inventory", hashes.view()) ;
			request.seal = hashOf( seal) ;
			CollectorSegmentSwitchDraft derived ;	// 元carryを本番非保存coreから再導出します。
			// 不成立のdraftから後続JSONを補完しません。
			if( prepareCollectorSegmentSwitchDraft( carried, carried, request, derived) != 0U) {
				throw std::runtime_error( "segment rebound draft") ;
			}

			// 4096要求の正例だけ新しいledgerをsealへ結合し、元台帳の負例は修復しません。
			if( carried.requests.size() != snapshot.requests.size()) {
				seal		 = replaceSegmentFixtureField( std::move( seal), "ledger",
														  quote( derived.intent.ledger)) ;
				request.seal = hashOf( seal) ;
				// 新ledgerへ結合したsealを起点に全参照をもう一度導出します。
				if( prepareCollectorSegmentSwitchDraft( carried, carried, request, derived) != 0U) {
					throw std::runtime_error( "segment rebound carried draft") ;
				}
			}

			CollectorSharedLedgerBytes shared ;	// 元合法台帳の本文を先に保持します。
			// 不成立台帳を試験の上位参照再計算へ流用しません。
			if( encodeCollectorSharedLedger( carried, shared) != 0U) {
				throw std::runtime_error( "segment rebound shared") ;
			}

			// 不正像の実hashを全上位へ結び、外側hash不一致だけの拒否にしません。
			if( imageOverride) {
				const auto n = imageOverride->first ;	// 固定66像の一つだけです。
				// Callerのfixture誤りを製品拒否へ数えません。
				if( n >= 66U) {
					throw std::runtime_error( "segment rebound image ordinal") ;
				}

				(n == 0U   ? shared.budget
				 : n == 1U ? shared.groups
						   : shared.requests[n - 2U]) = imageOverride->second ;
				collector_projected_json::Writer imageHashes( 8192U) ;	// 元66順の指紋配列です。
				imageHashes.append( "[") ;
				// 差替え後の全像を実CNGで検査し、前の指紋を残しません。
				for( std::size_t index = 0U; index < 66U; ++index) {
					const auto &body =
						index == 0U	  ? shared.budget
						: index == 1U ? shared.groups
									  : shared.requests[index - 2U] ;	// 同期呼出し中の所有本文です。
					derived.images[index] = hashOf( body) ;
					// 先頭以外の区切りを固定します。
					if( index != 0U) {
						imageHashes.append( ",") ;
					}

					imageHashes.wideText( derived.images[index]) ;
				}

				imageHashes.append( "]") ;
				const auto ledgerBody =
					"{\"schema\":\"collector-shared-digest-v1\",\"collection\":" +
					quote( carried.collection) + ",\"hashes\":" + std::string( imageHashes.view()) +
					"}" ;	// 元digest domainです。
				derived.intent.ledger = hashOf( ledgerBody) ;
				seal				  = replaceSegmentFixtureField( std::move( seal), "ledger",
																   quote( derived.intent.ledger)) ;
				derived.intent.seal	  = hashOf( seal) ;
				// 下流を含まないbaseから一方向に再hashします。
				for( auto *body : {&derived.base, &derived.bootstrap}) {
					*body = replaceSegmentFixtureField( std::move( *body), "ledger",
													   quote( derived.intent.ledger)) ;
					*body = replaceSegmentFixtureField( std::move( *body), "seal",
													   quote( derived.intent.seal)) ;
				}

				derived.intent.base = hashOf( derived.base) ;
				derived.bootstrap = replaceSegmentFixtureField( std::move( derived.bootstrap), "base",
															   quote( derived.intent.base)) ;
				derived.bootstrap = replaceSegmentFixtureField( std::move( derived.bootstrap),
															   "hashes", imageHashes.view()) ;
				derived.intent.bootstrap = hashOf( derived.bootstrap) ;
				derived.nextHead = replaceSegmentFixtureField( std::move( derived.nextHead), "ledger",
															  quote( derived.intent.ledger)) ;
				derived.nextHead = replaceSegmentFixtureField( std::move( derived.nextHead), "base",
															  quote( derived.intent.base)) ;
				derived.nextHead = replaceSegmentFixtureField(
					std::move( derived.nextHead), "bootstrap", quote( derived.intent.bootstrap)) ;
				derived.nextHead = replaceSegmentFixtureField( std::move( derived.nextHead), "seal",
															  quote( derived.intent.seal)) ;
				derived.intent.nextHead = hashOf( derived.nextHead) ;
				// 型付きintentの固定field順を維持し、不正像の本文はcodecへ渡すまで保存します。
				if( encodeCollectorSegmentSwitchIntent( derived.intent, derived.intentBytes) != 0U) {
					throw std::runtime_error( "segment rebound override intent") ;
				}

				derived.intentHash = hashOf( derived.intentBytes) ;
			}

			auto result = frames[3] ;	// 元非対象の旧payloadは保持します。
			// 元intentに結合した固定名だけを置換し、任意JSONのpathを使用しません。
			for( auto it = result.begin(); it != result.end();) {
				const auto &name = it->first ;	// このmapだけの安定参照です。
				// key付き直接根拠は新hash名で再配置します。固定名は上書きです。
				if( name == intentName || name == activationName ||
				   name.starts_with( oldPrefix + L"runs/segment-inventory-") ||
				   name.starts_with( newPrefix + L"runs/segment-switch-image-") ||
				   name.starts_with( newPrefix + L"runs/segment-switch-bootstrap-")) {
					it = result.erase( it) ;
				} else {
					++it ;
				}
			}

			auto rootBody = bodyOf( frames[3].at( rootName)) ;	// 元17fieldから全参照だけ更新します。
			rootBody =
				replaceSegmentFixtureField( std::move( rootBody), "seal", quote( derived.intent.seal)) ;
			rootBody = replaceSegmentFixtureField( std::move( rootBody), "ledger",
												  quote( derived.intent.ledger)) ;
			rootBody =
				replaceSegmentFixtureField( std::move( rootBody), "base", quote( derived.intent.base)) ;
			rootBody = replaceSegmentFixtureField( std::move( rootBody), "bootstrap",
												  quote( derived.intent.bootstrap)) ;
			rootBody = replaceSegmentFixtureField( std::move( rootBody), "switchIntent",
												  quote( derived.intentHash)) ;
			collector_projected_json::Writer images( 8192U) ;	// 元66本文のCNG hash順です。
			images.append( "[") ;
			// 空shardも含めて全66像へ結合します。
			for( const auto &hash : derived.images) {
				// 先頭以外にdelimiterを追加します。
				if( images.view().size() != 1U) {
					images.append( ",") ;
				}

				images.wideText( hash) ;
			}

			images.append( "]") ;
			rootBody = replaceSegmentFixtureField( std::move( rootBody), "images", images.view()) ;
			auto activationBody = bodyOf( frames[3].at( activationName)) ;	// 元head rawは保持します。
			activationBody		= replaceSegmentFixtureField( std::move( activationBody), "intent",
															 quote( derived.intentHash)) ;
			activationBody = replaceSegmentFixtureField( std::move( activationBody), "initialRoot",
														quote( hashOf( rootBody))) ;
			activationBody = replaceSegmentFixtureField( std::move( activationBody), "nextHead",
														quote( derived.intent.nextHead)) ;
			result[L"runs/segment-switch-intent-" + derived.intentHash + L".json"] =
				segmentFixtureEnvelope( derived.intentBytes) ;
			result[L"runs/segment-switch-activation-" + derived.intentHash + L".json"] =
				segmentFixtureEnvelope( activationBody) ;
			result[L"current/collection-head-v1.json"] = segmentFixtureEnvelope( derived.nextHead) ;
			result[rootName]						   = segmentFixtureEnvelope( rootBody) ;
			result[sealName]						   = segmentFixtureEnvelope( seal) ;
			result[newPrefix + L"current/segment-shared-base-v1.json"] =
				segmentFixtureEnvelope( derived.base) ;
			result[newPrefix + L"runs/segment-switch-bootstrap-" + derived.intentHash + L".json"] =
				segmentFixtureEnvelope( derived.bootstrap) ;
			constexpr std::wstring_view digits = L"0123456789abcdef" ;	// 固定ordinalです。
			// 全66carryを同じrawで親現在像へ配置します。
			for( std::size_t n = 0U; n < 66U; ++n) {
				const auto ordinal = std::wstring( 1U, digits[n / 16U]) +
									 // 00～41です。
									 std::wstring( 1U, digits[n % 16U]) ;
				const auto	current = n == 0U ? std::wstring( L"current/shared-budget-v1.json")
									  : n == 1U
										  ? std::wstring( L"current/shared-groups-v1.json")
										  : L"current/shared-requests-" +
												std::wstring( 1U, digits[(n - 2U) / 16U]) +
												// 全固定名です。
												std::wstring( 1U, digits[(n - 2U) % 16U]) + L".json" ;
				const auto &body	= n == 0U	? shared.budget
									  : n == 1U ? shared.groups
												: shared.requests[n - 2U] ;	// 完成後だけ借用します。
				const auto	raw		= segmentFixtureEnvelope( body) ;		// 実CNGと外側canonicalです。
				result[current]		= raw ;
				result[newPrefix + L"runs/segment-switch-image-" + derived.intentHash + L"-" +
					   ordinal + L".json"] = raw ;
			}

			// 最大16の完全ordinal名からだけ実file名を生成します。
			for( std::size_t n = 0U; n < bodies.size(); ++n) {
				const auto ordinal = std::wstring( 1U, digits[n / 16U]) +
									 // 00～0fです。
									 std::wstring( 1U, digits[n % 16U]) ;
				result[oldPrefix + L"runs/segment-inventory-" + derived.intentHash + L"-" +
					   ordinal + L".json"] = segmentFixtureEnvelope( bodies[n]) ;
			}

			return std::make_pair( std::move( result), derived.intentHash) ;
		} ; // 所有rawは同期実検査まで保持し、製品の保存能力ではありません。
	const auto applyFrame = [&]( const std::map<std::wstring, std::string> &frame) {
		const auto current = segmentFixtureImage( location) ;	// 自作全保存集合だけです。
		// 次の固定frameにない自作fileだけを除去します。directoryやlockは触りません。
		for( const auto &[name, raw] : current) {
			(void)raw ;
			// 新しいfixtureに含まれないキー付き直接fileだけを片付けます。
			if( !frame.contains( name) &&
			   !std::filesystem::remove( segmentFixturePath( location / name))) {
				throw std::runtime_error( "segment rebound remove") ;
			}
		}

		// 差分rawだけを試験callerが保存して正規DACLを複製します。
		for( const auto &[name, raw] : frame) {
			const auto found = current.find( name) ;	// 元fixture側の非変更判定です。
			// 完全同byteの非対象fileは書き直しません。
			if( found == current.end() || found->second != raw) {
				alterSegmentFixture( location / name, raw) ;
				copySegmentFixtureDacl( model, location / name) ;
			}
		}
	} ; // 保護領域内の自作fixtureだけです。製品のrepairではありません。
	const auto checkFrame = [&]( const auto &bound, const DWORD expected,
								const std::size_t fileCount, const std::size_t requestCount = 0U) {
		applyFrame( bound.first) ;
		bool	   called{} ;	// 意味拒否が診断へ到達していないことを測ります。
		const auto code =
			LocalCollectorSegmentReader::inspect( *reopened, bound.second, proof, diagnostic, [&] {
				called = true ;
				return DWORD{0U} ;
			}) ; // 同threadの非通信callbackです。
		context.expect(
			code == expected &&
				(expected == 0U
					 ? proof && called && proof->state().files.size() == fileCount &&
						   proof->state().recovery.carried.requests.size() == requestCount
					 : !proof && !called && diagnostic.finalReadCalls == 0U),
			"segment rebound code=" + std::to_string( code) +
				" expected=" + std::to_string( expected),
			__FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == bound.first &&
										diagnostic.oldPayloadReads == 0U) ;
		proof.reset() ;
		applyFrame( frames[3]) ;
	} ; // 能力を破棄してから元保存像へ戻し、次の試験へ独立に進みます。
	checkFrame( rebound( snapshot, originalInventories, originalSeal), 0U, 168U,
			   snapshot.requests.size()) ;
	CollectorSharedLedgerBytes originalShared ;	// 66像の正例は元codecからだけ作ります。
	// 故障注入元が正規本文でない場合は試験を中止します。
	if( encodeCollectorSharedLedger( snapshot, originalShared) != 0U) {
		throw std::runtime_error( "segment all images fixture") ;
	}

	checkFrame( rebound( snapshot, originalInventories, originalSeal,
					   std::make_pair( std::size_t{0U}, originalShared.budget)),
			   0U, 168U, snapshot.requests.size()) ;
	// 各像の意味不一致と非canonical本文を個別に全上位再結合し、外側だけの改変と分離します。
	for( std::size_t n = 0U; n < 66U; ++n) {
		const auto &body = n == 0U	 ? originalShared.budget
						   : n == 1U ? originalShared.groups
									 : originalShared.requests[n - 2U] ;	// 元合法の一像です。
		const auto	changed =
			 n < 2U
				 ? replaceSegmentFixtureField( body, "collection", quote( std::wstring( 64U, L'f')))
				 : replaceSegmentFixtureField(
					   body, "ordinal", std::to_string( (n - 1U) % 64U)) ;	// 型とfield順を保持します。
		checkFrame( rebound( snapshot, originalInventories, originalSeal, std::make_pair( n, changed)),
				   13U, 0U) ;
		checkFrame(
			rebound( snapshot, originalInventories, originalSeal, std::make_pair( n, " " + body)),
			13U, 0U) ;
	}

	std::cout << "Segment reader all rehash: semanticImages=66 noncanonicalImages=66\n" ;
	// 初回専用ROOTの非空値は後続更新schemaの実装を仮定せず拒否します。
	for( const auto &[key, value] :
		std::vector<std::pair<std::string, std::string>>{{"generations", "[\"entry\"]"},
														 {"operations", "[\"entry\"]"},
														 {"active", "\"entry\""}}) {
		auto bound =
			// 他の参照は成立した正例です。
			rebound( snapshot, originalInventories, originalSeal) ;
		const auto changed = replaceSegmentFixtureField( bodyOf( bound.first.at( rootName)), key,
														value) ;	// 非対応値です。
		const auto activation =
			L"runs/segment-switch-activation-" + bound.second + L".json" ;	// 同intent固定名です。
		bound.first[rootName]	= segmentFixtureEnvelope( changed) ;
		bound.first[activation] = segmentFixtureEnvelope( replaceSegmentFixtureField(
			bodyOf( bound.first.at( activation)), "initialRoot", quote( hashOf( changed)))) ;
		checkFrame( bound, 13U, 0U) ;
	}

	// 親のrevision／commit更新を初回ready headへfallbackしません。
	for( const auto &[key, value] : std::vector<std::pair<std::string, std::string>>{
			{"revision", "2"}, {"commit", quote( std::wstring( 64U, L'f'))}}) {
		auto bound =
			// 旧payloadは非変更です。
			rebound( snapshot, originalInventories, originalSeal) ;
		bound.first[L"current/collection-head-v1.json"] =
			segmentFixtureEnvelope( replaceSegmentFixtureField(
				bodyOf( bound.first.at( L"current/collection-head-v1.json")), key, value)) ;
		checkFrame( bound, 13U, 0U) ;
	}

	std::cout << "Segment reader unsupported initial: roots=3 heads=2\n" ;
	std::size_t semanticCases{} ;	// 独立の意味反証ケース数です。
	// 全上位参照を正しいCNGで結合してもsealの元identity／時計／合計は差替えできません。
	for( const auto key :
		{"collection", "segment", "root", "head", "ledger", "rootUtc", "inspectedUtc",
		 "historyFiles", "sharedFiles", "historyBytes", "sharedBytes", "fileCount", "fileBytes"}) {
		const bool hash = std::string_view( key) == "collection" ||
						  std::string_view( key) == "segment" || std::string_view( key) == "root" ||
						  std::string_view( key) == "head" ||
						  // 型を壊さない反証です。
						  std::string_view( key) == "ledger" ;
		checkFrame( rebound( snapshot, originalInventories,
						   replaceSegmentFixtureField( originalSeal, key,
													  hash ? quote( std::wstring( 64U, L'f')) : "1")),
				   13U, 0U) ;
		++semanticCases ;
	}

	// 元head行のpath／scope／raw hash／sizeだけを変え、登録本文まで全参照を再結合します。
	for( const auto &[key, value] :
		std::vector<std::pair<std::string, std::string>>{{"scope", "\"segment\""},
														 {"scope", "\"unknown\""},
														 {"name", "\"current/../head.json\""},
														 {"name", "\"current/other.json\""},
														 {"sha256", quote( draft.intent.oldHead)},
														 {"bytes", "1"}}) {
		auto bodies = originalInventories ;	// 元shard集合を個別に保持します。
		bodies[0]	= replaceSegmentFixtureField( bodies[0], key, value) ;
		checkFrame( rebound( snapshot, bodies, originalSeal), 13U, 0U) ;
		++semanticCases ;
	}

	DRIVERCRATE_EXPECT( context, inspect() == 0U && proof) ;
	const auto acceptedState = proof->state() ;	// 最大登録行の独立合成に使う非能力値です。
	proof.reset() ;
	auto files = acceptedState.files ;	// 元168行と元head結合を保持します。
	// 未選択旧payloadの架空登録だけを最大8192行まで追加します。本文は作成しません。
	while( files.size() < 8192U) {
		files.push_back( {L"history",
						 L"runs/zzz-fixture-" + std::to_wstring( 10000U + files.size()) + L".json",
						 std::wstring( 64U, L'0'), 1U}) ;
	}

	std::vector<std::string> largeInventories ;	// 16shardの正規本文を所有します。
	// 元writerと同じ512行の固定partitionで合成登録を生成します。
	for( std::size_t first = 0U; first < files.size(); first += 512U) {
		collector_projected_json::Writer writer( 256U * 1024U) ;	// 一shardの本文上限です。
		writer.append( "{\"schema\":\"collector-segment-root-inventory-v1\",\"collection\":") ;
		writer.wideText( collectionKey) ;
		writer.append( ",\"segment\":") ;
		writer.wideText( oldKey) ;
		writer.append( ",\"ordinal\":") ;
		writer.number( largeInventories.size()) ;
		writer.append( ",\"fileCount\":8192,\"files\":[") ;
		// 元順と各行の既知scope／相対名を保持します。
		for( std::size_t n = first; n < first + 512U; ++n) {
			// 行先頭以外へ固定delimiterを追加します。
			if( n != first) {
				writer.append( ",") ;
			}

			const auto &file = files[n] ;	// 未選択旧payloadの登録であり、読取り許可ではありません。
			writer.append( "{\"scope\":") ;
			writer.wideText( file.scope) ;
			writer.append( ",\"name\":") ;
			writer.wideText( file.name) ;
			writer.append( ",\"bytes\":") ;
			writer.number( file.bytes) ;
			writer.append( ",\"sha256\":") ;
			writer.wideText( file.sha256) ;
			writer.append( "}") ;
		}

		writer.append( "]}") ;
		largeInventories.push_back( writer.take()) ;
	}

	const auto extra = files.size() - acceptedState.files.size() ;	// 追加登録の1byte合計です。
	auto	   largeSeal =
		replaceSegmentFixtureField( originalSeal, "historyFiles",
								   // 登録件数だけの変化です。
								   std::to_string( acceptedState.checkpoint.historyFiles + extra)) ;
	largeSeal =
		replaceSegmentFixtureField( std::move( largeSeal), "historyBytes",
								   std::to_string( acceptedState.checkpoint.historyBytes + extra)) ;
	largeSeal = replaceSegmentFixtureField( std::move( largeSeal), "fileCount", "8192") ;
	largeSeal =
		replaceSegmentFixtureField( std::move( largeSeal), "fileBytes",
								   std::to_string( acceptedState.checkpoint.historyBytes +
												  acceptedState.checkpoint.sharedBytes + extra)) ;
	auto	   largeLedger = snapshot ;								// 元待機・予算・groupを維持する合法合成です。
	const auto prototype = largeLedger.requests.begin()->second ;	// 閉鎖済み元requestを複製します。
	// 固定ASCII hashへ区別した4096 requestを生成し、旧source対応数へ加算しません。
	for( std::size_t n = 0U; largeLedger.requests.size() < 4096U; ++n) {
		auto request			= prototype ;	// 元閉鎖・CACHE参照を保持する行です。
		request.control.request = hashOf( "reader-valid-request-" + std::to_string( n)) ;
		largeLedger.requests.emplace( request.control.request, std::move( request)) ;
	}

	const auto large =
		// 全CNG参照を一貫して再結合します。
		rebound( largeLedger, largeInventories, largeSeal) ;
	checkFrame( large, 0U, 8192U, 4096U) ;
	DRIVERCRATE_EXPECT(
		context,
		diagnostic.sharedNames == 68U && diagnostic.segmentNames == 90U &&
			diagnostic.sharedReadCalls == 136U && diagnostic.segmentReadCalls == 180U &&
			diagnostic.finalReadCalls == 158U && diagnostic.sharedBytes > sharedBytes * 2U &&
			diagnostic.segmentBytes > segmentBytes * 2U && diagnostic.sharedBytes <= SHARED_BOUND &&
			diagnostic.segmentBytes <= SEGMENT_BOUND && diagnostic.oldPayloadReads == 0U) ;
	std::cout << "Segment reader semantic cases: " << semanticCases
			  << " validRequests=4096 validInventoryRows=8192 validInventoryShards=16 sharedBytes="
			  << diagnostic.sharedBytes << " segmentBytes=" << diagnostic.segmentBytes << '\n' ;
	largeInventories[1] = replaceSegmentFixtureField( largeInventories[1], "ordinal", "0") ;
	checkFrame( rebound( snapshot, largeInventories, largeSeal), 13U, 0U) ;
	++semanticCases ;
	// 全所有を解放してからdirectoryの実junctionを注入します。
	DRIVERCRATE_EXPECT( context, reopened->close() == 0U) ;
	reopened.reset() ;
	std::size_t junctionCases{} ;	// 初期化停止と実reader停止を区別して出力します。
	// 固定階層の各directoryを一つずつ自作GUID内で一時退避します。
	for( const auto &name :
		{std::wstring( L"current"), std::wstring( L"runs"), std::wstring( L"segments"),
		 oldPrefix.substr( 0U, oldPrefix.size() - 1U), newPrefix.substr( 0U, newPrefix.size() - 1U),
		 oldPrefix + L"current", oldPrefix + L"runs", newPrefix + L"current", newPrefix + L"runs",
		 newPrefix + L"history", newPrefix + L"history/current", newPrefix + L"history/runs"}) {
		const auto path = location / name ;	// 元自作directoryだけです。
		const auto backup =
			// 同GUID内の明示退避先です。
			location.parent_path() / L"reader-junction-original" ;
		const auto before = segmentFixtureImage( path) ;	// 参照先の非変更比較です。
		std::filesystem::rename( segmentFixturePath( path), segmentFixturePath( backup)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::create_directory( segmentFixturePath( path))) ;
		copySegmentFixtureDacl( backup, path) ;
		junctionSegmentFixture( path, backup) ;
		reopened = std::make_unique<LocalCollectorCollectionStore>() ;
		const auto initializationCode =
			// 親preflightを別に記録します。
			reopened->initialize( location, collectionKey) ;
		const auto code = initializationCode == 0U
							  ? inspect()
							  : initializationCode ;	// 失敗した親へreaderを呼びません。
		context.expect( code == 5U && !proof, "segment junction code=" + std::to_string( code),
					   __FILE__, __LINE__) ;
		std::cout << "Segment reader junction: index=" << junctionCases << " code=" << code
				  << " phase=" << (initializationCode == 0U ? "reader" : "initializer") << '\n' ;
		DRIVERCRATE_EXPECT( context, segmentFixtureImage( backup) == before &&
										(GetFileAttributesW( segmentFixturePath( path).c_str()) &
										 FILE_ATTRIBUTE_REPARSE_POINT) != 0U) ;
		reopened.reset() ;
		// Junction nodeだけを外し、参照先を削除せず元directoryへ戻します。
		if( !RemoveDirectoryW( segmentFixturePath( path).c_str())) {
			throw std::runtime_error( "segment fixture junction cleanup") ;
		}

		std::filesystem::rename( segmentFixturePath( backup), segmentFixturePath( path)) ;
		++junctionCases ;
	}

	DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == frames[3]) ;
	std::size_t fileLinkCases{} ;	// 初回file linkと診断後を別に計数します。
	const auto	injectFileLink = [&]( const std::wstring &name, const bool afterCallback) {
		 const auto path = location / name ;	// 自作固定fileだけを退避します。
		 const auto backup =
			 // 同GUID内の明示参照先です。
			 location.parent_path() / L"reader-file-original" ;
		 const auto inject = [&] {
			 std::filesystem::rename( segmentFixturePath( path), segmentFixturePath( backup)) ;
			 // 注入不能を製品reparse拒否の成功として扱いません。
			 if( !CreateSymbolicLinkW( segmentFixturePath( path).c_str(),
									 segmentFixturePath( backup).c_str(),
									 SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
				 throw std::runtime_error( "segment fixture file link") ;
			 }
		 } ; // 同期診断か全所有解放後だけの自作故障です。
		 DWORD code{} ;					// 元保護拒否値です。
		 DWORD initializationCode{} ;	// 親初期化と実readerを分けます。
		 // 生存contextからfileを書き替えず、発行直前の診断だけで注入します。
		 if( afterCallback) {
			 code = LocalCollectorSegmentReader::inspect( *reopened, draft.intentHash, proof,
														 diagnostic, [&] {
															 inject() ;
															 return DWORD{0U} ;
														 }) ;
		 } else {
			 inject() ;
			 reopened			= std::make_unique<LocalCollectorCollectionStore>() ;
			 initializationCode = reopened->initialize( location, collectionKey) ;
			 code				= initializationCode == 0U ? inspect() : initializationCode ;
		 }

		 context.expect( code == 5U && !proof, "segment file link code=" + std::to_string( code),
						__FILE__, __LINE__) ;
		 const auto attributes =
			 // nodeの属性です。
			 GetFileAttributesW( segmentFixturePath( path).c_str()) ;
		 DRIVERCRATE_EXPECT( context, attributes != INVALID_FILE_ATTRIBUTES &&
										 (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0U &&
										 segmentFixtureImage( location) == frames[3]) ;
		 std::cout << "Segment reader file link: index=" << fileLinkCases << " code=" << code
				   << " phase="
				   << (afterCallback			  ? "final"
					   : initializationCode == 0U ? "reader"
												  : "initializer")
				   << " finalReads=" << (initializationCode == 0U ? diagnostic.finalReadCalls : 0U)
				   << '\n' ;
		 // link nodeだけを除去し、参照先の元fileは削除せず戻します。
		 DRIVERCRATE_EXPECT( context, DeleteFileW( segmentFixturePath( path).c_str()) != FALSE) ;
		 std::filesystem::rename( segmentFixturePath( backup), segmentFixturePath( path)) ;
		 // 各初回故障を独立にするため、取得した親を全解放します。
		 if( !afterCallback) {
			 (void)reopened->close() ;
			 reopened.reset() ;
		 }

		 ++fileLinkCases ;
	} ; // 全所有解放または同期診断に限定し、製品による修復と区別します。
	// 全current／carryの意味試験とは別に、各直接scopeの代表fileをreparseへ置換します。
	for( const auto &name :
		{std::wstring( L"current/collection-head-v1.json"),
		 std::wstring( L"current/shared-budget-v1.json"),
		 std::wstring( L"current/shared-groups-v1.json"),
		 std::wstring( L"current/shared-requests-3f.json"), intentName, activationName, sealName,
		 oldPrefix + L"runs/segment-inventory-" + draft.intentHash + L"-00.json",
		 newPrefix + L"current/segment-shared-base-v1.json",
		 newPrefix + L"runs/segment-switch-bootstrap-" + draft.intentHash + L".json",
		 newPrefix + L"runs/segment-switch-image-" + draft.intentHash + L"-00.json",
		 newPrefix + L"runs/segment-switch-image-" + draft.intentHash + L"-41.json", rootName}) {
		injectFileLink( name, false) ;
	}

	reopened = std::make_unique<LocalCollectorCollectionStore>() ;
	DRIVERCRATE_EXPECT( context, reopened->initialize( location, collectionKey) == 0U) ;
	// 診断後の現在三scopeと旧sealの置換も発行前に止めます。
	for( const auto &name : {std::wstring( L"current/collection-head-v1.json"), sealName,
							newPrefix + L"current/segment-shared-base-v1.json", rootName}) {
		injectFileLink( name, true) ;
	}

	DRIVERCRATE_EXPECT( context,
					   reopened->close() == 0U && segmentFixtureImage( location) == frames[3]) ;
	reopened.reset() ;
	std::cout << "Segment reader file links: initial=13 final=4 total=" << fileLinkCases << '\n' ;
	std::vector<wchar_t> cliBuffer( 32768U) ;	// opt-inは同構成の隣のEXEだけに限定します。
	const auto			 cliLength =
		GetEnvironmentVariableW( L"DRIVERCRATE_TEST_LEGACY_COLLECTOR", cliBuffer.data(),
								// 通常OFFの回帰ではprobeを起動しません。
								static_cast<DWORD>( cliBuffer.size())) ;
	// 指定された場合だけ固定binaryを実processとして検査します。
	if( cliLength != 0U) {
		std::vector<wchar_t> moduleBuffer( 32768U) ;	// Native自身の同構成pathです。
		const auto			 moduleLength = GetModuleFileNameW(
			  nullptr, moduleBuffer.data(), static_cast<DWORD>( moduleBuffer.size())) ;	// 元EXEです。
		// 別構成・別programや切れたpathを起動しません。
		if( cliLength >= cliBuffer.size() || moduleLength == 0U ||
		   moduleLength >= moduleBuffer.size()) {
			throw std::runtime_error( "segment CLI module path") ;
		}

		const std::filesystem::path cli(
			// 明示pathです。
			std::wstring( cliBuffer.data(), cliLength)) ;
		const auto expected =
			std::filesystem::path( std::wstring( moduleBuffer.data(), moduleLength)).parent_path() /
			L"DriverCrateCollector.exe" ;	// 同構成だけを許可します。
		// 任意binaryや存在しないcollectorへfallbackしません。
		if( cli != expected || !std::filesystem::is_regular_file( cli)) {
			throw std::runtime_error( "segment CLI executable") ;
		}

		const auto trackedWorkspace = rootFactory() ;	// 例外時も元回収集合へ戻すGUIDです。
		auto	   workspace = trackedWorkspace ;		// 旧path上限の対照後だけ短い同一GUIDへ移します。
		const auto sourceAdr =
			std::filesystem::current_path() /
			L"docs/adr/0209-local-first-recurring-driver-collector.md" ;	// 自作文書です。
		const auto copiedAdr =
			workspace /
			L"docs/adr/0209-local-first-recurring-driver-collector.md" ;	// 存在guardを満たすfixtureです。
		(void)std::filesystem::create_directories( segmentFixturePath( copiedAdr.parent_path())) ;
		(void)std::filesystem::copy_file( sourceAdr, segmentFixturePath( copiedAdr)) ;
		auto manifest = workspace / L"manifest.json" ;	// 正規の公開targetだけです。
		alterSegmentFixture(
			manifest,
			"{\"schema\":\"dc-collector-targets-v1\",\"targets\":[{\"source\":\"INTEL_ETHERNET_WINDOWS11\",\"publicModel\":\"\",\"operatingSystem\":\"Windows 11 64-bit\",\"category\":\"\"}]}") ;
		std::vector<LocalCollectorTarget> targets ;			// manifest拒否をstate拒否へ数えません。
		std::wstring					  manifestHash ;	// 元byteの実CNG指紋です。
		DRIVERCRATE_EXPECT( context, loadLocalCollectorManifest( manifest, targets, manifestHash) &&
										targets.size() == 1U) ;
		auto state =
			workspace / L"work/state" / collectionKey ;	// CLIに許可された直下の既存collectionです。
		(void)std::filesystem::create_directories( segmentFixturePath( state.parent_path())) ;
		std::filesystem::rename( segmentFixturePath( location), segmentFixturePath( state)) ;
		const auto unchanged =
			// mini workspaceでも全元byteを保持します。
			segmentFixtureImage( state) ;
		// manifestの正例を非作成validateで先に実測します。--onceは正例へ使いません。
		const auto absent = workspace / L"work/state/nonexistent-cli-probe" ;	// 作成禁止の正例です。
		const auto positive =
			// 非通信です。
			runSegmentFixtureCli( cli, L"--validate", manifest, absent, workspace) ;
		DRIVERCRATE_EXPECT( context,
						   positive.first == 0U &&
							   positive.second.find( "COLLECTOR_RESULT code=0 state_error=0") !=
								   std::string::npos &&
							   positive.second.find( "targets=1") != std::string::npos &&
							   !std::filesystem::exists( absent)) ;
		auto longest = state / L"current/collection-head-v1.json" ;	// 旧監査が開く実fileです。
		// 旧監査が先に走査する親runsだけの最大pathを元保存像から導出します。
		for( const auto &[name, raw] : unchanged) {
			// 子historyなどの未到達fileを旧path原因へ混ぜません。
			if( name.starts_with( L"runs/") &&
			   (state / name).native().size() > longest.native().size()) {
				longest = state / name ;
			}
		}

		const auto ordinaryAttributes = GetFileAttributesW( longest.c_str()) ;	// 旧DOS表現です。
		const auto ordinaryError	  = GetLastError() ;						// 同じAPIの実失敗を直ちに保持します。
		const auto extendedAttributes =
			// 存在の独立対照です。
			GetFileAttributesW( segmentFixturePath( longest).c_str()) ;
		DRIVERCRATE_EXPECT( context, longest.native().size() >= MAX_PATH &&
										ordinaryAttributes == INVALID_FILE_ATTRIBUTES &&
										ordinaryError == ERROR_PATH_NOT_FOUND &&
										extendedAttributes != INVALID_FILE_ATTRIBUTES) ;
		const auto longControl = runSegmentFixtureCli( cli, L"--validate", manifest, state,
													  workspace) ;	// 同じ長い配置です。
		DRIVERCRATE_EXPECT(
			context, longControl.first == 2U &&
						 longControl.second.find( "COLLECTOR_RESULT code=2 state_error=3") !=
							 std::string::npos &&
						 longControl.second.find( "targets=1") != std::string::npos &&
						 longControl.second.find( "acquired=0 installed=0") != std::string::npos &&
						 segmentFixtureImage( state) == unchanged) ;
		std::cout << "Segment reader CLI long-path control: chars=" << longest.native().size()
				  << " attributesError=" << ordinaryError << " exit=" << longControl.first
				  << " output=" << longControl.second ;
		const auto shortWorkspace =
			// 同じ親の同一GUIDであり、他の領域や固定collectionを使いません。
			workspace.parent_path() /
			workspace.filename().native().substr( std::wstring_view( L"campaign-fixture-").size()) ;
		// 同じ自作GUIDのprefixだけを短くし、collection名・全byte・ACLを保持します。
		std::filesystem::rename( segmentFixturePath( workspace), segmentFixturePath( shortWorkspace)) ;
		workspace = shortWorkspace ;
		manifest  = workspace / L"manifest.json" ;
		state	  = workspace / L"work/state" / collectionKey ;
		const auto shortLongest =
			// 元最大fileの同じ相対名を短いworkspaceへ結合します。
			state / longest.lexically_relative( trackedWorkspace / L"work/state" / collectionKey) ;
		DRIVERCRATE_EXPECT( context, shortLongest.native().size() < MAX_PATH &&
										GetFileAttributesW( shortLongest.c_str()) !=
											INVALID_FILE_ATTRIBUTES &&
										segmentFixtureImage( state) == unchanged) ;
		std::cout << "Segment reader CLI short-path control: chars=" << shortLongest.native().size()
				  << " byteChanges=0\n" ;
		// CLIまたはfixtureの例外でも短い領域を元のGUID回収集合へ戻します。
		try {
			std::size_t cliCases{} ;	// 四実processをAPI分母と分けます。
			// 固定親と深いhistoryを二modeで測り、state errorと入口path拒否を区別します。
			for( const auto command :
				{std::wstring_view( L"--validate"), std::wstring_view( L"--once")}) {
				// 親stateと深いhistoryの実停止位置を一つずつ比較します。
				for( const auto &path : {state, state / (newPrefix + L"history")}) {
					const bool parentPath =
						// 深いpathはcheckedStateRootで先に停止します。
						path == state ;
					const auto result = runSegmentFixtureCli( cli, command, manifest, path,
															 workspace) ;	// 自作拒否状態だけです。
					context.expect(
						result.first == 2U &&
							result.second.find( parentPath
												   ? "COLLECTOR_RESULT code=2 state_error=123"
												   : "COLLECTOR_RESULT code=2 state_error=0") !=
								std::string::npos &&
							result.second.find( parentPath ? "targets=1" : "targets=0") !=
								std::string::npos &&
							result.second.find( "acquired=0 installed=0") != std::string::npos &&
							segmentFixtureImage( state) == unchanged,
						"segment actual CLI index=" + std::to_string( cliCases) +
							" exit=" + std::to_string( result.first) + " output=" + result.second,
						__FILE__, __LINE__) ;
					std::cout << "Segment reader actual CLI: index=" << cliCases
							  << " mode=" << (command == L"--validate" ? "validate" : "once")
							  << " kind=" << (parentPath ? "collection" : "history")
							  << " exit=" << result.first << " output=" << result.second ;
					++cliCases ;
				}
			}

			std::filesystem::rename( segmentFixturePath( state), segmentFixturePath( location)) ;
			DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == frames[3]) ;
			std::cout << "Segment reader actual CLI: positiveValidate=1 refusalProcesses=4\n" ;
		} catch( ...) {
			std::filesystem::rename( segmentFixturePath( workspace),
									segmentFixturePath( trackedWorkspace)) ;
			throw ;
		}

		std::filesystem::rename( segmentFixturePath( workspace),
								segmentFixturePath( trackedWorkspace)) ;
	} else {
		std::cout << "Segment reader actual CLI: disabled explicit opt-in required\n" ;
	}

	// 旧汎用storeと旧監督は、新ROOTを通常modeへ補修・enrollしません。
	for( const auto &path : {location, location / (newPrefix + L"history")}) {
		LocalCollectorStateStore legacy ;					// 元通常入口の独立instanceです。
		const auto	code = legacy.initialize( path, true) ;	// 既存保護状態だけの拒否です。
		const DWORD expected =
			// 親の未知階層とhistory直開きの第一拒否です。
			path == location ? 123U : 13U ;
		context.expect( code == expected, "segment legacy initializer code=" + std::to_string( code),
					   __FILE__, __LINE__) ;
		LocalCollectorRecovery supervisor ;	// 不成立storeからHTTP所有を作りません。
		const auto			   supervisorCode =
			supervisor.initializeProjected( legacy, definition, HTTP_TEST_UTC + 129000U,
										   0U) ;	// 不成立storeの元能力拒否を保持します。
		DRIVERCRATE_EXPECT( context,
						   supervisorCode == 87U && segmentFixtureImage( location) == frames[3]) ;
		std::cout << "Segment reader legacy: kind=" << (path == location ? "collection" : "history")
				  << " initializer=" << code << " expected=" << expected
				  << " supervisor=" << supervisorCode << '\n' ;
	}

	reopened = std::make_unique<LocalCollectorCollectionStore>() ;
	DRIVERCRATE_EXPECT( context, reopened->initialize( location, collectionKey) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> legacyLease ;	// 新ROOTの通常借用を拒否します。
	const auto									legacyBorrowCode =
		// 本番通常入口です。
		reopened->borrowHistorySegment( newKey, false, legacyLease) ;
	context.expect(
		legacyBorrowCode == 13U && !legacyLease && segmentFixtureImage( location) == frames[3],
		"segment legacy borrow code=" + std::to_string( legacyBorrowCode), __FILE__, __LINE__) ;
	std::cout << "Segment reader legacy borrow: code=" << legacyBorrowCode << '\n' ;
	std::cout << "Segment reader remaining probes: semanticCases=" << semanticCases
			  << " junctionCases=" << junctionCases
			  << " legacyInitializerCases=2 legacyBorrowCases=1\n" ;
	const auto oldRootName =
		oldPrefix + L"history/current/campaign-root-v2.json" ;	// 未選択旧ROOTです。
	alterSegmentFixture( location / oldRootName, "{}") ;
	const auto extraOldName =
		oldPrefix + L"runs/unregistered-old-reader.json" ;	// 未選択古い未知名です。
	alterSegmentFixture( location / extraOldName, "{}") ;
	copySegmentFixtureDacl( model, location / extraOldName) ;
	const auto oldAltered = segmentFixtureImage( location) ;	// 未検出範囲を含む元像です。
	{
		const auto handle = CreateFileW(
			segmentFixturePath( location / oldRootName).c_str(), GENERIC_READ, 0U, nullptr,
			OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 読むと32になる未選択fileです。
		// 旧payload read0の実負例を注入できなければ試験を停止します。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "read context old payload fixture") ;
		}

		const std::unique_ptr<void, decltype( &CloseHandle)> locked(
			handle, &CloseHandle) ;	// 最後まで排他です。
		DRIVERCRATE_EXPECT( context, inspect() == 0U && proof && diagnostic.oldPayloadReads == 0U) ;
		proof.reset() ;
	}
	DRIVERCRATE_EXPECT( context, oldAltered == segmentFixtureImage( location)) ;
	alterSegmentFixture( location / oldRootName, frames[3].at( oldRootName)) ;
	DRIVERCRATE_EXPECT( context,
					   std::filesystem::remove( segmentFixturePath( location / extraOldName))) ;
	DRIVERCRATE_EXPECT( context, inspect() == 0U && proof) ;
	reopened.reset() ;
	{
		LocalCollectorCollectionStore competing ;	// 元wrapperなしでもcontextが親lockを保持します。
		DRIVERCRATE_EXPECT( context, competing.initialize( location, collectionKey) == 32U) ;
	}
	proof.reset() ;
	LocalCollectorCollectionStore afterRelease ;	// 最後のcontext解放後だけ同親を取得できます。
	DRIVERCRATE_EXPECT( context, afterRelease.initialize( location, collectionKey) == 0U &&
									afterRelease.close() == 0U &&
									segmentFixtureImage( location) == frames[3]) ;
}

/** @see local_collector_http_tests.h */
void runCollectorSegmentInitialReadCodecTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空collectionです。
	const std::wstring segmentKey( 64U, L'2') ;						// 架空旧区間です。
	const std::wstring nextKey( 64U, L'3') ;						// 架空新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID内の専用領域です。
	LocalCollectorCollectionStore				parent ;			// 最終capture後に元writerを完全解放します。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;				// 唯一旧historyの実能力です。
	DRIVERCRATE_EXPECT( context, parent.initialize( location, collectionKey) == 0U &&
									parent.borrowHistorySegment( segmentKey, true, lease) == 0U &&
									lease && lease->history()) ;
	// 初期化失敗から成功fixtureを作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "recovery codec lease") ;
	}

	auto &store = *lease->history() ;				// 元fake workerと完了保存を結合します。
	CollectorProjectedCampaignIdentity identity ;	// 元公開入力identityです。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// Workerより長い元入力です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でfake workerを起動しません。
	if( !campaign) {
		throw std::runtime_error( "recovery codec campaign") ;
	}

	const auto responsesOwner = std::make_unique<
		std::array<CollectorProjectedResponseBytes, 2U>>() ;	// 固定件数と型を保って所有する。

	auto &responses = *responsesOwner ;	// 元workerの保存応答です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 完了保存後に監督借用を返します。
		DRIVERCRATE_EXPECT(
			context,
			owner.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot =
		// 元実本文です。
		matchingSegmentFixture( context, store, collectionKey, segmentKey) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 元fresh予約です。
	std::size_t												  saved{} ;	// 実保存の検査済み件数です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 予約未発行なら保存byte互換を合格にしません。
	if( !pending) {
		throw std::runtime_error( "recovery codec reservation") ;
	}

	const auto originalDraftOwner =
		std::make_unique<std::remove_cvref_t<decltype( pending->draft())>>(
			// 同じ元値をこのscopeで所有する。
			pending->draft()) ;

	const auto &originalDraft =
		// 元と同じ期間だけ結果を借用する。					// Capability解放後も期待値だけを保持します。
		*originalDraftOwner ;
	const auto begin = originalDraft.intent.inventory.size() + 2U ;	// 新子markerの固定境界です。
	const auto roles = std::vector<CollectorSegmentStorageRole>(
		// 元固定名です。
		pending->roles().begin(), pending->roles().end()) ;
	DRIVERCRATE_EXPECT(
		context,
		LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U && saved == begin &&
			LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 0U &&
			saved == 69U &&
			LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 0U &&
			saved == 1U) ;
	std::array<std::map<std::wstring, std::string>, 4U> frames ;	// 各保存地点の独立所有byteです。
	frames[0] = segmentFixtureImage( location) ;
	// 元head保持記録・登録head・最終headの三地点を実保存からcaptureします。
	for( std::size_t prefix = 1U; prefix <= 3U; ++prefix) {
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads(
										pending, saved,
										[prefix]( const std::size_t current) {
											return current == prefix ? DWORD{1223U} : DWORD{0U} ;
										}) == 1223U &&
										saved == prefix) ;
		frames[prefix] = segmentFixtureImage( location) ;
	}

	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent.close() == 0U && frames[0].size() == 241U &&
									frames[3].size() == 242U) ;
	const auto childPrefix = L"segments/" + nextKey + L"/" ;	// 自作固定新子名だけです。
	const auto activationName =
		L"runs/segment-switch-activation-" + originalDraft.intentHash + L".json" ;	// 元固定名です。
	std::vector<std::string_view> inventoryViews ;									// 全decodeより長く生存する元checkpointです。
	// 元固定旧子roleから全inventoryをordinal順に借用します。
	for( std::size_t n = 1U; n + 1U < begin; ++n) {
		inventoryViews.push_back( frames[3].at( L"segments/" + segmentKey + L"/" + roles[n].name)) ;
	}

	const auto bind = [&]( const std::map<std::wstring, std::string> &frame) {
		CollectorSegmentInitialReadBytes bytes ;	// FrameとinventoryViewsの寿命内だけの借用です。
		bytes.recovery.intent = frame.at( roles[0].name) ;
		bytes.recovery.root =
			frame.at( childPrefix + L"history/current/segment-history-root-v1.json") ;
		bytes.recovery.head	  = frame.at( L"current/collection-head-v1.json") ;
		const auto activation = frame.find( activationName) ;	// 未保存記録は空のままです。
		// 未保存を成功記録へ補完しません。
		if( activation != frame.end()) {
			bytes.recovery.activation = activation->second ;
		}

		// 全66carryと親現在rawを各固定保存名から取得します。
		for( std::size_t n = 0U; n < bytes.currentImages.size(); ++n) {
			bytes.recovery.images[n]		   = frame.at( childPrefix + roles[begin + 1U + n].name) ;
			constexpr std::wstring_view digits = L"0123456789abcdef" ;	// 架空shardの固定小文字です。
			const auto name		   = n == 0U   ? std::wstring( L"current/shared-budget-v1.json")
									 : n == 1U ? std::wstring( L"current/shared-groups-v1.json")
											   : L"current/shared-requests-" +
												 std::wstring( 1U, digits[(n - 2U) / 16U]) +
												 std::wstring( 1U, digits[(n - 2U) % 16U]) +
												 L".json" ;	// 空shardも元rawです。
			bytes.currentImages[n] = frame.at( name) ;
		}

		bytes.base		   = frame.at( childPrefix + roles[begin + 67U].name) ;
		bytes.bootstrap	   = frame.at( childPrefix + roles[begin + 68U].name) ;
		bytes.oldSeal	   = frame.at( L"segments/" + segmentKey + L"/" + roles[begin - 1U].name) ;
		bytes.oldInventory = inventoryViews ;
		return bytes ;
	} ; // 同期呼出しを越えて借用byteを保存しません。
	const auto valid		 = bind( frames[3]) ;	// 全改変試験の元入力です。
	const auto acceptedOwner = std::make_unique<
		CollectorSegmentInitialReadState>() ;									// 同じscopeだけで大きなfixtureを所有する。
	auto	  &accepted = *acceptedOwner ;										// 成功だけの所有値です。
	const auto readCode = decodeCollectorSegmentInitialRead( valid, accepted) ;	// 第一数値です。
	context.expect( readCode == 0U && accepted.recovery.saved == 3U &&
					   accepted.recovery.draft.intent == originalDraft.intent &&
					   accepted.recovery.carried.lastUtcMillis == snapshot.lastUtcMillis &&
					   !accepted.files.empty(),
				   "initial acceptance code=" + std::to_string( readCode), __FILE__, __LINE__) ;
	// 成功fixtureの不成立を後続参照で隠しません。
	if( accepted.files.empty()) {
		throw std::runtime_error( "initial read codec acceptance") ;
	}

	std::uint64_t expectedShared = valid.recovery.head.size() * 2U ;	// 実read計数ではありません。
	std::uint64_t expectedSegment{} ;									// 必要入力だけの独立合算です。
	// 全固定制御rawの元byteを二回分として数えます。
	for( const auto raw : {valid.recovery.intent, valid.recovery.activation, valid.recovery.root,
						  valid.base, valid.bootstrap, valid.oldSeal}) {
		expectedSegment += raw.size() * 2U ;
	}

	// Carryと親現在像の枠を別に比較します。
	for( std::size_t n = 0U; n < valid.currentImages.size(); ++n) {
		expectedShared += valid.currentImages[n].size() * 2U ;
		expectedSegment += valid.recovery.images[n].size() * 2U ;
	}

	// 全inventoryの二回分を新区間側へ数えます。
	for( const auto raw : inventoryViews) {
		expectedSegment += raw.size() * 2U ;
	}

	DRIVERCRATE_EXPECT( context, accepted.sharedInputBytes == expectedShared &&
									accepted.segmentInputBytes == expectedSegment &&
									decodeCollectorSegmentInitialRead( valid, accepted) == 0U &&
									segmentFixtureImage( location) == frames[3]) ;
	const auto reject = [&]( const CollectorSegmentInitialReadBytes &bytes,
							const DWORD								expected = 13U) {
		const auto stateOwner = std::make_unique<std::remove_cvref_t<decltype( accepted)>>(
			accepted) ;	// 同じ元値をこのscopeで所有する。
		auto &state =
			// 元と同じ期間だけ結果を借用する。											// 全失敗で汚染出力を消すことも測ります。
			*stateOwner ;
		const auto code = decodeCollectorSegmentInitialRead( bytes, state) ;	// 第一数値です。
		context.expect( code == expected,
					   "initial read code=" + std::to_string( code) +
						   " expected=" + std::to_string( expected),
					   __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT(
			context,
			state.files.empty() && state.recovery.saved == 0U &&
				state.recovery.oldHeadRaw.empty() && state.recovery.carried.collection.empty() &&
				state.recovery.draft.intentBytes.empty() && state.checkpoint.rootKey.empty() &&
				state.checkpoint.historySeal.empty() && state.checkpoint.sharedSeal.empty() &&
				state.checkpoint.generations == 0U && state.sharedInputBytes == 0U &&
				state.segmentInputBytes == 0U) ;
	} ; // 各候補の借用rawはこの同期呼出し中に生存します。
	// 元head／記録保存／登録headの三地点を暗黙回復なしで拒否します。
	for( std::size_t n = 0U; n < 3U; ++n) {
		reject( bind( frames[n])) ;
	}

	const auto oversized = std::string( 2U * 1024U * 1024U + 1U, 'x') ;	// 一raw超過です。
	// Carryと親現在の全132fieldを欠損・破損・超過で独立反証します。
	for( std::size_t n = 0U; n < 66U; ++n) {
		// 二つのscopeを同じ成功条件へまとめません。
		for( unsigned scope = 0U; scope < 2U; ++scope) {
			const auto bytesOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
				valid) ;	// 同じ元値をこのscopeで所有する。
			auto &bytes =
				*bytesOwner ;	// 元と同じ期間だけ結果を借用する。	// 一fieldだけの改変です。
			auto &field =
				// 元借用です。
				scope == 0U ? bytes.recovery.images[n] : bytes.currentImages[n] ;
			field = {} ;
			reject( bytes) ;
			field = "{}" ;
			reject( bytes) ;
			field = oversized ;
			reject( bytes, 68U) ;
		}
	}

	// 全七制御rawの欠損・破損・外側枠超過を独立に確認します。
	for( std::size_t n = 0U; n < 7U; ++n) {
		const auto bytesOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;				// 同じ元値をこのscopeで所有する。
		auto &bytes = *bytesOwner ;	// 元と同じ期間だけ結果を借用する。	// 元入力を変更しません。
		std::array<std::string_view *, 7U> fields{&bytes.recovery.intent,
												  &bytes.recovery.activation,
												  &bytes.recovery.root,
												  &bytes.recovery.head,
												  &bytes.base,
												  &bytes.bootstrap,
												  &bytes.oldSeal} ;	// 固定用途です。
		*fields[n] = {} ;
		reject( bytes) ;
		*fields[n] = "{}" ;
		reject( bytes) ;
		*fields[n] = oversized ;
		reject( bytes, 68U) ;
	}

	{
		const auto bytesOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &bytes =
			*bytesOwner ;	// 元と同じ期間だけ結果を借用する。	// Shard集合自体の有限枠です。
		bytes.oldInventory = {} ;
		reject( bytes) ;
		std::array<std::string_view, 17U> excessive ;	// 借用だけで17shardを提示します。
		excessive.fill( inventoryViews[0]) ;
		bytes.oldInventory = excessive ;
		reject( bytes, 68U) ;
		std::array<std::string_view, 1U> bad{oversized} ;	// 一inventory rawの超過です。
		bytes.oldInventory = bad ;
		reject( bytes, 68U) ;
		bad[0] = "{}" ;
		reject( bytes) ;
		bad[0] = {} ;
		reject( bytes) ;
	}
	const auto pack = [&]( const std::string_view body) {
		std::wstring hash ;	// 改変本文の独立実CNGです。
		DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( body, hash) == 0) ;
		collector_projected_json::Writer writer( 2U * 1024U * 1024U) ;	// 固定外側枠です。
		writer.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
		writer.text( body) ;
		writer.append( ",\"sha256\":") ;
		writer.wideText( hash) ;
		writer.append( "}") ;
		return writer.take() ;
	} ; // 生成byteはcallerが所有し、CNG失敗を成功へ補完しません。
	const auto bodyOf = []( const std::string_view raw) {
		return winrt::to_string( JsonObject::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
	} ; // 独立fixture readerでだけ解析します。
	const auto replaceField = []( std::string body, const std::string_view key,
								 const std::string_view replacement) {
		const auto prefix	= "\"" + std::string( key) + "\":" ;	// 元順を維持する固定fieldです。
		const auto position = body.find( prefix) ;					// Fixture契約の欠損を隠しません。
		// 不正offsetで製品の拒否結果を作りません。
		if( position == std::string::npos) {
			throw std::runtime_error( "initial read fixture field") ;
		}

		const auto						 start = position + prefix.size() ;	// 元値の先頭です。
		collector_projected_json::Reader reader( body,
												2U * 1024U * 1024U) ;	// 完全objectを先に検査します。
		reader.literal( std::string_view( body).substr( 0U, start)) ;
		const auto original = reader.value() ;	// 全型の元値を借用し、長さだけ使います。
		body.replace( start, original.size(), replacement) ;
		return body ;
	} ; // Canonical順を維持し、一fieldだけの故意な改変に使います。
	const auto hashOf = [&]( const std::string_view bytes) {
		std::wstring hash ;	// 外側でなくcallerが指定した元byteのhashです。
		DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( bytes, hash) == 0) ;
		return hash ;
	} ; // 同期CNG失敗をfixture合格へ読み替えません。
	const auto quote = []( const std::wstring_view hash) {
		return "\"" + winrt::to_string( hash) + "\"" ;
	} ; // 検査済みASCII hashをJSON値にだけ使います。
	const auto originalInventory = bodyOf( inventoryViews[0]) ;	// 元実shardの完全本文です。
	const auto originalSeal		 = bodyOf( valid.oldSeal) ;		// 元実22fieldの順序です。
	const auto checkRebound		 = [&]( const std::vector<std::string> &bodies, std::string seal,
								   const DWORD expected) {
		 std::vector<std::string>	   raw ;		// 再hash後のshard envelopeを所有します。
		 std::vector<std::string_view> views ;		// raw完成後だけ借用します。
		 CollectorSegmentSwitchRequest request ;	// Caller hashは能力ではありません。
		 request.oldSegment	 = originalDraft.intent.oldSegment ;
		 request.newSegment	 = originalDraft.intent.newSegment ;
		 request.oldHead	 = originalDraft.intent.oldHead ;
		 request.oldRoot	 = originalDraft.intent.oldRoot ;
		 request.accepted	 = originalDraft.intent.accepted ;
		 request.observation = {true, true, true, 0U, 0U, false} ;
		 collector_projected_json::Writer hashes( 4096U) ;	// 最大16元hashを同じ順で結合します。
		 hashes.append( "[") ;
		 // 参照とCNGを整合させ、単なる上位hash差替え拒否だけの試験にしません。
		 for( const auto &entry : bodies) {
			 // 先頭以外へ固定delimiterを追加します。
			 if( !request.inventory.empty()) {
				 hashes.append( ",") ;
			 }

			 request.inventory.push_back( hashOf( entry)) ;
			 hashes.wideText( request.inventory.back()) ;
			 raw.push_back( pack( entry)) ;
		 }

		 hashes.append( "]") ;
		 seal				   = replaceField( std::move( seal), "inventory", hashes.view()) ;
		 request.seal		   = hashOf( seal) ;
		 const auto draftOwner = std::make_unique<
				 CollectorSegmentSwitchDraft>() ;	// 同じscopeだけで大きなfixtureを所有する。
		 auto &draft = *draftOwner ;				// 元全carryを変更しない再導出です。
		 DRIVERCRATE_EXPECT(
			 context, prepareCollectorSegmentSwitchDraft( snapshot, snapshot, request, draft) == 0U) ;
		 auto rootBody = bodyOf( valid.recovery.root) ;	// 全17fieldの元ROOTを保持します。
		 rootBody	   = replaceField( std::move( rootBody), "seal", quote( draft.intent.seal)) ;
		 rootBody	   = replaceField( std::move( rootBody), "base", quote( draft.intent.base)) ;
		 rootBody = replaceField( std::move( rootBody), "bootstrap", quote( draft.intent.bootstrap)) ;
		 rootBody = replaceField( std::move( rootBody), "switchIntent", quote( draft.intentHash)) ;
		 auto activationBody = bodyOf( valid.recovery.activation) ;	// 元head rawは変更しません。
		 activationBody = replaceField( std::move( activationBody), "intent", quote( draft.intentHash)) ;
		 activationBody =
			 replaceField( std::move( activationBody), "initialRoot", quote( hashOf( rootBody))) ;
		 activationBody =
			 replaceField( std::move( activationBody), "nextHead", quote( draft.intent.nextHead)) ;
		 const auto intentRaw	  = pack( draft.intentBytes) ;	// 全参照の再結合後だけrawにします。
		 const auto rootRaw		  = pack( rootBody) ;			// 保存は行いません。
		 const auto activationRaw = pack( activationBody) ;		// 元保持記録の固定順です。
		 const auto headRaw		  = pack( draft.nextHead) ;		// 正しい最終headを再導出します。
		 const auto baseRaw		  = pack( draft.base) ;			// 新sealへ結合します。
		 const auto bootstrapRaw  = pack( draft.bootstrap) ;	// 新inventoryへ結合します。
		 const auto sealRaw		  = pack( seal) ;				// 正しいCNGでも意味矛盾を拒否させます。
		 // 所有raw完成後だけ全shardを借用します。
		 for( const auto &entry : raw) {
			 views.push_back( entry) ;
		 }

		 const auto bytesOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			 valid) ;	// 同じ元値をこのscopeで所有する。

		 auto &bytes =
			 *bytesOwner ;	// 元と同じ期間だけ結果を借用する。	// 元全66像と親現在像は保持します。
		 bytes.recovery.intent	   = intentRaw ;
		 bytes.recovery.root	   = rootRaw ;
		 bytes.recovery.activation = activationRaw ;
		 bytes.recovery.head	   = headRaw ;
		 bytes.base				   = baseRaw ;
		 bytes.bootstrap		   = bootstrapRaw ;
		 bytes.oldSeal			   = sealRaw ;
		 bytes.oldInventory		   = views ;
		 // 成功例と拒否例の分母を区別します。
		 if( expected == 0U) {
			 const auto stateOwner = std::make_unique<
					 CollectorSegmentInitialReadState>() ;	// 同じscopeだけで大きなfixtureを所有する。
			 auto &state = *stateOwner ;					// 合成checkpointの値だけです。
			 DRIVERCRATE_EXPECT( context, decodeCollectorSegmentInitialRead( bytes, state) == 0U &&
												 state.files.size() == state.checkpoint.historyFiles +
																		   state.checkpoint.sharedFiles) ;
		 } else {
			 reject( bytes, expected) ;
		 }
	} ; // 全借用rawはこの同期検査より長く生存し、実storeへ保存しません。
	DRIVERCRATE_EXPECT( context, inventoryViews.size() == 1U) ;
	checkRebound( {originalInventory}, originalSeal, 0U) ;
	// 全参照を再hashした後でもsealのidentity／時計／合計矛盾を拒否します。
	for( const auto key : {"collection", "segment", "root", "head", "ledger"}) {
		const auto seal =
			// 一元参照です。
			replaceField( originalSeal, key, quote( std::wstring( 64U, L'0'))) ;
		checkRebound( {originalInventory}, seal, 13U) ;
	}

	// Canonical数値でも元時計／集計へ矛盾する場合は13です。
	for( const auto key :
		{"rootUtc", "inspectedUtc", "historyBytes", "sharedBytes", "fileBytes", "fileCount"}) {
		const auto object = JsonObject::Parse( winrt::to_hstring( originalSeal)) ;	// 独立元数値です。
		const auto number = static_cast<std::uint64_t>(
			// 架空小数なしです。
			object.GetNamedNumber( winrt::to_hstring( key))) ;
		const auto seal =
			// 一数値だけです。
			replaceField( originalSeal, key, std::to_string( number + 1U)) ;
		checkRebound( {originalInventory}, seal, 13U) ;
	}

	// 既存v3と共有鎖の独立した有限件数を超えるcheckpointは68です。
	for( const auto key :
		{"generations", "historyOperations", "cacheCount", "sharedOperations", "sharedFiles"}) {
		const auto number = std::string_view( key) == "sharedOperations" ? 65U
							: std::string_view( key) == "sharedFiles"
								? 257U
								: 301U ;	// それぞれの既存上限一件超過です。
		checkRebound( {originalInventory}, replaceField( originalSeal, key, std::to_string( number)),
					 68U) ;
	}

	// Shardの連続ordinalと元identity／全件数を上位の正しいhashの内側で反証します。
	for( const auto key : {"ordinal", "fileCount", "collection", "segment"}) {
		const auto value = std::string_view( key) == "ordinal" ? std::string( "1")
						   : std::string_view( key) == "fileCount"
							   ? std::string( "1")
							   : quote( std::wstring( 64U, L'0')) ;	// 不整合値です。
		checkRebound( {replaceField( originalInventory, key, value)}, originalSeal, 13U) ;
	}

	// 最初の元親head行だけのscope／path／raw hash／sizeを再hash後に変更します。
	for( const auto &[key, value] : std::vector<std::pair<std::string, std::string>>{
			{"scope", "\"unknown\""},
			{"scope", "\"segment\""},
			{"name", "\"current/../head.json\""},
			{"name", "\"current/Head.json\""},
			{"name", "\"current/head.json.tmp\""},
			{"name", "\"current/other.json\""},
			{"sha256", quote( originalDraft.intent.oldHead)},
			{"bytes", "1"},
			{"bytes", "0"},
			{"bytes", "2097153"}}) {
		checkRebound( {replaceField( originalInventory, key, value)}, originalSeal,
					 key == "bytes" && value == "2097153" ? 68U : 13U) ;
	}

	{
		const auto object =
			// 行集合の独立解析です。
			JsonObject::Parse( winrt::to_hstring( originalInventory)) ;
		const auto rows = object.GetNamedArray( L"files") ;	// 元順を保持するfixture配列です。
		DRIVERCRATE_EXPECT( context, rows.Size() > 2U) ;
		collector_projected_json::Reader reader( originalInventory,
												256U * 1024U) ;				// 元四field行をそのまま借用します。
		const auto start = originalInventory.find( "\"files\":[") + 9U ;	// 配列先頭の後です。
		reader.literal( std::string_view( originalInventory).substr( 0U, start)) ;
		const auto first = std::string( reader.value()) ;	// 元headの一行です。
		reader.literal( ",") ;
		const auto second	 = std::string( reader.value()) ;	// 元次行です。
		const auto duplicate = originalInventory.substr( 0U, start) + first + "," + first +
							   originalInventory.substr( start + first.size() + 1U +
														// 全件数を維持した重複です。
														second.size()) ;
		checkRebound( {duplicate}, originalSeal, 13U) ;
		const auto swapped = originalInventory.substr( 0U, start) + second + "," + first +
							 originalInventory.substr( start + first.size() + 1U +
													  // 群内順序の逆転です。
													  second.size()) ;
		checkRebound( {swapped}, originalSeal, 13U) ;
	}
	// 用途別本文のちょうどと一byte超過を、外側raw枠と区別します。
	// 512／513と16shard8192行を合成checkpointだけで測り、実file数の達成へ数えません。
	for( const auto count : {512U, 513U, 8192U}) {
		auto files = accepted.files ;	// 元head行と元全scopeを保持します。
		// 未読の合成history行を元群の最後へ辞書順に追加します。
		while( files.size() < count) {
			const auto ordinal = files.size() ;	// 固定五桁で順序が逆転しない架空名です。
			files.push_back( {L"history",
							 L"runs/zzz-fixture-" + std::to_wstring( 10000U + ordinal) + L".json",
							 std::wstring( 64U, L'0'), 1U}) ;
		}

		std::vector<std::string> bodies ;	// 全shard本文を所有してから検査します。
		// 既存writerと同じ512行partitionを合成値だけに適用します。
		for( std::size_t first = 0U; first < files.size(); first += 512U) {
			collector_projected_json::Writer writer( 256U * 1024U) ;	// 一shard独立上限です。
			writer.append( "{\"schema\":\"collector-segment-root-inventory-v1\",\"collection\":") ;
			writer.wideText( collectionKey) ;
			writer.append( ",\"segment\":") ;
			writer.wideText( segmentKey) ;
			writer.append( ",\"ordinal\":") ;
			writer.number( bodies.size()) ;
			writer.append( ",\"fileCount\":") ;
			writer.number( files.size()) ;
			writer.append( ",\"files\":[") ;
			// 元scope／名と最後の残行を保持します。
			for( std::size_t n = first; n < std::min( first + 512U, files.size()); ++n) {
				// 先頭以外へ元delimiterを置きます。
				if( n != first) {
					writer.append( ",") ;
				}

				const auto &file = files[n] ;	// 未読rawの登録行だけです。
				writer.append( "{\"scope\":") ;
				writer.wideText( file.scope) ;
				writer.append( ",\"name\":") ;
				writer.wideText( file.name) ;
				writer.append( ",\"bytes\":") ;
				writer.number( file.bytes) ;
				writer.append( ",\"sha256\":") ;
				writer.wideText( file.sha256) ;
				writer.append( "}") ;
			}

			writer.append( "]}") ;
			bodies.push_back( writer.take()) ;
		}

		const auto extra = count - accepted.files.size() ;	// 追加した架空1byte行数です。
		auto	   seal	 = replaceField( originalSeal, "historyFiles",
										// 全集計を再結合します。
										std::to_string( accepted.checkpoint.historyFiles + extra)) ;
		seal			 = replaceField( std::move( seal), "historyBytes",
										std::to_string( accepted.checkpoint.historyBytes + extra)) ;
		seal			 = replaceField( std::move( seal), "fileCount", std::to_string( count)) ;
		seal			 = replaceField( std::move( seal), "fileBytes",
										std::to_string( accepted.checkpoint.historyBytes +
													   accepted.checkpoint.sharedBytes + extra)) ;
		checkRebound( bodies, seal, 0U) ;
		// 複数shardのordinal重複を、全上位hash再結合後にも拒否します。
		if( bodies.size() > 1U) {
			bodies[1U] = replaceField( bodies[1U], "ordinal", "0") ;
			checkRebound( bodies, seal, 13U) ;
		}
	}

	// 用途別本文のちょうどと一byte超過を、外側raw枠と区別します。
	for( unsigned type = 0U; type < 4U; ++type) {
		const auto limit = type == 3U ? 256U * 1024U : 16U * 1024U ;	// 制御三型とinventoryです。
		// 枠内の内容13と枠超過68を別に測ります。
		for( unsigned extra = 0U; extra <= 1U; ++extra) {
			const auto raw		  = pack( std::string( limit + extra, 'x')) ;	// 外側hashは正当です。
			const auto bytesOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
				valid) ;	// 同じ元値をこのscopeで所有する。
			auto &bytes =
				*bytesOwner ;								// 元と同じ期間だけ結果を借用する。										// 元他fieldを保持します。
			std::array<std::string_view, 1U> shard{raw} ;	// 一inventoryだけを変更します。
			// Inventory以外は固定制御用途へ割当てます。
			if( type == 3U) {
				bytes.oldInventory = shard ;
			} else {
				(type == 0U ? bytes.base : type == 1U ? bytes.bootstrap : bytes.oldSeal) = raw ;
			}

			reject( bytes, extra == 0U ? 13U : 68U) ;
		}
	}

	{
		const auto raw		  = std::string( 2U * 1024U * 1024U, 'x') ;	// 個別枠内の合成byteです。
		const auto bytesOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &bytes =
			*bytesOwner ;	// 元と同じ期間だけ結果を借用する。									// 全66像の独立枠で総枠を拡大しません。
		bytes.currentImages.fill( {}) ;
		// 二回分16 MiBの必要入力をちょうど埋めます。
		for( std::size_t n = 0U; n < 3U; ++n) {
			bytes.currentImages[n] = raw ;
		}

		bytes.currentImages[3U] =
			std::string_view( raw).substr( 0U, raw.size() - valid.recovery.head.size()) ;
		reject( bytes) ;
		bytes.currentImages[3U] =
			std::string_view( raw).substr( 0U, bytes.currentImages[3U].size() + 1U) ;
		reject( bytes, 68U) ;
		bytes = valid ;
		bytes.recovery.images.fill( {}) ;
		std::size_t controls{} ;	// 新区間側の二回分の半分だけを先に数えます。
		// 元制御とinventoryを残して総枠を正確に埋めます。
		for( const auto entry :
			{valid.recovery.intent, valid.recovery.activation, valid.recovery.root, valid.base,
			 valid.bootstrap, valid.oldSeal, inventoryViews[0]}) {
			controls += entry.size() ;
		}

		// Carryだけで32 MiBから元制御量を引いた一passを提示します。
		for( std::size_t n = 0U; n < 15U; ++n) {
			bytes.recovery.images[n] = raw ;
		}

		DRIVERCRATE_EXPECT( context, controls < raw.size()) ;
		bytes.recovery.images[15U] = std::string_view( raw).substr( 0U, raw.size() - controls) ;
		reject( bytes) ;
		bytes.recovery.images[15U] =
			std::string_view( raw).substr( 0U, bytes.recovery.images[15U].size() + 1U) ;
		reject( bytes, 68U) ;
	}
	{
		const auto intentOwner =
			std::make_unique<std::remove_cvref_t<decltype( originalDraft.intent)>>(
				originalDraft.intent) ;	// 同じ元値をこのscopeで所有する。
		auto &intent =
			*intentOwner ;	// 元と同じ期間だけ結果を借用する。	// 後続ordinalだけの有限codec反証です。
		intent.ordinal = 2U ;
		std::string body ;	// 別ordinalのcanonical元intentです。
		DRIVERCRATE_EXPECT( context, encodeCollectorSegmentSwitchIntent( intent, body) == 0U) ;
		const auto raw		  = pack( body) ;	// 後続seal集合を検査しない入口は50です。
		const auto bytesOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &bytes =
			*bytesOwner ;	// 元と同じ期間だけ結果を借用する。			// その他のrawは初回のままです。
		bytes.recovery.intent = raw ;
		reject( bytes, 50U) ;
	}
	DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == frames[3]) ;
}
/** @see local_collector_http_tests.h */
void runCollectorSegmentRecoveryCodecTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空collectionです。
	const std::wstring segmentKey( 64U, L'2') ;						// 架空旧区間です。
	const std::wstring nextKey( 64U, L'3') ;						// 架空新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID内の専用領域です。
	LocalCollectorCollectionStore				parent ;			// 最終capture後に元writerを完全解放します。
	std::unique_ptr<LocalCollectorSegmentLease> lease ;				// 唯一旧historyの実能力です。
	DRIVERCRATE_EXPECT( context, parent.initialize( location, collectionKey) == 0U &&
									parent.borrowHistorySegment( segmentKey, true, lease) == 0U &&
									lease && lease->history()) ;
	// 初期化失敗から成功fixtureを作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "recovery codec lease") ;
	}

	auto	  &store		 = *lease->history() ;	// 元fake workerと完了保存を結合します。
	const auto identityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。
	auto &identity = *identityOwner ;			// 元公開入力identityです。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// Workerより長い元入力です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でfake workerを起動しません。
	if( !campaign) {
		throw std::runtime_error( "recovery codec campaign") ;
	}

	const auto responsesOwner = std::make_unique<
		std::array<CollectorProjectedResponseBytes, 2U>>() ;	// 固定件数と型を保って所有する。

	auto &responses = *responsesOwner ;	// 元workerの保存応答です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 完了保存後に監督借用を返します。
		DRIVERCRATE_EXPECT(
			context,
			owner.initializeProjected( store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U &&
				owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot =
		// 元実本文です。
		matchingSegmentFixture( context, store, collectionKey, segmentKey) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 元fresh予約です。
	std::size_t												  saved{} ;	// 実保存の検査済み件数です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 予約未発行なら保存byte互換を合格にしません。
	if( !pending) {
		throw std::runtime_error( "recovery codec reservation") ;
	}

	const auto originalDraftOwner =
		std::make_unique<std::remove_cvref_t<decltype( pending->draft())>>(
			// 同じ元値をこのscopeで所有する。
			pending->draft()) ;

	const auto &originalDraft =
		// 元と同じ期間だけ結果を借用する。					// Capability解放後も期待値だけを保持します。
		*originalDraftOwner ;
	const auto begin = originalDraft.intent.inventory.size() + 2U ;	// 新子markerの固定境界です。
	const auto roles = std::vector<CollectorSegmentStorageRole>(
		// 元固定名です。
		pending->roles().begin(), pending->roles().end()) ;
	DRIVERCRATE_EXPECT(
		context,
		LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U && saved == begin &&
			LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 0U &&
			saved == 69U &&
			LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 0U &&
			saved == 1U) ;
	std::array<std::map<std::wstring, std::string>, 4U> frames ;	// 各保存地点の独立所有byteです。
	frames[0] = segmentFixtureImage( location) ;
	// 元head保持記録・登録head・最終headの三地点を実保存からcaptureします。
	for( std::size_t prefix = 1U; prefix <= 3U; ++prefix) {
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads(
										pending, saved,
										[prefix]( const std::size_t current) {
											return current == prefix ? DWORD{1223U} : DWORD{0U} ;
										}) == 1223U &&
										saved == prefix) ;
		frames[prefix] = segmentFixtureImage( location) ;
	}

	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent.close() == 0U && frames[0].size() == 241U &&
									frames[3].size() == 242U) ;
	const auto childPrefix = L"segments/" + nextKey + L"/" ;	// 自作固定新子名だけです。
	const auto activationName =
		L"runs/segment-switch-activation-" + originalDraft.intentHash + L".json" ;	// 元固定名です。
	const auto bind = [&]( const std::map<std::wstring, std::string> &frame) {
		CollectorSegmentRecoveryBytes bytes ;	// Frame生存中だけの借用です。
		bytes.intent = frame.at( roles[0].name) ;
		bytes.root	 = frame.at( childPrefix + L"history/current/segment-history-root-v1.json") ;
		bytes.head	 = frame.at( L"current/collection-head-v1.json") ;
		const auto activation = frame.find( activationName) ;	// 未保存記録だけ空を許します。
		// 欠損を成功記録へ補完しません。
		if( activation != frame.end()) {
			bytes.activation = activation->second ;
		}

		// 各像は元保存の固定名から取得し、期待hashからrawを生成しません。
		for( std::size_t n = 0U; n < bytes.images.size(); ++n) {
			bytes.images[n] = frame.at( childPrefix + roles[begin + 1U + n].name) ;
		}

		return bytes ;
	} ; // 全capture frameは同期decodeより長く生存します。
	CollectorSharedLedgerBytes expectedBodies ;	// 元共有値全fieldの独立比較です。
	DRIVERCRATE_EXPECT( context, encodeCollectorSharedLedger( snapshot, expectedBodies) == 0U) ;
	// 全四保存状態の出力を元実保存・全台帳byteと照合します。
	for( std::size_t prefix = 0U; prefix < frames.size(); ++prefix) {
		const auto bytes	  = bind( frames[prefix]) ;	// このloopで生存する元frameの借用です。
		const auto stateOwner = std::make_unique<
			CollectorSegmentRecoveryState>() ;	// 同じscopeだけで大きなfixtureを所有する。
		auto &state = *stateOwner ;				// 全結合後だけの値です。
		DRIVERCRATE_EXPECT(
			context, decodeCollectorSegmentRecovery( bytes, state) == 0U && state.saved == prefix &&
						 state.oldHeadRaw == frames[0].at( L"current/collection-head-v1.json") &&
						 state.draft.intent == originalDraft.intent &&
						 state.draft.intentBytes == originalDraft.intentBytes &&
						 state.draft.images == originalDraft.images &&
						 state.draft.nextHead == originalDraft.nextHead &&
						 state.draft.base == originalDraft.base &&
						 state.draft.bootstrap == originalDraft.bootstrap &&
						 state.carried.lastUtcMillis == snapshot.lastUtcMillis &&
						 state.initialRootSha256.size() == 64U) ;
		CollectorSharedLedgerBytes actualBodies ;	// 予算・待機・CACHEの全本文比較です。
		DRIVERCRATE_EXPECT( context,
						   encodeCollectorSharedLedger( state.carried, actualBodies) == 0U &&
							   actualBodies.budget == expectedBodies.budget &&
							   actualBodies.groups == expectedBodies.groups &&
							   actualBodies.requests == expectedBodies.requests) ;
		DRIVERCRATE_EXPECT( context, decodeCollectorSegmentRecovery( bytes, state) == 0U &&
										state.saved == prefix) ;
	}

	const auto valid	= bind( frames[3]) ;	// 全改変試験より長く生存する元正当な入力です。
	const auto rejected = [&]( const CollectorSegmentRecoveryBytes &bytes,
							  const DWORD						   expected = 13U) {
		const auto stateOwner = std::make_unique<
			CollectorSegmentRecoveryState>() ;			// 同じscopeだけで大きなfixtureを所有する。
		auto &state					  = *stateOwner ;	// 失敗時の全クリアを確認する汚染出力です。
		state.saved					  = 99U ;
		state.oldHeadRaw			  = "old" ;
		state.initialRootSha256		  = L"old" ;
		state.draft.intent.collection = L"old" ;
		state.draft.base			  = "old" ;
		state.draft.bootstrap		  = "old" ;
		state.draft.nextHead		  = "old" ;
		state.draft.intentBytes		  = "old" ;
		state.draft.intentHash		  = L"old" ;
		state.draft.images.fill( L"old") ;
		state.carried.collection = L"old" ;
		DRIVERCRATE_EXPECT( context, decodeCollectorSegmentRecovery( bytes, state) == expected) ;
		DRIVERCRATE_EXPECT(
			context, state.saved == 0U && state.oldHeadRaw.empty() &&
						 state.initialRootSha256.empty() && state.draft.intent.collection.empty() &&
						 state.draft.intentBytes.empty() && state.draft.base.empty() &&
						 state.draft.bootstrap.empty() && state.draft.nextHead.empty() &&
						 state.draft.intentHash.empty() &&
						 std::all_of( state.draft.images.begin(), state.draft.images.end(),
									 []( const auto &hash) { return hash.empty() ; }) &&
						 state.carried.collection.empty() && state.carried.requests.empty() &&
						 state.carried.groups.empty()) ;
	} ; // Candidateの借用byteはこの同期呼出しより長く生存します。
	// 全66像それぞれの破損と欠損を独立に拒否します。
	for( std::size_t n = 0U; n < valid.images.size(); ++n) {
		const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &candidate =
			*candidateOwner ;	// 元と同じ期間だけ結果を借用する。	// 元入力を変更しない一像改変です。
		candidate.images[n] = "{}" ;
		rejected( candidate) ;
		candidate.images[n] = {} ;
		rejected( candidate) ;
	}

	const auto oversized = std::string( 2U * 1024U * 1024U + 1U, 'x') ;	// 一rawの超過入力です。
	// 全四制御rawの破損・欠損・外側超過とcanonical末尾を確認します。
	for( std::size_t n = 0U; n < 4U; ++n) {
		const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &candidate =
			*candidateOwner ;	// 元と同じ期間だけ結果を借用する。	// 変更する一制御rawだけの借用です。
		std::array<std::string_view *, 4U> fields{&candidate.intent, &candidate.activation,
												  &candidate.root,
												  &candidate.head} ;	// 固定四fieldです。
		*fields[n] = "{}" ;
		rejected( candidate) ;
		*fields[n] = {} ;
		rejected( candidate) ;
		*fields[n] = oversized ;
		rejected( candidate, 68U) ;
		const auto trailing = std::string( *std::array<const std::string_view *, 4U>{
								  &valid.intent, &valid.activation, &valid.root, &valid.head}[n]) +
							  " " ;	// 余分な末尾です。
		*fields[n] = trailing ;
		rejected( candidate) ;
	}

	const auto repack = [&]( const std::string_view body) {
		std::wstring hash ;	// 改変した元本文の独立実CNGです。
		DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( body, hash) == 0) ;
		collector_projected_json::Writer writer( 2U * 1024U * 1024U) ;	// 元外側の有限枠です。
		writer.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
		writer.text( body) ;
		writer.append( ",\"sha256\":") ;
		writer.wideText( hash) ;
		writer.append( "}") ;
		return writer.take() ;
	} ; // 同期呼出し中だけcontextを借用し、返したrawをcallerが所有します。
	const auto bodyOf = []( const std::string_view raw) {
		return winrt::to_string( JsonObject::Parse( winrt::to_hstring( raw)).GetNamedString( L"body")) ;
	} ; // 独立WinRT readerをfixtureの解析にだけ使います。
	// 各制御rawの本文枠をちょうど／一byte超過で分け、外側枠へ流用しません。
	for( std::size_t n = 0U; n < 4U; ++n) {
		const auto limit = n == 0U || n == 2U ? 16U * 1024U : 256U * 1024U ;	// 用途別本文枠です。
		// 枠内の不正本文13と、枠超過68の第一分類を独立に検査します。
		for( std::size_t extra = 0U; extra <= 1U; ++extra) {
			const auto body =
				// 字句不正と容量超過を区別する合成本文です。
				std::string( limit + extra, 'x') ;
			const auto raw			  = repack( body) ;	// 外側CNGは正当です。
			const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
				valid) ;	// 同じ元値をこのscopeで所有する。
			auto &candidate =
				*candidateOwner ;	// 元と同じ期間だけ結果を借用する。			// 元全66像は保持します。
			std::array<std::string_view *, 4U> fields{&candidate.intent, &candidate.activation,
													  &candidate.root,
													  &candidate.head} ;	// 固定四用途です。
			*fields[n] = raw ;
			rejected( candidate, extra == 0U ? 13U : 68U) ;
		}
	}

	{
		const auto originalOwner = std::make_unique<
			CollectorSegmentRecoveryState>() ;	// 同じscopeだけで大きなfixtureを所有する。
		auto &original = *originalOwner ;		// 元参照を独立decodeで取得します。
		DRIVERCRATE_EXPECT( context, decodeCollectorSegmentRecovery( valid, original) == 0U) ;
		// 元head rawの独立128 KiB枠をactivationの256 KiB枠へ流用しません。
		for( std::size_t extra = 0U; extra <= 1U; ++extra) {
			collector_projected_json::Writer record( 256U *
													1024U) ;	// 元七fieldを正しい順で保持します。
			record.append( "{\"schema\":\"collector-segment-switch-activation-v1\",\"collection\":") ;
			record.wideText( originalDraft.intent.collection) ;
			record.append( ",\"intent\":") ;
			record.wideText( originalDraft.intentHash) ;
			record.append( ",\"oldHead\":") ;
			record.wideText( originalDraft.intent.oldHead) ;
			record.append( ",\"oldHeadRaw\":") ;
			record.text( std::string( 128U * 1024U + extra, 'x')) ;
			record.append( ",\"initialRoot\":") ;
			record.wideText( original.initialRootSha256) ;
			record.append( ",\"nextHead\":") ;
			record.wideText( originalDraft.intent.nextHead) ;
			record.append( "}") ;
			const auto raw			  = repack( record.take()) ;	// 外側と他の参照は正当です。
			const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
				valid) ;	// 同じ元値をこのscopeで所有する。
			auto &candidate =
				*candidateOwner ;	// 元と同じ期間だけ結果を借用する。					// 借用はrawの寿命内です。
			candidate.activation = raw ;
			rejected( candidate, extra == 0U ? 13U : 68U) ;
		}
	}
	// 外側hashを正しく再計算した三型の参照差し替えを拒否します。
	for( std::size_t type = 0U; type < 3U; ++type) {
		const auto original = bodyOf( type == 0U	  ? valid.intent
									 : type == 1U ? valid.root
												  : valid.activation) ;	// 元実本文です。
		// 三型で共通するcollectionと固有のhash参照を独立に変えます。
		for( const auto field :
			{std::string_view( "collection"), type == 0U	  ? std::string_view( "ledger")
											 : type == 1U ? std::string_view( "switchIntent")
														  : std::string_view( "initialRoot")}) {
			auto	   body	  = original ;											// 一fieldだけの故意な改変です。
			const auto offset = body.find( "\"" + std::string( field) + "\":\"") ;	// 固定値位置です。
			DRIVERCRATE_EXPECT( context, offset != std::string::npos) ;
			// Fixture欠損で不正indexを参照しません。
			if( offset == std::string::npos) {
				throw std::runtime_error( "recovery codec field") ;
			}

			const auto position		  = offset + field.size() + 4U ;	// Hash先頭の一文字です。
			body[position]			  = body[position] == '0' ? '1' : '0' ;
			const auto raw			  = repack( body) ;	// 正しいCNGの偽本文です。
			const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
				valid) ;	// 同じ元値をこのscopeで所有する。
			auto &candidate =
				*candidateOwner ;	// 元と同じ期間だけ結果を借用する。			// 元全像を保持した一参照差し替えです。
			(type == 0U	  ? candidate.intent
			 : type == 1U ? candidate.root
						  : candidate.activation) = raw ;
			rejected( candidate) ;
		}
	}

	// ROOT末尾の三fieldを正しいCNGで変更しても初期ROOTと扱いません。
	for( const auto replacement :
		{std::string_view( "\"generations\":[{}]"), std::string_view( "\"operations\":[{}]"),
		 std::string_view( "\"active\":false")}) {
		auto	   body		= bodyOf( valid.root) ;						// 元ROOTだけの改変です。
		const auto fieldEnd = replacement.find( ':') ;					// 元固定field名の終端です。
		const auto field	= replacement.substr( 0U, fieldEnd + 1U) ;	// 元fieldを省略しません。
		const auto original =
			// 元初期末尾です。
			std::string( field) + (field == "\"active\":" ? "null" : "[]") ;
		const auto offset = body.find( original) ;	// 固定末尾の一箇所です。
		DRIVERCRATE_EXPECT( context, offset != std::string::npos) ;
		// Fixture誤りを製品合格へ読み替えません。
		if( offset == std::string::npos) {
			throw std::runtime_error( "recovery codec root tail") ;
		}

		body.replace( offset, original.size(), replacement) ;
		const auto raw			  = repack( body) ;	// 正しい外側hashへ戻します。
		const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &candidate =
			*candidateOwner ;	// 元と同じ期間だけ結果を借用する。			// 借用はrawの寿命内だけです。
		candidate.root = raw ;
		rejected( candidate) ;
	}

	{
		const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &candidate =
			*candidateOwner ;	// 元と同じ期間だけ結果を借用する。	// 空shardを含むordinal順を保持する必須関係です。
		std::swap( candidate.images[0], candidate.images[1]) ;
		rejected( candidate) ;
		candidate			 = valid ;
		candidate.images[65] = oversized ;
		rejected( candidate, 68U) ;
		const auto body		= std::string( 768U * 1024U + 1U, 'x') ;	// 一像の本文超過です。
		const auto raw		= repack( body) ;							// 外側2 MiBは超えません。
		candidate			= valid ;
		candidate.images[0] = raw ;
		rejected( candidate, 68U) ;
	}
	{
		const auto intentOwner =
			std::make_unique<std::remove_cvref_t<decltype( originalDraft.intent)>>(
				originalDraft.intent) ;	// 同じ元値をこのscopeで所有する。
		auto &intent =
			*intentOwner ;	// 元と同じ期間だけ結果を借用する。	// 後続ordinalを現行decoderの成功にしません。
		intent.ordinal = 2U ;
		std::string body ;	// 元型付きcodecの正当な後続intentです。
		DRIVERCRATE_EXPECT( context, encodeCollectorSegmentSwitchIntent( intent, body) == 0U) ;
		const auto raw			  = repack( body) ;	// 第一非対応50を検査します。
		const auto candidateOwner = std::make_unique<std::remove_cvref_t<decltype( valid)>>(
			valid) ;	// 同じ元値をこのscopeで所有する。
		auto &candidate =
			*candidateOwner ;	// 元と同じ期間だけ結果を借用する。			// 他のfieldは元実保存のままです。
		candidate.intent = raw ;
		rejected( candidate, 50U) ;
	}
	DRIVERCRATE_EXPECT( context, segmentFixtureImage( location) == frames[3]) ;
}
/** @see local_collector_http_tests.h */
void runCollectorParentHeadStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空の親identityです。
	const std::wstring segmentKey( 64U, L'2') ;						// 同親旧子です。
	const std::wstring nextKey( 64U, L'3') ;						// 未存在の新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID領域です。
	auto			   parent =
		std::make_unique<LocalCollectorCollectionStore>() ;	// Wrapper解放を独立検査します。
	DRIVERCRATE_EXPECT( context, parent->initialize( location, collectionKey) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 唯一旧子のhistory付き能力です。
	DRIVERCRATE_EXPECT( context, parent->borrowHistorySegment( segmentKey, true, lease) == 0U) ;
	// 欠測したfixtureから切替保持の成功を作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "storage fixture lease") ;
	}

	auto &store = *lease->history() ;				// Reservationが後でも強所有する元historyです。
	CollectorProjectedCampaignIdentity identity ;	// 元公開契約の再導出です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// 偽workerより長い所有です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でnative factoryを呼びません。
	if( !campaign) {
		throw std::runtime_error( "storage fixture input") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実worker／偽HTTPの元保存です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 最終完了後に監督借用を返します。
		DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot = matchingSegmentFixture(
		context, store, collectionKey, segmentKey) ;	// 新encoderではなく元保存本文から作ります。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( *parent, *lease, snapshot) == 0U) ;
	const auto	baseline = segmentFixtureImage( location) ;	// 新子の作成も禁止する元全byteです。
	std::size_t saved	 = 99U ;							// 新子保存の失敗出力です。
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads( {}, saved) == 87U &&
									saved == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 唯一の元fresh能力です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 元fixtureの不成立から新子を作りません。
	if( !pending) {
		throw std::runtime_error( "parent head fixture") ;
	}

	const auto begin	= pending->draft().intent.inventory.size() + 2U ;	// 旧準備の固定境界です。
	const auto newRoot	= location / L"segments" / nextKey ;				// 同じ自作新子の保護領域です。
	const auto rootName = L"segments/" + nextKey +
						  L"/history/current/segment-history-root-v1.json" ;	// 元全像の一名です。
	const auto headPath = location / L"current/collection-head-v1.json" ;		// 置換を許す一headです。
	const auto activationName = L"runs/segment-switch-activation-" + pending->draft().intentHash +
								L".json" ;										// 元intentだけの名です。
	const auto activationPath = location / activationName ;						// このGUID領域だけの固定記録です。
	const auto oldBudget	  = location / L"current/shared-budget-v1.json" ;	// 保持する元予算です。
	DRIVERCRATE_EXPECT( context, begin == 3U && baseline.size() == 168U) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveParentHeads( pending, saved) == 13U &&
						   saved == 0U && baseline == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U &&
						   saved == begin) ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 0U &&
					 saved == 69U) ;
	const auto withoutRoot = segmentFixtureImage( location) ;	// ROOT欠損では親へ保存しません。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveParentHeads( pending, saved) == 13U &&
						   saved == 0U && withoutRoot == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 0U &&
						   saved == 1U) ;
	const auto prepared = segmentFixtureImage( location) ;	// 元headと全準備・ROOTの独立期待像です。
	DRIVERCRATE_EXPECT( context, prepared.size() == 241U &&
									prepared.at( L"current/collection-head-v1.json") ==
										baseline.at( L"current/collection-head-v1.json")) ;
	// 全準備済み241rawを一件ずつ改変し、親head保存による補完を拒否します。
	for( const auto &[name, raw] : prepared) {
		const auto target = location / name ;	// このGUID内の既存一fileだけです。
		alterSegmentFixture( target, "{}") ;
		const auto changed = segmentFixtureImage( location) ;	// 故意な改変を保持します。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveParentHeads( pending, saved) == 13U &&
							   saved == 0U && changed == segmentFixtureImage( location) &&
							   !std::filesystem::exists( segmentFixturePath( activationPath))) ;
		alterSegmentFixture( target, raw) ;
	}

	auto clone = pending ;	// 元wrapper／leaseを解放した後も元全handleを保持します。
	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent->close() == 170U) ;
	parent.reset() ;
	std::string activationRaw ;	// 独立field検査済みの固定記録です。
	// 三保存地点それぞれで三診断停止を測り、同じ生存予約から不足分だけ再開します。
	for( std::size_t stopAt = 1U; stopAt <= 3U; ++stopAt) {
		// OOM／その他例外／数値停止を同じ各地点へ独立に注入します。
		for( std::size_t mode = 0U; mode < 3U; ++mode) {
			std::size_t callbacks{} ;	// この初回保存で通知した実地点数です。
			const auto	code = LocalCollectorSegmentStorage::saveParentHeads(
				 clone, saved, [&]( const std::size_t prefix) -> DWORD {
					 ++callbacks ;
					 DRIVERCRATE_EXPECT( context, prefix == callbacks && prefix <= stopAt) ;
					 std::size_t nested = 99U ;	// 診断再入の失敗出力です。
					 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads(
													 clone, nested) == 170U &&
													 nested == 0U) ;
					 DRIVERCRATE_EXPECT( context,
										LocalCollectorSegmentStorage::saveInitialHistoryRoot(
											clone, nested) == 170U &&
											nested == 0U) ;
					 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::savePreparation(
													 clone, nested) == 170U &&
													 nested == 0U) ;
					 saved = std::numeric_limits<std::size_t>::max() ;
					 // 元停止地点より前は確定値だけを保持して次へ進みます。
					 if( prefix < stopAt) {
						 return ERROR_SUCCESS ;
					 }

					 // 診断確保失敗を保存成功へ読み替えません。
					 if( mode == 0U) {
						 throw std::bad_alloc() ;
					 }

					 // 他の診断例外も実保存件数を保持します。
					 if( mode == 1U) {
						 throw std::runtime_error( "intentional parent head checkpoint") ;
					 }

					 return ERROR_CANCELLED ;
				 }) ; // Cloneを同期入口も強所有し、caller出力を内部添字に使いません。
			DRIVERCRATE_EXPECT( context, code == (mode == 0U	  ? 8U
												 : mode == 1U ? 13U
															  : 1223U) &&
											saved == stopAt && callbacks == stopAt) ;
			const auto actual = segmentFixtureImage( location) ;	// 診断停止後の全実像です。
			const auto raw	  = actual.at( activationName) ;		// 独立検査する元head保持記録です。
			// 初回実保存だけを独立JSONとCNGで固定七fieldへ結合します。
			if( stopAt == 1U && mode == 0U) {
				activationRaw = raw ;
				const auto envelope =
					// 独立外側readerです。
					JsonObject::Parse( winrt::to_hstring( raw)) ;
				const auto body =
					// 同じ元本文です。
					winrt::to_string( envelope.GetNamedString( L"body")) ;
				const auto record =
					// 独立field集合です。
					JsonObject::Parse( winrt::to_hstring( body)) ;
				const auto rootEnvelope =
					// 元ROOTだけです。
					JsonObject::Parse( winrt::to_hstring( prepared.at( rootName))) ;
				const auto rootBody =
					// 元ROOT本文です。
					winrt::to_string( rootEnvelope.GetNamedString( L"body")) ;
				std::wstring hash ;		// 記録本文の実CNG指紋です。
				std::wstring rootHash ;	// ROOT本文の独立実CNG指紋です。
				DRIVERCRATE_EXPECT( context,
								   computeCollectorMetadataSha256( body, hash) == 0 &&
									   envelope.GetNamedString( L"sha256") == hash &&
									   computeCollectorMetadataSha256( rootBody, rootHash) == 0 &&
									   record.Size() == 7U) ;
				DRIVERCRATE_EXPECT(
					context,
					record.GetNamedString( L"schema") == L"collector-segment-switch-activation-v1" &&
						record.GetNamedString( L"collection") == collectionKey &&
						record.GetNamedString( L"intent") == clone->draft().intentHash &&
						record.GetNamedString( L"oldHead") == clone->draft().intent.oldHead &&
						record.GetNamedString( L"oldHeadRaw") ==
							winrt::to_hstring( baseline.at( L"current/collection-head-v1.json")) &&
						record.GetNamedString( L"initialRoot") == rootHash &&
						record.GetNamedString( L"nextHead") == clone->draft().intent.nextHead) ;
			}

			auto expected = prepared ;	// 元全byteのうち一headと新記録だけが変化します。
			expected.emplace( activationName, activationRaw) ;
			// 登録または最終headの実停止状態だけを反映します。
			if( stopAt >= 2U) {
				expected[L"current/collection-head-v1.json"] =
					clone->roles()[begin + 67U + stopAt].raw ;
			}

			DRIVERCRATE_EXPECT( context,
							   raw == activationRaw && actual == expected && actual.size() == 242U) ;
			callbacks = 0U ;
			DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads(
											clone, saved,
											[&]( const std::size_t prefix) {
												++callbacks ;
												DRIVERCRATE_EXPECT( context,
																   prefix == stopAt + callbacks) ;
												return ERROR_SUCCESS ;
											}) == 0U &&
											saved == 3U && callbacks == 3U - stopAt) ;
			expected[L"current/collection-head-v1.json"] = clone->roles()[begin + 70U].raw ;
			DRIVERCRATE_EXPECT( context, expected == segmentFixtureImage( location)) ;
			callbacks = 0U ;
			DRIVERCRATE_EXPECT(
				context, LocalCollectorSegmentStorage::saveParentHeads( clone, saved,
																	   [&]( const std::size_t) {
																		   ++callbacks ;
																		   return ERROR_SUCCESS ;
																	   }) == 0U &&
							 saved == 3U && callbacks == 0U &&
							 expected == segmentFixtureImage( location)) ;
			// 次の自作故障窓だけを元全準備状態へ戻し、利用者fileは触りません。
			alterSegmentFixture( headPath, baseline.at( L"current/collection-head-v1.json")) ;
			DRIVERCRATE_EXPECT( context,
							   std::filesystem::remove( segmentFixturePath( activationPath))) ;
			DRIVERCRATE_EXPECT( context, prepared == segmentFixtureImage( location)) ;
		}
	}

	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 0U &&
									saved == 3U) ;
	const auto committed = segmentFixtureImage( location) ;	// 最終headと元保持記録の完全期待像です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveInitialHistoryRoot( clone, saved) == 13U &&
						   saved == 0U && committed == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( clone, saved) == 13U &&
					 saved == 0U && committed == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::savePreparation( clone, saved) == 13U &&
						   saved == 0U && committed == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( activationPath))) ;
	const auto missingActivation =
		// 記録なしの最終headを拒否します。
		segmentFixtureImage( location) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 13U &&
						   saved == 0U && missingActivation == segmentFixtureImage( location)) ;
	alterSegmentFixture( activationPath, activationRaw) ;
	copySegmentFixtureDacl( oldBudget, activationPath) ;
	// 完了後も各scopeの選択した未知名を非変更で拒否します。
	for( const auto &target :
		{location / L"runs/unregistered-head.json", newRoot / L"current/unregistered-head.json",
		 newRoot / L"history/runs/unregistered-head.json"}) {
		alterSegmentFixture( target, "{}") ;
		copySegmentFixtureDacl( oldBudget, target) ;
		const auto changed = segmentFixtureImage( location) ;	// 未登録名を保持する実像です。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 13U &&
							   saved == 0U && changed == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( target))) ;
	}

	// head／記録／ROOTのprotected readで元共有拒否32を維持します。
	for( const auto &target : {headPath, activationPath, location / rootName}) {
		const auto handle = CreateFileW( segmentFixturePath( target).c_str(), GENERIC_READ, 0U,
										nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
										nullptr) ;	// 故障注入だけの一handleです。
		// 故障注入不成立をAPI成功として数えません。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "parent head sharing fixture") ;
		}

		const std::unique_ptr<void, decltype( &CloseHandle)> locked(
			handle, &CloseHandle) ;	// 各窓で必ず返します。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 32U &&
							   saved == 0U) ;
	}

	alterSegmentFixture( activationPath, "{}") ;
	const auto corruptActivation = segmentFixtureImage( location) ;	// 別記録を修復しません。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 13U &&
						   saved == 0U && corruptActivation == segmentFixtureImage( location)) ;
	alterSegmentFixture( activationPath, activationRaw) ;
	const auto originalEnvelope =
		// 元正当な記録です。
		JsonObject::Parse( winrt::to_hstring( activationRaw)) ;
	const auto originalBody =
		// 改変対象の元本文です。
		winrt::to_string( originalEnvelope.GetNamedString( L"body")) ;
	// 正しい外側CNGでもROOT／次headの参照違いを受理しません。
	for( const auto field : {std::string_view( "initialRoot"), std::string_view( "nextHead")}) {
		auto	   body = originalBody ;	// 一fieldだけを故意に改変します。
		const auto offset =
			// 固定field位置だけです。
			body.find( "\"" + std::string( field) + "\":\"") ;
		DRIVERCRATE_EXPECT( context, offset != std::string::npos) ;
		const auto value = offset + field.size() + 4U ;	// 最初のhash文字位置です。
		body[value]		 = body[value] == '0' ? '1' : '0' ;
		std::wstring hash ;	// 偽本文の実CNGです。
		DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( body, hash) == 0) ;
		collector_projected_json::Writer forged( 2U * 1024U * 1024U) ;	// 同じ外側上限です。
		forged.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
		forged.text( body) ;
		forged.append( ",\"sha256\":") ;
		forged.wideText( hash) ;
		forged.append( "}") ;
		alterSegmentFixture( activationPath, forged.take()) ;
		const auto changed = segmentFixtureImage( location) ;	// 再hashされた参照違いを保持します。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 13U &&
							   saved == 0U && changed == segmentFixtureImage( location)) ;
		alterSegmentFixture( activationPath, activationRaw) ;
	}

	alterSegmentFixture( headPath, "{}") ;
	const auto wrongHead = segmentFixtureImage( location) ;	// 記録が正しくても別headを修復しません。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 13U &&
						   saved == 0U && wrongHead == segmentFixtureImage( location)) ;
	alterSegmentFixture( headPath, committed.at( L"current/collection-head-v1.json")) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( activationPath))) ;
	alterSegmentFixture( headPath, baseline.at( L"current/collection-head-v1.json")) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads(
									clone, saved,
									[&]( const std::size_t prefix) {
										// 最終診断後にも元予算の改変を検出します。
										if( prefix == 3U) {
											alterSegmentFixture( oldBudget, "{}") ;
										}

										saved = std::numeric_limits<std::size_t>::max() ;
										return ERROR_SUCCESS ;
									}) == 13U &&
									saved == 3U) ;
	auto changedAfterSave = committed ;	// 一予算の故意な改変だけを反映します。
	changedAfterSave[L"current/shared-budget-v1.json"] = "{}" ;
	DRIVERCRATE_EXPECT( context, changedAfterSave == segmentFixtureImage( location)) ;
	alterSegmentFixture( oldBudget, baseline.at( L"current/shared-budget-v1.json")) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveParentHeads( clone, saved) == 0U &&
									saved == 3U && committed == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( activationPath))) ;
	alterSegmentFixture( headPath, baseline.at( L"current/collection-head-v1.json")) ;
	DRIVERCRATE_EXPECT(
		context,
		LocalCollectorSegmentStorage::saveParentHeads(
			clone, saved,
			[&]( const std::size_t prefix) {
				// 最初の記録保存後にcallerの最後の所有者を返します。
				if( prefix == 1U) {
					clone.reset() ;
					LocalCollectorCollectionStore contender ;	// 同期入口だけが元親lockを保持します。
					DRIVERCRATE_EXPECT( context,
									   contender.initialize( location, collectionKey) != 0U) ;
				}

				saved = std::numeric_limits<std::size_t>::max() ;
				return ERROR_SUCCESS ;
			}) == 0U &&
			saved == 3U && !clone && committed == segmentFixtureImage( location)) ;
	LocalCollectorCollectionStore reopened ;	// 元全能力解放後の別process相当です。
	DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U &&
									reopened.borrowHistorySegment( segmentKey, false, lease) == 0U &&
									lease) ;
	// 再初期化が不成立の場合も無効なleaseを検査入口へ渡しません。
	if( !lease) {
		throw std::runtime_error( "parent head reopen fixture") ;
	}

	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( reopened, *lease, definition.sources,
															 nextKey, utc, pending) == 13U &&
						   !pending && committed == segmentFixtureImage( location)) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, reopened.borrowHistorySegment( nextKey, false, lease) == 13U &&
									!lease && committed == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
}

/** @see local_collector_http_tests.h */
void runCollectorInitialRootStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空の親identityです。
	const std::wstring segmentKey( 64U, L'2') ;						// 同親旧子です。
	const std::wstring nextKey( 64U, L'3') ;						// 未存在の新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID領域です。
	auto			   parent =
		std::make_unique<LocalCollectorCollectionStore>() ;	// Wrapper解放を独立検査します。
	DRIVERCRATE_EXPECT( context, parent->initialize( location, collectionKey) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 唯一旧子のhistory付き能力です。
	DRIVERCRATE_EXPECT( context, parent->borrowHistorySegment( segmentKey, true, lease) == 0U) ;
	// 欠測したfixtureから切替保持の成功を作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "storage fixture lease") ;
	}

	auto &store = *lease->history() ;				// Reservationが後でも強所有する元historyです。
	CollectorProjectedCampaignIdentity identity ;	// 元公開契約の再導出です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// 偽workerより長い所有です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でnative factoryを呼びません。
	if( !campaign) {
		throw std::runtime_error( "storage fixture input") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実worker／偽HTTPの元保存です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 最終完了後に監督借用を返します。
		DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot = matchingSegmentFixture(
		context, store, collectionKey, segmentKey) ;	// 新encoderではなく元保存本文から作ります。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( *parent, *lease, snapshot) == 0U) ;
	const auto	baseline = segmentFixtureImage( location) ;	// 新子の作成も禁止する元全byteです。
	std::size_t saved	 = 99U ;							// 新子保存の失敗出力です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveInitialHistoryRoot( {}, saved) == 87U &&
						   saved == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 唯一の元fresh能力です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 元fixtureの不成立から新子を作りません。
	if( !pending) {
		throw std::runtime_error( "initial root fixture") ;
	}

	const auto begin   = pending->draft().intent.inventory.size() + 2U ;	// 旧準備の固定件数です。
	const auto newRoot = location / L"segments" / nextKey ;					// 元予約に結合する自作新子です。
	const auto rootPath =
		newRoot / L"history/current/segment-history-root-v1.json" ;	// 本試験の専用ROOTだけです。
	const auto rootName =
		L"segments/" + nextKey +
		L"/history/current/segment-history-root-v1.json" ;	// 全像の固定scope名です。
	DRIVERCRATE_EXPECT( context, begin == 3U && baseline.size() == 168U) ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
					 saved == 0U && baseline == segmentFixtureImage( location) &&
					 !std::filesystem::exists( segmentFixturePath( newRoot))) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U &&
						   saved == begin) ;
	const auto oldPrepared = segmentFixtureImage( location) ;	// 親intent／旧準備だけの実像です。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
					 saved == 0U && oldPrepared == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
									pending, saved,
									[]( const std::size_t prefix) {
										return prefix == 68U ? ERROR_CANCELLED : ERROR_SUCCESS ;
									}) == 1223U &&
									// 初期ROOT前の不足bootstrapを実保存窓で作ります。
									saved == 68U) ;
	const auto partial = segmentFixtureImage( location) ;	// 68準備の後続欠損を補完しません。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
					 saved == 0U && partial == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 0U &&
					 saved == 69U) ;
	auto expected = baseline ;	// 元payloadと固定準備だけの独立期待像です。
	// 親／旧子／新子の全固定準備を元scope別に追加します。
	for( std::size_t i = 0U; i < begin + 69U; ++i) {
		const auto &role = pending->roles()[i] ;	// 元固定roleだけの期待byteです。
		const auto	name =
			 role.scope == CollectorSegmentStorageScope::PARENT
				 ? role.name
				 : L"segments/" +
					   (role.scope == CollectorSegmentStorageScope::OLD_SEGMENT ? segmentKey
																				: nextKey) +
					   L"/" + role.name ;	// 各scopeを混ぜません。
		expected.emplace( name, role.raw) ;
	}

	DRIVERCRATE_EXPECT( context,
					   expected.size() == 240U && expected == segmentFixtureImage( location)) ;
	// 元168rawを個別に改変し、ROOT作成で旧破損を補完しません。
	for( const auto &[name, raw] : baseline) {
		const auto target = location / name ;	// このGUID内の既存fixture一fileです。
		alterSegmentFixture( target, "{}") ;
		const auto changed = segmentFixtureImage( location) ;	// 故意な改変をそのまま保持します。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
						 saved == 0U && changed == segmentFixtureImage( location) &&
						 !std::filesystem::exists( segmentFixturePath( rootPath))) ;
		alterSegmentFixture( target, raw) ;
	}

	// 新子69準備の全rawを個別に改変し、任意carryを取り込みません。
	for( std::size_t i = 0U; i < 69U; ++i) {
		const auto &role   = pending->roles()[begin + i] ;	// 元新子の一固定保存です。
		const auto	target = newRoot / role.name ;			// 同じ自作子の一fileだけです。
		alterSegmentFixture( target, "{}") ;
		const auto changed = segmentFixtureImage( location) ;	// 別byteを修復しません。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
						 saved == 0U && changed == segmentFixtureImage( location)) ;
		alterSegmentFixture( target, role.raw) ;
	}

	const auto oldBudget =
		location / L"current/shared-budget-v1.json" ;	// 元親予算と保護DACLの参照です。
	// 親・新子・新historyの未知名を非変更で拒否します。
	for( const auto &target :
		{location / L"runs/unregistered-root.json", newRoot / L"current/unregistered-root.json",
		 newRoot / L"history/runs/unregistered-root.json"}) {
		alterSegmentFixture( target, "{}") ;
		copySegmentFixtureDacl( oldBudget, target) ;
		const auto changed = segmentFixtureImage( location) ;	// 未登録名を含む実像です。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
						 saved == 0U && changed == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( target))) ;
	}

	const auto &image = pending->roles()[begin + 1U] ;	// 元budget像の途中欠損です。
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( newRoot / image.name))) ;
	const auto missing = segmentFixtureImage( location) ;	// 欠損像を元snapshotで補完しません。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( pending, saved) == 13U &&
					 saved == 0U && missing == segmentFixtureImage( location)) ;
	alterSegmentFixture( newRoot / image.name, image.raw) ;
	copySegmentFixtureDacl( oldBudget, newRoot / image.name) ;
	auto clone = pending ;	// 元wrapper／leaseを解放しても実handleを保持します。
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent->close() == 170U) ;
	parent.reset() ;
	std::string canonicalRoot ;	// 実保存を独立に復号する一ROOTです。
	// 同じ一保存地点の診断OOM／例外／数値停止を個別に確認します。
	for( std::size_t mode = 0U; mode < 3U; ++mode) {
		std::size_t callbacks{} ;	// 初回実保存だけが一度通知します。
		const auto	code = LocalCollectorSegmentStorage::saveInitialHistoryRoot(
			 clone, saved, [&]( const std::size_t prefix) -> DWORD {
				 ++callbacks ;
				 DRIVERCRATE_EXPECT( context, prefix == 1U) ;
				 std::size_t nested = 99U ;	// 同じ保存借用の再入だけを測ります。
				 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveInitialHistoryRoot(
												 clone, nested) == 170U &&
												 nested == 0U) ;
				 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
												 clone, nested) == 170U &&
												 nested == 0U) ;
				 DRIVERCRATE_EXPECT(
					 context, LocalCollectorSegmentStorage::savePreparation( clone, nested) == 170U &&
								  nested == 0U) ;
				 pending.reset() ;
				 saved = std::numeric_limits<std::size_t>::max() ;
				 // 診断確保失敗を保存成功へ変換しません。
				 if( mode == 0U) {
					 throw std::bad_alloc() ;
				 }

				 // その他診断例外も元byteを保持して拒否します。
				 if( mode == 1U) {
					 throw std::runtime_error( "intentional initial root checkpoint") ;
				 }

				 return ERROR_CANCELLED ;
			 }) ; // 元cloneを同期入口も強所有します。
		DRIVERCRATE_EXPECT( context, code == (mode == 0U	  ? 8U
											 : mode == 1U ? 13U
														  : 1223U) &&
										saved == 1U && callbacks == 1U && !pending) ;
		const auto actual = segmentFixtureImage( location) ;	// 一ROOT保存後の全実像です。
		const auto raw	  = actual.at( rootName) ;				// ログへ渡さない架空ROOTだけです。
		// 最初の実保存を独立JSON readerで全関係へ照合します。
		if( mode == 0U) {
			canonicalRoot = raw ;
			const auto envelope =
				// 型付きcodecとは独立のreaderです。
				JsonObject::Parse( winrt::to_hstring( raw)) ;
			const auto body =
				// 原本文を独立に復号します。
				winrt::to_string( envelope.GetNamedString( L"body")) ;
			const auto root =
				// 固定field集合を検査します。
				JsonObject::Parse( winrt::to_hstring( body)) ;
			std::wstring hash ;								// 元bodyのCNG指紋です。
			const auto	&intent = clone->draft().intent ;	// 元fresh予約の非循環関係です。
			DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( body, hash) == 0 &&
											envelope.GetNamedString( L"sha256") == hash &&
											root.Size() == 17U &&
											root.GetNamedString( L"schema") ==
												L"collector-segment-history-root-v1") ;
			DRIVERCRATE_EXPECT( context,
							   root.GetNamedString( L"collection") == collectionKey &&
								   root.GetNamedString( L"segment") == nextKey &&
								   root.GetNamedNumber( L"ordinal") == 1.0 &&
								   root.GetNamedNumber( L"accepted") == static_cast<double>( utc) &&
								   root.GetNamedNumber( L"lastUtc") ==
									   static_cast<double>( snapshot.lastUtcMillis) &&
								   snapshot.lastUtcMillis != utc) ;
			DRIVERCRATE_EXPECT( context, root.GetNamedString( L"oldSegment") == segmentKey &&
											root.GetNamedString( L"oldRoot") == intent.oldRoot &&
											root.GetNamedString( L"seal") == intent.seal &&
											root.GetNamedString( L"ledger") == intent.ledger &&
											root.GetNamedString( L"base") == intent.base &&
											root.GetNamedString( L"bootstrap") == intent.bootstrap &&
											root.GetNamedString( L"switchIntent") ==
												clone->draft().intentHash) ;
			const auto images = root.GetNamedArray( L"images") ;	// 全66像を元ordinalへ結合します。
			DRIVERCRATE_EXPECT( context, images.Size() == 66U &&
											root.GetNamedArray( L"generations").Size() == 0U &&
											root.GetNamedArray( L"operations").Size() == 0U &&
											root.GetNamedValue( L"active").ValueType() ==
												winrt::Windows::Data::Json::JsonValueType::Null) ;
			// 空request shardを省略せず元全hashと完全一致させます。
			for( std::uint32_t i = 0U; i < 66U; ++i) {
				DRIVERCRATE_EXPECT( context, images.GetStringAt( i) == clone->draft().images[i]) ;
			}
		}

		auto committed = expected ;	// 元240rawに一ROOTだけ追加する期待像です。
		committed.emplace( rootName, canonicalRoot) ;
		DRIVERCRATE_EXPECT( context,
						   committed.size() == 241U && actual == committed && raw == canonicalRoot) ;
		std::size_t repeated{} ;	// 完全一致ROOTの再呼出しは通知・保存しません。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( clone, saved,
																		  [&]( std::size_t) {
																			  ++repeated ;
																			  return ERROR_SUCCESS ;
																		  }) == 0U &&
						 saved == 1U && repeated == 0U &&
						 committed == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( clone, saved) == 13U &&
						 saved == 0U && committed == segmentFixtureImage( location)) ;
		// 次診断は本試験が作成した一ROOTだけを明示的に欠損させます。
		if( mode != 2U) {
			DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( rootPath))) ;
		}
	}

	auto committed = expected ;	// 以後は一ROOT登録済みの全byteを正本とします。
	committed.emplace( rootName, canonicalRoot) ;
	alterSegmentFixture( rootPath, "{}") ;
	const auto badRoot = segmentFixtureImage( location) ;	// 別ROOTは修復しません。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveInitialHistoryRoot( clone, saved) == 13U &&
						   saved == 0U && badRoot == segmentFixtureImage( location)) ;
	alterSegmentFixture( rootPath, canonicalRoot) ;
	const auto originalEnvelope =
		// 実ROOTの独立復号です。
		JsonObject::Parse( winrt::to_hstring( canonicalRoot)) ;
	auto forgedBody = winrt::to_string(
		// 正しいhash付きの不正ROOTを作ります。
		originalEnvelope.GetNamedString( L"body")) ;
	const auto active = forgedBody.find( "\"active\":null") ;	// 元固定fieldの位置だけです。
	DRIVERCRATE_EXPECT( context, active != std::string::npos) ;
	forgedBody.replace( active, 13U, "\"active\":false") ;
	std::wstring forgedHash ;	// 偽bodyに実CNGを使いhash破損とは区別します。
	DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( forgedBody, forgedHash) == 0) ;
	std::string						 forgedRaw ;					// 正当な外側schemaでも登録値は一致しません。
	collector_projected_json::Writer forged( 2U * 1024U * 1024U) ;	// 同じraw上限内の故意な偽像です。
	forged.append( "{\"schema\":\"collector-shared-envelope-v1\",\"body\":") ;
	forged.text( forgedBody) ;
	forged.append( ",\"sha256\":") ;
	forged.wideText( forgedHash) ;
	forged.append( "}") ;
	forgedRaw = forged.take() ;
	alterSegmentFixture( rootPath, forgedRaw) ;
	const auto forgedImage = segmentFixtureImage( location) ;	// 再hashした不正ROOTを保持します。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveInitialHistoryRoot( clone, saved) == 13U &&
						   saved == 0U && forgedImage == segmentFixtureImage( location)) ;
	alterSegmentFixture( rootPath, canonicalRoot) ;
	{
		const auto handle = CreateFileW( segmentFixturePath( rootPath).c_str(), GENERIC_READ, 0U,
										nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
										nullptr) ;	// 実保護readの共有拒否です。
		// 故障注入不成立を元error保持の成功にしません。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "initial root sharing fixture") ;
		}

		const std::unique_ptr<void, decltype( &CloseHandle)> locked(
			handle, &CloseHandle) ;	// 必ず返す故障handleです。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveInitialHistoryRoot( clone, saved) == 32U &&
						 saved == 0U) ;
	}
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( rootPath))) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveInitialHistoryRoot(
									clone, saved,
									[&]( const std::size_t prefix) {
										DRIVERCRATE_EXPECT( context, prefix == 1U) ;
										alterSegmentFixture( oldBudget, "{}") ;
										saved = std::numeric_limits<std::size_t>::max() ;
										return ERROR_SUCCESS ;
									}) == 13U &&
									// 診断後も元旧rawを再検査します。
									saved == 1U) ;
	auto changedAfterSave = committed ;	// 故意な予算改変だけを含む全像です。
	changedAfterSave[L"current/shared-budget-v1.json"] = "{}" ;
	DRIVERCRATE_EXPECT( context, changedAfterSave == segmentFixtureImage( location)) ;
	alterSegmentFixture( oldBudget, baseline.at( L"current/shared-budget-v1.json")) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveInitialHistoryRoot( clone, saved) == 0U &&
						   saved == 1U && committed == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( rootPath))) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveInitialHistoryRoot(
						   clone, saved,
						   [&]( const std::size_t prefix) {
							   DRIVERCRATE_EXPECT( context, prefix == 1U) ;
							   clone.reset() ;
							   saved = std::numeric_limits<std::size_t>::max() ;
							   LocalCollectorCollectionStore
								   contender ;	// 入口の強所有だけが親lockを保持しています。
							   DRIVERCRATE_EXPECT(
								   context, contender.initialize( location, collectionKey) != 0U) ;
							   return ERROR_SUCCESS ;
						   }) == 0U &&
						   saved == 1U && !clone && committed == segmentFixtureImage( location)) ;
	LocalCollectorCollectionStore reopened ;	// 元全能力解放後の新しいprocess相当です。
	DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U &&
									reopened.borrowHistorySegment( segmentKey, false, lease) == 0U &&
									lease) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( reopened, *lease, definition.sources,
															 nextKey, utc, pending) == 13U &&
						   !pending && committed == segmentFixtureImage( location)) ;
	lease.reset() ;
	// 専用ROOTだけの非空historyを旧v3 mode欠損の初回領域として開きません。
	DRIVERCRATE_EXPECT( context,
					   reopened.borrowHistorySegment( nextKey, false, lease) == 13U && !lease) ;
	DRIVERCRATE_EXPECT( context, committed == segmentFixtureImage( location)) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
}

/** @see local_collector_http_tests.h */
void runCollectorNewSegmentStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空の親identityです。
	const std::wstring segmentKey( 64U, L'2') ;						// 同親旧子です。
	const std::wstring nextKey( 64U, L'3') ;						// 未存在の新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID領域です。
	auto			   parent =
		std::make_unique<LocalCollectorCollectionStore>() ;	// Wrapper解放を独立検査します。
	DRIVERCRATE_EXPECT( context, parent->initialize( location, collectionKey) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 唯一旧子のhistory付き能力です。
	DRIVERCRATE_EXPECT( context, parent->borrowHistorySegment( segmentKey, true, lease) == 0U) ;
	// 欠測したfixtureから切替保持の成功を作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "storage fixture lease") ;
	}

	auto &store = *lease->history() ;				// Reservationが後でも強所有する元historyです。
	CollectorProjectedCampaignIdentity identity ;	// 元公開契約の再導出です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// 偽workerより長い所有です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でnative factoryを呼びません。
	if( !campaign) {
		throw std::runtime_error( "storage fixture input") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実worker／偽HTTPの元保存です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 最終完了後に監督借用を返します。
		DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot = matchingSegmentFixture(
		context, store, collectionKey, segmentKey) ;	// 新encoderではなく元保存本文から作ります。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( *parent, *lease, snapshot) == 0U) ;
	const auto	baseline = segmentFixtureImage( location) ;	// 新子の作成も禁止する元全byteです。
	std::size_t saved	 = 99U ;							// 新子保存の失敗出力です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::saveNewSegmentPreparation( {}, saved) == 87U &&
						   saved == 0U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 唯一の元fresh能力です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 元fixtureの不成立から新子を作りません。
	if( !pending) {
		throw std::runtime_error( "new segment storage fixture") ;
	}

	const auto begin   = pending->draft().intent.inventory.size() + 2U ;	// 旧準備の全role数です。
	const auto newRoot = location / L"segments" / nextKey ;					// 元予約に結合する自作新子です。
	DRIVERCRATE_EXPECT( context, begin == 3U && baseline.size() == 168U &&
									pending->roles().size() == begin + 71U) ;
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 13U &&
					 saved == 0U && baseline == segmentFixtureImage( location) &&
					 !std::filesystem::exists( segmentFixturePath( newRoot))) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 0U &&
						   saved == begin) ;
	std::map<std::wstring, std::string> expected =
		baseline ;	// 元payloadと固定準備だけの期待像です。
	// 元旧準備の実保存byteだけを新子前の正本へ追加します。
	for( std::size_t i = 0U; i < begin; ++i) {
		const auto &role = pending->roles()[i] ;	// 親または旧子の固定roleです。
		const auto	name =
			 role.scope == CollectorSegmentStorageScope::PARENT
				 ? role.name
				 : L"segments/" + segmentKey + L"/" + role.name ;	// Scopeを混ぜない元相対名です。
		expected.emplace( name, role.raw) ;
	}

	const auto oldBudget = location / L"current/shared-budget-v1.json" ;	// 元親の非変更予算です。
	alterSegmentFixture( oldBudget, "{}") ;
	const auto changedOld = segmentFixtureImage( location) ;	// 作成前の故意な元raw改変です。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( pending, saved) == 13U &&
					 saved == 0U && changedOld == segmentFixtureImage( location) &&
					 !std::filesystem::exists( segmentFixturePath( newRoot))) ;
	alterSegmentFixture( oldBudget, baseline.at( L"current/shared-budget-v1.json")) ;
	auto clone = pending ;	// 元wrapperと旧lease解放後も全実handleを保持します。
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent->close() == 170U) ;
	std::unique_ptr<LocalCollectorSegmentLease> denied ;	// 公開の二子借用を許しません。
	DRIVERCRATE_EXPECT( context,
					   parent->borrowHistorySegment( nextKey, true, denied) == 170U && !denied) ;
	parent.reset() ;
	// Marker・全66像・base・bootstrapの69地点を一保存ずつ停止して同一holdで再開します。
	for( std::size_t i = 0U; i < 69U; ++i) {
		std::size_t callbacks{} ;	// 不足roleの一地点だけを通知します。
		const auto	code = LocalCollectorSegmentStorage::saveNewSegmentPreparation(
			 clone, saved, [&]( const std::size_t prefix) -> DWORD {
				 ++callbacks ;
				 DRIVERCRATE_EXPECT( context, prefix == i + 1U) ;
				 std::size_t nested = 99U ;	// 同じ新子への保存再入を拒否します。
				 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
												 clone, nested) == 170U &&
												 nested == 0U) ;
				 DRIVERCRATE_EXPECT(
					 context, LocalCollectorSegmentStorage::savePreparation( clone, nested) == 170U &&
								  nested == 0U) ;
				 pending.reset() ;
				 saved = std::numeric_limits<std::size_t>::max() ;
				 // 診断OOMでも確認済み物理prefixを維持します。
				 if( i % 3U == 0U) {
					 throw std::bad_alloc() ;
				 }

				 // その他の診断例外を成功へ変換しません。
				 if( i % 3U == 1U) {
					 throw std::runtime_error( "intentional new segment checkpoint") ;
				 }

				 return ERROR_CANCELLED ;
			 }) ; // 元cloneを同期呼出し中の保存入口も強所有します。
		DRIVERCRATE_EXPECT( context, callbacks == 1U && saved == i + 1U &&
										code == (i % 3U == 0U	? 8U
												 : i % 3U == 1U ? 13U
																: 1223U) &&
										!pending) ;
		const auto &role = clone->roles()[begin + i] ;	// 今回確認した新子の一roleです。
		expected.emplace( L"segments/" + nextKey + L"/" + role.name, role.raw) ;
		DRIVERCRATE_EXPECT(
			context, role.scope == CollectorSegmentStorageScope::NEW_SEGMENT &&
						 expected == segmentFixtureImage( location) &&
						 std::filesystem::is_directory( segmentFixturePath( newRoot / L"history"))) ;
		// Markerはcanonical専用schemaでありenvelopeを重ねません。
		if( i == 0U) {
			const auto marker = JsonObject::Parse( winrt::to_hstring( role.raw)) ;	// 独立readerです。
			DRIVERCRATE_EXPECT( context, marker.GetNamedString( L"collection") == collectionKey &&
											marker.GetNamedString( L"segment") == nextKey &&
											marker.GetNamedString( L"history") == L"history") ;
		} else {
			const auto envelope = JsonObject::Parse( winrt::to_hstring( role.raw)) ;	// 実保存rawです。
			const auto original =
				// 独立復号です。
				winrt::to_string( envelope.GetNamedString( L"body")) ;
			std::wstring hash ;	// 元CNGでbody hashを独立導出します。
			const auto	 required = i <= 66U   ? clone->draft().images[i - 1U]
									: i == 67U ? clone->draft().intent.base
											   : clone->draft().intent.bootstrap ;	// 元固定関係です。
			DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( original, hash) == 0 &&
											hash == required &&
											envelope.GetNamedString( L"sha256") == hash) ;
		}
	}

	// 保存済みの全69rawを個別改変し、別byteを修復せず拒否します。
	for( std::size_t i = 0U; i < 69U; ++i) {
		const auto &role   = clone->roles()[begin + i] ;	// 改変する元固定新子roleです。
		const auto	target = newRoot / role.name ;			// 同じ自作GUID内の明示fileです。
		alterSegmentFixture( target, "{}") ;
		const auto changed = segmentFixtureImage( location) ;	// 改変像をそのまま保持します。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( clone, saved) == 13U &&
						 saved == 0U && changed == segmentFixtureImage( location)) ;
		alterSegmentFixture( target, role.raw) ;
	}

	// 初期marker／像／baseの途中欠損を後続存在の不足suffixへ格下げしません。
	for( const std::size_t i : {0U, 1U, 67U}) {
		const auto &role   = clone->roles()[begin + i] ;	// 故意に抜く元固定roleです。
		const auto	target = newRoot / role.name ;			// 本試験が作った一fileだけです。
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( target))) ;
		const auto changed = segmentFixtureImage( location) ;	// 穴のある像を修復しません。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( clone, saved) == 13U &&
						 saved == 0U && changed == segmentFixtureImage( location)) ;
		alterSegmentFixture( target, role.raw) ;
		copySegmentFixtureDacl( oldBudget, target) ;
	}

	// 新子と空historyの未知name／未登録ROOTを非空初回へ読み替えません。
	for( const auto &target : {newRoot / L"runs/unregistered-preparation.json",
							  newRoot / L"history/current/campaign-root-v3.json"}) {
		alterSegmentFixture( target, "{}") ;
		copySegmentFixtureDacl( oldBudget, target) ;
		const auto changed = segmentFixtureImage( location) ;	// 未登録payloadを含む実像です。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( clone, saved) == 13U &&
						 saved == 0U && changed == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( target))) ;
	}

	const auto basePath = newRoot / clone->roles()[begin + 67U].name ;	// 新baseの共有拒否対象です。
	{
		const auto handle = CreateFileW( segmentFixturePath( basePath).c_str(), GENERIC_READ, 0U,
										nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL,
										nullptr) ;	// 実保護readだけを共有拒否します。
		// 故障注入の不成立を製品の元error保持にしません。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "new segment sharing fixture") ;
		}

		const std::unique_ptr<void, decltype( &CloseHandle)> locked(
			handle, &CloseHandle) ;	// 必ず返す故障handleです。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( clone, saved) == 32U &&
						 saved == 0U) ;
	}
	const auto &bootstrap = clone->roles()[begin + 68U] ;	// 末尾の一不足suffixだけを再現します。
	DRIVERCRATE_EXPECT( context,
					   std::filesystem::remove( segmentFixturePath( newRoot / bootstrap.name))) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::saveNewSegmentPreparation(
									clone, saved,
									[&]( const std::size_t prefix) {
										DRIVERCRATE_EXPECT( context, prefix == 69U) ;
										alterSegmentFixture( oldBudget, "{}") ;
										saved = std::numeric_limits<std::size_t>::max() ;
										return ERROR_SUCCESS ;
									}) == 13U &&
									// 最後の診断後も元旧rawを再照合します。
									saved == 69U) ;
	auto changedAfterSave = expected ;	// 故意の元予算変更だけを含む保存後像です。
	changedAfterSave[L"current/shared-budget-v1.json"] = "{}" ;
	DRIVERCRATE_EXPECT( context, changedAfterSave == segmentFixtureImage( location)) ;
	alterSegmentFixture( oldBudget, baseline.at( L"current/shared-budget-v1.json")) ;
	std::size_t callbacks{} ;	// 完了した準備は再保存・再通知しません。
	DRIVERCRATE_EXPECT(
		context, LocalCollectorSegmentStorage::saveNewSegmentPreparation( clone, saved,
																		 [&]( std::size_t) {
																			 ++callbacks ;
																			 return ERROR_SUCCESS ;
																		 }) == 0U &&
					 saved == 69U && callbacks == 0U && expected == segmentFixtureImage( location) &&
					 expected.size() == 240U) ;
	{
		LocalCollectorCollectionStore contender ;	// 全元wrapper解放後も親lockは取得できません。
		DRIVERCRATE_EXPECT( context, contender.initialize( location, collectionKey) != 0U &&
										expected == segmentFixtureImage( location)) ;
	}
	clone.reset() ;
	LocalCollectorCollectionStore reopened ;	// 全hold解放後の再起動相当です。
	DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U &&
									reopened.borrowHistorySegment( segmentKey, false, lease) == 0U &&
									lease) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( reopened, *lease, definition.sources,
															 nextKey, utc, pending) == 13U &&
						   !pending && expected == segmentFixtureImage( location)) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, reopened.borrowHistorySegment( nextKey, false, lease) == 0U &&
									lease && lease->history()) ;
	CollectorSharedLedgerSnapshot unavailable ;	// 新子を正本headとして読み替えません。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::load( reopened, *lease, unavailable) == 13U &&
						   expected == segmentFixtureImage( location)) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
}

/** @see local_collector_http_tests.h */
void runCollectorSegmentPreparationStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空の親identityです。
	const std::wstring segmentKey( 64U, L'2') ;						// 同親旧子です。
	const std::wstring nextKey( 64U, L'3') ;						// 未存在の新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID領域です。
	auto			   parent =
		std::make_unique<LocalCollectorCollectionStore>() ;	// Wrapper解放を独立検査します。
	DRIVERCRATE_EXPECT( context, parent->initialize( location, collectionKey) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 唯一旧子のhistory付き能力です。
	DRIVERCRATE_EXPECT( context, parent->borrowHistorySegment( segmentKey, true, lease) == 0U) ;
	// 欠測したfixtureから切替保持の成功を作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "storage fixture lease") ;
	}

	auto &store = *lease->history() ;				// Reservationが後でも強所有する元historyです。
	CollectorProjectedCampaignIdentity identity ;	// 元公開契約の再導出です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// 偽workerより長い所有です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でnative factoryを呼びません。
	if( !campaign) {
		throw std::runtime_error( "storage fixture input") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実worker／偽HTTPの元保存です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 最終完了後に監督借用を返します。
		DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot = matchingSegmentFixture(
		context, store, collectionKey, segmentKey) ;	// 新encoderではなく元保存本文から作ります。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( *parent, *lease, snapshot) == 0U) ;
	const auto	baseline = segmentFixtureImage( location) ;	// 新子の作成も禁止する元全byteです。
	std::size_t saved	 = 99U ;							// 不正能力でも失敗出力は0です。
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::savePreparation( {}, saved) == 87U &&
									saved == 0U && baseline == segmentFixtureImage( location)) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 元fresh能力だけです。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 欠損fixtureから準備保存を成功扱いにしません。
	if( !pending) {
		throw std::runtime_error( "preparation storage fixture") ;
	}

	const auto count = pending->draft().intent.inventory.size() + 2U ;	// このfixtureは一shardです。
	DRIVERCRATE_EXPECT( context, count == 3U && baseline.size() == 168U) ;
	// 元全rawを一つずつ改変し、保存前のfresh拒否と非変更を独立に測ります。
	for( const auto &[name, raw] : baseline) {
		alterSegmentFixture( location / name, "{}") ;
		const auto changed = segmentFixtureImage( location) ;	// 改変済み像を修復しません。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 13U &&
							   saved == 0U && changed == segmentFixtureImage( location)) ;
		alterSegmentFixture( location / name, raw) ;
	}

	const auto rolePath = [&]( const CollectorSegmentStorageRole &role) {
		return role.scope == CollectorSegmentStorageScope::PARENT
				   ? location / role.name
				   : location / L"segments" / segmentKey / role.name ;
	} ; // 元予約の固定親／旧子名だけを自作fixtureへ結合します。
	const auto modelPath = [&]( const CollectorSegmentStorageRole &role) {
		return role.scope == CollectorSegmentStorageScope::PARENT
				   ? location / L"current/collector-campaign-mode-v1.json"
				   : location / L"segments" / segmentKey /
						 L"current/collector-campaign-mode-v1.json" ;
	} ; // 不正ACLと非prefixを分離する元検査済みfileです。
	// Intent欠損で後続roleだけが存在する非prefixを、削除・補完せず拒否します。
	for( std::size_t i = 1U; i < count; ++i) {
		const auto &role   = pending->roles()[i] ;	// 元固定rawの故意な順序違反です。
		const auto	target = rolePath( role) ;		// 自作GUID内の明示一fileです。
		alterSegmentFixture( target, role.raw) ;
		copySegmentFixtureDacl( modelPath( role), target) ;
		const auto changed = segmentFixtureImage( location) ;	// 非prefix状態そのものを保持します。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 13U &&
							   saved == 0U && changed == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( target))) ;
	}

	// 全scopeの未知名を、同sizeや正規ACLでも無視しません。
	for( const auto &directory : {location, location / L"segments" / segmentKey,
								 location / L"segments" / segmentKey / L"history"}) {
		const auto target = directory / L"runs/unregistered-preparation.json" ;	// 自作未知名です。
		alterSegmentFixture( target, "{}") ;
		copySegmentFixtureDacl( location / L"current/collector-campaign-mode-v1.json", target) ;
		const auto changed = segmentFixtureImage( location) ;	// 未知名を含む非変更期待像です。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 13U &&
							   saved == 0U && changed == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( target))) ;
	}

	const auto unavailable =
		location / L"current/shared-budget-v1.json" ;	// 元親の共有拒否対象です。
	{
		const auto handle =
			CreateFileW( segmentFixturePath( unavailable).c_str(), GENERIC_READ, 0U, nullptr,
						OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) ;	// 元rawを共有拒否します。
		// Sharing故障注入に失敗したまま製品の元error保持を合格にしません。
		if( handle == INVALID_HANDLE_VALUE) {
			throw std::runtime_error( "preparation storage sharing fixture") ;
		}

		const std::unique_ptr<void, decltype( &CloseHandle)> locked(
			handle, &CloseHandle) ;	// 自作故障handleを返します。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::savePreparation( pending, saved) == 32U &&
							   saved == 0U) ;
	}
	DRIVERCRATE_EXPECT( context, baseline == segmentFixtureImage( location)) ;
	auto clone = pending ;	// 元wrapper／lease解放後も実能力を所有します。
	lease.reset() ;
	parent.reset() ;
	std::map<std::wstring, std::string> expected =
		baseline ;	// 元全payloadと追加準備だけの期待像です。
	// 三つの保存窓で数値停止／OOM／例外後に同じholdから不足分だけを再開します。
	for( std::size_t i = 0U; i < count; ++i) {
		std::size_t callbacks{} ;	// 保存済みroleへ診断を再実行しません。
		const auto	code = LocalCollectorSegmentStorage::savePreparation(
			 clone, saved, [&]( const std::size_t prefix) -> DWORD {
				 ++callbacks ;
				 DRIVERCRATE_EXPECT( context, prefix == i + 1U) ;
				 std::size_t nested = 99U ;	// 同じholdへの再入を拒否します。
				 DRIVERCRATE_EXPECT(
					 context, LocalCollectorSegmentStorage::savePreparation( clone, nested) == 170U &&
								  nested == 0U) ;
				 pending.reset() ;
				 saved = std::numeric_limits<std::size_t>::max() ;
				 // 保存後のOOMでも第一errorと確認済みprefixを保持します。
				 if( i == 0U) {
					 throw std::bad_alloc() ;
				 }

				 // その他の例外も保存済みprefixを巻き戻しません。
				 if( i == 1U) {
					 throw std::runtime_error( "intentional preparation checkpoint") ;
				 }

				 return ERROR_CANCELLED ;
			 }) ; // cloneと元fixtureは同期診断より長く存続します。
		DRIVERCRATE_EXPECT( context, code == (i == 0U   ? 8U
											 : i == 1U ? 13U
													   : 1223U) &&
										saved == i + 1U && callbacks == 1U && !pending) ;
		const auto &role = clone->roles()[i] ;	// 本回保存した元固定roleです。
		const auto	relative =
			 role.scope == CollectorSegmentStorageScope::PARENT
				 ? role.name
				 : L"segments/" + segmentKey + L"/" + role.name ;	// 三scopeを区別する固定相対名です。
		expected.emplace( relative, role.raw) ;
		DRIVERCRATE_EXPECT( context, expected == segmentFixtureImage( location) &&
										!std::filesystem::exists(
											segmentFixturePath( location / L"segments" / nextKey))) ;
		// 保存済み全準備roleを改変し、別byteを上書き修復しません。
		for( std::size_t j = 0U; j <= i; ++j) {
			const auto &existing = clone->roles()[j] ;	// 保存済みの元固定roleです。
			alterSegmentFixture( rolePath( existing), "{}") ;
			const auto changed = segmentFixtureImage( location) ;	// 保存済み準備の改変像です。
			DRIVERCRATE_EXPECT( context,
							   LocalCollectorSegmentStorage::savePreparation( clone, saved) == 13U &&
								   saved == 0U && changed == segmentFixtureImage( location)) ;
			alterSegmentFixture( rolePath( existing), existing.raw) ;
		}
	}

	// 確定prefixの途中欠損は、後続sealがあっても不足suffixへ格下げしません。
	for( std::size_t i = 0U; i + 1U < count; ++i) {
		const auto &role   = clone->roles()[i] ;	// 故意に抜く元準備roleです。
		const auto	target = rolePath( role) ;		// この試験が作った明示fileだけです。
		DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( target))) ;
		const auto changed = segmentFixtureImage( location) ;	// 穴のあるprefixを修復しません。
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::savePreparation( clone, saved) == 13U &&
							   saved == 0U && changed == segmentFixtureImage( location)) ;
		alterSegmentFixture( target, role.raw) ;
		copySegmentFixtureDacl( modelPath( role), target) ;
	}

	const auto &sealRole = clone->roles()[count - 1U] ;	// 末尾だけの不足suffixを再現します。
	DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( rolePath( sealRole)))) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::savePreparation(
									clone, saved,
									[&]( const std::size_t prefix) {
										DRIVERCRATE_EXPECT( context, prefix == count) ;
										alterSegmentFixture( unavailable, "{}") ;
										saved = std::numeric_limits<std::size_t>::max() ;
										return ERROR_SUCCESS ;
									}) == 13U &&
									// 最後の診断後も全元rawを再検査します。
									saved == count) ;
	auto changedAfterSave = expected ;	// 実保存したsealと故意の元payload改変だけです。
	changedAfterSave[L"current/shared-budget-v1.json"] = "{}" ;
	DRIVERCRATE_EXPECT( context, changedAfterSave == segmentFixtureImage( location)) ;
	alterSegmentFixture( unavailable, baseline.at( L"current/shared-budget-v1.json")) ;
	std::size_t callbacks{} ;	// 完了準備の再呼出しでcallbackも再発行しません。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::savePreparation( clone, saved,
																	 [&]( std::size_t) {
																		 ++callbacks ;
																		 return ERROR_SUCCESS ;
																	 }) == 0U &&
						   saved == count && callbacks == 0U &&
						   expected == segmentFixtureImage( location)) ;
	const auto intent =
		// 実保存envelopeです。
		JsonObject::Parse( winrt::to_hstring( clone->roles()[0].raw)) ;
	const auto body = JsonObject::Parse( intent.GetNamedString( L"body")) ;	// 独立JSON readerです。
	DRIVERCRATE_EXPECT( context, body.GetNamedString( L"collection") == collectionKey &&
									body.GetNamedString( L"oldSegment") == segmentKey &&
									body.GetNamedString( L"newSegment") == nextKey &&
									body.GetNamedNumber( L"accepted") == static_cast<double>( utc)) ;
	clone.reset() ;
	LocalCollectorCollectionStore reopened ;	// 再起動相当ではまだ予約を再発行しません。
	DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U &&
									reopened.borrowHistorySegment( segmentKey, false, lease) == 0U &&
									lease) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( reopened, *lease, definition.sources,
															 nextKey, utc, pending) == 13U &&
						   !pending && expected == segmentFixtureImage( location)) ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
}

/** @see local_collector_http_tests.h */
void runCollectorSegmentStorageTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	constexpr std::uint64_t limit = 5ULL * 1024U * 1024U * 1024U ;	// 既存storeの独立上限です。
	std::array<CollectorStoreUsage, 3U> usage{} ;					// 単体容量DTOは実fileの測定ではありません。
	std::array<CollectorSegmentStorageCost, 3U> cost ;				// 失敗後も空を照合します。
	std::vector<CollectorSegmentStorageRole>	roles{
		   {CollectorSegmentStorageScope::PARENT, L"current/collection-head-v1.json", "a"},
		   {CollectorSegmentStorageScope::PARENT, L"current/collection-head-v1.json",
			"b"}} ;	// 二回保存です。
	DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 0U &&
									cost[0].bytes == 2U && cost[0].stagingBytes == 1U &&
									cost[0].currentNames == 1U && cost[0].runNames == 0U &&
									cost[1].bytes == 0U && cost[2].bytes == 0U) ;
	// 三scopeの各byte境界を独立適用し、他scopeの余裕で補完しません。
	for( std::size_t i = 0U; i < usage.size(); ++i) {
		roles[0].scope = static_cast<CollectorSegmentStorageScope>( i) ;
		roles[1].scope = roles[0].scope ;
		usage		   = {} ;
		usage[i].bytes = limit - 3U ;
		DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 0U) ;
		++usage[i].bytes ;
		DRIVERCRATE_EXPECT( context,
						   checkCollectorSegmentStorageCapacity( usage, roles, cost) == 68U &&
							   std::all_of( cost.begin(), cost.end(),
										   []( const auto &value) { return value.bytes == 0U ; })) ;
		usage					= {} ;
		usage[i].currentEntries = 4094U ;
		DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 0U) ;
		++usage[i].currentEntries ;
		DRIVERCRATE_EXPECT( context,
						   checkCollectorSegmentStorageCapacity( usage, roles, cost) == 68U) ;
		roles[0].name		= L"runs/one.json" ;
		roles[1].name		= L"runs/one.json" ;
		usage				= {} ;
		usage[i].runEntries = 4094U ;
		DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 0U) ;
		++usage[i].runEntries ;
		DRIVERCRATE_EXPECT( context,
						   checkCollectorSegmentStorageCapacity( usage, roles, cost) == 68U) ;
		roles[0].name = L"current/collection-head-v1.json" ;
		roles[1].name = roles[0].name ;
	}

	usage		   = {} ;
	usage[0].bytes = std::numeric_limits<std::uint64_t>::max() ;
	DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 68U) ;
	usage = {} ;
	roles.resize( 1U) ;
	roles[0].raw.assign( 2U * 1024U * 1024U, 'a') ;
	DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 0U) ;
	roles[0].raw.push_back( 'a') ;
	DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 68U) ;
	roles[0].raw   = "a" ;
	roles[0].scope = static_cast<CollectorSegmentStorageScope>( 3U) ;
	DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 13U) ;
	roles[0].scope = CollectorSegmentStorageScope::PARENT ;
	// 相対scope外の名は容量計算単体でも成功へしません。
	for( const std::wstring_view name :
		{L"../one.json", L"current/../one.json", L"current/child/one.json", L"current\\one.json",
		 L"current/one.json:stream"}) {
		roles[0].name = name ;
		DRIVERCRATE_EXPECT( context,
						   checkCollectorSegmentStorageCapacity( usage, roles, cost) == 13U) ;
	}

	roles[0].name = L"runs/one.json" ;
	roles.resize( 90U, roles.front()) ;
	DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 0U) ;
	roles.push_back( roles.front()) ;
	DRIVERCRATE_EXPECT( context, checkCollectorSegmentStorageCapacity( usage, roles, cost) == 68U) ;
	DRIVERCRATE_EXPECT(
		context,
		!std::is_default_constructible_v<CollectorSegmentStorageReservation::ConstructionKey>) ;

	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 架空の親identityです。
	const std::wstring segmentKey( 64U, L'2') ;						// 同親旧子です。
	const std::wstring nextKey( 64U, L'3') ;						// 未存在の新区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID領域です。
	auto			   parent =
		std::make_unique<LocalCollectorCollectionStore>() ;	// Wrapper解放を独立検査します。
	DRIVERCRATE_EXPECT( context, parent->initialize( location, collectionKey) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 唯一旧子のhistory付き能力です。
	DRIVERCRATE_EXPECT( context, parent->borrowHistorySegment( segmentKey, true, lease) == 0U) ;
	// 欠測したfixtureから切替保持の成功を作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "storage fixture lease") ;
	}

	auto &store = *lease->history() ;				// Reservationが後でも強所有する元historyです。
	CollectorProjectedCampaignIdentity identity ;	// 元公開契約の再導出です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// 偽workerより長い所有です。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 未準備入力でnative factoryを呼びません。
	if( !campaign) {
		throw std::runtime_error( "storage fixture input") ;
	}

	std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実worker／偽HTTPの元保存です。
	DRIVERCRATE_EXPECT( context, initialProjectedStorageFixture( context, store, definition, campaign,
															   0U, {}, responses) == 0U) ;
	{
		LocalCollectorRecovery owner ;	// 最終完了後に監督借用を返します。
		DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, definition,
															  HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
	}
	const auto snapshot = matchingSegmentFixture(
		context, store, collectionKey, segmentKey) ;	// 新encoderではなく元保存本文から作ります。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( *parent, *lease, snapshot) == 0U) ;
	const auto baseline = segmentFixtureImage( location) ;				// 新子の作成も禁止する元全byteです。
	std::shared_ptr<const CollectorSegmentStorageReservation> pending ;	// 全失敗は空です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 L"invalid", utc, pending) == 13U &&
						   !pending) ;
	{
		LocalCollectorCollectionStore other ;					// 別親能力を元根拠へ混在させません。
		const auto otherRoot = rootFactory() / collectionKey ;	// 別の自作GUID領域です。
		DRIVERCRATE_EXPECT( context, other.initialize( otherRoot, collectionKey) == 0U) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentStorage::prepare( other, *lease, definition.sources,
																 nextKey, utc, pending) == 87U &&
							   !pending) ;
	}
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	// 失敗contextを後続の独立oracleへ渡しません。
	if( !pending) {
		throw std::runtime_error( "storage fixture prepare") ;
	}

	DRIVERCRATE_EXPECT(
		context,
		pending->roles().size() == 73U + pending->draft().intent.inventory.size() &&
			!std::filesystem::exists( segmentFixturePath( location / L"segments" / nextKey)) &&
			baseline == segmentFixtureImage( location)) ;
	std::size_t images{} ;	// 全66固定roleを独立に数えます。
	// 元envelopeを別JSON readerで復号して本文hashと全固定scopeを照合します。
	for( const auto &role : pending->roles()) {
		DRIVERCRATE_EXPECT( context, !role.raw.empty() && (role.name.starts_with( L"current/") ||
														  role.name.starts_with( L"runs/"))) ;
		// Markerは元canonical byteのままで、envelopeへ重ねません。
		if( role.scope == CollectorSegmentStorageScope::NEW_SEGMENT &&
		   role.name == L"current/collector-campaign-mode-v1.json") {
			const auto marker =
				// 別readerの原値です。
				JsonObject::Parse( winrt::to_hstring( role.raw)) ;
			DRIVERCRATE_EXPECT( context, marker.GetNamedString( L"collection") == collectionKey &&
											marker.GetNamedString( L"segment") == nextKey &&
											marker.GetNamedString( L"history") == L"history") ;
			continue ;
		}

		const auto envelope =
			// 既存外側schemaです。
			JsonObject::Parse( winrt::to_hstring( role.raw)) ;
		const auto body =
			// 独立復号した原byteです。
			winrt::to_string( envelope.GetNamedString( L"body")) ;
		std::wstring hash ;	// 本番CNGによる独立の元body hashです。
		DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( body, hash) == 0 &&
										envelope.GetNamedString( L"sha256") == hash &&
										envelope.GetNamedString( L"schema") ==
											L"collector-shared-envelope-v1") ;
		// 予算・group・全空requestも元draftのordinalに完全結合します。
		if( role.name.starts_with( L"runs/segment-switch-image-")) {
			DRIVERCRATE_EXPECT( context, role.scope == CollectorSegmentStorageScope::NEW_SEGMENT &&
											images < 66U &&
											hash == pending->draft().images[images]) ;
			++images ;
		}
	}

	DRIVERCRATE_EXPECT(
		context, images == 66U && pending->cost()[0].currentNames == 1U &&
					 pending->cost()[0].runNames == 1U && pending->cost()[1].currentNames == 1U &&
					 pending->cost()[1].runNames == 1U && pending->cost()[2].currentNames == 2U &&
					 pending->cost()[2].runNames == 67U) ;
	std::shared_ptr<const CollectorSegmentStorageReservation> clone =
		pending ;															// 最後の所有者を分離します。
	std::shared_ptr<const CollectorSegmentStorageReservation> repeated ;	// 再入拒否出力です。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 nextKey, utc, repeated) == 170U &&
						   !repeated) ;
	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentStorage::prepare(
									*parent, *lease, definition.sources,
									pending->draft().intent.newSegment, utc, pending) == 170U &&
									!pending && clone && baseline == segmentFixtureImage( location)) ;
	CollectorSharedLedgerSnapshot closed ;	// 共有保存／読戻しの旧入口も再入させません。
	DRIVERCRATE_EXPECT( context, LocalCollectorSharedStore::load( *parent, *lease, closed) == 170U) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( *parent, *lease, snapshot) == 170U) ;
	const CollectorSharedOperation blocked ;	// 元操作の導出前に親保持が更新を拒否します。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::commit( *parent, *lease, blocked) == 170U &&
						   baseline == segmentFixtureImage( location)) ;
	clone.reset() ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( *parent, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending) ;
	clone = pending ;
	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, parent->close() == 170U &&
									parent->initialize( location, collectionKey) == 170U) ;
	std::unique_ptr<LocalCollectorSegmentLease> denied ;	// 子lease解放後もholdが親を保持します。
	DRIVERCRATE_EXPECT( context,
					   parent->borrowHistorySegment( nextKey, true, denied) == 170U && !denied) ;
	{
		LocalCollectorRecovery deniedOwner ;	// 元historyはholdが実強所有しています。
		DRIVERCRATE_EXPECT( context,
						   deniedOwner.initializeProjected( store, definition, utc, 0U) == 170U) ;
	}
	parent.reset() ;
	{
		LocalCollectorCollectionStore contender ;	// 元wrapperがなくても親writerを重複取得しません。
		DRIVERCRATE_EXPECT( context, contender.initialize( location, collectionKey) != 0U &&
										baseline == segmentFixtureImage( location)) ;
	}
	clone.reset() ;
	LocalCollectorCollectionStore reopened ;	// 最後のhold解放後だけ新しいwriterへ進めます。
	DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
	DRIVERCRATE_EXPECT( context, reopened.borrowHistorySegment( segmentKey, false, lease) == 0U &&
									lease && baseline == segmentFixtureImage( location)) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentStorage::prepare( reopened, *lease, definition.sources,
															 nextKey, utc, pending) == 0U &&
						   pending && baseline == segmentFixtureImage( location)) ;
	pending.reset() ;
	lease.reset() ;
	DRIVERCRATE_EXPECT( context, reopened.close() == 0U) ;
}

/** @see local_collector_http_tests.h */
void runCollectorHttpQuiescenceTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 実端末identityではありません。
	const std::wstring segmentKey( 64U, L'2') ;						// 元一区間の架空keyです。
	const std::wstring nextKey( 64U, L'3') ;						// 存在しない次区間です。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元完了後のacceptedだけです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID領域です。
	LocalCollectorCollectionStore parent ;							// 同親の実唯一writerです。
	DRIVERCRATE_EXPECT( context, parent.initialize( location, collectionKey) == 0U) ;
	std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 実固定history付きleaseです。
	DRIVERCRATE_EXPECT( context, parent.borrowHistorySegment( segmentKey, true, lease) == 0U) ;
	// 不成立のfixtureから元rootの成功を作りません。
	if( !lease || !lease->history()) {
		throw std::runtime_error( "quiescence fixture lease") ;
	}

	auto	  &store		 = *lease->history() ;	// 閉鎖を結合する実historyです。
	const auto identityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。
	auto &identity = *identityOwner ;			// 元入力の厳密再導出です。
	std::shared_ptr<const CollectorPreparedProjectedCampaign>
		campaign ;	// Workerより長く所有します。
	DRIVERCRATE_EXPECT(
		context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
					 prepareCollectorProjectedCampaign(
						 identity.canonicalInput, identity.inputSha256, identity.generationKey,
						 definition.artifactSha256, definition.sources, campaign)) ;
	// 依存欠損をnative factoryで補完しません。
	if( !campaign) {
		throw std::runtime_error( "quiescence fixture input") ;
	}

	std::shared_ptr<const CollectorSegmentQuiescentSwitch> pending ;	// 各拒否で空です。
	DRIVERCRATE_EXPECT(
		context,
		!std::is_default_constructible_v<CollectorStoreHttpLease::ConstructionKey> &&
			!std::is_default_constructible_v<CollectorStoreHttpFreeze::ConstructionKey> &&
			!std::is_default_constructible_v<CollectorSegmentQuiescentSwitch::ConstructionKey>) ;
	auto recovery = std::make_unique<LocalCollectorRecovery>() ;	// Poolより先に登録します。
	DRIVERCRATE_EXPECT( context,
					   recovery->initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
	const auto fixturesOwner =
		std::make_unique<std::array<IoFixture, 2U>>() ;	// 固定件数と型を保って所有する。
	auto &fixtures	 = *fixturesOwner ;					// HTTP／DNSの実APIを使いません。
	fixtures[0].body = winrt::to_string( winrt::hstring( projectedIntelHtml())) ;
	fixtures[1].body = winrt::to_string( winrt::hstring( projectedAsusRowsHtml( 2U))) ;
	std::atomic_bool					   released{} ;		// 最長10秒で終了する実workerの開始待機です。
	std::atomic_uint32_t				   entered{} ;		// Worker二件だけが開始を通知します。
	CollectorProjectedExecutorDependencies dependencies ;	// この関数内だけの所有依存です。
	dependencies.campaign = campaign ;
	dependencies.clock	  = [] {
		   return activeFixture ? activeFixture->clock : CollectorHttpClockSample{HTTP_TEST_UTC, 0U} ;
	} ;
	dependencies.createClient = [] {
		return std::make_unique<LocalCollectorHttpClient>( fixtureHttp(), fixtureDns()) ;
	} ;
	std::size_t started{} ;	// Parentだけが元slotを数えます。
	dependencies.start = [&]( std::function<void()> worker) {
		const auto slot = started++ ;	// 元slotを実threadへ所有copyします。
		return std::thread( [&, slot, worker = std::move( worker)] {
			entered.fetch_add( 1U, std::memory_order_release) ;
			const auto deadline =
				// Fixture有限待機。
				std::chrono::steady_clock::now() + std::chrono::seconds( 10) ;
			// Parentの明示開始か最長10秒で待機を終え、thread所有を回収可能に保ちます。
			while( !released.load( std::memory_order_acquire) &&
				  std::chrono::steady_clock::now() < deadline) {
				std::this_thread::yield() ;
			}

			fixtures[slot].ownerThread = std::this_thread::get_id() ;
			fixtures[slot].clock	   = {HTTP_TEST_UTC, 0U} ;
			FixtureScope scope( fixtures[slot]) ;	// 実worker本体をfake APIへ固定します。
			worker() ;
		}) ;
	} ;
	auto executor = std::make_unique<LocalCollectorProjectedExecutor>(
		// 実thread所有です。
		std::move( dependencies)) ;
	DRIVERCRATE_EXPECT( context, executor->startNext( *recovery) == 0U &&
									executor->startNext( *recovery) == 0U) ;
	const auto running = segmentFixtureImage( location) ;	// 未join拒否前の全rawです。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, nextKey, utc, pending) == 170U &&
						   !pending && running == segmentFixtureImage( location)) ;
	released.store( true, std::memory_order_release) ;
	const auto joined = executor->join() ;	// Thread通知だけでなく実joinを必須とします。
	DRIVERCRATE_EXPECT( context, entered.load( std::memory_order_acquire) == 2U &&
									joined.error == 0U && joined.started == 2U &&
									joined.joined == 2U && joined.notified == 2U) ;
	DRIVERCRATE_EXPECT(
		context,
		recovery->acceptInitialProjected( *executor, 1U, HTTP_TEST_UTC + 125000U, 125000U) == 0U &&
			recovery->acceptInitialProjected( *executor, 0U, HTTP_TEST_UTC + 125000U, 125000U) ==
				0U &&
			recovery->finishInitialProjected( HTTP_TEST_UTC + 127000U, 127000U) == 0U) ;
	// 所有結果を保持するexecutorに非所有監督pointerは残りません。
	recovery.reset() ;
	const auto snapshot =
		// 元ROOTの全値です。
		matchingSegmentFixture( context, store, collectionKey, segmentKey) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
	const auto baseline = segmentFixtureImage( location) ;	// 未変更の三scope全rawです。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, nextKey, utc, pending) == 170U &&
						   !pending && baseline == segmentFixtureImage( location)) ;
	// 実join後のpoolと全control所有を解放します。
	executor.reset() ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, nextKey, utc, pending) == 0U &&
						   pending) ;
	// 閉鎖取得失敗を後続oracleの成功へ補完しません。
	if( !pending) {
		throw std::runtime_error( "quiescence fixture acceptance") ;
	}

	DRIVERCRATE_EXPECT( context, pending->draft().intent.ledger ==
										pending->root().evidence().shared->evidence().ledger &&
									pending->draft().intent.oldRoot ==
										pending->root().evidence().history->evidence().rootSha256 &&
									baseline == segmentFixtureImage( location)) ;
	{
		LocalCollectorRecovery stopped ;	// 元UTCを変更する前に閉鎖を確認します。
		DRIVERCRATE_EXPECT(
			context, stopped.initializeProjected( store, definition, utc + 86400000U, 0U) == 170U &&
						 baseline == segmentFixtureImage( location)) ;
	}
	DRIVERCRATE_EXPECT( context, store.initialize( location / L"unrelated", true) == 170U &&
									store.root() == lease->store().root() / L"history") ;
	std::shared_ptr<const CollectorSegmentQuiescentSwitch> second ;	// 元閉鎖を参照で複製しません。
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, nextKey, utc, second) == 170U &&
						   !second) ;
	auto held = pending ;	// 出力参照を返しても最後の所有者までは閉鎖を保持します。
	pending.reset() ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, nextKey, utc, second) == 170U &&
						   !second) ;
	held.reset() ;
	// 元I/Oと確保例外を第一結果で返し、全失敗後の閉鎖返却を確認します。
	for( const DWORD stop : {5U, 8U, 13U, 68U, 1223U}) {
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepareQuiescent(
										parent, *lease, definition.sources, nextKey, utc, pending,
										[stop] { return stop ; }) == stop &&
										!pending && baseline == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSegmentPreparation::prepareQuiescent(
							   parent, *lease, definition.sources, nextKey, utc, pending) == 0U &&
							   pending) ;
		pending.reset() ;
	}

	DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepareQuiescent(
									parent, *lease, definition.sources, nextKey, utc, pending,
									[]() -> DWORD { throw std::bad_alloc{} ; }) == 8U &&
									!pending) ;
	DRIVERCRATE_EXPECT(
		context,
		LocalCollectorSegmentPreparation::prepareQuiescent(
			parent, *lease, definition.sources, nextKey, utc, pending,
			[&] {
				LocalCollectorRecovery blocked ;	// Reader借用中の再発行を拒否します。
				DRIVERCRATE_EXPECT( context,
								   blocked.initializeProjected( store, definition, utc, 0U) == 170U) ;
				DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepareQuiescent(
												parent, *lease, definition.sources, nextKey, utc,
												second) == 170U &&
												!second) ;
				return ERROR_SUCCESS ;
			}) == 0U &&
			pending) ;
	const auto alias =
		// 元出力寿命を同期保持します。
		std::wstring_view( pending->draft().intent.newSegment) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, alias, utc, pending) == 170U &&
						   !pending) ;
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, nextKey, utc, pending) == 0U &&
						   pending) ;
	pending.reset() ;
	{
		LocalCollectorRecovery owner ;	// 完了済み世代なので新予約は全てRETRYです。
		DRIVERCRATE_EXPECT( context, owner.initializeProjected( store, definition, utc, 0U) == 0U) ;
		std::vector<std::unique_ptr<CollectorHttpPermitPool>>
					pools ;		// 実64所有を同じ監督から登録します。
		std::size_t clocks{} ;	// 拒否65個目のclock未採取も確認します。
		// 永続予約なしでも持出し可能な固定poolの登録は上限まで保守的に保持します。
		for( std::size_t index = 0U; index < 65U; ++index) {
			auto				pool = std::make_unique<CollectorHttpPermitPool>( [&] {
				   ++clocks ;
				   return CollectorHttpClockSample{utc, 0U} ;
			   }) ;			// 全control確保は元予約より前です。
			CollectorHttpPermit permit ;	// 全RETRYで空です。
			DRIVERCRATE_EXPECT( context, pool->reserveProjected( owner, permit) ==
												(index < 64U ? 1237U : 68U) &&
											!permit.present()) ;
			pools.push_back( std::move( pool)) ;
		}

		DRIVERCRATE_EXPECT( context, clocks == 64U) ;
		LocalCollectorRecovery unrelated ;	// 別ownerを元poolへ混在させません。
		CollectorHttpPermit	   denied ;		// 拒否前から空です。
		DRIVERCRATE_EXPECT( context, pools.front()->reserveProjected( unrelated, denied) == 87U &&
										clocks == 64U && !denied.present()) ;
	}
	DRIVERCRATE_EXPECT( context,
					   LocalCollectorSegmentPreparation::prepareQuiescent(
						   parent, *lease, definition.sources, nextKey, utc, pending) == 0U &&
						   pending && baseline == segmentFixtureImage( location)) ;
	pending.reset() ;
	// Pool消滅後のpermitとclaim後controlを、それぞれ最後の実所有として確認します。
	for( const bool claim : {false, true}) {
		const auto isolated = rootFactory() / collectionKey ;	// 未完了v3の独立架空領域です。
		LocalCollectorCollectionStore isolatedParent ;			// 元成功fixtureを壊しません。
		DRIVERCRATE_EXPECT( context, isolatedParent.initialize( isolated, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> isolatedLease ;	// 同じ私有能力だけです。
		DRIVERCRATE_EXPECT(
			context, isolatedParent.borrowHistorySegment( segmentKey, true, isolatedLease) == 0U) ;
		CollectorHttpPermit					  permit ;	// Poolと監督より後まで実所有します。
		std::shared_ptr<CollectorHttpControl> control ;	// Claimした時だけ持ち出します。
		{
			LocalCollectorRecovery owner ;	// 元予約の監督です。
			DRIVERCRATE_EXPECT( context,
							   owner.initializeProjected( *isolatedLease->history(), definition,
														 HTTP_TEST_UTC, 0U) == 0U) ;
			CollectorHttpPermitPool pool(
				[] { return CollectorHttpClockSample{HTTP_TEST_UTC, 0U} ; }) ;	// 実発行元です。
			DRIVERCRATE_EXPECT( context,
							   pool.reserveProjected( owner, permit) == 0U && permit.present()) ;
			// Control持出しは元dispatchを一致させた一回claimだけで行います。
			if( claim) {
				control = permit.claim( &context, *permit.binding()) ;
				DRIVERCRATE_EXPECT( context, control != nullptr) ;
			}
		}
		const auto original = segmentFixtureImage( isolated) ;	// 未完了ROOTの元byteも保持します。
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepareQuiescent(
										isolatedParent, *isolatedLease, definition.sources, nextKey,
										utc, pending) == 170U &&
										!pending && original == segmentFixtureImage( isolated)) ;
		permit = CollectorHttpPermit{} ;
		// もう一つの実control所有者が残る場合だけ閉鎖を止めます。
		if( control) {
			DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepareQuiescent(
											isolatedParent, *isolatedLease, definition.sources,
											nextKey, utc, pending) == 170U &&
											!pending) ;
		}

		control.reset() ;
		// 所有0になっても未完了履歴を成功切替として採用しません。
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepareQuiescent(
										isolatedParent, *isolatedLease, definition.sources, nextKey,
										utc, pending) == 13U &&
										!pending && original == segmentFixtureImage( isolated)) ;
	}
}

/** @see local_collector_http_tests.h */
void runCollectorSegmentPreparationTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;				// 元二sourceだけの架空公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;						// 実端末identityではありません。
	const std::wstring segmentKey( 64U, L'2') ;							// 元一区間の架空keyです。
	const std::wstring nextKey( 64U, L'3') ;							// 存在しない次区間候補です。
	const auto		   location = rootFactory() / collectionKey ;		// 自作GUIDだけです。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;				// 元最高時計より後のacceptedです。
	std::shared_ptr<const CollectorSegmentPreparedSwitch> reference ;	// 再起動の期待値だけです。
	std::map<std::wstring, std::string>					  baseline ;	// 三scopeの全原byteです。
	{
		LocalCollectorCollectionStore parent ;	// 実唯一writerです。
		DRIVERCRATE_EXPECT( context, parent.initialize( location, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 元同親historyだけです。
		DRIVERCRATE_EXPECT( context, parent.borrowHistorySegment( segmentKey, true, lease) == 0U) ;
		// Fixture不成立を根拠なしの成功へ補完しません。
		if( !lease || !lease->history()) {
			throw std::runtime_error( "preparation fixture lease") ;
		}

		auto							  &store = *lease->history() ;	// 同親固定historyです。
		CollectorProjectedCampaignIdentity identity ;					// 元公開定義を再検査します。
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			campaign ;	// 全workerより長い寿命です。
		DRIVERCRATE_EXPECT(
			context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
						 prepareCollectorProjectedCampaign(
							 identity.canonicalInput, identity.inputSha256, identity.generationKey,
							 definition.artifactSha256, definition.sources, campaign)) ;
		// 未準備入力を実fake workerへ渡しません。
		if( !campaign) {
			throw std::runtime_error( "preparation fixture input") ;
		}

		std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実workerのfake 200です。
		DRIVERCRATE_EXPECT( context,
						   initialProjectedStorageFixture( context, store, definition, campaign, 0U,
														  {}, responses) == 0U) ;
		std::shared_ptr<const CollectorSegmentPreparedSwitch> pending ;	// 全失敗時は空です。
		{
			LocalCollectorRecovery owner ;	// 未完了／監督生存中は準備を拒否します。
			DRIVERCRATE_EXPECT( context, owner.initializeProjected(
											store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
			DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
											parent, *lease, definition.sources, nextKey, utc, true,
											pending) == 170U &&
											!pending) ;
			DRIVERCRATE_EXPECT( context,
							   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
		}

		const auto snapshot =
			// 元本文由来です。
			matchingSegmentFixture( context, store, collectionKey, segmentKey) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
		baseline = segmentFixtureImage( location) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentPreparation::prepare(
						 parent, *lease, definition.sources, nextKey, utc, true, reference) == 0U &&
						 reference) ;
		// 元根拠なしでoracleを参照しません。
		if( !reference) {
			throw std::runtime_error( "preparation fixture acceptance") ;
		}

		const auto &root  = reference->root().evidence() ;	// 今回のfresh根拠です。
		const auto &draft = reference->draft() ;			// 非保存の全出力です。
		const auto &i	  = draft.intent ;					// 独立JSONとの比較対象です。
		DRIVERCRATE_EXPECT(
			context,
			!std::is_default_constructible_v<CollectorSegmentPreparedSwitch::ConstructionKey>) ;
		DRIVERCRATE_EXPECT( context, i.collection == collectionKey && i.oldSegment == segmentKey &&
										i.newSegment == nextKey &&
										i.oldHead == root.shared->evidence().headSha256 &&
										i.oldRoot == root.history->evidence().rootSha256 &&
										i.seal == root.sealSha256 && i.accepted == utc &&
										i.ordinal == 1U &&
										i.ledger == root.shared->evidence().ledger &&
										i.inventory.size() == root.shards.size() &&
										i.inventory.front() == root.shards.front().sha256) ;
		CollectorSharedLedgerBytes bytes ;	// 期待値は元保存から読み取った全snapshotです。
		DRIVERCRATE_EXPECT( context, encodeCollectorSharedLedger( snapshot, bytes) == 0U) ;
		const auto bootstrap =
			// 独立JSON parserです。
			JsonObject::Parse( winrt::to_hstring( draft.bootstrap)) ;
		DRIVERCRATE_EXPECT( context, bootstrap.GetNamedArray( L"hashes").Size() == 66U) ;
		// 全66元本文を一行ずつ独立hashにし、draftとbootstrapの両方へ照合します。
		for( std::size_t index = 0U; index < 66U; ++index) {
			const auto	&body = index == 0U	  ? bytes.budget
								: index == 1U ? bytes.groups
											  : bytes.requests[index - 2U] ;	// 元順序です。
			std::wstring expected ;												// Draft内hashを期待値へ流用しません。
			DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( body, expected) == 0 &&
											draft.images[index] == expected &&
											bootstrap.GetNamedArray( L"hashes").GetStringAt(
												static_cast<std::uint32_t>( index)) == expected) ;
		}

		// 全非循環bodyの本文hashを独立に再計算します。
		for( const auto &[body, expected] :
			{std::pair<std::string, std::wstring>{draft.base, i.base},
			 {draft.bootstrap, i.bootstrap},
			 {draft.nextHead, i.nextHead},
			 {draft.intentBytes, draft.intentHash}}) {
			std::wstring hash ;	// 元全byteだけの指紋です。
			DRIVERCRATE_EXPECT( context,
							   computeCollectorMetadataSha256( body, hash) == 0 && hash == expected) ;
		}

		const auto base =
			// 全fieldの独立期待値です。
			JsonObject::Parse( winrt::to_hstring( draft.base)) ;
		const auto head = JsonObject::Parse(
			// 新ready headはまだ保存しません。
			winrt::to_hstring( draft.nextHead)) ;
		const auto intent =
			// 固定intentの全fieldです。
			JsonObject::Parse( winrt::to_hstring( draft.intentBytes)) ;
		DRIVERCRATE_EXPECT(
			context, base.Size() == 9U &&
						 base.GetNamedString( L"schema") == L"collector-segment-switch-base-v1" &&
						 base.GetNamedString( L"collection") == collectionKey &&
						 base.GetNamedString( L"segment") == nextKey &&
						 base.GetNamedNumber( L"ordinal") == 1.0 &&
						 base.GetNamedNumber( L"accepted") == static_cast<double>( utc) &&
						 base.GetNamedString( L"oldRoot") == i.oldRoot &&
						 base.GetNamedString( L"ledger") == i.ledger &&
						 base.GetNamedString( L"oldSegment") == segmentKey &&
						 base.GetNamedString( L"seal") == i.seal) ;
		DRIVERCRATE_EXPECT( context,
						   bootstrap.Size() == 13U &&
							   bootstrap.GetNamedString( L"schema") ==
								   L"collector-segment-switch-bootstrap-v1" &&
							   bootstrap.GetNamedString( L"collection") == collectionKey &&
							   bootstrap.GetNamedString( L"segment") == nextKey &&
							   bootstrap.GetNamedNumber( L"ordinal") == 1.0 &&
							   bootstrap.GetNamedNumber( L"accepted") == static_cast<double>( utc) &&
							   bootstrap.GetNamedString( L"oldRoot") == i.oldRoot &&
							   bootstrap.GetNamedString( L"ledger") == i.ledger &&
							   bootstrap.GetNamedString( L"oldSegment") == segmentKey &&
							   bootstrap.GetNamedString( L"seal") == i.seal &&
							   bootstrap.GetNamedString( L"oldHead") == i.oldHead &&
							   bootstrap.GetNamedString( L"base") == i.base &&
							   bootstrap.GetNamedArray( L"inventory").Size() == i.inventory.size() &&
							   bootstrap.GetNamedArray( L"inventory").GetStringAt( 0U) ==
								   root.shards.front().sha256) ;
		DRIVERCRATE_EXPECT(
			context, head.Size() == 11U &&
						 head.GetNamedString( L"schema") == L"collector-segment-switch-head-v1" &&
						 head.GetNamedString( L"collection") == collectionKey &&
						 head.GetNamedString( L"segment") == nextKey &&
						 head.GetNamedNumber( L"ordinal") == 1.0 &&
						 head.GetNamedNumber( L"revision") == 1.0 &&
						 head.GetNamedNumber( L"accepted") == static_cast<double>( utc) &&
						 head.GetNamedString( L"ledger") == i.ledger &&
						 head.GetNamedString( L"base") == i.base &&
						 head.GetNamedString( L"bootstrap") == i.bootstrap &&
						 head.GetNamedValue( L"commit").ValueType() ==
							 winrt::Windows::Data::Json::JsonValueType::Null &&
						 head.GetNamedArray( L"sealed").Size() == 1U &&
						 head.GetNamedArray( L"sealed").GetObjectAt( 0U).Size() == 2U &&
						 head.GetNamedArray( L"sealed").GetObjectAt( 0U).GetNamedString( L"segment") ==
							 segmentKey &&
						 head.GetNamedArray( L"sealed").GetObjectAt( 0U).GetNamedString( L"seal") ==
							 root.sealSha256) ;
		DRIVERCRATE_EXPECT( context,
						   intent.Size() == 14U &&
							   intent.GetNamedString( L"schema") == L"collector-segment-switch-v1" &&
							   intent.GetNamedString( L"collection") == collectionKey &&
							   intent.GetNamedString( L"oldSegment") == segmentKey &&
							   intent.GetNamedString( L"newSegment") == nextKey &&
							   intent.GetNamedString( L"oldHead") == i.oldHead &&
							   intent.GetNamedNumber( L"ordinal") == 1.0 &&
							   intent.GetNamedNumber( L"accepted") == static_cast<double>( utc) &&
							   intent.GetNamedString( L"ledger") == i.ledger &&
							   intent.GetNamedString( L"oldRoot") == i.oldRoot &&
							   intent.GetNamedString( L"seal") == i.seal &&
							   intent.GetNamedString( L"base") == i.base &&
							   intent.GetNamedString( L"bootstrap") == i.bootstrap &&
							   intent.GetNamedString( L"nextHead") == i.nextHead &&
							   intent.GetNamedArray( L"inventory").Size() == i.inventory.size() &&
							   intent.GetNamedArray( L"inventory").GetStringAt( 0U) ==
								   root.shards.front().sha256) ;
		DRIVERCRATE_EXPECT( context, baseline == segmentFixtureImage( location)) ;
		unsigned callbacks{} ;	// 拒否前に診断を呼ばない条件の分母です。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentPreparation::prepare( parent, *lease, definition.sources,
															   nextKey, utc, false, pending,
															   [&] {
																   ++callbacks ;
																   return ERROR_SUCCESS ;
															   }) == 13U &&
						 !pending && callbacks == 0U) ;
		// 有限keyの字句不正は借用や診断より前に拒否します。
		for( const auto &key : {std::wstring{}, std::wstring( 63U, L'3'), std::wstring( 65U, L'3'),
							   std::wstring( 64U, L'g'), std::wstring( 64U, L'A')}) {
			pending = reference ;
			DRIVERCRATE_EXPECT( context,
							   LocalCollectorSegmentPreparation::prepare(
								   parent, *lease, definition.sources, key, utc, true, pending,
								   [&] {
									   ++callbacks ;
									   return ERROR_SUCCESS ;
								   }) == 13U &&
								   !pending && callbacks == 0U) ;
		}

		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
										parent, *lease, definition.sources, segmentKey, utc, true,
										pending) == 13U &&
										!pending) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
										parent, *lease, {}, nextKey, utc, true, pending) == 13U &&
										!pending) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
										parent, *lease, definition.sources, nextKey,
										snapshot.lastUtcMillis - 1U, true, pending) == 13U &&
										!pending) ;
		// 元readerとcallbackの第一数値を内容拒否へ変えません。
		for( const DWORD stop : {5U, 8U, 13U, 68U, 1223U}) {
			pending = reference ;
			DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
											parent, *lease, definition.sources, nextKey, utc, true,
											pending, [stop] { return stop ; }) == stop &&
											!pending && baseline == segmentFixtureImage( location)) ;
		}

		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
										parent, *lease, definition.sources, nextKey, utc, true,
										pending, []() -> DWORD { throw std::bad_alloc{} ; }) == 8U &&
										!pending) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentPreparation::prepare(
						 parent, *lease, definition.sources, nextKey, utc, true, pending,
						 [&] {
							 std::shared_ptr<const CollectorSegmentPreparedSwitch>
								 nested ;	// 同じ借用へ再入します。
							 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
															 parent, *lease, definition.sources,
															 nextKey, utc, true, nested) == 170U &&
															 !nested) ;
							 return ERROR_SUCCESS ;
						 }) == 0U &&
						 pending && pending->draft().intentHash == draft.intentHash) ;
		std::wstring callerKey = nextKey ;	// 呼出し中の診断で変更しても入口の元値を保持します。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentPreparation::prepare( parent, *lease, definition.sources,
															   callerKey, utc, true, pending,
															   [&] {
																   callerKey.assign( 64U, L'9') ;
																   return ERROR_SUCCESS ;
															   }) == 0U &&
						 pending && pending->draft().intent.newSegment == nextKey) ;
		const std::weak_ptr<const CollectorSegmentPreparedSwitch> previousOwner =
			pending ;	// 旧出力だけが持つ寿命です。
		const std::wstring_view aliasedKey =
			// 出力内の借用keyです。
			pending->draft().intent.newSegment ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
										parent, *lease, definition.sources, aliasedKey, utc, true,
										pending) == 0U &&
										pending && pending->draft().intent.newSegment == nextKey &&
										previousOwner.expired()) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentPreparation::prepare(
										parent, *lease, definition.sources, nextKey,
										4102444800000ULL, true, pending) == 13U &&
										!pending) ;
		LocalCollectorCollectionStore other ;	// 別親能力を成功へ取り込みません。
		DRIVERCRATE_EXPECT( context,
						   other.initialize( rootFactory() / collectionKey, collectionKey) == 0U) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentPreparation::prepare(
						 other, *lease, definition.sources, nextKey, utc, true, pending) == 87U &&
						 !pending) ;
		// 全168原fileの各破損は準備前に拒否し、元破損状態も修復しません。
		for( const auto &[name, raw] : baseline) {
			alterSegmentFixture( location / name, "{}") ;
			const auto changed	= segmentFixtureImage( location) ;	// 改変済みの非変更期待値です。
			pending				= reference ;
			const auto rejected = LocalCollectorSegmentPreparation::prepare(
				parent, *lease, definition.sources, nextKey, utc, true,
				pending) ;	// 元先着数値です。
			DRIVERCRATE_EXPECT( context, rejected != 0U && !pending &&
											changed == segmentFixtureImage( location)) ;
			alterSegmentFixture( location / name, raw) ;
		}

		// 各scopeの終端改変／正規ACL未知追加は最終再検査で拒否します。
		for( const auto &target : {location / L"current/collection-head-v1.json",
								  lease->store().root() / L"current/segment-shared-base-v1.json",
								  store.root() / L"current/campaign-root-v2.json"}) {
			const auto original =
				// 元rawです。
				baseline.at( target.lexically_relative( location).generic_wstring()) ;
			DRIVERCRATE_EXPECT( context,
							   LocalCollectorSegmentPreparation::prepare(
								   parent, *lease, definition.sources, nextKey, utc, true, pending,
								   [&] {
									   alterSegmentFixture( target, "{}") ;
									   return ERROR_SUCCESS ;
								   }) == 13U &&
								   !pending) ;
			alterSegmentFixture( target, original) ;
			const auto addition = target.parent_path() /
								  L"unknown-preparation-fixture.json" ;	// 自作追加fileだけです。
			DRIVERCRATE_EXPECT( context,
							   LocalCollectorSegmentPreparation::prepare(
								   parent, *lease, definition.sources, nextKey, utc, true, pending,
								   [&] {
									   alterSegmentFixture( addition, "{}") ;
									   copySegmentFixtureDacl( target, addition) ;
									   return ERROR_SUCCESS ;
								   }) == 13U &&
								   !pending) ;
			DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( addition))) ;
			HANDLE blocked = INVALID_HANDLE_VALUE ;	// 同じ自作fileだけに共有拒否を注入します。
			DRIVERCRATE_EXPECT(
				context, LocalCollectorSegmentPreparation::prepare(
							 parent, *lease, definition.sources, nextKey, utc, true, pending,
							 [&] {
								 blocked = CreateFileW( segmentFixturePath( target).c_str(),
													   GENERIC_READ, 0U, nullptr, OPEN_EXISTING,
													   FILE_ATTRIBUTE_NORMAL, nullptr) ;
								 return blocked == INVALID_HANDLE_VALUE ? GetLastError()
																		: ERROR_SUCCESS ;
							 }) == ERROR_SHARING_VIOLATION &&
							 !pending) ;
			// 自分が開いた故障handleだけを検査後に解放します。
			if( blocked != INVALID_HANDLE_VALUE) {
				const BOOL closed =
					// 自己所有の故障handleを一回だけ解放する。
					CloseHandle( blocked) ;
				DRIVERCRATE_EXPECT( context, closed != FALSE) ;
			}
		}

		// 翌日acceptedでも元日予算／control／CACHEの保存byteを変更しません。
		DRIVERCRATE_EXPECT(
			context,
			LocalCollectorSegmentPreparation::prepare( parent, *lease, definition.sources, nextKey,
													  utc + 86400000U, true, pending) == 0U &&
				pending && pending->draft().images == draft.images &&
				pending->draft().intent.ledger == i.ledger &&
				pending->draft().intent.accepted == utc + 86400000U &&
				pending->root().evidence().history->evidence().rootUtcMillis ==
					snapshot.lastUtcMillis &&
				baseline == segmentFixtureImage( location)) ;
	}
	{
		LocalCollectorCollectionStore reopened ;	// 全旧能力を解放後だけ再起動します。
		DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 既存専用区間を非作成で開きます。
		DRIVERCRATE_EXPECT( context, reopened.borrowHistorySegment( segmentKey, false, lease) == 0U) ;
		std::shared_ptr<const CollectorSegmentPreparedSwitch>
			fresh ;	// 過去contextを入口へ戻しません。
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentPreparation::prepare( reopened, *lease, definition.sources,
															   nextKey, utc, true, fresh) == 0U &&
						 fresh && fresh->draft().intentHash == reference->draft().intentHash &&
						 fresh->root().evidence().seal == reference->root().evidence().seal &&
						 baseline == segmentFixtureImage( location)) ;
	}
}

/** @see local_collector_http_tests.h */
void runCollectorSegmentInventoryTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory)
{
	const auto		   definition = definitionFactory() ;			// 元二sourceだけのfake公開入力です。
	const std::wstring collectionKey( 64U, L'1') ;					// 実端末identityではありません。
	const std::wstring segmentKey( 64U, L'2') ;						// ROOT keyと別の配置keyです。
	const auto		   location = rootFactory() / collectionKey ;	// 自作GUID祖先だけです。
	const auto		   utc		= HTTP_TEST_UTC + 128000U ;			// 元最高時計より後の非変更検査時計です。
	std::shared_ptr<const CollectorSegmentRootInventory> proof ;	// 失敗時消去も検査します。
	std::map<std::wstring, std::string> historyRaw ;				// 個別不一致fixtureの元rawです。
	CollectorSharedLedgerSnapshot		snapshot ;					// 元保存本文から作る独立期待値です。
	std::map<std::wstring, std::string> baseline ;					// 全三scopeの元保存byteです。
	{
		LocalCollectorCollectionStore parent ;	// 元唯一writerです。
		DRIVERCRATE_EXPECT( context, parent.initialize( location, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 先にhistoryを閉じる能力です。
		DRIVERCRATE_EXPECT( context, parent.borrowHistorySegment( segmentKey, true, lease) == 0U) ;
		// Fixture準備の不成立を後続assertionへ広げません。
		if( !lease || !lease->history()) {
			throw std::runtime_error( "segment fixture lease") ;
		}

		auto							  &store = *lease->history() ;	// 元固定history writerです。
		CollectorProjectedCampaignIdentity identity ;					// 元公開入力のidentityです。
		std::shared_ptr<const CollectorPreparedProjectedCampaign>
			prepared ;	// workerより長く保持します。
		DRIVERCRATE_EXPECT(
			context, makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
						 prepareCollectorProjectedCampaign(
							 identity.canonicalInput, identity.inputSha256, identity.generationKey,
							 definition.artifactSha256, definition.sources, prepared)) ;
		// 未準備入力から成功履歴を作りません。
		if( !prepared) {
			throw std::runtime_error( "segment fixture input") ;
		}

		std::array<CollectorProjectedResponseBytes, 2U> responses ;	// 実workerのfake 200です。
		DRIVERCRATE_EXPECT( context,
						   initialProjectedStorageFixture( context, store, definition, prepared, 0U,
														  {}, responses) == 0U) ;
		{
			LocalCollectorRecovery owner ;	// 借用中は新結合入口も170です。
			DRIVERCRATE_EXPECT( context, owner.initializeProjected(
											store, definition, HTTP_TEST_UTC + 126000U, 0U) == 0U) ;
			DRIVERCRATE_EXPECT(
				context, LocalCollectorSegmentInventory::inspect( parent, *lease, definition.sources,
																 utc, proof) == 170U &&
							 !proof) ;
			DRIVERCRATE_EXPECT( context,
							   owner.finishInitialProjected( HTTP_TEST_UTC + 127000U, 1000U) == 0U) ;
		}
		historyRaw = projectedStoreSnapshot( context, store) ;
		snapshot   = matchingSegmentFixture( context, store, collectionKey, segmentKey) ;
		DRIVERCRATE_EXPECT( context,
						   LocalCollectorSharedStore::bootstrap( parent, *lease, snapshot) == 0U) ;
		baseline			= segmentFixtureImage( location) ;
		const auto accepted = LocalCollectorSegmentInventory::inspect(
			parent, *lease, definition.sources, utc, proof) ;	// 新入口の第一数値です。
		context.expect( accepted == 0U && proof, "segment accept code=" + std::to_string( accepted),
					   __FILE__, __LINE__) ;
		// 根拠なしでoracleを参照しません。
		if( !proof) {
			throw std::runtime_error( "segment fixture acceptance") ;
		}

		const auto &evidence = proof->evidence() ;				// 検査済み所有値だけです。
		const auto &history	 = evidence.history->evidence() ;	// 元history scopeです。
		const auto &shared	 = evidence.shared->evidence() ;	// 元親／子scopeです。
		const auto	seal =
			// 独立JSON oracleです。
			JsonObject::Parse( winrt::to_hstring( evidence.seal)) ;
		std::wstring digest ;	// 期待hashをcontext内hashへ流用しません。
		DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( evidence.seal, digest) == 0 &&
										digest == evidence.sealSha256 &&
										evidence.seal.size() <= 16U * 1024U) ;
		DRIVERCRATE_EXPECT(
			context,
			seal.Size() == 22U &&
				seal.GetNamedString( L"schema") == L"collector-segment-root-seal-v1" &&
				seal.GetNamedString( L"collection") == collectionKey &&
				seal.GetNamedString( L"segment") == segmentKey &&
				seal.GetNamedString( L"rootKey") == history.rootKey &&
				seal.GetNamedString( L"root") == history.rootSha256 &&
				seal.GetNamedString( L"historySeal") == history.sealSha256 &&
				seal.GetNamedString( L"sharedSeal") == shared.sealSha256 &&
				seal.GetNamedString( L"head") == shared.headSha256 &&
				seal.GetNamedString( L"ledger") == shared.ledger &&
				seal.GetNamedNumber( L"rootUtc") == static_cast<double>( snapshot.lastUtcMillis) &&
				seal.GetNamedNumber( L"inspectedUtc") == static_cast<double>( utc) &&
				seal.GetNamedNumber( L"generations") == 1.0 &&
				seal.GetNamedNumber( L"historyOperations") == 2.0 &&
				seal.GetNamedNumber( L"sharedOperations") == 0.0 &&
				seal.GetNamedNumber( L"cacheCount") == 2.0 &&
				seal.GetNamedNumber( L"historyFiles") == static_cast<double>( history.files.size()) &&
				seal.GetNamedNumber( L"sharedFiles") == static_cast<double>( shared.files.size()) &&
				seal.GetNamedNumber( L"historyBytes") == static_cast<double>( history.fileBytes) &&
				seal.GetNamedNumber( L"sharedBytes") == static_cast<double>( shared.fileBytes)) ;
		DRIVERCRATE_EXPECT(
			context,
			history.budgetBody == httpSavedBody( store, L"current/campaign-budget-v1.json") &&
				history.controlBody == httpSavedBody( store, L"current/campaign-controls-v1.json") &&
				history.caches.size() == 2U && baseline == segmentFixtureImage( location)) ;
		DRIVERCRATE_EXPECT(
			context,
			evidence.files.size() == baseline.size() &&
				evidence.files.size() == history.files.size() + shared.files.size() &&
				evidence.shards.size() == 1U &&
				seal.GetNamedNumber( L"fileCount") == static_cast<double>( baseline.size()) &&
				seal.GetNamedNumber( L"fileBytes") == static_cast<double>( evidence.fileBytes) &&
				seal.GetNamedArray( L"inventory").Size() == evidence.shards.size()) ;
		std::size_t			   ordinal = 0U ;	// 全shardをまたぐ元raw行の順序です。
		std::uint64_t		   bytes   = 0U ;	// 独立rawからの全byte合計です。
		std::set<std::wstring> seen ;			// 別scopeを含む完全名の重複を拒否します。
		// すべての有限区間shardを独立JSON／実rawへ照合します。
		for( const auto &shard : evidence.shards) {
			const auto rows =
				// 本番writerをoracleにしません。
				JsonObject::Parse( winrt::to_hstring( shard.body)) ;
			DRIVERCRATE_EXPECT(
				context,
				computeCollectorMetadataSha256( shard.body, digest) == 0 && digest == shard.sha256 &&
					seal.GetNamedArray( L"inventory")
							.GetStringAt( static_cast<std::uint32_t>( ordinal / 512U)) == digest &&
					rows.GetNamedString( L"schema") == L"collector-segment-root-inventory-v1" &&
					rows.GetNamedString( L"collection") == collectionKey &&
					rows.GetNamedString( L"segment") == segmentKey &&
					rows.GetNamedNumber( L"ordinal") == static_cast<double>( ordinal / 512U) &&
					rows.GetNamedNumber( L"fileCount") == static_cast<double>( baseline.size()) &&
					shard.body.size() <= 256U * 1024U) ;
			// 全行を元三scopeの実raw名／hash／sizeへ一対一に結合します。
			for( const auto &value : rows.GetNamedArray( L"files")) {
				const auto	row	 = value.GetObject() ;				// このordinalの一rawです。
				const auto &file = evidence.files.at( ordinal) ;	// 同じ所有値の順序です。
				const auto	name = file.scope == L"parent"
									   ? file.name
									   : L"segments/" + segmentKey + L"/" +
											 (file.scope == L"history" ? L"history/" : L"") +
											 file.name ;	// scope別の完全名です。
				const auto &raw	 = baseline.at( name) ;		// 元全byteを独立に保持しています。
				DRIVERCRATE_EXPECT( context, computeCollectorMetadataSha256( raw, digest) == 0 &&
												digest == file.sha256 && file.bytes == raw.size() &&
												seen.insert( name).second && row.Size() == 4U &&
												row.GetNamedString( L"scope") == file.scope &&
												row.GetNamedString( L"name") == file.name &&
												row.GetNamedString( L"sha256") == digest &&
												row.GetNamedNumber( L"bytes") ==
													static_cast<double>( raw.size())) ;
				bytes += raw.size() ;
				++ordinal ;
			}
		}

		DRIVERCRATE_EXPECT( context, ordinal == baseline.size() && seen.size() == baseline.size() &&
										bytes == evidence.fileBytes) ;
		DRIVERCRATE_EXPECT(
			context,
			!std::is_default_constructible_v<CollectorSegmentRootInventory::ConstructionKey>) ;
		std::shared_ptr<const CollectorSegmentRootInventory> repeated =
			proof ;	// 旧出力の消去対象です。
		// 元数値を変更せず、全停止で借用が戻ることを後続成功で確認します。
		for( const DWORD stop : {5U, 1223U, 13U, 68U, 8U}) {
			DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
											parent, *lease, definition.sources, utc, repeated,
											[stop] { return stop ; }) == stop &&
											!repeated && baseline == segmentFixtureImage( location)) ;
		}

		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
										parent, *lease, definition.sources, utc, repeated,
										[]() -> DWORD { throw std::bad_alloc() ; }) == 8U &&
										!repeated) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentInventory::inspect(
						 parent, *lease, definition.sources, utc, repeated,
						 [&] {
							 std::shared_ptr<const CollectorSegmentRootInventory>
								 nested ;	// 同一historyの再入です。
							 std::shared_ptr<const CollectorSharedRootInventory>
								 child ;	// 共有借用も保持中です。
							 std::shared_ptr<const CollectorCompletedRootInventory>
								 original ;	// 履歴借用も保持中です。
							 DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
															 parent, *lease, definition.sources,
															 utc, nested) == 170U &&
															 !nested) ;
							 DRIVERCRATE_EXPECT(
								 context, LocalCollectorSharedStore::inspectSharedRootInventory(
											  parent, *lease, utc, child) == 170U &&
											  !child) ;
							 DRIVERCRATE_EXPECT(
								 context, LocalCollectorRecovery::inspectCompletedRootInventory(
											  store, definition.sources, utc, original) == 170U &&
											  !original) ;
							 DRIVERCRATE_EXPECT( context, LocalCollectorSharedStore::bootstrap(
															 parent, *lease, snapshot) == 170U) ;
							 return ERROR_SUCCESS ;
						 }) == 0U &&
						 repeated && repeated->evidence().seal == evidence.seal &&
						 baseline == segmentFixtureImage( location)) ;
		std::shared_ptr<const CollectorSharedRootInventory>
			borrowedShared ;	// 公開readerで共有借用を競合させます。
		DRIVERCRATE_EXPECT( context, LocalCollectorSharedStore::inspectSharedRootInventory(
										parent, *lease, utc, borrowedShared,
										[&] {
											DRIVERCRATE_EXPECT(
												context, LocalCollectorSegmentInventory::inspect(
															 parent, *lease, definition.sources,
															 utc, repeated) == 170U &&
															 !repeated) ;
											return ERROR_SUCCESS ;
										}) == 0U &&
										borrowedShared) ;
		LocalCollectorCollectionStore other ;	// 別親能力を成功へ採用しません。
		DRIVERCRATE_EXPECT( context,
						   other.initialize( rootFactory() / collectionKey, collectionKey) == 0U) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
										other, *lease, definition.sources, utc, repeated) == 87U &&
										!repeated) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect( parent, *lease, {}, utc,
																			repeated) == 13U &&
										!repeated) ;
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
										parent, *lease, definition.sources,
										snapshot.lastUtcMillis - 1U, repeated) == 13U &&
										!repeated) ;
		// 全三scopeの全存在rawを一つずつ破損させ、自己hashや本文の成功を注入しません。
		for( const auto &[name, raw] : baseline) {
			alterSegmentFixture( location / name, "{}") ;
			const auto changed =
				// 改変そのもの以外の非保存を確認します。
				segmentFixtureImage( location) ;
			repeated			= proof ;
			const auto rejected = LocalCollectorSegmentInventory::inspect(
				parent, *lease, definition.sources, utc, repeated) ;	// 先着拒否です。
			context.expect( rejected != 0U && !repeated && changed == segmentFixtureImage( location),
						   "segment raw " + winrt::to_string( name) +
							   " code=" + std::to_string( rejected),
						   __FILE__, __LINE__) ;
			alterSegmentFixture( location / name, raw) ;
		}

		// 両再検査でしか検出できない終端改変／追加／実sharingをscope別に測ります。
		for( const auto &target : {location / L"current/collection-head-v1.json",
								  lease->store().root() / L"current/segment-shared-base-v1.json",
								  store.root() / L"current/campaign-root-v2.json"}) {
			const auto name =
				// 元明示fileです。
				target.lexically_relative( location).generic_wstring() ;
			const auto original = baseline.at( name) ;	// callback後にだけ復元します。
			DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
											parent, *lease, definition.sources, utc, repeated,
											[&] {
												alterSegmentFixture( target, "{}") ;
												return ERROR_SUCCESS ;
											}) == 13U &&
											!repeated) ;
			alterSegmentFixture( target, original) ;
			const auto addition =
				// 自作追加fileだけです。
				target.parent_path() / L"unknown-segment-fixture.json" ;
			// 不正な継承ACLの元5と、正規ACLでも未知名である元13を独立に測ります。
			for( const bool protectedDacl : {false, true}) {
				const auto added = LocalCollectorSegmentInventory::inspect(
					parent, *lease, definition.sources, utc, repeated, [&] {
						alterSegmentFixture( addition, "{}") ;
						// 自作未知fileだけを正規DACLへ合わせて意味拒否を分離します。
						if( protectedDacl) {
							copySegmentFixtureDacl( target, addition) ;
						}

						return ERROR_SUCCESS ;
					}) ; // 元先着errorを改変せず診断します。
				const DWORD expected = protectedDacl ? ERROR_INVALID_DATA
													 : ERROR_ACCESS_DENIED ;	// 別拒否を区別します。
				context.expect( added == expected && !repeated,
							   "segment final addition code=" + std::to_string( added), __FILE__,
							   __LINE__) ;
				DRIVERCRATE_EXPECT( context, std::filesystem::remove( segmentFixturePath( addition))) ;
			}

			HANDLE blocked = INVALID_HANDLE_VALUE ;	// 自分の故障用handleだけを閉じます。
			DRIVERCRATE_EXPECT(
				context, LocalCollectorSegmentInventory::inspect(
							 parent, *lease, definition.sources, utc, repeated,
							 [&] {
								 blocked = CreateFileW( segmentFixturePath( target).c_str(),
													   GENERIC_READ, 0U, nullptr, OPEN_EXISTING,
													   FILE_ATTRIBUTE_NORMAL, nullptr) ;
								 return blocked == INVALID_HANDLE_VALUE ? GetLastError()
																		: ERROR_SUCCESS ;
							 }) == ERROR_SHARING_VIOLATION &&
							 !repeated) ;
			// 故障handleは最終再検査の後に解放します。
			if( blocked != INVALID_HANDLE_VALUE) {
				const BOOL closed =
					// 自己所有の故障handleを一回だけ解放する。
					CloseHandle( blocked) ;
				DRIVERCRATE_EXPECT( context, closed != FALSE) ;
			}
		}

		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
										parent, *lease, definition.sources, utc, repeated) == 0U &&
										repeated && repeated->evidence().seal == evidence.seal &&
										baseline == segmentFixtureImage( location)) ;
	}
	{
		LocalCollectorCollectionStore reopened ;	// 元ownerを完全解放後だけ再開します。
		DRIVERCRATE_EXPECT( context, reopened.initialize( location, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 非作成の元同親historyです。
		DRIVERCRATE_EXPECT( context, reopened.borrowHistorySegment( segmentKey, false, lease) == 0U) ;
		std::shared_ptr<const CollectorSegmentRootInventory>
			fresh ;	// 旧根拠の再利用ではありません。
		DRIVERCRATE_EXPECT( context, LocalCollectorSegmentInventory::inspect(
										reopened, *lease, definition.sources, utc, fresh) == 0U &&
										fresh && fresh->evidence().seal == proof->evidence().seal) ;
		DRIVERCRATE_EXPECT(
			context, LocalCollectorSegmentInventory::inspect( reopened, *lease, definition.sources,
															 utc + 1U, fresh) == 0U &&
						 fresh && fresh->evidence().seal != proof->evidence().seal &&
						 baseline == segmentFixtureImage( location)) ;
	}
	// 単独共有readerが合格する一項目の相違を、別の実保護rootで結合readerだけが拒否します。
	for( unsigned scenario = 0U; scenario < 18U; ++scenario) {
		auto  altered = snapshot ;							// 同じ元値から一条件だけ変更します。
		auto &group	  = altered.groups.begin()->second ;	// 元第一groupです。
		auto &request = altered.requests.begin()->second ;	// 元第一requestです。
		// 一つの相違を元型の有効範囲内で作り、共有単独の失敗へ依存しません。
		switch( scenario) {
			case 0U:	// 最高UTCの不一致。
				++altered.lastUtcMillis ;
				break ;

			case 1U:	// 元実受領量の不一致。
				++altered.budget.reservations.front().charged ;
				break ;

			case 2U:	// 同じ予約集合の元順序の不一致。
				std::reverse( altered.budget.reservations.begin(),
							 altered.budget.reservations.end()) ;
				break ;

			case 3U:	// 元予算最高時計の不一致。
				--altered.budget.lastUtc ;
				break ;

			case 4U:	// Group要確認の不一致。
				group.review = !group.review ;
				break ;

			case 5U:	// Group待機の不一致。
				group.notBefore += 1000U ;
				break ;

			case 6U:	// Group元完了観測の不一致。
				group.completed = 0U ;
				break ;

			case 7U:	// Group最高観測の不一致。
				++group.observed ;
				break ;

			case 8U:	// Request要確認の不一致。
				request.control.review = !request.control.review ;
				break ;

			case 9U:	// Request待機の不一致。
				request.control.notBefore += 1000U ;
				break ;

			case 10U:	// Request最高観測の不一致。
				++request.control.observed ;
				break ;

			case 11U:	// 旧区間の参照を現区間根拠へ代用しません。
				request.cache->segment = std::wstring( 64U, L'3') ;
				break ;

			case 12U:	// CACHE本文hashだけの不一致。
				request.cache->cacheSha256 = std::wstring( 64U, L'3') ;
				break ;

			case 13U:	// Bindingだけの不一致。
				request.cache->binding = std::wstring( 64U, L'3') ;
				break ;

			case 14U:	// 存在すべき元参照の欠損。
				request.cache.reset() ;
				break ;

			// 元にないgroup集合の混入を検査します。
			case 15U: {
				auto extra	= group ;	// 有効な元controlを別groupへ結合します。
				extra.group = L"fixture-extra" ;
				altered.groups.emplace( extra.group, extra) ;
				break ;
			}
			// 元にないrequest集合の混入を検査します。
			case 16U: {
				auto extra			  = request ;	// 開始intentは元の空値です。
				extra.control.request = std::wstring( 64U, L'f') ;
				extra.cache.reset() ;
				altered.requests.emplace( extra.control.request, extra) ;
				break ;
			}
			case 17U:	// 元request集合の欠損。
				altered.requests.erase( altered.requests.begin()) ;
				break ;

			default:	// 有限fixture集合外へ成功条件を拡張しません。
				throw std::runtime_error( "segment fixture scenario") ;
		}

		LocalCollectorCollectionStore parent ;				// 条件ごとの独立writerです。
		const auto root = rootFactory() / collectionKey ;	// 元正本は変更しません。
		DRIVERCRATE_EXPECT( context, parent.initialize( root, collectionKey) == 0U) ;
		std::unique_ptr<LocalCollectorSegmentLease> lease ;	// 元v3 byteを複製する固定領域です。
		DRIVERCRATE_EXPECT( context, parent.borrowHistorySegment( segmentKey, true, lease) == 0U) ;
		// 正常な元履歴は全byteで複製し、同親履歴はcaller contextから受け取りません。
		for( const auto &[name, raw] : historyRaw) {
			DRIVERCRATE_EXPECT( context, lease->history()->write( name, raw) == 0U) ;
		}

		const auto boot =
			// 独立した有効台帳です。
			LocalCollectorSharedStore::bootstrap( parent, *lease, altered) ;
		context.expect( boot == 0U,
					   "segment mismatch bootstrap " + std::to_string( scenario) +
						   " code=" + std::to_string( boot),
					   __FILE__, __LINE__) ;
		std::shared_ptr<const CollectorSharedRootInventory>
			shared ;	// 単独共有根拠は成功する必要があります。
		DRIVERCRATE_EXPECT( context, LocalCollectorSharedStore::inspectSharedRootInventory(
										parent, *lease, utc, shared) == 0U &&
										shared) ;
		const auto before	= segmentFixtureImage( root) ;	// 拒否しても元の相違を修復しません。
		auto	   rejected = proof ;						// 旧成功contextを必ず消去します。
		const auto code		= LocalCollectorSegmentInventory::inspect(
			parent, *lease, definition.sources, utc, rejected) ;	// 値不一致の先着errorです。
		context.expect( code == 13U && !rejected && before == segmentFixtureImage( root),
					   "segment mismatch " + std::to_string( scenario) +
						   " code=" + std::to_string( code),
					   __FILE__, __LINE__) ;
	}
}

/** @see local_collector_http_tests.h */
void runCollectorProjectedHttpTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory,
	const std::function<CollectorProjectedCampaignDefinition()> &definitionFactory,
	const bool													 fingerprintOnly)
{
	// Workerで使用する同じ非所有判定を先に確認する。
	projectedRelationChecks( context) ;
	// 保存前にも用いる実配列の共通件数境界。
	projectedCountChecks( context) ;
	const auto definition	 = definitionFactory() ;	// 二sourceを同じ元manifestから固定する。
	const auto identityOwner = std::make_unique<
		CollectorProjectedCampaignIdentity>() ;	// 同じscopeだけで大きなfixtureを所有する。
	auto &identity = *identityOwner ;			// 元jobの所有scopeをHTTP結果と照合する。
	DRIVERCRATE_EXPECT( context,
					   makeCollectorProjectedCampaignIdentity( definition, L"20260927", identity) &&
						   identity.jobs.size() == 2U) ;
	// 準備失敗を後続の架空成功に変換しない。
	if( identity.jobs.size() != 2U) {
		return ;
	}

	std::shared_ptr<const CollectorPreparedProjectedCampaign> prepared ;	// 元保存入力だけから準備。
	DRIVERCRATE_EXPECT( context,
					   prepareCollectorProjectedCampaign(
						   identity.canonicalInput, identity.inputSha256, identity.generationKey,
						   definition.artifactSha256, definition.sources, prepared) &&
						   prepared && prepared->jobCount() == 2U) ;
	// 準備型なしで偽HTTPを成功扱いにしない。
	if( !prepared || prepared->jobCount() != 2U) {
		return ;
	}

	// 指紋訂正の限定枠では既確認の保存/回復全枠を重複して実行しません。
	if( !fingerprintOnly) {
		projectedWorkerChecks( context, rootFactory, definition, prepared) ;
		projectedParentChecks( context, rootFactory, definition, prepared) ;
		projectedHistoryReservationChecks( context, rootFactory, definition, prepared) ;
		registeredProjectedHistoryChecks( context, rootFactory, definition) ;
		initialProjectedStorageChecks( context, rootFactory, definition, prepared) ;
		generationCompletionChecks( context, rootFactory, definition, prepared) ;
		allCompletedHistoryChecks( context, rootFactory, definition, prepared) ;
		completedEmptyCacheChecks( context, rootFactory, definition, prepared) ;
		nextProjectedGenerationChecks( context, rootFactory, definition, prepared) ;
		nextProjectedStorageChecks( context, rootFactory, definition, prepared) ;
		nextProjectedPreparedRecoveryChecks( context, rootFactory, definition, prepared) ;
	}

	projectedFaultChecks( context, rootFactory, definition) ;
	// ASUSの大規模境界は既定全枠だけで従来の順序を維持します。
	if( !fingerprintOnly) {
		projectedLargeAsusWorkerChecks( context, rootFactory, definition) ;
	}

	// 正常200、無条件304、read故障、空200、不正UTF-8、未pin validator、別scope／job、空permitを分離する。
	for( std::size_t source = 0U; source < (fingerprintOnly ? 0U : 2U); ++source) {
		// 各source内の故障を独立storeとpermitで再現する。
		for( unsigned mode = 0U; mode < 11U; ++mode) {
			const auto fixtureOwner =
				std::make_unique<IoFixture>() ;		// 同じscopeだけで大きなfixtureを所有する。
			auto		&fixture = *fixtureOwner ;	// 一条件一threadの完全fake依存。
			FixtureScope scope( fixture) ;			// Native APIへ流入しない。
			// 各失敗を同じ公開requestの原GETへ注入する。
			switch( mode) {
				// 無条件304は元200を持たないため拒否する。
				case 1:
					fixture.status = 304U ;
					break ;

				// 最初のreadでnative errorを返す。
				case 2:
					fixture.failure = "read" ;
					break ;

				// 空200から本文型を作らない。
				case 3:
					fixture.body.clear() ;
					break ;

				// 不正UTF-8を置換decodeしない。
				case 4:
					fixture.body = std::string( 1U, static_cast<char>( 0xff)) ;
					break ;

				// 正常200・送信前拒否のfixture本文は変更しない。
				default:
					break ;
			}

			LocalCollectorStateStore store ;	// 旧root・別caseへ干渉しない保護store。
			DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
			LocalCollectorRecovery recovery ;	// 同じ元inputからの実永続予約。
			DRIVERCRATE_EXPECT(
				context, recovery.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
			CollectorHttpPermitPool pool( [&fixture] { return fixture.clock ; }) ;	// 元二時計。
			CollectorHttpPermit		permit ;										// GET許可は保存後だけ発行。
			CollectorHttpPermit		emptyPermit ;									// 未発行のまま使う拒否条件。
			// 別sourceのため先行jobを予約し、二番目の許可を使う。
			if( source == 1U) {
				CollectorHttpPermit first ;	// 回収前の第一slotを保持する。
				DRIVERCRATE_EXPECT( context, pool.reserveProjected( recovery, first) == 0U) ;
				DRIVERCRATE_EXPECT( context, pool.reserveProjected( recovery, permit) == 0U) ;
			} else {
				DRIVERCRATE_EXPECT( context, pool.reserveProjected( recovery, permit) == 0U) ;
			}

			// 許可欠損で空参照せず当該条件を失敗で保持する。
			if( permit.binding() == nullptr) {
				DRIVERCRATE_EXPECT( context, false) ;
				continue ;
			}

			const auto bindingOwner =
				std::make_unique<std::remove_cvref_t<decltype( *permit.binding())>>(
					*permit.binding()) ;	// 同じ元値をこのscopeで所有する。

			auto &binding =
				*bindingOwner ;									// 元と同じ期間だけ結果を借用する。				// 元永続予約の全field。
			const auto &job = prepared->job( source)->value() ;	// 不変の全対象scope。
			// 偽の全対象scopeを元予約から流用しない。
			if( mode == 6U) {
				binding.scopeSha256 = std::wstring( 64U, L'b') ;
			}

			LocalCollectorHttpClient			 client( fixtureHttp(), fixtureDns()) ;	// 完全fake。
			std::optional<CollectorMetadataBody> body ;									// 正常200だけに構築。
			const auto							 observationOwner = std::make_unique<
										  CollectorControlledHttpObservation>() ;	// 同じscopeだけで大きなfixtureを所有する。
			auto &observation = *observationOwner ;									// 原status・受信量。
			std::shared_ptr<CollectorHttpControl> control ;							// Claim後の所有制御。
			// 取消し注入にも使う同一pointer。
			fixture.control = &control ;
			const auto tag	= mode == 5U ? std::wstring_view( L"\"revision1\"")
										 : std::wstring_view{} ;	// 未pinの条件付きGETだけ拒否。
			// 元予約とfake nativeの一回GETだけを呼ぶ。
			const auto error	 = client.getMetadataBody( *prepared, source, binding,
													  mode == 8U ? emptyPermit : permit, tag, body,
														  observation, control) ;
			const bool preflight = mode == 5U || mode == 6U || mode == 8U ;	// 送信前拒否。
			const auto label	 = "projected HTTP " + std::to_string( source) + "/" +
							   // URLを含まない診断。
							   std::to_string( mode) ;
			context.expect( (error == 0U) == (mode == 0U || mode == 7U || mode == 9U || mode == 10U),
						   label, __FILE__, __LINE__) ;
			DRIVERCRATE_EXPECT( context,
							   fixture.valid && fixture.calls["send"] == (preflight ? 0U : 1U)) ;
			DRIVERCRATE_EXPECT( context, (control == nullptr) == preflight &&
											body.has_value() == (mode == 0U || mode == 7U ||
																 mode == 9U || mode == 10U)) ;
			// 元200の本文・raw hash・時刻・全対象scopeを同じ予約に結合する。
			if( (mode == 0U || mode == 7U || mode == 9U || mode == 10U) && body) {
				std::wstring hash ;	// Fake raw byteから独立再計算。
				DRIVERCRATE_EXPECT( context, computeBytesSha256( fixture.body, hash) == 0U) ;
				DRIVERCRATE_EXPECT( context,
								   body->text() == L"abc" && body->bodySha256() == hash &&
									   body->headerUtcMillis() == HTTP_TEST_UTC &&
									   body->validatedUtcMillis() >= body->headerUtcMillis() &&
									   sameCollectorRecoveryDispatch( body->binding(), binding) &&
									   body->scopeSha256() == job.scopeSha256 &&
									   body->providerId() == job.providerId &&
									   body->policyId() == job.policyId && body->valid()) ;
				CollectorMetadataBody moved( std::move( *body)) ;	// 所有権を一つだけ移す。
				DRIVERCRATE_EXPECT( context,
								   !body->valid() && body->text().empty() && moved.valid()) ;
				// 自身へのmoveでは本文を失わず、移動元からの再提示はできません。
				auto *self = &moved ;	// 同じ所有者を意図的に再指定します。
				moved	   = std::move( *self) ;
				std::shared_ptr<CollectorHttpControl> movedFromControl ;	// 失敗時は空です。
				DRIVERCRATE_EXPECT(
					context, moved.valid() && moved.text() == L"abc" &&
								 !body->consumeForProjection( *prepared, source, movedFromControl) &&
								 !movedFromControl) ;
				// 完了済み・取消し済みcontrolからは元本文を射影へ再利用しません。
				if( mode == 9U) {
					DRIVERCRATE_EXPECT( context, control->finish() && control->snapshot().sealed) ;
				}

				// Worker外からの停止でも同じ元controlを使用します。
				if( mode == 10U) {
					control->requestStop() ;
					DRIVERCRATE_EXPECT( context,
									   control->snapshot().cause == CollectorIoCause::CANCELLED) ;
				}

				std::shared_ptr<CollectorHttpControl> parserControl ;	// 同じGETの制御。
				// 別jobで最初に消費した本文を正しいjobへ再利用させない。
				const auto parserIndex = mode == 7U ? (source + 1U) % 2U : source ;
				DRIVERCRATE_EXPECT( context,
								   moved.consumeForProjection( *prepared, parserIndex,
															  parserControl) == (mode == 0U)) ;
				DRIVERCRATE_EXPECT(
					context, (mode == 0U ? parserControl == control : !parserControl) &&
								 !moved.valid() &&
								 !moved.consumeForProjection( *prepared, source, parserControl)) ;
			}

			// 304は観測だけ、未pin validator・別scopeは送信前に拒否する。
			if( mode == 1U) {
				DRIVERCRATE_EXPECT( context,
								   observation.status == 304U && observation.bodySha256.empty()) ;
			}

			// Claim後の失敗ではnativeを回収し、原原因を空本文で保持する。
			if( control) {
				const auto observed = control->snapshot() ;	// 追加GET前の原値。
				DRIVERCRATE_EXPECT( context,
								   observed.nativeReleased && observed.sends == 1U &&
									   observed.cause ==
										   (mode == 0U || mode == 7U ? CollectorIoCause::NONE
											: mode == 9U			 ? CollectorIoCause::COMPLETE
											: mode == 10U			 ? CollectorIoCause::CANCELLED
											: mode <= 2U			 ? CollectorIoCause::HTTP
																	 : CollectorIoCause::PARSER)) ;
				const std::vector<int> expectedClose{3, 2, 1} ;	// Fake handle所有順。
				const std::vector<int> expectedDns{1, 2} ;		// 結果解放後のWSA後始末。
				DRIVERCRATE_EXPECT( context, fixture.closed == expectedClose &&
												fixture.dnsRelease == expectedDns) ;
			}

			// 成功・失敗のいずれでも同一clientとpermitの二度目のGETはない。
			DRIVERCRATE_EXPECT( context,
							   client.getMetadataBody( *prepared, source, binding, permit, L"", body,
													  observation, control) != 0U) ;
			DRIVERCRATE_EXPECT( context, !body && fixture.calls["send"] == (preflight ? 0U : 1U)) ;
		}
	}

	// 正常200の実parserから公開record・全対象edgeまでを同一の偽HTTPで検査します。
	for( unsigned mode = 0U; mode < 4U; ++mode) {
		const std::size_t source = (mode == 0U || mode == 3U) ? 0U : 1U ;	// 元job index。
		const auto		  fixtureOwner =
			std::make_unique<IoFixture>() ;		// 同じscopeだけで大きなfixtureを所有する。
		auto		&fixture = *fixtureOwner ;	// 一条件だけの完全fake通信。
		FixtureScope fixtureScope( fixture) ;	// 同threadのfake table登録。
		std::wstring html =
			(source == 0U)
				? projectedIntelHtml()
				: projectedAsusHtml( mode == 2U
										? L"/pub/ASUS/mb/04LAN/../DRV_LAN_Fixture.zip"
										: L"/pub/ASUS/mb/04LAN/DRV_LAN_Fixture.zip") ;	// 原HTML。
		// Heroと許諾が同じURLを参照してもdot segmentは配布URLとして拒否します。
		if( mode == 3U) {
			const auto marker = html.find( L"/900011/Wired_driver_") ;	// 一つの配布button。
			DRIVERCRATE_EXPECT( context, marker != html.npos) ;
			// 元fixtureにないbuttonを別URLへ補完しません。
			if( marker != html.npos) {
				html.replace( marker, 8U, L"/900011/../") ;
			}
		}

		fixture.body = winrt::to_string( winrt::hstring( html)) ;
		LocalCollectorStateStore store ;	// caseごとの保護台帳。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 元prepared定義の永続予約。
		DRIVERCRATE_EXPECT(
			context, recovery.initializeProjected( store, definition, HTTP_TEST_UTC, 0U) == 0U) ;
		CollectorHttpPermitPool pool( [&fixture] { return fixture.clock ; }) ;	// 固定二時計。
		CollectorHttpPermit		permit ;										// 現jobの一回GET許可。
		// 二つ目のASUS jobも同じ元予約campaignから許可を取ります。
		if( source == 1U) {
			CollectorHttpPermit first ;	// Intel先行slotの予約。
			DRIVERCRATE_EXPECT( context, pool.reserveProjected( recovery, first) == 0U) ;
		}

		DRIVERCRATE_EXPECT( context, pool.reserveProjected( recovery, permit) == 0U) ;
		// 予約欠測を架空のGET成功へ変換しません。
		if( permit.binding() == nullptr) {
			DRIVERCRATE_EXPECT( context, false) ;
			continue ;
		}

		const auto bindingOwner =
			std::make_unique<std::remove_cvref_t<decltype( *permit.binding())>>(
				*permit.binding()) ;	// 同じ元値をこのscopeで所有する。

		const auto &binding =
			*bindingOwner ;												// 元と同じ期間だけ結果を借用する。			// 元予約の全field。
		LocalCollectorHttpClient client( fixtureHttp(), fixtureDns()) ;	// Nativeなしclient。
		std::optional<CollectorMetadataBody> body ;						// 一回GETの正常本文。
		const auto							 observationOwner = std::make_unique<
									  CollectorControlledHttpObservation>() ;	// 同じscopeだけで大きなfixtureを所有する。
		auto								 &observation = *observationOwner ;	// HTTP原観測。
		std::shared_ptr<CollectorHttpControl> control ;							// 元GET・parser共通制御。
		fixture.control = &control ;
		const auto error =
			client.getMetadataBody( *prepared, source, binding, permit, L"", body, observation,
								   control) ;	// 実HTTPを使わない取得結果。
		DRIVERCRATE_EXPECT( context, error == 0U && body && control && fixture.valid &&
										fixture.calls["send"] == 1U) ;
		// 本文欠測のまま解析へ進めません。
		if( !body || !control) {
			continue ;
		}

		const auto draftOwner = std::make_unique<
			CollectorMetadataProjectionDraft>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto	  &draft  = *draftOwner ;	// 秘密値なしの未確定結果。
		const auto parsed = projectCollectorMetadataBody( std::move( *body), *prepared, source,
														 draft) ;	// 本文消費結果。
		DRIVERCRATE_EXPECT( context, !body->valid() && body->text().empty()) ;
		// Dot segmentを含む行は候補として採用せず保留します。
		if( mode == 2U) {
			// Parserが危険な行を採用しない場合も全対象はHELDとして残します。
			DRIVERCRATE_EXPECT( context, parsed.status == CollectorParserStatus::COMPLETED &&
											draft.status == CollectorProjectionDraftStatus::HELD &&
											draft.records.empty() && draft.edges.size() == 1U &&
											draft.edges[0].recordFingerprints.empty() &&
											draft.sourceReasonCounts[5U] == 1U) ;
		} else {
			// Intel候補に残った曖昧pathはmetadata gateで全体拒否します。
			if( mode == 3U) {
				const auto label =
					"Intel unsafe URL status=" +
					std::to_string( static_cast<unsigned>( parsed.status)) +
					" records=" + std::to_string( draft.records.size()) ;	// URL拒否の分類。
				context.expect( parsed.status == CollectorParserStatus::REJECTED &&
								   draft.status ==
									   CollectorProjectionDraftStatus::MINIMAL_FAILURE &&
								   draft.records.empty() && draft.edges.empty(),
							   label, __FILE__, __LINE__) ;
				continue ;
			}

			const auto label = "projected source=" + std::to_string( source) +
							   " status=" + std::to_string( static_cast<unsigned>( parsed.status)) +
							   " error=" + std::to_string( parsed.error.code) +
							   " records=" + std::to_string( draft.records.size()) +
							   " edges=" + std::to_string( draft.edges.size()) ;	// 失敗時の有限診断。
			context.expect( parsed.status == CollectorParserStatus::COMPLETED &&
							   draft.records.size() == 1U &&
							   draft.edges.size() == (source == 0U ? 26U : 1U) &&
							   draft.records[0].payloads.size() == 1U &&
							   draft.records[0].payloads[0].payloadLinkValidated &&
							   draft.bodySha256 == observation.bodySha256,
						   label, __FILE__, __LINE__) ;
			// 後続参照を空配列へ実行しません。
			if( draft.records.size() != 1U) {
				continue ;
			}

			// ASUSの採用一行とIntelの重複なし一覧を数値診断へ保持します。
			DRIVERCRATE_EXPECT( context, source == 0U ? draft.sourceDuplicates == 0U &&
														   draft.sourceRejected == 0U &&
														   draft.sourceCollisions == 0U
													 : draft.sourceReasonCounts[0U] == 1U) ;

			// 通常recordと新GETの同一EULA候補が現parser revisionの同じ指紋を持つことを確認します。
			if( source == 0U) {
				const auto actual = projectedFingerprintHex(
					draft.records[0].value.stableFingerprint) ;	// 新workerの値。
				context.expect(
					actual == "7311bb9fa363bd94ae3ac18dce8077724c3ea7376e45f508e6daaa3b28860073",
					"Intel usual fingerprint actual=" + actual, __FILE__, __LINE__) ;
			}

			// 公式側のURLとEULA本文は所有DTOへ出しません。
			DRIVERCRATE_EXPECT(
				context, draft.records[0].value.recordKey.find( L"https://") == std::wstring::npos &&
							 draft.records[0].value.eulaRevision.find( L"Fixture terms.") ==
								 std::wstring::npos) ;
			// Intelの一recordは26対象へ共有され、ASUSは一対象だけです。
			for( const auto &edge : draft.edges) {
				DRIVERCRATE_EXPECT(
					context,
					edge.recordFingerprints.size() == 1U &&
						edge.recordFingerprints[0].bytes ==
							draft.records[0].value.stableFingerprint.bytes &&
						edge.bodySha256 == draft.bodySha256 &&
						edge.recordParser == prepared->job( source)->value().recordParser &&
						edge.identityParser == prepared->job( source)->value().identityParser &&
						edge.matchingRule == prepared->job( source)->value().matchingRule) ;
				// 一覧で製品名が未掲載なら公式SKUを公開queryで補完しません。
				if( source == 0U) {
					DRIVERCRATE_EXPECT( context, !edge.sourceProductId && !edge.sourceDisplayName &&
													!edge.sourceComparisonName) ;
				}
			}
		}
	}
}

/** @see local_collector_http_tests.h */
void runCollectorControlledHttpTests( TestContext								  &context,
									 const std::function<std::filesystem::path()> &rootFactory)
{
	// 固定条件ごとに保存予約・HTTP fixtureを独立させる。
	for( unsigned mode = 0U; mode < 77U; ++mode) {
		const auto fixtureOwner =
			std::make_unique<IoFixture>() ;		// 同じscopeだけで大きなfixtureを所有する。
		auto		&fixture = *fixtureOwner ;	// 一条件だけの非通信状態。
		FixtureScope scope( fixture) ;			// Thread-localはscope末尾で必ず解除。
		const auto	 requestOwner =
			std::make_unique<LocalCollectorRequest>() ;			// 同じscopeだけで大きなfixtureを所有する。
		auto			&request	= *requestOwner ;			// 本番共通builderで公式routeを再構築。
		auto			 target		= fixtureTarget( request) ;	// 架空製品・端末IDなし。
		std::uint64_t	 maximum	= 1024U ;					// 本文予算。
		CollectorIoCause expected	= CollectorIoCause::NONE ;	// 未finishの正常HTTP。
		bool			 bytesKnown = true ;					// 明示失敗API以外は実読取り量を保持する。
		std::uint64_t	 lower		= 3U ;						// デフォルトはabcの3 byte。
		std::wstring	 tag ;									// 通常は無条件GET。
		auto			 dns  = fixtureDns() ;					// 完全fake表。
		auto			 http = fixtureHttp() ;					// 完全fake表。
		// 有限ケースと期待値を測定前に固定する。
		switch( mode) {
			// 正常EOF。
			case 0:
				break ;

			// 厳密長ちょうどでは上限外probeなし。
			case 1:
				maximum										  = 3U ;
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"3"} ;
				break ;

			// 短い本文のEOFは不完全。
			case 2:
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"4"} ;
				expected									  = CollectorIoCause::BODY_INCOMPLETE ;
				break ;

			// 非数字長。
			case 3:
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"x"} ;
				expected									  = CollectorIoCause::HTTP ;
				lower										  = 0U ;
				break ;

			// 重複長。
			case 4:
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"3", L"3"} ;
				expected									  = CollectorIoCause::HTTP ;
				lower										  = 0U ;
				break ;

			// TEとCLの併存。
			case 5:
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH]	 = {L"3"} ;
				fixture.headers[WINHTTP_QUERY_TRANSFER_ENCODING] = {L"chunked"} ;
				expected										 = CollectorIoCause::HTTP ;
				lower											 = 0U ;
				break ;

			// 長さなし・上限ちょうど・Query0では未確認。
			case 6:
				maximum	 = 3U ;
				expected = CollectorIoCause::BODY_INCOMPLETE ;
				break ;

			// 残0で次byteがあるが読まない。
			case 7:
				maximum	 = 2U ;
				expected = CollectorIoCause::BODY_LIMIT ;
				lower	 = 2U ;
				break ;

			// Query0でもReadで本文が得られる。
			case 8:
				fixture.queryZero = true ;
				break ;

			// 空200。
			case 9:
				fixture.body.clear() ;
				expected = CollectorIoCause::PARSER ;
				lower	 = 0U ;
				break ;

			// 不正UTF-8でも成功read量を保持する。
			case 10:
				fixture.body = std::string( 1U, static_cast<char>( 0xff)) ;
				expected	 = CollectorIoCause::PARSER ;
				lower		 = 1U ;
				break ;

			// 要求を超える不正返却量。
			case 11:
				fixture.invalidRead = true ;
				expected			= CollectorIoCause::SETUP ;
				bytesKnown			= false ;
				lower				= 0U ;
				break ;

			// 明示0長。
			case 12:
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"0"} ;
				expected									  = CollectorIoCause::BODY_INCOMPLETE ;
				lower										  = 0U ;
				break ;

			// 過大長。
			case 13:
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"1025"} ;
				expected									  = CollectorIoCause::BODY_LIMIT ;
				lower										  = 0U ;
				break ;

			// 自動展開していない圧縮本文。
			case 14:
				fixture.headers[WINHTTP_QUERY_CONTENT_ENCODING] = {L"gzip"} ;
				expected										= CollectorIoCause::HTTP ;
				lower											= 0U ;
				break ;

			// 長さなしchunkedのEOF。
			case 15:
				fixture.headers[WINHTTP_QUERY_TRANSFER_ENCODING] = {L"chunked"} ;
				break ;

			// 304には本文も今回hashもない。
			case 16:
				fixture.status = 304U ;
				tag			   = L"\"revision1\"" ;
				lower		   = 0U ;
				break ;

			// 異なるETag。
			case 17:
				fixture.status = 304U ;
				tag			   = L"\"revision2\"" ;
				expected	   = CollectorIoCause::HTTP ;
				lower		   = 0U ;
				break ;

			// ETagなし304。
			case 18:
				fixture.status = 304U ;
				tag			   = L"\"revision1\"" ;
				fixture.headers.clear() ;
				expected = CollectorIoCause::HTTP ;
				lower	 = 0U ;
				break ;

			// 301を追跡しない。
			case 19:
				fixture.status = 301U ;
				expected	   = CollectorIoCause::HTTP ;
				lower		   = 0U ;
				break ;

			// 相対Retry-Afterをheader UTCへ固定する。
			case 20:
				fixture.status							   = 429U ;
				fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"60"} ;
				expected								   = CollectorIoCause::HTTP ;
				lower									   = 0U ;
				break ;

			// 不正待機は要確認。
			case 21:
				fixture.status							   = 503U ;
				fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"later"} ;
				expected								   = CollectorIoCause::HTTP ;
				lower									   = 0U ;
				break ;

			// HTTP範囲外。
			case 22:
				fixture.status = 999U ;
				expected	   = CollectorIoCause::HTTP ;
				lower		   = 0U ;
				break ;

			// 送信失敗は再送なし・本文全量未知。
			case 23:
				fixture.failure = "send" ;
				expected		= CollectorIoCause::HTTP ;
				bytesKnown		= false ;
				lower			= 0U ;
				break ;

			// 応答待機失敗。
			case 24:
				fixture.failure = "receive" ;
				expected		= CollectorIoCause::HTTP ;
				bytesKnown		= false ;
				lower			= 0U ;
				break ;

			// 最初のread失敗。
			case 25:
				fixture.failure = "read" ;
				expected		= CollectorIoCause::HTTP ;
				bytesKnown		= false ;
				lower			= 0U ;
				break ;

			// 部分read後の失敗で下限を保持。
			case 26:
				fixture.failure = "read" ;
				fixture.failAt	= 2U ;
				fixture.chunk	= 2U ;
				expected		= CollectorIoCause::HTTP ;
				bytesKnown		= false ;
				lower			= 2U ;
				break ;

			// 部分read後のQuery失敗。
			case 27:
				fixture.failure = "query" ;
				fixture.failAt	= 2U ;
				fixture.chunk	= 2U ;
				expected		= CollectorIoCause::HTTP ;
				bytesKnown		= false ;
				lower			= 2U ;
				break ;

			// Header APIの原値。
			case 28:
				fixture.failure = "headers" ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Session生成失敗。
			case 29:
				fixture.failure = "open" ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Connection生成失敗。
			case 30:
				fixture.failure = "connect" ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Request生成失敗。
			case 31:
				fixture.failure = "request" ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Timeout設定失敗。
			case 32:
				fixture.failure = "timeout" ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Option設定失敗。
			case 33:
				fixture.failure = "option" ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Header設定失敗。
			case 34:
				fixture.failure = "add" ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// 所有者close失敗。
			case 35:
				fixture.failure = "close" ;
				expected		= CollectorIoCause::SETUP ;
				break ;

			// WSAStartup失敗ではcleanupなし。
			case 36:
				fixture.failure = "startup" ;
				fixture.error	= WSASYSNOTREADY ;
				expected		= CollectorIoCause::DNS ;
				lower			= 0U ;
				break ;

			// DNS失敗時も結果listを解放。
			case 37:
				fixture.failure = "dns" ;
				fixture.error	= WSAHOST_NOT_FOUND ;
				expected		= CollectorIoCause::DNS ;
				lower			= 0U ;
				break ;

			// Cleanup失敗ではHTTP開始なし。
			case 38:
				fixture.failure = "cleanup" ;
				fixture.error	= WSANOTINITIALISED ;
				expected		= CollectorIoCause::SETUP ;
				lower			= 0U ;
				break ;

			// Private IPv4を一つ混ぜる。
			case 39:
				fixture.addressCount   = 2U ;
				fixture.privateAddress = true ;
				expected			   = CollectorIoCause::DNS ;
				lower				   = 0U ;
				break ;

			// 正常IPv6。
			case 40:
				fixture.ipv6 = true ;
				break ;

			// Private IPv6混在。
			case 41:
				fixture.ipv6		   = true ;
				fixture.addressCount   = 2U ;
				fixture.privateAddress = true ;
				expected			   = CollectorIoCause::DNS ;
				lower				   = 0U ;
				break ;

			// DNS空結果。
			case 42:
				fixture.addressCount = 0U ;
				expected			 = CollectorIoCause::DNS ;
				lower				 = 0U ;
				break ;

			// 未知family。
			case 43:
				fixture.unknownFamily = true ;
				expected			  = CollectorIoCause::DNS ;
				lower				  = 0U ;
				break ;

			// 65件目。
			case 44:
				fixture.addressCount = 65U ;
				expected			 = CollectorIoCause::DNS ;
				lower				 = 0U ;
				break ;

			// DNS復帰前取消し。
			case 45:
				fixture.cancel = "dns" ;
				expected	   = CollectorIoCause::CANCELLED ;
				lower		   = 0U ;
				break ;

			// 送信中取消し。
			case 46:
				fixture.cancel = "send" ;
				expected	   = CollectorIoCause::CANCELLED ;
				lower		   = 0U ;
				break ;

			// 応答待機中取消し。
			case 47:
				fixture.cancel = "receive" ;
				expected	   = CollectorIoCause::CANCELLED ;
				lower		   = 0U ;
				break ;

			// Read成功量は取消しより先に計数。
			case 48:
				fixture.cancel = "read" ;
				expected	   = CollectorIoCause::CANCELLED ;
				break ;

			// 取消し先着でも元API errorを副診断へ保持。
			case 49:
				fixture.cancel	= "read" ;
				fixture.failure = "read" ;
				expected		= CollectorIoCause::CANCELLED ;
				bytesKnown		= false ;
				lower			= 0U ;
				break ;

			// 期限到達後のread成功。
			case 50:
				fixture.expire = "read" ;
				expected	   = CollectorIoCause::DEADLINE ;
				break ;

			// 時計後退後のread成功。
			case 51:
				fixture.rollback = "read" ;
				expected		 = CollectorIoCause::CLOCK ;
				break ;

			// 完全依存の欠損。
			case 52:
				http.readData = nullptr ;
				expected	  = CollectorIoCause::SETUP ;
				lower		  = 0U ;
				break ;

			// Native既定が一つ残るfixtureを拒否。
			case 53:
				http.readData = WinHttpReadData ;
				expected	  = CollectorIoCause::SETUP ;
				lower		  = 0U ;
				break ;

			// Request binding不一致。
			case 54:
				expected = CollectorIoCause::SETUP ;
				lower	 = 0U ;
				break ;

			// 別thread取消しとのread競合。
			case 55:
				fixture.threadedCancel = true ;
				expected			   = CollectorIoCause::CANCELLED ;
				break ;

			// 64 KiBをまたぐ本文を正数readへ分割。
			case 56:
				maximum = 70000U ;
				fixture.body.assign( 65537U, 'a') ;
				lower = 65537U ;
				break ;

			// 過大availableでも実読取りを残1へ限定。
			case 57:
				maximum	 = 1U ;
				expected = CollectorIoCause::BODY_LIMIT ;
				lower	 = 1U ;
				break ;

			// 既定DNS混在もnative呼出し前に拒否。
			case 58:
				dns.resolve = GetAddrInfoExW ;
				expected	= CollectorIoCause::SETUP ;
				lower		= 0U ;
				break ;

			// Status欠損もnative失敗として保持する。
			case 59:
				fixture.failure = "headers" ;
				fixture.error	= ERROR_WINHTTP_HEADER_NOT_FOUND ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Header実値読取りの欠損を任意headerなしへ変換しない。
			case 60:
				fixture.failure = "headers" ;
				fixture.failAt	= 3U ;
				fixture.error	= ERROR_WINHTTP_HEADER_NOT_FOUND ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Header probeの本当のI/O失敗。
			case 61:
				fixture.failure = "headers" ;
				fixture.failAt	= 2U ;
				fixture.error	= ERROR_ACCESS_DENIED ;
				expected		= CollectorIoCause::HTTP ;
				lower			= 0U ;
				break ;

			// Header観測中取消し。
			case 62:
				fixture.cancel = "headers" ;
				expected	   = CollectorIoCause::CANCELLED ;
				lower		   = 0U ;
				break ;

			// Query復帰後はreadを始めない。
			case 63:
				fixture.cancel = "query" ;
				expected	   = CollectorIoCause::CANCELLED ;
				lower		   = 0U ;
				break ;

			// Session生成後に取消しを受理し、同handleを所有者が回収する。
			case 64:
				fixture.cancel = "open" ;
				expected	   = CollectorIoCause::CANCELLED ;
				lower		   = 0U ;
				break ;

			// DNS正常復帰でも期限後はHTTPへ進まない。
			case 65:
				fixture.expire = "dns" ;
				expected	   = CollectorIoCause::DEADLINE ;
				lower		   = 0U ;
				break ;

			// Query正常復帰後に期限到達。
			case 66:
				fixture.expire = "query" ;
				expected	   = CollectorIoCause::DEADLINE ;
				lower		   = 0U ;
				break ;

			// Option設定中の取消しは送信0。
			case 67:
				fixture.cancel = "option" ;
				expected	   = CollectorIoCause::CANCELLED ;
				lower		   = 0U ;
				break ;

			// 送信正常復帰後に期限到達。
			case 68:
				fixture.expire = "send" ;
				expected	   = CollectorIoCause::DEADLINE ;
				lower		   = 0U ;
				break ;

			// 全WinHTTP phaseを残1msへclampする。
			case 69:
				break ;

			// Native API失敗が先着した場合は後始末中取消しへ置換しない。
			case 70:
				fixture.failure = "read" ;
				fixture.cancel	= "close" ;
				expected		= CollectorIoCause::HTTP ;
				bytesKnown		= false ;
				lower			= 0U ;
				break ;

			// DNSの最大64件は部分省略せず全件受理する。
			case 71:
				fixture.addressCount = 64U ;
				break ;

			// 明示0秒指定を欠損と区別する。
			case 73:
				fixture.status							   = 429U ;
				fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"0"} ;
				expected								   = CollectorIoCause::HTTP ;
				lower									   = 0U ;
				break ;

			// 秒境界でない元header時刻を切り捨てない。
			case 74:
				fixture.status							   = 429U ;
				fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"60"} ;
				expected								   = CollectorIoCause::HTTP ;
				lower									   = 0U ;
				break ;

			// 厳密HTTP-dateの元値を保存する。
			case 75:
				fixture.status							   = 503U ;
				fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"Wed, 21 Oct 2015 07:28:00 GMT"} ;
				expected								   = CollectorIoCause::HTTP ;
				lower									   = 0U ;
				break ;

			// 数字待機の上限超過を短縮しない。
			case 76:
				fixture.status							   = 429U ;
				fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"2592001"} ;
				expected								   = CollectorIoCause::HTTP ;
				lower									   = 0U ;
				break ;

			// UInt64を超える長さを丸めない。
			case 72:
				fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"18446744073709551616"} ;
				expected									  = CollectorIoCause::BODY_LIMIT ;
				lower										  = 0U ;
				break ;
		}

		LocalCollectorStateStore store ;	// 他試験・旧実測rootと別の保護台帳。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		auto input = fixtureInput( request, maximum) ;	// 同じrequest identity。
		// 別request keyへ台帳を結合し、値の自作で照合を迂回できないことを確認する。
		if( mode == 54U) {
			input.requestKeys[0] = std::wstring( 64U, L'b') ;
		}

		LocalCollectorRecovery recovery ;	// 単一writer。
		DRIVERCRATE_EXPECT( context, recovery.initialize( store, input, HTTP_TEST_UTC, 0U) == 0U) ;
		CollectorHttpPermitPool pool( [&fixture] { return fixture.clock ; }) ;	// Scope内の同じ時計。
		CollectorHttpPermit		permit ;										// 永続保存後だけ得る実許可。
		DRIVERCRATE_EXPECT( context,
						   pool.reserve( recovery, permit) == 0U && permit.binding() != nullptr) ;
		// 予約失敗でnull参照し、テストを中断しない。
		if( permit.binding() == nullptr) {
			continue ;
		}

		const auto bindingOwner =
			std::make_unique<std::remove_cvref_t<decltype( *permit.binding())>>(
				*permit.binding()) ;	// 同じ元値をこのscopeで所有する。

		const auto &binding =
			*bindingOwner ;	// 元と同じ期間だけ結果を借用する。	// Worker所有の元dispatch。
		// 予約保存・thread準備に相当する遅延を新deadlineで延長しない。
		if( mode == 69U) {
			fixture.clock = {HTTP_TEST_UTC + 119999U, 119999U} ;
		}

		LocalCollectorHttpClient			  client( http, dns) ;	// 完全非通信依存。
		std::shared_ptr<CollectorHttpControl> control ;				// Claim後の同じ観測。
		fixture.control = &control ;
		// 元header時刻の端数を含む待機期限を保持する。
		if( mode == 73U || mode == 74U) {
			fixture.clock = {HTTP_TEST_UTC + 599U, 599U} ;
		}

		const auto observationOwner = std::make_unique<
			CollectorControlledHttpObservation>() ;	// 同じscopeだけで大きなfixtureを所有する。

		auto		&observation = *observationOwner ;	// 新modeだけの時刻付きHTTP観測。
		std::wstring text ;								// 厳密decodeした本文だけ。
		const auto	 error =
			// 本番接続。
			client.get( target, binding, permit, tag, text, observation, control) ;
		DRIVERCRATE_EXPECT( context, control != nullptr) ;
		// 原因をcase ID付きで報告できる条件名を組み立てる。
		const std::string label = "controlled HTTP mode " + std::to_string( mode) ;	// URLなし診断。
		// Claim失敗を後段成功として扱わない。
		if( !control) {
			continue ;
		}

		const auto observed = control->snapshot() ;	// Finish前の固定観測。
		context.expect( (error == 0) == (expected == CollectorIoCause::NONE) &&
						   observed.cause == expected,
					   label, __FILE__, __LINE__) ;
		DRIVERCRATE_EXPECT( context,
						   observed.bytesKnown == bytesKnown && observed.lowerBytes == lower) ;
		DRIVERCRATE_EXPECT( context, fixture.valid && fixture.calls["send"] <= 1U &&
										observed.sends == fixture.calls["send"] &&
										!observed.sealed) ;
		DRIVERCRATE_EXPECT( context, observed.nativeReleased == (mode != 35U && mode != 38U)) ;
		// Body未検査の失敗や304には本文hashを作らない。
		if( expected != CollectorIoCause::NONE || mode == 16U) {
			DRIVERCRATE_EXPECT( context, text.empty() && observation.bodySha256.empty()) ;
		} else {
			std::wstring expectedHash ;	// 別の共通hash APIでrawとの一致を確認。
			DRIVERCRATE_EXPECT( context, computeBytesSha256( fixture.body, expectedHash) == 0 &&
											observation.bodySha256 == expectedHash &&
											text.size() == fixture.body.size()) ;
		}

		// Handle取得に対応する一回の所有者解放だけを要求する。
		const std::vector<int> expectedClose =
			fixture.calls["request"] != 0U && mode != 31U	? std::vector<int>{3, 2, 1}
			: fixture.calls["connect"] != 0U && mode != 30U ? std::vector<int>{2, 1}
			: fixture.calls["open"] != 0U && mode != 29U
				? std::vector<int>{1}
				: std::vector<int>{} ;	// 確保済みhandle集合。
		DRIVERCRATE_EXPECT( context, fixture.closed == expectedClose) ;
		// DNS結果listをWSA参照より先に一回だけ解放する。
		const std::vector<int> expectedDnsRelease = fixture.calls["startup"] == 0U || mode == 36U
														? std::vector<int>{}
													: mode == 42U ? std::vector<int>{2}
																  : std::vector<int>{1, 2} ;
		DRIVERCRATE_EXPECT( context, fixture.dnsRelease == expectedDnsRelease) ;
		// HTTPの全phaseに1ms未満や元上限を渡さない。
		if( mode == 69U) {
			DRIVERCRATE_EXPECT( context,
							   fixture.dnsMillis == 1U && !fixture.timeouts.empty() &&
								   std::all_of( fixture.timeouts.begin(), fixture.timeouts.end(),
											   []( const auto &values) {
												   return values == std::array<int, 4>{1, 1, 1, 1} ;
											   })) ;
		}

		// Native API故障は後始末のLastErrorで999へ変えない。
		if( !fixture.failure.empty()) {
			DRIVERCRATE_EXPECT( context, observed.native && observed.native->code == fixture.error) ;
		}

		// 相対待機を観測UTCへ一回だけ結合する。
		if( mode == 20U) {
			DRIVERCRATE_EXPECT( context,
							   observed.headerUtcMillis == HTTP_TEST_UTC &&
								   observation.retryAfterUtcMillis == HTTP_TEST_UTC + 60000U &&
								   observation.retryAfterDelaySeconds == 0U) ;
		}

		// 不正待機を0秒指定にしない。
		if( mode == 21U) {
			DRIVERCRATE_EXPECT( context, observation.retryAfterNeedsReview) ;
		}

		// 絶対期限は取得時に確定し、旧秒fieldから再結合しない。
		if( mode == 73U || mode == 74U || mode == 75U || mode == 76U) {
			const auto absolute = mode == 73U ? std::optional<std::uint64_t>( HTTP_TEST_UTC + 599U)
								  : mode == 74U
									  ? std::optional<std::uint64_t>( HTTP_TEST_UTC + 60599U)
								  : mode == 75U ? std::optional<std::uint64_t>( 1445412480000ULL)
												: std::nullopt ;	// 固定oracle。
			DRIVERCRATE_EXPECT( context, observation.retryAfterUtcMillis == absolute &&
											observation.retryAfterDelaySeconds == 0U &&
											observation.retryAfterUtcSeconds == 0U &&
											observation.retryAfterNeedsReview == (mode == 76U)) ;
		}

		// 304はreadを開始しない。
		if( mode >= 16U && mode <= 18U) {
			DRIVERCRATE_EXPECT( context, fixture.reads.empty()) ;
		}

		// 上限外probeを一度も行わない。
		DRIVERCRATE_EXPECT(
			context,
			std::all_of( fixture.reads.begin(), fixture.reads.end(), [maximum]( DWORD count) {
				return count > 0U && count <= std::min<std::uint64_t>( 65536U, maximum) ;
			})) ;
		const auto							  sends = fixture.calls["send"] ;	// Client再使用前の値。
		std::shared_ptr<CollectorHttpControl> second ;							// 再使用からcontrolを受け取れない。
		DRIVERCRATE_EXPECT(
			context, client.get( target, binding, permit, tag, text, observation, second) != 0 &&
						 fixture.calls["send"] == sends && !second) ;
		DRIVERCRATE_EXPECT( context, control->finish() && control->snapshot().sealed) ;
		// HTTP成功時でも公式parserのOBSERVEDはまだ作っていない。
		if( expected == CollectorIoCause::NONE) {
			DRIVERCRATE_EXPECT( context, control->snapshot().cause == CollectorIoCause::COMPLETE) ;
		}
	}

	// 残msからTIMEVALへの変換と期限0でのAPI非呼出しを独立検証する。
	for( const std::uint64_t remaining : {1ULL, 999ULL, 1000ULL, 15000ULL, 0ULL}) {
		const auto fixtureOwner =
			std::make_unique<IoFixture>() ;		// 同じscopeだけで大きなfixtureを所有する。
		auto		&fixture = *fixtureOwner ;	// DNS専用の独立fake。
		// 本条件のAPIだけにfake状態を借用するscope。
		FixtureScope scope( fixture) ;
		const auto	 requestOwner =
			std::make_unique<LocalCollectorRequest>() ;	// 同じscopeだけで大きなfixtureを所有する。
		auto	  &request = *requestOwner ;			// 共通request identity。
		const auto target  = fixtureTarget( request) ;	// 公開架空target。
		(void)target ;
		LocalCollectorStateStore store ;	// 一件の永続予約。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		LocalCollectorRecovery recovery ;	// 元deadlineを作る監督。
		DRIVERCRATE_EXPECT( context, recovery.initialize( store, fixtureInput( request, 1024U),
														HTTP_TEST_UTC, 0U) == 0U) ;
		CollectorHttpPermitPool pool( [&fixture] { return fixture.clock ; }) ;	// 同じclock。
		CollectorHttpPermit		permit ;										// 予約からのみ発行。
		DRIVERCRATE_EXPECT( context, pool.reserve( recovery, permit) == 0U) ;
		auto control = permit.claim( &fixture, *permit.binding()) ;	// 一つのDNS clientだけへclaim。
		fixture.control = &control ;
		fixture.clock	= {HTTP_TEST_UTC + 120000U - remaining, 120000U - remaining} ;
		OfficialPublicDestinationEvidence evidence ;	// 成功件数のみ。
		// 本番有限resolverからの原結果。
		const auto						  error =
			resolveCollectorPublicDestination( L"sample.example", *control, fixtureDns(), evidence) ;
		DRIVERCRATE_EXPECT( context, (error == 0) == (remaining != 0U) && fixture.valid) ;
		DRIVERCRATE_EXPECT( context, fixture.calls["dns"] == (remaining != 0U ? 1U : 0U) &&
										fixture.dnsMillis == remaining) ;
		DRIVERCRATE_EXPECT( context, fixture.dnsRelease == (remaining != 0U ? std::vector<int>{1, 2}
																		   : std::vector<int>{})) ;
	}
}
/** @see local_collector_http_tests.h */
void runCollectorControlledExecutorHttpTests(
	TestContext &context, const std::function<std::filesystem::path()> &rootFactory)
{
	// 各caseは明示したfake APIだけをworker内へ作り、raw GET・decode・hashを通す。
	for( unsigned mode = 0U; mode < 19U; ++mode) {
		std::mutex				 clockMutex ;				// 親とworker終了後のclock対を保護する。
		CollectorHttpClockSample clock{HTTP_TEST_UTC, 0U} ;	// 元予約時計。
		CollectorHttpClock		 current = [&] {
			  // 同期API scope内は同threadのclockを読む。
			  if( activeFixture != nullptr) {
				  return activeFixture->clock ;
			  }

			  const std::lock_guard lock( clockMutex) ;	// Scope終了後の共有対を読む。
			  return clock ;
		  } ; // Native関数へfallbackしない。
		LocalCollectorRequest	 request ;							// 共通builder入力。
		const auto				 target = fixtureTarget( request) ;	// 架空の公開製品。
		LocalCollectorStateStore store ;							// 同じwriterだけが保存する。
		DRIVERCRATE_EXPECT( context, store.initialize( rootFactory(), true) == 0U) ;
		auto recovery = std::make_unique<LocalCollectorRecovery>() ;	// 再開前に元借用を解除する。
		DRIVERCRATE_EXPECT( context, recovery->initialize( store, fixtureInput( request, 1024U),
														 HTTP_TEST_UTC, 0U) == 0U) ;
		bool					valid{} ;								// Join後だけ読むowner／解放結果。
		std::condition_variable endedChanged ;							// 元entry終了を親へ伝える。
		bool					ended{} ;								// clockMutexで公開し、run終了まで寿命を維持する。
		bool					endedInTime{true} ;						// 有限fixture通知の成否。
		unsigned				sends{} ;								// Workerの実SendRequest回数。
		CollectorIoCause		expected{CollectorIoCause::COMPLETE} ;	// 元cause oracle。
		std::uint64_t			lower{3U} ;								// 受信下限oracle。
		bool					known{true} ;							// 量の既知性oracle。
		// 取得先source・purposeの品質試験ではない有限HTTP条件。
		switch( mode) {
			// Raw正常EOF。
			case 0:
				break ;

			// DNS前／後に原取消しを保持する。
			case 1:
				expected = CollectorIoCause::CANCELLED ;
				lower	 = 0U ;
				break ;

			// SEND復帰で取消し、物理送信は推測しない。
			case 2:
				expected = CollectorIoCause::CANCELLED ;
				lower	 = 0U ;
				break ;

			// READ復帰で量を反映してから取消す。
			case 3:
				expected = CollectorIoCause::CANCELLED ;
				break ;

			// 部分read後の原失敗は下限だけ既知。
			case 4:
				expected = CollectorIoCause::HTTP ;
				lower	 = 2U ;
				known	 = false ;
				break ;

			// 厳密decode拒否も受信量を失わない。
			case 5:
				expected = CollectorIoCause::PARSER ;
				lower	 = 1U ;
				break ;

			// Retry-Afterを元header時刻へ結合する。
			case 6:
				expected = CollectorIoCause::HTTP ;
				lower	 = 0U ;
				break ;

			// Close失敗のnative解放未確認。
			case 7:
				expected = CollectorIoCause::SETUP ;
				break ;

			// 期限復帰後に追加readを開始しない。
			case 8:
				expected = CollectorIoCause::DEADLINE ;
				break ;

			// Query0でも正数readで本文とEOFを観測する。
			case 9:
				break ;

			// SEND／RECEIVE／QUERY原失敗も未知maximumへ精算する。
			case 10:
			// RECEIVE復帰の原失敗。
			case 11:
			// QUERY復帰の原失敗。
			case 12:
				expected = CollectorIoCause::HTTP ;
				lower	 = 0U ;
				known	 = false ;
				break ;

			// 宣言長より早いEOF。
			case 13:
				expected = CollectorIoCause::BODY_INCOMPLETE ;
				break ;

			// 上限を超える本文の既知下限。
			case 14:
				expected = CollectorIoCause::BODY_LIMIT ;
				lower	 = 1024U ;
				break ;

			// 厳密長上限ちょうどは完了。
			case 15:
				lower = 1024U ;
				break ;

			// 上限ちょうどでも終端未確認は完了でない。
			case 16:
				expected = CollectorIoCause::BODY_INCOMPLETE ;
				lower	 = 1024U ;
				break ;

			// 503のHTTP-dateは24時間規則より長い原値を保持する。
			case 17:
				expected = CollectorIoCause::HTTP ;
				lower	 = 0U ;
				break ;

			// Resolver原WINSOCKをv3・既知0精算・再開まで保持する。
			case 18:
				expected = CollectorIoCause::DNS ;
				lower	 = 0U ;
				break ;
		}

		LocalCollectorExecutor executor(
			{current,
			 [&]( std::size_t, const auto &binding, auto &permit, auto &observation) -> NativeError {
				 IoFixture	  fixture ;								// このworkerだけがnative fake handleを所有する。
				 FixtureScope scope( fixture) ;						// Worker間にfixtureを共有しない。
				 std::shared_ptr<CollectorHttpControl> control ;	// HTTP scopeだけで借用する。
				 fixture.control = &control ;
				 // 条件別の故障は本番関数を呼ぶ前に固定する。
				 switch( mode) {
					 // 正常raw。
					 case 0:
						 break ;

					 // DNS後取消し。
					 case 1:
						 fixture.cancel = "dns" ;
						 break ;

					 // 送信復帰後取消し。
					 case 2:
						 fixture.cancel = "send" ;
						 break ;

					 // read復帰後取消し。
					 case 3:
						 fixture.cancel = "read" ;
						 break ;

					 // 部分read失敗の原値。
					 case 4:
						 fixture.failure = "read" ;
						 fixture.failAt	 = 2U ;
						 fixture.chunk	 = 2U ;
						 break ;

					 // 不正UTF-8をrawで渡す。
					 case 5:
						 fixture.body = std::string( 1U, static_cast<char>( 0xff)) ;
						 break ;

					 // 相対待機の絶対観測。
					 case 6:
						 fixture.status								= 429U ;
						 fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {L"60"} ;
						 break ;

					 // Request所有者closeの原値。
					 case 7:
						 fixture.failure = "close" ;
						 break ;

					 // Read直後の元期限。
					 case 8:
						 fixture.expire = "read" ;
						 break ;

					 // QueryだけでEOFを作らない。
					 case 9:
						 fixture.queryZero = true ;
						 break ;

					 // WinHTTPの原12002と失敗phaseを保存まで通す。
					 case 10:
					 // RECEIVEに同じ原値を注入する。
					 case 11:
					 // QUERYに同じ原値を注入する。
					 case 12:
						 fixture.failure = mode == 10U ? "send" : mode == 11U ? "receive" : "query" ;
						 break ;

					 // EOFを宣言長一致へ読み替えない。
					 case 13:
						 fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"4"} ;
						 break ;

					 // 正数READを元上限1024へclampする。
					 case 14:
					 // 宣言長1024の完了を確認する。
					 case 15:
					 // 同量でも宣言なしの終端未確認は保留する。
					 case 16:
						 fixture.body.assign( mode == 14U ? 1025U : 1024U, 'a') ;
						 // 厳密長を明示した場合だけ上限一致で終了する。
						 if( mode == 15U) {
							 fixture.headers[WINHTTP_QUERY_CONTENT_LENGTH] = {L"1024"} ;
						 }

						 break ;

					 // 固定UTCの二日後を元headerのHTTP-dateで与える。
					 case 17:
						 fixture.status								= 503U ;
						 fixture.headers[WINHTTP_QUERY_RETRY_AFTER] = {
							 L"Mon, 28 Sep 2026 21:00:00 GMT"} ;
						 break ;

					 // 名前解決原値はHRESULTへ丸めずWINSOCKとして保存する。
					 case 18:
						 fixture.failure = "dns" ;
						 fixture.error	 = 11001U ;
						 break ;
				 }

				 NativeError error{} ;	// 本番GETの元結果。
				 {
					 LocalCollectorHttpClient client( fixtureHttp(), fixtureDns()) ;	// 全API明示。
					 std::wstring			  text ;									// 同じworkerだけのdecoded本文。
					 error = client.get( target, binding, permit, L"", text, observation, control) ;
				 } // ClientをCOM利用終了・最終観測より先に解放する。
				 valid =
					 fixture.valid && fixture.calls["send"] <= 1U &&
					 fixture.closed == (mode == 1U || mode == 18U ? std::vector<int>{}
																  : std::vector<int>{3, 2, 1}) &&
					 fixture.dnsRelease == std::vector<int>{1, 2} ;
				 sends = fixture.calls["send"] ;
				 {
					 const std::lock_guard lock( clockMutex) ;	// Finishと親受領へ同じ原clockを渡す。
					 clock = fixture.clock ;
				 }
				 return error ;
			 },
			 // Retry条件では元workerの終了後にだけ125秒の保存遅延を入れる。
			 [&]( std::function<void()> entry) {
				 // 通常条件の所有thread開始を変更しない。
				 if( mode != 6U && mode != 17U) {
					 return std::thread( std::move( entry)) ;
				 }

				 std::thread worker( [&, entry = std::move( entry)] {
					 entry() ;
					 {
						 const std::lock_guard lock( clockMutex) ;
						 ended = true ;
					 }
					 endedChanged.notify_all() ;
				 }) ; // 同期用変数が終了まで存続する。
				 {
					 std::unique_lock lock( clockMutex) ;
					 // 通知が期限内に届かなくてもthread所有権を親へ返して回収する。
					 endedInTime = endedChanged.wait_for( lock, std::chrono::seconds( 10),
														 [&] { return ended ; }) ;
					 clock		 = {HTTP_TEST_UTC + 125000U, 125000U} ;
				 }
				 // 元所有threadのjoinは本番executorに任せる。
				 return worker ;
			 }}) ;
		const auto		  report = executor.run( *recovery) ;								// GET・解放・join・保存の実経路。
		const std::string label	 = "controlled executor HTTP " + std::to_string( mode) ;	// URLなし。
		context.expect( valid && endedInTime && report.reserved == 1U && report.started == 1U &&
						   report.joined == 1U && report.saved == 1U &&
						   report.error == (mode == 7U ? 12002U : 0U),
					   label, __FILE__, __LINE__) ;
		std::vector<std::wstring> names ;	// 実保存応答を検査する。
		DRIVERCRATE_EXPECT( context, store.listRunNames( names) == 0U) ;
		std::size_t count{} ;	// v3を一件だけ要求する。
		// 元fileからschema・IO・予算を確認する。
		for( const auto &name : names) {
			// v3以外を受信成功へ加算しない。
			if( !name.starts_with( L"campaign-response-v3-")) {
				continue ;
			}

			++count ;
			std::string envelope ;	// 同期storeの元byte。
			bool		found{} ;	// 欠損を成功にしない。
			DRIVERCRATE_EXPECT( context,
							   store.read( L"runs/" + name, envelope, found) == 0U && found) ;
			const auto object = JsonObject::Parse(
				// 元応答。
				JsonObject::Parse( winrt::to_hstring( envelope)).GetNamedString( L"body")) ;
			const auto			io = object.GetNamedObject( L"io") ;	// 固定観測codecへ再生する。
			CollectorIoSnapshot decoded ;								// 保存IOの厳密decode。
			DRIVERCRATE_EXPECT(
				context, decodeCollectorHttpObservation( winrt::to_string( io.Stringify()),
														io.GetNamedString( L"permit"), decoded) &&
							 decoded.cause == expected && decoded.lowerBytes == lower &&
							 object.GetNamedNumber( L"sends") == sends &&
							 object.GetNamedString( L"state") ==
								 (expected == CollectorIoCause::COMPLETE ? L"HELD" : L"FAILED")) ;
			DRIVERCRATE_EXPECT( context, known
											? object.GetNamedNumber( L"bytes") == lower
											: object.GetNamedValue( L"bytes").ValueType() ==
												  winrt::Windows::Data::Json::JsonValueType::Null) ;
			// 正常rawのhashを別APIで照合する。
			if( expected == CollectorIoCause::COMPLETE) {
				std::wstring hash ;	// abc原byteのhash。
				DRIVERCRATE_EXPECT(
					context,
					computeBytesSha256( mode == 15U ? std::string( 1024U, 'a') : "abc", hash) == 0 &&
						object.GetNamedString( L"body") == hash) ;
			}

			// 保存時刻へRetry-Afterを付け替えない。
			if( mode == 6U) {
				DRIVERCRATE_EXPECT( context, object.GetNamedNumber( L"retryAfter") ==
													HTTP_TEST_UTC + 60000.0 &&
												io.GetNamedNumber( L"headerUtc") == HTTP_TEST_UTC) ;
			}

			// 日付headerの原値も保存時刻へ付け替えない。
			if( mode == 17U) {
				DRIVERCRATE_EXPECT( context, object.GetNamedNumber( L"retryAfter") ==
													HTTP_TEST_UTC + 172800000.0 &&
												io.GetNamedNumber( L"headerUtc") == HTTP_TEST_UTC) ;
			}

			// Raw API失敗の原値・phaseを包んだまま保持する。
			if( mode == 18U) {
				DRIVERCRATE_EXPECT(
					context, decoded.native && decoded.native->code == 11001U &&
								 decoded.native->domain == CollectorIoErrorDomain::WINSOCK_ERROR &&
								 decoded.native->stage == CollectorIoStage::DNS &&
								 object.GetNamedString( L"errorDomain") == L"WINSOCK") ;
			}

			// Send／receive／query／readの原Win32 errorも変更しない。
			if( mode == 4U || (mode >= 10U && mode <= 12U)) {
				DRIVERCRATE_EXPECT(
					context, decoded.native && decoded.native->code == 12002U &&
								 decoded.native->domain == CollectorIoErrorDomain::WIN32_ERROR &&
								 decoded.native->stage == (mode == 10U	 ? CollectorIoStage::SEND
														   : mode == 11U ? CollectorIoStage::RECEIVE
														   : mode == 12U ? CollectorIoStage::QUERY
																		 : CollectorIoStage::READ)) ;
			}
		}

		DRIVERCRATE_EXPECT( context, count == 1U) ;
		std::vector<std::pair<std::wstring, std::string>> originals ;	// 一件v3の元byte。
		// 登録済み応答を再開時刻で書き換えないことを後で照合する。
		for( const auto &name : names) {
			// 補助fileを応答不変性の代用にしない。
			if( name.starts_with( L"campaign-response-v3-")) {
				originals.emplace_back( L"runs/" + name, httpSavedBody( store, L"runs/" + name)) ;
			}
		}

		CollectorBudgetSnapshot budget ;	// v3から導出した実精算を直接確認する。
		DRIVERCRATE_EXPECT( context,
						   parseCollectorBudgetSnapshot(
							   httpSavedBody( store, L"current/campaign-budget-v1.json"), budget) &&
							   budget.reservations.size() == 1U &&
							   budget.reservations[0].charged == (known ? lower : 1024U) &&
							   budget.reservations[0].phase == 1U) ;
		recovery.reset() ;
		LocalCollectorRecovery resumed ;	// 元control／writer借用を解放した後に再開する。
		DRIVERCRATE_EXPECT( context, resumed.initialize( store, fixtureInput( request, 1024U),
													   HTTP_TEST_UTC + 126000U, 0U) == 0U &&
										resumed.terminalJobs() == 1U) ;
		// 再開後も同じ元応答と精算を保持する。
		for( const auto &[name, original] : originals) {
			DRIVERCRATE_EXPECT( context, httpSavedBody( store, name) == original) ;
		}

		DRIVERCRATE_EXPECT( context,
						   parseCollectorBudgetSnapshot(
							   httpSavedBody( store, L"current/campaign-budget-v1.json"), budget) &&
							   budget.reservations.size() == 1U &&
							   budget.reservations[0].charged == (known ? lower : 1024U)) ;
		// Retryは元headerと24時間規則のmaxであり、遅延保存／再開時刻へ移さない。
		if( mode == 6U || mode == 17U) {
			CollectorWaitSnapshot waits ;	// 保存済みのrequestとgroupの原値。
			DRIVERCRATE_EXPECT(
				context, parseCollectorWaitSnapshot(
							 httpSavedBody( store, L"current/campaign-controls-v1.json"), waits) &&
							 waits.controls.at( L"g-" + request.group).notBefore ==
								 HTTP_TEST_UTC + (mode == 6U ? 86400000U : 172800000U)) ;
		}
	}
}
} // namespace drivercrate::test
