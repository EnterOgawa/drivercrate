//------------------------------------------------------------------------------
/**
 * @file official_cdn_token.h
 * @brief 匿名CDN解決の公開文脈とsession限定結果を定義する。
 * @version 01.00.01
 * @date 2026/11/03
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
 * Ver.01.00.00 Shunji Ogawa  2026/11/03  閉じたempty JSON/queryと秘密解決結果を追加。
 * Ver.01.00.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 * @note 公開文脈自体に取得能力はなく、response/tokenは永続化しない。
 * @see docs/adr/0431-session-only-anonymous-cdn-resolution.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/update_types.h"
#include "platform/secret_official_url.h"
#include <cstdint>
#include <string>
#include <string_view>

namespace drivercrate {
/** @brief 署名recordが持つ公開path/modelの限定protocol。 */
struct OfficialAnonymousCdnPlan {
	/// 原metadataのASCII model selector。
	std::wstring model ;
	/// 固定payload origin配下の原path。
	std::wstring path ;
	/// 保存一次JSのproduction systemCode。
	std::wstring systemCode ;
	/**
	 * @brief 共有可能な元取得policyだけを比較する。
	 * @param[in] other 別recordの元policy。
	 * @return 全原値が等しい場合true。
	 */
	bool		 operator==( const OfficialAnonymousCdnPlan &other) const = default ;
} ;
/** @brief 補助HTTPの閉じた非秘密実数。TLS/headerの回線量ではない。 */
struct OfficialAuxiliaryHttpObservation {
	/// sendRequest開始直前の試行数。最大1。
	std::uint32_t requests{} ;
	/// 成功ReadDataで取得した本文byte。最大16KiB。
	std::uint64_t bodyBytes{} ;
	/// 実応答HTTP status。未受信は0。
	std::uint32_t httpStatus{} ;
} ;
/** @brief 固定protocol builderだけが生成するempty JSON/query POST。 */
class OfficialEmptyJsonQueryPost final {
public:
	/**
	 * @brief 未検証の空requestを作る。
	 */
	OfficialEmptyJsonQueryPost() = default ;
	/**
	 * @brief 完全な固定文脈があるか返す。
	 * @return builder成功時だけtrue。
	 */
	[[nodiscard]] bool valid() const noexcept
	{
		return valid_ ;
	}
	/**
	 * @brief 公開query付きmetadata起点を借用する。
	 * @return このrequestの寿命内だけ有効な原URL。
	 */
	[[nodiscard]] std::wstring_view url() const noexcept
	{
		return url_ ;
	}
	/**
	 * @brief 固定source Originを借用する。
	 * @return builderが設定した原origin。
	 */
	[[nodiscard]] std::wstring_view origin() const noexcept
	{
		return origin_ ;
	}
	/**
	 * @brief 固定source Refererを借用する。
	 * @return builderが設定した原referer。
	 */
	[[nodiscard]] std::wstring_view referer() const noexcept
	{
		return referer_ ;
	}

private:
	/**
	 * @brief 保存一次JSの二段encodingで固定POSTを作る。
	 * @note 第1引数（const OfficialAnonymousCdnPlan &、in）はこの宣言では無名です。元recordの公開文脈。
	 * @note 第2引数（OfficialEmptyJsonQueryPost &、out）はこの宣言では無名です。全成功時だけ有効な閉第2引数。
	 * @return 成功0、不正文脈またはallocationはHRESULT。
	 */
	friend NativeError makeAsusAnonymousCdnPost( const OfficialAnonymousCdnPlan &,
												OfficialEmptyJsonQueryPost &) ;
	/// 任意HTTP requestから書き換えない公開endpoint。
	std::wstring	   url_ ;
	/// builderだけが設定する安全なheader値。
	std::wstring	   origin_ ;
	/// builderだけが設定する安全なheader値。
	std::wstring	   referer_ ;
	/// 全文脈の検査が揃ったときだけtrue。
	bool			   valid_{} ;
} ;
/** @brief 秘密URLを単独所有する非永続の解決結果。権限はない。 */
struct OfficialAnonymousCdnResolution {
	/// session内だけの元queryと三認証値を含むURL。
	SecretOfficialUrl target ;
	/// protocolが明示したUTC Unix秒。推定TTLではない。
	std::uint64_t	  expiresUtcSeconds{} ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 現固定protocolの公開値を有限文法へ検査する。
 * @param[in] plan 元recordの公開文脈。
 * @return 現protocolで表現可能ならtrue。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		   validAsusAnonymousCdnPlan( const OfficialAnonymousCdnPlan &plan) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 元path/modelから唯一のpublic canonical URLを作る。
 * @param[in] plan 検査済み公開文脈。
 * @return 正常時の元URL。不成立なら空。
 */
//------------------------------------------------------------------------------
[[nodiscard]] std::wstring asusAnonymousCdnCanonicalUrl( const OfficialAnonymousCdnPlan &plan) ;
//------------------------------------------------------------------------------
/**
 * @brief 保存一次JSの二段encodingで固定POSTを作る。
 * @param[in] plan 元recordの公開文脈。
 * @param[out] request 全成功時だけ有効な閉request。
 * @return 成功0、不正文脈またはallocationはHRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError  makeAsusAnonymousCdnPost( const OfficialAnonymousCdnPlan &plan,
													OfficialEmptyJsonQueryPost	   &request) ;
//------------------------------------------------------------------------------
/**
 * @brief 有限responseを元public URLとprotocol epochへ結ぶ。
 * @param[in] response session内だけのUTF-16 JSON。保存しない。
 * @param[in] plan 元recordの公開文脈。
 * @param[out] result 全型/文法/量を成功した秘密URL。権限ではない。
 * @return 全解釈成功0、不正応答は元HRESULT。
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError  parseAsusAnonymousCdnResponse( std::wstring_view				 response,
														 const OfficialAnonymousCdnPlan &plan,
														 OfficialAnonymousCdnResolution &result) ;
//------------------------------------------------------------------------------
/**
 * @brief 解決結果が元公開queryと同じepochを保持するか再照合する。
 * @param[in] plan 同recordの公開文脈。
 * @param[in] target session限定の完全解決URL。
 * @param[in] expires 同responseのUTC Unix秒。
 * @return 元URLと各認証fieldが一度だけ一致する場合true。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool		   matchesAsusAnonymousCdnTarget( const OfficialAnonymousCdnPlan &plan,
														 std::wstring_view target, std::uint64_t expires) ;
} // namespace drivercrate
