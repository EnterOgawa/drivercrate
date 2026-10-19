//------------------------------------------------------------------------------
/**
 * @file official_delegated_http_request.h
 * @brief Record限定grantから一回のGETだけを作る秘密requestを定義します。
 * @version 01.04.01
 * @date 2026/09/15
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
 * Ver.01.00.00 Shunji Ogawa  2026/09/15  GET限定の秘密request所有型を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/09/15  固定payload redirect照合用viewを追加。
 * Ver.01.02.00 Shunji Ogawa  2026/09/15  各HTTP hop開始前の期限再検証を追加。
 * Ver.01.03.00 Shunji Ogawa  2026/09/15  取得予算でgrant上限を狭める準備引数を追加。
 * Ver.01.04.00 Shunji Ogawa  2026/10/12  署名索引の共通取得境界と既存経路の区別を追加。
 * Ver.01.04.01  Shunji Ogawa  2026/10/16  特殊メンバーの所有権・既定動作の契約を明記。
 * </pre>
 *
 * @note Provider worker threadで直列使用します。完全URLはHTTP送信境界だけへ貸し出し、
 *       header、credential、request body、redirect先を本型に追加できません。
 * @see docs/adr/0152-record-scoped-official-download-delegation.md
 */
//------------------------------------------------------------------------------

#pragma once

#include "platform/official_download_grant.h"
#include "platform/secret_official_url.h"

#include <cstdint>
#include <string_view>

namespace drivercrate {

/**
 * @brief Record限定GET requestのworker内lifecycleを表します。
 */
enum class OfficialDelegatedGetState {
	/// Grantをclaimしていない状態です。
	EMPTY,
	/// 秘密URLを所有し、GET開始前の状態です。
	READY,
	/// 秘密URLを一回のGET境界へ貸出済みです。
	STARTED,
	/// URLを消去し、再使用できない状態です。
	CONSUMED,
} ;

/**
 * @brief Claim済みrecord grantから一回のGETだけを所有します。
 * @note 本型はmethod選択、任意header、credential、Referer、Cookie、bodyのfieldを持ちません。
 * @warning `prepare`へ渡したgrantはrequestより長生きさせてください。
 */
class OfficialDelegatedGetRequest final {
public:
	/**
	 * @brief Grant未結合の空requestを作ります。
	 */
	OfficialDelegatedGetRequest() noexcept = default ;

	/**
	 * @brief 未終端requestを失敗とし、秘密URLを消去します。
	 */
	~OfficialDelegatedGetRequest() noexcept ;

	/**
	 * @brief claim済みgrantとGET終端責務の二重管理を防ぐため、コピー構築を禁止する。
	 */
	OfficialDelegatedGetRequest( const OfficialDelegatedGetRequest &) = delete ;
	/**
	 * @brief claim済みgrantとGET終端責務を別個体の状態で上書きさせないため、コピー代入を禁止する。
	 */
	OfficialDelegatedGetRequest &operator=( const OfficialDelegatedGetRequest &) = delete ;

	/**
	 * @brief Requestとgrantへの終端責務を移動します。
	 * @param[in,out] other 空状態へ戻る移動元。
	 */
	OfficialDelegatedGetRequest( OfficialDelegatedGetRequest &&other) noexcept ;

	/**
	 * @brief 現在のrequestを安全に中止し、別requestの所有権を移動します。
	 * @param[in,out] other 空状態へ戻る移動元。自己代入も許可します。
	 * @return このobjectへの参照。
	 */
	OfficialDelegatedGetRequest &operator=( OfficialDelegatedGetRequest &&other) noexcept ;

	/**
	 * @brief SessionとID・30秒余裕をgrantで検証し、秘密URL所有権を引き取ります。
	 * @param[in,out] grant 成功時に`ACQUIRING`となり、request終了まで生存するgrant。
	 * @param[in] scanSessionId 現在のworker scan session ID。
	 * @param[in] grantId 操作が指定したopaque grant ID。
	 * @param[in] nowUtcSeconds 最初のrequest開始直前UTC秒。
	 * @param[in] maximumBytes Session予算と公開sizeで狭めた0ではない受信上限。
	 * @return 準備成功時は0、再使用・stale・期限切れ・所有権不整合はHRESULT bit pattern。
	 * @pre 本requestは`EMPTY`です。
	 * @post 成功時は`READY`です。
	 */
	[[nodiscard]] NativeError prepare( RecordScopedDownloadGrant &grant, ScanSessionId scanSessionId,
									  std::uint64_t grantId, std::uint64_t nowUtcSeconds,
									  std::uint64_t maximumBytes) noexcept ;

	/**
	 * @brief 所有中のexact targetを一回のHTTP GET開始境界へ貸し出します。
	 * @param[out] exactTarget 成功時にだけrequest所有の完全URLを参照するview。
	 * @return 最初の開始成功時は0、未準備・再使用・空URLはHRESULT bit pattern。
	 * @post 成功時は`STARTED`です。
	 * @warning ViewをHTTP parserと`WinHttpOpenRequest`呼出しより長く保持しないでください。
	 */
	[[nodiscard]] NativeError beginGet( std::wstring_view &exactTarget) noexcept ;

	/**
	 * @brief Grantの取得結果を確定し、requestの秘密URLを消去します。
	 * @param[in] outcome `RecordScopedDownloadGrant::finishAcquisition`が許可する終端結果。
	 * @param[in] error 成功は0、それ以外は0ではない診断値。
	 * @return Grantの終端成功時は0、不正状態・結果・診断値はHRESULT bit pattern。
	 * @post 成功時は`CONSUMED`でURLを保持しません。
	 */
	[[nodiscard]] NativeError finish( OfficialDownloadGrantState outcome,
									 NativeError				error) noexcept ;

	/**
	 * @brief URLを公開せず現在のrequest状態を返します。
	 * @return Worker内requestの現在状態。
	 */
	[[nodiscard]] OfficialDelegatedGetState state() const noexcept ;

	/**
	 * @brief Grantが許可した有限受信上限を返します。
	 * @return `READY`または`STARTED`の上限byte数。それ以外は0。
	 */
	[[nodiscard]] std::uint64_t				maximumBytes() const noexcept ;

	/**
	 * @brief 固定payload policy照合に使うProvider stable IDを返します。
	 * @return `READY`または`STARTED`のProvider ID。それ以外は空view。
	 */
	[[nodiscard]] std::wstring_view			providerId() const noexcept ;

	/**
	 * @brief 固定payload policy照合に使うresource IDを返します。
	 * @return `READY`または`STARTED`のpayload resource ID。それ以外は空view。
	 */
	[[nodiscard]] std::wstring_view			payloadResourceId() const noexcept ;

	/**
	 * @brief 現在のGET hopを開始できる期限余裕があるか検証します。
	 * @param[in] nowUtcSeconds Hop開始直前のUTC秒。
	 * @return 30秒以上の余裕があれば0、状態不整合・時計異常・期限不足はHRESULT bit pattern。
	 */
	[[nodiscard]] NativeError validateStartDeadline( std::uint64_t nowUtcSeconds) const noexcept ;

	/**
	 * @brief 認識済み外部expiryを持つ初回grantか返します。
	 * @return 外部expiryがあり、root再解決回数が0の有効requestならtrue。
	 * @note 本値だけでは再解決を実行せず、期限または最初の401／403を別途要求します。
	 */
	[[nodiscard]] bool		  canReresolveExpiringTarget() const noexcept ;
	/** @brief 現requestのgrant由来を非機密分類で返します。
	 * @return 結合済みgrant由来。空requestでは従来分類です。
	 */
	[[nodiscard]] OfficialDownloadGrantOrigin origin() const noexcept ;
	/** @brief 索引grant自身の封印exact routeを再照合します。
	 * @param[in] target 現hopの完全URL。
	 * @param[in] hop 0起点hop位置。
	 * @param[in] finalResponse 最終200 responseの確認指定。
	 * @return 生存封印・exact順一致時0。それ以外は拒否HRESULT。
	 */
	[[nodiscard]] NativeError validateSignedIndexHop( std::wstring_view target, std::uint32_t hop,
													 bool finalResponse) const noexcept ;
	/** @brief Grantが固定した期待content typeを借用します。
	 * @return 結合grantの期待形式。空requestは空です。
	 */
	[[nodiscard]] std::wstring_view expectedContentType() const noexcept ;

private:
	/**
	 * @brief 未終端grantを失敗へ進め、request所有値を消去します。
	 */
	void					   abandon() noexcept ;

	/**
	 * @brief 秘密URL・grant終端責務と非機密状態を移動します。
	 * @param[in,out] other 空に戻る移動元。
	 */
	void					   moveFrom( OfficialDelegatedGetRequest &other) noexcept ;

	/// Request完了まで生存する所有外grant。
	RecordScopedDownloadGrant *grant_{} ;
	/// 一回のGETだけに貸し出すrecord直結の完全URL。
	SecretOfficialUrl		   targetUrl_ ;
	/// URLを含まないworker内request状態。
	OfficialDelegatedGetState  state_{OfficialDelegatedGetState::EMPTY} ;
	/// Grantが固定した受信上限byte数。
	std::uint64_t			   maximumBytes_{} ;
} ;

} // namespace drivercrate
