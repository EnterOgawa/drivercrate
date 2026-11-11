//------------------------------------------------------------------------------
/**
 * @file driver_package_signature_internal.h
 * @brief 実byteへ固定した内部署名API fixtureと製品native dispatchを定義します。
 * @version 01.08.01
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  同workerの索引候補と指定導入の内部境界を追加。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  完全file集合へ固定した二保護rootの内部検証を追加。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  INF別完全原hash集合と33件cap境界の実rootを固定。
 * Ver.01.03.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.03.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.04.00 Shunji Ogawa  2026/10/13  内部CAT fixtureのroot-INF-owner組の有限契約を明示。
 * Ver.01.05.00 Shunji Ogawa  2026/10/13  同rootの安全相対memberと全位置/hash/owner照合の有限契約を明示。
 * Ver.01.06.00 Shunji Ogawa  2026/10/15  内部試験だけの128/129完全閉包と有限root容量を明示。
 * Ver.01.07.00 Shunji Ogawa  2026/10/24  原archive試験の引数なしnative署名adapterを追加。
 * Ver.01.08.00 Shunji Ogawa  2026/11/05  人工CAT宣言を元固定hashとroot/ownerへ限定接続。
 * Ver.01.08.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合。
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include <Windows.h>
#include <SetupAPI.h>
#include <wintrust.h>
#include <wincrypt.h>
#include <cstddef>
#include <memory>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate::driver_package_signature_detail {
/** @brief 同じWindows ABIだけでAuthenticodeと証明書読取りを差し替える完全表です。 */
struct AuthenticodeApi {
	/// Generic file trustのVERIFY/CLOSEを検査する元ABIです。
	decltype( &WinVerifyTrust)			  verify{} ;
	/// Embedded PKCS7を取得する元ABIです。
	decltype( &CryptQueryObject)			  query{} ;
	/// Signer情報の二段階照会を行う元ABIです。
	decltype( &CryptMsgGetParam)			  messageParameter{} ;
	/// Issuer/serialへ一致する証明書を探す元ABIです。
	decltype( &CertFindCertificateInStore) findCertificate{} ;
	/// Certificateのexact publisher名を返す元ABIです。
	decltype( &CertGetNameStringW)		  certificateName{} ;
	/// 借用したcertificateを解放する元ABIです。
	decltype( &CertFreeCertificateContext) freeCertificate{} ;
	/// Embedded messageを閉じる元ABIです。
	decltype( &CryptMsgClose)			  closeMessage{} ;
	/// Embedded certificate storeを閉じる元ABIです。
	decltype( &CertCloseStore)			  closeStore{} ;
} ;
/** @brief 同workerだけへ完全低位Authenticode表を固定する内部scopeです。 */
class ScopedAuthenticodeFixture final {
public:
	/**
	 * @brief 同threadの表を解除し、native backendを汚染しません。
	 */
	~ScopedAuthenticodeFixture() noexcept ;
	/**
	 * @brief Thread限定の署名scopeの複製を禁止します。
	 * @param[in] other 借用scopeです。本constructorは呼出し禁止です。
	 */
	ScopedAuthenticodeFixture( const ScopedAuthenticodeFixture &other) = delete ;
	/**
	 * @brief Thread限定の署名scopeの代入を禁止します。
	 * @param[in] other 借用scopeです。本演算子は呼出し禁止です。
	 */
	ScopedAuthenticodeFixture			&operator=( const ScopedAuthenticodeFixture &other) = delete ;
	/**
	 * @brief 元低位表だけを借用します。
	 * @return scope中不変で完全なWindows ABI表です。
	 */
	[[nodiscard]] const AuthenticodeApi &api() const noexcept
	{
		return api_ ;
	}

private:
	friend struct Access ;
	/**
	 * @brief 完全な内部表だけを同threadへ固定します。
	 * @param[in] api 欠損を持たない内部Windows ABI表です。
	 */
	explicit ScopedAuthenticodeFixture( AuthenticodeApi api) noexcept ;
	/// Scopeが単独所有する完全低位表です。
	AuthenticodeApi api_ ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 製品は固定native、内部scopeは欠損のない元ABIへ戻します。
 * @return 同threadの不変低位表です。部分的なnative fallbackはありません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] const AuthenticodeApi &authenticodeApi() noexcept ;
/** @brief 低位署名APIへ結合する実fileの固定期待hashです。 */
struct FixtureFile {
	/// 同じ保護rootの安全な完全相対名です。INF/CATは直下、参照memberだけsubdirを許します。
	std::wstring name ;
	/// 元fixture byteの小文字SHA-256。実fileを毎回照合します。
	std::wstring sha256 ;
	/// この完全閉包の基本INF名です。旧単一集合だけは空を許します。
	std::wstring infOwner ;
} ;
/** @brief 本workerで明示選択された署名backendの呼出し件数を観測します。 */
struct Receipt {
	/// 実byteを全て照合したrootと元INF-owner組の数です。同directoryの役割も別に固定します。
	std::size_t inspectionRoots{} ;
	/// 実INF署名APIの呼出し数。
	std::size_t setupCalls{} ;
	/// 実member trust検証の呼出し数。
	std::size_t verifyCalls{} ;
	/// 同trust終了の呼出し数。
	std::size_t closeCalls{} ;
	/// 入力・hash・policy拒否の呼出し数。
	std::size_t rejectedCalls{} ;
} ;
struct Access ;
/** @brief 同threadへ固定した完全署名fixtureをscope所有します。 */
class ScopedFixture final {
public:
	/**
	 * @brief 本threadのfixtureを解除します。
	 */
	~ScopedFixture() noexcept ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ScopedFixture( const ScopedFixture &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ScopedFixture		 &operator=( const ScopedFixture &) = delete ;
	/**
	 * @brief 秘密pathを含まない呼出し件数を返します。
	 * @return Scope中だけ有効な有限receipt。
	 */
	[[nodiscard]] Receipt receipt() const noexcept ;

private:
	friend struct Access ;
	/**
	 * @brief 内部factoryだけが既存native署名への委譲scopeを作ります。
	 */
	ScopedFixture() noexcept ;
	/**
	 * @brief 完全な固定file集合だけを所有します。
	 * @param[in] files INF/CATと参照fileの固定hash集合。
	 * @param[in] maximumRoots 固定集合を許す保護root-INF-owner組数。内部factoryだけが1～129を指定します。
	 */
	explicit ScopedFixture( std::vector<FixtureFile> files, std::size_t maximumRoots) ;
	/// 実fileを照合する完全な固定集合。
	std::vector<FixtureFile>  files_ ;
	/// 各ownerの全file実hashを照合済みの絶対root。同rootをowner別に最大129組保持します。
	std::vector<std::wstring> roots_ ;
	/// 各実rootへ固定した完全閉包の元INF名です。roots_と同位置で組を識別します。
	std::vector<std::wstring> rootOwners_ ;
	/// Factoryが予約した保護root-INF-owner組の上限。129は共通archive128上限の拒否入力用です。
	std::size_t				  maximumRoots_{} ;
	/// 明示内部factoryだけが有効にする、元Windows署名APIへの引数不変委譲です。
	bool					  nativeAdapter_{} ;
	/// VERIFYへ使用したexact memberとCLOSE待機状態。
	std::wstring			  pendingMember_ ;
	/// 今回のcall receipt。
	Receipt					  receipt_ ;
	/**
	 * @brief 製品は固定native、内部scopeは実hash fixtureまたは明示native adapterへdispatchします。
	 * @note 第1引数（PCWSTR、in）はこの宣言では無名です。実INF絶対第1引数。
	 * @note 第2引数（PSP_ALTPLATFORM_INFO、in）はこの宣言では無名です。Windowsの第2引数条件。
	 * @note 第3引数（PSP_INF_SIGNER_INFO_W、out）はこの宣言では無名です。Windows標準のCAT/signature出力。
	 * @return 署名API成功TRUE、拒否FALSE。
	 */
	friend BOOL setupVerifyInf( PCWSTR, PSP_ALTPLATFORM_INFO, PSP_INF_SIGNER_INFO_W) noexcept ;
	/**
	 * @brief 同member/tag/policyのVERIFYとCLOSEを同じbackendで処理します。
	 * @note 第1引数（HWND、in）はこの宣言では無名です。親第1引数。内部fixtureはnullptrだけを受理します。
	 * @note 第2引数（GUID *、in）はこの宣言では無名です。Windows標準policy GUID。
	 * @note 第3引数（LPVOID、in,out）はこの宣言では無名です。完全なWINTRUST_DATA。
	 * @return 検証成功0、それ以外は元trust error。
	 */
	friend LONG verifyTrust( HWND, GUID *, LPVOID) noexcept ;
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
	/**
	 * @brief 既存の明示人工scopeだけで、確認済み同root/ownerの元member hashを取得します。
	 * @note 第1引数（std :: wstring_view、in）はこの宣言では無名です。元固定CATの完全第1引数です。
	 * @note 第2引数（std :: vector < std :: wstring > &、out）はこの宣言では無名です。全成功時だけ人工memberの元SHA256集合です。失敗時は
	 *       空です。
	 * @return 元CAT/全file/root-ownerが同scopeで確認済みの場合だけtrueです。
	 * @note 実CATやnative adapterへは適用せず、署名や実適合の根拠を作りません。
	 */
	friend bool readSyntheticCatalogDigests( std::wstring_view,
											std::vector<std::wstring> &) noexcept ;
#endif
} ;
//------------------------------------------------------------------------------
/**
 * @brief 製品は固定native、内部scopeは実hash fixtureまたは明示native adapterへdispatchします。
 * @param[in] path 実INF絶対path。
 * @param[in] platform Windowsのplatform条件。
 * @param[out] signer Windows標準のCAT/signature出力。
 * @return 署名API成功TRUE、拒否FALSE。
 */
//------------------------------------------------------------------------------
[[nodiscard]] BOOL setupVerifyInf( PCWSTR path, PSP_ALTPLATFORM_INFO platform,
								  PSP_INF_SIGNER_INFO_W signer) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 同member/tag/policyのVERIFYとCLOSEを同じbackendで処理します。
 * @param[in] window 親window。内部fixtureはnullptrだけを受理します。
 * @param[in] action Windows標準policy GUID。
 * @param[in,out] data 完全なWINTRUST_DATA。
 * @return 検証成功0、それ以外は元trust error。
 */
//------------------------------------------------------------------------------
[[nodiscard]] LONG verifyTrust( HWND window, GUID *action, LPVOID data) noexcept ;
// 内部試験だけへfactoryを公開し、製品constructorや設定へ注入しません。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
//------------------------------------------------------------------------------
/**
 * @brief 既存の明示人工scopeだけで、確認済み同root/ownerの元member hashを取得します。
 * @param[in] path 元固定CATの完全pathです。
 * @param[out] hashes 全成功時だけ人工memberの元SHA256集合です。失敗時は空です。
 * @return 元CAT/全file/root-ownerが同scopeで確認済みの場合だけtrueです。
 * @note 実CATやnative adapterへは適用せず、署名や実適合の根拠を作りません。
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool readSyntheticCatalogDigests( std::wstring_view		  path,
											   std::vector<std::wstring> &hashes) noexcept ;
/** @brief 固定file fixtureまたは元nativeへの委譲を同threadへ結ぶ内部factoryです。 */
struct Access {
	/**
	 * @brief 元Windows署名APIへそのまま委譲する内部scopeを作ります。
	 * @return 同threadに既存scopeがなければ単独所有adapter、それ以外はnullptrです。
	 * @note 成功値/publisher/検証policyを補完せず、証明書通信を含む元APIの動作を保持します。公開JSON/成功bool/鍵を受けず、実inventoryや取得・導入能
	 *       力を発行しません。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture>				createNativeAdapter() ;
	/**
	 * @brief 完全低位Authenticode表を同workerへ固定します。
	 * @param[in] api 全八ABIが揃った内部表です。外部設定は受理しません。
	 * @return 完全表だけの単独scope、不足または別scope存在時nullptrです。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedAuthenticodeFixture> createAuthenticode(
		AuthenticodeApi api) ;
	/**
	 * @brief 未登録file・未知hash・重複を拒否して本worker lifetimeへ固定します。
	 * @param[in] files 直下INF/CATと安全相対参照memberの完全な原byte hash。最大387file／129INFです。
	 * @param[in] maximumRoots 完全なroot-INF-owner組の数。1～129だけを受理します。
	 * @return 完全集合の場合だけscope。任意の署名合格boolを受理しません。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture> create( std::vector<FixtureFile> files,
															   std::size_t maximumRoots = 1U) ;
} ;
#endif
} // namespace drivercrate::driver_package_signature_detail
