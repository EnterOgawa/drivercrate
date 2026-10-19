//------------------------------------------------------------------------------
/**
 * @file driver_package_signature_internal.h
 * @brief 実byteへ固定した内部署名API fixtureと製品native dispatchを定義します。
 * @version 01.06.00
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
	/** @brief 同threadの表を解除し、native backendを汚染しません。 */
	~ScopedAuthenticodeFixture() noexcept ;
	/** @brief Thread限定の署名scopeの複製を禁止します。
	 * @param[in] other 借用scopeです。本constructorは呼出し禁止です。
	 */
	ScopedAuthenticodeFixture( const ScopedAuthenticodeFixture &other) = delete ;
	/** @brief Thread限定の署名scopeの代入を禁止します。
	 * @param[in] other 借用scopeです。本演算子は呼出し禁止です。
	 * @return 本演算子は呼出し禁止です。
	 */
	ScopedAuthenticodeFixture			&operator=( const ScopedAuthenticodeFixture &other) = delete ;
	/** @brief 元低位表だけを借用します。
	 * @return scope中不変で完全なWindows ABI表です。
	 */
	[[nodiscard]] const AuthenticodeApi &api() const noexcept
	{
		return api_ ;
	}

private:
	friend struct Access ;
	/** @brief 完全な内部表だけを同threadへ固定します。
	 * @param[in] api 欠損を持たない内部Windows ABI表です。
	 */
	explicit ScopedAuthenticodeFixture( AuthenticodeApi api) noexcept ;
	/// Scopeが単独所有する完全低位表です。
	AuthenticodeApi api_ ;
} ;
/** @brief 製品は固定native、内部scopeは欠損のない元ABIへ戻します。
 * @return 同threadの不変低位表です。部分的なnative fallbackはありません。
 */
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
/** @brief 本workerのfixture呼出しとnative fallbackの非発生を観測します。 */
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
	/** @brief 本threadのfixtureを解除します。 */
	~ScopedFixture() noexcept ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ScopedFixture( const ScopedFixture &) = delete ;
	/**
	 * @brief 所有状態の複製をコンパイル時に禁止します。
	 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
	 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
	 */
	ScopedFixture		 &operator=( const ScopedFixture &) = delete ;
	/** @brief 秘密pathを含まない呼出し件数を返します。
	 * @return Scope中だけ有効な有限receipt。
	 */
	[[nodiscard]] Receipt receipt() const noexcept ;

private:
	friend struct Access ;
	/** @brief 完全な固定file集合だけを所有します。
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
	/// VERIFYへ使用したexact memberとCLOSE待機状態。
	std::wstring			  pendingMember_ ;
	/// 今回のcall receipt。
	Receipt					  receipt_ ;
	friend BOOL setupVerifyInf( PCWSTR, PSP_ALTPLATFORM_INFO, PSP_INF_SIGNER_INFO_W) noexcept ;
	friend LONG verifyTrust( HWND, GUID *, LPVOID) noexcept ;
} ;
/** @brief 製品wrapperは固定native、内部scopeは実hash付き完全fixtureへdispatchします。
 * @param[in] path 実INF絶対path。
 * @param[in] platform Windowsのplatform条件。
 * @param[out] signer Windows標準のCAT/signature出力。
 * @return 署名API成功TRUE、拒否FALSE。
 */
[[nodiscard]] BOOL setupVerifyInf( PCWSTR path, PSP_ALTPLATFORM_INFO platform,
								  PSP_INF_SIGNER_INFO_W signer) noexcept ;
/** @brief 同member/tag/policyのVERIFYとCLOSEを同じbackendで処理します。
 * @param[in] window 親window。内部fixtureはnullptrだけを受理します。
 * @param[in] action Windows標準policy GUID。
 * @param[in,out] data 完全なWINTRUST_DATA。
 * @return 検証成功0、それ以外は元trust error。
 */
[[nodiscard]] LONG verifyTrust( HWND window, GUID *action, LPVOID data) noexcept ;
// 内部試験だけへfactoryを公開し、製品constructorや設定へ注入しません。
#if defined( DRIVERCRATE_INTERNAL_INDEX_TESTS)
/** @brief 全低位callを固定fileへ照合する内部成功fixture factoryです。 */
struct Access {
	/** @brief 完全低位Authenticode表を同workerへ固定します。
	 * @param[in] api 全八ABIが揃った内部表です。外部設定は受理しません。
	 * @return 完全表だけの単独scope、不足または別scope存在時nullptrです。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedAuthenticodeFixture> createAuthenticode(
		AuthenticodeApi api) ;
	/** @brief 未登録file・未知hash・重複を拒否して本worker lifetimeへ固定します。
	 * @param[in] files 直下INF/CATと安全相対参照memberの完全な原byte hash。最大387file／129INFです。
	 * @param[in] maximumRoots 完全なroot-INF-owner組の数。1～129だけを受理します。
	 * @return 完全集合の場合だけscope。任意の署名合格boolを受理しません。
	 */
	[[nodiscard]] static std::unique_ptr<ScopedFixture> create( std::vector<FixtureFile> files,
															   std::size_t maximumRoots = 1U) ;
} ;
#endif
} // namespace drivercrate::driver_package_signature_detail
