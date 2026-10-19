//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding.h
 * @brief 元認証recordと実取得閉包から候補と指定導入routeを私有保持します。
 * @version 01.03.00
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
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  複数INFと元共有taskのdevice別pairを保持。
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続。
 * Ver.01.02.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足。
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  一候補の必要計画と復旧前の全選択再確認を結合。
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません。
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/official_preparation_audit.h"
#include "platform/official_delegated_package_inspection.h"
#include "platform/official_inf_install_binding.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/signed_index_record_lookup.h"
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace drivercrate {
class SignedIndexScanSession ;
class DriverStoreProvider ;
class CompositeUpdateProvider ;
class SignedIndexAcquisitionAdapter ;
namespace provider_worker_index_detail {
struct Services ;
}
namespace signed_index_candidate_binding_detail {
struct Access ;
}
/** @brief 外部DTOから構築できない同workerの候補・token・閉包所有者です。 */
class SignedIndexCandidateBindingSession final {
private:
	friend class SignedIndexScanSession ;
	friend class CompositeUpdateProvider ;
	friend struct signed_index_candidate_binding_detail::Access ;
	/** @brief 元同scanの一意なtargetと既表示参照行を結合します。 */
	struct Reference {
		/// 原認証lookupのglobal関係位置。
		std::size_t					relationIndex{} ;
		/// describeが生成した未変更の取得対象。
		OfficialPreparationTarget	target ;
		/// 同Providerの既表示非導入行。
		UpdateCandidate				candidate ;
		/// 元Driver Store現在行。現在版不足を補完しません。
		UpdateCandidate				current ;
		/// 元deviceの検証済みopaque hint。
		OfficialDiscoveryDeviceHint hint ;
	} ;
	/** @brief 元取得task・grant・seal・全内容をmove所有します。 */
	struct PreparedRecord {
		/// 共有寿命を権限寿命にしない同認証lookup。
		std::shared_ptr<const SignedIndexRecordLookup> lookup ;
		/// 原scan operationとinventoryの未変更context。
		IndexLookupContext							   context ;
		/// claimした元取得task全文。
		OfficialPreparationTask						   task ;
		/// 同issuerが発行し消費した一回grant。
		RecordScopedDownloadGrant					   grant ;
		/// 私有ledgerへ結合する実取得結果。
		OfficialAcquisitionResult					   acquisition ;
		/// 公開DTOから作れない実file seal。
		OfficialAcquiredFileEvidence				   seal ;
		/// 原record・実archiveの期待値。
		IndexedDriverArchiveHint					   hint ;
		/// 同元保護archive入力。
		DriverArchiveInput							   input ;
		/// 同消費済みgrantから作った非authorityの入力。
		DelegatedOfficialPackageInput				   delegated ;
		/// 本体共通検査がmove所有する個別INFと閉包。
		IndexedDriverPackageInspection				   inspection ;
		/// 原EXE/MSIの専用検査です。標準INFへ変換しません。
		bool										   installerHandoff{} ;
		/// 元認証方式がWINDOWS_MSIの場合だけtrueです。
		bool										   msi{} ;
		/// 元descriptorのexact期待publisherです。
		std::wstring								   publisher ;
		/// 専用内容検査の元HRESULTです。検査未実施を成功へ数えません。
		NativeError									   installerError{} ;
		/// 同私有参照行の0起点位置。
		std::size_t									   referenceIndex{} ;
		/** @brief 元recordを同workerで未発行状態に作ります。 */
		PreparedRecord() = default ;
		/**
		 * @brief 所有状態の複製をコンパイル時に禁止します。
		 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
		 */
		PreparedRecord( const PreparedRecord &) = delete ;
		/**
		 * @brief 所有状態の複製をコンパイル時に禁止します。
		 * @return 宣言された自己参照型。削除宣言のため戻り値を生成する呼出しは成立しません。
		 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません。
		 */
		PreparedRecord &operator=( const PreparedRecord &) = delete ;
		/** @brief 元権限・実byte・内容の所有だけを移します。
		 * @param[in,out] other 再検証不能になる移動元。
		 */
		PreparedRecord( PreparedRecord &&other) noexcept = default ;
		/** @brief 元権限・実byte・内容を同所有者へ移します。
		 * @param[in,out] other 再検証不能になる移動元。
		 * @return 移動先。
		 */
		PreparedRecord &operator=( PreparedRecord &&other) noexcept = default ;
	} ;
	/** @brief 一INF-deviceの元HRESULT、rank、bindingとrouteを保持します。 */
	struct Pair {
		/// 動的配列pointerへ依存しない私有record位置。
		std::size_t										   recordIndex{} ;
		/// 同record内の元INF位置。
		std::size_t										   infOrdinal{} ;
		/// 同取得task内で当該deviceへ結合した元参照位置。
		std::size_t										   referenceIndex{} ;
		/// 同scanのopaque device。
		std::wstring									   deviceIdentity ;
		/// Windows候補観測の元HRESULT。
		NativeError										   observerError{} ;
		/// 元Windows candidate node rank。未観測・非適用は空です。
		std::optional<std::uint32_t>					   observedRank ;
		/// 現在driverとの完全rank監査。
		OfficialDriverRankAudit							   rankAudit ;
		/// rank/binding発行の元HRESULT。
		NativeError										   bindingError{} ;
		/// Driver Storeの私有unique token。
		OfficialInfInstallBinding						   binding ;
		/// 元検証済みbyteから生成し同issuerへ固定した必要役割計画です。
		std::shared_ptr<const RequiredDriverComponentPlan> requiredPlan ;
		/// 同issuerの元present/current専用guardです。INFのrank tokenと分けます。
		std::uint64_t									   installerToken{} ;
		/// 全guard後の表示用候補。権限は元record/tokenに保持します。
		UpdateCandidate									   candidate ;
	} ;
	/** @brief 未発行の私有ownerを作ります。 */
	SignedIndexCandidateBindingSession() = default ;
	/** @brief 新candidate・tokenを一括rollbackします。
	 * @param[in,out] store 元token issuer。
	 */
	void									   rollback( DriverStoreProvider &store) noexcept ;
	/** @brief 全検証後だけ新routeをnoexcept swapします。 */
	void									   commit() noexcept ;
	/** @brief 全route・record・参照行を終端失効します。
	 * @param[in,out] store 元issuer。未結合の場合nullptrです。
	 */
	void									   invalidate( DriverStoreProvider *store) noexcept ;
	/** @brief 同describeのtargetへ一意に元current行を結合します。
	 * @param[in] lookup 原認証lookup。
	 * @param[in] adapter 同原lookupの全元関係を保持する取得issuer。
	 * @param[in] plan 同scanの未変更取得計画。
	 * @param[in] candidates 同scanの既表示現在行。
	 * @param[in] hints 同deviceの検証済みopaque hint。
	 * @return 元recordと同deviceへ結合した非導入参照行。
	 */
	[[nodiscard]] std::vector<UpdateCandidate> makeReferences(
		const std::shared_ptr<const SignedIndexRecordLookup> &lookup,
		const SignedIndexAcquisitionAdapter &adapter, const OfficialPreparationPlan &plan,
		std::span<const UpdateCandidate>			 candidates,
		std::span<const OfficialDiscoveryDeviceHint> hints) ;
	/** @brief 元取得と実sealを再確認して内容・rank・bindingをpendingへ監査します。
	 * @param[in,out] owner 元scan/取得の私有owner。
	 * @param[in,out] store 同workerのDriver Store。
	 * @param[in] services 元worker固定service。
	 * @param[in] targetIdentity 元取得target。
	 * @param[in] displayed 同scan既表示行。
	 * @return 当該取得成功を保持する有限report。別targetでは空です。
	 */
	[[nodiscard]] std::optional<OfficialPreparationAuditReport> auditPreparedRecord(
		SignedIndexScanSession &owner, DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, std::wstring_view targetIdentity,
		std::span<const UpdateCandidate> displayed) ;
	/** @brief 元task/grant/期限/seal/実byteを同所有者へ再照合します。
	 * @param[in] owner 同取得issuer/元workspace。
	 * @param[in] record 同所有record。
	 * @param[in] services Worker固定のUTC。
	 * @return 完全一致0、失効・期限・内容変化の元HRESULT。
	 */
	[[nodiscard]] NativeError reverifyRecord(
		const SignedIndexScanSession &owner, const PreparedRecord &record,
		const provider_worker_index_detail::Services &services) const ;
	/** @brief 必要役割を含む元選択を復旧開始前に一括検証します。
	 * @param[in] owner 元取得ownerです。
	 * @param[in] store 同workerの元binding issuerです。
	 * @param[in] services 元期限serviceです。
	 * @param[in] session 元scanです。
	 * @param[in] identities 通常画面の元選択ID集合です。
	 * @return 全元必要計画のbyte/期限/状態一致0、不足はHRESULTです。
	 * @note 他Providerを変更せず、stage/復旧/導入を呼びません。
	 */
	[[nodiscard]] NativeError preflightRequiredInstall(
		const SignedIndexScanSession &owner, const DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, ScanSessionId session,
		std::span<const std::wstring> identities) const ;
	/** @brief 本体保護境界内で元選択routeだけを指定導入します。
	 * @param[in,out] owner 元取得と内容の私有owner。
	 * @param[in,out] store 同workerのDriver Store。
	 * @param[in] services Worker固定service。
	 * @param[in] session 元scan session。
	 * @param[in] identities 本体が許可した元表示/選択ID。
	 * @param[in] parentWindowNative 最終dialog親window。
	 * @param[in] progress 確定件数の通知先。
	 * @return 元選択順の独立取得/導入/元HRESULTと再起動結果。
	 */
	[[nodiscard]] InstallResult executeBoundInstall(
		SignedIndexScanSession &owner, DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, ScanSessionId session,
		std::span<const std::wstring> identities, std::uintptr_t parentWindowNative,
		const ProviderProgressCallback &progress) ;
	/// 最大256件の元targetと既表示行。
	std::vector<Reference>		references_ ;
	/// 元取得権限/byte/内容を単独所有する最大256record。
	std::vector<PreparedRecord> records_ ;
	/// 全監査における元pair結果。観測0を適用性合格へしません。
	std::vector<Pair>			pairs_ ;
	/// 本体publicationと同時にcommitしたroute集合。
	std::vector<Pair>			routes_ ;
	/// 既存routeのcopyと今回の新tokenを全検証後にswapする集合。
	std::vector<Pair>			pendingRoutes_ ;
	/// Pending transactionが開始済みの場合trueです。
	bool						pending_{} ;
	/// 保持した実閉包byte。512MiB以下と元予算の最小値です。
	std::uint64_t				retainedBytes_{} ;
} ;
} // namespace drivercrate
