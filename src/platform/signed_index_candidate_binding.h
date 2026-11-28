//------------------------------------------------------------------------------
/**
 * @file signed_index_candidate_binding.h
 * @brief 元認証recordと実取得閉包から候補と指定導入routeを私有保持します
 * @version 01.21.00
 * @date 2026/10/12
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/12  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  複数INFと元共有taskのdevice別pairを保持
 * Ver.01.02.00 Shunji Ogawa  2026/10/12  元署名索引の同意・追加形式の安全境界を接続
 * Ver.01.02.01 Shunji Ogawa  2026/10/12  default/delete宣言の所有権と非実行契約を補足
 * Ver.01.03.00 Shunji Ogawa  2026/10/13  一候補の必要計画と復旧前の全選択再確認を結合
 * Ver.01.04.00 Shunji Ogawa  2026/11/03  未署名検査と通常候補の完全tuple比較を共用
 * Ver.01.05.00 Shunji Ogawa  2026/11/06  同一INFの代替OS Modelsを私有選択集合へ保持
 * Ver.01.06.00 Shunji Ogawa  2026/11/08  同内容候補の表示集約と元一件選択を保持
 * Ver.01.07.00 Shunji Ogawa  2026/11/10  対象限定の完了更新と未処理所有・本体再検証を接続
 * Ver.01.07.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.07.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.08.00 Shunji Ogawa  2026/11/18  純粋所有照合と最終Server Models/host再確認を分離
 * Ver.01.09.00 Shunji Ogawa  2026/11/19  正規client最低build条件も同所有Models・host再確認へ接続
 * Ver.01.10.00 Shunji Ogawa  2026/11/19  独自クラスの実選択を元署名レコードへ結合
 * Ver.01.11.00 Shunji Ogawa  2026/11/20  Catalog対象の元選択を復元準備と導入の直前へ引き継ぐ
 * Ver.01.12.00 Shunji Ogawa  2026/11/20  公式対象HardwareIdsを持つ導入経路の共通契約へ整合
 * Ver.01.13.00 Shunji Ogawa  2026/11/22  公式Modelsの内容結果を導入用の閉包と分けて保持
 * Ver.01.13.01 Shunji Ogawa  2026/11/22  公式Modelsの検査済み閉包だけを読み取り専用で動的保持
 * Ver.01.14.00 Shunji Ogawa  2026/11/22  専用Modelsの端末別候補と導入の原権限を保持
 * Ver.01.15.00 Shunji Ogawa  2026/11/23  同じ端末のWiX候補を閲覧専用で表示
 * Ver.01.16.00 Shunji Ogawa  2026/11/23  WiXの検査専用対象を同じ候補へ結合
 * Ver.01.17.00 Shunji Ogawa  2026/11/23  検査専用取得の保護規約とドライバー閉包を保持
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  同じ機器とWiX取得の私有参照を再照合
 * Ver.01.19.00 Shunji Ogawa  2026/11/23  WiXの単一起動候補を元規約の確認待ちで発行
 * Ver.01.20.00 Shunji Ogawa  2026/11/23  元規約に結ぶ導入同意と再検証の契約を追加
 * Ver.01.20.01 Shunji Ogawa  2026/11/27  初回検査と再照合で署名済み配布形式を共有
 * Ver.01.21.00 Shunji Ogawa  2026/11/28  全取得前参照に表示直前の個別期限を適用
 * </pre>
 *
 * @note Worker内だけで直列使用し、公開設定から取得権限を生成しません
 * @see docs/adr/0331-signed-index-acquisition-descriptor.md
 */
//------------------------------------------------------------------------------
#pragma once
#include "core/official_preparation_operation.h"
#include "core/official_preparation_audit.h"
#include "platform/official_delegated_package_inspection.h"
#include "platform/official_inf_install_binding.h"
#include "platform/indexed_driver_package_inspection.h"
#include "platform/official_wix_package.h"
#include "platform/signed_index_record_lookup.h"
#include "platform/signed_index_records.h"
#include <chrono>
#include <cstddef>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <vector>

namespace drivercrate {
struct ScopedInfInstallQualification ;
struct WixTermsPresentation ;

inline constexpr std::size_t MAXIMUM_WIX_INSTALL_CONSENTS = 256U ;	// 一スキャンの検査対象上限です

/** @brief 明示導入操作が引き受ける一候補と同じ元規約の表示証拠です */
struct WixInstallConsent {
	/// 同じスキャンの確認画面に表示した導入候補です
	std::wstring								candidateIdentity ;
	/// 元取得が発行した同じ全言語の不変表示です。Workerの所有参照との一致が必要です
	std::shared_ptr<const WixTermsPresentation> terms ;

	/**
	 * @brief 一回の復元なし続行に同じ元同意が渡ったかを比較します
	 * @param[in] other 同じ元操作と比較する候補と表示証拠です
	 * @return 候補IDと不変表示の元参照が等しい場合だけtrueです
	 */
	[[nodiscard]] bool operator==( const WixInstallConsent &other) const = default ;
} ;
//------------------------------------------------------------------------------
/**
 * @brief 同じINF/Modelsの原内容とpolicyだけを比較する表示専用判定です
 * @param[in] left 同じ署名snapshotから参照する原recordです
 * @param[in] right 同snapshotの別原recordです
 * @return 完全payload/policy・INF証拠・同Models/公表ID・version/日付一致時だけtrueです
 * @note 原Reference/record/routingを統合せず、取得・導入権限を発行しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool areIdenticalIndexDisplayChoices( const IndexDistributionRecord &left,
												   const IndexDistributionRecord &right) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 同一INFの異なる標準x64 OS装飾を持つ代替recordの厳密値比較です
 * @param[in] left 個別codec検査済みの元recordです
 * @param[in] right 同じ署名snapshotから参照する別の元recordです
 * @return 元payload/policy/期限・INF/hash/Class/版/公表ID全集合とModels base一致時だけtrueです
 * @note 認証/通信/適合/導入権限を発行しません。私有Referenceが元relation集合を別に所有します
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool areEquivalentIndexModelChoices( const IndexDistributionRecord &left,
												  const IndexDistributionRecord &right) noexcept ;
//------------------------------------------------------------------------------
/**
 * @brief 原record申告を通常候補と同じINF完全tuple比較へ渡します。許可を発行しません
 * @param[in] original 共通codecが検査した元record値です。認証の有無は表しません
 * @param[in] inspection 同元outerを所有する通常内容検査結果です
 * @param[in] hint 同元outerのsize/hashとrecord参照です
 * @param[in] inf 同保護workspaceの一INFです
 * @param[in] actual 同元HINFから再読取りした公開identityです
 * @return 元outer/INF/Models/Class/種別付き公開ID全集合が一致する場合trueです
 * @note Windows適合、rank、候補session、tokenを生成しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] bool matchesIndexPublishedInf( const IndexDistributionRecord		&original,
											const CommonDriverPackageInspection &inspection,
											const IndexedDriverArchiveHint		&hint,
											const CommonInfInspection			&inf,
											const OfficialInfPublishedIdentity	&actual) ;

class SignedIndexScanSession ;
class DriverStoreProvider ;
struct DeclarativeInfInstallQualification ;
class CompositeUpdateProvider ;
class SignedIndexAcquisitionAdapter ;
namespace provider_worker_index_detail {
struct Services ;
}
namespace signed_index_candidate_binding_detail {
struct Access ;
}
/** @brief 外部DTOから構築できない同workerの候補・token・閉包所有者です */
class SignedIndexCandidateBindingSession final {
private:
	friend class SignedIndexScanSession ;
	friend class CompositeUpdateProvider ;
	friend struct signed_index_candidate_binding_detail::Access ;
	/** @brief 元同scanの一意なtargetと既表示参照行を結合します */
	struct Reference {
		/// 原認証lookupのglobal関係位置
		std::size_t					relationIndex{} ;
		/// 同じ選択意図へ厳密集約した全原Models recordのrelation位置。代表も含む
		std::vector<std::size_t>	relationIndices ;
		/// describeが生成した未変更の取得対象
		OfficialPreparationTarget	target ;
		/// 同Providerの既表示非導入行
		UpdateCandidate				candidate ;
		/// 元Driver Store現在行。現在版不足を補完しません
		UpdateCandidate				current ;
		/// 元deviceの検証済みopaque hint
		OfficialDiscoveryDeviceHint hint ;
	} ;
	/** @brief 元取得task・grant・seal・全内容をmove所有します */
	struct PreparedRecord {
		/// 共有寿命を権限寿命にしない同認証lookup
		std::shared_ptr<const SignedIndexRecordLookup>		   lookup ;
		/// 原scan operationとinventoryの未変更context
		IndexLookupContext									   context ;
		/// claimした元取得task全文
		OfficialPreparationTask								   task ;
		/// 同vectorの元owned recordを直接指します。連鎖/循環は許可しません
		std::optional<std::size_t>							   ownedBodyRecordIndex ;
		/// 当該LOCAL taskの実検査照合票です。TRANSFER証拠を複写しません
		std::shared_ptr<const OfficialLocalInspectionEvidence> localInspection ;
		/// 同issuerが発行し消費した一回grant
		RecordScopedDownloadGrant							   grant ;
		/// 私有ledgerへ結合する実取得結果
		OfficialAcquisitionResult							   acquisition ;
		/// 公開DTOから作れない実file seal
		OfficialAcquiredFileEvidence						   seal ;
		/// 原record・実archiveの期待値
		IndexedDriverArchiveHint							   hint ;
		/// 同元保護archive入力
		DriverArchiveInput									   input ;
		/// 同消費済みgrantから作った非authorityの入力
		DelegatedOfficialPackageInput						   delegated ;
		/// 本体共通検査がmove所有する個別INFと閉包
		IndexedDriverPackageInspection						   inspection ;
		/// DMの元証拠で照合した非導入用の閉包です。保持した場合だけ非nullです
		std::shared_ptr<const CollectorDriverPackageContent>   scopedInspection ;
		/// 元署名EXEと同じ規約原文、MSIとドライバー閉包です。同じscanの検査専用で保持します
		std::shared_ptr<const OfficialWixDriverContent>		   wixInspection ;
		/// この元取得で発行した全言語の表示証拠です。同じものへの明示同意だけを照合します
		std::shared_ptr<const WixTermsPresentation>			   wixTerms ;
		/// 原EXE/MSIの専用検査です。標準INFへ変換しません
		bool												   installerHandoff{} ;
		/// 元認証方式がWINDOWS_MSIの場合だけtrueです
		bool												   msi{} ;
		/// 元descriptorのexact期待publisherです
		std::wstring										   publisher ;
		/// 専用内容検査の元HRESULTです。検査未実施を成功へ数えません
		NativeError											   installerError{} ;
		/// 同私有参照行の0起点位置
		std::size_t											   referenceIndex{} ;
		/**
		 * @brief 元recordを同workerで未発行状態に作ります
		 */
		PreparedRecord() = default ;
		/**
		 * @brief 所有状態の複製をコンパイル時に禁止します
		 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
		 */
		PreparedRecord( const PreparedRecord &) = delete ;
		/**
		 * @brief 所有状態の複製をコンパイル時に禁止します
		 * @note 引数の参照先を借用・変更せず、実行可能な関数本体はありません
		 */
		PreparedRecord &operator=( const PreparedRecord &) = delete ;
		/**
		 * @brief 元権限・実byte・内容の所有だけを移します
		 * @param[in,out] other 再検証不能になる移動元
		 */
		PreparedRecord( PreparedRecord &&other) noexcept = default ;
		/**
		 * @brief 元権限・実byte・内容を同所有者へ移します
		 * @param[in,out] other 再検証不能になる移動元
		 * @return 移動先
		 */
		PreparedRecord &operator=( PreparedRecord &&other) noexcept = default ;
	} ;
	/**
	 * @brief 元署名の配布形式と消費済みgrantを共通検査へ結ぶ
	 * @param[in] acquisition 元取得の確定結果
	 * @param[in] grant 同じ元取得で消費した権限
	 * @param[in] hint 封印から確認した元レコードと配布バイト
	 * @param[in] format 元署名レコードが指定した配布形式
	 * @param[out] input 成功時だけ共通検査入力。失敗時は空
	 * @return 元配布の照合成立で0、拒否時は元HRESULT
	 * @note 非実行形式の確定に実行ファイルの拡張子を使わない
	 */
	[[nodiscard]] static NativeError bindDelegatedInput(
		const OfficialAcquisitionResult &acquisition, const RecordScopedDownloadGrant &grant,
		const IndexedDriverArchiveHint &hint, IndexPayloadFormat format,
		DelegatedOfficialPackageInput &input) noexcept ;

	/** @brief 一INF-deviceの元HRESULT、rank、bindingとrouteを保持します */
	struct Pair {
		/// 動的配列pointerへ依存しない私有record位置
		std::size_t												  recordIndex{} ;
		/// 同record内の元INF位置
		std::size_t												  infOrdinal{} ;
		/// 同取得task内で当該deviceへ結合した元参照位置
		std::size_t												  referenceIndex{} ;
		/// 同参照集合内で実INF/Modelsの完全tupleへ唯一一致した原relation位置
		std::size_t												  relationIndex{} ;
		/// 同scanのopaque device
		std::wstring											  deviceIdentity ;
		/// Windows候補観測の元HRESULT
		NativeError												  observerError{} ;
		/// 元Windows candidate node rank。未観測・非適用は空です
		std::optional<std::uint32_t>							  observedRank ;
		/// 現在driverとの完全rank監査
		OfficialDriverRankAudit									  rankAudit ;
		/// 独自クラスで導入可能な元作用を確認した実選択
		std::shared_ptr<const DeclarativeInfInstallQualification> declarativeQualification ;
		/// 同原レコードと端末で選んだModels行・作用を保持する私有計画です
		std::shared_ptr<const ScopedInfInstallQualification>	  scopedQualification ;
		/// rank/binding発行の元HRESULT
		NativeError												  bindingError{} ;
		/// Driver Storeの私有unique token
		OfficialInfInstallBinding								  binding ;
		/// 元検証済みbyteから生成し同issuerへ固定した必要役割計画です
		std::shared_ptr<const RequiredDriverComponentPlan>		  requiredPlan ;
		/// 公式配布対象のHardwareIds限定証拠に結ぶ元選択です
		bool													  hardwareScoped{} ;
		/// 同issuerの元present/current専用guardです。INFのrank tokenと分けます
		std::uint64_t											  installerToken{} ;
		/// 全guard後の表示用候補。権限は元record/tokenに保持します
		UpdateCandidate											  candidate ;
	} ;
	/**
	 * @brief 未発行の私有ownerを作ります
	 */
	SignedIndexCandidateBindingSession() = default ;
	/**
	 * @brief 新candidate・tokenを一括rollbackします
	 * @param[in,out] store 元token issuer
	 */
	void											rollback( DriverStoreProvider &store) noexcept ;
	/**
	 * @brief 全検証後だけ新routeをnoexcept swapします
	 */
	void											commit() noexcept ;
	/**
	 * @brief 全route・record・参照行を終端失効します
	 * @param[in,out] store 元issuer。未結合の場合nullptrです
	 */
	void											invalidate( DriverStoreProvider *store) noexcept ;
	/**
	 * @brief 同じ署名レコードと端末へ発行した一意のWiX検査対象を選びます
	 * @param[in] lookup 表示する元の不変lookupです
	 * @param[in] adapter 同じ取得issuerです
	 * @param[in] plan 同じスキャンの元取得計画です
	 * @param[in] relation 表示する同じレコードと端末の元関係です
	 * @param[in] nowUtc 元期限の照合に使う表示直前の信頼UTCです
	 * @return 一意で有効な元取得参照の位置です。不明または曖昧なら値なしです
	 * @note 呼出し中だけ位置を借用します。通信、規約同意、導入許可は発行しません
	 */
	[[nodiscard]] static std::optional<std::size_t> findWixInspectionBinding(
		const std::shared_ptr<const SignedIndexRecordLookup> &lookup,
		const SignedIndexAcquisitionAdapter &adapter, const OfficialPreparationPlan &plan,
		const IndexRecordRelation &relation, std::chrono::sys_seconds nowUtc) ;
	/**
	 * @brief 照合済みの取得前参照を同じ端末の現在行へ結合します
	 * @param[in] lookup 原認証lookup
	 * @param[in] adapter 同原lookupの全元関係を保持する取得issuer
	 * @param[in] plan 同scanの未変更取得計画
	 * @param[in] candidates 同scanの既表示現在行
	 * @param[in] hints 同deviceの検証済みopaque hint
	 * @param[in] nowUtc 表示直前の信頼UTCです。未確認の場合は索引の参照を発行しません
	 * @return 元recordと同deviceへ結合した非導入参照行
	 * @note WiX候補は元計画と同じ端末への私有参照を保持し、検査専用の表示を返します
	 */
	[[nodiscard]] std::vector<UpdateCandidate> makeReferences(
		const std::shared_ptr<const SignedIndexRecordLookup> &lookup,
		const SignedIndexAcquisitionAdapter &adapter, const OfficialPreparationPlan &plan,
		std::span<const UpdateCandidate>			 candidates,
		std::span<const OfficialDiscoveryDeviceHint> hints,
		std::optional<std::chrono::sys_seconds>		 nowUtc) ;
	/**
	 * @brief 元取得と実sealを再確認して内容・rank・bindingをpendingへ監査します
	 * @param[in,out] owner 元scan/取得の私有owner
	 * @param[in,out] store 同workerのDriver Store
	 * @param[in] services 元worker固定service
	 * @param[in] targetIdentity 元取得target
	 * @param[in] displayed 同scan既表示行
	 * @param[in] cancellation 検査後の候補発行も停止する同取得操作の取消しです
	 * @return 当該取得成功を保持する有限report。別targetでは空です
	 */
	[[nodiscard]] std::optional<OfficialPreparationAuditReport> auditPreparedRecord(
		SignedIndexScanSession &owner, DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, std::wstring_view targetIdentity,
		std::span<const UpdateCandidate> displayed,
		const PreparationCancellation	&cancellation = {}) ;
	/**
	 * @brief WiXの同じ元機器一台に、元規約への同意を要する単一起動候補を発行します
	 * @param[in,out] owner 元取得と索引の所有者です
	 * @param[in,out] store 同じ端末のWindows選択を照合する所有者です
	 * @param[in] services 元期限を確認する依存です
	 * @param[in] recordIndex 元閉包と消費済み取得を持つ私有位置です
	 * @param[in] cancellation 同取得からの取消しです
	 * @return 適合性の結果と、発行条件が成立した場合だけ未確定の候補です
	 */
	[[nodiscard]] std::optional<OfficialPreparationAuditReport> auditWixPreparedRecord(
		SignedIndexScanSession &owner, DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, std::size_t recordIndex,
		const PreparationCancellation &cancellation) ;
	/**
	 * @brief 元task・grant・期限・封印・全参照と実byteを再照合します
	 * @param[in] owner 同取得issuer/元workspace
	 * @param[in] record 同所有record
	 * @param[in] services Worker固定のUTC
	 * @param[in] observeHost 取得入力の再照合で既定のホスト観測も行う場合trueです
	 * @return 完全一致0、失効・期限・内容変化の元HRESULT
	 * @note LOCAL claimを再消費しません
	 */
	[[nodiscard]] NativeError reverifyRecordBinding(
		const SignedIndexScanSession &owner, const PreparedRecord &record,
		const provider_worker_index_detail::Services &services, bool observeHost = true) const ;
	/**
	 * @brief 専用Modelsの端末関係から同じ取得を承認した原レコードを参照します
	 * @param[in] record 元取得を保持する記録です
	 * @param[in] pair 同じ承認に属する端末の候補です
	 * @return 元領域・レコード・端末が一致した専用レコードです。不一致時はnullptrです
	 */
	[[nodiscard]] const IndexDistributionRecord *scopedRouteOriginal( const PreparedRecord &record,
																	 const Pair &pair) const ;
	/**
	 * @brief 同じ端末・元署名・取得許可を現在の状態と時刻で確認します
	 * @param[in] owner 元スキャンと取得許可を持つ所有者です
	 * @param[in] record 元取得または再利用の記録です
	 * @param[in] pair 同じ端末とレコードを指す導入先です
	 * @param[in] services 観測後に実UTCを読むサービスです
	 * @return 元ホスト・端末・取得許可と原期限が成立すれば0、元拒否はHRESULTです
	 * @pre 同じ記録の元保護ファイルと所有を検査済みです
	 */
	[[nodiscard]] NativeError					 authorizeScopedRoute(
						   const SignedIndexScanSession &owner, const PreparedRecord &record, const Pair &pair,
						   const provider_worker_index_detail::Services &services) const ;
	/**
	 * @brief 専用候補の元ファイル・元レコード・端末の私有計画とトークンを確認します
	 * @param[in] owner 元取得を保持する同じスキャンです
	 * @param[in] store トークンを発行した同じDriver Storeです
	 * @param[in] services 元期限を確認するサービスです
	 * @param[in] record 同じ取得と閉包を所有する記録です
	 * @param[in] pair 同じ端末と候補を保持する導入先です
	 * @return 全照合成功0、元拒否はHRESULTです
	 * @note 後段の明示確認まではホスト観測や実変更を呼びません
	 */
	[[nodiscard]] NativeError reverifyScopedRoute(
		const SignedIndexScanSession &owner, const DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, const PreparedRecord &record,
		const Pair &pair) const ;
	/**
	 * @brief 所有済みの専用Models閉包から端末ごとの実用候補を発行待ちへ加えます
	 * @param[in] owner 元取得・元ホストの所有者です
	 * @param[in,out] store 同スキャンのトークン発行元です
	 * @param[in] services 元期限を確認するサービスです
	 * @param[in] recordIndex 同じ取得結果の私有位置です
	 * @param[in,out] report 内容・適合と候補の監査結果です
	 * @param[out] applicableReferences Windows実選択に合格した参照位置です
	 */
	void auditScopedInfCandidates( const SignedIndexScanSession &owner, DriverStoreProvider &store,
								  const provider_worker_index_detail::Services &services,
								  std::size_t recordIndex, OfficialPreparationAuditReport &report,
								  std::set<std::size_t> &applicableReferences) ;
	/**
	 * @brief 元取得物と照合した後に対象OSと機種を再観測します
	 * @param[in] owner 同取得issuerと原hostの所有者です
	 * @param[in] record 同所有recordです
	 * @param[in] services 元UTC serviceです
	 * @return 全成立0、原binding又は当該候補の端末条件の拒否です
	 * @note 機種条件の不一致は当該候補に適用します
	 */
	[[nodiscard]] NativeError reverifyRecord(
		const SignedIndexScanSession &owner, const PreparedRecord &record,
		const provider_worker_index_detail::Services &services) const ;
	/**
	 * @brief 指定導入に使う元INF・全Models・対象端末条件を再確認します
	 * @param[in] owner 同scanと原hostの所有者です
	 * @param[in] record 同取得recordです
	 * @param[in] pair 同record/元relation/INF ordinalへ結ぶ既routeです
	 * @param[in] services 元UTC serviceです
	 * @param[in] observeHost 同選択の内容検査後にOSと端末機種も再観測する場合trueです
	 * @return 完全一致0、内容不一致E_ACCESSDENIED又は原拒否です
	 * @note 内容不一致からhost拒否ラッチや新tokenを作りません
	 */
	[[nodiscard]] NativeError reverifyBoundScopedPair(
		const SignedIndexScanSession &owner, const PreparedRecord &record, const Pair &pair,
		const provider_worker_index_detail::Services &services, bool observeHost = true) const ;
	/**
	 * @brief 同じ選択内のすべてのWiX候補に元規約の明示同意があることを確認します
	 * @param[in] session 元通常スキャンです
	 * @param[in] identities 今回の選択候補です。他ProviderのIDも含められます
	 * @param[in] wixConsents 元規約への同意です。候補ごとに一件必要です
	 * @return 保持している元表示と全件一致した場合だけtrueです
	 * @note 端末は観測せず、実取得と期限は後続の検査で確認します
	 */
	[[nodiscard]] bool validateWixInstallConsents(
		ScanSessionId session, std::span<const std::wstring> identities,
		std::span<const WixInstallConsent> wixConsents) const ;
	/**
	 * @brief 必要役割を含む元選択を復旧開始前に一括検証します
	 * @param[in] owner 元取得ownerです
	 * @param[in] store 同workerの元binding issuerです
	 * @param[in] services 元期限serviceです
	 * @param[in] session 元scanです
	 * @param[in] identities 通常画面の元選択ID集合です
	 * @param[in] wixConsents 同じ操作が明示同意した検査済みWiX候補と元規約です
	 * @return 全元必要計画のbyte/期限/状態一致0、不足はHRESULTです
	 * @note 他Providerを変更せず、stage/復旧/導入を呼びません
	 */
	[[nodiscard]] NativeError preflightRequiredInstall(
		const SignedIndexScanSession &owner, const DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, ScanSessionId session,
		std::span<const std::wstring>	   identities,
		std::span<const WixInstallConsent> wixConsents = {}) const ;
	/**
	 * @brief 本体保護境界内で元選択routeだけを指定導入します
	 * @param[in,out] owner 元取得と内容の私有owner
	 * @param[in,out] store 同workerのDriver Store
	 * @param[in] services Worker固定service
	 * @param[in] session 元scan session
	 * @param[in] identities 本体が許可した元表示/選択ID
	 * @param[in] parentWindowNative 最終dialog親window
	 * @param[in] progress 確定件数の通知先
	 * @param[in] wixConsents 同じ操作の全選択に結合されたWiXの元同意です
	 * @return 元選択順の独立取得/導入/元HRESULTと再起動結果
	 */
	[[nodiscard]] InstallResult executeBoundInstall(
		SignedIndexScanSession &owner, DriverStoreProvider &store,
		const provider_worker_index_detail::Services &services, ScanSessionId session,
		std::span<const std::wstring> identities, std::uintptr_t parentWindowNative,
		const ProviderProgressCallback	  &progress,
		std::span<const WixInstallConsent> wixConsents = {}) ;
	/// 最大256件の元targetと既表示行
	std::vector<Reference>		references_ ;
	/// 元取得権限/byte/内容を単独所有する最大256record
	std::vector<PreparedRecord> records_ ;
	/// 全監査における元pair結果。観測0を適用性合格へしません
	std::vector<Pair>			pairs_ ;
	/// 本体publicationと同時にcommitしたroute集合
	std::vector<Pair>			routes_ ;
	/// 既存routeのcopyと今回の新tokenを全検証後にswapする集合
	std::vector<Pair>			pendingRoutes_ ;
	/// Pending transactionが開始済みの場合trueです
	bool						pending_{} ;
	/// 保持した実閉包byte。512MiB以下と元予算の最小値です
	std::uint64_t				retainedBytes_{} ;
} ;
} // namespace drivercrate
