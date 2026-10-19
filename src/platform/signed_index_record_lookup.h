//------------------------------------------------------------------------------
/**
 * @file signed_index_record_lookup.h
 * @brief 保存済み署名索引と同worker公開ID照合の読取り境界を定義します。
 * @version 01.02.00
 * @date 2026/10/11
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
 * Ver.01.00.00 Shunji Ogawa  2026/10/11  保存snapshotと有限read-only resolver seamを追加。
 * Ver.01.00.01 Shunji Ogawa  2026/10/11  直接使用する型の定義headerを明示。
 * Ver.01.01.00 Shunji Ogawa  2026/10/12  同snapshotと全context限定の私有batch集約を追加。
 * Ver.01.01.01 Shunji Ogawa  2026/10/12  Friend宣言のparameter名を契約と一致させます。
 * Ver.01.02.00 Shunji Ogawa  2026/10/14  Native私有証拠付き部分positiveと元公開ID役割を区別。
 * </pre>
 *
 * @note Worker内だけの読取りです。索引一致はWindows適合・導入許可ではありません。
 * @see docs/adr/0329-minimal-index-and-install-binding-contract.md
 */
//------------------------------------------------------------------------------
#pragma once

#include "core/update_types.h"
#include "platform/signed_index_manifest.h"
#include "platform/signed_index_records.h"
#include "platform/signed_index_store.h"
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {
namespace signed_index_acquisition_detail {
struct Access ;
}
class SignedIndexScanSession ;
class DriverStoreProvider ;

// 一回の有限batch枠。全driver対応数の上限ではありません。
inline constexpr std::size_t INDEX_LOOKUP_RECORD_BATCH_MAX = 256U ;
// 一回のworker present集合の有限枠。
inline constexpr std::size_t INDEX_LOOKUP_PRESENT_MAX = 4096U ;
// 一batchで呼び出せる同期resolverの最大回数。
inline constexpr std::size_t INDEX_LOOKUP_RESOLVER_CALL_MAX = 32768U ;

/** @brief 同workerのoperation・scan・inventoryの結合contextです。 */
struct IndexLookupContext {
	/// 正のoperation identity。
	std::uint64_t	   operationId{} ;
	/// 正のscan session identity。
	std::uint64_t	   scanSessionId{} ;
	/// 正のinventory世代。
	std::uint64_t	   inventoryGeneration{} ;
	/** @brief 全context fieldの完全一致を比較します。
	 * @param[in] other 比較対象。
	 * @return 全field一致の場合だけtrue。
	 */
	[[nodiscard]] bool operator==( const IndexLookupContext &other) const noexcept = default ;
} ;

/** @brief 同snapshotから読む有限batchとcallback回数の指定です。 */
struct IndexLookupBudget {
	/// 先頭recordの0起点位置。record数と同値なら空batchです。
	std::size_t recordOffset{} ;
	/// 最大256record。残り件数より大きい場合は残りまで読みます。
	std::size_t recordCount{INDEX_LOOKUP_RECORD_BATCH_MAX} ;
	/// 最大32768回。0では未実行の理由を保持します。
	std::size_t resolverCalls{INDEX_LOOKUP_RESOLVER_CALL_MAX} ;
} ;

/** @brief 同scanの既知Class positiveだけをDriverStoreが発行する不変証拠です。
 * @note 公開DTOから構築できません。Windows適合・rank・導入許可は発行しません。
 */
class NativeIndexPositiveProof final {
private:
	/** @brief DriverStoreだけが初期構築できる非公開mint keyです。 */
	class MintKey final {
	public:
		/** @brief 発行済みkeyを標準所有factory内へ値として渡します。
		 * @param[in] other 同じ発行呼出しのkeyです。状態や権限を追加しません。
		 */
		MintKey( const MintKey &other) = default ;

	private:
		/** @brief DriverStoreの内部発行だけで空のkeyを構築します。 */
		MintKey() = default ;
		friend class DriverStoreProvider ;
	} ;
	friend class DriverStoreProvider ;

public:
	/** @brief 同scanから確認した元公開tupleと既知device集合を不変保存します。
	 * @param[in] key DriverStoreだけが構築した発行keyです。
	 * @param[in] context 元worker／scan／inventoryの全contextです。
	 * @param[in] kind 元公開INF側のidentifier役割です。
	 * @param[in] publishedId 元公開ASCII identifierを本呼出し中だけ借用してcopyします。
	 * @param[in] classGuid 元公開Class文字列を本呼出し中だけ借用してcopyします。
	 * @param[in] ownerThread 同inventoryを所有するWindows thread IDです。
	 * @param[in] lease Providerが強所有する元scan stateへのweak leaseです。
	 * @param[in] devices 両native属性と既知Classが検証されたopaque集合を所有moveします。
	 * @param[in] error 同callbackが保持した元不足診断です。
	 * @note 元列挙完了と必要属性の検証は発行側の前提です。秘密IDやURLを保持しません。
	 */
	NativeIndexPositiveProof( MintKey key, IndexLookupContext context, IndexPnpIdKind kind,
							 std::string_view publishedId, std::string_view classGuid,
							 std::uint32_t ownerThread, std::weak_ptr<const void> lease,
							 std::vector<std::wstring> devices, NativeError error) ;
	/** @brief 元tupleとdevice集合の完全一致および同ownerの生存を確認します。
	 * @param[in] context 現callbackの全contextです。
	 * @param[in] kind lookupが元recordから読んだ公開役割です。
	 * @param[in] publishedId lookupが元recordから読んだ公開identifierです。
	 * @param[in] classGuid lookupが元recordから読んだ公開Classです。
	 * @param[in] ownerThread lookupを実行中のWindows thread IDです。
	 * @param[in] devices callbackが返した全opaque集合を本呼出し中だけ借用します。
	 * @param[in] error callbackまたは私有relationが保持した元不足診断です。
	 * @return 全一致と生存確認が成立した場合だけtrueです。
	 * @note I/Oや参照の保持は行いません。失効したscanを再有効化しません。
	 */
	[[nodiscard]] bool matches( IndexLookupContext context, IndexPnpIdKind kind,
							   std::string_view publishedId, std::string_view classGuid,
							   std::uint32_t ownerThread, std::span<const std::wstring> devices,
							   NativeError error) const noexcept ;

private:
	/// 元発行の全contextです。
	IndexLookupContext		  context_ ;
	/// 元公開identifierの役割です。native property指定へ読み替えません。
	IndexPnpIdKind			  kind_ ;
	/// 元公開identifierだけのcopyです。端末raw IDを含みません。
	std::string				  publishedId_ ;
	/// 元公開Classだけのcopyです。
	std::string				  classGuid_ ;
	/// 同scanのWindows owner thread IDです。
	std::uint32_t			  ownerThread_{} ;
	/// Providerが失効させる元stateを強所有しないleaseです。
	std::weak_ptr<const void> lease_ ;
	/// 必要な両native属性と既知Classを確認したopaque集合です。
	std::vector<std::wstring> devices_ ;
	/// 同callbackの元不足診断です。後続の成功値で上書きしません。
	NativeError				  error_{} ;
} ;

/** @brief 公開ID一つの同期照合結果です。適合結果ではありません。 */
struct IndexPublicIdResolution {
	/// 結果を観測した同worker context。
	IndexLookupContext								context ;
	/// 同contextのinventory列挙と照合が全て完了した場合だけtrueです。
	/// 部分inventory・入力不足・未実行ではfalseです。
	bool											completed{} ;
	/// Callbackの元HRESULT。失敗を成功へまとめません。
	NativeError										error{} ;
	/// 最大4096件のopaque identity。端末raw IDを入れません。
	std::vector<std::wstring>						devices ;
	/// 全列挙完了と既知Class positiveの私有根拠です。一般partial DTOではnullです。
	std::shared_ptr<const NativeIndexPositiveProof> positiveProof ;
} ;

/** @brief 公開側IDだけを同worker present集合へ照合するread-only callbackです。
 * @note 借用は呼出し中だけ有効です。有限同期処理で戻り、参照を保持せず、I/O・導入を行いません。
 */
class IndexPublicIdResolver {
public:
	/** @brief Callbackの所有者が派生資源を解放します。 */
	virtual ~IndexPublicIdResolver() = default ;
	/** @brief 元公開ID役割を保持し、native両集合とClassGUIDを照合します。
	 * @param[in] kind メーカー公表INF側identifierの元役割。native property指定ではありません。
	 * @param[in] publishedId 元公開ASCII ID。端末actual IDではありません。
	 * @param[in] classGuid 元申告ClassGUID。
	 * @param[in] context 現在のworker context。
	 * @param[in] present 現在の有限opaque集合。本呼出し中だけ借用します。
	 * @return 完了区分・元HRESULTとopaque候補集合。全inventory列挙と照合の全完了だけがcompleted trueです。
	 * 部分集合・列挙失敗・全presentか不明な入力ではcompleted falseを返します。
	 * DriverStoreの私有証拠がある既知positiveだけを全体不足と分離でき、適合やrankは示しません。
	 * @note 例外は共通入口で診断へ変換されます。同workerから呼び、再入しません。
	 */
	[[nodiscard]] virtual IndexPublicIdResolution resolve(
		IndexPnpIdKind kind, std::string_view publishedId, std::string_view classGuid,
		IndexLookupContext context, std::span<const std::wstring> present) const = 0 ;
} ;

/** @brief 元公開IDとopaque集合とのread-only関係を区別します。 */
enum class IndexRecordMatchState {
	/// 一公開IDが一つのpresent opaqueへ結ばれました。Windows適合ではありません。
	MATCHED,
	/// 完了結果が空または非一意です。
	UNMATCHED,
	/// 未実行・不足・障害・不正結果を保持します。
	UNDETERMINED,
	/// 全体は未判定ですが、私有native証拠で既知deviceだけのexact関係を確認しました。
	VERIFIED_PARTIAL
} ;

/** @brief 一致の有無から独立した読取り理由です。 */
enum class IndexRecordMatchReason {
	/// 一意なopaque関係です。
	UNIQUE_RELATION,
	/// 元申告の公開identityまたはclassが不足しています。
	PUBLIC_IDENTITY_UNKNOWN,
	/// Callbackがありません。
	RESOLVER_UNAVAILABLE,
	/// 有限callback予算を使い切りました。
	BUDGET_EXHAUSTED,
	/// Callbackが完了していません。
	RESOLVER_INCOMPLETE,
	/// Callbackの元HRESULTが失敗しました。
	RESOLVER_FAILED,
	/// Callbackが例外を送出しました。
	RESOLVER_EXCEPTION,
	/// Callbackのcontextが一致しません。
	RESOLVER_CONTEXT_MISMATCH,
	/// Callbackが未知・重複・上限超過opaqueを返しました。
	INVALID_OPAQUE_RESULT,
	/// 完了した照合でidentityがありません。
	NO_RELATION,
	/// 完了した照合が複数の異なるidentityを返しました。
	NON_UNIQUE_RELATION,
	/// 全体不足と元診断を保持した私有証拠付き既知positiveです。
	VERIFIED_POSITIVE_PARTIAL
} ;

/** @brief 公開文字列を持たないrecordとopaque deviceの結果tupleです。 */
struct IndexRecordRelation {
	/// 所有snapshot内の0起点record位置。
	std::size_t					recordIndex{} ;
	/// 同record内の公開ID位置。公開identity不明ではnulloptです。
	std::optional<std::size_t>	publicIdIndex ;
	/// 同operation・scan・inventoryの観測context。
	IndexLookupContext			context ;
	/// 元record原byteだけのSHA-256。
	IndexManifestSha256			recordSha256{} ;
	/// 元source identity。取得URLではありません。
	std::string					sourceId ;
	/// 元record identity。実package identityではありません。
	std::string					recordId ;
	/// 完全一意または私有証拠付き部分集合内で一deviceのときだけ存在するopaqueです。
	std::optional<std::wstring> deviceIdentity ;
	/// 完了結果または私有証拠で確認した有効opaque集合。未読nodeを含めません。
	std::vector<std::wstring>	relatedDevices ;
	/// 一致・完了不一致・未判定を区別します。
	IndexRecordMatchState		state{IndexRecordMatchState::UNDETERMINED} ;
	/// 不足や障害を一致状態へ読み替えない理由です。
	IndexRecordMatchReason		reason{IndexRecordMatchReason::PUBLIC_IDENTITY_UNKNOWN} ;
	/// Callbackの元HRESULTまたは例外変換診断。
	NativeError					error{} ;
	/// VERIFIED_PARTIALだけの元native私有証拠です。同scan失効後は使用できません。
	std::shared_ptr<const NativeIndexPositiveProof> positiveProof ;
} ;

struct IndexRecordLookupResult ;

/** @brief 保存snapshotと有限関係を所有するworker専用の不変読取り結果です。
 * @note 各借用参照は本objectの寿命まで有効で、move・破棄後は使えません。通常UIへ渡しません。
 */
class SignedIndexRecordLookup final {
public:
	/** @brief 原hash・世代・policy・source／record／UNKNOWNを保持するsnapshotを借用します。
	 * @return 本lookupが所有する不変snapshot。
	 */
	[[nodiscard]] const AuthenticatedIndexSnapshot	  &snapshot() const noexcept ;
	/** @brief 公開ID文字列を含まない有限関係を借用します。
	 * @return 本lookupの寿命まで有効な不変span。
	 */
	[[nodiscard]] std::span<const IndexRecordRelation> relations() const noexcept ;

private:
	/** @brief 保存済みconst snapshotの所有を共有し、関係を所有します。
	 * @param[in] snapshot 完全な原保存snapshot。
	 * @param[in] relations 同contextの有限関係。
	 * @param[in] context 元scanの完全context。取得operationへ書き換えません。
	 */
	SignedIndexRecordLookup( std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot,
							std::vector<IndexRecordRelation> relations, IndexLookupContext context) ;
	/** @brief 同ownerが発行した全batchだけを一つの不変lookupへ凍結します。
	 * @param[in] snapshot 同scanの原保存snapshotの共有所有。
	 * @param[in] context 元scanの完全context。
	 * @param[in] batches 私有構築済みbatch。公開relationから再構築しません。
	 * @param[in] nowUtc 現信頼UTC。期限は凍結時も再照合します。
	 * @return 同snapshot・全context・原record結合成立時だけ集約lookup。
	 */
	[[nodiscard]] static IndexRecordLookupResult freezeOwnedBatches(
		std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, IndexLookupContext context,
		std::span<const SignedIndexRecordLookup> batches,
		std::optional<std::chrono::sys_seconds>	 nowUtc) noexcept ;
	friend class SignedIndexScanSession ;
	friend struct signed_index_acquisition_detail::Access ;
	friend IndexRecordLookupResult lookupSignedIndexRecords(
		std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, IndexLookupContext request,
		IndexLookupContext current, std::span<const std::wstring> present, IndexLookupBudget budget,
		std::optional<std::chrono::sys_seconds> nowUtc,
		const IndexPublicIdResolver			   *resolver) noexcept ;
	/// 保存済みconst原byteと全元申告を共有所有します。Batchごとに複製しません。
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot_ ;
	/// 同batchのread-only関係を単独所有します。
	std::vector<IndexRecordRelation>				  relations_ ;
	/// 関係が空でも失わない元scanの完全context。
	IndexLookupContext								  context_ ;
} ;

/** @brief 全体の入力拒否と読取り成立を区別します。 */
enum class IndexRecordLookupStatus {
	/// 読取りが成立しました。各関係は未判定の場合もあります。
	LOOKUP_READY,
	/// Move元等の必須byteが不足しています。
	INCOMPLETE_SNAPSHOT,
	/// 信頼UTCがありません。
	TIME_UNAVAILABLE,
	/// 署名発行前です。
	NOT_YET_VALID,
	/// 署名期限以上です。
	EXPIRED,
	/// Contextは0または現在値と不一致です。
	STALE_CONTEXT,
	/// Present集合の空identity・重複です。
	INVALID_PRESENT_SET,
	/// Batch・present件数・callback枠が上限外です。
	BUDGET_LIMIT,
	/// 所有結果の確保失敗です。
	OUT_OF_MEMORY,
	/// 型不明の内部障害です。
	INTERNAL_FAILURE
} ;

/** @brief 全入力成立時だけ所有読取り結果を持ちます。 */
struct IndexRecordLookupResult {
	/// 未検査を成功にしない初期区分。
	IndexRecordLookupStatus				   status{IndexRecordLookupStatus::INCOMPLETE_SNAPSHOT} ;
	/// 内部API障害の診断。入力拒否では0です。
	NativeError							   error{} ;
	/// 読取り成立時だけ存在し、snapshotを所有します。
	std::optional<SignedIndexRecordLookup> lookup ;
} ;

/** @brief 原保存snapshotの有限record batchを同worker resolverへ結びます。
 * @param[in] snapshot Commit／reloadだけが発行した完全const snapshotの共有所有。
 * Null・move元を拒否します。正規結果を一度moveしてconst所有とし、可変aliasを使いません。
 * @param[in] request 呼出しが要求する正のcontext。
 * @param[in] current 現workerが確認した正のcontext。
 * @param[in] present 同contextのopaque present集合。本呼出し中不変です。
 * @param[in] budget 有限batchとcallback枠。
 * @param[in] nowUtc 現在信頼UTC。発行前・期限以上・確認不能は拒否します。
 * @param[in] resolver 同workerの借用callback。nullptrは未実行として保持します。
 * @return 入力拒否、または元snapshotと各関係を所有する読取り結果。
 * @note 参照を外へ保持せず、例外を境界で診断へ変換します。独立入力は独立workerで呼出し可能です。
 */
[[nodiscard]] IndexRecordLookupResult lookupSignedIndexRecords(
	std::shared_ptr<const AuthenticatedIndexSnapshot> snapshot, IndexLookupContext request,
	IndexLookupContext current, std::span<const std::wstring> present, IndexLookupBudget budget,
	std::optional<std::chrono::sys_seconds> nowUtc, const IndexPublicIdResolver *resolver) noexcept ;

} // namespace drivercrate
