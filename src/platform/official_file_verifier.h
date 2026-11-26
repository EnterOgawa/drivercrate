//------------------------------------------------------------------------------
/**
 * @file official_file_verifier.h
 * @brief 公式配布file共通検証定義
 * @version 01.18.00
 * @date 2026/09/23
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
 * @par 移行前更新履歴（製品版）
 * <pre>
 * VerNo.       author        update      comment
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  新規作成
 * Ver.0.1.0    Shunji Ogawa  2026/09/02  XML署名publisher検証追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/03  CAT member検証追加
 * Ver.0.1.0    Shunji Ogawa  2026/09/10  承認済みコーディング書式へ統一
 * </pre>
 *
 * @par 更新履歴
 * <pre>
 * VerNo.       author        update      comment
 * Ver.01.00.00 Shunji Ogawa  2026/09/11  新規作成
 * Ver.01.01.00 Shunji Ogawa  2026/09/23  SHA-256と共通のstream処理によるSHA-512計算を追加
 * Ver.01.02.00 Shunji Ogawa  2026/09/23  全区間取得接続と公式module根拠付き許諾境界を追加
 * Ver.01.03.00 Shunji Ogawa  2026/09/25  収集metadata専用の8 MiB hash上限を分離
 * Ver.01.04.00 Shunji Ogawa  2026/10/06  原container専用の128 MiB hash入口を分離
 * Ver.01.05.00 Shunji Ogawa  2026/10/17 明示cached-onlyの共通Authenticode入口を追加
 * Ver.01.06.00 Shunji Ogawa  2026/11/05 CAT原宣言のmember算法と署名検証の契約を分離
 * Ver.01.06.01 Shunji Ogawa  2026/11/11  宣言・定義の独立契約と参照省略禁止へコメントを整合
 * Ver.01.06.02 Shunji Ogawa  2026/11/12  コメント末尾と初回履歴の表記を統一
 * Ver.01.06.03 Shunji Ogawa  2026/11/13  847kの検証済みSYSTEM媒体作用と限定資格を接続
 * Ver.01.07.00 Shunji Ogawa  2026/11/16  選択storageの原全作用・私有資格と通常導入経路を接続
 * Ver.01.08.00 Shunji Ogawa  2026/11/22  保護されたSystem32直下の補助EXEの現在状態を保持
 * Ver.01.09.00 Shunji Ogawa  2026/11/22  登録済み配布のCATとメンバーを通信なしで照合
 * Ver.01.10.00 Shunji Ogawa  2026/11/23  Driver Store内の補助EXEを保護付きで読み取る契約を追加
 * Ver.01.11.00 Shunji Ogawa  2026/11/23  正規drivers直下のSYSを保護付きで観測する
 * Ver.01.12.00 Shunji Ogawa  2026/11/23  System32直下のストレージ用イベント資源DLLの読取りを追加
 * Ver.01.13.00 Shunji Ogawa  2026/11/23  Windows同梱machine.infの空導入委譲を検証
 * Ver.01.14.00 Shunji Ogawa  2026/11/23  固定入力の主署名と実際に検証した署名者を照合
 * Ver.01.15.00 Shunji Ogawa  2026/11/23  信頼済みマニフェストの原SHA-1照合用に全ファイルを読取る
 * Ver.01.16.00 Shunji Ogawa  2026/11/23  公開INFとStoreの同梱署名の共通読取りを追加
 * Ver.01.17.00 Shunji Ogawa  2026/11/23  署名INFの同一バイトを保持する一時解析を共用
 * Ver.01.18.00 Shunji Ogawa  2026/11/23  選択済み登録配布のINF・CAT・SYSを保護付きで読取る
 * </pre>
 *
 * @note 公式catalogとpayloadのsize、SHA-256、Authenticode publisherを共通のfail-closed規則で検証します。URLや端末識別情報は保持し
 *       ません
 */
//------------------------------------------------------------------------------

#pragma once

#include "core/update_types.h"

#include <array>
#include <cstdint>
#include <cstddef>
#include <functional>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace drivercrate {

class OfficialMappedFile ;

/**
 * @brief 親metadataが宣言した公式fileのsizeとSHA-256条件を表す
 */
struct OfficialFileMetadataPolicy {
	/// 完全一致を要求するbyte数。未指定時は検査しない
	std::optional<std::uint64_t> expectedSize ;
	/// 64桁ASCII hex。空の場合はhash検査を行わない
	std::wstring_view			 expectedSha256 ;
} ;

/** @brief 保護された標準位置で開いたバイナリの同一性と変更対象証拠 */
struct ProtectedExecutableEvidence {
	/// 同じvolumeから取得した識別値。通常ログへ出さない
	std::uint64_t				  volume{} ;
	/// 保持したファイルの128 bit ID
	std::array<std::uint8_t, 16U> fileId{} ;
	/// 実ファイルの完全byte数
	std::uint64_t				  bytes{} ;
	/// 元ファイルのWindows属性
	std::uint32_t				  attributes{} ;
	/// 保持した実ファイルへのハードリンク数
	std::uint32_t				  links{} ;
	/// 元ファイルの最終書込み時刻
	std::uint64_t				  lastWrite{} ;
	/// 保持した全byteのSHA-256
	std::wstring				  sha256 ;
	/// 元owner、group、制御とDACLの固定順の記録
	std::vector<std::byte>		  security ;
	/**
	 * @brief 同じファイルの独立した観測と全値を照合する
	 * @param[in] other 別の時点で読んだ証拠
	 * @return ファイルの同一性、内容と保護が全て一致すればtrue
	 */
	bool operator==( const ProtectedExecutableEvidence &other) const = default ;
} ;

/** @brief 保護された標準位置のバイナリの正式不在または現在値 */
struct ProtectedExecutableSnapshot {
	/// ファイルの直接の親の元owner、group、制御とDACL
	std::vector<std::byte>					   directorySecurity ;
	/// FileRepositoryを使う場合の元保護。System32内の読取りでは空
	std::vector<std::byte>					   repositorySecurity ;
	/// 保護された正規親で正式な不在を確認した場合のみ空
	std::optional<ProtectedExecutableEvidence> existing ;
	/**
	 * @brief 同じ標準位置に対する再観測を比較する
	 * @param[in] other 別の時点で読んだ証拠
	 * @return 親の保護と元ファイルの全状態が一致すればtrue
	 */
	bool operator==( const ProtectedExecutableSnapshot &other) const = default ;
} ;

/** @brief System32直下の補助実行ファイルを既存の読取り経路へ保持する型 */
using System32ExecutableSnapshot = ProtectedExecutableSnapshot ;

//------------------------------------------------------------------------------
/**
 * @brief SCMの元コマンドを固定Driver Store内の実ファイルへ解決して保護付きで読み取る
 * @param[in] command SCMの原文字列。全体を囲む引用符だけを許容する
 * @param[in] sourceFile 署名済みの選択が宣言した一つのEXEファイル名
 * @param[out] resolved 同じWindowsのFileRepository内の絶対位置。失敗時は空
 * @param[out] snapshot ファイルと二つの親の同一性・保護とハッシュ。失敗時は空
 * @return 保護された実ファイルの読取り成功0、構文・位置・種別・読取の不成立はHRESULT
 * @note 現在ファイルの署名元や登録済みパッケージの所有は別に確認する。実行しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDriverStoreExecutableSnapshot( std::wstring_view			 command,
															std::wstring_view			 sourceFile,
															std::wstring				&resolved,
															ProtectedExecutableSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 選択した補助EXEの同じSystem32直下位置を読み取る
 * @param[in] path 元INFが指定した正確なSystem32直下のEXE絶対位置
 * @param[out] snapshot 正規親の保護と現在ファイル。失敗時は空
 * @return 読取り成功0、空の親、権限、非通常ファイル、読取り失敗はHRESULT
 * @note 既存配布の署名と所有者は呼出側で確認する。ファイルは起動・変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSystem32ExecutableSnapshot( std::wstring_view			 path,
														 System32ExecutableSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 元INFが指定するSystem32のdrivers直下のSYSを保護付きで読み取る
 * @param[in] path 同じWindowsにある元コピー先の正確な絶対位置
 * @param[out] snapshot 親の保護とSYSの元値、または葉の正式な不在。失敗時は空
 * @return 読取り成功0、位置・保護・ファイルの照会に失敗した場合はHRESULT
 * @note 元登録と同じCATかどうかは呼出し側で照合する。ファイルを実行せず変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSystem32StorageDriverSnapshot( std::wstring_view			 path,
															ProtectedExecutableSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 保護されたDriver Storeの一パッケージに属する元SYSと親の現在値を読む
 * @param[in] path 照合済みStore INFと同じ一パッケージ直下の元SYSの絶対パス
 * @param[out] snapshot 元の親、元SYSの保護、同一性と全ハッシュ。失敗時は空
 * @return 正規位置、AMD64形式と保護付き読取りが成立すれば0、失敗はHRESULT
 * @note 署名と現用機器への結合は別に確認する。SYSを実行せず変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readDriverStoreStorageDriverSnapshot(
	std::wstring_view path, ProtectedExecutableSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 正規の登録配布にある元ファイルと親の保護、同一性、完全ハッシュを読む
 * @param[in] path 呼出側でWindowsの公開INF又は同じFileRepository配布直下と確認した絶対位置
 * @param[in] store trueはStore側。falseは公開INFだけ
 * @param[out] snapshot 元ファイルと親の保護付き観測。失敗時は空
 * @return 通常の元ファイルの内容と保護を確認して0、位置、形式や読取りの失敗はHRESULT
 * @note 拡張子ごとの上限を適用する。元位置の登録対応と元CATの署名は呼出側で独立に確認する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readProtectedRegisteredPackageSnapshot(
	std::wstring_view path, bool store, ProtectedExecutableSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief 元INFが指定するSystem32直下のストレージ用イベント資源DLLを保護付きで読み取る
 * @param[in] path 同じWindowsにある元コピー先の正確なDLL絶対位置
 * @param[out] snapshot 親の保護とDLLの元値、または葉の正式な不在。失敗時は空
 * @return 読取り成功0、位置・保護・ファイル照会の不成立はHRESULT
 * @note 呼出側がDLLの存在と署名済み元媒体のハッシュを照合する。DLLをロードせず変更しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError readSystem32StorageEventResourceSnapshot(
	std::wstring_view path, ProtectedExecutableSnapshot &snapshot) ;

//------------------------------------------------------------------------------
/**
 * @brief File全体のSHA-256を小文字ASCII hexへ変換する。EOFまでの全byteをCNG SHA-256へ順序通り入力する
 * @param[in] path 読み取るfileの絶対path
 * @param[out] sha256 成功時の64桁小文字SHA-256。失敗時は空
 * @return 成功時は0、fileまたはCNG処理失敗時はHRESULT bit pattern。 成功時は0、fileまたはCNG失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError computeFileSha256( std::wstring_view path, std::wstring &sha256) ;

//------------------------------------------------------------------------------
/**
 * @brief 信頼済み元マニフェストに宣言されたSHA-1との比較用にファイル全体を読取る
 * @param[in] path 呼出し側が読取り中固定した通常ファイルの絶対path
 * @param[out] sha1 成功時の40桁小文字hex。失敗時は空
 * @return 成功0、fileまたはCNG失敗時はHRESULT
 * @note SHA-256による元取得の照合、配布元の署名検証、ドライバーCAT検査の代替には使わない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError computeFileSha1ForSignedManifest( std::wstring_view path,
														   std::wstring		&sha1) ;

//------------------------------------------------------------------------------
/**
 * @brief 最大1 MiBの原byte列からSHA-256を計算します
 * @param[in] bytes 空でない有限入力。BOM等を正規化しません
 * @param[out] sha256 成功時の小文字64桁hex。失敗時は空
 * @return 成功0、入力不正またはCNG失敗時はHRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError computeBytesSha256( std::string_view bytes, std::wstring &sha256) ;

//------------------------------------------------------------------------------
/**
 * @brief 収集した最大8 MiBの原metadata本文を同じCNG処理でhashします
 * @param[in] bytes 1 byte以上8 MiB以下のsession内本文
 * @param[out] sha256 成功時の小文字SHA-256、失敗時は空です
 * @return 成功0、上限拒否またはCNG失敗のHRESULT
 * @note 既存computeBytesSha256の1 MiB上限は変更しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError computeCollectorMetadataSha256( std::string_view bytes,
														 std::wstring	 &sha256) ;
//------------------------------------------------------------------------------
/**
 * @brief 原container memoryの最大128 MiBを既存CNG処理でhashする
 * @param[in] bytes 空でない有限原byte。呼出し中に不変とする
 * @param[out] sha256 成功時の小文字64桁SHA-256、失敗時は空
 * @return 完了0、上限拒否またはCNG／allocation失敗のHRESULT
 * @note 従来の1 MiB／8 MiB入口は変更せず、用途別の抽出上限を代替しない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError computeDriverContainerSha256( std::string_view bytes,
													   std::wstring	   &sha256) ;

//------------------------------------------------------------------------------
/**
 * @brief File全体のSHA-512を有限bufferで計算します
 * @param[in] path 読み取るfileの絶対path
 * @param[out] sha512 成功時の128桁小文字hex。失敗時は空
 * @return 成功0、file／CNG／allocation失敗時はHRESULT
 * @note 公開hashの照合用であり、署名や導入許可を表しません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError computeFileSha512( std::wstring_view path, std::wstring &sha512) ;

//------------------------------------------------------------------------------
/**
 * @brief 公式fileのsizeとSHA-256を親metadataの宣言へ完全一致させる。公式fileのsizeとSHA-256をmetadata宣言へ一致させる。Sizeを先に確認し、不
 *        一致fileのhash計算を行わない
 * @param[in] path 検証するfileの絶対path
 * @param[in] policy 一つ以上のsizeまたはSHA-256条件
 * @return 全指定条件一致時は0、不正条件または不一致時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialFileMetadata( std::wstring_view				   path,
													 const OfficialFileMetadataPolicy &policy) ;

//------------------------------------------------------------------------------
/**
 * @brief FileのAuthenticode chainと許可publisher完全一致を検証する。Windows trust policy成功後にembedded signerを完全一致する
 * @param[in] path 検証するfileの絶対path
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可するpublisher表示名群
 * @return Chain、revocation、publisher一致時は0、失敗時はtrust HRESULT。 Chain、revocation、publisher一致時は0、失敗時は
 *         HRESULT
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyAuthenticodePublisher(
	std::wstring_view path, std::span<const std::wstring_view> acceptedPublishers) ;

//------------------------------------------------------------------------------
/**
 * @brief 通信せずcache内のchainと失効情報だけで共通Authenticodeを検証します
 * @param[in] path 検証中に呼出側が実handleで変更・置換を防いだ絶対path
 * @param[in] acceptedPublishers 許可するembedded certificateの完全publisher名群
 * @return 成功0、cache不足・失効・chain・publisher不一致は元trust HRESULT
 * @note 通常入口のpolicyは変えず、online fallbackやcatalog-only signer推測は行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyAuthenticodePublisherCachedOnly(
	std::wstring_view path, std::span<const std::wstring_view> acceptedPublishers) ;

//------------------------------------------------------------------------------
/**
 * @brief 固定した元ファイルの主Authenticode署名を、元PKCS#7と検証済み署名者の両方で照合する
 * @param[in] path mappedFileを開いた同じ元ファイルの絶対path
 * @param[in] mappedFile 呼出し中ずっと開いている読取り専用mapping所有者
 * @param[in] certificate PKCS#7の元領域。末尾の8-byte境界用の零詰めを含められる
 * @param[in] acceptedPublishers 許可する証明書の表示名
 * @param[in] cachedOnly trueなら証明書取得・失効確認をcache内に制限する
 * @return 成功0、入力、信頼、署名者照合の失敗はHRESULT
 * @note 署名者を別fileや別の埋込み署名から求めず、この検証結果そのものを使う
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyPrimaryAuthenticodePublisher(
	std::wstring_view path, const OfficialMappedFile &mappedFile,
	std::span<const std::byte> certificate, std::span<const std::wstring_view> acceptedPublishers,
	bool cachedOnly) ;

/** @brief 固定SYSTEM fileの原byte/権限と原CATの不変tupleです。embedded時はCAT部分だけ空です */
struct WindowsSystemFileTrust {
	/// 同OSの固定helperの完全位置です。一般logへ出しません
	std::wstring		   filePath ;
	/// 同helperの原byteに結ぶ完全SHA-256です
	std::wstring		   fileSha256 ;
	/// 原helperの有限な実byte数です
	std::uint64_t		   fileBytes{} ;
	/// 原owner/group/control/DACLの完全な順序付きsnapshotです
	std::vector<std::byte> fileSecurity ;
	/// Trust中に固定したlocal catalogの絶対位置です。一般logへ出しません
	std::wstring		   catalogPath ;
	/// 同CATの完全SHA-256です。呼出し元の再固定へ結びます
	std::wstring		   catalogSha256 ;
	/// 同CATの実byte数です。embedded署名の場合0です
	std::uint64_t		   catalogBytes{} ;
	/// CAT選択時の同owner/group/control/DACLです。embedded時は空です
	std::vector<std::byte> catalogSecurity ;
	/**
	 * @brief 同原byte/位置/権限/署名形式の完全な一致を確認します
	 * @param[in] other 同選択の再検証で得た独立したtupleです
	 * @return 全fieldが完全一致する場合trueです
	 */
	[[nodiscard]] bool	   operator==( const WindowsSystemFileTrust &other) const = default ;
} ;

/** @brief 固定SYSTEM fileの非秘密な検証地点です。合否へ使用しません */
enum class WindowsSystemFileStage : std::uint32_t {
	/// 未到達です
	NONE = 0U,
	/// 元fileと祖先を保持します
	FILE_OPEN = 1U,
	/// 署名方式を原PEから選びます
	SIGNATURE_FORM = 2U,
	/// 既embedded cache-only trustです
	EMBEDDED_TRUST = 3U,
	/// 同digestのlocal CATを取得します
	CATALOG_LOOKUP = 4U,
	/// 原CAT memberのcache-only trustです
	CATALOG_TRUST = 5U,
	/// 同CATの正確なpublisherを取得します
	CATALOG_PUBLISHER = 6U,
	/// 元SDを取得します
	SECURITY_DESCRIPTOR = 101U,
	/// 標準保守SIDを作成します
	SECURITY_PRINCIPALS = 102U,
	/// ownerと全allow ACEを確認します
	SECURITY_POLICY = 103U,
	/// 元process tokenを読みます
	PROCESS_TOKEN = 104U,
	/// 一時restricted tokenを作成します
	RESTRICTED_TOKEN = 105U,
	/// 本人SIDを取得します
	TOKEN_USER = 106U,
	/// 一時tokenのownerを本人へ設定します
	TOKEN_OWNER = 107U,
	/// AccessCheck用tokenを複製します
	IMPERSONATION_TOKEN = 108U,
	/// 非特権writeを独立に確認します
	ACCESS_CHECK = 109U,
} ;

//------------------------------------------------------------------------------
/**
 * @brief 防改変権限を持つWindows fileを実署名形式に従いcache-onlyで検証します
 * @param[in] path 呼出し元が同OSの固定System32名から決め、非reparse祖先と実fileを保持する絶対位置です
 * @param[out] evidence 成功時だけ原file/権限/CAT tupleです。失敗時は空です
 * @param[out] diagnosticStage null可の固定検証地点です。合否には使用しません
 * @return Windows publisher/chain/原member/hash/権限の全成立0、最初の元HRESULTです
 * @note Trust失敗後の方式/CAT変更、online fallback、実行/ACL変更を行いません
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyWindowsSystemFileCachedOnly(
	std::wstring_view path, WindowsSystemFileTrust &evidence,
	std::uint32_t *diagnosticStage = nullptr) ;

/** @brief 元の保持中にStore位置、公開INFとCATの信頼、原バイトを借用する同期検査 */
using VerifiedWindowsInboxInfInspector = std::function<NativeError(
	std::wstring_view, const WindowsSystemFileTrust &, std::span<const std::uint8_t>)> ;

//------------------------------------------------------------------------------
/**
 * @brief 保護されたWindows同梱INFの公開ファイル、Store原本と登録CATを照合してから内容検査を呼ぶ
 * @param[in] publishedInfName 同じWindowsのINF直下にある公開INFの葉名
 * @param[in] inspect 成功したStore位置、公開INFとCATの信頼、全原バイトを同期で借用する検査
 * @return 署名元と内容の検査がともに成功して0、最初の失敗はHRESULT
 * @note 借用は呼出し中だけ有効。元INFとCATを保持する。解析用入力が必要なら原バイトを一時コピーする
 * @note 正確な元選択、SYSの所属、端末との対応は呼出し側で検証する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectVerifiedWindowsInboxInf(
	std::wstring_view publishedInfName, const VerifiedWindowsInboxInfInspector &inspect) ;

//------------------------------------------------------------------------------
/**
 * @brief 検査済みINFと完全一致する保護付き一時コピーを保持して内容検査を呼ぶ
 * @param[in] leaf 同じ元INFの安全な葉名
 * @param[in] bytes 同じ元ファイルから取得した有限な原バイト
 * @param[in] sha256 署名検査時の同じ元ファイルの完全SHA-256
 * @param[in] inspect コピーのパスを同期で借用する解析。元の配置は呼出し側で保持する
 * @return 元バイトとの完全一致と内容検査が成功すれば0、失敗はHRESULT
 * @note 元ファイルの署名は呼出し側で確認する。元のWindows INFを解析用に開かない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError inspectProtectedInfCopy(
	std::wstring_view leaf, std::span<const std::uint8_t> bytes, std::wstring_view sha256,
	const std::function<NativeError( const std::wstring &)> &inspect) ;

//------------------------------------------------------------------------------
/**
 * @brief 同じWindowsの公開INFとDriver Storeから同梱machine.infの空導入委譲を検証する
 * @return 正規配置・原バイト・保護・Microsoft Windows署名とNO_DRVの作用が一致すれば0、失敗はHRESULT
 * @note 固定したINFとCATを保持中にローカルの信頼情報とハッシュ一致した一時コピーを読み取る
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyWindowsInboxNullDriver() ;

//------------------------------------------------------------------------------
/**
 * @brief 同元packageのAMD64 PE32+ headerを既有界readerで非実行確認します
 * @param[in] path 元保護領域内の通常file絶対位置です
 * @return 完全headerと有限security table範囲成立0、元I/O又は形式不正のHRESULTです
 * @note 署名/コピー元/実行意味は検証しません。CATと全byteは呼出し側が別に確認します
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyAmd64PeFile( std::wstring_view path) ;

//------------------------------------------------------------------------------
/**
 * @brief 署名catalogが全member fileの現在内容を収録していることを検証する。署名catalogと全member fileを検証する。各fileに原CATの
 *        digest/tagが一致する既知算法をtrust前に選び、一件でも不一致なら全体を受理しません
 * @param[in] catalogPath 検証するCAT fileの絶対path
 * @param[in] memberPaths Catalog memberとして検証する通常fileの絶対path群。 Catalogへ収録されるべき通常file群
 * @return 全memberのhashとcatalog trustが有効なら0、最初の失敗はtrust HRESULT。 全memberのhashとcatalog trustが有効なら0、失敗
 *         時はHRESULT
 * @note 外側署名のcurrent strong-sign policyを維持し、未知・不正算法を拒否します。blocking処理はworkerで実行します
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialCatalogMembers( std::wstring_view			 catalogPath,
													   std::span<const std::wstring> memberPaths) ;

//------------------------------------------------------------------------------
/**
 * @brief 保持したCATの署名と全メンバーをローカルの信頼情報だけで検証する
 * @param[in] catalogPath 同じWindows配布から保持したCATの絶対位置
 * @param[in] memberPaths 同CATへ結ぶ全メンバーの絶対位置。呼出し中だけ借用する
 * @return CATの署名と全メンバーが成立すれば0、信頼情報の不足を含む失敗はHRESULT
 * @note 呼出側で元位置と実ファイルを保持する。オンライン照会には切り替えない
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialCatalogMembersCachedOnly(
	std::wstring_view catalogPath, std::span<const std::wstring> memberPaths) ;

//------------------------------------------------------------------------------
/**
 * @brief XML Digital Signatureと埋込みcertificateのpublisherを検証する。XML Digital Signatureとpublisherを検証する
 *        Certificate公開鍵と文書全体の単一referenceを結び付け、CryptXML extensionを使用しない
 * @param[in] path 検証するUTF-8 XML fileの絶対path。 検証するUTF-8 XML file絶対path
 * @param[in] maximumBytes 読取りを許可するXML byte数上限。 XML read上限byte数
 * @param[in] validationFiletime 署名済み時刻を表す1601年起点100ns単位値。 署名済みSigningTime
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可publisher表示名群
 * @return 文書全体の署名、code-signing chain、publisher一致時は0。 XML署名、chain、publisherが全て有効なら0
 * @note 単一enveloped reference、RSA-SHA256、SHA-256、標準C14Nだけを許可する
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyXmlSignaturePublisher(
	std::wstring_view path, std::uint64_t maximumBytes, std::uint64_t validationFiletime,
	std::span<const std::wstring_view> acceptedPublishers) ;

//------------------------------------------------------------------------------
/**
 * @brief Metadata条件とAuthenticode publisherを一つの順序で検証する。Metadata条件とAuthenticode publisherを順番に検証する。不一致
 *        payloadへWinTrust処理を行わず、全条件をfail-closedにする
 * @param[in] path 検証するfileの絶対path
 * @param[in] metadataPolicy 親metadataが宣言したsize／SHA-256条件。 親metadataのsize／SHA-256条件
 * @param[in] acceptedPublishers 許可するcertificate simple display name群。 許可するpublisher表示名群
 * @return 全検証成功時は0、最初に失敗した検証のHRESULT bit pattern。 全検証成功時は0、最初の失敗時はHRESULT bit pattern
 */
//------------------------------------------------------------------------------
[[nodiscard]] NativeError verifyOfficialFile( std::wstring_view					path,
											 const OfficialFileMetadataPolicy  &metadataPolicy,
											 std::span<const std::wstring_view> acceptedPublishers) ;

} // namespace drivercrate
