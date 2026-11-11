cmake_minimum_required(VERSION 3.28)

project(
    DriverCrate
    VERSION 1.0.5
    DESCRIPTION "Torrent-free Windows driver update manager"
    LANGUAGES C CXX RC
)

# 別shellからのbuildでも/showIncludesを同じ実在言語に固定する。既存launcherは内側に保持し、
# cacheを書き換えず、再configureでwrapperを重複させない。日本語だけのtoolchainでも
# 存在しない英語resourceを仮定せず、実compilerの接頭辞を毎configureで確認する。
if(MSVC AND CMAKE_GENERATOR MATCHES "Ninja")
    get_filename_component(drivercrate_compiler_directory "${CMAKE_CXX_COMPILER}" DIRECTORY)
    file(GLOB drivercrate_compiler_languages
        RELATIVE "${drivercrate_compiler_directory}" "${drivercrate_compiler_directory}/*/clui.dll")
    set(drivercrate_compiler_language 1033)
    if(NOT EXISTS "${drivercrate_compiler_directory}/1033/clui.dll"
        AND drivercrate_compiler_languages)
        list(GET drivercrate_compiler_languages 0 drivercrate_compiler_resource)
        get_filename_component(drivercrate_compiler_language "${drivercrate_compiler_resource}" DIRECTORY)
    endif()
    set(ENV{VSLANG} "${drivercrate_compiler_language}")
    set(drivercrate_include_probe "${CMAKE_CURRENT_BINARY_DIR}/CMakeFiles/DriverCrateShowIncludes")
    file(MAKE_DIRECTORY "${drivercrate_include_probe}")
    file(WRITE "${drivercrate_include_probe}/drivercrate_include_probe.h" "\n")
    file(WRITE "${drivercrate_include_probe}/main.c" "#include \"drivercrate_include_probe.h\"\n")
    execute_process(
        COMMAND "${CMAKE_CXX_COMPILER}" /nologo /showIncludes /EP /TC main.c
        WORKING_DIRECTORY "${drivercrate_include_probe}"
        OUTPUT_VARIABLE drivercrate_include_output
        ERROR_VARIABLE drivercrate_include_error
        RESULT_VARIABLE drivercrate_include_result
        ENCODING AUTO
    )
    if(NOT drivercrate_include_result EQUAL 0)
        message(FATAL_ERROR "MSVC include dependency probe failed: ${drivercrate_include_result}")
    endif()
    string(REGEX MATCH "(^|\n)([^\n]+: +)[A-Za-z]:[/\\\\]" drivercrate_include_match
        "${drivercrate_include_output}\n${drivercrate_include_error}")
    if(NOT drivercrate_include_match)
        message(FATAL_ERROR "MSVC include dependency prefix could not be detected.")
    endif()
    set(drivercrate_include_prefix "${CMAKE_MATCH_2}")
    # 日本語resourceの固定接頭辞は、CMakeのpipe／console文字コードの誤変換から分離する。
    # Compiler自身の応答確認を省かず、他の言語では実測した接頭辞をそのまま用いる。
    if(drivercrate_compiler_language STREQUAL "1041")
        set(drivercrate_include_prefix "メモ: インクルード ファイル: ")
    endif()
    foreach(drivercrate_language IN ITEMS C CXX)
        set(CMAKE_${drivercrate_language}_COMPILER_LAUNCHER
            "${CMAKE_COMMAND}" -E env "VSLANG=${drivercrate_compiler_language}"
            ${CMAKE_${drivercrate_language}_COMPILER_LAUNCHER}
        )
        set(CMAKE_${drivercrate_language}_CL_SHOWINCLUDES_PREFIX "${drivercrate_include_prefix}")
    endforeach()
    set(CMAKE_CL_SHOWINCLUDES_PREFIX "${drivercrate_include_prefix}")
endif()

if(NOT WIN32)
    message(FATAL_ERROR "DriverCrate supports Windows only.")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "DriverCrate supports x64 builds only.")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
# DriverCrate は C++ module を使用しない。MSVC/Ninja の module scanner に依存せず、通常の
# include dependency tracking で transitive header 変更を確実に再コンパイルする。
set(CMAKE_CXX_SCAN_FOR_MODULES OFF)
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(CTest)
include(FetchContent)
include(cmake/DriverCrateCompilerOptions.cmake)

option(
    DRIVERCRATE_ENABLE_ANALYZE
    "Enable MSVC static analysis for DriverCrate-owned source targets."
    OFF
)

# 撤去済みAI設定は黙って無視せず拒否し、OFFの旧cacheだけ除去する。
include(cmake/RejectRetiredAiOptions.cmake)
include(cmake/LocalIndexAcceptance.cmake)

# Dell Enterprise CatalogのGZipと公式ZIP packageの展開は、固定版・固定hashのminizを静的linkする。
# Application実行時に第三者DLLや外部展開toolを要求しない。MinizはC/C++両対応の
# sourceであり、DriverCrateのMSVC toolchainを一つに保つためC++として個別compileする。
FetchContent_Declare(
    miniz
    URL https://github.com/richgel999/miniz/archive/refs/tags/3.1.2.tar.gz
    URL_HASH SHA256=98468F8924934B723276680F85238B6C78BF1F8B49B4459CC9B7214A20E2E9FB
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR drivercrate-no-upstream-cmake
)
FetchContent_MakeAvailable(miniz)
set(drivercrate_miniz_sources
    ${miniz_SOURCE_DIR}/miniz.c
    ${miniz_SOURCE_DIR}/miniz_tdef.c
    ${miniz_SOURCE_DIR}/miniz_tinfl.c
    ${miniz_SOURCE_DIR}/miniz_zip.c
)
set_source_files_properties(${drivercrate_miniz_sources} PROPERTIES LANGUAGE CXX)
add_library(drivercrate_miniz STATIC ${drivercrate_miniz_sources})
include(GenerateExportHeader)
generate_export_header(
    drivercrate_miniz
    BASE_NAME miniz
    EXPORT_FILE_NAME ${CMAKE_CURRENT_BINARY_DIR}/generated/miniz_export.h
    STATIC_DEFINE MINIZ_STATIC_DEFINE
)
target_compile_definitions(drivercrate_miniz PUBLIC MINIZ_STATIC_DEFINE)
target_include_directories(
    drivercrate_miniz
    PUBLIC
        ${miniz_SOURCE_DIR}
        ${CMAKE_CURRENT_BINARY_DIR}/generated
)

# PE末尾7zの非実行展開に使用するLZMA SDKは、公式26.03 archiveとhashへ固定する。
# Archive内のsample、tool、SFX、precompiled binaryは実行・link・配布せず、C decoderの
# 必要sourceだけを第三者専用targetでCとしてcompileする。DriverCrate自作sourceの警告設定は
# このtargetへ流用せず、application側の/W4、/WXを維持する。
FetchContent_Declare(
    lzma_sdk
    URL https://github.com/ip7z/7zip/releases/download/26.03/lzma2603.7z
    URL_HASH SHA256=86C213F752520AB5325C310F50BEF63EC344B56DD1C80B0246D06DC6CEC953B2
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
    SOURCE_SUBDIR drivercrate-no-upstream-cmake
)
FetchContent_MakeAvailable(lzma_sdk)
set(drivercrate_lzma_sdk_sources
    ${lzma_sdk_SOURCE_DIR}/C/7zArcIn.c
    ${lzma_sdk_SOURCE_DIR}/C/7zBuf.c
    ${lzma_sdk_SOURCE_DIR}/C/7zCrc.c
    ${lzma_sdk_SOURCE_DIR}/C/7zCrcOpt.c
    ${lzma_sdk_SOURCE_DIR}/C/7zDec.c
    ${lzma_sdk_SOURCE_DIR}/C/7zStream.c
    ${lzma_sdk_SOURCE_DIR}/C/Bcj2.c
    ${lzma_sdk_SOURCE_DIR}/C/Bra.c
    ${lzma_sdk_SOURCE_DIR}/C/Bra86.c
    ${lzma_sdk_SOURCE_DIR}/C/BraIA64.c
    ${lzma_sdk_SOURCE_DIR}/C/CpuArch.c
    ${lzma_sdk_SOURCE_DIR}/C/Delta.c
    ${lzma_sdk_SOURCE_DIR}/C/Lzma2Dec.c
    ${lzma_sdk_SOURCE_DIR}/C/LzmaDec.c
)
add_library(drivercrate_lzma_sdk STATIC ${drivercrate_lzma_sdk_sources})
target_compile_definitions(drivercrate_lzma_sdk PRIVATE Z7_EXTRACT_ONLY)
target_include_directories(drivercrate_lzma_sdk PUBLIC ${lzma_sdk_SOURCE_DIR}/C)
if(MSVC)
    target_compile_options(drivercrate_lzma_sdk PRIVATE /W3 /sdl)
endif()

# Windows Updateや公式vendorへ通信するread-only live testは、明示的に有効化した場合だけ生成する。
option(
    DRIVERCRATE_BUILD_LIVE_TESTS
    "Build read-only tests that contact Windows Update or official vendor services."
    OFF
)

# 収集用成果物は通信測定用testと独立して明示buildできるようにする。
option(
    DRIVERCRATE_BUILD_COLLECTOR
    "Build the collector and its versioned setup independently of live tests."
    OFF
)

configure_file(
    cmake/DriverCrateVersion.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/generated/drivercrate_version.h
    @ONLY
)

add_library(drivercrate_core STATIC
    src/core/app_update.cpp
    src/core/pending_reference_version.cpp
    src/core/candidate_audit.cpp
    src/core/candidate_assessment.cpp
    src/core/candidate_selection.cpp
    src/core/candidate_source_group.cpp
    src/core/device_observation.cpp
    src/core/local_coverage.cpp
    src/core/metadata_search.cpp
    src/core/metadata_search_report.cpp
    src/core/metadata_search_budget.cpp
    src/core/official_discovery.cpp
    src/core/official_discovery_execution.cpp
    src/core/official_discovery_planner.cpp
    src/core/scan_measurement.cpp
    src/core/official_driver_rank.cpp
    src/core/official_release_observation.cpp
    src/core/official_preparation.cpp
    src/core/official_preparation_operation.cpp
    src/core/official_preparation_audit.cpp
    src/core/official_source_policy.cpp
    src/core/operation_controller.cpp
    src/core/package_selection.cpp
    src/core/provider_registry.cpp
    src/core/protected_install.cpp
    src/core/update_provider.cpp
)
target_include_directories(drivercrate_core PUBLIC src)
drivercrate_apply_compiler_options(drivercrate_core)

add_library(drivercrate_platform STATIC
    src/platform/app_update_service.cpp
    src/platform/app_update_windows.cpp
    src/platform/local_diagnostic_log.cpp
    src/platform/local_scan_diagnostics.cpp
    src/platform/amd_catalog_parser.cpp
    src/platform/amd_update_provider.cpp
    src/platform/asix_catalog_parser.cpp
    src/platform/asix_preparation.cpp
    src/platform/asix_update_provider.cpp
    src/platform/asrock_catalog_parser.cpp
    src/platform/asrock_system_identity.cpp
    src/platform/asrock_update_provider.cpp
    src/platform/broadcom_catalog_parser.cpp
    src/platform/broadcom_update_provider.cpp
    src/platform/broadcom_preparation.cpp
    src/platform/asus_catalog_parser.cpp
    src/platform/asus_collector_target_assessment.cpp
    src/platform/local_collector_metadata_projection.cpp
    src/platform/local_collector_projected_executor.cpp
    src/platform/local_collector_metadata_codec.cpp
    src/platform/local_collector_projected_response.cpp
    src/platform/local_collector_projected_cache.cpp
    src/platform/local_collector_projected_json.cpp
    src/platform/asus_network_record_adapter.cpp
    src/platform/asus_driver_package_audit.cpp
    src/platform/official_driver_package_audit.cpp
    src/platform/official_prepared_audit_report.cpp
    src/platform/official_prepared_install.cpp
    src/platform/official_bound_preparation.cpp
    src/platform/asus_cdn_token.cpp
    src/platform/asus_package_acquisition.cpp
    src/platform/asus_system_identity.cpp
    src/platform/asus_update_provider.cpp
    src/platform/composite_update_provider.cpp
    src/platform/common_driver_package.cpp
    src/platform/common_inf_plan.cpp
    src/platform/indexed_driver_package_inspection.cpp
    src/platform/metadata_search_runner.cpp
    src/platform/dell_catalog_parser.cpp
    src/platform/dell_server_catalog_parser.cpp
    src/platform/dell_server_catalog_source.cpp
    src/platform/dell_server_update_provider.cpp
    src/platform/dell_update_provider.cpp
    src/platform/driver_store_provider.cpp
    src/platform/generic_inf_package.cpp
    src/platform/hp_catalog_parser.cpp
    src/platform/hp_update_provider.cpp
    src/platform/intel_wireless_package.cpp
    src/platform/intel_wireless_package_provider.cpp
    src/platform/intel_ethernet_server_page_parser.cpp
    src/platform/intel_collector_identity_parser.cpp
    src/platform/intel_ethernet_windows11_record_adapter.cpp
    src/platform/intel_download_license_parser.cpp
    src/platform/prolific_serial_package.cpp
    src/platform/official_serial_provider.cpp
    src/platform/official_release_metadata.cpp
    src/platform/official_release_discovery_provider.cpp
    src/platform/official_release_preparation.cpp
    src/platform/official_release_local_probe.cpp
    src/platform/official_release_observation_store.cpp
    src/platform/official_record_resolution.cpp
    src/platform/official_record_payload_routing.cpp
    src/platform/official_static_record_parser.cpp
    src/platform/focusrite_download_page_parser.cpp
    src/platform/ricoh_universal_print_page_parser.cpp
    src/platform/wacom_driver_page_parser.cpp
    src/platform/silicon_labs_catalog_parser.cpp
    src/platform/wch_catalog_parser.cpp
    src/platform/silicon_labs_serial_package.cpp
    src/platform/wch_serial_package.cpp
    src/platform/intel_wireless_page_parser.cpp
    src/platform/intel_download_only_page.cpp
    src/platform/lenovo_catalog_parser.cpp
    src/platform/lenovo_update_provider.cpp
    src/platform/nvidia_catalog_parser.cpp
    src/platform/nvidia_update_provider.cpp
    src/platform/nvidia_winof2_catalog_parser.cpp
    src/platform/nvidia_winof2_driver_audit.cpp
    src/platform/nvidia_winof2_driver_package.cpp
    src/platform/nvidia_winof2_update_provider.cpp
    src/platform/official_cab.cpp
    src/platform/official_catalog_cache.cpp
    src/platform/official_catalog_validation.cpp
    src/platform/official_driver_closure.cpp
    src/platform/official_driver_package.cpp
    src/platform/inf_dependency_plan.cpp
    src/platform/inf_dependency_native.cpp
    src/platform/official_download_workspace.cpp
    src/platform/official_acquisition.cpp
    src/platform/nvidia_collector_metadata.cpp
    src/platform/collector_inspection_acquisition.cpp
    src/platform/official_record_utilities.cpp
    src/platform/official_download_grant.cpp
    src/platform/official_collector_public_text.cpp
    src/platform/official_delegated_package_inspection.cpp
    src/platform/official_discovery_inventory.cpp
    src/platform/official_discovery_cache.cpp
    src/platform/official_discovery_eula.cpp
    src/platform/official_discovery_package.cpp
    src/platform/official_discovery_provider_adapter.cpp
    src/platform/official_discovery_record_adapter.cpp
    src/platform/official_delegated_http_request.cpp
    src/platform/official_public_destination.cpp
    src/platform/official_collector_dns.cpp
    src/platform/secret_official_url.cpp
    src/platform/official_prepared_acquisition.cpp
    src/platform/official_file_verifier.cpp
    src/platform/official_mapped_file.cpp
    src/platform/official_gzip.cpp
    src/platform/official_http_client.cpp
    src/platform/official_html_terms.cpp
    src/platform/openpgp_signature_verifier.cpp
    src/platform/signed_index_manifest.cpp
    src/platform/signed_index_refresh.cpp
    src/platform/public_index_readback.cpp
    src/platform/signed_index_asset_bytes.cpp
    src/platform/signed_index_records.cpp
    src/platform/unsigned_index_candidate.cpp
    src/platform/signed_index_acquisition_adapter.cpp
    src/platform/signed_index_acquisition_descriptor_internal.cpp
    src/platform/signed_index_store.cpp
    src/platform/signed_index_record_lookup.cpp
    src/platform/signed_index_scan.cpp
    src/platform/signed_index_candidate_binding.cpp
    src/platform/official_msi.cpp
    src/platform/official_pe_resource.cpp
    src/platform/official_resource_content.cpp
    src/platform/signed_index_resource_plan.cpp
    src/platform/official_seven_zip.cpp
    src/platform/official_sfx.cpp
    src/platform/maintenance_embedded_file_table.cpp
    src/platform/official_zip.cpp
    src/platform/official_inf_archive_binding.cpp
    src/platform/official_pe_inf_extraction.cpp
    src/platform/official_inf_metadata_extraction.cpp
    src/platform/provider_worker.cpp
    src/platform/hardware_refresh.cpp
    src/platform/vaio_catalog_parser.cpp
    src/platform/vaio_update_provider.cpp
    src/platform/windows_restore_point_service.cpp
    src/platform/windows_product_type.cpp
    src/platform/windows_error.cpp
    src/platform/windows_update_provider.cpp
)
target_include_directories(drivercrate_platform
    PUBLIC src
    PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/generated
)
target_link_libraries(drivercrate_platform
    PUBLIC
        drivercrate_core
    PRIVATE
        advapi32
        bcrypt
        cfgmgr32
        crypt32
        cryptxml
        drivercrate_lzma_sdk
        drivercrate_miniz
        msxml6
        msi
        shell32
        shlwapi
        userenv
        windowsapp
        winhttp
        wintrust
        version
        ws2_32
        ole32
        oleaut32
        wbemuuid
        setupapi
        newdev
        normaliz
        wuguid
)
drivercrate_apply_compiler_options(drivercrate_platform)

add_executable(DriverCrate WIN32
    src/app/app.manifest
    src/app/app.rc
    src/app/assets/drivercrate.ico
    src/app/assets/drivercrate-icon-master.png
    src/app/main.cpp
    src/app/main_window.cpp
    src/app/main_window_preparation.cpp
    src/app/main_window_metadata_search.cpp
    src/app/main_window_assessment.cpp
    src/app/main_window_app_update.cpp
)
# RC compilerのdependency出力にはICON fileが含まれないため、画像変更時にresourceを再構築する。
set_property(
    SOURCE src/app/app.rc
    APPEND
    PROPERTY OBJECT_DEPENDS "${CMAKE_CURRENT_SOURCE_DIR}/src/app/assets/drivercrate.ico"
)
target_include_directories(DriverCrate PRIVATE src ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_link_libraries(DriverCrate
    PRIVATE
        drivercrate_core
        drivercrate_platform
        comdlg32
        comctl32
        dwmapi
        ole32
        setupapi
        uxtheme
)
drivercrate_apply_compiler_options(DriverCrate)
drivercrate_apply_linker_options(DriverCrate)
target_link_options(DriverCrate
    PRIVATE
        "SHELL:/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\""
)

# 実linkしたEXEとprofileを結合し、package入口でlocal buildを拒否する。
set_property(TARGET DriverCrate APPEND PROPERTY LINK_DEPENDS
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RecordIndexBuildProfile.cmake"
    "${CMAKE_CURRENT_SOURCE_DIR}/src/platform/index_distribution_trust.h")
add_custom_command(TARGET DriverCrate POST_BUILD
    COMMAND "${CMAKE_COMMAND}" "-DEXECUTABLE=$<TARGET_FILE:DriverCrate>"
        "-DLOCAL_PROFILE=${DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE}"
        "-DDISTRIBUTION_FINGERPRINT=${drivercrate_distribution_fingerprint}"
        "-DACQUISITION_POLICY_REVISION=${drivercrate_distribution_acquisition_revision}"
        -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/RecordIndexBuildProfile.cmake"
    VERBATIM)

# Public consumer snapshot: private collection products are not distributed here.
if(DRIVERCRATE_BUILD_COLLECTOR OR DRIVERCRATE_BUILD_LOCAL_INDEX_SIGNER OR DRIVERCRATE_BUILD_LIVE_TESTS)
    message(FATAL_ERROR "This source snapshot supports the consumer app and nonnetwork tests only.")
endif()

if(BUILD_TESTING)
    add_executable(drivercrate_app_update_tests tests/unit/app_update_tests.cpp)
    target_link_libraries(drivercrate_app_update_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_app_update_tests)
    drivercrate_apply_linker_options(drivercrate_app_update_tests)
    add_test(NAME drivercrate_app_update_tests COMMAND drivercrate_app_update_tests)
    add_executable(drivercrate_pending_reference_tests tests/unit/pending_reference_version_tests.cpp)
    target_link_libraries(drivercrate_pending_reference_tests PRIVATE drivercrate_core)
    drivercrate_apply_compiler_options(drivercrate_pending_reference_tests)
    drivercrate_apply_linker_options(drivercrate_pending_reference_tests)
    add_test(NAME drivercrate_pending_reference_tests COMMAND drivercrate_pending_reference_tests)
    add_executable(drivercrate_local_diagnostic_log_tests tests/unit/local_diagnostic_log_tests.cpp)
    target_link_libraries(drivercrate_local_diagnostic_log_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_local_diagnostic_log_tests)
    drivercrate_apply_linker_options(drivercrate_local_diagnostic_log_tests)
    add_test(NAME drivercrate_local_diagnostic_log_tests COMMAND drivercrate_local_diagnostic_log_tests)
    target_compile_definitions(drivercrate_platform PRIVATE DRIVERCRATE_INTERNAL_INDEX_TESTS)
    add_executable(drivercrate_published_inf_identity_tests tests/unit/published_inf_identity_tests.cpp)
    target_link_libraries(drivercrate_published_inf_identity_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_published_inf_identity_tests)
    drivercrate_apply_linker_options(drivercrate_published_inf_identity_tests)
    add_test(NAME drivercrate_published_inf_identity_tests COMMAND drivercrate_published_inf_identity_tests)
    add_executable(drivercrate_official_html_terms_tests tests/unit/official_html_terms_tests.cpp)
    target_link_libraries(drivercrate_official_html_terms_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_official_html_terms_tests)
    drivercrate_apply_linker_options(drivercrate_official_html_terms_tests)
    add_test(NAME drivercrate_official_html_terms_tests COMMAND drivercrate_official_html_terms_tests)
    add_executable(drivercrate_metadata_ui_tests
        tests/ui/metadata_ui_tests.cpp
        tests/ui/app_update_ui_tests.cpp
        # UI専用observer版が全定義を供給する。通常platformの同objectはこのEXEでlinkしない。
        # Services/class layoutは共通で、通常productへtarget固有macroを伝播させない。
        src/platform/signed_index_scan.cpp
        tests/support/metadata_ui_fixture.cpp
        tests/unit/signed_index_candidate_binding_tests.cpp
        src/app/main_window.cpp
        src/app/main_window_metadata_search.cpp
        src/app/main_window_preparation.cpp
        src/app/main_window_assessment.cpp
        src/app/main_window_app_update.cpp
        src/app/app.rc
    )
    target_compile_definitions(drivercrate_metadata_ui_tests PRIVATE
        DRIVERCRATE_INTERNAL_UI_TESTS DRIVERCRATE_INTERNAL_INDEX_TESTS
        DRIVERCRATE_INTERNAL_INDEX_TASK_OBSERVER)
    target_include_directories(drivercrate_metadata_ui_tests
        PRIVATE src tests tests/unit ${CMAKE_CURRENT_BINARY_DIR}/generated
    )
    target_link_libraries(drivercrate_metadata_ui_tests PRIVATE
        drivercrate_core drivercrate_platform drivercrate_miniz
        comdlg32 comctl32 dwmapi ole32 setupapi uxtheme windowscodecs
    )
    drivercrate_apply_compiler_options(drivercrate_metadata_ui_tests)
    drivercrate_apply_linker_options(drivercrate_metadata_ui_tests)
    target_link_options(drivercrate_metadata_ui_tests PRIVATE
        # 既存独立objectとarchive選択の有限なlink証拠を標準出力へ保持する。
        /VERBOSE:LIB
        "SHELL:/MANIFESTUAC:\"level='asInvoker' uiAccess='false'\""
        "SHELL:/MANIFESTDEPENDENCY:\"type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='amd64' publicKeyToken='6595b64144ccf1df' language='*'\""
    )
    add_test(NAME drivercrate_metadata_ui_default_tests
        COMMAND drivercrate_metadata_ui_tests --run-ui-tests)
    set_tests_properties(drivercrate_metadata_ui_default_tests PROPERTIES
        RUN_SERIAL TRUE TIMEOUT 600 LABELS "ui;nonnetwork")
    add_test(NAME drivercrate_app_update_ui_tests
        COMMAND drivercrate_metadata_ui_tests --run-ui-tests app-update)
    set_tests_properties(drivercrate_app_update_ui_tests PROPERTIES
        RUN_SERIAL TRUE TIMEOUT 120 LABELS "ui;nonnetwork")
    add_executable(drivercrate_unit_tests
        tests/unit/signed_index_candidate_binding_tests.cpp
        tests/support/live_search_diagnostics.cpp
        tests/support/scan_measurement_diagnostics.cpp
        tests/unit/live_search_diagnostics_tests.cpp
        tests/unit/amd_catalog_parser_tests.cpp
        tests/unit/asix_catalog_parser_tests.cpp
        tests/unit/asrock_catalog_parser_tests.cpp
        tests/unit/asrock_system_identity_tests.cpp
        tests/unit/broadcom_official_provider_tests.cpp
        tests/unit/official_release_metadata_tests.cpp
        tests/unit/official_release_local_probe_tests.cpp
        tests/unit/official_release_observation_tests.cpp
        tests/unit/official_release_observation_store_tests.cpp
        tests/unit/official_preparation_tests.cpp
        tests/unit/official_prepared_acquisition_tests.cpp
        tests/unit/official_preparation_operation_tests.cpp
        tests/unit/prepared_audit_display_tests.cpp
        tests/unit/provider_preparation_worker_tests.cpp
        tests/unit/asus_catalog_parser_tests.cpp
        tests/unit/asus_system_identity_tests.cpp
        tests/unit/candidate_audit_tests.cpp
        tests/unit/official_workflow_evaluation_tests.cpp
        tests/unit/candidate_selection_tests.cpp
        tests/unit/candidate_source_group_tests.cpp
        tests/unit/dell_catalog_parser_tests.cpp
        tests/unit/dell_server_catalog_parser_tests.cpp
        tests/unit/hp_catalog_parser_tests.cpp
        tests/unit/intel_wireless_package_tests.cpp
        tests/unit/intel_ethernet_server_page_parser_tests.cpp
        tests/unit/intel_collector_identity_parser_tests.cpp
        tests/unit/intel_wireless_page_parser_tests.cpp
        tests/unit/intel_download_only_page_tests.cpp
        tests/unit/local_coverage_tests.cpp
        tests/unit/scan_measurement_diagnostics_tests.cpp
        tests/unit/scan_measurement_tests.cpp
        tests/unit/metadata_search_tests.cpp
        tests/unit/metadata_search_runner_tests.cpp
        tests/unit/metadata_search_budget_tests.cpp
        tests/unit/metadata_search_http_tests.cpp
        tests/unit/metadata_inventory_tests.cpp
        tests/unit/official_discovery_tests.cpp
        tests/unit/official_discovery_eula_tests.cpp
        tests/unit/official_discovery_provider_adapter_tests.cpp
        tests/unit/official_discovery_record_adapter_tests.cpp
        tests/unit/lenovo_catalog_parser_tests.cpp
        tests/unit/nvidia_catalog_parser_tests.cpp
        tests/unit/nvidia_winof2_catalog_parser_tests.cpp
        tests/unit/nvidia_winof2_driver_audit_tests.cpp
        tests/unit/nvidia_winof2_driver_package_tests.cpp
        tests/unit/official_acquisition_tests.cpp
        tests/unit/official_delegated_package_inspection_tests.cpp
        tests/unit/official_download_grant_tests.cpp
        tests/unit/official_driver_closure_tests.cpp
        tests/unit/official_driver_package_tests.cpp
        tests/unit/official_driver_rank_tests.cpp
        tests/unit/official_record_payload_routing_tests.cpp
        tests/unit/official_validation_tests.cpp
        tests/unit/official_gzip_tests.cpp
        tests/unit/official_msi_tests.cpp
        tests/unit/official_source_policy_tests.cpp
        tests/unit/official_seven_zip_tests.cpp
        tests/unit/official_sfx_tests.cpp
        tests/unit/maintenance_embedded_file_table_tests.cpp
        tests/unit/indexed_driver_package_inspection_tests.cpp
        tests/unit/official_zip_tests.cpp
        tests/unit/openpgp_signature_verifier_tests.cpp
        tests/unit/signed_index_manifest_tests.cpp
        tests/unit/signed_index_refresh_tests.cpp
        tests/unit/operation_controller_tests.cpp
        tests/unit/package_selection_tests.cpp
        tests/unit/provider_registry_tests.cpp
        tests/unit/protected_install_tests.cpp
        tests/unit/prolific_serial_package_tests.cpp
        tests/unit/prolific_official_provider_tests.cpp
        tests/unit/silicon_labs_official_provider_tests.cpp
        tests/unit/wch_official_provider_tests.cpp
        tests/unit/silicon_labs_serial_package_tests.cpp
        tests/unit/user_selected_inf_package_provider_tests.cpp
        tests/unit/wch_serial_package_tests.cpp
        tests/unit/test_main.cpp
        tests/unit/vaio_catalog_parser_tests.cpp
        tests/unit/windows_update_provider_tests.cpp
    )
    target_include_directories(drivercrate_unit_tests PRIVATE src tests tests/unit)
    target_compile_definitions(drivercrate_unit_tests PRIVATE DRIVERCRATE_INTERNAL_INDEX_TESTS)
    target_link_libraries(
        drivercrate_unit_tests
        PRIVATE
            drivercrate_miniz
            drivercrate_platform
			bcrypt
            crypt32
            msi
    )
    drivercrate_apply_compiler_options(drivercrate_unit_tests)
    target_include_directories(drivercrate_unit_tests PRIVATE "${CMAKE_CURRENT_BINARY_DIR}/generated")
    add_test(NAME drivercrate_unit_tests COMMAND drivercrate_unit_tests)
    set_property(SOURCE tests/unit/metadata_inventory_tests.cpp APPEND PROPERTY OBJECT_DEPENDS
        "${CMAKE_CURRENT_SOURCE_DIR}/tests/unit/index_capacity_inventory_tests.cpp")
    add_executable(drivercrate_index_binding_tests
        tests/unit/test_main.cpp
        tests/unit/metadata_inventory_tests.cpp
        tests/unit/signed_index_manifest_tests.cpp
        tests/unit/signed_index_candidate_binding_tests.cpp
        tests/unit/official_acquisition_tests.cpp
        tests/unit/official_preparation_tests.cpp
        tests/unit/official_preparation_operation_tests.cpp
        tests/unit/official_prepared_acquisition_tests.cpp
        tests/unit/official_driver_rank_tests.cpp
        tests/unit/candidate_audit_tests.cpp
    )
    target_include_directories(drivercrate_index_binding_tests PRIVATE src tests tests/unit "${CMAKE_CURRENT_BINARY_DIR}/generated")
    target_sources(drivercrate_index_binding_tests PRIVATE tests/unit/official_download_grant_tests.cpp)
    target_compile_definitions(drivercrate_index_binding_tests PRIVATE
        DRIVERCRATE_INTERNAL_INDEX_TESTS DRIVERCRATE_INDEX_BINDING_STANDALONE)
    target_link_libraries(drivercrate_index_binding_tests PRIVATE
        drivercrate_miniz drivercrate_platform bcrypt crypt32 msi)
    drivercrate_apply_compiler_options(drivercrate_index_binding_tests)
    add_test(NAME drivercrate_index_binding_tests COMMAND drivercrate_index_binding_tests)
    add_executable(drivercrate_maintenance_inf_structure_tests
        tests/unit/maintenance_inf_structure_main.cpp
        tests/unit/official_driver_package_tests.cpp)
    target_include_directories(drivercrate_maintenance_inf_structure_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_maintenance_inf_structure_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_maintenance_inf_structure_tests)
    drivercrate_apply_linker_options(drivercrate_maintenance_inf_structure_tests)
    add_test(NAME drivercrate_maintenance_inf_structure_tests COMMAND drivercrate_maintenance_inf_structure_tests)
    set_tests_properties(drivercrate_maintenance_inf_structure_tests PROPERTIES TIMEOUT 120)
    add_executable(drivercrate_maintenance_inf_integrity_tests
        tests/unit/maintenance_inf_integrity_tests.cpp
        tests/live/maintenance_reached_reference_observation.cpp
        src/platform/official_driver_closure.cpp
        src/platform/common_driver_package.cpp)
    set(drivercrate_integrity_test_scratch
        "${CMAKE_CURRENT_BINARY_DIR}/test-scratch/maintenance-inf-integrity")
    file(MAKE_DIRECTORY "${drivercrate_integrity_test_scratch}")
    target_compile_definitions(drivercrate_maintenance_inf_integrity_tests PRIVATE
        DRIVERCRATE_MAINTENANCE_INTEGRITY_TESTING
        DRIVERCRATE_REACHED_REFERENCE_RESEARCH
        DRIVERCRATE_REACHED_WORKSPACE=L"${drivercrate_integrity_test_scratch}/reached-$<CONFIG>"
        DRIVERCRATE_RESIDUAL_WORKSPACE=L"${drivercrate_integrity_test_scratch}/residual-$<CONFIG>"
        verifyWindowsInfPackageIntegrity=verifyMaintenanceInfIntegrityForTest
        inspectNativeInfDependencies=inspectMaintenanceInfDependenciesForTest)
    target_include_directories(drivercrate_maintenance_inf_integrity_tests PRIVATE src tests/unit tests/live)
    target_link_libraries(drivercrate_maintenance_inf_integrity_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_maintenance_inf_integrity_tests)
    drivercrate_apply_linker_options(drivercrate_maintenance_inf_integrity_tests)
    add_test(NAME drivercrate_maintenance_inf_integrity_tests COMMAND drivercrate_maintenance_inf_integrity_tests)
    set_tests_properties(drivercrate_maintenance_inf_integrity_tests PROPERTIES TIMEOUT 120)
    add_executable(drivercrate_inf_dependency_tests tests/unit/inf_dependency_plan_tests.cpp)
    target_include_directories(drivercrate_inf_dependency_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_tests)
    add_test(NAME drivercrate_inf_dependency_tests COMMAND drivercrate_inf_dependency_tests)
    add_executable(drivercrate_inf_dependency_review_boundary_tests
        tests/unit/inf_dependency_review_boundary_tests.cpp)
    target_include_directories(drivercrate_inf_dependency_review_boundary_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_review_boundary_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_review_boundary_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_review_boundary_tests)
    add_test(NAME drivercrate_inf_dependency_review_boundary_tests COMMAND drivercrate_inf_dependency_review_boundary_tests)
    add_executable(drivercrate_resource_content_tests tests/unit/resource_content_tests.cpp)
    target_include_directories(drivercrate_resource_content_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_resource_content_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_resource_content_tests)
    drivercrate_apply_linker_options(drivercrate_resource_content_tests)
    add_test(NAME drivercrate_resource_content_tests COMMAND drivercrate_resource_content_tests
        vectors "${CMAKE_CURRENT_SOURCE_DIR}/tests/fixtures/pe-resource")
    add_executable(drivercrate_common_inf_plan_tests tests/unit/common_inf_plan_tests.cpp)
    target_include_directories(drivercrate_common_inf_plan_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_plan_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_plan_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_plan_tests)
    add_test(NAME drivercrate_common_inf_plan_tests COMMAND drivercrate_common_inf_plan_tests)
    add_executable(drivercrate_common_inf_batch_tests tests/unit/common_inf_batch_tests.cpp)
    target_include_directories(drivercrate_common_inf_batch_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_batch_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_batch_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_batch_tests)
    add_test(NAME drivercrate_common_inf_batch_tests COMMAND drivercrate_common_inf_batch_tests)
    add_executable(drivercrate_common_inf_factory_regression_tests tests/unit/common_inf_plan_tests.cpp)
    target_include_directories(drivercrate_common_inf_factory_regression_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_factory_regression_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_factory_regression_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_factory_regression_tests)
    add_test(NAME drivercrate_common_inf_factory_regression_tests COMMAND drivercrate_common_inf_factory_regression_tests)
    add_executable(drivercrate_common_inf_contract_tests tests/unit/common_inf_batch_tests.cpp)
    target_compile_definitions(drivercrate_common_inf_contract_tests PRIVATE DRIVERCRATE_COMMON_INF_CONTRACT_TESTS=1)
    target_include_directories(drivercrate_common_inf_contract_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_inf_contract_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_common_inf_contract_tests)
    drivercrate_apply_linker_options(drivercrate_common_inf_contract_tests)
    add_test(NAME drivercrate_common_inf_contract_tests COMMAND drivercrate_common_inf_contract_tests)
    add_executable(drivercrate_acquired_file_evidence_tests
        tests/unit/acquired_file_evidence_main.cpp tests/unit/official_acquisition_tests.cpp)
    target_include_directories(drivercrate_acquired_file_evidence_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_acquired_file_evidence_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_acquired_file_evidence_tests)
    drivercrate_apply_linker_options(drivercrate_acquired_file_evidence_tests)
    add_test(NAME drivercrate_acquired_file_evidence_tests COMMAND drivercrate_acquired_file_evidence_tests)
    add_executable(drivercrate_inf_archive_binding_tests tests/unit/official_inf_archive_binding_tests.cpp)
    target_include_directories(drivercrate_inf_archive_binding_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_archive_binding_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_inf_archive_binding_tests)
    drivercrate_apply_linker_options(drivercrate_inf_archive_binding_tests)
    add_test(NAME drivercrate_inf_archive_binding_tests COMMAND drivercrate_inf_archive_binding_tests)
    add_executable(drivercrate_acquired_inf_native_binding_tests
        tests/unit/official_inf_archive_binding_tests.cpp
        src/platform/inf_dependency_native.cpp)
    target_compile_definitions(drivercrate_acquired_inf_native_binding_tests PRIVATE
        DRIVERCRATE_INF_DEPENDENCY_TESTING DRIVERCRATE_ACQUIRED_INF_NATIVE_TESTING)
    target_include_directories(drivercrate_acquired_inf_native_binding_tests PRIVATE src tests tests/unit)
    target_link_libraries(drivercrate_acquired_inf_native_binding_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_acquired_inf_native_binding_tests)
    drivercrate_apply_linker_options(drivercrate_acquired_inf_native_binding_tests)
    add_test(NAME drivercrate_acquired_inf_native_binding_tests COMMAND drivercrate_acquired_inf_native_binding_tests)
    add_executable(drivercrate_collector_inspection_tests tests/unit/collector_inspection_acquisition_tests.cpp)
    target_include_directories(drivercrate_collector_inspection_tests PRIVATE src)
    target_link_libraries(drivercrate_collector_inspection_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_collector_inspection_tests)
    drivercrate_apply_linker_options(drivercrate_collector_inspection_tests)
    add_test(NAME drivercrate_collector_inspection_tests COMMAND drivercrate_collector_inspection_tests)
    add_executable(drivercrate_inf_dependency_native_tests tests/unit/inf_dependency_native_tests.cpp)
    target_include_directories(drivercrate_inf_dependency_native_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_inf_dependency_native_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_native_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_native_tests)
    add_test(NAME drivercrate_inf_dependency_native_tests COMMAND drivercrate_inf_dependency_native_tests)
    add_executable(drivercrate_inf_dependency_native_api_tests
        tests/unit/inf_dependency_native_api_tests.cpp
        tests/unit/official_driver_package_service_contract_tests.cpp
        src/platform/inf_dependency_native.cpp
    )
    target_compile_definitions(drivercrate_inf_dependency_native_api_tests PRIVATE DRIVERCRATE_INF_DEPENDENCY_TESTING)
    target_include_directories(drivercrate_inf_dependency_native_api_tests PRIVATE src tests tests/unit)
    target_link_libraries(drivercrate_inf_dependency_native_api_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_inf_dependency_native_api_tests)
    drivercrate_apply_linker_options(drivercrate_inf_dependency_native_api_tests)
    add_test(NAME drivercrate_inf_dependency_native_api_tests COMMAND drivercrate_inf_dependency_native_api_tests)
    add_executable(drivercrate_official_catalog_algorithm_tests tests/unit/official_catalog_algorithm_tests.cpp)
    target_compile_definitions(drivercrate_official_catalog_algorithm_tests PRIVATE DRIVERCRATE_INTERNAL_INDEX_TESTS)
    target_include_directories(drivercrate_official_catalog_algorithm_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_official_catalog_algorithm_tests PRIVATE drivercrate_platform)
    drivercrate_apply_compiler_options(drivercrate_official_catalog_algorithm_tests)
    drivercrate_apply_linker_options(drivercrate_official_catalog_algorithm_tests)
    add_test(NAME drivercrate_official_catalog_algorithm_tests COMMAND drivercrate_official_catalog_algorithm_tests)
    add_executable(drivercrate_common_driver_content_tests tests/unit/common_driver_content_tests.cpp)
    target_compile_definitions(drivercrate_common_driver_content_tests PRIVATE DRIVERCRATE_INTERNAL_INDEX_TESTS)
    target_include_directories(drivercrate_common_driver_content_tests PRIVATE src tests/unit)
    target_link_libraries(drivercrate_common_driver_content_tests PRIVATE drivercrate_platform drivercrate_miniz)
    drivercrate_apply_compiler_options(drivercrate_common_driver_content_tests)
    drivercrate_apply_linker_options(drivercrate_common_driver_content_tests)
    add_test(NAME drivercrate_common_driver_content_tests COMMAND drivercrate_common_driver_content_tests)
    foreach(drivercrate_ui_mode IN ITEMS close queue index binding multi unknown
            components needs extension formats preparation refresh)
        add_test(NAME drivercrate_metadata_ui_${drivercrate_ui_mode}_tests
            COMMAND drivercrate_metadata_ui_tests --run-ui-tests ${drivercrate_ui_mode})
        set_tests_properties(drivercrate_metadata_ui_${drivercrate_ui_mode}_tests PROPERTIES
            RUN_SERIAL TRUE TIMEOUT 600 LABELS "ui;nonnetwork")
    endforeach()
endif()
