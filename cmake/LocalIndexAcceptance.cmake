# ADR0337/0348: 通常製品の固定配布profileと排他的なlocal受入pin。
include("${CMAKE_CURRENT_LIST_DIR}/RecordIndexBuildProfile.cmake")
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS
    "${CMAKE_CURRENT_LIST_DIR}/RecordIndexBuildProfile.cmake"
    "${CMAKE_CURRENT_LIST_DIR}/../src/platform/index_distribution_trust.h")
drivercrate_distribution_profile(drivercrate_distribution_fingerprint drivercrate_distribution_acquisition_revision)
option(DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE "Use a pinned local acceptance index key (never distribute)." OFF)
option(DRIVERCRATE_LOCAL_INDEX_ACQUISITION "Allow revision1 acquisition for the pinned local key." OFF)
option(DRIVERCRATE_BUILD_LOCAL_INDEX_SIGNER "Build the explicit development-only native index signer." OFF)
set(DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB "" CACHE FILEPATH "Explicit public-only RSA3072 CNG blob.")
set(DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256 "" CACHE STRING "Reviewed full SHA256 of the public blob.")
set(drivercrate_local_index_blob_values "")
set(drivercrate_local_index_key_id "")
set(drivercrate_local_index_fingerprint "")
set(drivercrate_local_index_key_count 0)
set(drivercrate_local_index_acquisition_count 0)
set(drivercrate_local_index_trust_entry "")
set(drivercrate_local_index_acquisition_entry "")
set(drivercrate_local_index_enabled false)
if(DRIVERCRATE_LOCAL_INDEX_ACQUISITION AND NOT DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE)
    message(FATAL_ERROR "Local acquisition requires the independent acceptance profile.")
endif()
if(DRIVERCRATE_LOCAL_INDEX_ACCEPTANCE)
    set(drivercrate_local_index_enabled true)
    set(drivercrate_distribution_fingerprint "")
    set(drivercrate_distribution_acquisition_revision 0)
    if(NOT IS_ABSOLUTE "${DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB}"
        OR NOT EXISTS "${DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB}")
        message(FATAL_ERROR "An explicit existing absolute public blob is required.")
    endif()
    string(LENGTH "${DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256}" drivercrate_fingerprint_length)
    if(NOT drivercrate_fingerprint_length EQUAL 64
        OR NOT DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256 MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR "An exact lowercase SHA256 public fingerprint is required.")
    endif()
    # 同じimmutable byteからshape/hash/HEXを作る。通常OFFと製品runtimeではPythonを使わない。
    find_package(Python3 3.10 REQUIRED COMPONENTS Interpreter)
    execute_process(
        COMMAND "${Python3_EXECUTABLE}" -Xutf8 -B
            "${CMAKE_CURRENT_LIST_DIR}/../scripts/local_index_build_pin.py"
            --public-blob "${DRIVERCRATE_LOCAL_INDEX_PUBLIC_BLOB}"
            --fingerprint "${DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256}"
        RESULT_VARIABLE drivercrate_pin_result
        OUTPUT_VARIABLE drivercrate_pin_json
        ERROR_VARIABLE drivercrate_pin_error
        OUTPUT_STRIP_TRAILING_WHITESPACE
        TIMEOUT 120
    )
    if(NOT drivercrate_pin_result STREQUAL "0")
        message(FATAL_ERROR "Local public pin validation failed: ${drivercrate_pin_error}")
    endif()
    string(JSON drivercrate_pin_fields ERROR_VARIABLE drivercrate_pin_json_error
        LENGTH "${drivercrate_pin_json}")
    if(NOT drivercrate_pin_json_error STREQUAL "NOTFOUND" OR NOT drivercrate_pin_fields EQUAL 2)
        message(FATAL_ERROR "Local public pin response is malformed.")
    endif()
    string(JSON drivercrate_local_index_fingerprint GET "${drivercrate_pin_json}" fingerprint)
    string(JSON drivercrate_public_hex GET "${drivercrate_pin_json}" hex)
    string(LENGTH "${drivercrate_public_hex}" drivercrate_public_hex_length)
    if(NOT drivercrate_local_index_fingerprint STREQUAL DRIVERCRATE_LOCAL_INDEX_PUBLIC_SHA256
        OR NOT drivercrate_public_hex_length EQUAL 822
        OR NOT drivercrate_public_hex MATCHES "^[0-9a-f]+$")
        message(FATAL_ERROR "Local public pin response does not match the reviewed input.")
    endif()
    string(REGEX REPLACE "([0-9a-f][0-9a-f])" "0x\\1U," drivercrate_local_index_blob_values "${drivercrate_public_hex}")
    string(SUBSTRING "${drivercrate_local_index_fingerprint}" 0 32 drivercrate_local_index_key_suffix)
    set(drivercrate_local_index_key_id "local-index-${drivercrate_local_index_key_suffix}")
    set(drivercrate_local_index_key_count 1)
    set(drivercrate_local_index_trust_entry "{KEY_ID, PUBLIC_BLOB},")
    if(DRIVERCRATE_LOCAL_INDEX_ACQUISITION)
        set(drivercrate_local_index_acquisition_count 1)
        set(drivercrate_local_index_acquisition_entry "KEY_ID,")
    endif()
endif()
configure_file("${CMAKE_CURRENT_LIST_DIR}/local_index_acceptance.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/generated/local_index_acceptance.h" @ONLY)
