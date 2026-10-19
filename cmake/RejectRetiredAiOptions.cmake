# ADR 0224の撤去済み設定を拒否する。機能・target・runtime取得は追加しない。
# ADR 0224によりAIは撤去済み。旧設定のONを黙って無視せず、OFFの旧cacheだけ除去する。
get_cmake_property(drivercrate_cached_variables CACHE_VARIABLES)
foreach(drivercrate_cached_variable IN LISTS drivercrate_cached_variables)
    if(drivercrate_cached_variable MATCHES "^DRIVERCRATE_BUILD_LOCAL_AI_"
        OR drivercrate_cached_variable STREQUAL "DRIVERCRATE_GGML_CUDA_EXPLICIT_REGISTRATION"
        OR drivercrate_cached_variable STREQUAL "GGML_CUDA")
        if(${drivercrate_cached_variable})
            message(FATAL_ERROR
                "AI support was removed (ADR 0224); unset retired option: ${drivercrate_cached_variable}")
        endif()
        unset(${drivercrate_cached_variable} CACHE)
    elseif(drivercrate_cached_variable MATCHES "^(GGML_|LLAMA_|llama_cpp_|CUDA_|CUDAToolkit_)"
        OR drivercrate_cached_variable STREQUAL "DRIVERCRATE_CUDA_SDK_ROOT"
        OR drivercrate_cached_variable MATCHES "^CMAKE_CUDA_"
        OR drivercrate_cached_variable MATCHES "^FETCHCONTENT_.*LLAMA_CPP$"
        OR drivercrate_cached_variable MATCHES "^_CUDAToolkit_"
        OR drivercrate_cached_variable STREQUAL "FIND_PACKAGE_MESSAGE_DETAILS_CUDAToolkit")
        unset(${drivercrate_cached_variable} CACHE)
    endif()
endforeach()
