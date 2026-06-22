cmake_minimum_required(VERSION 3.10...3.26)
project(enchiridion VERSION 0.1.0 LANGUAGES C)
include(ExternalProject)
include(ProcessorCount)

# ------------------------------------------------------------
# Build configuration
# ------------------------------------------------------------
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

ProcessorCount(N)
if(N GREATER 0)
    set(MAKE_JOBS ${N})
else()
    set(MAKE_JOBS 1)
endif()

# ------------------------------------------------------------
# Options
# ------------------------------------------------------------
set(C2_IMPL "http" CACHE STRING "C2 implementation (semicolon-separated: http;websocket)")

set(ENCRYPTION_MODE "NONE" CACHE STRING "Encryption mode: NONE, STATIC_KEY, or EKE")
set_property(CACHE ENCRYPTION_MODE PROPERTY STRINGS NONE STATIC_KEY EKE)

if(NOT ENCRYPTION_MODE STREQUAL "NONE" AND
   NOT ENCRYPTION_MODE STREQUAL "STATIC_KEY" AND
   NOT ENCRYPTION_MODE STREQUAL "EKE")
    message(FATAL_ERROR "Invalid ENCRYPTION_MODE '${ENCRYPTION_MODE}'. Must be one of: NONE, STATIC_KEY, EKE")
endif()

# ------------------------------------------------------------
# Paths
# ------------------------------------------------------------
set(EXT_ROOT ${CMAKE_BINARY_DIR}/external)

set(PREBUILT_EXTERNAL_ROOT "" CACHE PATH "Pre-built external deps root (skips ExternalProject downloads)")
if(PREBUILT_EXTERNAL_ROOT)
    set(EXT_ROOT "${PREBUILT_EXTERNAL_ROOT}")
endif()

set(EXT_SRC  ${CMAKE_BINARY_DIR}/external/src)
file(MAKE_DIRECTORY ${EXT_ROOT}/include)

# ------------------------------------------------------------
# Build-type specific flags for external libraries
# ------------------------------------------------------------
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(EXT_C_FLAGS "-Os -ffunction-sections -fdata-sections -fvisibility=hidden -fno-asynchronous-unwind-tables -DNDEBUG -fno-ident -fno-stack-protector -fmacro-prefix-map=${EXT_SRC}=. -ffile-prefix-map=${EXT_SRC}=. -fdebug-prefix-map=${EXT_SRC}=.")
    set(STRIP_LIBS TRUE)
else()
    set(EXT_C_FLAGS "-g -O0")
    set(STRIP_LIBS FALSE)
endif()

# ------------------------------------------------------------
# Compiler / linker flags
# ------------------------------------------------------------
set(CMAKE_C_FLAGS
    "-Wall -Wextra -Wpedantic -Wshadow -Wformat=2 -Wundef -Wstrict-prototypes")
set(CMAKE_C_FLAGS_DEBUG   "-g -O0 -fno-omit-frame-pointer -DDEBUG")
set(CMAKE_C_FLAGS_RELEASE
    "-Os -DNDEBUG -fomit-frame-pointer -fdata-sections -ffunction-sections \
     -fno-asynchronous-unwind-tables -fvisibility=hidden -fno-stack-protector -fno-ident")

if(CMAKE_BUILD_TYPE STREQUAL "Release")
    set(CMAKE_EXE_LINKER_FLAGS_RELEASE
        "-static -Wl,--gc-sections -Wl,--strip-all -Wl,--build-id=none")
else()
    set(CMAKE_EXE_LINKER_FLAGS_DEBUG "-static")
endif()

# ------------------------------------------------------------
# Common CMake args forwarded to external projects
# ------------------------------------------------------------
set(COMMON_CMAKE_ARGS
    -DCMAKE_C_COMPILER=${CMAKE_C_COMPILER}
    -DCMAKE_CXX_COMPILER=${CMAKE_CXX_COMPILER}
    -DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}
    -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    -DCMAKE_C_FLAGS=${EXT_C_FLAGS}
    -DCMAKE_INSTALL_LIBDIR=lib
)

# ------------------------------------------------------------
# External dependency interface targets
# Each cmake/ file builds an external lib and creates an
# INTERFACE target that carries all link/include requirements.
# Consumers just target_link_libraries(...) against the target.
# ------------------------------------------------------------

# C2 implementations
set(VALID_C2_IMPLS http websocket)
foreach(impl IN LISTS C2_IMPL)
    if(impl STREQUAL "http")
        include(cmake/c2_http.cmake)
    elseif(impl STREQUAL "websocket")
        include(cmake/c2_websocket.cmake)
    else()
        message(FATAL_ERROR "Unknown C2_IMPL '${impl}'. Valid: ${VALID_C2_IMPLS}")
    endif()
endforeach()

# Encryption
if(NOT ENCRYPTION_MODE STREQUAL "NONE")
    include(cmake/encryption.cmake)
endif()

# ------------------------------------------------------------
# C2 library
# ------------------------------------------------------------
add_library(c2 STATIC)
target_include_directories(c2 PUBLIC include PRIVATE ${EXT_ROOT}/include)

if("http" IN_LIST C2_IMPL)
    target_sources(c2 PRIVATE src/c2/http.c)
    target_link_libraries(c2 PRIVATE ext::curl)
endif()

if("websocket" IN_LIST C2_IMPL)
    target_sources(c2 PRIVATE src/c2/websocket.c)
    target_link_libraries(c2 PRIVATE ext::websocket)
    # wolfSSL native API headers need options.h for feature-gated declarations
    target_compile_definitions(c2 PRIVATE WOLFSSL_USE_OPTIONS_H)
endif()

# ------------------------------------------------------------
# Main executable
# ------------------------------------------------------------
file(GLOB COMMAND_SOURCES CONFIGURE_DEPENDS "src/commands/*.c")
add_executable(enchiridion
    src/agent.c
    src/b64.c
    src/cJSON.c
    src/config.c
    src/enchiridion.c
    src/socks5.c
    src/utils.c
    ${COMMAND_SOURCES}
)

target_include_directories(enchiridion PRIVATE include ${EXT_ROOT}/include)

target_link_libraries(enchiridion PRIVATE c2)

if("http" IN_LIST C2_IMPL)
    target_compile_definitions(enchiridion PRIVATE CURL_STATICLIB)
    target_link_libraries(enchiridion PRIVATE ext::curl)
endif()

if("websocket" IN_LIST C2_IMPL)
    target_link_libraries(enchiridion PRIVATE ext::websocket)
endif()

if(NOT ENCRYPTION_MODE STREQUAL "NONE")
    target_sources(enchiridion PRIVATE src/crypto.c)
    target_link_libraries(enchiridion PRIVATE ext::wolfssl)
    target_compile_definitions(enchiridion PRIVATE WOLFSSL_USE_OPTIONS_H)
endif()

if(ENCRYPTION_MODE STREQUAL "STATIC_KEY")
    target_compile_definitions(enchiridion PRIVATE ENCRYPTION_STATIC_KEY)
elseif(ENCRYPTION_MODE STREQUAL "EKE")
    target_compile_definitions(enchiridion PRIVATE ENCRYPTION_EKE)
endif()

# Strip the final binary (Release only)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
    add_custom_command(TARGET enchiridion POST_BUILD
        COMMAND strip --strip-all $<TARGET_FILE:enchiridion>
        COMMAND objcopy --remove-section=.comment --remove-section=.note
                        --remove-section=.note.gnu.build-id
                        $<TARGET_FILE:enchiridion> || true
        COMMENT "Stripping enchiridion"
    )
endif()

# ------------------------------------------------------------
# Status
# ------------------------------------------------------------
message(STATUS "Build type:      ${CMAKE_BUILD_TYPE}")
message(STATUS "C2 impl:         ${C2_IMPL}")
message(STATUS "Encryption mode: ${ENCRYPTION_MODE}")
message(STATUS "C compiler:      ${CMAKE_C_COMPILER}")
message(STATUS "External flags:  ${EXT_C_FLAGS}")
message(STATUS "Strip libs:      ${STRIP_LIBS}")
message(STATUS "External root:   ${EXT_ROOT}")
