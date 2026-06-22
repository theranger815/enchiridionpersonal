# ------------------------------------------------------------
# HTTP C2 dependencies: zlib, WolfSSL, libcurl
# Produces ext::curl INTERFACE target.
# ------------------------------------------------------------
if(TARGET ext::curl)
    return()
endif()

# WolfSSL is the TLS backend for curl
include(${CMAKE_SOURCE_DIR}/cmake/wolfssl.cmake)

# zlib
if(PREBUILT_EXTERNAL_ROOT AND EXISTS "${EXT_ROOT}/lib/libz.a")
    add_library(ext::zlib STATIC IMPORTED GLOBAL)
    set_target_properties(ext::zlib PROPERTIES
        IMPORTED_LOCATION             ${EXT_ROOT}/lib/libz.a
        INTERFACE_INCLUDE_DIRECTORIES ${EXT_ROOT}/include
    )
else()

ExternalProject_Add(
    ext_zlib
    URL      https://github.com/madler/zlib/releases/download/v1.3.1/zlib-1.3.1.tar.gz
    URL_HASH SHA256=9a93b2b7dfdac77ceba5a558a580e74667dd6fede4585b91eefb60f03b72df23
    SOURCE_DIR ${EXT_SRC}/zlib
    CONFIGURE_COMMAND ${CMAKE_COMMAND} -E env
        CC=${CMAKE_C_COMPILER}
        CFLAGS=${EXT_C_FLAGS}
        <SOURCE_DIR>/configure
            --prefix=${EXT_ROOT}
            --static
    BUILD_COMMAND   ${CMAKE_MAKE_PROGRAM} -j${MAKE_JOBS}
    INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
    BUILD_BYPRODUCTS ${EXT_ROOT}/lib/libz.a
)

if(STRIP_LIBS)
    ExternalProject_Add_Step(ext_zlib strip_lib
        COMMAND strip --strip-unneeded ${EXT_ROOT}/lib/libz.a || true
        DEPENDEES install
    )
endif()

add_library(ext::zlib STATIC IMPORTED GLOBAL)
set_target_properties(ext::zlib PROPERTIES
    IMPORTED_LOCATION             ${EXT_ROOT}/lib/libz.a
    INTERFACE_INCLUDE_DIRECTORIES ${EXT_ROOT}/include
)
add_dependencies(ext::zlib ext_zlib)

endif() # PREBUILT_EXTERNAL_ROOT (zlib)

# libcurl
if(PREBUILT_EXTERNAL_ROOT AND EXISTS "${EXT_ROOT}/lib/libcurl.a")
    add_library(ext::curl STATIC IMPORTED GLOBAL)
    set_target_properties(ext::curl PROPERTIES
        IMPORTED_LOCATION                 ${EXT_ROOT}/lib/libcurl.a
        INTERFACE_INCLUDE_DIRECTORIES     ${EXT_ROOT}/include
        INTERFACE_COMPILE_DEFINITIONS     CURL_STATICLIB
        INTERFACE_LINK_LIBRARIES          "ext::wolfssl;ext::zlib"
    )
else()

ExternalProject_Add(
    ext_curl
    GIT_REPOSITORY https://github.com/curl/curl.git
    GIT_TAG        curl-8_11_1
    GIT_SHALLOW    ON
    SOURCE_DIR     ${EXT_SRC}/curl
    CMAKE_ARGS
        ${COMMON_CMAKE_ARGS}
        -DCMAKE_BUILD_TYPE=Release
        -DCMAKE_INSTALL_PREFIX=${EXT_ROOT}
        -DCMAKE_FIND_USE_SYSTEM_ENVIRONMENT_PATH=OFF
        -DBUILD_SHARED_LIBS=OFF
        -DCURL_STATICLIB=ON
        -DBUILD_TESTING=OFF
        -DBUILD_CURL_EXE=OFF
        # Disable optional features
        -DUSE_NGHTTP2=OFF
        -DUSE_LIBIDN2=OFF
        -DCURL_USE_LIBPSL=OFF
        -DCURL_USE_LIBSSH2=OFF
        -DCURL_BROTLI=OFF
        -DCURL_ZSTD=OFF
        -DENABLE_UNIX_SOCKETS=OFF
        # Disable unneeded protocols
        -DCURL_DISABLE_LDAP=ON
        -DCURL_DISABLE_LDAPS=ON
        -DCURL_DISABLE_TELNET=ON
        -DCURL_DISABLE_DICT=ON
        -DCURL_DISABLE_FILE=ON
        -DCURL_DISABLE_TFTP=ON
        -DCURL_DISABLE_RTSP=ON
        -DCURL_DISABLE_POP3=ON
        -DCURL_DISABLE_IMAP=ON
        -DCURL_DISABLE_SMTP=ON
        -DCURL_DISABLE_GOPHER=ON
        -DCURL_DISABLE_MQTT=ON
        # TLS: WolfSSL
        -DCURL_USE_WOLFSSL=ON
        -DWolfSSL_INCLUDE_DIR=${EXT_ROOT}/include
        -DWolfSSL_LIBRARY=${EXT_ROOT}/lib/libwolfssl.a
        # Compression: zlib
        -DZLIB_LIBRARY=${EXT_ROOT}/lib/libz.a
        -DZLIB_INCLUDE_DIR=${EXT_ROOT}/include
    DEPENDS ext_zlib ext_wolfssl
    BUILD_BYPRODUCTS ${EXT_ROOT}/lib/libcurl.a
)

if(STRIP_LIBS)
    ExternalProject_Add_Step(ext_curl strip_lib
        COMMAND strip --strip-unneeded ${EXT_ROOT}/lib/libcurl.a || true
        DEPENDEES install
    )
endif()

# ext::curl carries its own transitive deps (wolfssl, zlib) so
# anything linking ext::curl gets all three automatically.
add_library(ext::curl STATIC IMPORTED GLOBAL)
set_target_properties(ext::curl PROPERTIES
    IMPORTED_LOCATION                 ${EXT_ROOT}/lib/libcurl.a
    INTERFACE_INCLUDE_DIRECTORIES     ${EXT_ROOT}/include
    INTERFACE_COMPILE_DEFINITIONS     CURL_STATICLIB
    INTERFACE_LINK_LIBRARIES          "ext::wolfssl;ext::zlib"
)
add_dependencies(ext::curl ext_curl)

endif() # PREBUILT_EXTERNAL_ROOT (curl)
