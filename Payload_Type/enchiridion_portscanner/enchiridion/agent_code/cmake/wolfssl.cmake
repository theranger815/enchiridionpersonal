# ------------------------------------------------------------
# WolfSSL — ext::wolfssl INTERFACE target
# Guarded so it is safe to include from multiple places.
# ------------------------------------------------------------
if(TARGET ext::wolfssl)
    return()
endif()

if(PREBUILT_EXTERNAL_ROOT AND EXISTS "${EXT_ROOT}/lib/libwolfssl.a")
    add_library(ext::wolfssl STATIC IMPORTED GLOBAL)
    set_target_properties(ext::wolfssl PROPERTIES
        IMPORTED_LOCATION             ${EXT_ROOT}/lib/libwolfssl.a
        INTERFACE_INCLUDE_DIRECTORIES ${EXT_ROOT}/include
    )
else()

ExternalProject_Add(
    ext_wolfssl
    GIT_REPOSITORY https://github.com/wolfSSL/wolfssl.git
    GIT_TAG        v5.7.4-stable
    GIT_SHALLOW    ON
    SOURCE_DIR     ${EXT_SRC}/wolfssl
    BINARY_DIR     ${EXT_SRC}/wolfssl  # ADD THIS: Tells CMake where the Makefile is
    CONFIGURE_COMMAND cd <SOURCE_DIR> && ./autogen.sh && ${CMAKE_COMMAND} -E env
        CC=${CMAKE_C_COMPILER}
        CFLAGS=${EXT_C_FLAGS}
        ./configure
            --host=x86_64-linux
            --prefix=${EXT_ROOT}
            --enable-static
            --disable-shared
            --enable-curl
            --enable-keygen
            --enable-sni
            --enable-session-ticket
            --disable-examples
            --disable-crypttests
    BUILD_COMMAND   ${CMAKE_MAKE_PROGRAM} -j${MAKE_JOBS}
    INSTALL_COMMAND ${CMAKE_MAKE_PROGRAM} install
    BUILD_BYPRODUCTS ${EXT_ROOT}/lib/libwolfssl.a
)

if(STRIP_LIBS)
    ExternalProject_Add_Step(ext_wolfssl strip_lib
        COMMAND strip --strip-unneeded ${EXT_ROOT}/lib/libwolfssl.a || true
        DEPENDEES install
    )
endif()

add_library(ext::wolfssl STATIC IMPORTED GLOBAL)
set_target_properties(ext::wolfssl PROPERTIES
    IMPORTED_LOCATION             ${EXT_ROOT}/lib/libwolfssl.a
    INTERFACE_INCLUDE_DIRECTORIES ${EXT_ROOT}/include
)
add_dependencies(ext::wolfssl ext_wolfssl)

endif() # PREBUILT_EXTERNAL_ROOT
