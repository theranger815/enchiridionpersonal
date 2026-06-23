# cmake/musl-toolchain.cmake

set(MUSL_TRIPLE x86_64-linux-musl)
set(MUSL_ARCHIVE_NAME ${MUSL_TRIPLE}-native)

set(MUSL_ROOT ${CMAKE_BINARY_DIR}/musl-toolchain CACHE PATH "")
set(MUSL_URL  https://musl.cc/${MUSL_ARCHIVE_NAME}.tgz)

set(MUSL_SHA256 "" CACHE STRING "SHA256 of musl.cc toolchain archive")

set(MUSL_TOOLCHAIN_DIR ${MUSL_ROOT}/${MUSL_ARCHIVE_NAME})
set(MUSL_GCC ${MUSL_TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-gcc)

# ------------------------------------------------------------
# Download toolchain if missing
# ------------------------------------------------------------
if(NOT EXISTS ${MUSL_GCC})
    message(STATUS "Downloading musl toolchain from musl.cc")

    file(MAKE_DIRECTORY ${MUSL_ROOT})

    if(MUSL_SHA256)
        file(DOWNLOAD
            ${MUSL_URL}
            ${MUSL_ROOT}/${MUSL_ARCHIVE_NAME}.tgz
            EXPECTED_HASH SHA256=${MUSL_SHA256}
            SHOW_PROGRESS
        )
    else()
        message(WARNING
            "MUSL_SHA256 not set — musl toolchain will not be hash-verified")
        file(DOWNLOAD
            ${MUSL_URL}
            ${MUSL_ROOT}/${MUSL_ARCHIVE_NAME}.tgz
            SHOW_PROGRESS
        )
    endif()

    execute_process(
        COMMAND ${CMAKE_COMMAND} -E tar xzf
                ${MUSL_ROOT}/${MUSL_ARCHIVE_NAME}.tgz
        WORKING_DIRECTORY ${MUSL_ROOT}
    )
endif()

# ------------------------------------------------------------
# Toolchain configuration
# ------------------------------------------------------------
set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR x86_64)

# Set the compiler and binutils stuff
set(CMAKE_C_COMPILER ${MUSL_GCC})
set(CMAKE_AR     ${MUSL_TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-gcc-ar     CACHE FILEPATH "Archiver" FORCE)
set(CMAKE_RANLIB ${MUSL_TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-gcc-ranlib CACHE FILEPATH "Ranlib"   FORCE)
set(CMAKE_LINKER ${MUSL_TOOLCHAIN_DIR}/bin/${MUSL_TRIPLE}-gcc-ld     CACHE FILEPATH "Linker"   FORCE)


# Force static
set(CMAKE_EXE_LINKER_FLAGS_INIT "-static")
set(CMAKE_SHARED_LIBRARY_LINK_C_FLAGS "")
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")

# Prevent host contamination
set(CMAKE_FIND_ROOT_PATH ${MUSL_TOOLCHAIN_DIR})
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)

# Avoid try-run when cross-compiling
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)

