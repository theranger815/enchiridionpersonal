# ------------------------------------------------------------
# Encryption dependencies
# WolfSSL is used directly by enchiridion for payload crypto.
# wolfssl.cmake is guarded, so safe to include even if http C2
# already pulled it in.
# ------------------------------------------------------------
include(${CMAKE_SOURCE_DIR}/cmake/wolfssl.cmake)
