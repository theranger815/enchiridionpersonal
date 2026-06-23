# ------------------------------------------------------------
# WebSocket C2: wolfSSL only.
# The WebSocket protocol is implemented directly in src/c2/websocket.c
# (TCP connect → TLS → HTTP Upgrade → WebSocket framing) so there is no
# dependency on libwebsockets.  ext::websocket is a thin alias for ext::wolfssl.
# ------------------------------------------------------------
if(TARGET ext::websocket)
    return()
endif()

include(${CMAKE_SOURCE_DIR}/cmake/wolfssl.cmake)

add_library(ext::websocket INTERFACE IMPORTED GLOBAL)
set_property(TARGET ext::websocket PROPERTY
    INTERFACE_LINK_LIBRARIES ext::wolfssl
)
