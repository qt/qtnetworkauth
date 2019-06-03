# Generated from oauth2.pro.

#####################################################################
## tst_oauth2 Test:
#####################################################################

add_qt_test(tst_oauth2
    SOURCES
        ../shared/webserver.h
        tst_oauth2.cpp
    INCLUDE_DIRECTORIES
        ../shared
    LIBRARIES
        Qt::CorePrivate
        Qt::NetworkAuthPrivate
    PUBLIC_LIBRARIES
        Qt::Network
        Qt::NetworkAuth
)

#### Keys ignored in scope 1:.:.:oauth2.pro:<TRUE>:
# CONFIG = "testcase"
# TEMPLATE = "app"
