# Generated from oauth2.pro.

#####################################################################
## tst_oauth2 Test:
#####################################################################

qt_add_test(tst_oauth2
    SOURCES
        ../shared/webserver.h
        tst_oauth2.cpp
    INCLUDE_DIRECTORIES
        ../shared
    PUBLIC_LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
)

#### Keys ignored in scope 1:.:.:oauth2.pro:<TRUE>:
# TEMPLATE = "app"
