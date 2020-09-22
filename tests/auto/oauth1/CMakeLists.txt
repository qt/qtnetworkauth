# Generated from oauth1.pro.

#####################################################################
## tst_oauth1 Test:
#####################################################################

qt_internal_add_test(tst_oauth1
    SOURCES
        ../shared/webserver.h
        tst_oauth1.cpp
    INCLUDE_DIRECTORIES
        ../shared
    PUBLIC_LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
)

#### Keys ignored in scope 1:.:.:oauth1.pro:<TRUE>:
# TEMPLATE = "app"
