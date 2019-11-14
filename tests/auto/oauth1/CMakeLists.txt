# Generated from oauth1.pro.

#####################################################################
## tst_oauth1 Test:
#####################################################################

qt_add_test(tst_oauth1
    SOURCES
        ../shared/webserver.h
        tst_oauth1.cpp
    INCLUDE_DIRECTORIES
        ../shared
    LIBRARIES
        Qt::CorePrivate
        Qt::NetworkAuthPrivate
    PUBLIC_LIBRARIES
        Qt::Network
        Qt::NetworkAuth
)

#### Keys ignored in scope 1:.:.:oauth1.pro:<TRUE>:
# TEMPLATE = "app"
