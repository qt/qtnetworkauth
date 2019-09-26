# Generated from abstractoauth.pro.

#####################################################################
## tst_abstractoauth Test:
#####################################################################

add_qt_test(tst_abstractoauth
    SOURCES
        tst_abstractoauth.cpp
    LIBRARIES
        Qt::CorePrivate
        Qt::NetworkAuthPrivate
    PUBLIC_LIBRARIES
        Qt::Network
        Qt::NetworkAuth
)

#### Keys ignored in scope 1:.:.:abstractoauth.pro:<TRUE>:
# TEMPLATE = "app"
