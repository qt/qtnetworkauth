# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

# Generated from oauth2.pro.

#####################################################################
## tst_oauth2 Test:
#####################################################################

list(APPEND test_data "../shared/certs")

qt_internal_add_test(tst_oauth2
    SOURCES
        ../shared/webserver.h
        ../shared/tlswebserver.h
        ../shared/oauthtestutils.h ../shared/oauthtestutils.cpp
        tst_oauth2.cpp
    INCLUDE_DIRECTORIES
        ../shared
    LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
    TESTDATA ${test_data}
)

#### Keys ignored in scope 1:.:.:oauth2.pro:<TRUE>:
# TEMPLATE = "app"
