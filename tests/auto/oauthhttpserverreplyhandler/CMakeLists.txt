# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

# Generated from oauthhttpserverreplyhandler.pro.

#####################################################################
## tst_oauthhttpserverreplyhandler Test:
#####################################################################

list(APPEND test_data "../shared/certs")

qt_internal_add_test(tst_oauthhttpserverreplyhandler
    SOURCES
        ../shared/webserver.h ../shared/webserver.cpp
        tst_oauthhttpserverreplyhandler.cpp
    INCLUDE_DIRECTORIES
        ../shared
    LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
    TESTDATA ${test_data}
)

#### Keys ignored in scope 1:.:.:oauthhttpserverreplyhandler.pro:<TRUE>:
# TEMPLATE = "app"
