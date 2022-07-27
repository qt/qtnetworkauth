# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0

# Generated from oauth2.pro.

#####################################################################
## tst_oauth2 Test:
#####################################################################

qt_internal_add_test(tst_oauth2
    SOURCES
        ../shared/webserver.h
        tst_oauth2.cpp
    INCLUDE_DIRECTORIES
        ../shared
    LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
)

#### Keys ignored in scope 1:.:.:oauth2.pro:<TRUE>:
# TEMPLATE = "app"
