# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

if(NOT QT_BUILD_STANDALONE_TESTS AND NOT QT_BUILDING_QT)
    cmake_minimum_required(VERSION 3.16)
    project(tst_oauthhttpserverreplyhandler LANGUAGES CXX)
    find_package(Qt6BuildInternals REQUIRED COMPONENTS STANDALONE_TEST)
endif()

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
