# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

if(NOT QT_BUILD_STANDALONE_TESTS AND NOT QT_BUILDING_QT)
    cmake_minimum_required(VERSION 3.16)
    project(tst_oauth1 LANGUAGES CXX)
    find_package(Qt6BuildInternals REQUIRED COMPONENTS STANDALONE_TEST)
endif()

# Generated from oauth1.pro.

#####################################################################
## tst_oauth1 Test:
#####################################################################

qt_internal_add_test(tst_oauth1
    SOURCES
        ../shared/webserver.h ../shared/webserver.cpp
        tst_oauth1.cpp
    INCLUDE_DIRECTORIES
        ../shared
    LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
)

#### Keys ignored in scope 1:.:.:oauth1.pro:<TRUE>:
# TEMPLATE = "app"
