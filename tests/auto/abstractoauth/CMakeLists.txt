# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

if(NOT QT_BUILD_STANDALONE_TESTS AND NOT QT_BUILDING_QT)
    cmake_minimum_required(VERSION 3.16)
    project(tst_abstractoauth LANGUAGES CXX)
    find_package(Qt6BuildInternals REQUIRED COMPONENTS STANDALONE_TEST)
endif()

# Generated from abstractoauth.pro.

#####################################################################
## tst_abstractoauth Test:
#####################################################################

qt_internal_add_test(tst_abstractoauth
    SOURCES
        tst_abstractoauth.cpp
    LIBRARIES
        Qt::CorePrivate
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
)

#### Keys ignored in scope 1:.:.:abstractoauth.pro:<TRUE>:
# TEMPLATE = "app"
