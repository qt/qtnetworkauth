# Copyright (C) 2024 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

if(NOT QT_BUILD_STANDALONE_TESTS AND NOT QT_BUILDING_QT)
    cmake_minimum_required(VERSION 3.16)
    project(tst_oauthurischemereplyhandler LANGUAGES CXX)
    find_package(Qt6BuildInternals REQUIRED COMPONENTS STANDALONE_TEST)
endif()

qt_internal_add_test(tst_oauthurischemereplyhandler
    SOURCES
        tst_oauthurischemereplyhandler.cpp
    LIBRARIES
        Qt::Core
        Qt::Gui
        Qt::Network
        Qt::NetworkAuth
        Qt::NetworkAuthPrivate
)
