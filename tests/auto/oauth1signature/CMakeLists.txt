# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: BSD-3-Clause

if(NOT QT_BUILD_STANDALONE_TESTS AND NOT QT_BUILDING_QT)
    cmake_minimum_required(VERSION 3.16)
    project(tst_oauth1signature LANGUAGES CXX)
    find_package(Qt6BuildInternals REQUIRED COMPONENTS STANDALONE_TEST)
endif()

# Generated from oauth1signature.pro.

#####################################################################
## tst_oauth1signature Test:
#####################################################################

qt_internal_add_test(tst_oauth1signature
    SOURCES
        tst_oauth1signature.cpp
    LIBRARIES
        Qt::CorePrivate
        Qt::NetworkAuth
)

#### Keys ignored in scope 1:.:.:oauth1signature.pro:<TRUE>:
# TEMPLATE = "app"
