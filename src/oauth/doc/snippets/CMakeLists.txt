# Copyright (C) 2024 The Qt Company Ltd.
# SPDX-License-Identifier: LicenseRef-Qt-Commercial OR BSD-3-Clause

cmake_minimum_required(VERSION 3.16)

project(networkauth_oauth_snippets)

find_package(Qt6 REQUIRED COMPONENTS Core NetworkAuth Gui Quick WebEngineWidgets WebEngineQuick)

qt_standard_project_setup(REQUIRES 6.9)

add_executable(networkauth_oauth_snippets
    main.cpp
    src_oauth_replyhandlers_p.h src_oauth_replyhandlers.cpp
)

set_target_properties(networkauth_oauth_snippets PROPERTIES
    WIN32_EXECUTABLE TRUE
    MACOSX_BUNDLE TRUE
)

target_link_libraries(networkauth_oauth_snippets
    PRIVATE
        Qt6::Core
        Qt6::NetworkAuth
        Qt6::Gui
        Qt6::Quick
        Qt6::WebEngineWidgets
        Qt6::WebEngineQuick
)

qt_add_qml_module(networkauth_oauth_snippets
    URI OAuthSnippets
    VERSION 1.0
    SOURCES
        src_oauth_replyhandlers_p.h src_oauth_replyhandlers.cpp
    QML_FILES
        MainWindow.qml
)
