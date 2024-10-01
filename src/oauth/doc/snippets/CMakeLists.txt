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

# Check if jwt-cpp is available (it's a headers-only library => copy the project's include dir).
# Also check if we have OpenSSL, as jwt-cpp relies on it
#! [oidc-jwt-cpp-available-cmake]
find_package(OpenSSL 1.0.0 QUIET)
set(JWT_CPP_INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
if(OPENSSL_FOUND AND EXISTS "${JWT_CPP_INCLUDE_DIR}/jwt-cpp/jwt.h")
#! [oidc-jwt-cpp-available-cmake]
    message("Found OpenSSL version ${OPENSSL_VERSION}, and jwt-cpp: ${JWT_CPP_INCLUDE_DIR}")
    message("Enabling jwt-cpp support")
#! [oidc-jwt-cpp-link-and-include-cmake]
    target_include_directories(networkauth_oauth_snippets PRIVATE "${JWT_CPP_INCLUDE_DIR}")
    target_link_libraries(networkauth_oauth_snippets PRIVATE OpenSSL::SSL OpenSSL::Crypto)
    target_compile_definitions(networkauth_oauth_snippets PRIVATE JWT_CPP_AVAILABLE)
#! [oidc-jwt-cpp-link-and-include-cmake]
else()
    message("jwt-cpp support not available (check if OpenSSL and "
            "${JWT_CPP_INCLUDE_DIR}/jwt-cpp/jwt.h are available)")
endif()

qt_add_qml_module(networkauth_oauth_snippets
    URI OAuthSnippets
    VERSION 1.0
    SOURCES
        src_oauth_replyhandlers_p.h src_oauth_replyhandlers.cpp
    QML_FILES
        MainWindow.qml
)
