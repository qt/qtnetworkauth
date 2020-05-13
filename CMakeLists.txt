# Generated from qtnetworkauth.pro.

cmake_minimum_required(VERSION 3.15.0)

project(QtNetworkAuth
    VERSION 6.0.0
    DESCRIPTION "Qt Network Auth Libraries" # special case
    HOMEPAGE_URL "https://qt.io/"
    LANGUAGES CXX C
)

find_package(Qt6 ${PROJECT_VERSION} CONFIG REQUIRED COMPONENTS BuildInternals Core Network # special case
                                           OPTIONAL_COMPONENTS Widgets) # special case

if(NOT TARGET Qt::Network)
    message(NOTICE "Skipping the build as the condition \"TARGET Qt::Network\" is not met.")
    return()
endif()
qt_build_repo()
