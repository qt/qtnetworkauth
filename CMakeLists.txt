cmake_minimum_required(VERSION 3.15.0)

project(QtNetworkAuth
    VERSION 6.0.0
    DESCRIPTION "Qt Network Auth Libraries"
    HOMEPAGE_URL "https://qt.io/"
    LANGUAGES CXX C
)

find_package(Qt6 ${PROJECT_VERSION} CONFIG REQUIRED COMPONENTS BuildInternals Core Network)

qt_build_repo()
