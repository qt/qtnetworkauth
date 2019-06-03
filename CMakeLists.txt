cmake_minimum_required(VERSION 3.14.0)

project(QtNetworkAuth
    VERSION 5.14.0
    DESCRIPTION "Qt Network Auth Libraries"
    HOMEPAGE_URL "https://qt.io/"
    LANGUAGES CXX C
)

find_package(Qt5 ${PROJECT_VERSION} CONFIG REQUIRED COMPONENTS BuildInternals Core Network)

qt_build_repo()
