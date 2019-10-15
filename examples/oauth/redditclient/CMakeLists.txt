# Generated from redditclient.pro.

cmake_minimum_required(VERSION 3.14)
project(redditclient LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(INSTALL_EXAMPLEDIR "examples/oauth/redditclient")

find_package(Qt6 COMPONENTS Core)
find_package(Qt6 COMPONENTS Gui)
find_package(Qt6 COMPONENTS Widgets)
find_package(Qt6 COMPONENTS Network)
find_package(Qt6 COMPONENTS NetworkAuth)

add_qt_gui_executable(redditclient
    main.cpp
    redditmodel.cpp redditmodel.h
    redditwrapper.cpp redditwrapper.h
)
target_link_libraries(redditclient PUBLIC
    Qt::Core
    Qt::Gui
    Qt::Network
    Qt::NetworkAuth
    Qt::Widgets
)

install(TARGETS redditclient
    RUNTIME DESTINATION "${INSTALL_EXAMPLEDIR}"
    BUNDLE DESTINATION "${INSTALL_EXAMPLEDIR}"
    LIBRARY DESTINATION "${INSTALL_EXAMPLEDIR}"
)
