# Generated from twittertimeline.pro.

cmake_minimum_required(VERSION 3.14)
project(twittertimeline LANGUAGES CXX)

set(CMAKE_INCLUDE_CURRENT_DIR ON)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

set(INSTALL_EXAMPLEDIR "examples/oauth/twittertimeline")

find_package(Qt6 COMPONENTS Core)
find_package(Qt6 COMPONENTS Widgets)
find_package(Qt6 COMPONENTS Network)
find_package(Qt6 COMPONENTS NetworkAuth)

add_qt_gui_executable(twittertimeline
    main.cpp
    twitter.cpp twitter.h
    twitterdialog.ui
    twittertimelinemodel.cpp twittertimelinemodel.h
)
target_link_libraries(twittertimeline PUBLIC
    Qt::Core
    Qt::Network
    Qt::NetworkAuth
    Qt::Widgets
)

install(TARGETS twittertimeline
    RUNTIME DESTINATION "${INSTALL_EXAMPLEDIR}"
    BUNDLE DESTINATION "${INSTALL_EXAMPLEDIR}"
    LIBRARY DESTINATION "${INSTALL_EXAMPLEDIR}"
)
