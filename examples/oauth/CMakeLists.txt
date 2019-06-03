# Generated from oauth.pro.

find_package(Qt5 ${PROJECT_VERSION} CONFIG REQUIRED COMPONENTS Widgets)

if(TARGET Qt::Widgets)
    add_subdirectory(twittertimeline)
    add_subdirectory(redditclient)
endif()
