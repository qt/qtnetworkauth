# Generated from redditclient.pro.

#####################################################################
## redditclient Binary:
#####################################################################

add_qt_executable(redditclient
    GUI
    OUTPUT_DIRECTORY "${INSTALL_EXAMPLESDIR}/oauth/redditclient"
    INSTALL_DIRECTORY "${INSTALL_EXAMPLESDIR}/oauth/redditclient"
    SOURCES
        main.cpp
        redditmodel.cpp redditmodel.h
        redditwrapper.cpp redditwrapper.h
    PUBLIC_LIBRARIES
        Qt::Network
        Qt::NetworkAuth
        Qt::Widgets
)
