# Generated from twittertimeline.pro.

#####################################################################
## twittertimeline Binary:
#####################################################################

add_qt_executable(twittertimeline
    GUI
    OUTPUT_DIRECTORY "${INSTALL_EXAMPLESDIR}/oauth/twittertimeline"
    INSTALL_DIRECTORY "${INSTALL_EXAMPLESDIR}/oauth/twittertimeline"
    SOURCES
        main.cpp
        twitter.cpp twitter.h
        twitterdialog.ui
        twittertimelinemodel.cpp twittertimelinemodel.h
    PUBLIC_LIBRARIES
        Qt::Network
        Qt::NetworkAuth
        Qt::Widgets
    ENABLE_AUTOGEN_TOOLS
        uic
)

#### Keys ignored in scope 1:.:.:twittertimeline.pro:<TRUE>:
# CONFIG = "-app_bundle"
