# Generated from auto.pro.

## Currently doesn't build
#add_subdirectory(cmake)
add_subdirectory(oauth1)
add_subdirectory(oauth2)
add_subdirectory(oauth1signature)
add_subdirectory(oauthhttpserverreplyhandler)

if(QT_FEATURE_private_tests)
    add_subdirectory(abstractoauth)
endif()
