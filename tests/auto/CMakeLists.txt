# Copyright (C) 2022 The Qt Company Ltd.
# SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only WITH Qt-GPL-exception-1.0

# Generated from auto.pro.

# add_subdirectory(cmake) special case remove
add_subdirectory(oauth1)
add_subdirectory(oauth2)
add_subdirectory(oauth1signature)
add_subdirectory(oauthhttpserverreplyhandler)
if(QT_FEATURE_private_tests)
    add_subdirectory(abstractoauth)
endif()
