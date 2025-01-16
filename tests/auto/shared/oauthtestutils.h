// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#ifndef OAUTHTESTUTILS_H
#define OAUTHTESTUTILS_H

#include <QtNetworkAuth/qoauthglobal.h>

#ifndef QT_NO_SSL
#include <QtNetwork/qsslconfiguration.h>
#endif

#include <QtCore/qcontainerfwd.h>
#include <QtCore/qscopeguard.h>
#include <QtCore/qstring.h>
#include <QtCore/qtenvironmentvariables.h>

[[nodiscard]] inline auto useTemporaryKeychain()
{
#ifndef QT_NO_SSL
    // Set the same environment value as CI uses, so that it's possible
    // to run autotests locally without macOS asking for permission to use
    // a private key in keychain (with TLS sockets)
    auto value = qEnvironmentVariable("QT_SSL_USE_TEMPORARY_KEYCHAIN");
    qputenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", "1");
    auto envRollback = qScopeGuard([value](){
        if (value.isEmpty())
            qunsetenv("QT_SSL_USE_TEMPORARY_KEYCHAIN");
        else
            qputenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", value.toUtf8());
    });
    return envRollback;
#else
    // avoid maybe-unused warnings from callers
    return qScopeGuard([]{});
#endif // QT_NO_SSL
}

QString createSignedJWT(const QVariantMap &header = {}, const QVariantMap &payload = {});

#ifndef QT_NO_SSL
QSslConfiguration createSslConfiguration(const QString &keyFileName,
                                         const QString &certificateFileName);
#endif // QT_NO_SSL

#endif // OAUTHTESTUTILS_H
