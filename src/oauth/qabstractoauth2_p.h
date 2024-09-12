// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

//
//  W A R N I N G
//  -------------
//
// This file is not part of the Qt API.  It exists for the convenience
// of the Network Access API.  This header file may change from
// version to version without notice, or even be removed.
//
// We mean it.
//

#ifndef QABSTRACTOAUTH2_P_H
#define QABSTRACTOAUTH2_P_H

#ifndef QT_NO_HTTP

#include <optional>

#include <private/qabstractoauth_p.h>

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qabstractoauth2.h>

#include <QtCore/qurl.h>
#include <QtCore/qstring.h>
#include <QtCore/qpointer.h>

#include <QtNetwork/qnetworkreply.h>

QT_BEGIN_NAMESPACE

class QNetworkAccessManager;

class QAbstractOAuth2Private : public QAbstractOAuthPrivate
{
    Q_DECLARE_PUBLIC(QAbstractOAuth2)

public:
    QAbstractOAuth2Private(const QPair<QString, QString> &clientCredentials,
                           const QUrl &authorizationUrl, QNetworkAccessManager *manager = nullptr);
    ~QAbstractOAuth2Private();

    void setGrantedScope(const QStringList &scope);
    static QString generateRandomState();
    static QString generateNonce();
    QNetworkRequest createRequest(QUrl url, const QVariantMap *parameters = nullptr);
    bool authorizationShouldIncludeNonce() const;

    QString clientIdentifierSharedKey;
#if QT_DEPRECATED_SINCE(6, 11)
    QString scope;
#endif
    QStringList requestedScope;
    QStringList grantedScope;
    QString state = generateRandomState();
    QString userAgent = QStringLiteral("QtOAuth/1.0 (+https://www.qt.io)");
    QString responseType;
    const QString bearerFormat = QStringLiteral("Bearer %1"); // Case sensitive
    QDateTime expiresAt;
    QString refreshToken;
    QAbstractOAuth2::NonceMode nonceMode = QAbstractOAuth2::NonceMode::Automatic;
    QString nonce;
#ifndef QT_NO_SSL
    std::optional<QSslConfiguration> sslConfiguration;
#endif

    struct OAuth2KeyString
    {
        static const QString accessToken;
        static const QString apiKey;
        static const QString clientIdentifier;
        static const QString clientSharedSecret;
        static const QString code;
        static const QString error;
        static const QString errorDescription;
        static const QString errorUri;
        static const QString expiresIn;
        static const QString grantType;
        static const QString redirectUri;
        static const QString refreshToken;
        static const QString responseType;
        static const QString scope;
        static const QString state;
        static const QString tokenType;
        static const QString codeVerifier;
        static const QString codeChallenge;
        static const QString codeChallengeMethod;
        static const QString nonce;
    };
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QABSTRACTOAUTH2_P_H
