/****************************************************************************
**
** Copyright (C) 2016 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the QtNetwork module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:LGPL$
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** GNU Lesser General Public License Usage
** Alternatively, this file may be used under the terms of the GNU Lesser
** General Public License version 3 as published by the Free Software
** Foundation and appearing in the file LICENSE.LGPL3 included in the
** packaging of this file. Please review the following information to
** ensure the GNU Lesser General Public License version 3 requirements
** will be met: https://www.gnu.org/licenses/lgpl-3.0.html.
**
** GNU General Public License Usage
** Alternatively, this file may be used under the terms of the GNU
** General Public License version 2.0 or (at your option) the GNU General
** Public license version 3 or any later version approved by the KDE Free
** Qt Foundation. The licenses are as published by the Free Software
** Foundation and appearing in the file LICENSE.GPL2 and LICENSE.GPL3
** included in the packaging of this file. Please review the following
** information to ensure the GNU General Public License requirements will
** be met: https://www.gnu.org/licenses/gpl-2.0.html and
** https://www.gnu.org/licenses/gpl-3.0.html.
**
** $QT_END_LICENSE$
**
****************************************************************************/

#ifndef QT_NO_HTTP

#include <qabstractoauth2.h>
#include <private/qabstractoauth2_p.h>

#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qbytearray.h>
#include <QtCore/qmessageauthenticationcode.h>

#include <QtNetwork/qnetworkreply.h>
#include <QtNetwork/qnetworkrequest.h>
#include <QtNetwork/qnetworkaccessmanager.h>

QT_BEGIN_NAMESPACE

using Key = QAbstractOAuth2Private::OAuth2KeyString;
const QString Key::accessToken =        QStringLiteral("access_token");
const QString Key::apiKey =             QStringLiteral("api_key");
const QString Key::clientIdentifier =   QStringLiteral("client_id");
const QString Key::clientSharedSecret = QStringLiteral("client_secret");
const QString Key::code =               QStringLiteral("code");
const QString Key::error =              QStringLiteral("error");
const QString Key::errorDescription =   QStringLiteral("error_description");
const QString Key::errorUri =           QStringLiteral("error_uri");
const QString Key::expiresIn =          QStringLiteral("expires_in");
const QString Key::grantType =          QStringLiteral("grant_type");
const QString Key::redirectUri =        QStringLiteral("redirect_uri");
const QString Key::refreshToken =       QStringLiteral("refresh_token");
const QString Key::responseType =       QStringLiteral("response_type");
const QString Key::scope =              QStringLiteral("scope");
const QString Key::state =              QStringLiteral("state");
const QString Key::tokenType =          QStringLiteral("token_type");

QAbstractOAuth2Private::QAbstractOAuth2Private(const QPair<QString, QString> &clientCredentials,
                                               const QUrl &authorizationUrl,
                                               QNetworkAccessManager *manager) :
    QAbstractOAuthPrivate(authorizationUrl, manager), clientCredentials(clientCredentials)
{}

QAbstractOAuth2Private::QAbstractOAuth2Private(QNetworkAccessManager *manager) :
    QAbstractOAuthPrivate(authorizationUrl, manager)
{}

QAbstractOAuth2Private::~QAbstractOAuth2Private()
{}

QString QAbstractOAuth2Private::generateRandomState()
{
    return QString::fromUtf8(QAbstractOAuthPrivate::generateRandomString(8));
}

QNetworkRequest QAbstractOAuth2Private::createRequest(const QUrl &url, const QVariantMap &parameters)
{
    QUrlQuery query(url.query());

    for (auto it = parameters.begin(), end = parameters.end(); it != end; ++it)
        query.addQueryItem(it.key(), it.value().toString());

    QUrl u(url);
    u.setQuery(query);

    QNetworkRequest request(u);
    request.setHeader(QNetworkRequest::UserAgentHeader, userAgent);
    const QString bearer = bearerFormat.arg(token);
    request.setRawHeader("Authorization", bearer.toUtf8());
    return request;
}

QAbstractOAuth2::QAbstractOAuth2(QObject *parent) :
    QAbstractOAuth2(nullptr, parent)
{}

QAbstractOAuth2::QAbstractOAuth2(QNetworkAccessManager *manager, QObject *parent) :
    QAbstractOAuth(*new QAbstractOAuth2Private(manager), parent)
{}

QAbstractOAuth2::QAbstractOAuth2(QAbstractOAuth2Private &dd, QObject *parent) :
    QAbstractOAuth(dd, parent)
{}

QAbstractOAuth2::~QAbstractOAuth2()
{}

QUrl QAbstractOAuth2::createAuthenticatedUrl(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(const QAbstractOAuth2);
    if (Q_UNLIKELY(d->token.isEmpty())) {
        qWarning("QAbstractOAuth2::createAuthenticatedUrl: Empty access token");
        return QUrl();
    }
    QUrl ret = url;
    QUrlQuery query(ret.query());
    query.addQueryItem(Key::accessToken, d->token);
    for (auto it = parameters.begin(), end = parameters.end(); it != end ;++it)
        query.addQueryItem(it.key(), it.value().toString());
    ret.setQuery(query);
    return ret;
}

QNetworkReply *QAbstractOAuth2::head(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->head(d->createRequest(url, parameters));
    connect(reply, &QNetworkReply::finished, std::bind(&QAbstractOAuth::finished, this, reply));
    return reply;
}

QNetworkReply *QAbstractOAuth2::get(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->get(
                d->createRequest(url, parameters));
    connect(reply, &QNetworkReply::finished, std::bind(&QAbstractOAuth::finished, this, reply));
    return reply;
}

QNetworkReply *QAbstractOAuth2::post(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->post(
                d->createRequest(url, parameters), QByteArray());
    connect(reply, &QNetworkReply::finished, std::bind(&QAbstractOAuth::finished, this, reply));
    return reply;
}

QNetworkReply *QAbstractOAuth2::deleteResource(const QUrl &url, const QVariantMap &parameters)
{
    Q_D(QAbstractOAuth2);
    QNetworkReply *reply = d->networkAccessManager()->deleteResource(
                d->createRequest(url, parameters));
    connect(reply, &QNetworkReply::finished, std::bind(&QAbstractOAuth::finished, this, reply));
    return reply;
}

QString QAbstractOAuth2::scope() const
{
    Q_D(const QAbstractOAuth2);
    return d->scope;
}

void QAbstractOAuth2::setScope(const QString &scope)
{
    Q_D(QAbstractOAuth2);
    if (d->scope != scope) {
        d->scope = scope;
        Q_EMIT scopeChanged(scope);
    }
}

QString QAbstractOAuth2::userAgent() const
{
    Q_D(const QAbstractOAuth2);
    return d->userAgent;
}

void QAbstractOAuth2::setUserAgent(const QString &userAgent)
{
    Q_D(QAbstractOAuth2);
    if (d->userAgent != userAgent) {
        d->userAgent = userAgent;
        Q_EMIT userAgentChanged(userAgent);
    }
}

QString QAbstractOAuth2::clientIdentifier() const
{
    Q_D(const QAbstractOAuth2);
    return d->clientCredentials.first;
}

void QAbstractOAuth2::setClientIdentifier(const QString &clientIdentifier)
{
    Q_D(QAbstractOAuth2);
    if (d->clientCredentials.first != clientIdentifier) {
        d->clientCredentials.first = clientIdentifier;
        Q_EMIT clientIdentifierChanged(clientIdentifier);
    }
}

QString QAbstractOAuth2::clientIdentifierSharedKey() const
{
    Q_D(const QAbstractOAuth2);
    return d->clientCredentials.second;
}

void QAbstractOAuth2::setClientIdentifierSharedKey(const QString &clientIdentifierSharedKey)
{
    Q_D(QAbstractOAuth2);
    if (d->clientCredentials.second != clientIdentifierSharedKey) {
        d->clientCredentials.second = clientIdentifierSharedKey;
        Q_EMIT clientIdentifierSharedKeyChanged(clientIdentifierSharedKey);
    }
}

QString QAbstractOAuth2::token() const
{
    Q_D(const QAbstractOAuth2);
    return d->token;
}

void QAbstractOAuth2::setToken(const QString &token)
{
    Q_D(QAbstractOAuth2);
    if (d->token != token) {
        d->token = token;
        Q_EMIT tokenChanged(token);
    }
}

QString QAbstractOAuth2::state() const
{
    Q_D(const QAbstractOAuth2);
    return d->state;
}

void QAbstractOAuth2::setState(const QString &state)
{
    Q_D(QAbstractOAuth2);
    if (state != d->state) {
        d->state = state;
        Q_EMIT stateChanged(state);
    }
}

QDateTime QAbstractOAuth2::expirationAt() const
{
    Q_D(const QAbstractOAuth2);
    return d->expiresAt;
}

QT_END_NAMESPACE

#endif // QT_NO_HTTP
