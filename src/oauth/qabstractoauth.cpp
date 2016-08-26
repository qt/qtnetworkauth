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

#include <qabstractoauth.h>
#include <qabstractoauthreplyhandler.h>

#include <private/qabstractoauth_p.h>

#include <QtCore/qurl.h>
#include <QtCore/qpair.h>
#include <QtCore/qstring.h>
#include <QtCore/qdatetime.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qmessageauthenticationcode.h>

#include <QtNetwork/qnetworkrequest.h>
#include <QtNetwork/qnetworkaccessmanager.h>

#include <random>

Q_DECLARE_METATYPE(QAbstractOAuth::Error)

QT_BEGIN_NAMESPACE

QAbstractOAuthPrivate::QAbstractOAuthPrivate(QNetworkAccessManager *manager) :
    QAbstractOAuthPrivate(QUrl(), manager)
{}

QAbstractOAuthPrivate::QAbstractOAuthPrivate(const QUrl &authorizationUrl,
                                             QNetworkAccessManager *manager) :
    authorizationUrl(authorizationUrl), defaultReplyHandler(new QOAuthOobReplyHandler),
    networkAccessManagerPointer(manager)
{}

QAbstractOAuthPrivate::~QAbstractOAuthPrivate()
{}

QNetworkAccessManager *QAbstractOAuthPrivate::networkAccessManager()
{
    Q_Q(QAbstractOAuth);
    if (!networkAccessManagerPointer)
        networkAccessManagerPointer = new QNetworkAccessManager(q);
    return networkAccessManagerPointer.data();
}

void QAbstractOAuthPrivate::setStatus(QAbstractOAuth::Status newStatus)
{
    Q_Q(QAbstractOAuth);
    if (status != newStatus) {
        status = newStatus;
        Q_EMIT q->statusChanged(status);
        if (status == QAbstractOAuth::Status::Granted)
            Q_EMIT q->granted();
    }
}

QByteArray QAbstractOAuthPrivate::generateRandomString(quint8 length)
{
    const char characters[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    static std::mt19937 randomEngine(QDateTime::currentDateTime().toMSecsSinceEpoch());
    std::uniform_int_distribution<int> distribution(0, sizeof(characters) - 2);
    QByteArray data;
    data.reserve(length);
    for (quint8 i = 0; i < length; ++i)
        data.append(characters[distribution(randomEngine)]);
    return data;
}

QUrlQuery QAbstractOAuthPrivate::createQuery(const QVariantMap &parameters)
{
    QUrlQuery query;
    for (auto it = parameters.begin(), end = parameters.end(); it != end; ++it)
        query.addQueryItem(it.key(), it.value().toString());
    return query;
}

QAbstractOAuth::QAbstractOAuth(QAbstractOAuthPrivate &dd, QObject *parent)
    : QObject(dd, parent)
{
    qRegisterMetaType<QAbstractOAuth::Error>();
}

QAbstractOAuth::~QAbstractOAuth()
{}

QNetworkAccessManager *QAbstractOAuth::networkAccessManager() const
{
    Q_D(const QAbstractOAuth);
    return d->networkAccessManagerPointer.data();
}

void QAbstractOAuth::setNetworkAccessManager(QNetworkAccessManager *networkAccessManager)
{
    Q_D(QAbstractOAuth);
    if (networkAccessManager != d->networkAccessManagerPointer) {
        if (d->networkAccessManagerPointer && d->networkAccessManagerPointer->parent() == this)
            delete d->networkAccessManagerPointer.data();
        d->networkAccessManagerPointer = networkAccessManager;
    }
}

QAbstractOAuth::Status QAbstractOAuth::status() const
{
    Q_D(const QAbstractOAuth);
    return d->status;
}

QUrl QAbstractOAuth::authorizationUrl() const
{
    Q_D(const QAbstractOAuth);
    return d->authorizationUrl;
}

void QAbstractOAuth::setAuthorizationUrl(const QUrl &url)
{
    Q_D(QAbstractOAuth);
    if (d->authorizationUrl != url) {
        d->authorizationUrl = url;
        Q_EMIT authorizationUrlChanged(url);
    }
}

void QAbstractOAuth::setStatus(QAbstractOAuth::Status status)
{
    Q_D(QAbstractOAuth);
    if (status != d->status) {
        d->status = status;
        Q_EMIT statusChanged(status);
    }
}

QAbstractOAuthReplyHandler *QAbstractOAuth::replyHandler() const
{
    Q_D(const QAbstractOAuth);
    return d->replyHandler ? d->replyHandler.data() : d->defaultReplyHandler.data();
}

void QAbstractOAuth::setReplyHandler(QAbstractOAuthReplyHandler *handler)
{
    Q_D(QAbstractOAuth);
    d->replyHandler = handler;
}

QAbstractOAuth::ModifyParametersFunction QAbstractOAuth::modifyParametersFunction() const
{
    Q_D(const QAbstractOAuth);
    return d->modifyParametersFunction;
}

void QAbstractOAuth::setModifyParametersFunction(
        const QAbstractOAuth::ModifyParametersFunction &modifyParametersFunction)
{
    Q_D(QAbstractOAuth);
    d->modifyParametersFunction = modifyParametersFunction;
}

QVariantMap QAbstractOAuth::extraTokens() const
{
    Q_D(const QAbstractOAuth);
    return d->extraTokens;
}

QString QAbstractOAuth::callback() const
{
    Q_D(const QAbstractOAuth);
    return d->replyHandler ? d->replyHandler->callback()
                           : d->defaultReplyHandler->callback();
}

void QAbstractOAuth::resourceOwnerAuthorization(const QUrl &url, const QVariantMap &parameters)
{
    QUrl u = url;
    u.setQuery(QAbstractOAuthPrivate::createQuery(parameters));
    Q_EMIT authorizeWithBrowser(u);
}

QByteArray QAbstractOAuth::generateRandomString(quint8 length)
{
    return QAbstractOAuthPrivate::generateRandomString(length);
}

QT_END_NAMESPACE

#endif // QT_NO_HTTP
