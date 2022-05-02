/****************************************************************************
**
** Copyright (C) 2022 The Qt Company Ltd.
** Contact: https://www.qt.io/licensing/
**
** This file is part of the Qt Network Auth module of the Qt Toolkit.
**
** $QT_BEGIN_LICENSE:COMM$
**
** Commercial License Usage
** Licensees holding valid commercial Qt licenses may use this file in
** accordance with the commercial license agreement provided with the
** Software or, alternatively, in accordance with the terms contained in
** a written agreement between you and The Qt Company. For licensing terms
** and conditions see https://www.qt.io/terms-conditions. For further
** information use the contact form at https://www.qt.io/contact-us.
**
** $QT_END_LICENSE$
**
**
**
**
**
**
**
**
**
******************************************************************************/

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

#ifndef QABSTRACTQOAUTH_P_H
#define QABSTRACTQOAUTH_P_H

#ifndef QT_NO_HTTP

#include <private/qobject_p.h>

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qabstractoauth.h>
#include <QtNetworkAuth/qoauthoobreplyhandler.h>

#include <QtCore/qurl.h>
#include <QtCore/qglobal.h>
#include <QtCore/qvariant.h>
#include <QtCore/qscopedpointer.h>
#include <QtCore/qloggingcategory.h>

#include <QtNetwork/qtcpserver.h>
#include <QtNetwork/qnetworkaccessmanager.h>

QT_BEGIN_NAMESPACE

class QUrlQuery;

class Q_AUTOTEST_EXPORT QAbstractOAuthPrivate : public QObjectPrivate
{
    Q_DECLARE_PUBLIC(QAbstractOAuth)

public:
    QAbstractOAuthPrivate(const char *loggingCategory,
                          const QUrl &authorizationUrl,
                          const QString &clientIdentifier,
                          QNetworkAccessManager *manager);
    ~QAbstractOAuthPrivate();

    QNetworkAccessManager *networkAccessManager();
    void setStatus(QAbstractOAuth::Status status);
    static QByteArray generateRandomString(quint8 length);

    const QLoggingCategory loggingCategory;
    QString clientIdentifier;
    QString token;

    // Resource Owner Authorization: https://tools.ietf.org/html/rfc5849#section-2.2
    QUrl authorizationUrl;
    QVariantMap extraTokens;
    QAbstractOAuth::Status status = QAbstractOAuth::Status::NotAuthenticated;
    QNetworkAccessManager::Operation operation;
    QPointer<QAbstractOAuthReplyHandler> replyHandler;
    QScopedPointer<QOAuthOobReplyHandler> defaultReplyHandler;
    QPointer<QNetworkAccessManager> networkAccessManagerPointer;
    QAbstractOAuth::ModifyParametersFunction modifyParametersFunction;
    QAbstractOAuth::ContentType contentType = QAbstractOAuth::ContentType::WwwFormUrlEncoded;

    QByteArray convertParameters(const QVariantMap &parameters);
    void addContentTypeHeaders(QNetworkRequest *request);

    static QUrlQuery createQuery(const QMultiMap<QString, QVariant> &parameters);
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QABSTRACTQOAUTH_H
