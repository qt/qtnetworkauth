/****************************************************************************
**
** Copyright (C) 2021 The Qt Company Ltd.
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
****************************************************************************/

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

#ifndef QOAUTH2AUTHORIZATIONCODEFLOW_P_H
#define QOAUTH2AUTHORIZATIONCODEFLOW_P_H

#ifndef QT_NO_HTTP

#include <private/qabstractoauth2_p.h>

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qoauth2authorizationcodeflow.h>

#include <QtCore/qstring.h>
#include <QtCore/qdatetime.h>

QT_BEGIN_NAMESPACE

class QOAuth2AuthorizationCodeFlowPrivate : public QAbstractOAuth2Private
{
    Q_DECLARE_PUBLIC(QOAuth2AuthorizationCodeFlow)

public:
    QOAuth2AuthorizationCodeFlowPrivate(const QUrl &authorizationUrl,
                                        const QUrl &accessTokenUrl,
                                        const QString &clientIdentifier,
                                        QNetworkAccessManager *manager = nullptr);

    void _q_handleCallback(const QVariantMap &data);
    void _q_accessTokenRequestFinished(const QVariantMap &values);
    void _q_authenticate(QNetworkReply *reply, QAuthenticator *authenticator);

    QUrl accessTokenUrl;
    QString tokenType;
    QPointer<QNetworkReply> currentReply;
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QOAUTH2AUTHORIZATIONCODEFLOW_P_H
