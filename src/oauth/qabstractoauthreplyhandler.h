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

#ifndef QABSTRACTOAUTHREPLYHANDLER_H
#define QABSTRACTOAUTHREPLYHANDLER_H

#ifndef QT_NO_HTTP

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qabstractoauth.h>

#include <QtCore/qobject.h>

QT_BEGIN_NAMESPACE

class Q_OAUTH_EXPORT QAbstractOAuthReplyHandler : public QObject
{
    Q_OBJECT

public:
    explicit QAbstractOAuthReplyHandler(QObject *parent = nullptr);
    virtual ~QAbstractOAuthReplyHandler();

    virtual QString callback() const = 0;

public Q_SLOTS:
    virtual void networkReplyFinished(QNetworkReply *reply) = 0;

Q_SIGNALS:
    void callbackReceived(const QVariantMap &values);
    void tokensReceived(const QVariantMap &tokens);

    void replyDataReceived(const QByteArray &data);
    void callbackDataReceived(const QByteArray &data);

protected:
    QAbstractOAuthReplyHandler(QObjectPrivate &d, QObject *parent = nullptr);

private:
    Q_DISABLE_COPY(QAbstractOAuthReplyHandler)
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QABSTRACTOAUTHREPLYHANDLER_H
