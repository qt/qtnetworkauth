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

#ifndef QOAUTHOOBREPLYHANDLER_H
#define QOAUTHOOBREPLYHANDLER_H

#ifndef QT_NO_HTTP

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qabstractoauthreplyhandler.h>

QT_BEGIN_NAMESPACE

class Q_OAUTH_EXPORT QOAuthOobReplyHandler : public QAbstractOAuthReplyHandler
{
    Q_OBJECT

public:
    explicit QOAuthOobReplyHandler(QObject *parent = nullptr);

    QString callback() const override;

protected:
    void networkReplyFinished(QNetworkReply *reply) override;

private:
    QVariantMap parseResponse(const QByteArray &response);
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QOAUTHOOBREPLYHANDLER_H
