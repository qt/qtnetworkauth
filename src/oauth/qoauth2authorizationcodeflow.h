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

#ifndef QOAUTH2AUTHORIZATIONCODEFLOW_H
#define QOAUTH2AUTHORIZATIONCODEFLOW_H

#ifndef QT_NO_HTTP

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qabstractoauth2.h>

QT_BEGIN_NAMESPACE

class QUrl;
class QString;
class QNetworkAccessManager;

class QOAuth2AuthorizationCodeFlowPrivate;
class Q_OAUTH_EXPORT QOAuth2AuthorizationCodeFlow : public QAbstractOAuth2
{
    Q_OBJECT
    Q_PROPERTY(QUrl accessTokenUrl
               READ accessTokenUrl
               WRITE setAccessTokenUrl
               NOTIFY accessTokenUrlChanged)

public:
    explicit QOAuth2AuthorizationCodeFlow(QObject *parent = nullptr);
    explicit QOAuth2AuthorizationCodeFlow(QNetworkAccessManager *manager,
                                          QObject *parent = nullptr);

    QOAuth2AuthorizationCodeFlow(const QString &clientIdentifier,
                                 QNetworkAccessManager *manager,
                                 QObject *parent = nullptr);

    QOAuth2AuthorizationCodeFlow(const QUrl &authorizationUrl,
                                 const QUrl &accessTokenUrl,
                                 QNetworkAccessManager *manager,
                                 QObject *parent = nullptr);

    QOAuth2AuthorizationCodeFlow(const QString &clientIdentifier,
                                 const QUrl &authorizationUrl,
                                 const QUrl &accessTokenUrl,
                                 QNetworkAccessManager *manager,
                                 QObject *parent = nullptr);

    ~QOAuth2AuthorizationCodeFlow();

    QUrl accessTokenUrl() const;
    void setAccessTokenUrl(const QUrl &accessTokenUrl);

public Q_SLOTS:
    void grant() override;
    void refreshAccessToken();

protected:
    QUrl buildAuthenticateUrl(const QMultiMap<QString, QVariant> &parameters = {});
    void requestAccessToken(const QString &code);
    void resourceOwnerAuthorization(const QUrl &url,
                                    const QMultiMap<QString, QVariant> &parameters = {}) override;

Q_SIGNALS:
    void accessTokenUrlChanged(const QUrl &accessTokenUrl);

private:
    Q_DISABLE_COPY(QOAuth2AuthorizationCodeFlow)
    Q_DECLARE_PRIVATE(QOAuth2AuthorizationCodeFlow)
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QOAUTH2AUTHORIZATIONCODEFLOW_H
