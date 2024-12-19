// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#ifndef QOAUTH2DEVICEAUTHORIZATIONFLOW_H
#define QOAUTH2DEVICEAUTHORIZATIONFLOW_H

#ifndef QT_NO_HTTP

#include <QtNetworkAuth/qoauthglobal.h>
#include <QtNetworkAuth/qabstractoauth2.h>

#include <QtCore/qdatetime.h>

QT_BEGIN_NAMESPACE

class QUrl;
class QString;
class QNetworkAccessManager;

class QOAuth2DeviceAuthorizationFlowPrivate;
class Q_OAUTH_EXPORT QOAuth2DeviceAuthorizationFlow : public QAbstractOAuth2
{
    Q_OBJECT
    Q_PROPERTY(QString userCode READ userCode NOTIFY userCodeChanged FINAL)
    Q_PROPERTY(QUrl verificationUrl READ verificationUrl NOTIFY verificationUrlChanged FINAL)
    Q_PROPERTY(QUrl completeVerificationUrl READ completeVerificationUrl
               NOTIFY completeVerificationUrlChanged FINAL)
    Q_PROPERTY(bool polling READ isPolling NOTIFY pollingChanged FINAL)
    Q_PROPERTY(QDateTime userCodeExpirationAt READ userCodeExpirationAt
               NOTIFY userCodeExpirationAtChanged FINAL)

public:
    QOAuth2DeviceAuthorizationFlow();
    explicit QOAuth2DeviceAuthorizationFlow(QObject *parent);
    explicit QOAuth2DeviceAuthorizationFlow(QNetworkAccessManager *manager,
                                            QObject *parent = nullptr);
    ~QOAuth2DeviceAuthorizationFlow() override;

    QString userCode() const;
    QUrl verificationUrl() const;
    QUrl completeVerificationUrl() const;
    bool isPolling() const;
    QDateTime userCodeExpirationAt() const;

public Q_SLOTS:
    void grant() override;
#if QT_VERSION < QT_VERSION_CHECK(7, 0, 0)
    void refreshAccessToken();
#else
    void refreshTokens() override;
#endif
    bool startTokenPolling();
    void stopTokenPolling();

Q_SIGNALS:
    void authorizeWithUserCode(const QUrl &verificationUrl, const QString &userCode,
                               const QUrl &completeVerificationUrl);
    void userCodeChanged(const QString &userCode);
    void verificationUrlChanged(const QUrl &verificationUrl);
    void completeVerificationUrlChanged(const QUrl &completeVerificationUrl);
    void pollingChanged(bool polling);
    void userCodeExpirationAtChanged(const QDateTime &expiration);

protected:
    bool event(QEvent *event) override;

private:
    Q_DISABLE_COPY_MOVE(QOAuth2DeviceAuthorizationFlow)
    Q_DECLARE_PRIVATE(QOAuth2DeviceAuthorizationFlow)
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QOAUTH2DEVICEAUTHORIZATIONFLOW_H
