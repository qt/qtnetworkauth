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

#ifndef QOAUTH1SIGNATURE_H
#define QOAUTH1SIGNATURE_H

#ifndef QT_NO_HTTP

#include <QtNetworkAuth/qoauthglobal.h>

#include <QtCore/qurl.h>
#include <QtCore/qvariant.h>
#include <QtCore/qshareddata.h>

QT_BEGIN_NAMESPACE

class QUrlQuery;

class QOAuth1SignaturePrivate;
class Q_OAUTH_EXPORT QOAuth1Signature
{
public:
    enum class HttpRequestMethod {
        Head = 1,
        Get,
        Put,
        Post,
        Delete,
        Custom,

        Unknown = 0
    };

    explicit QOAuth1Signature(const QUrl &url = QUrl(),
                              HttpRequestMethod method = HttpRequestMethod::Post,
                              const QVariantMap &parameters = QVariantMap());
    QOAuth1Signature(const QUrl &url, const QString &clientSharedKey, const QString &tokenSecret,
                     HttpRequestMethod method = HttpRequestMethod::Post,
                     const QVariantMap &parameters = QVariantMap());
    QOAuth1Signature(const QOAuth1Signature &other);
    QOAuth1Signature(QOAuth1Signature &&other);
    ~QOAuth1Signature();

    HttpRequestMethod httpRequestMethod() const;
    void setHttpRequestMethod(HttpRequestMethod method);

    QByteArray customMethodString() const;
    void setCustomMethodString(const QByteArray &verb);

    QUrl url() const;
    void setUrl(const QUrl &url);

    QVariantMap parameters() const;
    void setParameters(const QVariantMap &parameters);
    void addRequestBody(const QUrlQuery &body);

    void insert(const QString &key, const QVariant &value);
    QList<QString> keys() const;
    QVariant take(const QString &key);
    QVariant value(const QString &key, const QVariant &defaultValue = QVariant()) const;

    QString clientSharedKey() const;
    void setClientSharedKey(const QString &secret);

    QString tokenSecret() const;
    void setTokenSecret(const QString &secret);

    QByteArray hmacSha1() const;
    QByteArray rsaSha1() const;
    QByteArray plainText() const;

    static QByteArray plainText(const QString &clientSharedSecret, const QString &tokenSecret);

    void swap(QOAuth1Signature &other);
    QOAuth1Signature &operator=(const QOAuth1Signature &other);
    QOAuth1Signature &operator=(QOAuth1Signature &&other);

private:
    QSharedDataPointer<QOAuth1SignaturePrivate> d;
};

QT_END_NAMESPACE

#endif // QT_NO_HTTP

#endif // QOAUTH1SIGNATURE_H
