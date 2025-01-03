// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#ifndef QT_NO_HTTP

#include "qoauthoobreplyhandler.h"
#include "qabstractoauthreplyhandler_p.h"

#include <QtCore/qurlquery.h>
#include <QtCore/qjsonobject.h>
#include <QtCore/qjsondocument.h>
#include <QtCore/qloggingcategory.h>

#include <QtNetwork/qnetworkreply.h>

QT_BEGIN_NAMESPACE

QOAuthOobReplyHandler::QOAuthOobReplyHandler(QObject *parent)
    : QAbstractOAuthReplyHandler(parent)
{}

QString QOAuthOobReplyHandler::callback() const
{
    return QStringLiteral("oob");
}

void QOAuthOobReplyHandler::networkReplyFinished(QNetworkReply *reply)
{
    if (reply->error() != QNetworkReply::NoError) {
        qCWarning(lcReplyHandler, "%s", qPrintable(reply->errorString()));
        return;
    }
    if (reply->header(QNetworkRequest::ContentTypeHeader).isNull()) {
        qCWarning(lcReplyHandler, "Empty Content-type header");
        return;
    }
    const QString contentType = reply->header(QNetworkRequest::ContentTypeHeader).isNull() ?
                QStringLiteral("text/html") :
                reply->header(QNetworkRequest::ContentTypeHeader).toString();
    const QByteArray data = reply->readAll();
    if (data.isEmpty()) {
        qCWarning(lcReplyHandler, "No received data");
        return;
    }

    Q_EMIT replyDataReceived(data);

    QVariantMap ret;

    if (contentType.startsWith(QStringLiteral("text/html")) ||
            contentType.startsWith(QStringLiteral("application/x-www-form-urlencoded"))) {
        ret = parseResponse(data);
    } else if (contentType.startsWith(QStringLiteral("application/json"))
               || contentType.startsWith(QStringLiteral("text/javascript"))) {
        const QJsonDocument document = QJsonDocument::fromJson(data);
        if (!document.isObject()) {
            qCWarning(lcReplyHandler, "Received data is not a JSON object: %s",
                      qPrintable(QString::fromUtf8(data)));
            return;
        }
        const QJsonObject object = document.object();
        if (object.isEmpty()) {
            qCWarning(lcReplyHandler, "Received empty JSON object: %s",
                      qPrintable(QString::fromUtf8(data)));
        }
        ret = object.toVariantMap();
    } else {
        qCWarning(lcReplyHandler, "Unknown Content-type: %s", qPrintable(contentType));
        return;
    }

    Q_EMIT tokensReceived(ret);
}

QVariantMap QOAuthOobReplyHandler::parseResponse(const QByteArray &response)
{
    QVariantMap ret;
    QUrlQuery query(QString::fromUtf8(response));
    auto queryItems = query.queryItems(QUrl::FullyDecoded);
    for (auto it = queryItems.begin(), end = queryItems.end(); it != end; ++it)
        ret.insert(it->first, it->second);
    return ret;
}

QT_END_NAMESPACE

#include "moc_qoauthoobreplyhandler.cpp"

#endif // QT_NO_HTTP
