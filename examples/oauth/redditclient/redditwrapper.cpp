// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR BSD-3-Clause

#include "redditwrapper.h"

#include <QtGui>
#include <QtCore>
#include <QtNetworkAuth>

const QUrl newUrl("https://oauth.reddit.com/new");
const QUrl hotUrl("https://oauth.reddit.com/hot");
const QUrl liveThreadsUrl("https://oauth.reddit.com/live/XXXX/about.json");

RedditWrapper::RedditWrapper(QObject *parent) : QObject(parent)
{
    auto replyHandler = new QOAuthHttpServerReplyHandler(1337, this);
    oauth2.setReplyHandler(replyHandler);
    oauth2.setAuthorizationUrl(QUrl("https://www.reddit.com/api/v1/authorize"));
    oauth2.setAccessTokenUrl(QUrl("https://www.reddit.com/api/v1/access_token"));
    oauth2.setScope("identity read");

    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::statusChanged, [=](
            QAbstractOAuth::Status status) {
        if (status == QAbstractOAuth::Status::Granted)
            emit authenticated();
    });
    oauth2.setModifyParametersFunction([&](QAbstractOAuth::Stage stage, QMultiMap<QString, QVariant> *parameters) {
        if (stage == QAbstractOAuth::Stage::RequestingAuthorization && isPermanent())
            parameters->insert("duration", "permanent");
    });
    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            &QDesktopServices::openUrl);
}

RedditWrapper::RedditWrapper(const QString &clientIdentifier, QObject *parent) :
    RedditWrapper(parent)
{
    oauth2.setClientIdentifier(clientIdentifier);
}

QNetworkReply *RedditWrapper::requestHotThreads()
{
    qDebug() << "Getting hot threads...";
    return oauth2.get(hotUrl);
}

bool RedditWrapper::isPermanent() const
{
    return permanent;
}

void RedditWrapper::setPermanent(bool value)
{
    permanent = value;
}

void RedditWrapper::grant()
{
    oauth2.grant();
}

void RedditWrapper::subscribeToLiveUpdates()
{
    qDebug() << "Susbscribing...";
    QNetworkReply *reply = oauth2.get(liveThreadsUrl);
    connect(reply, &QNetworkReply::finished, [=]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            qCritical() << "Reddit error:" << reply->errorString();
            return;
        }

        const auto json = reply->readAll();

        const auto document = QJsonDocument::fromJson(json);
        Q_ASSERT(document.isObject());
        const auto rootObject = document.object();
        const auto dataValue = rootObject.value("data");
        Q_ASSERT(dataValue.isObject());
        const auto dataObject = dataValue.toObject();
        const auto websocketUrlValue = dataObject.value("websocket_url");
        Q_ASSERT(websocketUrlValue.isString() && websocketUrlValue.toString().size());
        const QUrl websocketUrl(websocketUrlValue.toString());
        emit subscribed(websocketUrl);
    });
}
