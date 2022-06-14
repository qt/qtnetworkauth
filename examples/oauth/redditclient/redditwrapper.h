// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR BSD-3-Clause

#ifndef REDDITWRAPPER_H
#define REDDITWRAPPER_H

#include <QtCore>
#include <QtNetwork>

#include <QOAuth2AuthorizationCodeFlow>

class RedditWrapper : public QObject
{
    Q_OBJECT

public:
    RedditWrapper(QObject *parent = nullptr);
    RedditWrapper(const QString &clientIdentifier, QObject *parent = nullptr);

    QNetworkReply *requestHotThreads();

    bool isPermanent() const;
    void setPermanent(bool value);

public slots:
    void grant();
    void subscribeToLiveUpdates();

signals:
    void authenticated();
    void subscribed(const QUrl &url);

private:
    QOAuth2AuthorizationCodeFlow oauth2;
    bool permanent = false;
};

#endif // REDDITWRAPPER_H
