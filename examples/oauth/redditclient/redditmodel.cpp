// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR BSD-3-Clause

#include "redditmodel.h"

#include <QtCore>
#include <QtNetwork>

RedditModel::RedditModel(QObject *parent) : QAbstractTableModel(parent) {}

RedditModel::RedditModel(const QString &clientId, QObject *parent) :
    QAbstractTableModel(parent),
    redditWrapper(clientId)
{
    grant();
}

int RedditModel::rowCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return threads.size();
}

int RedditModel::columnCount(const QModelIndex &parent) const
{
    Q_UNUSED(parent);
    return threads.size() ? 1 : 0;
}

QVariant RedditModel::data(const QModelIndex &index, int role) const
{
    Q_UNUSED(role);
    if (!index.isValid())
        return QVariant();

    if (role == Qt::DisplayRole) {
        const auto childrenObject = threads.at(index.row());
        Q_ASSERT(childrenObject.value("data").isObject());
        const auto dataObject = childrenObject.value("data").toObject();
        return dataObject.value("title").toString();
    }
    return QVariant();
}

void RedditModel::grant()
{
    redditWrapper.grant();
    connect(&redditWrapper, &RedditWrapper::authenticated, this, &RedditModel::update);
}

void RedditModel::update()
{
    auto reply = redditWrapper.requestHotThreads();

    connect(reply, &QNetworkReply::finished, [=]() {
        reply->deleteLater();
        if (reply->error() != QNetworkReply::NoError) {
            emit error(reply->errorString());
            return;
        }
        const auto json = reply->readAll();
        const auto document = QJsonDocument::fromJson(json);
        Q_ASSERT(document.isObject());
        const auto rootObject = document.object();
        Q_ASSERT(rootObject.value("kind").toString() == "Listing");
        const auto dataValue = rootObject.value("data");
        Q_ASSERT(dataValue.isObject());
        const auto dataObject = dataValue.toObject();
        const auto childrenValue = dataObject.value("children");
        Q_ASSERT(childrenValue.isArray());
        const auto childrenArray = childrenValue.toArray();

        if (childrenArray.isEmpty())
            return;

        beginInsertRows(QModelIndex(), threads.size(), childrenArray.size() + threads.size() - 1);
        for (const auto childValue : std::as_const(childrenArray)) {
            Q_ASSERT(childValue.isObject());
            threads.append(childValue.toObject());
        }
        endInsertRows();
    });
}
