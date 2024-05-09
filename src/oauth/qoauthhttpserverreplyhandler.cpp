// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtNetwork/qtnetwork-config.h>

#ifndef QT_NO_HTTP

#include <qabstractoauth.h>
#include <qoauthhttpserverreplyhandler.h>
#include "qabstractoauthreplyhandler_p.h"

#include <private/qoauthhttpserverreplyhandler_p.h>

#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>
#include <QtCore/qcoreapplication.h>
#include <QtCore/qloggingcategory.h>
#include <QtCore/private/qlocale_p.h>

#include <QtNetwork/qtcpsocket.h>
#include <QtNetwork/qnetworkreply.h>

#include <cstring>
#include <functional>

QT_BEGIN_NAMESPACE

using namespace Qt::StringLiterals;

QOAuthHttpServerReplyHandlerPrivate::QOAuthHttpServerReplyHandlerPrivate(
        QOAuthHttpServerReplyHandler *p) :
    text(QObject::tr("Callback received. Feel free to close this page.")), path(u'/'), q_ptr(p)
{
    QObject::connect(&httpServer, &QTcpServer::newConnection, q_ptr,
                     [this]() { _q_clientConnected(); });
}

QOAuthHttpServerReplyHandlerPrivate::~QOAuthHttpServerReplyHandlerPrivate()
{
    if (httpServer.isListening())
        httpServer.close();
}

void QOAuthHttpServerReplyHandlerPrivate::_q_clientConnected()
{
    QTcpSocket *socket = httpServer.nextPendingConnection();

    QObject::connect(socket, &QTcpSocket::disconnected, socket, &QTcpSocket::deleteLater);
    QObject::connect(socket, &QTcpSocket::readyRead, q_ptr,
                     [this, socket]() { _q_readData(socket); });
}

void QOAuthHttpServerReplyHandlerPrivate::_q_readData(QTcpSocket *socket)
{
    QHttpRequest *request = nullptr;
    if (auto it = clients.find(socket); it == clients.end()) {
        request = &clients[socket];     // insert it
        request->port = httpServer.serverPort();
    } else {
        request = &*it;
    }

    bool error = false;

    if (Q_LIKELY(request->state == QHttpRequest::State::ReadingMethod))
        if (Q_UNLIKELY(error = !request->readMethod(socket)))
            qCWarning(lcReplyHandler, "Invalid Method");

    if (Q_LIKELY(!error && request->state == QHttpRequest::State::ReadingUrl))
        if (Q_UNLIKELY(error = !request->readUrl(socket)))
            qCWarning(lcReplyHandler, "Invalid URL");

    if (Q_LIKELY(!error && request->state == QHttpRequest::State::ReadingStatus))
        if (Q_UNLIKELY(error = !request->readStatus(socket)))
            qCWarning(lcReplyHandler, "Invalid Status");

    if (Q_LIKELY(!error && request->state == QHttpRequest::State::ReadingHeader))
        if (Q_UNLIKELY(error = !request->readHeader(socket)))
            qCWarning(lcReplyHandler, "Invalid Header");

    if (error) {
        socket->disconnectFromHost();
        clients.remove(socket);
    } else if (!request->url.isEmpty()) {
        Q_ASSERT(request->state != QHttpRequest::State::ReadingUrl);
        _q_answerClient(socket, request->url);
        clients.remove(socket);
    }
}

void QOAuthHttpServerReplyHandlerPrivate::_q_answerClient(QTcpSocket *socket, const QUrl &url)
{
    Q_Q(QOAuthHttpServerReplyHandler);
    if (url.path() != path) {
        qCWarning(lcReplyHandler, "Invalid request: %s", qPrintable(url.toString()));
    } else {
        QVariantMap receivedData;
        const QUrlQuery query(url.query());
        const auto items = query.queryItems();
        for (auto it = items.begin(), end = items.end(); it != end; ++it)
            receivedData.insert(it->first, it->second);
        Q_EMIT q->callbackReceived(receivedData);

        const QByteArray html = QByteArrayLiteral("<html><head><title>") +
                qApp->applicationName().toUtf8() +
                QByteArrayLiteral("</title></head><body>") +
                text.toUtf8() +
                QByteArrayLiteral("</body></html>");

        const QByteArray htmlSize = QByteArray::number(html.size());
        const QByteArray replyMessage = QByteArrayLiteral("HTTP/1.0 200 OK \r\n"
                                                          "Content-Type: text/html; "
                                                          "charset=\"utf-8\"\r\n"
                                                          "Content-Length: ") + htmlSize +
                QByteArrayLiteral("\r\n\r\n") +
                html;

        socket->write(replyMessage);
    }
    socket->disconnectFromHost();
}

bool QOAuthHttpServerReplyHandlerPrivate::QHttpRequest::readMethod(QTcpSocket *socket)
{
    bool finished = false;
    while (socket->bytesAvailable() && !finished) {
        char c;
        socket->getChar(&c);
        if (std::isupper(c) && fragment.size() < 6)
            fragment += c;
        else
            finished = true;
    }
    if (finished) {
        if (fragment == "HEAD")
            method = Method::Head;
        else if (fragment == "GET")
            method = Method::Get;
        else if (fragment == "PUT")
            method = Method::Put;
        else if (fragment == "POST")
            method = Method::Post;
        else if (fragment == "DELETE")
            method = Method::Delete;
        else
            qCWarning(lcReplyHandler, "Invalid operation %s", fragment.data());

        state = State::ReadingUrl;
        fragment.clear();

        return method != Method::Unknown;
    }
    return true;
}

bool QOAuthHttpServerReplyHandlerPrivate::QHttpRequest::readUrl(QTcpSocket *socket)
{
    bool finished = false;
    while (socket->bytesAvailable() && !finished) {
        char c;
        socket->getChar(&c);
        if (ascii_isspace(c))
            finished = true;
        else
            fragment += c;
    }
    if (finished) {
        url = QUrl::fromEncoded(fragment);
        state = State::ReadingStatus;

        if (!fragment.startsWith(u'/') || !url.isValid() || !url.scheme().isNull()
                || !url.host().isNull()) {
            qCWarning(lcReplyHandler, "Invalid request: %s", fragment.constData());
            return false;
        }
        fragment.clear();
        return true;
    }
    return true;
}

bool QOAuthHttpServerReplyHandlerPrivate::QHttpRequest::readStatus(QTcpSocket *socket)
{
    bool finished = false;
    while (socket->bytesAvailable() && !finished) {
        char c;
        socket->getChar(&c);
        fragment += c;
        if (fragment.endsWith("\r\n")) {
            finished = true;
            fragment.resize(fragment.size() - 2);
        }
    }
    if (finished) {
        if (!std::isdigit(fragment.at(fragment.size() - 3)) ||
                !std::isdigit(fragment.at(fragment.size() - 1))) {
            qCWarning(lcReplyHandler, "Invalid version");
            return false;
        }
        version = qMakePair(fragment.at(fragment.size() - 3) - '0',
                            fragment.at(fragment.size() - 1) - '0');
        state = State::ReadingHeader;
        fragment.clear();
    }
    return true;
}

bool QOAuthHttpServerReplyHandlerPrivate::QHttpRequest::readHeader(QTcpSocket *socket)
{
    while (socket->bytesAvailable()) {
        char c;
        socket->getChar(&c);
        fragment += c;
        if (fragment.endsWith("\r\n")) {
            if (fragment == "\r\n") {
                state = State::ReadingBody;
                fragment.clear();
                return true;
            } else {
                fragment.chop(2);
                const int index = fragment.indexOf(':');
                if (index == -1)
                    return false;

                const QByteArray key = fragment.mid(0, index).trimmed();
                const QByteArray value = fragment.mid(index + 1).trimmed();
                headers.insert(key, value);
                fragment.clear();
            }
        }
    }
    return false;
}

QOAuthHttpServerReplyHandler::QOAuthHttpServerReplyHandler(QObject *parent) :
    QOAuthHttpServerReplyHandler(QHostAddress::Null, 0, parent)
{}

QOAuthHttpServerReplyHandler::QOAuthHttpServerReplyHandler(quint16 port, QObject *parent) :
    QOAuthHttpServerReplyHandler(QHostAddress::Null, port, parent)
{}

QOAuthHttpServerReplyHandler::QOAuthHttpServerReplyHandler(const QHostAddress &address,
                                                           quint16 port, QObject *parent) :
    QOAuthOobReplyHandler(parent),
    d_ptr(new QOAuthHttpServerReplyHandlerPrivate(this))
{
    listen(address, port);
}

QOAuthHttpServerReplyHandler::~QOAuthHttpServerReplyHandler()
{}

QString QOAuthHttpServerReplyHandler::callback() const
{
    Q_D(const QOAuthHttpServerReplyHandler);

    Q_ASSERT(d->httpServer.isListening());
    QUrl url;
    url.setScheme(u"http"_s);
    url.setPort(d->httpServer.serverPort());
    url.setPath(d->path);

    // convert Any and Localhost addresses to "localhost"
    QHostAddress host = d->httpServer.serverAddress();
    if (host.isLoopback() || host == QHostAddress::AnyIPv4 || host == QHostAddress::Any
            || host == QHostAddress::AnyIPv6)
        url.setHost(u"localhost"_s);
    else
        url.setHost(host.toString());

    return url.toString(QUrl::EncodeSpaces | QUrl::EncodeUnicode | QUrl::EncodeDelimiters
                        | QUrl::EncodeReserved);
}

QString QOAuthHttpServerReplyHandler::callbackPath() const
{
    Q_D(const QOAuthHttpServerReplyHandler);
    return d->path;
}

void QOAuthHttpServerReplyHandler::setCallbackPath(const QString &path)
{
    Q_D(QOAuthHttpServerReplyHandler);
    // pass through QUrl to ensure normalization
    QUrl url;
    url.setPath(path);
    d->path = url.path(QUrl::FullyEncoded);
    if (d->path.isEmpty())
        d->path = u'/';
}

QString QOAuthHttpServerReplyHandler::callbackText() const
{
    Q_D(const QOAuthHttpServerReplyHandler);
    return d->text;
}

void QOAuthHttpServerReplyHandler::setCallbackText(const QString &text)
{
    Q_D(QOAuthHttpServerReplyHandler);
    d->text = text;
}

quint16 QOAuthHttpServerReplyHandler::port() const
{
    Q_D(const QOAuthHttpServerReplyHandler);
    return d->httpServer.serverPort();
}

bool QOAuthHttpServerReplyHandler::listen(const QHostAddress &address, quint16 port)
{
    Q_D(QOAuthHttpServerReplyHandler);
    if (address.isNull()) {
        // try IPv4 first, for greatest compatibility
        if (d->httpServer.listen(QHostAddress::LocalHost, port))
            return true;
        return d->httpServer.listen(QHostAddress::LocalHostIPv6, port);
    }
    return d->httpServer.listen(address, port);
}

void QOAuthHttpServerReplyHandler::close()
{
    Q_D(QOAuthHttpServerReplyHandler);
    return d->httpServer.close();
}

bool QOAuthHttpServerReplyHandler::isListening() const
{
    Q_D(const QOAuthHttpServerReplyHandler);
    return d->httpServer.isListening();
}

QT_END_NAMESPACE

#include "moc_qoauthhttpserverreplyhandler.cpp"

#endif // QT_NO_HTTP
