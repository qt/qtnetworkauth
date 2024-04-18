// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include "qabstractoauthreplyhandler_p.h" // for lcReplyHandler()
#include "qoauthoobreplyhandler_p.h"
#include "qoauthurischemereplyhandler.h"

#include <QtGui/qdesktopservices.h>

#include <private/qobject_p.h>

#include <QtCore/qloggingcategory.h>
#include <QtCore/qurlquery.h>

QT_BEGIN_NAMESPACE

class QOAuthUriSchemeReplyHandlerPrivate : public QOAuthOobReplyHandlerPrivate
{
    Q_DECLARE_PUBLIC(QOAuthUriSchemeReplyHandler)

public:
    bool hasValidRedirectUrl() const
    {
        // RFC 6749 Section 3.1.2
        return redirectUrl.isValid()
               && !redirectUrl.scheme().isEmpty()
               && redirectUrl.fragment().isEmpty();
    }

    void _q_handleRedirectUrl(const QUrl &url)
    {
        Q_Q(QOAuthUriSchemeReplyHandler);
        // Remove the query parameters from comparison, and compare them manually (the parameters
        // of interest like 'code' and 'state' are received as query parameters and comparison
        // would always fail). Fragments are removed as some servers (eg. Reddit) seem to add some,
        // possibly for some implementation consistency with other OAuth flows where fragments
        // are actually used.
        bool urlMatch = url.matches(redirectUrl, QUrl::RemoveQuery | QUrl::RemoveFragment);

        const QUrlQuery responseQuery{url};
        if (urlMatch) {
            // Verify that query parameters that are part of redirect URL are present in redirection
            const auto registeredItems = QUrlQuery{redirectUrl}.queryItems();
            for (const auto &item: registeredItems) {
                if (!responseQuery.hasQueryItem(item.first)
                    || responseQuery.queryItemValue(item.first) != item.second) {
                    urlMatch = false;
                    break;
                }
            }
        }

        if (!urlMatch) {
            qCDebug(lcReplyHandler(), "Url ignored");
            // The URLs received here might be unrelated. Further, in case of "https" scheme,
            // the first request issued to the authorization server comes through here
            // (if this handler is listening)
            QDesktopServices::openUrl(url);
            return;
        }

        qCDebug(lcReplyHandler(), "Url handled");

        QVariantMap resultParameters;
        const auto responseItems = responseQuery.queryItems(QUrl::FullyDecoded);
        for (const auto &item : responseItems)
            resultParameters.insert(item.first, item.second);

        emit q->callbackReceived(resultParameters);
    }

public:
    QUrl redirectUrl;
    bool listening = false;
};

QOAuthUriSchemeReplyHandler::QOAuthUriSchemeReplyHandler(QObject *parent) :
    QOAuthOobReplyHandler(*new QOAuthUriSchemeReplyHandlerPrivate(), parent)
{
}

QOAuthUriSchemeReplyHandler::QOAuthUriSchemeReplyHandler(const QUrl &redirectUrl, QObject *parent)
    : QOAuthUriSchemeReplyHandler(parent)
{
    Q_D(QOAuthUriSchemeReplyHandler);
    d->redirectUrl = redirectUrl;
    listen();
}

QOAuthUriSchemeReplyHandler::~QOAuthUriSchemeReplyHandler()
{
    close();
}

QString QOAuthUriSchemeReplyHandler::callback() const
{
    Q_D(const QOAuthUriSchemeReplyHandler);
    return d->redirectUrl.toString();
}

void QOAuthUriSchemeReplyHandler::setRedirectUrl(const QUrl &url)
{
    Q_D(QOAuthUriSchemeReplyHandler);
    if (url == d->redirectUrl)
        return;

    if (d->listening) {
        close(); // close previous url listening first
        d->redirectUrl = url;
        listen();
    } else {
        d->redirectUrl = url;
    }
    emit redirectUrlChanged();
}

QUrl QOAuthUriSchemeReplyHandler::redirectUrl() const
{
    Q_D(const QOAuthUriSchemeReplyHandler);
    return d->redirectUrl;
}

bool QOAuthUriSchemeReplyHandler::listen()
{
    Q_D(QOAuthUriSchemeReplyHandler);
    if (d->listening)
        return true;

    if (!d->hasValidRedirectUrl()) {
        qCWarning(lcReplyHandler(), "listen(): callback url not valid");
        return false;
    }
    qCDebug(lcReplyHandler(), "listen() URL listener");
    QDesktopServices::setUrlHandler(d->redirectUrl.scheme(), this, "_q_handleRedirectUrl");

    d->listening = true;
    return true;
}

void QOAuthUriSchemeReplyHandler::close()
{
    Q_D(QOAuthUriSchemeReplyHandler);
    if (!d->listening)
        return;

    qCDebug(lcReplyHandler(), "close() URL listener");
    QDesktopServices::unsetUrlHandler(d->redirectUrl.scheme());
    d->listening = false;
}

bool QOAuthUriSchemeReplyHandler::isListening() const noexcept
{
    Q_D(const QOAuthUriSchemeReplyHandler);
    return d->listening;
}

QT_END_NAMESPACE

#include "moc_qoauthurischemereplyhandler.cpp"
