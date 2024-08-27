// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR BSD-3-Clause

#include <QtNetworkAuth/qoauth2authorizationcodeflow.h>
#include <QtNetworkAuth/qoauthhttpserverreplyhandler.h>
#include <QtNetworkAuth/qoauthurischemereplyhandler.h>

#include <QtWebEngineWidgets/qwebengineview.h>

#include <QtWidgets/qmainwindow.h>

#include <QtNetwork/qnetworkrequestfactory.h>

#include <QtQml/qqmlregistration.h>

#include <QtGui/qdesktopservices.h>

#include <QtCore/qobject.h>
#include <QtCore/qurl.h>

using namespace Qt::StringLiterals;

//! [webengine-qml-control]
class HttpExample : public QObject
{
    Q_OBJECT
    QML_NAMED_ELEMENT(OAuth2)
public:
    Q_INVOKABLE void authorize();

signals:
    void authorizationCompleted(bool success);
    void authorizeWithBrowser(const QUrl &url);
//! [webengine-qml-control]

public:
    HttpExample();
    void setupSystemBrowser();
    void setupWebEngineWidgets();

private:
    //! [httpserver-variables]
    QOAuth2AuthorizationCodeFlow m_oauth;
    QOAuthHttpServerReplyHandler *m_handler = nullptr;
    //! [httpserver-variables]
    QNetworkRequestFactory m_api;
    QWebEngineView *webView = nullptr;
    QMainWindow mainWindow;
};

class UriSchemeExample : public QObject
{
    Q_OBJECT
public:
    UriSchemeExample();
    void setupSystemBrowserCustom();
    void setupWebEngineWidgetsCustom();
    void setupWebEngineWidgetsHttps();

private:
    //! [uri-variables]
    QOAuth2AuthorizationCodeFlow m_oauth;
    QOAuthUriSchemeReplyHandler m_handler;
    //! [uri-variables]
    QNetworkRequestFactory m_api;
    //! [webengine-widget-variables]
    QWebEngineView *webView = nullptr;
    QMainWindow mainWindow;
    //! [webengine-widget-variables]
};
