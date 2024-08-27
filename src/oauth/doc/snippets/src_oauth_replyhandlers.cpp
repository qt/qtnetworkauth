// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR BSD-3-Clause

#include "src_oauth_replyhandlers_p.h"

#include <QtWebEngineWidgets/qwebengineview.h>
#include <QtWebEngineCore/qwebenginenavigationrequest.h>

#include <QtNetworkAuth/qoauth2authorizationcodeflow.h>
#include <QtNetworkAuth/qoauthhttpserverreplyhandler.h>
#include <QtNetworkAuth/qoauthurischemereplyhandler.h>

#include <QtNetwork/qnetworkrequestfactory.h>

#include <QtQml/qqmlregistration.h>
#include <QtQml/qqmlapplicationengine.h>

#include <QtWidgets/qapplication.h>

#include <QtGui/qdesktopservices.h>

#include <QtCore/qcommandlineparser.h>
#include <QtCore/qobject.h>
#include <QtCore/qurl.h>

using namespace Qt::StringLiterals;

// To test against an actual authorization server, set authorization URL, access token URL and
// client identifier to their proper values. Note also to adjust the redirect URLs to match
// with what the authorization server expects.
static constexpr auto authorizationUrl = "https://www.myqtapp.example.com/api/v1/authorize"_L1;
static constexpr auto accessTokenUrl = "https://www.myqtapp.example.com/api/v1/access_token"_L1;
static constexpr auto clientIdentifier = "some_client_id"_L1;
static constexpr auto scope = "read"_L1;

HttpExample::HttpExample()
{
    webView = new QWebEngineView;
    mainWindow.setCentralWidget(webView);
    mainWindow.resize(800, 600);
    //! [httpserver-service-configuration]
    m_oauth.setAuthorizationUrl(QUrl(authorizationUrl));
    m_oauth.setAccessTokenUrl(QUrl(accessTokenUrl));
    m_oauth.setClientIdentifier(clientIdentifier);
    m_oauth.setRequestedScope({scope});
    //! [httpserver-service-configuration]
}

void HttpExample::setupSystemBrowser()
{
    //! [httpserver-oauth-setup]
    m_handler = new QOAuthHttpServerReplyHandler(1234, this);

    //! [system-browser-usage]
    connect(&m_oauth, &QAbstractOAuth::authorizeWithBrowser, this, &QDesktopServices::openUrl);
    //! [system-browser-usage]
    connect(&m_oauth, &QAbstractOAuth::granted, this, [this]() {
        // Here we use QNetworkRequestFactory to store the access token
        m_api.setBearerToken(m_oauth.token().toLatin1());
        m_handler->close();
    });
    //! [httpserver-oauth-setup]

    //! [httpserver-handler-setup]
    m_oauth.setReplyHandler(m_handler);

    // Initiate the authorization
    if (m_handler->isListening()) {
        m_oauth.grant();
    }
    //! [httpserver-handler-setup]
}

void HttpExample::setupWebEngineWidgets()
{
    m_handler = new QOAuthHttpServerReplyHandler(1234, this);

    //! [webengine-widget-authorization-start]
    connect(&m_oauth, &QAbstractOAuth::authorizeWithBrowser, this, [this](const QUrl &url) {
        mainWindow.show();
        webView->load(url);
        webView->show();
    });
    //! [webengine-widget-authorization-start]

    //! [webengine-widget-authorization-finish]
    connect(&m_oauth, &QAbstractOAuth::granted, this, [this]() {
        // Here we use QNetworkRequestFactory to store the access token
        m_api.setBearerToken(m_oauth.token().toLatin1());
        m_handler->close();
        webView->close();
    });
    //! [webengine-widget-authorization-finish]

    m_oauth.setReplyHandler(m_handler);

    // Initiate the authorization
    if (m_handler->isListening()) {
        m_oauth.grant();
    }
}

void HttpExample::authorize()
{
    if (!m_handler) {
        m_oauth.setAuthorizationUrl(QUrl(authorizationUrl));
        m_oauth.setAccessTokenUrl(QUrl(accessTokenUrl));
        m_oauth.setClientIdentifier(clientIdentifier);
        m_oauth.setRequestedScope({scope});

        m_handler = new QOAuthHttpServerReplyHandler(1234, this);

        connect(&m_oauth, &QAbstractOAuth::authorizeWithBrowser,
                this, &HttpExample::authorizeWithBrowser);

        connect(&m_oauth, &QAbstractOAuth::granted, this, [this]() {
            // Here we use QNetworkRequestFactory to store the access token
            m_api.setBearerToken(m_oauth.token().toLatin1());
            m_handler->close();
            emit authorizationCompleted(true);
        });
        m_oauth.setReplyHandler(m_handler);
    }
    // Initiate the authorization
    if (m_handler->isListening()) {
        m_oauth.grant();
    }
}

UriSchemeExample::UriSchemeExample()
{
    webView = new QWebEngineView;
    mainWindow.setCentralWidget(webView);
    mainWindow.resize(800, 600);

    //! [uri-service-configuration]
    m_oauth.setAuthorizationUrl(QUrl(authorizationUrl));
    m_oauth.setAccessTokenUrl(QUrl(accessTokenUrl));
    m_oauth.setClientIdentifier(clientIdentifier);
    m_oauth.setRequestedScope({scope});
    //! [uri-service-configuration]
}

void UriSchemeExample::setupSystemBrowserCustom()
{
    //! [uri-oauth-setup]
    connect(&m_oauth, &QAbstractOAuth::authorizeWithBrowser, this, &QDesktopServices::openUrl);
    connect(&m_oauth, &QAbstractOAuth::granted, this, [this]() {
        // Here we use QNetworkRequestFactory to store the access token
        m_api.setBearerToken(m_oauth.token().toLatin1());
        m_handler.close();
    });
    //! [uri-oauth-setup]

    //! [uri-handler-setup]
    m_handler.setRedirectUrl(QUrl{"com.example.myqtapp://oauth2redirect"_L1});
    m_oauth.setReplyHandler(&m_handler);

    // Initiate the authorization
    if (m_handler.listen()) {
        m_oauth.grant();
    }
    //! [uri-handler-setup]
}

void UriSchemeExample::setupWebEngineWidgetsCustom()
{
    //! [webengine-widgets-custom]
    m_handler.setRedirectUrl(QUrl{"com.example.myqtapp://oauth2redirect"_L1});
    m_oauth.setReplyHandler(&m_handler);

    connect(&m_oauth, &QAbstractOAuth::authorizeWithBrowser, this, [this](const QUrl &url) {
        mainWindow.show();
        webView->load(url);
        webView->show();
    });
    connect(&m_oauth, &QAbstractOAuth::granted, this, [this]() {
        // Here we use QNetworkRequestFactory to store the access token
        m_api.setBearerToken(m_oauth.token().toLatin1());
        m_handler.close();
        webView->close();
    });
    //! [webengine-widgets-custom]

    m_oauth.setReplyHandler(&m_handler);

    // Initiate the authorization
    m_handler.listen();
    if (m_handler.isListening()) {
        m_oauth.grant();
    }
}

void UriSchemeExample::setupWebEngineWidgetsHttps()
{
    m_handler.setRedirectUrl(QUrl{"https://myqtapp.example.com/oauth2redirect"_L1});
    m_handler.close();
    m_oauth.setReplyHandler(&m_handler);

    connect(&m_oauth, &QAbstractOAuth::authorizeWithBrowser, this, [this](const QUrl &url) {
        mainWindow.show();
        webView->load(url);
        webView->show();
    });

    /*
    //! [webengine-widgets-https]
    connect(webView, &QWebEngineView::urlChanged, this, [this](const QUrl &url){
        m_handler.handleAuthorizationRedirect(url);
    });
    //! [webengine-widgets-https]
    */

    //! [webengine-widget-https-filtering]
    connect(webView->page(), &QWebEnginePage::navigationRequested,
            this, [this](QWebEngineNavigationRequest &request) {
        if (request.navigationType() == QWebEngineNavigationRequest::RedirectNavigation
            && m_handler.handleAuthorizationRedirect(request.url())) {
            request.reject();
            webView->close();
        } else {
            request.accept();
        }
    });
    //! [webengine-widget-https-filtering]

    connect(&m_oauth, &QAbstractOAuth::granted, this, [this]() {
        // Here we use QNetworkRequestFactory to store the access token
        m_api.setBearerToken(m_oauth.token().toLatin1());
        m_handler.close();
        webView->close();
    });
    m_oauth.grant();
}
