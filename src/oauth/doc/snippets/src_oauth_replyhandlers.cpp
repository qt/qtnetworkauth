// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR BSD-3-Clause

#include "src_oauth_replyhandlers_p.h"

//! [oidc-jwt-cpp-include]
#ifdef JWT_CPP_AVAILABLE
#include "jwt-cpp/jwt.h"
#endif
//! [oidc-jwt-cpp-include]

#include <QtWebEngineWidgets/qwebengineview.h>
#include <QtWebEngineCore/qwebenginenavigationrequest.h>

#include <QtNetworkAuth/qoauth2authorizationcodeflow.h>
#include <QtNetworkAuth/qoauthhttpserverreplyhandler.h>
#include <QtNetworkAuth/qoauthurischemereplyhandler.h>

#include <QtNetwork/qrestreply.h>
#include <QtNetwork/qnetworkrequestfactory.h>

#include <QtQml/qqmlregistration.h>
#include <QtQml/qqmlapplicationengine.h>

#include <QtWidgets/qapplication.h>

#include <QtGui/qdesktopservices.h>

#include <QtCore/qcommandlineparser.h>
#include <QtCore/qjsonarray.h>
#include <QtCore/qjsondocument.h>
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
static constexpr auto oidcConfigUrl =
    "https://www.myqtapp.example.com/.well-known/openid-configuration"_L1;
static constexpr auto oidcJwksUrl = "https://www.myqtapp.example.com/v1/certs"_L1;
static constexpr auto oidcUserInfoUrl = "https://oidc.myqtapp.example.com/v1/userinfo"_L1;
static constexpr auto clientSecret = "abcdefg"_L1;

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

    //! [oidc-setting-scope]
    m_oauth.setRequestedScope({"openid"_L1});
    //! [oidc-setting-scope]

    //! [oidc-setting-nonce-mode]
    // This is for illustrative purposes, 'Automatic' is the default mode
    m_oauth.setNonceMode(QAbstractOAuth2::NonceMode::Automatic);
    //! [oidc-setting-nonce-mode]

    m_network = new QRestAccessManager(new QNetworkAccessManager(this), this);
}

void HttpExample::setupSystemBrowser()
{
    // m_oauth.setClientIdentifierSharedKey(clientSecret); // Need depends: vendor, scheme, app type
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

    //! [oidc-listen-idtoken-change]
    connect(&m_oauth, &QAbstractOAuth2::idTokenChanged, this, [this](const QString &token) {
        Q_UNUSED(token); // Handle token
    });
    //! [oidc-listen-idtoken-change]

    connect(&m_oauth, &QAbstractOAuth2::idTokenChanged, this, [this](const QString &token) {
        auto parsed = parseIDToken(token);
        if (parsed) {
            qDebug() << "ID token received and parsed";
            //qDebug() << "ID token:" << parsed->header << parsed->payload << parsed->signature;
            verifyIDToken();
        } else {
            qDebug() << "No ID token";
        }
    });

    //! [httpserver-handler-setup]
    m_oauth.setReplyHandler(m_handler);

    // Initiate the authorization
    if (m_handler->isListening()) {
        m_oauth.grant();
    }
    //! [httpserver-handler-setup]

    readOIDCConfiguration({oidcConfigUrl});
    readJSONWebKeySet({oidcJwksUrl});
    readUserInfo({oidcUserInfoUrl});
}

void HttpExample::readOIDCConfiguration(const QUrl &url)
{
    QNetworkRequest request(url);
    //! [oidc-get-openid-configuration]
    m_network->get(request, this, [this](QRestReply &reply) {
        if (reply.isSuccess()) {
            if (auto doc = reply.readJson(); doc && doc->isObject())
                m_oidcConfig = doc->object(); // Store the configuration
        }
    });
    //! [oidc-get-openid-configuration]
}

void HttpExample::readJSONWebKeySet(const QUrl &url)
{
    QNetworkRequest request(url);
    //! [oidc-get-jwks-keys]
    m_network->get(request, this, [this](QRestReply &reply) {
        if (reply.isSuccess()) {
            if (auto doc = reply.readJson(); doc && doc->isObject())
                m_jwks = doc; // Use the keys later to verify tokens
        }
    });
    //! [oidc-get-jwks-keys]
}

std::optional<HttpExample::IDToken> HttpExample::parseIDToken(const QString &token) const
{
    //! [oidc-id-token-parsing]
    if (token.isEmpty())
        return std::nullopt;

    QList<QByteArray> parts = token.toLatin1().split('.');
    if (parts.size() != 3)
        return std::nullopt;

    QJsonParseError parsing;

    QJsonDocument header = QJsonDocument::fromJson(
        QByteArray::fromBase64(parts.at(0), QByteArray::Base64UrlEncoding), &parsing);
    if (parsing.error != QJsonParseError::NoError || !header.isObject())
        return std::nullopt;

    QJsonDocument payload = QJsonDocument::fromJson(
        QByteArray::fromBase64(parts.at(1), QByteArray::Base64UrlEncoding), &parsing);
    if (parsing.error != QJsonParseError::NoError || !payload.isObject())
        return std::nullopt;

    QByteArray signature = QByteArray::fromBase64(parts.at(2), QByteArray::Base64UrlEncoding);

    return IDToken{header.object(), payload.object(), signature};
    //! [oidc-id-token-parsing]
}

void HttpExample::readUserInfo(const QUrl &url) const
{
    //! [oidc-set-bearertoken]
    QNetworkRequestFactory userInfoApi(url);
    userInfoApi.setBearerToken(m_oauth.token().toLatin1());
    //! [oidc-set-bearertoken]

    //! [oidc-read-userinfo]
    m_network->get(userInfoApi.createRequest(), this, [this](QRestReply &reply) {
        if (reply.isSuccess()) {
            if (auto doc = reply.readJson(); doc && doc->isObject())
                qDebug() << doc->object(); // Use the userinfo
        }
    });
    //! [oidc-read-userinfo]
}

bool HttpExample::verifyIDToken() const
{
    if (!m_jwks || !m_oidcConfig) {
        qWarning() << "Missing data to verify ID token";
        return false;
    }
#ifdef JWT_CPP_AVAILABLE
    qDebug() << "Verifying ID token";
    //! [oidc-jwt-cpp-key-matching]
    try {
        const auto jwt = jwt::decode(m_oauth.idToken().toStdString());
        const auto jwks = jwt::parse_jwks(m_jwks->toJson(QJsonDocument::Compact).toStdString());
        const auto jwk = jwks.get_jwk(jwt.get_key_id());
        //! [oidc-jwt-cpp-key-matching]

        //! [oidc-jwt-cpp-verification]
        // Here we use modulus and exponent to derive the key
        const auto n = jwk.get_jwk_claim("n").as_string(); // modulus
        const auto e = jwk.get_jwk_claim("e").as_string(); // exponent
        if (n.empty() || e.empty()) {
            qWarning() << "Modulus or exponent empty";
            return false;
        }
        if (jwt.get_algorithm() != "RS256") { // This example only supports RS256
            qWarning() << "Unsupported algorithm:" << jwt.get_algorithm();
            return false;
        }
        if (jwk.get_jwk_claim("kty").as_string() != "RSA") {
            qWarning() << "Unsupported key type:" << jwk.get_jwk_claim("kty").as_string();
            return false;
        }
        if (jwk.has_jwk_claim("use") && jwk.get_jwk_claim("use").as_string() != "sig") {
            qWarning() << "Key not for signature" << jwk.get_jwk_claim("use").as_string();
            return false;
        }
        // Simple minimal verification (omits special cases and eg. 'sub' verification).
        // jwt-cpp does check also 'exp', 'iat', and 'nbf' if they are present.
        const auto keyPEM = jwt::helper::create_public_key_from_rsa_components(n, e);
        auto verifier = jwt::verify()
                            .allow_algorithm(jwt::algorithm::rs256(keyPEM))
                            .with_claim("nonce", jwt::claim(m_oauth.nonce().toStdString()))
                            .with_issuer(m_oidcConfig->value("issuer"_L1).toString().toStdString())
                            .with_audience(std::string(clientIdentifier.data()))
                            .leeway(60UL);
        verifier.verify(jwt);
        qDebug() << "ID Token verified successfully";
        return true;
    } catch(const std::exception &e) {
        // Handle error. Alternatively pass error parameter to jwt-cpp calls
        qWarning() << "ID Token verification failed" << e.what();
        return false;
    }
    //! [oidc-jwt-cpp-verification]
#endif
    qWarning() << "ID token verification was not possible";
    return false;
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
