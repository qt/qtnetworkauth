// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtTest>

#ifndef QT_NO_SSL
#include <QSslKey>
#endif

#include <QtNetworkAuth/qabstractoauthreplyhandler.h>
#include <QtNetworkAuth/qoauth2authorizationcodeflow.h>

#include <QtCore/qcryptographichash.h>

#include "webserver.h"
#include "tlswebserver.h"

using namespace Qt::StringLiterals;

class tst_OAuth2 : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void state();
    void getToken();
    void refreshToken();
    void getAndRefreshToken();
    void tokenRequestErrors();
    void authorizationErrors();
    void prepareRequest();
    void pkce_data();
    void pkce();
    void nonce();
    void idToken();
#if QT_DEPRECATED_SINCE(6, 11)
    void scope_data();
    void scope();
    void scopeAndRequestedScope_data();
    void scopeAndRequestedScope();
#endif
    void requestedScope_data();
    void requestedScope();
    void grantedScope_data();
    void grantedScope();
#ifndef QT_NO_SSL
    void setSslConfig();
    void tlsAuthentication();
#endif

private:
    QString testDataDir;
    [[nodiscard]] auto useTemporaryKeychain()
    {
#ifndef QT_NO_SSL
        // Set the same environment value as CI uses, so that it's possible
        // to run autotests locally without macOS asking for permission to use
        // a private key in keychain (with TLS sockets)
        auto value = qEnvironmentVariable("QT_SSL_USE_TEMPORARY_KEYCHAIN");
        qputenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", "1");
        auto envRollback = qScopeGuard([value](){
            if (value.isEmpty())
                qunsetenv("QT_SSL_USE_TEMPORARY_KEYCHAIN");
            else
                qputenv("QT_SSL_USE_TEMPORARY_KEYCHAIN", value.toUtf8());
        });
        return envRollback;
#else
        // avoid maybe-unused warnings from callers
        return qScopeGuard([]{});
#endif // QT_NO_SSL
    }

};

struct ReplyHandler : QAbstractOAuthReplyHandler
{
    QString callback() const override
    {
        return QLatin1String("test");
    }

    QAbstractOAuth::Error aTokenRequestError = QAbstractOAuth::Error::NoError;

    void networkReplyFinished(QNetworkReply *reply) override
    {
        QVariantMap data;
        const auto items = QUrlQuery(reply->readAll()).queryItems();
        for (const auto &pair : items)
            data.insert(pair.first, pair.second);

        if (aTokenRequestError == QAbstractOAuth::Error::NoError)
            emit tokensReceived(data);
        else
            emit tokenRequestErrorOccurred(aTokenRequestError, "a token request error");
    }

    void emitCallbackReceived(const QVariantMap &data)
    {
        Q_EMIT callbackReceived(data);
    }

    void emitTokensReceived(const QVariantMap &data)
    {
        Q_EMIT tokensReceived(data);
    }
};

void tst_OAuth2::initTestCase()
{
    // QLoggingCategory::setFilterRules(QStringLiteral("qt.networkauth* = true"));
    testDataDir = QFileInfo(QFINDTESTDATA("certs")).absolutePath();
    if (testDataDir.isEmpty())
        testDataDir = QCoreApplication::applicationDirPath();
    if (!testDataDir.endsWith(QLatin1String("/")))
        testDataDir += QLatin1String("/");
}

void tst_OAuth2::state()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(QUrl{"authorizationUrl"_L1});
    oauth2.setAccessTokenUrl(QUrl{"accessTokenUrl"_L1});
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    QSignalSpy statePropertySpy(&oauth2, &QAbstractOAuth2::stateChanged);

    QString stateParameter;
    oauth2.setModifyParametersFunction(
        [&] (QAbstractOAuth::Stage, QMultiMap<QString, QVariant> *parameters) {
            stateParameter = parameters->value(u"state"_s).toString();
    });

    oauth2.grant();
    QVERIFY(!stateParameter.isEmpty()); // internally generated initial state used
    QCOMPARE(stateParameter, oauth2.state());

    // Test setting the 'state' property
    const QString simpleState = u"a_state"_s;
    oauth2.setState(simpleState);
    QCOMPARE(oauth2.state(), simpleState);
    QCOMPARE(statePropertySpy.size(), 1);
    QCOMPARE(statePropertySpy.at(0).at(0), simpleState);
    oauth2.grant();
    QCOMPARE(stateParameter, simpleState);

    // Test 'state' that contains illegal characters
    QTest::ignoreMessage(QtWarningMsg, "setState() contains illegal character(s), ignoring");
    oauth2.setState(u"foo€bar"_s);
    QCOMPARE(oauth2.state(), simpleState);
    QCOMPARE(statePropertySpy.size(), 1);

    // Test 'state' that requires encoding/decoding.
    // The 'state' value contains all allowed characters as defined by
    // https://datatracker.ietf.org/doc/html/rfc6749#appendix-A.5
    // state      = 1*VSCHAR
    // Where
    // VSCHAR     = %x20-7E
    const QString stateRequiringEncoding = u"! \"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~"_s;
    const QString stateAsEncoded = u"%21+%22%23%24%25%26%27%28%29%2A%2B%2C-.%2F0123456789%3A%3B%3C%3D%3E%3F%40ABCDEFGHIJKLMNOPQRSTUVWXYZ%5B%5C%5D%5E_%60abcdefghijklmnopqrstuvwxyz%7B%7C%7D~"_s;
    oauth2.setState(stateRequiringEncoding);
    QCOMPARE(oauth2.state(), stateRequiringEncoding);
    oauth2.grant();
    QCOMPARE(stateParameter, stateAsEncoded);
    // Conclude authorization stage, and check that the 'state' which we returned as encoded
    // matches the original decoded state (ie. the status changes to TemporaryCredentialsReceived)
    replyHandler.emitCallbackReceived({{"code", "acode"}, {"state", stateAsEncoded}});
    QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::TemporaryCredentialsReceived);
}

void tst_OAuth2::authorizationErrors()
{
    // This tests failures in authorization stage. For this test we don't need a web server
    // as we emit the final (failing) callbackReceived directly.
    // Helper to catch the expected warning messages:
    constexpr auto expectWarning = [](){
        static const QRegularExpression authStageWarning{"Authorization stage:.*"};
        QTest::ignoreMessage(QtWarningMsg, authStageWarning);
    };

    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(QUrl{"authorization"_L1});
    oauth2.setAccessTokenUrl(QUrl{"accessToken"_L1});
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);

    QVariantMap callbackParameters;
    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            &oauth2, [&](const QUrl& /* url */) {
        replyHandler.emitCallbackReceived(callbackParameters);
    });

    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);
    QSignalSpy errorSpy(&oauth2, &QAbstractOAuth2::error);
    QSignalSpy statusSpy(&oauth2, &QAbstractOAuth2::statusChanged);
    auto clearSpies = [&](){
        requestFailedSpy.clear();
        errorSpy.clear();
        statusSpy.clear();
    };

    // Test error response from the authorization server (RFC 6749 section 5.2)
    callbackParameters = {{"error"_L1, "invalid_grant"_L1},
                          {"error_description"_L1, "The error description"_L1},
                          {"error_uri"_L1, "The error URI"_L1}};
    expectWarning();
    oauth2.grant();
    QTRY_COMPARE(errorSpy.count(), 1);
    QTRY_COMPARE(requestFailedSpy.count(), 1);
    QCOMPARE(errorSpy.first().at(0).toString(), "invalid_grant"_L1);
    QCOMPARE(errorSpy.first().at(1).toString(), "The error description"_L1);
    QCOMPARE(errorSpy.first().at(2).toString(), "The error URI"_L1);
    QCOMPARE(requestFailedSpy.first().at(0).value<QAbstractOAuth::Error>(),
             QAbstractOAuth::Error::ServerError);
    QVERIFY(statusSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::NotAuthenticated);

    // Test not providing authorization code
    clearSpies();
    callbackParameters = {{"state"_L1, "thestate"_L1}};
    expectWarning();
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.count(), 1);
    QCOMPARE(requestFailedSpy.first().at(0).value<QAbstractOAuth::Error>(),
             QAbstractOAuth::Error::OAuthTokenNotFoundError);
    QCOMPARE(errorSpy.count(), 0);
    QVERIFY(statusSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::NotAuthenticated);

    // Test not providing a state
    clearSpies();
    callbackParameters = {{"code"_L1, "thecode"_L1}};
    expectWarning();
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.count(), 1);
    QCOMPARE(requestFailedSpy.first().at(0).value<QAbstractOAuth::Error>(),
             QAbstractOAuth::Error::ServerError);
    QCOMPARE(errorSpy.count(), 0);
    QVERIFY(statusSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::NotAuthenticated);

    // Test state mismatch (here we use "thestate" while the actual, expected, state is a
    // random generated string varying each run
    clearSpies();
    callbackParameters = {{"code"_L1, "thecode"_L1}, {"state"_L1, "thestate"_L1}};
    expectWarning();
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.count(), 1);
    QCOMPARE(requestFailedSpy.first().at(0).value<QAbstractOAuth::Error>(),
             QAbstractOAuth::Error::ServerError);
    QCOMPARE(errorSpy.count(), 0);
    QVERIFY(statusSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::NotAuthenticated);
}

void tst_OAuth2::getToken()
{
    WebServer webServer([](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        if (request.url.path() == QLatin1String("/accessToken")) {
            const QString text = "access_token=token&token_type=bearer";
            const QByteArray replyMessage {
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
                "Content-Length: " + QByteArray::number(text.size()) + "\r\n\r\n"
                + text.toUtf8()
            };
            socket->write(replyMessage);
        }
    });
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(webServer.url(QLatin1String("authorization")));
    oauth2.setAccessTokenUrl(webServer.url(QLatin1String("accessToken")));
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            this, [&](const QUrl &url) {
        const QUrlQuery query(url.query());
        replyHandler.emitCallbackReceived(QVariantMap {
                                               { QLatin1String("code"), QLatin1String("test") },
                                               { QLatin1String("state"),
                                                 query.queryItemValue(QLatin1String("state")) }
                                           });
    });
    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    oauth2.grant();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), QLatin1String("token"));
}

void tst_OAuth2::refreshToken()
{
    WebServer webServer([](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        if (request.url.path() == QLatin1String("/accessToken")) {
            const QString text = "access_token=token&token_type=bearer";
            const QByteArray replyMessage {
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
                "Content-Length: " + QByteArray::number(text.size()) + "\r\n\r\n"
                + text.toUtf8()
            };
            socket->write(replyMessage);
        }
    });
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAccessTokenUrl(webServer.url(QLatin1String("accessToken")));
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    oauth2.setRefreshToken(QLatin1String("refresh_token"));
    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    oauth2.refreshAccessToken();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), QLatin1String("token"));
}

void tst_OAuth2::getAndRefreshToken()
{
    // In this test we use the grant_type as a token to be able to
    // identify the token request from the token refresh.
    WebServer webServer([](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        if (request.url.path() == QLatin1String("/accessToken")) {
            const QUrlQuery query(request.body);
            const QString format = QStringLiteral("access_token=%1&token_type=bearer&expires_in=1&"
                                                  "refresh_token=refresh_token");
            const auto text = format.arg(query.queryItemValue(QLatin1String("grant_type")));
            const QByteArray replyMessage {
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
                "Content-Length: " + QByteArray::number(text.size()) + "\r\n\r\n"
                + text.toUtf8()
            };
            socket->write(replyMessage);
        }
    });
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(webServer.url(QLatin1String("authorization")));
    oauth2.setAccessTokenUrl(webServer.url(QLatin1String("accessToken")));
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            this, [&](const QUrl &url) {
        const QUrlQuery query(url.query());
        replyHandler.emitCallbackReceived(QVariantMap {
                                              { QLatin1String("code"), QLatin1String("test") },
                                              { QLatin1String("state"),
                                                query.queryItemValue(QLatin1String("state")) }
                                          });
    });
    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    oauth2.grant();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), QLatin1String("authorization_code"));
    grantedSpy.clear();
    oauth2.refreshAccessToken();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), QLatin1String("refresh_token"));
}

void tst_OAuth2::tokenRequestErrors()
{
    // This test tests the token acquisition and refreshing errors.
    // Helper to catch the expected warning messages:
    constexpr auto expectWarning = [](){
        static const QRegularExpression tokenWarning{"Token request failed:.*"};
        QTest::ignoreMessage(QtWarningMsg, tokenWarning);
    };

    QByteArray accessTokenResponse; // Varying reply for the auth server
    WebServer authServer([&](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        if (request.url.path() == QLatin1String("/accessToken"))
            socket->write(accessTokenResponse);
    });

    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(authServer.url(QLatin1String("authorization")));
    oauth2.setAccessTokenUrl(authServer.url(QLatin1String("accessToken")));

    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);

    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);
    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    QSignalSpy statusSpy(&oauth2, &QAbstractOAuth2::statusChanged);
    auto clearSpies = [&](){
        requestFailedSpy.clear();
        grantedSpy.clear();
        statusSpy.clear();
    };

    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            &oauth2, [&](const QUrl &url) {
        // Successful authorization stage, after which we can test token requests.
        // For clarity: in these tests we omit browser interaction by directly triggering
        // the emission of replyhandler::callbackReceived() signal
        const QUrlQuery query(url.query());
        replyHandler.emitCallbackReceived(QVariantMap {
            { QLatin1String("code"), QLatin1String("test") },
            { QLatin1String("state"),
             query.queryItemValue(QLatin1String("state")) }
        });
    });

    // Check the initial state
    QVERIFY(requestFailedSpy.isEmpty());
    QVERIFY(grantedSpy.isEmpty());
    QVERIFY(statusSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::NotAuthenticated);

    // Try to get an access token with an invalid response
    accessTokenResponse = "an invalid response"_ba;
    expectWarning();
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QVERIFY(grantedSpy.isEmpty());
    QCOMPARE(statusSpy.size(), 1); // Authorization was successful so we get one signal
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::TemporaryCredentialsReceived);

    // Try to get an access token, but replyhandler indicates an error
    clearSpies();
    replyHandler.aTokenRequestError = QAbstractOAuth::Error::NetworkError;
    expectWarning();
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QVERIFY(grantedSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::TemporaryCredentialsReceived);

    // Make a successful access & refresh token acquisition
    replyHandler.aTokenRequestError = QAbstractOAuth::Error::NoError;
    clearSpies();
    accessTokenResponse =
        "HTTP/1.0 200 OK\r\n"
        "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
        "\r\n"
        "access_token=the_access_token&token_type=bearer&refresh_token=the_refresh_token"_ba;
    oauth2.grant();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(statusSpy.size(), 3);
    // First status change is going from TempCred back to NotAuthenticated
    QCOMPARE(statusSpy.takeFirst().at(0).value<QAbstractOAuth::Status>(),
             QAbstractOAuth::Status::NotAuthenticated);
    QCOMPARE(statusSpy.takeFirst().at(0).value<QAbstractOAuth::Status>(),
             QAbstractOAuth::Status::TemporaryCredentialsReceived);
    QCOMPARE(statusSpy.takeFirst().at(0).value<QAbstractOAuth::Status>(),
             QAbstractOAuth::Status::Granted);
    QVERIFY(requestFailedSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::Granted);
    QCOMPARE(oauth2.token(), u"the_access_token"_s);
    QCOMPARE(oauth2.refreshToken(), u"the_refresh_token"_s);

    // Successfully refresh access token
    clearSpies();
    oauth2.refreshAccessToken();
    QTRY_COMPARE(statusSpy.size(), 2);
    QCOMPARE(statusSpy.takeFirst().at(0).value<QAbstractOAuth::Status>(),
             QAbstractOAuth::Status::RefreshingToken);
    QCOMPARE(statusSpy.takeFirst().at(0).value<QAbstractOAuth::Status>(),
             QAbstractOAuth::Status::Granted);
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::Granted);
    QVERIFY(requestFailedSpy.isEmpty());

    // Failed access token refresh
    clearSpies();
    replyHandler.aTokenRequestError = QAbstractOAuth::Error::ServerError;
    expectWarning();
    oauth2.refreshAccessToken();
    QTRY_COMPARE(statusSpy.size(), 2);
    QCOMPARE(statusSpy.takeFirst().at(0).value<QAbstractOAuth::Status>(),
             QAbstractOAuth::Status::RefreshingToken);
    QCOMPARE(statusSpy.takeFirst().at(0).value<QAbstractOAuth::Status>(),
             QAbstractOAuth::Status::Granted); // back to granted since we have an access token
    QCOMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::Granted);
}

void tst_OAuth2::prepareRequest()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setToken(QStringLiteral("access_token"));

    QNetworkRequest request(QUrl("http://localhost"));
    oauth2.prepareRequest(&request, QByteArray());
    QCOMPARE(request.rawHeader("Authorization"), QByteArray("Bearer access_token"));
}

using Method = QOAuth2AuthorizationCodeFlow::PkceMethod;

void tst_OAuth2::pkce_data()
{
    QTest::addColumn<Method>("method");
    QTest::addColumn<quint8>("verifierLength");

    QTest::addRow("none") << Method::None << quint8(43);
    QTest::addRow("plain_43") << Method::Plain << quint8(43);
    QTest::addRow("plain_77") << Method::Plain << quint8(77);
    QTest::addRow("S256_43") << Method::S256 << quint8(43);
    QTest::addRow("S256_88") << Method::S256 << quint8(88);
}

void tst_OAuth2::pkce()
{
    QFETCH(Method, method);
    QFETCH(quint8, verifierLength);

    static constexpr auto code_verifier = "code_verifier"_L1;
    static constexpr auto code_challenge = "code_challenge"_L1;
    static constexpr auto code_challenge_method = "code_challenge_method"_L1;

    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(QUrl("authorization_url"));
    oauth2.setAccessTokenUrl(QUrl("access_token_url"));
    oauth2.setState("a_state"_L1);
    QCOMPARE(oauth2.pkceMethod(), Method::S256); // the default
    oauth2.setPkceMethod(method, verifierLength);
    QCOMPARE(oauth2.pkceMethod(), method);

    QMultiMap<QString, QVariant> tokenRequestParms;
    oauth2.setModifyParametersFunction(
        [&] (QAbstractOAuth::Stage stage, QMultiMap<QString, QVariant> *parameters) {
            if (stage == QAbstractOAuth::Stage::RequestingAccessToken)
                tokenRequestParms = *parameters;
    });

    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    QSignalSpy openBrowserSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser);

    oauth2.grant(); // Initiate authorization

    // 1. Verify the authorization URL query parameters
    QTRY_VERIFY(!openBrowserSpy.isEmpty());
    auto authParms = QUrlQuery{openBrowserSpy.takeFirst().at(0).toUrl()};
    QVERIFY(!authParms.hasQueryItem(code_verifier));
    const auto codeChallenge = authParms.queryItemValue(code_challenge).toLatin1();
    if (method == Method::None) {
        QVERIFY(!authParms.hasQueryItem(code_challenge));
        QVERIFY(!authParms.hasQueryItem(code_challenge_method));
    } else if (method == Method::Plain) {
        QCOMPARE(codeChallenge.size(), verifierLength); // With plain the challenge == verifier
        QCOMPARE(authParms.queryItemValue(code_challenge_method), "plain"_L1);
    } else { // S256
        QCOMPARE(codeChallenge.size(), 43); // SHA-256 is 32 bytes, and that in base64 is ~43 bytes
        QCOMPARE(authParms.queryItemValue(code_challenge_method), "S256"_L1);
    }

    // Conclude authorization => starts access token request
    emit replyHandler.callbackReceived({{"code", "acode"}, {"state", "a_state"}});

    // 2. Verify the access token request parameters
    QTRY_VERIFY(!tokenRequestParms.isEmpty());
    QVERIFY(!tokenRequestParms.contains(code_challenge));
    QVERIFY(!tokenRequestParms.contains(code_challenge_method));
    // Verify the challenge received earlier was based on the verifier we receive here
    if (method == Method::None) {
        QVERIFY(!tokenRequestParms.contains(code_verifier));
    } else if (method == Method::Plain) {
        QVERIFY(tokenRequestParms.contains(code_verifier));
        QCOMPARE(tokenRequestParms.value(code_verifier).toByteArray(), codeChallenge);
    } else { // S256
        QVERIFY(tokenRequestParms.contains(code_verifier));
        const auto codeVerifier = tokenRequestParms.value(code_verifier).toByteArray();
        QCOMPARE(codeVerifier.size(), verifierLength);
        QCOMPARE(QCryptographicHash::hash(codeVerifier, QCryptographicHash::Algorithm::Sha256)
                 .toBase64(QByteArray::Base64Option::Base64UrlEncoding | QByteArray::Base64Option::OmitTrailingEquals)
                 , codeChallenge);
    }
}

void tst_OAuth2::nonce()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    const auto nonce = "a_nonce"_ba;

    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    oauth2.setAuthorizationUrl({"authorizationUrl"_L1});
    oauth2.setAccessTokenUrl({"accessTokenUrl"_L1});

    QByteArray nonceInAuthorizationUrl;
    connect(&oauth2, &QAbstractOAuth::authorizeWithBrowser, this, [&](const QUrl &url){
        QUrlQuery parameters(url);
        nonceInAuthorizationUrl = parameters.queryItemValue(u"nonce"_s).toUtf8();
    });

    // Test setting nonce mode
    QSignalSpy nonceModeSpy(&oauth2, &QAbstractOAuth2::nonceModeChanged);
    // -- Default
    QCOMPARE(oauth2.nonceMode(), QAbstractOAuth2::NonceMode::Automatic);
    // -- Change
    oauth2.setNonceMode(QAbstractOAuth2::NonceMode::Disabled);
    QCOMPARE(nonceModeSpy.size(), 1);
    QCOMPARE(nonceModeSpy.at(0).at(0).value<QAbstractOAuth2::NonceMode>(),
             QAbstractOAuth2::NonceMode::Disabled);
    QCOMPARE(oauth2.nonceMode(), QAbstractOAuth2::NonceMode::Disabled);
    // -- Attempt to change again, but to same value
    oauth2.setNonceMode(QAbstractOAuth2::NonceMode::Disabled);
    QCOMPARE(nonceModeSpy.size(), 1);
    QCOMPARE(oauth2.nonceMode(), QAbstractOAuth2::NonceMode::Disabled);

    // Test setting nonce value
    QSignalSpy nonceSpy(&oauth2, &QAbstractOAuth2::nonceChanged);
    // -- Default
    QVERIFY(oauth2.nonce().isEmpty());
    // -- Change
    oauth2.setNonce(nonce);
    QCOMPARE(nonceSpy.size(), 1);
    QCOMPARE(nonceSpy.at(0).at(0).toByteArray(), nonce);
    QCOMPARE(oauth2.nonce(), nonce);
    // -- Attempt to change again, but to same value
    oauth2.setNonce(nonce);
    QCOMPARE(nonceSpy.size(), 1);
    QCOMPARE(oauth2.nonce(), nonce);

    // Verify that nonce is set to authorization request when appropriate
    oauth2.setNonce(nonce);
    oauth2.setRequestedScope({u"scope_item1"_s});

    // -- Nonce is always included
    oauth2.setNonceMode(QAbstractOAuth2::NonceMode::Enabled);
    oauth2.grant();
    QCOMPARE(nonceInAuthorizationUrl, nonce);

    // -- Nonce is never included
    oauth2.setNonceMode(QAbstractOAuth2::NonceMode::Disabled);
    oauth2.grant();
    QVERIFY(nonceInAuthorizationUrl.isEmpty());

    // -- Nonce is included if scope contains 'openid'
    oauth2.setNonceMode(QAbstractOAuth2::NonceMode::Automatic);
    oauth2.grant();
    QVERIFY(nonceInAuthorizationUrl.isEmpty());

    oauth2.setRequestedScope({u"scope_item1"_s, u"openid"_s});
    oauth2.grant();
    QCOMPARE(nonceInAuthorizationUrl, nonce);

    // -- Clear nonce, one should be generated
    oauth2.setNonce("");
    QVERIFY(oauth2.nonce().isEmpty());
    oauth2.grant();
    QVERIFY(!oauth2.nonce().isEmpty());
    QCOMPARE(nonceInAuthorizationUrl, oauth2.nonce());
}

static QString createSignedJWT(const QVariantMap &header = {}, const QVariantMap &payload = {})
{
    auto base64Encode = [](const QByteArray &input) {
        return input.toBase64(QByteArray::Base64UrlEncoding | QByteArray::OmitTrailingEquals);
    };
    // Repeating values which can be overridden and augmented by the supplied 'header' and 'payload'
    QVariantMap mergedHeader = {{"alg", "HS256"},
                                {"typ", "JWT"}};
    QVariantMap mergedPayload = {{"iss", "https://tst_oauth2.example.com"},
                                 {"sub", "tst_oauth2"},
                                 {"aud", "tst_oauth2_client_id"},
                                 {"exp", QDateTime::currentSecsSinceEpoch() + 300}, // valid 5 mins
                                 {"iat", QDateTime::currentSecsSinceEpoch()}, // issued now
                                 {"name", "No Body"},
                                 {"email", "no.body@example.com"}};
    mergedHeader.insert(header);
    mergedPayload.insert(payload);

    // Signed JWT within OIDC context is: header.payload.signature (separated with dots)
    auto header64 =
        base64Encode(QJsonDocument::fromVariant(mergedHeader).toJson(QJsonDocument::Compact));
    auto payload64 =
        base64Encode(QJsonDocument::fromVariant(mergedPayload).toJson(QJsonDocument::Compact));
    auto token = header64 + "." + payload64;
    auto signature64 =
        base64Encode(QMessageAuthenticationCode::hash(token, "secret", QCryptographicHash::Sha256));
    token = token + "." + signature64;
    return token;
}

void tst_OAuth2::idToken()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setRequestedScope({"openid"_L1});
    oauth2.setAuthorizationUrl({"authorizationUrl"_L1});
    oauth2.setAccessTokenUrl({"accessTokenUrl"_L1});
    oauth2.setState("a_state"_L1);
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    QSignalSpy idTokenSpy(&oauth2, &QAbstractOAuth2::idTokenChanged);
    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);

    // Verify default token is empty
    QVERIFY(oauth2.idToken().isEmpty());

    // Test without openid and verify idToken doesn't change
    oauth2.setRequestedScope({"read"_L1});
    oauth2.grant();
    // Conclude authorization stage in order to proceed to access token stage
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}});
    // Conclude access token stage, during which the id token is (would be) provided
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}});
    QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted);
    QVERIFY(idTokenSpy.isEmpty());
    QVERIFY(oauth2.idToken().isEmpty());

    // Test with openid
    // Note: using a proper JWT or setting the matching 'nonce' is not required for this tests
    // purpose as we don't currently validate the received token, but no harm in being thorough
    auto idToken = createSignedJWT({}, {{"nonce"_L1, oauth2.nonce()}});
    oauth2.setRequestedScope({"openid"_L1});
    oauth2.grant();
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}});
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"id_token"_L1, idToken}});
    QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted);
    QCOMPARE(oauth2.idToken(), idToken);
    QCOMPARE(idTokenSpy.size(), 1);
    QCOMPARE(idTokenSpy.at(0).at(0).toByteArray(), idToken);

    // Test missing id_token error
    QVERIFY(requestFailedSpy.isEmpty());
    const QRegularExpression tokenWarning{"Token request failed: \"ID token not received\""};
    QTest::ignoreMessage(QtWarningMsg, tokenWarning);
    oauth2.grant();
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}});
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}});
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<QAbstractOAuth::Error>(),
             QAbstractOAuth::Error::OAuthTokenNotFoundError);
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::TemporaryCredentialsReceived);
    // idToken is cleared on failure
    QCOMPARE(idTokenSpy.size(), 2);
    QVERIFY(oauth2.idToken().isEmpty());
}

#if QT_DEPRECATED_SINCE(6, 11)
QT_WARNING_PUSH QT_WARNING_DISABLE_DEPRECATED
void tst_OAuth2::scope_data()
{
    static const auto requestedScope = u"requested"_s;
    QTest::addColumn<QString>("scope");
    QTest::addColumn<QString>("granted_scope");
    QTest::addColumn<QString>("expected_scope");

    QTest::addRow("scope_returned") << requestedScope << requestedScope << requestedScope;
    QTest::addRow("differing_scope_returned") << requestedScope << u"granted"_s << u"granted"_s;
    QTest::addRow("empty_scope_returned") << requestedScope << u""_s << requestedScope;
}

void tst_OAuth2::scope()
{
    QFETCH(QString, scope);
    QFETCH(QString, granted_scope);
    QFETCH(QString, expected_scope);

    QOAuth2AuthorizationCodeFlow oauth2;
    QVERIFY(oauth2.scope().isEmpty());

    // Set the requested scope and verify it changes
    QSignalSpy scopeSpy(&oauth2, &QAbstractOAuth2::scopeChanged);
    oauth2.setScope(scope);
    QCOMPARE(scopeSpy.size(), 1);
    QCOMPARE(oauth2.scope(), scope);
    QCOMPARE(scopeSpy.at(0).at(0).toString(), scope);

    // Verify that empty authorization server 'scope' response doesn't overwrite the
    // requested scope, whereas a returned scope value does
    WebServer webServer([granted_scope](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        if (request.url.path() == "/accessTokenUrl"_L1) {
            QString accessTokenResponseParams;
            accessTokenResponseParams += u"access_token=token&token_type=bearer"_s;
            if (!granted_scope.isEmpty())
                accessTokenResponseParams += u"&scope="_s + granted_scope;
            const QByteArray replyMessage {
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
                "Content-Length: "
                + QByteArray::number(accessTokenResponseParams.size()) + "\r\n\r\n"
                + accessTokenResponseParams.toUtf8()
            };
            socket->write(replyMessage);
        }
    });
    oauth2.setAuthorizationUrl(webServer.url("authorizationUrl"_L1));
    oauth2.setAccessTokenUrl(webServer.url("accessTokenUrl"_L1));
    oauth2.setState("a_state"_L1);
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            this, [&](const QUrl &) {
                replyHandler.emitCallbackReceived(QVariantMap {
                    { "code"_L1, "a_code"_L1 }, { "state"_L1, "a_state"_L1 },
        });
    });
    oauth2.grant();

    QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted);
    QCOMPARE(oauth2.scope(), expected_scope);
    if (!granted_scope.isEmpty() && (granted_scope != scope)) {
        QCOMPARE(scopeSpy.size(), 2);
        QCOMPARE(scopeSpy.at(1).at(0).toString(), expected_scope);
    } else {
        QCOMPARE(scopeSpy.size(), 1);
    }
}

void tst_OAuth2::scopeAndRequestedScope_data()
{
    const QString f = u"first"_s;
    const QString s = u"second"_s;
    const QString fs = u"first second"_s;

    QTest::addColumn<QString>("scope");
    QTest::addColumn<QString>("expected_scope");
    QTest::addColumn<QStringList>("requested_scope");
    QTest::addColumn<QString>("expected_resulting_request_scope");

    QTest::addRow("singlescope") << f << f << QStringList{f} << f;
    QTest::addRow("multiscope") << fs << fs << QStringList{f, s} << fs;
}

void tst_OAuth2::scopeAndRequestedScope()
{
    QFETCH(QString, scope);
    QFETCH(QString, expected_scope);
    QFETCH(QStringList, requested_scope);
    QFETCH(QString, expected_resulting_request_scope);

    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl({"authorizationUrl"_L1});
    oauth2.setAccessTokenUrl({"accessTokenUrl"_L1});
    QVERIFY(oauth2.scope().isEmpty());
    QVERIFY(oauth2.requestedScope().isEmpty());

    QSignalSpy scopeSpy(&oauth2, &QAbstractOAuth2::scopeChanged);
    QSignalSpy requestedScopeSpy(&oauth2, &QAbstractOAuth2::requestedScopeChanged);
    QString resultingRequestScope;
    QObject::connect(&oauth2, &QAbstractOAuth2::authorizeWithBrowser, this,
                     [&resultingRequestScope](const QUrl &url) {
                         QUrlQuery queryParameters(url);
                         resultingRequestScope = queryParameters.queryItemValue(u"scope"_s);
                     });

    // Set 'scope' and verify that both 'scope' and 'requestedScope' change
    oauth2.setScope(scope);

    QCOMPARE(scopeSpy.size(), 1);
    QCOMPARE(oauth2.scope(), expected_scope);
    QCOMPARE(scopeSpy.at(0).at(0).toString(), expected_scope);

    QCOMPARE(requestedScopeSpy.size(), 1);
    QCOMPARE(oauth2.requestedScope(), requested_scope);
    QCOMPARE(requestedScopeSpy.at(0).at(0).toStringList(), requested_scope);

    oauth2.grant();
    QCOMPARE(resultingRequestScope, expected_resulting_request_scope);

    // Clear data
    oauth2.setScope(u""_s);
    oauth2.setRequestedScope({});
    resultingRequestScope.clear();
    scopeSpy.clear();
    requestedScopeSpy.clear();

    // Set 'requestedScope' and verify that both 'scope' and 'requestedScope' change
    oauth2.setRequestedScope(requested_scope);

    QCOMPARE(requestedScopeSpy.size(), 1);
    QCOMPARE(oauth2.requestedScope(), requested_scope);
    QCOMPARE(requestedScopeSpy.at(0).at(0).toStringList(), requested_scope);

    QCOMPARE(scopeSpy.size(), 1);
    QCOMPARE(oauth2.scope(), expected_scope);
    QCOMPARE(scopeSpy.at(0).at(0).toString(), expected_scope);

    oauth2.grant();
    QCOMPARE(resultingRequestScope, expected_resulting_request_scope);
}
QT_WARNING_POP
#endif // QT_DEPRECATED_SINCE(6, 11)

void tst_OAuth2::requestedScope_data()
{
    const QString f = u"first"_s;
    const QString s = u"second"_s;
    const QString fs = u"first second"_s;

    QTest::addColumn<QStringList>("requested_scope");
    QTest::addColumn<QStringList>("expected_requested_scope");
    QTest::addColumn<QString>("expected_resulting_request_scope");

    QTest::addRow("singlescope") << QStringList{f} << QStringList{f} << f;
    QTest::addRow("multiscope")  << QStringList{f, s} << QStringList{f, s} << fs;
}

void tst_OAuth2::requestedScope()
{
    QFETCH(QStringList, requested_scope);
    QFETCH(QStringList, expected_requested_scope);
    QFETCH(QString, expected_resulting_request_scope);

    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl({"authorizationUrl"_L1});
    oauth2.setAccessTokenUrl({"accessTokenUrl"_L1});
    QVERIFY(oauth2.requestedScope().isEmpty());

    QSignalSpy requestedScopeSpy(&oauth2, &QAbstractOAuth2::requestedScopeChanged);
    QString resultingRequestScope;
    QObject::connect(&oauth2, &QAbstractOAuth2::authorizeWithBrowser, this,
                     [&resultingRequestScope](const QUrl &url) {
                         QUrlQuery queryParameters(url);
                         resultingRequestScope = queryParameters.queryItemValue(u"scope"_s);
                     });

    oauth2.setRequestedScope(requested_scope);

    QCOMPARE(requestedScopeSpy.size(), 1);
    QCOMPARE(oauth2.requestedScope(), expected_requested_scope);
    QCOMPARE(requestedScopeSpy.at(0).at(0).toStringList(), expected_requested_scope);

    oauth2.grant();
    QCOMPARE(resultingRequestScope, expected_resulting_request_scope);
}

void tst_OAuth2::grantedScope_data()
{
    const QStringList requestedScope = {u"first"_s, u"second"_s};
    const QString scope = u"first second"_s;
    const QString granted1 = u"granted1"_s;
    const QString granted2 = u"granted2"_s;
    const QString grantedJoined = granted1 + u" "_s + granted2;
    const QStringList grantedList = {granted1, granted2};

    QTest::addColumn<QStringList>("requested_scope");
    QTest::addColumn<QString>("granted_scope");
    QTest::addColumn<QStringList>("expected_granted_scope");

    QTest::addRow("requested_scope_returned")
        << requestedScope << scope << requestedScope;

    QTest::addRow("differing_singlescope_returned")
        << requestedScope << granted1 << QStringList{granted1};

    QTest::addRow("differing_multiscope_returned")
        << requestedScope << grantedJoined << grantedList;

    QTest::addRow("empty_scope_returned")
        << requestedScope << u""_s << requestedScope;
}

void tst_OAuth2::grantedScope()
{
    QFETCH(QStringList, requested_scope);
    QFETCH(QString, granted_scope);
    QFETCH(QStringList, expected_granted_scope);

    QOAuth2AuthorizationCodeFlow oauth2;
    QSignalSpy grantedSpy(&oauth2, &QAbstractOAuth2::grantedScopeChanged);
    oauth2.setRequestedScope(requested_scope);
    oauth2.setAuthorizationUrl({"authorizationUrl"_L1});
    oauth2.setAccessTokenUrl({"accessTokenUrl"_L1});
    oauth2.setState("a_state"_L1);
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);

    oauth2.grant();
    // Conclude authorization stage in order to proceed to access token stage
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}});

    QVariantMap accessTokenResponseParameters;
    if (granted_scope.isEmpty())
        accessTokenResponseParameters = {{"access_token"_L1, "at"_L1}};
    else
        accessTokenResponseParameters = {{"access_token"_L1, "at"_L1}, {"scope"_L1, granted_scope}};
    // Conclude access token stage, during which the granted scope is provided
    replyHandler.emitTokensReceived(accessTokenResponseParameters);

    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.grantedScope(), expected_granted_scope);
    QCOMPARE(grantedSpy.at(0).at(0).toStringList(), expected_granted_scope);
}

#ifndef QT_NO_SSL
static QSslConfiguration createSslConfiguration(QString keyFileName, QString certificateFileName)
{
    QSslConfiguration configuration(QSslConfiguration::defaultConfiguration());

    QFile keyFile(keyFileName);
    if (keyFile.open(QIODevice::ReadOnly)) {
        QSslKey key(keyFile.readAll(), QSsl::Rsa, QSsl::Pem, QSsl::PrivateKey);
        if (!key.isNull()) {
            configuration.setPrivateKey(key);
        } else {
            qCritical() << "Could not parse key: " << keyFileName;
        }
    } else {
        qCritical() << "Could not find key: " << keyFileName;
    }

    QList<QSslCertificate> localCert = QSslCertificate::fromPath(certificateFileName);
    if (!localCert.isEmpty() && !localCert.first().isNull()) {
        configuration.setLocalCertificate(localCert.first());
    } else {
        qCritical() << "Could not find certificate: " << certificateFileName;
    }

    configuration.setPeerVerifyMode(QSslSocket::VerifyPeer);

    return configuration;
}

void tst_OAuth2::setSslConfig()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    QSignalSpy sslConfigSpy(&oauth2, &QAbstractOAuth2::sslConfigurationChanged);

    QVERIFY(sslConfigSpy.isValid());
    QCOMPARE(oauth2.sslConfiguration(), QSslConfiguration());
    QCOMPARE(sslConfigSpy.size(), 0);

    auto config = createSslConfiguration(testDataDir + "certs/selfsigned-server.key",
                                         testDataDir + "certs/selfsigned-server.crt");
    oauth2.setSslConfiguration(config);

    QCOMPARE(oauth2.sslConfiguration(), config);
    QCOMPARE(sslConfigSpy.size(), 1);

    // set same config - nothing happens
    oauth2.setSslConfiguration(config);
    QCOMPARE(sslConfigSpy.size(), 1);

    // change config
    config.setPeerVerifyMode(QSslSocket::VerifyNone);
    oauth2.setSslConfiguration(config);
    QCOMPARE(oauth2.sslConfiguration(), config);
    QCOMPARE(sslConfigSpy.size(), 2);
}

void tst_OAuth2::tlsAuthentication()
{
    if (!QSslSocket::supportsSsl())
        QSKIP("This test will fail because the backend does not support TLS");

    auto rollback = useTemporaryKeychain();

    // erros may vary, depending on backend
    const QSet<QSslError::SslError> expectedErrors{ QSslError::SelfSignedCertificate,
                                                    QSslError::CertificateUntrusted,
                                                    QSslError::HostNameMismatch };
    auto serverConfig = createSslConfiguration(testDataDir + "certs/selfsigned-server.key",
                                               testDataDir + "certs/selfsigned-server.crt");
    TlsWebServer tlsServer([](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        if (request.url.path() == QLatin1String("/accessToken")) {
            const QString text = "access_token=token&token_type=bearer";
            const QByteArray replyMessage {
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
                "Content-Length: " + QByteArray::number(text.size()) + "\r\n\r\n"
                + text.toUtf8()
            };
            socket->write(replyMessage);
        }
    }, serverConfig);
    tlsServer.setExpectedSslErrors(expectedErrors);

    auto clientConfig = createSslConfiguration(testDataDir + "certs/selfsigned-client.key",
                                               testDataDir + "certs/selfsigned-client.crt");
    QNetworkAccessManager nam;
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setNetworkAccessManager(&nam);
    oauth2.setSslConfiguration(clientConfig);
    oauth2.setAuthorizationUrl(tlsServer.url(QLatin1String("authorization")));
    oauth2.setAccessTokenUrl(tlsServer.url(QLatin1String("accessToken")));
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    connect(&oauth2, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser,
            this, [&](const QUrl &url) {
        const QUrlQuery query(url.query());
        replyHandler.emitCallbackReceived(QVariantMap {
                                               { QLatin1String("code"), QLatin1String("test") },
                                               { QLatin1String("state"),
                                                 query.queryItemValue(QLatin1String("state")) }
                                           });
    });
    connect(&nam, &QNetworkAccessManager::sslErrors, this,
        [&expectedErrors](QNetworkReply *r, const QList<QSslError> &errors) {
            QCOMPARE(errors.size(), 2);
            for (const auto &err : errors)
                QVERIFY(expectedErrors.contains(err.error()));
            r->ignoreSslErrors();
        });

    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    oauth2.grant();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), QLatin1String("token"));
}
#endif // !QT_NO_SSL

QTEST_MAIN(tst_OAuth2)
#include "tst_oauth2.moc"
