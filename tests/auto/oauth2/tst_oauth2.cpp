// Copyright (C) 2017 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtTest>

#include <QtNetworkAuth/qabstractoauthreplyhandler.h>
#include <QtNetworkAuth/qoauth2authorizationcodeflow.h>

#include "oauthtestutils.h"
#include "webserver.h"
#include "tlswebserver.h"

using namespace Qt::StringLiterals;
using namespace std::chrono_literals;

#if QT_VERSION < QT_VERSION_CHECK(7, 0, 0)
#define REFRESH_TOKENS(obj) obj.refreshAccessToken()
#else
#define REFRESH_TOKENS(obj) obj.refreshTokens()
#endif

class tst_OAuth2 : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void state();
    void tokenUrlChanged();
    void getToken();
    void refreshToken();
    void getAndRefreshToken();
    void tokenRequestErrors();
    void authorizationErrors();
    void modifyTokenRequests();
    void prepareRequest();
    void pkce_data();
    void pkce();
    void nonce();
    void idToken();
#if QT_REMOVAL_QT7_DEPRECATED_SINCE(6, 13)
    void scope_data();
    void scope();
    void scopeAndRequestedScope_data();
    void scopeAndRequestedScope();
#endif
    void requestedScope_data();
    void requestedScope();
    void grantedScope_data();
    void grantedScope();
    void setAutoRefresh();
    void refreshLeadTime_data();
    void refreshLeadTime();
    void invalidRefreshLeadTime();
    void alreadyExpiredTokenClientSideRefresh();

#ifndef QT_NO_SSL
    void setSslConfig();
    void tlsAuthentication();
#endif
    void extraTokens();
    void expirationAt();

private:
    QString testDataDir;
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
    testDataDir = QFileInfo(QFINDTESTDATA("../shared/certs")).absolutePath();
    if (testDataDir.isEmpty())
        testDataDir = QCoreApplication::applicationDirPath();
    if (!testDataDir.endsWith(QLatin1String("/")))
        testDataDir += QLatin1String("/");
}

void tst_OAuth2::state()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(QUrl{"authorizationUrl"_L1});
    oauth2.setTokenUrl(QUrl{"accessTokenUrl"_L1});
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

void tst_OAuth2::tokenUrlChanged()
{
    QOAuth2AuthorizationCodeFlow oauth2;

    QCOMPARE_EQ(oauth2.tokenUrl(), QUrl());
#if QT_REMOVAL_QT7_DEPRECATED_SINCE(6, 13)
    QT_IGNORE_DEPRECATIONS(QCOMPARE_EQ(oauth2.accessTokenUrl(), QUrl());)
#endif

    const QUrl someTokenUrl{"accessToken"_L1};
    const QUrl otherTokenUrl{"otherAccessToken"_L1};

    // new property
    QSignalSpy tokenUrlChangedSpy(&oauth2, &QAbstractOAuth2::tokenUrlChanged);

    oauth2.setTokenUrl(someTokenUrl);
    QCOMPARE_EQ(oauth2.tokenUrl(), someTokenUrl);
    QCOMPARE_EQ(tokenUrlChangedSpy.size(), 1);
    QCOMPARE_EQ(tokenUrlChangedSpy.at(0).at(0).toUrl(), someTokenUrl);

    // setting the same value does not trigger any update
    tokenUrlChangedSpy.clear();
    oauth2.setTokenUrl(someTokenUrl);
    QCOMPARE_EQ(oauth2.tokenUrl(), someTokenUrl);
    QCOMPARE_EQ(tokenUrlChangedSpy.size(), 0);

    // set another value
    tokenUrlChangedSpy.clear();
    oauth2.setTokenUrl(otherTokenUrl);
    QCOMPARE_EQ(oauth2.tokenUrl(), otherTokenUrl);
    QCOMPARE_EQ(tokenUrlChangedSpy.size(), 1);
    QCOMPARE_EQ(tokenUrlChangedSpy.at(0).at(0).toUrl(), otherTokenUrl);

#if QT_REMOVAL_QT7_DEPRECATED_SINCE(6, 13)
QT_WARNING_PUSH
QT_WARNING_DISABLE_DEPRECATED
    // old property
    tokenUrlChangedSpy.clear();
    QSignalSpy accessTokenUrlChangedSpy(&oauth2,
                                        &QOAuth2AuthorizationCodeFlow::accessTokenUrlChanged);

    oauth2.setAccessTokenUrl(someTokenUrl);
    QCOMPARE_EQ(oauth2.tokenUrl(), someTokenUrl);
    QCOMPARE_EQ(oauth2.accessTokenUrl(), someTokenUrl);
    QCOMPARE_EQ(tokenUrlChangedSpy.size(), 1);
    QCOMPARE_EQ(tokenUrlChangedSpy.at(0).at(0).toUrl(), someTokenUrl);
    QCOMPARE_EQ(accessTokenUrlChangedSpy.size(), 1);
    QCOMPARE_EQ(accessTokenUrlChangedSpy.at(0).at(0).toUrl(), someTokenUrl);

    // setting the same value does not trigger any update
    tokenUrlChangedSpy.clear();
    accessTokenUrlChangedSpy.clear();
    oauth2.setAccessTokenUrl(someTokenUrl);
    QCOMPARE_EQ(oauth2.tokenUrl(), someTokenUrl);
    QCOMPARE_EQ(oauth2.accessTokenUrl(), someTokenUrl);
    QCOMPARE_EQ(tokenUrlChangedSpy.size(), 0);
    QCOMPARE_EQ(accessTokenUrlChangedSpy.size(), 0);

    // set another value
    tokenUrlChangedSpy.clear();
    accessTokenUrlChangedSpy.clear();
    oauth2.setAccessTokenUrl(otherTokenUrl);
    QCOMPARE_EQ(oauth2.tokenUrl(), otherTokenUrl);
    QCOMPARE_EQ(oauth2.accessTokenUrl(), otherTokenUrl);
    QCOMPARE_EQ(tokenUrlChangedSpy.size(), 1);
    QCOMPARE_EQ(tokenUrlChangedSpy.at(0).at(0).toUrl(), otherTokenUrl);
    QCOMPARE_EQ(accessTokenUrlChangedSpy.size(), 1);
    QCOMPARE_EQ(accessTokenUrlChangedSpy.at(0).at(0).toUrl(), otherTokenUrl);
QT_WARNING_POP
#endif
}

QT_WARNING_PUSH QT_WARNING_DISABLE_DEPRECATED
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
#if QT_DEPRECATED_SINCE(6, 13)
    QSignalSpy errorSpy(&oauth2, &QAbstractOAuth2::error);
#endif
    QSignalSpy serverReportedErrorOccurredSpy(&oauth2,
                                              &QAbstractOAuth2::serverReportedErrorOccurred);
    QSignalSpy statusSpy(&oauth2, &QAbstractOAuth2::statusChanged);
    auto clearSpies = [&](){
        requestFailedSpy.clear();
        serverReportedErrorOccurredSpy.clear();
#if QT_DEPRECATED_SINCE(6, 13)
        errorSpy.clear();
#endif
        statusSpy.clear();
    };

    // Test error response from the authorization server (RFC 6749 section 5.2)
    callbackParameters = {{"error"_L1, "invalid_grant"_L1},
                          {"error_description"_L1, "The error description"_L1},
                          {"error_uri"_L1, "The error URI"_L1}};
    expectWarning();
    oauth2.grant();
#if QT_DEPRECATED_SINCE(6, 13)
    QTRY_COMPARE(errorSpy.count(), 1);
#endif
    QTRY_COMPARE(serverReportedErrorOccurredSpy.count(), 1);
    QTRY_COMPARE(requestFailedSpy.count(), 1);
#if QT_DEPRECATED_SINCE(6, 13)
    QCOMPARE(errorSpy.first().at(0).toString(), "invalid_grant"_L1);
    QCOMPARE(errorSpy.first().at(1).toString(), "The error description"_L1);
    QCOMPARE(errorSpy.first().at(2).toString(), "The error URI"_L1);
#endif
    QCOMPARE(serverReportedErrorOccurredSpy.first().at(0).toString(), "invalid_grant"_L1);
    QCOMPARE(serverReportedErrorOccurredSpy.first().at(1).toString(), "The error description"_L1);
    QCOMPARE(serverReportedErrorOccurredSpy.first().at(2).toString(), "The error URI"_L1);
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

#if QT_DEPRECATED_SINCE(6, 13)
    QCOMPARE(errorSpy.count(), 0);
#endif
    QCOMPARE(serverReportedErrorOccurredSpy.count(), 0);
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
#if QT_DEPRECATED_SINCE(6, 13)
    QCOMPARE(errorSpy.count(), 0);
#endif
    QCOMPARE(serverReportedErrorOccurredSpy.count(), 0);
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
#if QT_DEPRECATED_SINCE(6, 13)
    QCOMPARE(errorSpy.count(), 0);
#endif
    QCOMPARE(serverReportedErrorOccurredSpy.count(), 0);
    QVERIFY(statusSpy.isEmpty());
    QCOMPARE(oauth2.status(), QAbstractOAuth::Status::NotAuthenticated);
}
QT_WARNING_POP

class RequestModifier : public QObject
{
    Q_OBJECT
public:
    RequestModifier(QObject *parent = nullptr) : QObject(parent) {}

    void handleRequestModification(QNetworkRequest &request, QAbstractOAuth::Stage stage)
    {
        stageReceivedByModifier = stage;
        auto headers = request.headers();
        headers.append("test-header-name"_ba, valueToSet);
        request.setHeaders(headers);
    }
    QAbstractOAuth::Stage stageReceivedByModifier =
        QAbstractOAuth::Stage::RequestingTemporaryCredentials;
    QByteArray valueToSet;
};

#define TEST_MODIFY_REQUEST_WITH_MODIFIER(STAGE_RECEIVED, VALUE_SET, VALUE_PREFIX) \
    { \
        valueReceivedByTokenServer.clear(); \
        STAGE_RECEIVED = QAbstractOAuth::Stage::RequestingTemporaryCredentials; \
        VALUE_SET = QByteArray(VALUE_PREFIX) + "_access_token"; \
        oauth2.grant(); \
        /* Conclude authorization stage so that we proceed into access token request */ \
        replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}}); \
        QTRY_COMPARE(STAGE_RECEIVED, QAbstractOAuth::Stage::RequestingAccessToken); \
        QTRY_COMPARE(valueReceivedByTokenServer, VALUE_SET); \
        QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted); \
        /* Refresh token request */ \
        VALUE_SET = QByteArray(VALUE_PREFIX) + "_refresh_token"; \
        valueReceivedByTokenServer.clear(); \
        STAGE_RECEIVED = QAbstractOAuth::Stage::RequestingTemporaryCredentials; \
        REFRESH_TOKENS(oauth2); \
        QCOMPARE(oauth2.status(), QAbstractOAuth::Status::RefreshingToken); \
        QTRY_COMPARE(STAGE_RECEIVED, QAbstractOAuth::Stage::RefreshingAccessToken); \
        QTRY_COMPARE(valueReceivedByTokenServer, VALUE_SET); \
        QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted); \
        oauth2.clearNetworkRequestModifier(); \
    } \

#define TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(VALUE_SET) \
    { \
        valueReceivedByTokenServer.clear(); \
        VALUE_SET = "must_not_be_set"_ba; \
        oauth2.grant(); \
        /* Conclude authorization stage so that we proceed into access token request */ \
        replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}}); \
        QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted); \
        QVERIFY(valueReceivedByTokenServer.isEmpty()); \
        REFRESH_TOKENS(oauth2); \
        QCOMPARE(oauth2.status(), QAbstractOAuth::Status::RefreshingToken); \
        QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted); \
        QVERIFY(valueReceivedByTokenServer.isEmpty()); \
        oauth2.clearNetworkRequestModifier(); \
    } \

void tst_OAuth2::modifyTokenRequests()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    std::unique_ptr<RequestModifier> context(new RequestModifier);
    QRegularExpression nullContextWarning(u".*Context object must not be null, ignoring"_s);
    QRegularExpression wrongThreadWarning(u".*Context object must reside in the same thread"_s);
    auto valueToSet = ""_ba;

    QByteArray valueReceivedByTokenServer;
    WebServer tokenServer([&](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        valueReceivedByTokenServer = request.headers.value("test-header-name"_ba);
        const QString text = "access_token=token&token_type=bearer";
        const QByteArray replyMessage {
            "HTTP/1.0 200 OK\r\n"
            "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
            "Content-Length: " + QByteArray::number(text.size()) + "\r\n\r\n"
            + text.toUtf8()
        };
        socket->write(replyMessage);
    });
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    oauth2.setRefreshToken(u"refresh_token"_s);
    oauth2.setAuthorizationUrl(tokenServer.url(QLatin1String("authorization")));
    oauth2.setTokenUrl(tokenServer.url(QLatin1String("accessToken")));
    oauth2.setState("a_state"_L1);

    QAbstractOAuth::Stage stageReceivedByModifier =
        QAbstractOAuth::Stage::RequestingTemporaryCredentials;
    auto modifierLambda = [&](QNetworkRequest &request, QAbstractOAuth::Stage stage) {
        stageReceivedByModifier = stage;
        auto headers = request.headers();
        headers.append("test-header-name"_ba, valueToSet);
        request.setHeaders(headers);
    };
    std::function<void(QNetworkRequest &, QAbstractOAuth::Stage)> modifierFunc = modifierLambda;

    // Lambda with a context object
    oauth2.setNetworkRequestModifier(context.get(), modifierLambda);
    TEST_MODIFY_REQUEST_WITH_MODIFIER(stageReceivedByModifier, valueToSet, "lambda_with_context")

    // Test that the modifier will be cleared
    oauth2.clearNetworkRequestModifier();
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet)

    // Lambda without a context object
    QTest::ignoreMessage(QtWarningMsg, nullContextWarning);
    oauth2.setNetworkRequestModifier(nullptr, modifierLambda);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet)

    // std::function with a context object
    oauth2.setNetworkRequestModifier(context.get(), modifierFunc);
    TEST_MODIFY_REQUEST_WITH_MODIFIER(stageReceivedByModifier, valueToSet, "func_with_context")

    // PMF with context object
    oauth2.setNetworkRequestModifier(context.get(), &RequestModifier::handleRequestModification);
    TEST_MODIFY_REQUEST_WITH_MODIFIER(context->stageReceivedByModifier,
                                      context->valueToSet, "pmf_with_context")

    // PMF without context object
    QTest::ignoreMessage(QtWarningMsg, nullContextWarning);
    oauth2.setNetworkRequestModifier(nullptr, &RequestModifier::handleRequestModification);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(context->valueToSet)

    // Destroy context object => no callback (or crash)
    oauth2.setNetworkRequestModifier(context.get(), modifierLambda);
    context.reset(nullptr);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet)

    // Context object in wrong thread
    QThread thread;
    QObject objectInWrongThread;
    // Initially context object is in correct thread
    oauth2.setNetworkRequestModifier(&objectInWrongThread, modifierLambda);
    // Move to wrong thread, verify we get warnings when it's time to call the callback
    objectInWrongThread.moveToThread(&thread);
    oauth2.grant();
    QTest::ignoreMessage(QtWarningMsg, wrongThreadWarning);
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}});
    QTRY_COMPARE(oauth2.status(), QAbstractOAuth::Status::Granted);
    // Now the context object is in wrong thread when attempting to set the modifier
    oauth2.clearNetworkRequestModifier();
    QTest::ignoreMessage(QtWarningMsg, wrongThreadWarning);
    oauth2.setNetworkRequestModifier(&objectInWrongThread, modifierLambda);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet)

    // These must not compile
    // oauth2.setRequestModifier();
    // oauth2.setRequestModifier(&context, [](const QString& wrongType){});
    // oauth2.setRequestModifier(&context, [](QNetworkRequest &request, int wrongType){});
    // oauth2.setRequestModifier(&context, [](int wrongType, QAbstractOAuth::Stage stage){});
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
    oauth2.setTokenUrl(webServer.url(QLatin1String("accessToken")));
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
#if QT_REMOVAL_QT7_DEPRECATED_SINCE(6, 13)
    QT_IGNORE_DEPRECATIONS(oauth2.setAccessTokenUrl(webServer.url(QLatin1String("accessToken")));)
#else
    oauth2.setTokenUrl(webServer.url(QLatin1String("accessToken")));
#endif
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    oauth2.setRefreshToken(QLatin1String("refresh_token"));
    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    REFRESH_TOKENS(oauth2);
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
            const QString format = QStringLiteral("access_token=%1&token_type=bearer&expires_in=20&"
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
    oauth2.setTokenUrl(webServer.url(QLatin1String("accessToken")));
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
    REFRESH_TOKENS(oauth2);
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
    oauth2.setTokenUrl(authServer.url(QLatin1String("accessToken")));

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
    REFRESH_TOKENS(oauth2);
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
    REFRESH_TOKENS(oauth2);
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
    oauth2.setTokenUrl(QUrl("access_token_url"));
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
    oauth2.setTokenUrl({"accessTokenUrl"_L1});

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

void tst_OAuth2::idToken()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setRequestedScope({"openid"_L1});
    oauth2.setAuthorizationUrl({"authorizationUrl"_L1});
    oauth2.setTokenUrl({"accessTokenUrl"_L1});
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

#if QT_REMOVAL_QT7_DEPRECATED_SINCE(6, 13)
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
#endif // QT_REMOVAL_QT7_DEPRECATED_SINCE(6, 13)

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
    oauth2.setTokenUrl({"accessTokenUrl"_L1});
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
    oauth2.setTokenUrl({"accessTokenUrl"_L1});
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

void tst_OAuth2::setAutoRefresh()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    QSignalSpy autoRefreshSpy(&oauth2, &QAbstractOAuth2::autoRefreshChanged);

    QCOMPARE(oauth2.autoRefresh(), false);

    oauth2.setAutoRefresh(true);
    QTRY_COMPARE(autoRefreshSpy.size(), 1);
    QCOMPARE(oauth2.autoRefresh(), true);
    QCOMPARE(autoRefreshSpy.at(0).at(0).toBool(), true);

    autoRefreshSpy.clear();
    oauth2.setAutoRefresh(false);
    QTRY_COMPARE(autoRefreshSpy.size(), 1);
    QCOMPARE(oauth2.autoRefresh(), false);
    QCOMPARE(autoRefreshSpy.at(0).at(0).toBool(), false);
}

void tst_OAuth2::refreshLeadTime_data()
{
    QTest::addColumn<std::chrono::seconds>("refreshLeadTime");
    QTest::addColumn<int>("expiresIn");
    QTest::addColumn<std::chrono::seconds>("waitTimeForExpiration");
    QTest::addColumn<bool>("autoRefresh");
    QTest::addColumn<bool>("expectExpirationSignal");
    QTest::addColumn<QString>("refreshToken");
    QTest::addColumn<bool>("expectRefreshRequest");

    const QString refreshToken = u"refreshToken"_s;

    // wait-time: 20s - 18s = 2s, + 1s for robustness => 3s
    QTest::addRow("validSetExpiration")
            << 18s << 20 << 3s << true  << true  << refreshToken << true;

    // wait-time calculation: 15s - 10s = 5s, + 1s for robustness => 6s
    QTest::addRow("validCalculatedExpiration")
            << 0s  << 15 << 6s << true  << true  << refreshToken << true;

    // wait-time: 5s - 10s = -5s => 2s minimum + 1s for robustness => 3s
    QTest::addRow("tooShortCalculatedExpiration")
            << 0s  << 5 << 3s  << true  << true  << refreshToken << true;

    // wait-time: 5s - 10s = -5s => 2s minimum + 1s for robustness => 3s
    QTest::addRow("tooShortSetExpiration")
            << 10s  << 5 << 3s << true  << true  << refreshToken << true;

    // wait-time: 3s - 1s = 2s, +1s for robustness => 3s
    QTest::addRow("leadTimeNearExpiration")
            << 1s  << 3 << 3s  << true  << true << refreshToken << true;

    QTest::addRow("invalidExpirationTime")
            << 1s  << 0 << 3s  << true  << false << refreshToken << false;

    // wait-time: 2s - 1s = 1s, => minimum 2s + 1s for robustness => 2s
    QTest::addRow("autoRefreshDisabled")
            << 1s  << 2 << 3s  << false << true  << refreshToken << false;

    QTest::addRow("emptyRefreshToken")
            << 18s << 20 << 3s << true  << true << QString() << false;
}

void tst_OAuth2::refreshLeadTime()
{
    QFETCH(std::chrono::seconds, refreshLeadTime);
    QFETCH(int, expiresIn);
    QFETCH(std::chrono::seconds, waitTimeForExpiration);
    QFETCH(bool, autoRefresh);
    QFETCH(bool, expectExpirationSignal);
    QFETCH(QString, refreshToken);
    QFETCH(bool, expectRefreshRequest);

    QString accessToken = u"initial-access-token"_s;
    WebServer webServer([&](const WebServer::HttpRequest &request, QTcpSocket *socket) {
        if (request.url.path() == QLatin1String("/accessToken")) {
            const QString parameters = u"access_token="_s + accessToken
                                       + u"&token_type=bearer&expires_in=%1&refresh_token=%2"_s;
            const auto httpBody = parameters.arg(QString::number(expiresIn), refreshToken);
            const QByteArray replyMessage {
                "HTTP/1.0 200 OK\r\n"
                "Content-Type: application/x-www-form-urlencoded; charset=\"utf-8\"\r\n"
                "Content-Length: " + QByteArray::number(httpBody.size()) + "\r\n\r\n"
                + httpBody.toUtf8()
            };
            socket->write(replyMessage);
        }
    });
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(webServer.url("authorizationUrl"));
    oauth2.setTokenUrl(webServer.url("accessToken"));
    oauth2.setState("s"_L1);
    oauth2.setRefreshLeadTime(refreshLeadTime);
    oauth2.setAutoRefresh(autoRefresh);

    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);

    QSignalSpy expiredSpy(&oauth2, &QAbstractOAuth2::accessTokenAboutToExpire);
    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    oauth2.grant();
    replyHandler.emitCallbackReceived(QVariantMap {{ "code"_L1, "c"_L1 }, { "state"_L1, "s"_L1 }});
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), u"initial-access-token"_s);

    if (expectExpirationSignal) {
        accessToken = u"refreshed-access-token"_s;
        QTRY_COMPARE_WITH_TIMEOUT(expiredSpy.size(), 1, waitTimeForExpiration);
        if (expectRefreshRequest) {
            QTRY_COMPARE(oauth2.token(), "refreshed-access-token"_L1);
            QCOMPARE(expiredSpy.size(), 1);
        }
    }
}

void tst_OAuth2::invalidRefreshLeadTime()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    QCOMPARE(oauth2.refreshLeadTime(), 0s);
    QTest::ignoreMessage(QtWarningMsg, "Invalid refresh leadTime");
    oauth2.setRefreshLeadTime(-5s);
    QCOMPARE(oauth2.refreshLeadTime(), 0s);
}

void tst_OAuth2::alreadyExpiredTokenClientSideRefresh()
{
    // This tests a particular corner-case where user adjusts leadTime such
    // that the pre-existing token is updated immediately
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl(QUrl("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(QUrl("accessTokenEndpoint"_L1));
    oauth2.setState("s"_L1);

    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);

    QSignalSpy expiredSpy(&oauth2, &QAbstractOAuth2::accessTokenAboutToExpire);
    QSignalSpy grantedSpy(&oauth2, &QOAuth2AuthorizationCodeFlow::granted);
    oauth2.grant();
    replyHandler.emitCallbackReceived(QVariantMap {{ "code"_L1, "c"_L1 }, { "state"_L1, "s"_L1 }});
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"scope"_L1, "scope"},
                                     {"refresh_token"_L1, "refreshToken"_L1},
                                     {"expires_in"_L1, 3}});
    QTRY_COMPARE(grantedSpy.size(), 1);
    // Triggers an immediate expiration because from leadTime point-of-view the
    // token is either expired or should've expired already
    expiredSpy.clear();
    oauth2.setRefreshLeadTime(10s);
    QCOMPARE(expiredSpy.size(), 1);
}

#ifndef QT_NO_SSL
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
    oauth2.setTokenUrl(tlsServer.url(QLatin1String("accessToken")));
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

void tst_OAuth2::extraTokens()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl({"authorizationUrl"_L1});
    oauth2.setTokenUrl({"accessTokenUrl"_L1});
    oauth2.setState("a_state"_L1);
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    QSignalSpy extraTokensSpy(&oauth2, &QAbstractOAuth::extraTokensChanged);
    QVERIFY(oauth2.extraTokens().isEmpty());

    constexpr auto name1 = "name1"_L1;
    constexpr auto value1 = "value1"_L1;
    constexpr auto name2 = "name2"_L1;
    constexpr auto value2 = "value2"_L1;

    // Conclude authorization stage without extra tokens
    oauth2.grant();
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}});
    QCOMPARE(extraTokensSpy.size(), 0);

    // Conclude authorization stage with extra tokens
    extraTokensSpy.clear();
    oauth2.grant();
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1},
                                       {name1, value1}});
    QTRY_COMPARE(extraTokensSpy.size(), 1);
    QVariantMap extraTokens = oauth2.extraTokens();
    QCOMPARE(extraTokens, extraTokensSpy.at(0).at(0).toMap());
    QCOMPARE(extraTokens.size(), 1);
    QCOMPARE(extraTokens.value(name1).toString(), value1);

    // Conclude token stage without additional extra tokens
    extraTokensSpy.clear();
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}});
    QCOMPARE(extraTokensSpy.size(), 0);
    extraTokens = oauth2.extraTokens();
    QCOMPARE(extraTokens.size(), 1);
    QCOMPARE(extraTokens.value(name1).toString(), value1);

    // Conclude token stage with additional extra tokens
    extraTokensSpy.clear();
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {name2, value2}});
    QTRY_COMPARE(extraTokensSpy.size(), 1);
    extraTokens = oauth2.extraTokens();
    QCOMPARE(extraTokens, extraTokensSpy.at(0).at(0).toMap());
    QCOMPARE(extraTokens.size(), 2);
    QCOMPARE(extraTokens.value(name1).toString(), value1);
    QCOMPARE(extraTokens.value(name2).toString(), value2);
}

void tst_OAuth2::expirationAt()
{
    QOAuth2AuthorizationCodeFlow oauth2;
    oauth2.setAuthorizationUrl({"authorizationEndpoint"_L1});
    oauth2.setTokenUrl({"tokenEndpoint"_L1});
    oauth2.setState("a_state"_L1);
    ReplyHandler replyHandler;
    oauth2.setReplyHandler(&replyHandler);
    QSignalSpy expirationAtSpy(&oauth2, &QAbstractOAuth2::expirationAtChanged);

    const auto expiresAtIsInSecondsFromNow = [&](int fromNow) -> bool {
        // For test robustness check that the time is within +/- 2 seconds
        return qAbs(
            oauth2.expirationAt().secsTo(QDateTime::currentDateTime().addSecs(fromNow))) <= 2;
    };
    // Initial value
    QVERIFY(!oauth2.expirationAt().isValid());

    // Conclude authorization stage
    oauth2.grant();
    replyHandler.emitCallbackReceived({{"code"_L1, "acode"_L1}, {"state"_L1, "a_state"_L1}});
    QVERIFY(expirationAtSpy.isEmpty());

    // Test expiration in 50 seconds from now
    int expires_in = 50;
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"expires_in", expires_in}});
    QCOMPARE(expirationAtSpy.size(), 1);
    QCOMPARE(expirationAtSpy.at(0).at(0).toDateTime(), oauth2.expirationAt());
    QVERIFY(expiresAtIsInSecondsFromNow(expires_in));
    expirationAtSpy.clear();

    // Changes to 100 seconds from now
    expires_in = 100;
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"expires_in", expires_in}});
    QCOMPARE(expirationAtSpy.size(), 1);
    QCOMPARE(expirationAtSpy.at(0).at(0).toDateTime(), oauth2.expirationAt());
    QVERIFY(expiresAtIsInSecondsFromNow(expires_in));
    expirationAtSpy.clear();

    // Zero expires_in value, expiresAt should become invalid
    expires_in = 0;
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"expires_in", expires_in}});
    QCOMPARE(expirationAtSpy.size(), 1);
    QCOMPARE(expirationAtSpy.at(0).at(0).toDateTime(), oauth2.expirationAt());
    QVERIFY(!oauth2.expirationAt().isValid());
    expirationAtSpy.clear();

    // Negative expires_in value, expiresAt should remain invalid
    expires_in = -10;
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"expires_in", expires_in}});
    QCOMPARE(expirationAtSpy.size(), 0);
    QVERIFY(!oauth2.expirationAt().isValid());
    expirationAtSpy.clear();

    // Non-number expires_in value, expiresAt should remain invalid
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"expires_in", "garbage"}});
    QCOMPARE(expirationAtSpy.size(), 0);
    QVERIFY(!oauth2.expirationAt().isValid());
    expirationAtSpy.clear();

    // Expiration goes back to valid
    expires_in = 70;
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}, {"expires_in", expires_in}});
    QCOMPARE(expirationAtSpy.size(), 1);
    QCOMPARE(expirationAtSpy.at(0).at(0).toDateTime(), oauth2.expirationAt());
    QVERIFY(expiresAtIsInSecondsFromNow(expires_in));
    expirationAtSpy.clear();

    // Expiration is not provided, expiresAt should become invalid
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}});
    QCOMPARE(expirationAtSpy.size(), 1);
    QCOMPARE(expirationAtSpy.at(0).at(0).toDateTime(), oauth2.expirationAt());
    QVERIFY(!oauth2.expirationAt().isValid());
    expirationAtSpy.clear();

    // Expiration is still not provided, expiresAt should remain unchanged
    replyHandler.emitTokensReceived({{"access_token"_L1, "at"_L1}});
    QCOMPARE(expirationAtSpy.size(), 0);
    QVERIFY(!oauth2.expirationAt().isValid());
}

QTEST_MAIN(tst_OAuth2)
#include "tst_oauth2.moc"
