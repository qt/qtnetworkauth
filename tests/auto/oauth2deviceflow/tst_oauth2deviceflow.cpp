// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtTest>

#include "oauthtestutils.h"
#include "tlswebserver.h"
#include "webserver.h"

#include "private/qoauth2deviceauthorizationflow_p.h"

#include <QtNetworkAuth/qoauth2deviceauthorizationflow.h>

#ifndef QT_NO_SSL
#include <QtNetwork/qsslkey.h>
#endif


#include <QtCore/qoperatingsystemversion.h>
#include <QtCore/qsystemdetection.h>

#include <QtCore/qcryptographichash.h>

using namespace Qt::StringLiterals;
using namespace std::chrono_literals;
using Error = QAbstractOAuth::Error;
using Status = QAbstractOAuth::Status;
using Stage = QAbstractOAuth::Stage;

#if QT_VERSION < QT_VERSION_CHECK(7, 0, 0)
#define REFRESH_TOKENS(obj) obj.refreshAccessToken()
#else
#define REFRESH_TOKENS(obj) obj.refreshTokens()
#endif

class tst_OAuth2DeviceFlow : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void init();
    void initTestCase();
    void getAndRefreshToken();
    void clientError();
    void authorizationErrors();
    void tokenRequestErrors();
    void idToken();
    void nonce();
    void requestedScope_data();
    void requestedScope();
    void grantedScope_data();
    void grantedScope();
    void refreshLeadTime_data();
    void refreshLeadTime();
    void modifyTokenRequests();
    void userCodeExpiration();
    void startStopTokenPolling();
    void destruction_data();
    void destruction();
    void changeNetworkAccessManager();
    void tlsAuthentication();

private:
    QString testDataDir;
    QList<WebServer::HttpRequest> receivedAuthorizationRequests;
    QList<WebServer::HttpRequest> receivedTokenRequests;
    template<typename ServerType, typename... Args>
    ServerType *createAuthorizationServer(const QString &authBody, const QString &authHttpStatus,
                                          const QString &tokenBody, const QString &tokenHttpStatus,
                                          Args&&... args);
};

namespace Responses {
    // Basic successful authorization response. Note that interval is 50,
    // which maps to 50ms if DeviceFlow useAutoTestDurations is true, and 50s
    // otherwise.
    static constexpr auto authorizationSuccess = R"(
        {
            "device_code": "a-device-code",
            "user_code": "a-user-code",
            "verification_uri": "a-verification-uri",
            "verification_uri_complete": "a-verification-uri-complete",
            "expires_in": 1800,
            "interval": 50
        })"_L1;

    static constexpr auto tokenSuccess = R"(
        {
            "access_token": "an-access-token",
            "refresh_token": "a-refresh-token",
            "token_type": "bearer",
            "expires_in": 3600
        })"_L1;

    static constexpr auto tokenAuthorizationPending = R"(
        {
            "error": "authorization_pending",
            "error_description": "User hasnt authorized yet",
            "error_uri": "an-error-uri"
        })"_L1;

    static constexpr auto tokenExpired =  R"(
        {
            "error": "expired_token",
            "error_description": "code expired",
            "error_uri": "an-error-uri"
        })"_L1;

    static constexpr auto OK_200 = "200 OK"_L1;
    static constexpr auto BR_400 = "400 Bad Request"_L1;

    static QString authorizationResponseWithTimes(int interval, int expiration) {
        return R"(
        {
            "device_code": "a-device-code",
            "user_code": "a-user-code",
            "verification_uri": "a-verification-uri",
            "verification_uri_complete": "a-verification-uri-complete",
            "interval": )" + QString::number(interval) + "," +
            R"("expires_in": )" + QString::number(expiration) +
        "}"_L1;
    };
};

// Creates a local http server. The provided arguments are captured
// by reference, meaning that they can be modified at runtime by
// test cases to vary the responses as needed. The template
// is used so that the function can return either WebServer* or TlsWebServer*
template<typename ServerType, typename... Args>
ServerType *tst_OAuth2DeviceFlow::createAuthorizationServer(
        const QString &authBody, const QString &authHttpStatus,
        const QString &tokenBody, const QString &tokenHttpStatus,
        Args&&... args)
{
    auto handler = [&] (const WebServer::HttpRequest &request, QTcpSocket *socket) {
        QByteArray replyMessage;
        if (request.url.path() == "/authorizationEndpoint"_L1) {
            // Set received request for test cases to check
            receivedAuthorizationRequests.append(request);
            replyMessage =
                "HTTP/1.0 " + authHttpStatus.toLatin1() + "\r\n"
                "Content-Type: application/json; charset=\"utf-8\"\r\n"
                "Content-Length: " + QByteArray::number(authBody.toUtf8().size()) + "\r\n\r\n"
                + authBody.toUtf8();
        } else if (request.url.path() == "/tokenEndpoint"_L1) {
            // Set received request for test cases to check
            receivedTokenRequests.append(request);
            replyMessage =
                "HTTP/1.0 " + tokenHttpStatus.toLatin1() + "\r\n"
                "Content-Type: application/json; charset=\"utf-8\"\r\n"
                "Content-Length: " + QByteArray::number(tokenBody.toUtf8().size()) + "\r\n\r\n"
                + tokenBody.toUtf8();
        } else {
            qFatal() << "Unsupported URL:" << request.url;
        }
        socket->write(replyMessage);
    };
    return new ServerType(handler, std::forward<Args>(args)...);
}

// This class is used to access flow class's private class, in order to make
// the class use milliseconds instead of seconds for expirations and intervals,
// making these autotest finish in a more pragmatic timeframe
class DeviceFlow : public QOAuth2DeviceAuthorizationFlow
{
public:
    QOAuth2DeviceAuthorizationFlowPrivate *flowPrivate()
    {
        return static_cast<QOAuth2DeviceAuthorizationFlowPrivate*>(d_ptr.data());
    }
};

static void expectWarning(const QString &warningText)
{
    const QRegularExpression warning(warningText);
    QTest::ignoreMessage(QtWarningMsg, warning);
};

void tst_OAuth2DeviceFlow::init()
{
    receivedAuthorizationRequests.clear();
    receivedTokenRequests.clear();
}

void tst_OAuth2DeviceFlow::initTestCase()
{
    // QLoggingCategory::setFilterRules(QStringLiteral("qt.networkauth* = true"));
    testDataDir = QFileInfo(QFINDTESTDATA("../shared/certs")).absolutePath();
    if (testDataDir.isEmpty())
        testDataDir = QCoreApplication::applicationDirPath();
    if (!testDataDir.endsWith(QLatin1String("/")))
        testDataDir += QLatin1String("/");
}

class RequestModifier : public QObject
{
    Q_OBJECT
public:
    RequestModifier(QObject *parent = nullptr) : QObject(parent) {}

    void handleRequestModification(QNetworkRequest &request, Stage stage)
    {
        stagesReceivedByModifier.append(stage);
        auto headers = request.headers();
        headers.append("test-header-name"_ba, valueToSet);
        request.setHeaders(headers);
    }
    QList<Stage> stagesReceivedByModifier;
    QByteArray valueToSet;
};

#define TEST_MODIFY_REQUEST_WITH_MODIFIER(STAGES_RECEIVED, VALUE_SET, VALUE_PREFIX) \
do { \
    receivedAuthorizationRequests.clear(); \
    receivedTokenRequests.clear(); \
    STAGES_RECEIVED.clear(); \
    VALUE_SET = QByteArray(VALUE_PREFIX) + "_authorization_and_access_token"; \
    oauth2.grant(); \
    QTRY_COMPARE(STAGES_RECEIVED.size(), 2); \
    QCOMPARE(STAGES_RECEIVED.at(0), Stage::RequestingAuthorization); \
    QCOMPARE(STAGES_RECEIVED.at(1), Stage::RequestingAccessToken); \
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1); \
    QCOMPARE(receivedAuthorizationRequests.at(0).headers.value("test-header-name"_ba), VALUE_SET); \
    QTRY_COMPARE(receivedTokenRequests.size(), 1); \
    QCOMPARE(receivedTokenRequests.at(0).headers.value("test-header-name"_ba), VALUE_SET); \
    QTRY_COMPARE(oauth2.status(), Status::Granted); \
    /* Refresh token request */ \
    VALUE_SET = QByteArray(VALUE_PREFIX) + "_refresh_token"; \
    receivedTokenRequests.clear(); \
    STAGES_RECEIVED.clear(); \
    requestFailedSpy.clear(); \
    REFRESH_TOKENS(oauth2); \
    QVERIFY(requestFailedSpy.isEmpty()); \
    QCOMPARE(oauth2.status(), Status::RefreshingToken); \
    QTRY_COMPARE(STAGES_RECEIVED.size(), 1); \
    QCOMPARE(STAGES_RECEIVED.at(0), Stage::RefreshingAccessToken); \
    QTRY_COMPARE(receivedTokenRequests.size(), 1); \
    QCOMPARE(receivedTokenRequests.at(0).headers.value("test-header-name"_ba), VALUE_SET); \
    QTRY_COMPARE(oauth2.status(), Status::Granted); \
    oauth2.clearNetworkRequestModifier(); \
} while (false) \

#define TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(VALUE_SET) \
do { \
    receivedAuthorizationRequests.clear(); \
    receivedTokenRequests.clear(); \
    VALUE_SET = "must_not_be_set"_ba; \
    oauth2.grant(); \
    QTRY_COMPARE(oauth2.status(), Status::Granted); \
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1); \
    QVERIFY(receivedAuthorizationRequests.at(0).headers.value("test-header-name"_ba).isEmpty()); \
    QTRY_COMPARE(receivedTokenRequests.size(), 1); \
    QVERIFY(receivedTokenRequests.at(0).headers.value("test-header-name"_ba).isEmpty()); \
    receivedTokenRequests.clear(); \
    requestFailedSpy.clear(); \
    REFRESH_TOKENS(oauth2); \
    QVERIFY(requestFailedSpy.isEmpty()); \
    QCOMPARE(oauth2.status(), Status::RefreshingToken); \
    QTRY_COMPARE(oauth2.status(), Status::Granted); \
    QTRY_COMPARE(receivedTokenRequests.size(), 1); \
    QVERIFY(receivedTokenRequests.at(0).headers.value("test-header-name"_ba).isEmpty()); \
    oauth2.clearNetworkRequestModifier(); \
} while (false) \

void tst_OAuth2DeviceFlow::modifyTokenRequests()
{
    std::unique_ptr<RequestModifier> context(new RequestModifier);
    QRegularExpression nullContextWarning(u".*Context object must not be null, ignoring"_s);
    QRegularExpression wrongThreadWarning(u".*Context object must reside in the same thread"_s);
    auto valueToSet = ""_ba;

    const QString authBody = Responses::authorizationSuccess;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenSuccess;
    QString tokenHttpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));
    oauth2.setRefreshToken(u"refresh_token"_s);

    QSignalSpy requestFailedSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::requestFailed);

    QList<Stage> stagesReceivedByModifier;
    auto modifierLambda = [&](QNetworkRequest &request, Stage stage) {
        stagesReceivedByModifier.append(stage);
        auto headers = request.headers();
        headers.append("test-header-name"_ba, valueToSet);
        request.setHeaders(headers);
    };
    std::function<void(QNetworkRequest &, Stage)> modifierFunc = modifierLambda;

    // Lambda with a context object
    oauth2.setNetworkRequestModifier(context.get(), modifierLambda);
    TEST_MODIFY_REQUEST_WITH_MODIFIER(stagesReceivedByModifier,
                                      valueToSet, "lambda_with_context");

    // Test that the modifier will be cleared
    oauth2.clearNetworkRequestModifier();
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet);

    // Lambda without a context object
    QTest::ignoreMessage(QtWarningMsg, nullContextWarning);
    oauth2.setNetworkRequestModifier(nullptr, modifierLambda);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet);

    // std::function with a context object
    oauth2.setNetworkRequestModifier(context.get(), modifierFunc);
    TEST_MODIFY_REQUEST_WITH_MODIFIER(stagesReceivedByModifier, valueToSet, "func_with_context");

    // PMF with context object
    oauth2.setNetworkRequestModifier(context.get(), &RequestModifier::handleRequestModification);
    TEST_MODIFY_REQUEST_WITH_MODIFIER(context->stagesReceivedByModifier,
                                      context->valueToSet, "pmf_with_context");

    // PMF without context object
    QTest::ignoreMessage(QtWarningMsg, nullContextWarning);
    oauth2.setNetworkRequestModifier(nullptr, &RequestModifier::handleRequestModification);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(context->valueToSet);

    // Destroy context object => no callback (or crash)
    oauth2.setNetworkRequestModifier(context.get(), modifierLambda);
    context.reset(nullptr);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet);

    // Context object in wrong thread
    QThread thread;
    QObject objectInWrongThread;
    // Initially context object is in correct thread
    oauth2.setNetworkRequestModifier(&objectInWrongThread, modifierLambda);
    // Move to wrong thread, verify we get warnings when it's time to call the callback
    objectInWrongThread.moveToThread(&thread);
    QTest::ignoreMessage(QtWarningMsg, wrongThreadWarning);
    oauth2.grant();
    QTRY_COMPARE(oauth2.status(), Status::Granted);
    // Now the context object is in wrong thread when attempting to set the modifier
    oauth2.clearNetworkRequestModifier();
    QTest::ignoreMessage(QtWarningMsg, wrongThreadWarning);
    oauth2.setNetworkRequestModifier(&objectInWrongThread, modifierLambda);
    TEST_MODIFY_REQUEST_WITHOUT_MODIFIER(valueToSet);
}

void tst_OAuth2DeviceFlow::userCodeExpiration()
{
    QString authBody;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenAuthorizationPending;
    QString tokenHttpStatus = Responses::BR_400;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    QOAuth2DeviceAuthorizationFlow oauth2;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));

    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);
    QSignalSpy statusSpy(&oauth2, &QAbstractOAuth::statusChanged);
    QSignalSpy grantedSpy(&oauth2, &QAbstractOAuth::granted);
    QSignalSpy codeExpirationSpy(&oauth2,
                                 &QOAuth2DeviceAuthorizationFlow::userCodeExpirationAtChanged);

    const auto clearTestData = [&](){
        receivedAuthorizationRequests.clear();
        receivedTokenRequests.clear();
        requestFailedSpy.clear();
        codeExpirationSpy.clear();
        statusSpy.clear();
        grantedSpy.clear();
    };

    // Initial expiration
    QCOMPARE(oauth2.userCodeExpirationAt(), QDateTime());

    // Code would expire before first poll request
    authBody = Responses::authorizationResponseWithTimes(100, 50);
    expectWarning("code expired");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ExpiredError);
    QCOMPARE(codeExpirationSpy.size(), 1);
    // The expiration is expressed as seconds from 'now'. To robustly compare the time
    // that device flow class calculates vs. what this test case calculates, verify
    // the expiration with two seconds tolerance
    QVERIFY(
        qAbs(oauth2.userCodeExpirationAt().secsTo(QDateTime::currentDateTime().addSecs(50))) <= 2);
    QCOMPARE(codeExpirationSpy.at(0).at(0).toDateTime(), oauth2.userCodeExpirationAt());
    QCOMPARE(receivedAuthorizationRequests.size(), 1);
    QCOMPARE(receivedTokenRequests.size(), 0);
    QCOMPARE(oauth2.status(), Status::NotAuthenticated);

    // Code expires while polling
    clearTestData();
    authBody = Responses::authorizationResponseWithTimes(1, 4);
    expectWarning("code expired");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ExpiredError);
    QCOMPARE(codeExpirationSpy.size(), 2);
    QCOMPARE(codeExpirationSpy.at(0).at(0).toDateTime(), QDateTime()); // grant() resets properties
    QCOMPARE(codeExpirationSpy.at(1).at(0).toDateTime(), oauth2.userCodeExpirationAt());
    QCOMPARE(receivedAuthorizationRequests.size(), 1);
    QVERIFY(receivedTokenRequests.size() > 1); // first at 1s, then at 2s, ...
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);

    // Code expiration is indicated by authorization server's token response
    clearTestData();
    tokenBody = Responses::tokenExpired;
    expectWarning("code expired");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ExpiredError);
}

void tst_OAuth2DeviceFlow::startStopTokenPolling()
{
    QString authBody = Responses::authorizationSuccess;
    QString tokenBody = Responses::tokenAuthorizationPending;
    QString authHttpStatus = Responses::OK_200;
    QString tokenHttpStatus = Responses::BR_400;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    DeviceFlow oauth2;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));
    oauth2.flowPrivate()->useAutoTestDurations = true;
    QSignalSpy pollingSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::pollingChanged);
    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);

    auto clearTestVariables = [&](){
        pollingSpy.clear();
        requestFailedSpy.clear();
        receivedAuthorizationRequests.clear();
        receivedTokenRequests.clear();
    };

    // Initial state
    QVERIFY(!oauth2.isPolling());
    oauth2.stopTokenPolling(); // Mustn't cause harm

    // Flow doesn't yet have device code
    expectWarning(u"missing device code for polling"_s);
    QVERIFY(!oauth2.startTokenPolling());
    QVERIFY(!oauth2.isPolling());
    QVERIFY(pollingSpy.isEmpty());
    QCOMPARE(requestFailedSpy.size(), 1);

    // Successful start of flow, enters polling automatically
    clearTestVariables();
    oauth2.grant();
    QTRY_COMPARE(pollingSpy.size(), 1);
    QVERIFY(pollingSpy.at(0).at(0).toBool());
    QCOMPARE(receivedAuthorizationRequests.size(), 1);
    QVERIFY(oauth2.isPolling());
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);
    QVERIFY(requestFailedSpy.isEmpty());

    // Stop polling
    clearTestVariables();
    oauth2.stopTokenPolling();
    QTRY_COMPARE(pollingSpy.size(), 1);
    QVERIFY(!pollingSpy.at(0).at(0).toBool());
    QVERIFY(!oauth2.isPolling());
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);
    QVERIFY(requestFailedSpy.isEmpty());

    // Resume polling manually
    clearTestVariables();
    QVERIFY(oauth2.startTokenPolling());
    QTRY_COMPARE(pollingSpy.size(), 1);
    QVERIFY(pollingSpy.at(0).at(0).toBool());
    QTRY_COMPARE(receivedTokenRequests.size(), 1);
    QCOMPARE(receivedAuthorizationRequests.size(), 0);
    QVERIFY(oauth2.isPolling());
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);
    QVERIFY(requestFailedSpy.isEmpty());

    // Polling already active, no impact
    QVERIFY(oauth2.startTokenPolling());
    QVERIFY(oauth2.isPolling());
    QTRY_COMPARE(receivedTokenRequests.size(), 2);
    QVERIFY(requestFailedSpy.isEmpty());

    // Empty token endpoint URL during polling
    clearTestVariables();
    QVERIFY(oauth2.isPolling());
    oauth2.setTokenUrl(QUrl());
    expectWarning("token URL is empty");
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);
    QVERIFY(!oauth2.isPolling());
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);

    // Attempt to start polling with empty token URL
    clearTestVariables();
    expectWarning("token URL is empty");
    QVERIFY(!oauth2.startTokenPolling());
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);
    QVERIFY(!oauth2.isPolling());
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);
}

void tst_OAuth2DeviceFlow::getAndRefreshToken()
{
    static constexpr auto clientId = "a-client-id"_L1;
    static constexpr auto scope = "a-scope"_L1;
    static constexpr auto accessToken = "an-access-token"_L1;
    static constexpr auto clientSecret = "a-client-secret"_L1;
    static constexpr auto deviceCode = "a-device-code"_L1;
    static constexpr auto userCode = "a-user-code"_L1;
    static constexpr auto refreshToken = "a-refresh-token"_L1;
    static constexpr auto refreshToken2 = "a-refresh-token-2"_L1;
    static constexpr auto verificationUrl = "a-verification-uri"_L1;
    static constexpr auto completeVerificationUrl = "a-verification-uri-complete"_L1;

    // Test-case authorization server appends this list with received requests:
    QString authBody = Responses::authorizationSuccess;
    QString tokenBody = Responses::tokenSuccess;
    QString httpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, httpStatus,
        tokenBody, httpStatus));

    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;

    oauth2.setClientIdentifier(clientId);
    oauth2.setClientIdentifierSharedKey(clientSecret);
    oauth2.setRequestedScope({scope});
    QSignalSpy grantedSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::granted);
    QSignalSpy statusSpy(&oauth2, &QAbstractOAuth::statusChanged);
    QSignalSpy userCodeSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::userCodeChanged);
    QSignalSpy verificationUrlSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::verificationUrlChanged);
    QSignalSpy completeVerificationUrlSpy(
        &oauth2, &QOAuth2DeviceAuthorizationFlow::completeVerificationUrlChanged);
    QSignalSpy authorizationUrlSpy(&oauth2,
                                   &QOAuth2DeviceAuthorizationFlow::authorizationUrlChanged);
    QSignalSpy tokenUrlSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::tokenUrlChanged);
    QSignalSpy tokenSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::tokenChanged);
    QSignalSpy refreshTokenSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::refreshTokenChanged);
    QSignalSpy requestFailedSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::requestFailed);

    // Initial values
    QCOMPARE(oauth2.status(), Status::NotAuthenticated);
    QVERIFY(oauth2.userCode().isEmpty());
    QVERIFY(oauth2.verificationUrl().isEmpty());
    QVERIFY(oauth2.completeVerificationUrl().isEmpty());

    // Set authorization url
    const auto authorizationUrl = authorizationServer->url("authorizationEndpoint"_L1);
    oauth2.setAuthorizationUrl(authorizationUrl);
    QCOMPARE(oauth2.authorizationUrl(), authorizationUrl);
    QCOMPARE(authorizationUrlSpy.size(), 1);
    QCOMPARE(authorizationUrlSpy.at(0).at(0).toUrl(), authorizationUrl);

    // Set access token URL
    const auto tokenUrl = authorizationServer->url("tokenEndpoint"_L1);
    oauth2.setTokenUrl(tokenUrl);
    QCOMPARE(oauth2.tokenUrl(), tokenUrl);
    QCOMPARE(tokenUrlSpy.size(), 1);
    QCOMPARE(tokenUrlSpy.at(0).at(0).toUrl(), tokenUrl);

    // Get access token (and refresh token)
    oauth2.grant();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.status(), Status::Granted);

    // Verify requests that the authorization server received
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1);
    {
        // Authorization request
        QUrlQuery query(QUrl::fromPercentEncoding(receivedAuthorizationRequests.at(0).body));
        QCOMPARE(query.queryItems().size(), 2);
        QCOMPARE(query.queryItemValue("client_id"_L1), clientId);
        QCOMPARE(query.queryItemValue("scope"_L1), scope);
    }
    QTRY_COMPARE(receivedTokenRequests.size(), 1);
    {
        // Access token poll request
        QUrlQuery query(QUrl::fromPercentEncoding(receivedTokenRequests.at(0).body));
        QCOMPARE(query.queryItems().size(), 4);
        QCOMPARE(query.queryItemValue("grant_type"_L1),
                 "urn:ietf:params:oauth:grant-type:device_code"_L1);
        QCOMPARE(query.queryItemValue("device_code"_L1), deviceCode);
        QCOMPARE(query.queryItemValue("client_id"_L1), clientId);
        QCOMPARE(query.queryItemValue("client_secret"_L1), clientSecret);
    }

    // Verify that appropriate properties changed
    QCOMPARE(statusSpy.size(), 2);
    QCOMPARE(statusSpy.at(0).at(0).value<Status>(), Status::TemporaryCredentialsReceived);
    QCOMPARE(statusSpy.at(1).at(0).value<Status>(), Status::Granted);

    QCOMPARE(oauth2.userCode(), userCode);
    QCOMPARE(userCodeSpy.size(), 1);
    QCOMPARE(userCodeSpy.at(0).at(0).toString(), userCode);

    QCOMPARE(oauth2.verificationUrl(), QUrl(verificationUrl));
    QCOMPARE(verificationUrlSpy.size(), 1);
    QCOMPARE(verificationUrlSpy.at(0).at(0).toUrl(), QUrl(verificationUrl));

    QCOMPARE(oauth2.completeVerificationUrl(), QUrl(completeVerificationUrl));
    QCOMPARE(completeVerificationUrlSpy.size(), 1);
    QCOMPARE(completeVerificationUrlSpy.at(0).at(0).toUrl(), QUrl(completeVerificationUrl));

    QCOMPARE(oauth2.token(), accessToken);
    QCOMPARE(tokenSpy.size(), 1);
    QCOMPARE(tokenSpy.at(0).at(0).toString(), accessToken);

    QCOMPARE(oauth2.refreshToken(), refreshToken);
    QCOMPARE(refreshTokenSpy.size(), 1);
    QCOMPARE(refreshTokenSpy.at(0).at(0).toString(), refreshToken);

    // Manually set the refresh token, and then use it to refresh the access token
    oauth2.setRefreshToken(refreshToken2);
    QCOMPARE(refreshTokenSpy.size(), 2);
    QCOMPARE(refreshTokenSpy.at(1).at(0).toString(), refreshToken2);

    statusSpy.clear();
    receivedTokenRequests.clear();
    requestFailedSpy.clear();
    REFRESH_TOKENS(oauth2);
    QVERIFY(requestFailedSpy.isEmpty());
    QTRY_COMPARE(statusSpy.size(), 2);
    QCOMPARE(receivedTokenRequests.size(), 1);
    {
        // Refresh request
        QUrlQuery query(QUrl::fromPercentEncoding(receivedTokenRequests.at(0).body));
        QCOMPARE(query.queryItems().size(), 4);
        QCOMPARE(query.queryItemValue("grant_type"_L1), "refresh_token"_L1);
        QCOMPARE(query.queryItemValue("refresh_token"_L1), refreshToken2);
        QCOMPARE(query.queryItemValue("client_id"_L1), clientId);
        QCOMPARE(query.queryItemValue("client_secret"_L1), clientSecret);
    }
    QCOMPARE(statusSpy.at(0).at(0).value<Status>(), Status::RefreshingToken);
    QCOMPARE(statusSpy.at(1).at(0).value<Status>(), Status::Granted);
    QCOMPARE(oauth2.status(), Status::Granted);
    QCOMPARE(grantedSpy.size(), 2);
    // The refresh token is also renewed
    QCOMPARE(oauth2.refreshToken(), refreshToken);
    QCOMPARE(oauth2.token(), accessToken);
}

void tst_OAuth2DeviceFlow::clientError()
{
    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;
    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);

    // Authorization URL missing with grant()
    expectWarning("No authorization URL");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);

    // Token URL missing with grant()
    requestFailedSpy.clear();
    oauth2.setAuthorizationUrl(QUrl("an-authorization-url"));
    expectWarning("No token URL");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);

    // Refresh token missing for refreshing
    requestFailedSpy.clear();
    expectWarning("empty refresh token");
    REFRESH_TOKENS(oauth2);
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);

    // Token URL missing for refreshing
    requestFailedSpy.clear();
    oauth2.setRefreshToken("a-refresh-token"_L1);
    expectWarning("No token URL");
    REFRESH_TOKENS(oauth2);
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);

    QString authBody = Responses::authorizationSuccess;
    QString tokenBody = Responses::tokenAuthorizationPending;
    QString httpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, httpStatus, tokenBody, httpStatus));

    // Refresh while polling
    requestFailedSpy.clear();
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));
    oauth2.grant();
    QTRY_VERIFY(oauth2.isPolling());
    expectWarning("polling in progress");
    REFRESH_TOKENS(oauth2);
    QCOMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);

    // Clear tokenUrl while polling
    requestFailedSpy.clear();
    QVERIFY(oauth2.isPolling());
    expectWarning("token URL is empty");
    oauth2.setTokenUrl({});
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ClientError);

    // Refresh while refreshing, no client error
    requestFailedSpy.clear();
    oauth2.stopTokenPolling();
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));
    REFRESH_TOKENS(oauth2);
    REFRESH_TOKENS(oauth2);
    REFRESH_TOKENS(oauth2);
    QVERIFY(requestFailedSpy.isEmpty());
}

QT_WARNING_PUSH QT_WARNING_DISABLE_DEPRECATED
void tst_OAuth2DeviceFlow::authorizationErrors()
{
    QString authBody;
    QString httpStatus;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, httpStatus, {}, {}));

    QOAuth2DeviceAuthorizationFlow oauth2;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(QUrl("not-needed"_L1));

    QSignalSpy statusSpy(&oauth2, &QAbstractOAuth::statusChanged);
    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);
#if QT_DEPRECATED_SINCE(6, 13)
    QSignalSpy errorSpy(&oauth2, &QAbstractOAuth2::error);
#endif
    QSignalSpy serverReportedErrorOccurredSpy(&oauth2,
                                              &QAbstractOAuth2::serverReportedErrorOccurred);
    const auto clearSpies = [&](){
        requestFailedSpy.clear();
        serverReportedErrorOccurredSpy.clear();
#if QT_DEPRECATED_SINCE(6, 13)
        errorSpy.clear();
#endif
        statusSpy.clear();
    };

    // Error response from the authorization server (RFC 6749 section 5.2)
    authBody = R"(
            {
                "error": "an-error",
                "error_description": "an-error-description",
                "error_uri": "an-error-uri"
            }
    )"_L1;
    httpStatus = Responses::BR_400;

    oauth2.grant();

    expectWarning("Authorization stage:.*");
#if QT_DEPRECATED_SINCE(6, 13)
    QTRY_COMPARE(errorSpy.size(), 1);
#endif
    QTRY_COMPARE(serverReportedErrorOccurredSpy.size(), 1);
    QTRY_COMPARE(requestFailedSpy.size(), 1);
#if QT_DEPRECATED_SINCE(6, 13)
    QCOMPARE(errorSpy.at(0).at(0).toString(), "an-error"_L1);
    QCOMPARE(errorSpy.at(0).at(1).toString(), "an-error-description"_L1);
    QCOMPARE(errorSpy.at(0).at(2).toString(), "an-error-uri"_L1);
#endif
    QCOMPARE(serverReportedErrorOccurredSpy.at(0).at(0).toString(), "an-error"_L1);
    QCOMPARE(serverReportedErrorOccurredSpy.at(0).at(1).toString(), "an-error-description"_L1);
    QCOMPARE(serverReportedErrorOccurredSpy.at(0).at(2).toString(), "an-error-uri"_L1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ServerError);
    QVERIFY(statusSpy.isEmpty());
    QCOMPARE(oauth2.status(), Status::NotAuthenticated);

    const auto checkAuthorizationError = [&]()
    {
        clearSpies();
        oauth2.grant();
        expectWarning("Authorization stage:.*");
        QTRY_COMPARE(requestFailedSpy.size(), 1);
        QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::OAuthTokenNotFoundError);
        QVERIFY(statusSpy.isEmpty());
        QCOMPARE(oauth2.status(), Status::NotAuthenticated);
        // Other error signals should not have been emitted
#if QT_DEPRECATED_SINCE(6, 13)
        QCOMPARE(errorSpy.size(), 0);
#endif
        QCOMPARE(serverReportedErrorOccurredSpy.size(), 0);
        QVERIFY(statusSpy.isEmpty());
    };

    // Missing user code value
    authBody = R"(
        {
            "user_code": "",
            "device_code": "a-device-code",
            "verification_uri": "a-verification-uri",
            "expires_in": 1800
        })"_L1;
    checkAuthorizationError();

    // Missing user code field
    authBody = R"(
        {
            "device_code": "a-device-code",
            "verification_uri": "a-verification-uri",
            "expires_in": 1800
        })"_L1;
    checkAuthorizationError();

    // Missing device code value
    authBody = R"(
        {
            "user_code": "a-user-code",
            "device_code": "",
            "verification_uri": "a-verification-uri",
            "expires_in": 1800
        })"_L1;
    checkAuthorizationError();

    // Missing device code field
    authBody = R"(
        {
            "user_code": "a-user-code",
            "verification_uri": "a-verification-uri",
            "expires_in": 1800
        })"_L1;
    checkAuthorizationError();

    // Missing expiration value
    authBody = R"(
        {
            "user_code": "a-user-code",
            "device_code": "a-device-code",
            "verification_uri": "a-verification-uri",
            "expires_in": 0
        })"_L1;
    checkAuthorizationError();

    // Missing expiration field
    authBody = R"(
        {
            "user_code": "a-user-code",
            "device_code": "a-device-code",
            "verification_uri": "a-verification-uri"
        })"_L1;
    checkAuthorizationError();

    // Missing verification uri value
    authBody = R"(
        {
            "user_code": "a-user-code",
            "device_code": "a-device-code",
            "verification_uri": "",
            "expires_in": 1800
        })"_L1;
    checkAuthorizationError();

    // Missing verification uri field
    authBody = R"(
        {
            "user_code": "a-user-code",
            "device_code": "a-device-code",
            "expires_in": 1800
        })"_L1;
    checkAuthorizationError();
}
QT_WARNING_POP

void tst_OAuth2DeviceFlow::tokenRequestErrors()
{
    const QString authBody = Responses::authorizationSuccess;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody;
    QString tokenHttpStatus;

    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));

    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);
    QSignalSpy grantedSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::granted);
    QSignalSpy statusSpy(&oauth2, &QAbstractOAuth2::statusChanged);
    auto clearTestVariables = [&](){
        requestFailedSpy.clear();
        grantedSpy.clear();
        statusSpy.clear();
        receivedAuthorizationRequests.clear();
        receivedTokenRequests.clear();
    };

    // Invalid access token response
    tokenHttpStatus = Responses::OK_200;
    tokenBody = u"not the expected json response"_s;
    expectWarning("Token request failed");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(receivedAuthorizationRequests.size(), 1);
    QCOMPARE(receivedTokenRequests.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ServerError);
    QVERIFY(grantedSpy.isEmpty());
    QCOMPARE(statusSpy.size(), 1);
    QCOMPARE(statusSpy.at(0).at(0).value<Status>(), Status::TemporaryCredentialsReceived);
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);

    // Access token error response (RFC 6749 section 5.2)
    tokenBody = R"(
            {
                "error": "an-error",
                "error_description": "an-error-description",
                "error_uri": "an-error-uri"
            }
    )"_L1;
    tokenHttpStatus = Responses::BR_400;
    clearTestVariables();
    expectWarning("Token request failed");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::ServerError);
    QCOMPARE(receivedAuthorizationRequests.size(), 1);
    QCOMPARE(receivedTokenRequests.size(), 1);
    QVERIFY(grantedSpy.isEmpty());
    QCOMPARE(statusSpy.size(), 2);
    QCOMPARE(statusSpy.at(0).at(0).value<Status>(), Status::NotAuthenticated);
    QCOMPARE(statusSpy.at(1).at(0).value<Status>(), Status::TemporaryCredentialsReceived);
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);

    // Missing access token
    tokenBody = R"(
        {
            "refresh_token": "a-refresh-token",
            "token_type": "bearer",
            "expires_in": 3600
        })"_L1;
    tokenHttpStatus = Responses::OK_200;
    clearTestVariables();
    expectWarning("token not received");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(receivedTokenRequests.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::OAuthTokenNotFoundError);
    QCOMPARE(grantedSpy.size(), 0);
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);

    // authorization_pending
    // https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
    tokenBody = Responses::tokenAuthorizationPending;
    tokenHttpStatus = Responses::BR_400;
    clearTestVariables();
    oauth2.grant();
    // Verify that retries (polls) are received (more than one token poll)
    QTRY_VERIFY(receivedTokenRequests.size() > 1);
    QCOMPARE(requestFailedSpy.size(), 0);
    // Change to OK response and verify token is handled successfully
    tokenHttpStatus = Responses::OK_200;
    tokenBody = Responses::tokenSuccess;
    QTRY_COMPARE(oauth2.status(), Status::Granted);

    // slow_down
    // https://datatracker.ietf.org/doc/html/rfc8628#section-3.5
    tokenBody = R"(
            {
                "error": "slow_down",
                "error_description": "You're polling too fast"
            }
    )"_L1;
    tokenHttpStatus = Responses::BR_400;
    clearTestVariables();
    oauth2.grant();
    // Verify that retries (polls) are received (more than one token poll)
    QTRY_VERIFY(receivedTokenRequests.size() > 1);
    QCOMPARE(requestFailedSpy.size(), 0);
    // Change to OK response and verify token is handled successfully
    tokenHttpStatus = Responses::OK_200;
    tokenBody = Responses::tokenSuccess;
    QTRY_COMPARE(oauth2.status(), Status::Granted);

    // Failed access token refresh (missing access token)
    tokenBody = R"(
        {
            "token_type": "bearer",
            "expires_in": 3600
        })"_L1;
    tokenHttpStatus = Responses::OK_200;
    clearTestVariables();
    expectWarning("token not received");
    REFRESH_TOKENS(oauth2);
    QCOMPARE(oauth2.status(), QAbstractOAuth2::Status::RefreshingToken);
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(receivedTokenRequests.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::OAuthTokenNotFoundError);
    QCOMPARE(oauth2.status(), Status::Granted); // Because we still have valid access token

    // Network error
    clearTestVariables();
    authorizationServer->close();
    expectWarning("network error");
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::NetworkError);
    QCOMPARE(grantedSpy.size(), 0);
    QCOMPARE(oauth2.status(), Status::NotAuthenticated);
}

void tst_OAuth2DeviceFlow::nonce()
{
    const auto nonce = "a_nonce"_ba;
    const QString authBody = Responses::authorizationSuccess;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenSuccess;
    QString tokenHttpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    QOAuth2DeviceAuthorizationFlow oauth2;
    oauth2.setRequestedScope({"openid"_L1});
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));

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
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1);
    QUrlQuery parameters;
    parameters.setQuery(receivedAuthorizationRequests.at(0).body);
    QCOMPARE(parameters.queryItemValue(u"nonce"_s).toUtf8(), nonce);

    // -- Nonce is never included
    oauth2.setNonceMode(QAbstractOAuth2::NonceMode::Disabled);
    receivedAuthorizationRequests.clear();
    oauth2.grant();
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1);
    parameters.setQuery(receivedAuthorizationRequests.at(0).body);
    QVERIFY(parameters.queryItemValue(u"nonce"_s).toUtf8().isEmpty());

    // -- Nonce is included if scope contains 'openid'
    oauth2.setNonceMode(QAbstractOAuth2::NonceMode::Automatic);
    receivedAuthorizationRequests.clear();
    oauth2.grant();
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1);
    parameters.setQuery(receivedAuthorizationRequests.at(0).body);
    QVERIFY(parameters.queryItemValue(u"nonce"_s).toUtf8().isEmpty());

    oauth2.setRequestedScope({u"scope_item1"_s, u"openid"_s});
    receivedAuthorizationRequests.clear();
    oauth2.grant();
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1);
    parameters.setQuery(receivedAuthorizationRequests.at(0).body);
    QCOMPARE(parameters.queryItemValue(u"nonce"_s).toUtf8(), nonce);

    // -- Clear nonce, one should be generated
    oauth2.setNonce("");
    QVERIFY(oauth2.nonce().isEmpty());
    receivedAuthorizationRequests.clear();
    oauth2.grant();
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1);
    QVERIFY(!oauth2.nonce().isEmpty());
    parameters.setQuery(receivedAuthorizationRequests.at(0).body);
    QCOMPARE(parameters.queryItemValue(u"nonce"_s).toUtf8(), oauth2.nonce());
}

void tst_OAuth2DeviceFlow::idToken()
{
    const QString authBody = Responses::authorizationSuccess;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenSuccess;
    QString tokenHttpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;
    oauth2.setRequestedScope({"openid"_L1});
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));

    QSignalSpy idTokenSpy(&oauth2, &QAbstractOAuth2::idTokenChanged);
    QSignalSpy requestFailedSpy(&oauth2, &QAbstractOAuth::requestFailed);

    // Verify default token is empty
    QVERIFY(oauth2.idToken().isEmpty());

    // Test without openid and verify idToken doesn't change
    oauth2.setRequestedScope({"read"_L1});
    oauth2.grant();
    QTRY_COMPARE(oauth2.status(), Status::Granted);
    QVERIFY(idTokenSpy.isEmpty());
    QVERIFY(oauth2.idToken().isEmpty());

    // Test with openid
    // Note: using a proper JWT or setting the matching 'nonce' is not required for this tests
    // purpose as we don't currently validate the received token, but no harm in being thorough
    auto idToken = createSignedJWT({}, {{"nonce"_L1, oauth2.nonce()}});
    oauth2.setRequestedScope({"openid"_L1});
    tokenBody = R"(
        {
            "access_token": "an-access-token",
            "refresh_token": "a-refresh-token",
            "token_type": "bearer",
            "expires_in": 3600,
            "id_token": ")"_L1 + idToken +
        "\"}";
    oauth2.grant();

    QTRY_COMPARE(oauth2.status(), Status::Granted);
    QCOMPARE(oauth2.idToken(), idToken);
    QCOMPARE(idTokenSpy.size(), 1);
    QCOMPARE(idTokenSpy.at(0).at(0).toByteArray(), idToken);

    // Test missing id_token error
    QVERIFY(requestFailedSpy.isEmpty());
    expectWarning("ID token not received");
    tokenBody = Responses::tokenSuccess;
    oauth2.grant();
    QTRY_COMPARE(requestFailedSpy.size(), 1);
    QCOMPARE(requestFailedSpy.at(0).at(0).value<Error>(), Error::OAuthTokenNotFoundError);
    QCOMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);
    // idToken is cleared on failure
    QCOMPARE(idTokenSpy.size(), 2);
    QVERIFY(oauth2.idToken().isEmpty());
}

void tst_OAuth2DeviceFlow::requestedScope_data()
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

void tst_OAuth2DeviceFlow::requestedScope()
{
    QFETCH(QStringList, requested_scope);
    QFETCH(QStringList, expected_requested_scope);
    QFETCH(QString, expected_resulting_request_scope);

    const QString authBody = Responses::authorizationSuccess;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenSuccess;
    QString tokenHttpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    QOAuth2DeviceAuthorizationFlow oauth2;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));
    QVERIFY(oauth2.requestedScope().isEmpty());

    QSignalSpy requestedScopeSpy(&oauth2, &QAbstractOAuth2::requestedScopeChanged);
    oauth2.setRequestedScope(requested_scope);

    QCOMPARE(requestedScopeSpy.size(), 1);
    QCOMPARE(oauth2.requestedScope(), expected_requested_scope);
    QCOMPARE(requestedScopeSpy.at(0).at(0).toStringList(), expected_requested_scope);

    oauth2.grant();
    QTRY_COMPARE(receivedAuthorizationRequests.size(), 1);
    QUrlQuery parameters(receivedAuthorizationRequests.at(0).body);
    QCOMPARE(parameters.queryItemValue(u"scope"_s), expected_resulting_request_scope);
}

void tst_OAuth2DeviceFlow::grantedScope_data()
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

void tst_OAuth2DeviceFlow::grantedScope()
{
    QFETCH(QStringList, requested_scope);
    QFETCH(QString, granted_scope);
    QFETCH(QStringList, expected_granted_scope);

    const QString authBody = Responses::authorizationSuccess;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenSuccess;
    QString tokenHttpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));

    QSignalSpy grantedSpy(&oauth2, &QAbstractOAuth2::grantedScopeChanged);
    oauth2.setRequestedScope(requested_scope);

    if (!granted_scope.isEmpty()) {
        tokenBody =  R"(
        {
            "access_token": "an-access-token",
            "refresh_token": "a-refresh-token",
            "token_type": "bearer",
            "expires_in": 3600,
            "scope": ")" + granted_scope +
        "\"}"_L1;
    }
    oauth2.grant();

    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.grantedScope(), expected_granted_scope);
    QCOMPARE(grantedSpy.at(0).at(0).toStringList(), expected_granted_scope);
}

void tst_OAuth2DeviceFlow::refreshLeadTime_data()
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

void tst_OAuth2DeviceFlow::refreshLeadTime()
{
    QFETCH(std::chrono::seconds, refreshLeadTime);
    QFETCH(int, expiresIn);
    QFETCH(std::chrono::seconds, waitTimeForExpiration);
    QFETCH(bool, autoRefresh);
    QFETCH(bool, expectExpirationSignal);
    QFETCH(QString, refreshToken);
    QFETCH(bool, expectRefreshRequest);

    const QString authBody = Responses::authorizationSuccess;
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenSuccess;
    QString tokenHttpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
            authBody, authHttpStatus, tokenBody, tokenHttpStatus));

    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));
    oauth2.setRefreshLeadTime(refreshLeadTime);
    oauth2.setAutoRefresh(autoRefresh);

    QSignalSpy expiredSpy(&oauth2, &QAbstractOAuth2::accessTokenAboutToExpire);
    QSignalSpy grantedSpy(&oauth2, &QAbstractOAuth2::grantedScopeChanged);

    tokenBody = R"(
    {
        "access_token": "initial-access-token",
        "token_type": "bearer",
        "expires_in": ")" + QString::number(expiresIn) + R"(",
        "scope": "s",
        "refresh_token": ")" + refreshToken +
    "\"}"_L1;
    oauth2.grant();

    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), u"initial-access-token"_s);

    // Clear initial token request
    receivedTokenRequests.clear();

    if (expectExpirationSignal) {
        tokenBody = R"(
            {
                "access_token": "refreshed-access-token",
                "token_type": "bearer",
                "expires_in": 3600,
                "scope": "s",
                "refresh_token": "a-refresh-token"
            })"_L1;
        QTRY_COMPARE_WITH_TIMEOUT(expiredSpy.size(), 1, waitTimeForExpiration);
        if (expectRefreshRequest) {
            QTRY_COMPARE(oauth2.token(), "refreshed-access-token"_L1);
            QCOMPARE(receivedTokenRequests.size(), 1);
            QCOMPARE(expiredSpy.size(), 1);
        } else {
            // Refresh request isn't expected. To be sure that it isn't sent, allow a bit time
            // for the network stack to process before testing that it indeed wasn't sent
            QTest::qWait(100);
            QCOMPARE(receivedTokenRequests.size(), 0);
        }
    }
}

void tst_OAuth2DeviceFlow::destruction_data()
{
    QTest::addColumn<QNetworkAccessManager *>("qnam");

    QTest::addRow("no qnam supplied") << static_cast<QNetworkAccessManager*>(nullptr);
    QTest::addRow("default qnam") << new QNetworkAccessManager;
    auto qnamWithAutoDelete = new QNetworkAccessManager;
    qnamWithAutoDelete->setAutoDeleteReplies(true);
    QTest::addRow("autodeleting qnam") << qnamWithAutoDelete;
}

void tst_OAuth2DeviceFlow::destruction()
{
    // Test destroying the device flow class in different stages of the flow
    // and verify that things destruct cleanly
    QFETCH(QNetworkAccessManager *, qnam);
    std::unique_ptr<QNetworkAccessManager> accessManager(qnam);
    QString authBody = Responses::authorizationResponseWithTimes(1, 5);
    QString tokenBody = Responses::tokenAuthorizationPending;
    QString httpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, httpStatus, tokenBody, httpStatus));

    const auto newFlow = [&]() -> QOAuth2DeviceAuthorizationFlow * {
        QOAuth2DeviceAuthorizationFlow *flow =
            new QOAuth2DeviceAuthorizationFlow(accessManager.get());
        flow->setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
        flow->setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));
        return flow;
    };

    std::unique_ptr<QOAuth2DeviceAuthorizationFlow> oauth2;
    oauth2.reset(newFlow());

    // Delete right after creation
    oauth2.reset(nullptr);

    // Delete while authorization request is out
    oauth2.reset(newFlow());
    oauth2->grant();
    oauth2.reset(nullptr);

    // Delete while polling
    oauth2.reset(newFlow());
    oauth2->grant();
    QTRY_VERIFY(receivedTokenRequests.size() >= 1);
    oauth2.reset(nullptr);
}

void tst_OAuth2DeviceFlow::changeNetworkAccessManager()
{
    const QString authBody = Responses::authorizationResponseWithTimes(100, 1000);
    QString tokenBody = Responses::tokenSuccess;
    const QString httpStatus = Responses::OK_200;
    std::unique_ptr<WebServer> authorizationServer(createAuthorizationServer<WebServer>(
        authBody, httpStatus, tokenBody, httpStatus));

    QNetworkAccessManager *qnam0 = nullptr;
    QNetworkAccessManager qnam1;
    QNetworkAccessManager qnam2;

    DeviceFlow oauth2;
    oauth2.flowPrivate()->useAutoTestDurations = true;
    oauth2.setAuthorizationUrl(authorizationServer->url("authorizationEndpoint"_L1));
    oauth2.setTokenUrl(authorizationServer->url("tokenEndpoint"_L1));

    bool stopPollingAfterAuthorization = true;
    connect(&oauth2, &QAbstractOAuth::statusChanged, this, [&](Status status) {
        if (status == Status::TemporaryCredentialsReceived && stopPollingAfterAuthorization)
            oauth2.stopTokenPolling();
    });

    // Change QNAM between authorization and polling
    stopPollingAfterAuthorization = true;
    oauth2.setNetworkAccessManager(&qnam1);
    oauth2.grant();
    QTRY_COMPARE(oauth2.status(), Status::TemporaryCredentialsReceived);
    oauth2.setNetworkAccessManager(&qnam2);
    oauth2.startTokenPolling();
    QTRY_COMPARE(oauth2.status(), Status::Granted);

    // Set QNAM to nullptr, which should trigger creation of a new (internal) one
    oauth2.setNetworkAccessManager(qnam0);
    stopPollingAfterAuthorization = false;
    oauth2.grant();
    QTRY_COMPARE(oauth2.status(), Status::Granted);

    // Change QNAM right after sending authorization request. The authorization
    // works because the first QNAM isn't an internal one (which would get deleted)
    oauth2.setNetworkAccessManager(&qnam1);
    oauth2.grant();
    oauth2.setNetworkAccessManager(&qnam2);
    QTRY_COMPARE(oauth2.status(), Status::Granted);

    // Change QNAM right after sending authorization request. This time authorization
    // won't work because the internally created QNAM will get deleted. This is a
    // corner case, but must not crash etc.
    oauth2.setNetworkAccessManager(nullptr);
    oauth2.grant();
    oauth2.setNetworkAccessManager(&qnam2);
    QTest::qWait(200ms);
    QCOMPARE(oauth2.status(), Status::NotAuthenticated);
    // restart with the new QNAM
    oauth2.grant();
    QTRY_COMPARE(oauth2.status(), Status::Granted);
}

#ifndef QT_NO_SSL
void tst_OAuth2DeviceFlow::tlsAuthentication()
{
    if (!QSslSocket::supportsSsl())
        QSKIP("This test will fail because the backend does not support TLS");

#ifdef Q_OS_MACOS
#if !QT_MACOS_IOS_PLATFORM_SDK_EQUAL_OR_ABOVE(150000, 180000)
    if (QOperatingSystemVersion::current() >= QOperatingSystemVersion::MacOSSequoia
        && QSslSocket::activeBackend() == QLatin1String("securetransport")) {
        // Built with SDK < 15, with file-based keychains that no longer work on macOS >= 15.
        QSKIP("SecureTransport will block the test server while accessing the login keychain");
    }
#endif
#endif // Q_OS_MACOS

    auto rollback = useTemporaryKeychain();

    // erros may vary, depending on backend
    const QSet<QSslError::SslError> expectedErrors{ QSslError::SelfSignedCertificate,
                                                    QSslError::CertificateUntrusted,
                                                    QSslError::HostNameMismatch };
    auto serverConfig = createSslConfiguration(testDataDir + "certs/selfsigned-server.key",
                                               testDataDir + "certs/selfsigned-server.crt");

    // SSL establishment can take awhile, use one full second for poll interval
    const QString authBody = Responses::authorizationResponseWithTimes(1, 10);
    const QString authHttpStatus = Responses::OK_200;
    QString tokenBody = Responses::tokenSuccess;
    QString tokenHttpStatus = Responses::OK_200;

    std::unique_ptr<TlsWebServer> authorizationServer(createAuthorizationServer<TlsWebServer>(
        authBody, authHttpStatus, tokenBody, tokenHttpStatus, serverConfig));
    authorizationServer->setExpectedSslErrors(expectedErrors);
    auto clientConfig = createSslConfiguration(testDataDir + "certs/selfsigned-client.key",
                                               testDataDir + "certs/selfsigned-client.crt");

    QNetworkAccessManager qnam;
    QOAuth2DeviceAuthorizationFlow oauth2;
    oauth2.setNetworkAccessManager(&qnam);
    oauth2.setSslConfiguration(clientConfig);
    oauth2.setAuthorizationUrl(authorizationServer->url(QLatin1String("authorizationEndpoint")));
    oauth2.setTokenUrl(authorizationServer->url(QLatin1String("tokenEndpoint")));

    connect(&qnam, &QNetworkAccessManager::sslErrors, this,
        [&expectedErrors](QNetworkReply *r, const QList<QSslError> &errors) {
            QCOMPARE(errors.size(), 2);
            for (const auto &err : errors)
                QVERIFY(expectedErrors.contains(err.error()));
            r->ignoreSslErrors();
        });

    QSignalSpy grantedSpy(&oauth2, &QOAuth2DeviceAuthorizationFlow::granted);
    oauth2.grant();
    QTRY_COMPARE(grantedSpy.size(), 1);
    QCOMPARE(oauth2.token(), "an-access-token"_L1);
}
#endif // !QT_NO_SSL

QTEST_MAIN(tst_OAuth2DeviceFlow)
#include "tst_oauth2deviceflow.moc"
