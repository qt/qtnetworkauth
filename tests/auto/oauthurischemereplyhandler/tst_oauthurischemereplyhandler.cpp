// Copyright (C) 2024 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtTest/qsignalspy.h>
#include <QtTest/qtest.h>

#include <QtGui/qdesktopservices.h>

#include <QtNetworkAuth/qoauth2authorizationcodeflow.h>
#include <QtNetworkAuth/qoauthurischemereplyhandler.h>

#include <QtCore/qloggingcategory.h>
#include <QtCore/qscopeguard.h>
#include <QtCore/qurl.h>
#include <QtCore/qurlquery.h>

using namespace Qt::StringLiterals;

class tst_QOAuthUriSchemeReplyHandler : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void construction();
    void redirectUrl();
    void listenClose();
    void authorization_data();
    void authorization();
    void callbackDataReceived_data();
    void callbackDataReceived();

private:
    const QUrl customUrlWithPath{"com.my.app:/somepath"_L1};
    const QUrl customUrlWithoutPath{"com.my.app"_L1};
    const QUrl customUrlWithHost{"com.my.app://some.host.org"_L1};
    const QUrl customUrlWithExtra{"com.my.app:/somepath:1234?key=value"_L1};
    const QUrl authorizationUrl{"https://example.foo.bar.com/api/authorize"_L1};
    const QUrl accessTokenUrl{"idontexist"_L1}; // token acqusition is irrelevant for this test
    static constexpr auto state = "a_state"_L1;
    static constexpr auto code = "a_code"_L1;
    const QString stateCodeQuery = "?state="_L1 + state + "&code="_L1  + code;
    const QVariantMap stateCodeMap{{"state"_L1, state}, {"code"_L1, code}};
};

void tst_QOAuthUriSchemeReplyHandler::construction()
{
    QOAuthUriSchemeReplyHandler rh1;
    QVERIFY(!rh1.isListening());
    QVERIFY(rh1.callback().isEmpty());
    QVERIFY(rh1.redirectUrl().isEmpty());

    QOAuthUriSchemeReplyHandler rh2(customUrlWithPath);
    QVERIFY(rh2.isListening());
    QCOMPARE(rh2.redirectUrl(), customUrlWithPath);
    QCOMPARE(rh2.callback(), customUrlWithPath.toString());
}

void tst_QOAuthUriSchemeReplyHandler::redirectUrl()
{
    QOAuthUriSchemeReplyHandler rh;
    QSignalSpy urlChangedSpy(&rh, &QOAuthUriSchemeReplyHandler::redirectUrlChanged);

    rh.setRedirectUrl(customUrlWithPath);
    QCOMPARE(rh.redirectUrl(), customUrlWithPath);
    QCOMPARE(rh.callback(), customUrlWithPath.toString());
    QCOMPARE(urlChangedSpy.size(), 1);

    rh.setRedirectUrl(customUrlWithHost);
    QCOMPARE(rh.redirectUrl(), customUrlWithHost);
    QCOMPARE(rh.callback(), customUrlWithHost.toString());
    QCOMPARE(urlChangedSpy.size(), 2);

    rh.setRedirectUrl(customUrlWithExtra);
    QCOMPARE(rh.redirectUrl(), customUrlWithExtra);
    QCOMPARE(rh.callback(), customUrlWithExtra.toString());
    QCOMPARE(urlChangedSpy.size(), 3);

    rh.setRedirectUrl(customUrlWithExtra); // Same URL again
    QCOMPARE(urlChangedSpy.size(), 3);

    rh.setRedirectUrl({});
    QVERIFY(rh.redirectUrl().isEmpty());
    QVERIFY(rh.callback().isEmpty());
    QCOMPARE(urlChangedSpy.size(), 4);
}

void tst_QOAuthUriSchemeReplyHandler::listenClose()
{
    const QUrl scheme1 = u"scheme1:/foo"_s;
    const QUrl scheme2 = u"scheme2:/foo"_s;
    QOAuthUriSchemeReplyHandler rh;
    QSignalSpy callbackSpy(&rh, &QAbstractOAuthReplyHandler::callbackReceived);

    rh.setRedirectUrl(scheme1);
    QVERIFY(rh.listen());
    QDesktopServices::openUrl(scheme1);
    QCOMPARE(callbackSpy.size(), 1);

    rh.setRedirectUrl(scheme2);
    QDesktopServices::openUrl(scheme2);
    QCOMPARE(callbackSpy.size(), 2);

    QDesktopServices::openUrl(scheme1); // Previous scheme should be unregistered
    QCOMPARE(callbackSpy.size(), 2);

    rh.close();
    QDesktopServices::openUrl(scheme2);
    QCOMPARE(callbackSpy.size(), 2);
}

void tst_QOAuthUriSchemeReplyHandler::authorization_data()
{
    QTest::addColumn<QUrl>("registered_redirect_uri");
    QTest::addColumn<QUrl>("response_redirect_uri");
    QTest::addColumn<bool>("matches");
    QTest::addColumn<QVariantMap>("result_parameters");

    QTest::newRow("match_with_path")
        << QUrl{"com.example:/cb"_L1} << QUrl{"com.example:/cb"_L1 + stateCodeQuery}
        << true << stateCodeMap;

    QTest::newRow("match_with_host")
        << QUrl{"com.example://cb.example.org"_L1}
        << QUrl{"com.example://cb.example.org"_L1 + stateCodeQuery}
        << true << stateCodeMap;

    QTest::newRow("match_with_host_and_path")
        << QUrl{"com.example://cb.example.org/a_path"_L1}
        << QUrl{"com.example://cb.example.org/a_path"_L1 + stateCodeQuery}
        << true << stateCodeMap;

    QVariantMap resultParameters = stateCodeMap;
    resultParameters.insert("lang"_L1, "de");
    QTest::newRow("match_with_path_and_query")
        << QUrl{"com.example:/cb?lang=de"_L1}
        << QUrl{"com.example:/cb"_L1 + stateCodeQuery + "&lang=de"_L1}
        << true << resultParameters;

    QTest::newRow("mismatch_path")
        << QUrl{"com.example:/cb"_L1} << QUrl{"com.example:/wrong"_L1 + stateCodeQuery}
        << false << stateCodeMap;

    QTest::newRow("mismatch_parameters")
        << QUrl{"com.example:/cb?lang=de"_L1} << QUrl{"com.example:/cb?code=foo"_L1}
        << false << stateCodeMap;

    QTest::newRow("mismatch_parameter_value")
        << QUrl{"com.example:/cb?lang=de"_L1} << QUrl{"com.example:/cb?lang=wrong"_L1}
        << false << stateCodeMap;
}

void tst_QOAuthUriSchemeReplyHandler::authorization()
{
    // The registered redirect URI is what is typically registered at the cloud
    QFETCH(const QUrl, registered_redirect_uri);
    // The response redirect URI is registered URI with additional parameters from server
    QFETCH(const QUrl, response_redirect_uri);
    QFETCH(const bool, matches);
    QFETCH(const QVariantMap, result_parameters);

    QOAuthUriSchemeReplyHandler rh;
    rh.setRedirectUrl(registered_redirect_uri);
    rh.listen();

    QOAuth2AuthorizationCodeFlow oauth;
    oauth.setAuthorizationUrl(authorizationUrl);
    oauth.setAccessTokenUrl(accessTokenUrl);
    oauth.setState(state);
    oauth.setReplyHandler(&rh);

    QSignalSpy openBrowserSpy(&oauth, &QOAuth2AuthorizationCodeFlow::authorizeWithBrowser);
    QSignalSpy redirectedSpy(&rh, &QAbstractOAuthReplyHandler::callbackReceived);

    oauth.grant();

    // First step would be to open browser: catch the signal and verify correct redirect_uri
    QTRY_VERIFY(!openBrowserSpy.isEmpty());
    const auto authParms = QUrlQuery{openBrowserSpy.takeFirst().at(0).toUrl()};
    QVERIFY(authParms.hasQueryItem(u"redirect_uri"_s));
    QCOMPARE(authParms.queryItemValue(u"redirect_uri"_s), registered_redirect_uri.toString());

    // The failure is silent from API point of view (consider user just closing the browser, the
    // application would never know) => use log messages
    auto cleanup = qScopeGuard([]{
        QLoggingCategory::setFilterRules(u"qt.networkauth.replyhandler=false"_s);
    });
    QLoggingCategory::setFilterRules(u"qt.networkauth.replyhandler=true"_s);
    QRegularExpression re;
    if (matches)
        re.setPattern("Url handled*"_L1);
    else
        re.setPattern("Url ignored*"_L1);
    // Don't open the browser but mimic authorization completion by invoking the redirect_uri
    QTest::ignoreMessage(QtMsgType::QtDebugMsg, re);
    QDesktopServices::openUrl(response_redirect_uri);
    if (matches) {
        QTRY_VERIFY(!redirectedSpy.isEmpty());
        QCOMPARE(redirectedSpy.takeFirst().at(0).toMap(), result_parameters);
    }
}

void tst_QOAuthUriSchemeReplyHandler::callbackDataReceived_data()
{
    QTest::addColumn<QUrl>("response_redirect_uri");

    QTest::addRow("base_url") << QUrl(u"io:/path"_s);
    QTest::addRow("query_parameters") << QUrl(u"io:/path?k1=v1"_s);
}

void tst_QOAuthUriSchemeReplyHandler::callbackDataReceived()
{
    QFETCH(const QUrl, response_redirect_uri);

    QOAuthUriSchemeReplyHandler rh(QUrl{u"io:/path"_s});
    QSignalSpy spy(&rh, &QOAuthUriSchemeReplyHandler::callbackDataReceived);
    QVERIFY(rh.isListening());

    QDesktopServices::openUrl(response_redirect_uri);
    QTRY_COMPARE(spy.size(), 1);
    QCOMPARE(spy.at(0).at(0).toByteArray(), response_redirect_uri.toEncoded());
}

QTEST_MAIN(tst_QOAuthUriSchemeReplyHandler)
#include "tst_oauthurischemereplyhandler.moc"
