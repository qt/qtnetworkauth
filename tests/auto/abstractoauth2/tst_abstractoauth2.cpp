// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtTest>
#include <QtNetworkAuth/qabstractoauth2.h>

#include "oauthtestutils.h"

using namespace Qt::StringLiterals;
using namespace std::chrono_literals;

class tst_AbstractOAuth2 : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void sslConfig();
    void invalidRefreshLeadTime();
    void tokenUrl();
    void autoRefresh();

private:
    QString testDataDir;
};

class TestFlow : public QAbstractOAuth2
{
    Q_OBJECT
public:
    TestFlow() {}
    explicit TestFlow(QObject *parent) : QAbstractOAuth2(parent) {}

public Q_SLOTS:
    void grant() override {}

protected Q_SLOTS:
    void refreshTokensImplementation() QT7_ONLY(override) {}
};

void tst_AbstractOAuth2::initTestCase()
{
    // QLoggingCategory::setFilterRules(QStringLiteral("qt.networkauth* = true"));
    testDataDir = QFileInfo(QFINDTESTDATA("../shared/certs")).absolutePath();
    if (testDataDir.isEmpty())
        testDataDir = QCoreApplication::applicationDirPath();
    if (!testDataDir.endsWith(QLatin1String("/")))
        testDataDir += QLatin1String("/");
}

void tst_AbstractOAuth2::sslConfig()
{
#ifdef QT_NO_SSL
    QSKIP("Skipping SSL test, not supported by build");
#else
    TestFlow oauth2;
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
#endif // QT_NO_SSL
}

void tst_AbstractOAuth2::invalidRefreshLeadTime()
{
    TestFlow oauth2;
    QCOMPARE(oauth2.refreshLeadTime(), 0s);
    QTest::ignoreMessage(QtWarningMsg, "Invalid refresh leadTime");
    oauth2.setRefreshLeadTime(-5s);
    QCOMPARE(oauth2.refreshLeadTime(), 0s);
}

void tst_AbstractOAuth2::tokenUrl()
{
    TestFlow oauth2;
    QCOMPARE_EQ(oauth2.tokenUrl(), QUrl());

    const QUrl someTokenUrl{"accessToken"_L1};
    const QUrl otherTokenUrl{"otherAccessToken"_L1};

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
}

void tst_AbstractOAuth2::autoRefresh()
{
    TestFlow oauth2;
    QSignalSpy autoRefreshSpy(&oauth2, &QAbstractOAuth2::autoRefreshChanged);

    QCOMPARE(oauth2.autoRefresh(), false);

    oauth2.setAutoRefresh(true);
    QCOMPARE(autoRefreshSpy.size(), 1);
    QCOMPARE(oauth2.autoRefresh(), true);
    QCOMPARE(autoRefreshSpy.at(0).at(0).toBool(), true);

    autoRefreshSpy.clear();
    oauth2.setAutoRefresh(false);
    QCOMPARE(autoRefreshSpy.size(), 1);
    QCOMPARE(oauth2.autoRefresh(), false);
    QCOMPARE(autoRefreshSpy.at(0).at(0).toBool(), false);
}


QTEST_MAIN(tst_AbstractOAuth2)
#include "tst_abstractoauth2.moc"
