// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtTest>
#include <QtNetworkAuth/qabstractoauth2.h>

using namespace Qt::StringLiterals;

class tst_AbstractOAuth2 : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
    void tokenUrl();
    void autoRefresh();
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
