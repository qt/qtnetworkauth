// Copyright (C) 2025 The Qt Company Ltd.
// SPDX-License-Identifier: LicenseRef-Qt-Commercial OR GPL-3.0-only

#include <QtTest>

class tst_AbstractOAuth2 : public QObject
{
    Q_OBJECT

private Q_SLOTS:
    void initTestCase();
};

void tst_AbstractOAuth2::initTestCase()
{
}

QTEST_MAIN(tst_AbstractOAuth2)
#include "tst_abstractoauth2.moc"
