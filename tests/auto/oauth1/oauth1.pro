TEMPLATE = app
CONFIG += testcase
CONFIG += insignificant_test  # It's using external server. The test need a rewrite
TARGET = tst_oauth1
SOURCES  += tst_oauth1.cpp

QT = core core-private network networkauth networkauth-private testlib
