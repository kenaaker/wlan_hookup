INCLUDEPATH += /usr/include/libnl3
LIBS += -lnl-3
LIBS += -lnl-genl-3

QT += core network
QT -= gui

CONFIG += c++11

TARGET = wlan_hookup
CONFIG += console
CONFIG -= app_bundle

TEMPLATE = app

SOURCES += \
    wlan_hookup.cpp \
    wlan_monitor.cpp

HEADERS += \
    wlan_monitor.h
