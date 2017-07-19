#ifndef WLAN_MONITOR_H
#define WLAN_MONITOR_H

#include <QObject>

class wlan_monitor : public QObject
{
    Q_OBJECT
public:
    explicit wlan_monitor(QObject *parent = nullptr);

signals:

public slots:
};

#endif // WLAN_MONITOR_H