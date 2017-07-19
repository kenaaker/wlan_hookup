#ifndef WLAN_MONITOR_H
#define WLAN_MONITOR_H

#include <QObject>
#include <QTimer>

class wlan_monitor : public QObject {
    Q_OBJECT
public:
    explicit wlan_monitor(QObject *parent = nullptr);
    void set_preferred_ssid(QString &s) {
        preferred_ssid = s;
    }

signals:
    void finished();

public slots:
    void run_wlan_monitor(void);
    void get_association(void);
    void try_for_preferred_association(void);
    void get_ssids();

private:
    int cycle_count;
    QStringList ssid_list;
    QString ifx_name;
    QString associated_ssid;
    QString preferred_ssid;

    QTimer monitor_ssids;
    QTimer monitor_associations;
};

#endif // WLAN_MONITOR_H
