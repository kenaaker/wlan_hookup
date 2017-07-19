#include <QCoreApplication>
#include <QTimer>
#include "wlan_monitor.h"

int main(int argc, char *argv[]) {

    QCoreApplication a(argc, argv);
    wlan_monitor monitor;
    QString preferred_ssid("Verizon-SM-N920V-F080");
    int ret = 0;

    QObject::connect(&monitor, SIGNAL(finished()), &a, SLOT(quit()));

    QTimer::singleShot(0, &monitor, SLOT(run_wlan_monitor()));

    monitor.set_preferred_ssid(preferred_ssid);

    ret = a.exec();

    return ret;
}
