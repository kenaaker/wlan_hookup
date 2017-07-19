#include <QDebug>
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/family.h>
#include <netlink/genl/ctrl.h>
#include <linux/nl80211.h>
#include <net/if.h>
#include <stdlib.h>

#include "wlan_monitor.h"

static int finish_handler(struct nl_msg *, void *arg) {
    bool *done = (bool *)arg;

    *done = true;
    return NL_SKIP;
}

static int error_handler(struct sockaddr_nl *, struct nlmsgerr *err, void *arg) {
    qDebug() << "error_handler() called.";
    int *ret = (int *)arg;
    *ret = err->error;
    return NL_STOP;
}

static int ack_handler(struct nl_msg *, void *arg) {
    int *ret = (int *)arg;
    *ret = 0;
    return NL_STOP;
}

/* For family_handler() and nl_get_multicast_id(). */
struct handler_args {
    const char *group;
    int id;
};


static int family_handler(struct nl_msg *msg, void *arg) {
    struct handler_args *grp = (handler_args *)arg;
    struct nlattr *tb[CTRL_ATTR_MAX + 1];
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *mcgrp;
    int rem_mcgrp;

    nla_parse(tb, CTRL_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);

    if (tb[CTRL_ATTR_MCAST_GROUPS]) {
        nla_for_each_nested(mcgrp, tb[CTRL_ATTR_MCAST_GROUPS], rem_mcgrp) {
            struct nlattr *tb_mcgrp[CTRL_ATTR_MCAST_GRP_MAX + 1];

            nla_parse(tb_mcgrp, CTRL_ATTR_MCAST_GRP_MAX, (nlattr *)nla_data(mcgrp), nla_len(mcgrp), NULL);

            if (tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME] && tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]) {
                if (!strncmp((const char *)nla_data(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]), grp->group,
                             nla_len(tb_mcgrp[CTRL_ATTR_MCAST_GRP_NAME]))) {
                    grp->id = nla_get_u32(tb_mcgrp[CTRL_ATTR_MCAST_GRP_ID]);
                    break;
                }
            }
        }
    }

    return NL_SKIP;
}

static int nl_get_multicast_id(struct nl_sock *sock, const char *family, const char *group) {
    struct nl_msg *msg;
    struct nl_cb *cb;
    int ret;
    int ctrlid;
    struct handler_args grp = {
        .group = group,
        .id = -ENOENT,
    };

    msg = nlmsg_alloc();
    if (!msg) {
        ret = -ENOMEM;
    } else {
        cb = nl_cb_alloc(NL_CB_DEFAULT);
        if (!cb) {
            ret = -ENOMEM;
        } else {
            ctrlid = genl_ctrl_resolve(sock, "nlctrl");
            genlmsg_put(msg, 0, 0, ctrlid, 0, 0, CTRL_CMD_GETFAMILY, 0);
            ret = -ENOBUFS;
            if (nla_put(msg, CTRL_ATTR_FAMILY_NAME, strlen(family) + 1, family) >= 0) {
                ret = nl_send_auto_complete(sock, msg);
                if (ret >= 0) {
                    ret = 1;
                    nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &ret);
                    nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &ret);
                    nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, family_handler, &grp);

                    while (ret > 0) {
                        nl_recvmsgs(sock, cb);
                    }

                    if (ret == 0) {
                        ret = grp.id;
                    }
                }
            }
            nl_cb_put(cb);
        }
        nlmsg_free(msg);
    }
    return ret;
}

struct trigger_results {
    int done;
    int aborted;
};

/* Called by the kernel when the scan is done or has been aborted. */
static int callback_trigger(struct nl_msg *msg, void *arg) {
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
    struct trigger_results *results = (struct trigger_results *)arg;

    if (gnlh->cmd == NL80211_CMD_SCAN_ABORTED) {
        qDebug() << "Got NL80211_CMD_SCAN_ABORTED.";
        results->done = 1;
        results->aborted = 1;
    } else if (gnlh->cmd == NL80211_CMD_NEW_SCAN_RESULTS) {
        results->done = 1;
        results->aborted = 0;
    }  // else probably an uninteresting multicast message.

    return NL_SKIP;
}

/* Callback for NL_CB_SEQ_CHECK. */
static int no_seq_check(struct nl_msg *, void *) {
    return NL_OK;
}

/* Starts the scan and waits for it to finish. Does not return until the scan is done or has been aborted. */
static int do_scan_trigger(struct nl_sock *nls, int if_index, int driver_id) {
    struct trigger_results results = {
        .done = 0,
        .aborted = 0
    };
    struct nl_msg *msg;
    struct nl_cb *cb;
    struct nl_msg *ssids_to_scan;
    int err;
    int ret;
    int mcid = nl_get_multicast_id(nls, "nl80211", "scan");

    // Allocate the messages and callback handler.
    msg = nlmsg_alloc();
    if (!msg) {
        qDebug() << "ERROR: Failed to allocate netlink message for msg.";
        ret = -ENOMEM;
    } else {
        ssids_to_scan = nlmsg_alloc();
        if (!ssids_to_scan) {
            qDebug() << "ERROR: Failed to allocate netlink message for ssids_to_scan.";
            ret = -ENOMEM;
        } else {
            cb = nl_cb_alloc(NL_CB_DEFAULT);
            if (!cb) {
                qDebug() << "ERROR: Failed to allocate netlink callbacks.";
                ret = -ENOMEM;
            } else {
                nl_socket_add_membership(nls, mcid);  // Without this, callback_trigger() won't be called.
                // Setup the messages and callback handler.
                genlmsg_put(msg, 0, 0, driver_id, 0, 0, NL80211_CMD_TRIGGER_SCAN, 0);  // Setup which command to run.
                nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);  // Add message attribute, which interface to use.
                nl_cb_set(cb, NL_CB_VALID, NL_CB_CUSTOM, callback_trigger, &results);  // Add the callback.
                nl_cb_err(cb, NL_CB_CUSTOM, error_handler, &err);
                nl_cb_set(cb, NL_CB_FINISH, NL_CB_CUSTOM, finish_handler, &err);
                nl_cb_set(cb, NL_CB_ACK, NL_CB_CUSTOM, ack_handler, &err);
                nl_cb_set(cb, NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, NULL);  // No sequence checking for multicast messages.

                // Send NL80211_CMD_TRIGGER_SCAN to start the scan. The kernel may reply with NL80211_CMD_NEW_SCAN_RESULTS on
                // success or NL80211_CMD_SCAN_ABORTED if another scan was started by another process.
                err = 1;
                ret = nl_send_auto(nls, msg);  // Send the message.
                while (err > 0) {
                    ret = nl_recvmsgs(nls, cb);  // First wait for ack_handler(). This helps with basic errors.
                }
                if (err < 0) {
                    qDebug() << "WARNING: err has a value of " << err;
                }
                if (ret < 0) {
                    qDebug() << "ERROR: nl_recvmsgs() returned " << ret << nl_geterror(-ret);
                    return ret;
                }
                while (!results.done) {
                    nl_recvmsgs(nls, cb);  // Now wait until the scan is done or aborted.
                }
                if (results.aborted) {
                    qDebug() << "ERROR: Kernel aborted scan.";
                    ret = 1;
                }

                // Cleanup.
                nl_cb_put(cb);
                nl_socket_drop_membership(nls, mcid);  // No longer need this.
            }
            nlmsg_free(ssids_to_scan);
        }
        nlmsg_free(msg);
    }
    return ret;
}

static void make_ssid_list(QStringList *ssid_list, const char *ie, int ielen) {

    QString ssid_string;
    QByteArray ssid_bytes;

    while ((ielen >= 2) && (ielen >= ie[1])) {
        /* The ssid name does fit within the memory block supplied */
        if (ie[0] == 0) {       /* First byte of 0 marks a string */
            unsigned int ssid_name_string_len = ie[1];
            ssid_bytes = QByteArray((const char *)ie+2, ssid_name_string_len);
            ssid_string = QString(ssid_bytes);

            ssid_list->append(ssid_string);
        }
        ielen -= ie[1] + 2;
        ie += ie[1] + 2;
    }
}

/* Called by the kernel with a dump of the successful scan's data. Called for each SSID. */
static int callback_ssids(struct nl_msg *msg, void *closure) {
    int ret;
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    struct nla_policy bss_policy[NL80211_BSS_MAX + 1];

    QStringList *ssid_list = (QStringList *)closure;
    memset(bss_policy, 0, sizeof(bss_policy));
    bss_policy[NL80211_BSS_TSF].type = NLA_U64;
    bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
    bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
    bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
    bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
    bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
    bss_policy[NL80211_BSS_STATUS].type = NLA_U32;
    bss_policy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;

    /* Parse and error check. */
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (tb[NL80211_ATTR_BSS] == NULL) {
        qDebug() << "bss info missing.";
        ret = NL_SKIP;
    } else {
        if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) != 0) {
            qDebug() << "failed to parse nested attributes.";
            ret = NL_SKIP;
        } else {
            if (!bss[NL80211_BSS_BSSID]) {
                ret = NL_SKIP;
            } else {
                if (!bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
                    ret = NL_SKIP;
                } else {
                    make_ssid_list(ssid_list,(const char *)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
                                   nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));
                    ret = NL_SKIP;
                }
            }
        }
    }
    return ret;
}

static QStringList env_ssids(QString &wifi_interface) {
    int if_index; /* The wireless interface for scanning. */
    struct nl_sock *socket;
    int driver_id;
    int ret;

    QStringList ssid_list;

    if_index = if_nametoindex(wifi_interface.toLatin1());
    socket = nl_socket_alloc();
    genl_connect(socket);
    driver_id = genl_ctrl_resolve(socket, "nl80211");  /* Find the nl80211 driver ID. */

    /* Issue NL80211_CMD_TRIGGER_SCAN to the kernel and wait for it to finish. */
    int err = do_scan_trigger(socket, if_index, driver_id);
    if (err != 0) {
        qDebug() << "do_scan_trigger() failed with rc = " << err;
    } else {
        /* Now get info for all SSIDs detected. */
        struct nl_msg *msg = nlmsg_alloc();

        genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);  /* Setup which command to run. */
        nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);  /* Add message attribute, which interface to use. */
        nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback_ssids, (void *)&ssid_list);
        ret = nl_send_auto(socket, msg);  /* Send the message. */
        ret = nl_recvmsgs_default(socket);  /* Retrieve the kernel's answer. callback_ssid() updates the ssid_list */
        nlmsg_free(msg);
        if (ret < 0) {
            qDebug() << "ERROR: nl_recvmsgs_default() returned " << ret << " ("<< nl_geterror(-ret);
        }
    }
    nl_close(socket);
    nl_socket_free(socket);
    return ssid_list;
}

static QString make_ssid(const char *ie, int ielen) {

    QString ssid_string;
    QByteArray ssid_bytes;

    while ((ielen >= 2) && (ielen >= ie[1])) {
        /* The ssid name does fit within the memory block supplied */
        if (ie[0] == 0) {       /* First byte of 0 marks a string */
            unsigned int ssid_name_string_len = ie[1];
            ssid_bytes = QByteArray((const char *)ie+2, ssid_name_string_len);
            ssid_string = QString(ssid_bytes);
        }
        ielen -= ie[1] + 2;
        ie += ie[1] + 2;
    }
    return ssid_string;
}

/* Called by the kernel with a dump of the successful scan's data. Called for each SSID. */
static int callback_associated_ssid(struct nl_msg *msg, void *closure) {
    int ret;
    struct genlmsghdr *gnlh = (struct genlmsghdr *)nlmsg_data(nlmsg_hdr(msg));
    struct nlattr *tb[NL80211_ATTR_MAX + 1];
    struct nlattr *bss[NL80211_BSS_MAX + 1];
    struct nla_policy bss_policy[NL80211_BSS_MAX + 1];

    QString *ssid = (QString *)closure;
    memset(bss_policy, 0, sizeof(bss_policy));
    bss_policy[NL80211_BSS_TSF].type = NLA_U64;
    bss_policy[NL80211_BSS_FREQUENCY].type = NLA_U32;
    bss_policy[NL80211_BSS_BEACON_INTERVAL].type = NLA_U16;
    bss_policy[NL80211_BSS_CAPABILITY].type = NLA_U16;
    bss_policy[NL80211_BSS_SIGNAL_MBM].type = NLA_U32;
    bss_policy[NL80211_BSS_SIGNAL_UNSPEC].type = NLA_U8;
    bss_policy[NL80211_BSS_STATUS].type = NLA_U32;
    bss_policy[NL80211_BSS_SEEN_MS_AGO].type = NLA_U32;

    /* Parse and error check. */
    nla_parse(tb, NL80211_ATTR_MAX, genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL);
    if (tb[NL80211_ATTR_BSS] == NULL) {
        qDebug() << "bss info missing.";
        ret = NL_SKIP;
    } else {
        if (nla_parse_nested(bss, NL80211_BSS_MAX, tb[NL80211_ATTR_BSS], bss_policy) != 0) {
            qDebug() << "failed to parse nested attributes.";
            ret = NL_SKIP;
        } else {
            if (!bss[NL80211_BSS_BSSID]) {
                ret = NL_SKIP;
            } else {
                if (!bss[NL80211_BSS_INFORMATION_ELEMENTS]) {
                    ret = NL_SKIP;
                } else {
                    if (bss[NL80211_BSS_STATUS]) {
                        uint32_t bss_status;
                        bss_status = nla_get_u32(bss[NL80211_BSS_STATUS]);
                        if (bss_status == NL80211_BSS_STATUS_ASSOCIATED) {
                            *ssid = make_ssid((const char *)nla_data(bss[NL80211_BSS_INFORMATION_ELEMENTS]),
                                              nla_len(bss[NL80211_BSS_INFORMATION_ELEMENTS]));
                        }
                    }
                    ret = NL_SKIP;
                }
            }
        }
    }
    return ret;
}

static QString get_associated_ssid(QString &wifi_interface) {
    int if_index; /* The wireless interface for scanning. */
    struct nl_sock *socket;
    int driver_id;
    int ret;

    QString ssid;

    if_index = if_nametoindex(wifi_interface.toLatin1());
    socket = nl_socket_alloc();
    genl_connect(socket);
    driver_id = genl_ctrl_resolve(socket, "nl80211");  /* Find the nl80211 driver ID. */

    /* Now get info for all SSIDs detected. */
    struct nl_msg *msg = nlmsg_alloc();

    genlmsg_put(msg, 0, 0, driver_id, 0, NLM_F_DUMP, NL80211_CMD_GET_SCAN, 0);  /* Setup which command to run. */
    nla_put_u32(msg, NL80211_ATTR_IFINDEX, if_index);  /* Add message attribute, which interface to use. */
    nl_socket_modify_cb(socket, NL_CB_VALID, NL_CB_CUSTOM, callback_associated_ssid, (void *)&ssid);
    ret = nl_send_auto(socket, msg);  /* Send the message. */
    ret = nl_recvmsgs_default(socket);  /* Retrieve the kernel's answer. callback_associated()) sets ssid */
    nlmsg_free(msg);
    if (ret < 0) {
        qDebug() << "ERROR: nl_recvmsgs_default() returned " << ret << " ("<< nl_geterror(-ret);
    }
    nl_close(socket);
    nl_socket_free(socket);
    return ssid;
}

wlan_monitor::wlan_monitor(QObject *parent): QObject(parent) {
    cycle_count = 0;
    ifx_name = QString("wlan0");
}

void wlan_monitor::run_wlan_monitor() {

    connect(&monitor_ssids, SIGNAL(timeout()), this, SLOT(get_association()));
    connect(&monitor_associations, SIGNAL(timeout()), this, SLOT(get_ssids()));

    monitor_ssids.start(10 * 1000);
    monitor_associations.start(30 * 1000);
}

void wlan_monitor::get_ssids() {
    ssid_list = env_ssids(ifx_name);
    qDebug() << "List of ssids is" << ssid_list;
    if ((ssid_list.contains(preferred_ssid)) &&
        (associated_ssid != preferred_ssid)) {
        qDebug() << "Going to try to switch WiFi association to " << preferred_ssid;
        emit try_for_preferred_association();
    }
}

void wlan_monitor::get_association() {

    associated_ssid = get_associated_ssid(ifx_name);
    qDebug() << "Asssociated ssid is" << associated_ssid;
}

void wlan_monitor::try_for_preferred_association() {

    qDebug() << "Trying for preferred WiFi association" << preferred_ssid;
    system("/sbin/ifdown wlan0; sleep 5; /sbin/ifup wlan0");
}
