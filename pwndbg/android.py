#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.color.message as message
import pwndbg.events
import pwndbg.file
import pwndbg.memoize
import pwndbg.remote


@pwndbg.memoize.reset_on_start
@pwndbg.memoize.reset_on_exit
def is_android():
    try:
        if pwndbg.file.get('/system/etc/hosts'):
            return True
    except OSError:
        pass

    return False

@pwndbg.events.start
def sysroot():
    cmd = 'set sysroot remote:/'
    if is_android():
        if gdb.parameter('sysroot') == 'target:':
            gdb.execute(cmd)
        else:
            print(message.notice("sysroot is already set, skipping %r" % cmd))

KNOWN_AIDS = {
0: "AID_ROOT",
1000: "AID_SYSTEM",
1001: "AID_RADIO",
1002: "AID_BLUETOOTH",
1003: "AID_GRAPHICS",
1004: "AID_INPUT",
1005: "AID_AUDIO",
1006: "AID_CAMERA",
1007: "AID_LOG",
1008: "AID_COMPASS",
1009: "AID_MOUNT",
1010: "AID_WIFI",
1011: "AID_ADB",
1012: "AID_INSTALL",
1013: "AID_MEDIA",
1014: "AID_DHCP",
1015: "AID_SDCARD_RW",
1016: "AID_VPN",
1017: "AID_KEYSTORE",
1018: "AID_USB",
1019: "AID_DRM",
1020: "AID_MDNSR",
1021: "AID_GPS",
1022: "AID_UNUSED1",
1023: "AID_MEDIA_RW",
1024: "AID_MTP",
1025: "AID_UNUSED2",
1026: "AID_DRMRPC",
1027: "AID_NFC",
1028: "AID_SDCARD_R",
1029: "AID_CLAT",
1030: "AID_LOOP_RADIO",
1031: "AID_MEDIA_DRM",
1032: "AID_PACKAGE_INFO",
1033: "AID_SDCARD_PICS",
1034: "AID_SDCARD_AV",
1035: "AID_SDCARD_ALL",
1036: "AID_LOGD",
1037: "AID_SHARED_RELRO",
1038: "AID_DBUS",
1039: "AID_TLSDATE",
1040: "AID_MEDIA_EX",
1041: "AID_AUDIOSERVER",
1042: "AID_METRICS_COLL",
1043: "AID_METRICSD",
1044: "AID_WEBSERV",
1045: "AID_DEBUGGERD",
1046: "AID_MEDIA_CODEC",
1047: "AID_CAMERASERVER",
1048: "AID_FIREWALL",
1049: "AID_TRUNKS",
1050: "AID_NVRAM",
2001: "AID_CACHE",
2002: "AID_DIAG",
2900: "AID_OEM_RESERVED_START",
2999: "AID_OEM_RESERVED_END",
3001: "AID_NET_BT_ADMIN",
3002: "AID_NET_BT",
3003: "AID_INET",
3004: "AID_NET_RAW",
3005: "AID_NET_ADMIN",
3006: "AID_NET_BW_STATS",
3007: "AID_NET_BW_ACCT",
3008: "AID_NET_BT_STACK",
3009: "AID_READPROC",
3010: "AID_WAKELOCK",
5000: "AID_OEM_RESERVED_2_START",
5999: "AID_OEM_RESERVED_2_END",
9997: "AID_EVERYBODY",
9998: "AID_MISC",
9999: "AID_NOBODY",
10000: "AID_APP",
50000: "AID_SHARED_GID_START",
59999: "AID_SHARED_GID_END",
99000: "AID_ISOLATED_START",
99999: "AID_ISOLATED_END",
100000: "AID_USER",
}

def aid_name(uid):
    if uid in KNOWN_AIDS:
        return KNOWN_AIDS[uid]

    for closest in sorted(KNOWN_AIDS, reverse=True):
        if uid > closest:
            break
    else:
        return str(uid)

    return "%s+%s" % (KNOWN_AIDS[closest], uid-closest)
