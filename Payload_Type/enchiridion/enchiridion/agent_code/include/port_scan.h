#ifndef PORT_SCAN_H
#define PORT_SCAN_H
#define PORT_SCAN_MAX_PORTS 65535

#include "commands.h"

// host:  IPv4 address or hostname to scan
// ports: port spec - single ("80"), range ("1-1024"), or comma-separated
//        list of either ("22,80,8000-8010"), capped at PORT_SCAN_MAX_PORTS
// mode:  "syn" (raw-socket SYN scan, requires CAP_NET_RAW) or "banner"
//        (TCP connect scan with banner grab)
int portScanCommand(const char *host, const char *ports, const char *mode, TaskResponse *resp);

#endif // !PORT_SCAN_H
