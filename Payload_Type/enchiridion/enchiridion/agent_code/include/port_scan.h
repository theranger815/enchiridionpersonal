#ifndef PORT_SCAN_H
#define PORT_SCAN_H
#define PORT_SCAN_MAX_PORTS 65535
#define RECV_TIMEOUT_S 2
#define SCAN_DELAY_NS 150000L /

#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include "commands.h"
#include <stdint.h>
#include <linux/types.h>


   
struct BSDtcphdr
  {
    uint16_t source;
    uint16_t dest;
    uint32_t seq;
    uint32_t ack_seq;
#  if __BYTE_ORDER == __LITTLE_ENDIAN
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#  elif __BYTE_ORDER == __BIG_ENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#  else
#   error "Adjust your <bits/endian.h> defines"
#  endif
    uint16_t window;
    uint16_t check;
    uint16_t urg_ptr;
};
// host:  IPv4 address or hostname to scan
// ports: port spec - single ("80"), range ("1-1024"), or comma-separated
//        list of either ("22,80,8000-8010"), capped at PORT_SCAN_MAX_PORTS
// mode:  "syn" (raw-socket SYN scan, requires CAP_NET_RAW) or "banner"
//        (TCP connect scan with banner grab)
//int portScanCommand(const char *host, const char *ports, const char *mode, TaskResponse *resp);
void portScan(char *host, char *port, char *mode, TaskResponse *resp);
#endif // !PORT_SCAN_H
