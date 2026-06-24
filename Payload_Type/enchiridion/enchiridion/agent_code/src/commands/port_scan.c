#include "port_scan.h"
#include "commands.h"
#include "cJSON.h"
#include "utils.h"
#include "agent.h"
#include "b64.h"
#include "enchiridion.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define BUF_LEN 1024

int scan(int port, int sockfd, struct sockaddr_in serv_addr) {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[!] ERROR: Socket creation failed");
    }
    serv_addr.sin_port = htons(port);

    // If connection fails
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        port = -1;
    }

    close(sockfd);
    return port;
}

static void appendPort(char **buf, size_t *cap, size_t *len, int port) {
    char line[16];
    int line_len = snprintf(line, sizeof(line), "%d\n", port);

    while (*len + (size_t)line_len + 1 > *cap) {
        *cap *= 2;
        *buf = realloc(*buf, *cap);
    }

    memcpy(*buf + *len, line, (size_t)line_len);
    *len += (size_t)line_len;
}

void portScan(char *host, char *port, char *mode, TaskResponse *resp) {

    int sockfd;
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(host);

    // Split on commas
    char* token = strtok(port, ",");

    int scanned_port = 0;
    size_t buf_len = 0;
    size_t buf_cap = BUF_LEN;
    resp->output = malloc(buf_cap);
    resp->output[0] = '\0';

    // Iterate through each port (or port range)
    while (token != NULL) {

        char *dash = strchr(token, '-');

        if (dash != NULL) {
            int range_start = atoi(token);
            int range_end = atoi(dash + 1);

            if (range_start > range_end) {
                int tmp = range_start;
                range_start = range_end;
                range_end = tmp;
            }
            if (range_start < 1) range_start = 1;
            if (range_end > PORT_SCAN_MAX_PORTS) range_end = PORT_SCAN_MAX_PORTS;

            for (int p = range_start; p <= range_end; p++) {
                printf("[*] Scanning %d...\n", p);
                scanned_port = scan(p, sockfd, serv_addr);

                if (scanned_port != -1) {
                    appendPort(&resp->output, &buf_cap, &buf_len, scanned_port);
                }
            }
        } else {
            printf("[*] Scanning %s...\n", token);
            scanned_port = scan(atoi(token), sockfd, serv_addr);

            if (scanned_port != -1) {
                appendPort(&resp->output, &buf_cap, &buf_len, scanned_port);
            }
        }

        token = strtok(NULL, ",");
    }

    resp->output[buf_len] = '\0';
    resp->status = 0;

    return;
}
