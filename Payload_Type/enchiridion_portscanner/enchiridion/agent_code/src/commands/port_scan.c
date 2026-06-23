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

void portScan(char *host, char *port, char *mode, TaskResponse *resp) {

    int sockfd;
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr(host); 

    // Split on commas
    char* token = strtok(port, ",");

    int scanned_port = 0;
    size_t buf_len = 0;
    resp->output = malloc(BUF_LEN);

    // Iterate through each port
    while (token != NULL) {

        // TODO: Range parsing
        if (strchr(token, '-')) {
            printf("[-] Will do ranges later (%s)...\n", token);
            token = strtok(NULL, ",");
            continue;
        }

        printf("[*] Scanning %s...\n", token);
        scanned_port = scan(atoi(token), sockfd, serv_addr);

        if (scanned_port != -1) {
            // strcpy(resp->output, scanned_port);
            resp->output[buf_len] = scanned_port;
            buf_len += sizeof(scanned_port);

            resp->output[buf_len] = '\n';
            buf_len++;
        }

        token = strtok(NULL, ",");
    }

    resp->output[buf_len] = '\0';
    resp->status = 0;

    return;
}
