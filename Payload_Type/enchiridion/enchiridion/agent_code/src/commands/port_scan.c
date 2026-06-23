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

int scan(int port, int sockfd, struct sockaddr_in serv_addr) {
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("[!] ERROR: Socket creation failed");
    }
    serv_addr.sin_port = htons(port);

    // If connection fails
    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) != 0) {
        port = 0;
    }

    if (port != 0) 
        printf("Port %d is open\n", port);

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

    // Iterate through each port
    while (token != NULL) {

        // TODO: Range parsing
        if (strchr(token, '-')) {
            printf("[-] Will do ranges later (%s)...\n", token);
            token = strtok(NULL, ",");
            continue;
        }

        printf("[*] Scanning %s...\n", token);
        scan(atoi(token), sockfd, serv_addr);

        token = strtok(NULL, ",");
    }

    resp->output = malloc(100);
    strcpy(resp->output, "wifey still here\0");
    resp->status = 0;

    return;
}
