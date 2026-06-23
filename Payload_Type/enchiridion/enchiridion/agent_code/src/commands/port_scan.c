
#include "port_scan.h"

void portScan(char *host, char *port, char *mode, TaskResponse *resp) {

    int sockfd;
    struct sockaddr_in serv_addr;

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); 

    for (int port = 1; port <= 1024; port++) {
        sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd < 0) {
            perror("Socket creation failed");
            continue;
        }
        serv_addr.sin_port = htons(port);

        if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) == 0) {
            printf("Port %d is open\n", port);
        }
        close(sockfd);
    }

    resp->output = malloc(100);
    strcpy(resp->output, "wifey still here\0");
    resp->status = 0;

    return;
}
