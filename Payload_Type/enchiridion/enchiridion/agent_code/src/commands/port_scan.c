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

#include <sys/types.h>
#include <errno.h>
#include <pthread.h>
#include <netdb.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>

unsigned short csum(unsigned short* ptr, int nbytes);
int get_local_ip(char* buffer, struct in_addr dest); 
char* hostname_to_ip(char* hostname); 
int start_recv(TaskResponse *resp, size_t *buf_cap, size_t *buf_len, int port); 
int synScan(int port, int sockfd, struct sockaddr_in serv_addr);
int process_packet(unsigned char* buffer, int size, int port); 
static void appendPort(char **buf, size_t *cap, size_t *len, int port);

#define BUF_LEN 1024

struct pseudo_header {
	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;

	struct tcphdr tcp;
};

unsigned short csum(unsigned short* ptr, int nbytes) {
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum = 0;
	while (nbytes > 1) {
		sum += *ptr++;
		nbytes -= 2;
	}
	if (nbytes == 1) {
		oddbyte = 0;
		*((u_char*)&oddbyte) = *(u_char*)ptr;
		sum += oddbyte;
	}

	sum = (sum >> 16) + (sum & 0xffff);
	sum = sum + (sum >> 16);
	answer = (short)~sum;

	return answer;
}

int get_local_ip(char* buffer, struct in_addr dest) {
	int sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (sock < 0) {
		return -1;
	}

	int dns_port = 53;
	struct sockaddr_in serv;

	memset(&serv, 0, sizeof(serv));
	serv.sin_family = AF_INET;
	serv.sin_addr.s_addr = dest.s_addr;
	serv.sin_port = htons(dns_port);

	// Connect
	int err = connect(sock ,(const struct sockaddr*)&serv, sizeof(serv));
	if (err < 0) {
		return -1;
	}

	struct sockaddr_in name;
	socklen_t namelen = sizeof(name);
	err = getsockname(sock, (struct sockaddr*)&name, &namelen);
	if (err < 0) {
		return -1;
	}

	close(sock);

	if (inet_ntop(AF_INET, &name.sin_addr, buffer, 100) == NULL) {
		return -1;
	}
	return 0;
}

char* hostname_to_ip(char* hostname) {
	struct hostent *he;
	struct in_addr **addr_list;
  //maybe use getaddrinfo()
	if ((he = gethostbyname(hostname)) == NULL) {
		herror("gethostbyname");
		return NULL;
	}

	addr_list = (struct in_addr **)he->h_addr_list;

	for (int i=0; addr_list[i] != NULL; i++){
		return inet_ntoa(*addr_list[i]);
	}

	return NULL;
}



int start_recv(TaskResponse *resp, size_t *buf_cap, size_t *buf_len, int port  ) {

	int sock_raw;

	socklen_t saddr_size;
	int data_size;
	struct sockaddr saddr;
  int sport;
	unsigned char *buffer = (unsigned char*)malloc(65536);

	sock_raw = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if (sock_raw < 0) {
	  perror("[!] Socket error!\n");
	
		return -1;
	}
	struct timeval tv;
	tv.tv_sec = RECV_TIMEOUT_S;
	tv.tv_usec = 0;
	if (setsockopt(sock_raw, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof(tv)) < 0) {
		perror("[!] Error setting socket option\n");
		
		return(-1);
	}

	saddr_size = sizeof(saddr);

	while (1) {
    //receive any packet,use process_packet to determine if the packet was meant for us
		data_size = recvfrom(sock_raw, buffer, 65536, 0, &saddr, &saddr_size);

		// Check whether a timeout ocurred
		if (errno == EAGAIN || errno == EWOULDBLOCK ){
			break;
		}

		if (data_size < 0) {
			perror("[!] Error receiving packets!\n");
			
			return -1;
		}

		sport = process_packet(buffer, data_size, port);
  
    if(!(sport == -1) ){
      appendPort(resp->output, buf_cap, buf_len, port);
    }
    
	}

	close(sock_raw);
	free(buffer);
	return 0;
}




int synScan(int port, int sockfd, struct sockaddr_in serv_addr){
  



  target = serv_addr
  


  // Create a raw socket
  sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
  if (sockfd < 0) {
        perror("[!] ERROR: Socket creation failed");
    }
  // TCP datagram
  char datagram[4096];
  memset(datagram,0,4096);
  // IP header
	struct iphdr* iph = (struct iphdr*)datagram;

	// TCP header
	struct tcphdr* tcph = (struct tcphdr*)(datagram+sizeof(struct ip));

	struct sockaddr_in dest;
	struct pseudo_header psh;
  
  int source_port = 6769;
  char source_ip[20];
  
  // Get the local IP on the right interface
	int err = get_local_ip(source_ip, dest_ip);
	if (err < 0) {
    perror("[!] ERROR: Could not get local ip");
    return -1;
	}

  
// Fill the IP header
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct ip) + sizeof(struct tcphdr);
	iph->id = htons(24541);
	iph->frag_off = htons(16384);
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0;
	iph->saddr = inet_addr(source_ip);
	iph->daddr = dest_ip.s_addr;

	iph->check = csum((unsigned short*)datagram, iph->tot_len >> 1);

	// Fill the TCP header
	tcph->source = htons(source_port);
	tcph->dest = htons(80);
	tcph->seq = htonl(1105024978);
	tcph->ack_seq = 0;
	tcph->doff = sizeof(struct tcphdr)/4;
	/*
	*  SYN scan: 0 1 0 0 0 0
	* XMAS scan: 1 0 0 1 0 1
	*/
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->window = htons(14600);
	tcph->check = 0; // filled by the kernel's IP stack
	tcph->urg_ptr = 0;

  int one = 1;
	const int* val = &one;

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) < 0) {
		perror("[!] ERROR: error setting socket option");

    return -1;
	}

  printf("[!] Starting TCP SYN scan");


  dest.sin_family = AF_INET;
	dest.sin_addr.s_addr = dest_ip.s_addr;
 
  //construct tcp header  
  tcph->dest = htons(port);
  tcph->check = 0;


  psh.source_address = inet_addr(source_ip);
	psh.dest_address = dest.sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr));

	memcpy(&psh.tcp, tcph, sizeof(struct tcphdr));

  tcph->check = csum((unsigned short*)&psh, sizeof(struct pseudo_header));

		// Send the packet
	if (sendto(sock, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
	  perror("[!] ERROR: error sending SYN packet");
    return -1;
  }
  
	struct timespec tim;
              tim.tv_sec = 0;
              tim.tv_nsec = SCAN_DELAY_NS;
              nanosleep(&tim, NULL);
  // Return 0 on success, otherwise -1 
  return 0; 
}
//change params to ensure proper parsing
int process_packet(unsigned char* buffer, int size, int port) {
	struct iphdr *iph = (struct iphdr*)buffer;
	struct sockaddr_in source;
	struct sockaddr_in dest;
	unsigned short iphdrlen;

	if (iph->protocol == 6) {
		struct iphdr *iph = (struct iphdr*)buffer;
		iphdrlen = iph->ihl * 4;

		struct tcphdr* tcph = (struct tcphdr*)(buffer + iphdrlen);
		memset(&source, 0, sizeof(source));
		source.sin_addr.s_addr = iph->saddr;

		memset(&dest, 0, sizeof(dest));
		dest.sin_addr.s_addr = iph->daddr;

		uint16_t s_port = ntohs(tcph->source);
    uint16_t d_port = ntohs(tcph->dest);

		if (d_port == port && tcph->syn && tcph->ack && source.sin_addr.s_addr == dest_ip.s_addr) {
			
    
			return s_port;
		}
    return -1;
	}
}

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
    if(strcmp(mode, "syn") == 0){
        pthread_t recv_thread;

        if (pthread_create(&recv_thread, NULL, start_recv, resp, &buf_cap, &buf_len ) {
            perror("[!] Error creating thread\n";
            
        }
            }
    // Iterate through each port (or port range)
    while (token != NULL) {
i       
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
                if(strcmp(mode, "banner") == 0){ 
                  scanned_port = scan(p, sockfd, serv_addr);
        
                  if (scanned_port != -1) {
                      appendPort(&resp->output, &buf_cap, &buf_len, scanned_port);
                  }
                }
                else if (strcmp(mode, "syn") == 0){
                  synScan(p, sockfd, serv_addr);
    
                  }
            }
        } else {
            printf("[*] Scanning %s...\n", token);
            if(strcmp(mode, "banner"){
              scanned_port = scan(atoi(token), sockfd, serv_addr);

              if (scanned_port != -1) {
                  appendPort(&resp->output, &buf_cap, &buf_len, scanned_port);
            }
      }
            else if (strcmp(mode, "syn") == 0){
              synScan(atoi(token), sockfd, serv_addr);
              }
        }

        token = strtok(NULL, ",");
    }
    if(strcmp(mode, "syn") == 0){ 
      pthread_join(recv_thread, NULL);
    }
    resp->output[buf_len] = '\0';
    resp->status = 0;

    return;
}
