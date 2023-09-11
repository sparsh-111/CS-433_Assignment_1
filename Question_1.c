#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netdb.h>
void process_packet(unsigned char* buffer, int size) {
    struct ip *iph = (struct ip*)buffer;
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph->ip_hl * 4);
        printf("Source IP: %s\n", inet_ntoa(iph->ip_src));
        printf("Source Port: %d\n", ntohs(tcph->th_sport));
        printf("Destination IP: %s\n", inet_ntoa(iph->ip_dst));
        printf("Destination Port: %d\n", ntohs(tcph->th_dport));
        printf("\n");
    }
}

void reverse_dns_lookup(const char* ip_address) {
    struct sockaddr_in sa;
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &(sa.sin_addr));

    struct hostent* host = gethostbyaddr(&sa.sin_addr, sizeof(sa.sin_addr), AF_INET);
    if (host != NULL) {
        printf("Reverse DNS Lookup for %s: %s\n", ip_address, host->h_name);
    } else {
        printf("Reverse DNS Lookup for %s failed\n", ip_address);
    }
}

int main() {
    int raw_socket;
    struct sockaddr_in server;
    unsigned char buffer[65536]; // Maximum packet size

    // Create a raw socket
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        perror("Socket creation error");
        exit(1);
    }

    while (1) {
        int data_size = recvfrom(raw_socket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            perror("Packet receive error");
            exit(1);
        }

        // Process the received packet
        // process_packet(buffer, data_size);
        reverse_dns_lookup("35.201.103.21");
    }

    close(raw_socket);
    return 0;
}

