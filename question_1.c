#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>

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

int main() {
    int raw_socket;
    struct sockaddr_in server;
    unsigned char buffer[65536]; // Maximum packet size
    // Creating  a raw socket
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        perror("Error Creating a Socket");
        exit(1);
    }
    while (1) {
        int data_size = recvfrom(raw_socket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            perror("Error recieving a Packet");
            exit(1);
        }
        // Process the received packet
        process_packet(buffer, data_size);
    }
    close(raw_socket);
    return 0;
}

