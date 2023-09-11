#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ether.h>

void identifyFlag(unsigned char* buffer, int size) {
    struct ip *iph = (struct ip*)buffer;
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph->ip_hl * 4);
        // Check for the keyword "Flag" in the packet data
	
        // Extract TCP flags
        int tcp_flags = tcph->th_flags;

        // Check for specific TCP flags and print them
        if (tcp_flags & TH_SYN) {
            printf("SYN flag set\n");
        }
        if (tcp_flags & TH_ACK) {
            printf("ACK flag set\n");
        }
        if (tcp_flags & TH_FIN) {
            printf("FIN flag set\n");
        }
        if (tcp_flags & TH_RST) {
            printf("RST flag set\n");
        }
        if (tcp_flags & TH_PUSH) {
            printf("PSH flag set\n");
        }
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
	// process_packet(buffer,data_size);

        // Call the functions to identify hidden information in packets
        identifyFlag(buffer, data_size);
   
    }

    close(raw_socket);
    return 0;
}
