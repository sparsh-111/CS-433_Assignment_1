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

void identifySecretUsername(unsigned char* buffer, int size) {
    // Function to identify the secret username in the packet data
    struct ip *iph = (struct ip*)buffer;
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph->ip_hl * 4);

        // Convert the packet data to a string
        char* packetData = (char*)(buffer + iph->ip_hl * 4 + tcph->th_off * 4);
        
        // Implement your logic to search for the secret username
        // For example, you can search for a keyword or a specific pattern
        if (strstr(packetData, "My username is secret") != NULL) {
            // Extract and print the secret username
            char* usernameStart = strstr(packetData, "My username is secret") + strlen("My username is secret");
            printf("Secret Username: %s\n", usernameStart);
        }
    }
}

void identifyChecksum(unsigned char* buffer, int size) {
    // Function to identify the TCP checksum "0xcde1" and instructions in the path
    struct ip *iph = (struct ip*)buffer;
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph->ip_hl * 4);

        // Check for the specific TCP checksum value
        if (ntohs(tcph->th_sum) == 0xcde1) {
            printf("TCP Checksum: 0x%x\n", ntohs(tcph->th_sum));

            // Extract and print any instructions in the packet data
            char* packetData = (char*)(buffer + iph->ip_hl * 4 + tcph->th_off * 4);
            printf("Instructions in the packet: %s\n", packetData);
        }
    }
}

void identifyPersonByIP(unsigned char* buffer, int size) {
    // Function to identify the person by the IP address "12.34.56.78"
    struct ip *iph = (struct ip*)buffer;
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph->ip_hl * 4);

        // Check for the specific IP address
        char* targetIP = "12.34.56.78";
        if (strcmp(inet_ntoa(iph->ip_dst), targetIP) == 0 || strcmp(inet_ntoa(iph->ip_src), targetIP) == 0) {
            int sourcePort = ntohs(tcph->th_sport);
            int destPort = ntohs(tcph->th_dport);

            // Calculate the sum of connection ports
            int portSum = sourcePort + destPort;

            printf("IP Address: %s\n", targetIP);
            printf("Sum of Connection Ports: %d\n", portSum);
        }
    }
}

void identifyMilkshakeFlavor(unsigned char* buffer, int size) {
    // Function to identify the milkshake flavor requested from localhost
    struct ip *iph = (struct ip*)buffer;
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr*)(buffer + iph->ip_hl * 4);

        // Check for packets coming from localhost (127.0.0.1)
        char* localhostIP = "127.0.0.1";
        if (strcmp(inet_ntoa(iph->ip_src), localhostIP) == 0) {
            // Extract and print the milkshake flavor from the packet data
            char* packetData = (char*)(buffer + iph->ip_hl * 4 + tcph->th_off * 4);
            printf("Milkshake Flavor Requested: %s\n", packetData);
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
	// identifySecretUsername(buffer, data_size);
        // identifyChecksum(buffer, data_size);
        // identifyPersonByIP(buffer, data_size);
        // identifyMilkshakeFlavor(buffer, data_size);
   
    }

    close(raw_socket);
    return 0;
}
