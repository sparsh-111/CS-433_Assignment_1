#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <signal.h>

// Function declarations
void process_packet(unsigned char* buffer, int size);
int getPID(int port);
void handle_ctrl_c(int signum);

// Global variable to indicate whether the user wants to continue or not
int keep_running = 1;

int main() {
    int raw_socket;
    struct sockaddr_in server;
    unsigned char buffer[65536]; // Maximum packet size

    // Creating a raw socket
    raw_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (raw_socket == -1) {
        perror("Error Creating a Socket");
        exit(1);
    }

    // Set up a signal handler for Ctrl+C
    signal(SIGINT, handle_ctrl_c);

    while (keep_running) {
        int data_size = recvfrom(raw_socket, buffer, sizeof(buffer), 0, NULL, NULL);
        if (data_size < 0) {
            perror("Error receiving a Packet");
            exit(1);
        }
        // Process the received packet
        process_packet(buffer, data_size);
    }
    close(raw_socket);
    return 0;
}

void process_packet(unsigned char* buffer, int size) {
    struct ip* iph = (struct ip*)buffer;
    if (iph->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcph = (struct tcphdr*)(buffer + iph->ip_hl * 4);
        printf("Source IP: %s\n", inet_ntoa(iph->ip_src));
        printf("Source Port: %d\n", ntohs(tcph->th_sport));
        printf("Destination IP: %s\n", inet_ntoa(iph->ip_dst));
        printf("Destination Port: %d\n", ntohs(tcph->th_dport));
        printf("\n");

        // Now, find the process ID associated with the port number
        int port_to_find = ntohs(tcph->th_sport); // Replace with the desired port
        int pid = getPID(port_to_find);
        if (pid != -1) {
            printf("Process ID: %d\n", pid);
        }
    }
}

int getPID(int port) {
    char command[100];
    char result[1000];
    sprintf(command, "lsof -i :%d | awk 'NR==2 {print $2}'", port);

    FILE *fp = popen(command, "r");
    if (fp == NULL) {
        perror("popen "); // failure occurred
        exit(EXIT_FAILURE);
    }

    if (fgets(result, sizeof(result), fp) != NULL) {
        int pid;
        if (sscanf(result, "%d", &pid) == 1) {
            pclose(fp);
            return pid;
        }
    }

    pclose(fp);
    printf("No valid process ID found for port %d.\n", port);
    return -1;
}

void handle_ctrl_c(int signum) {
    keep_running = 0;
}

