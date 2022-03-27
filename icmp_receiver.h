#ifndef ICMP_RECEIVER_H
#define ICMP_RECEIVER_H

#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

void print_as_bytes (unsigned char* buff, ssize_t length);
int validate_packet(struct icmp *icmp_header, pid_t pid, uint16_t seqnum);
int icmp_receive_packets(int sockfd, pid_t pid, uint16_t seqnum);

#endif // !ICMP_RECEIVER_H