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

#include "utils.h"

typedef enum RESPONSE_TYPE
{
    SUCCESS,    // results in '[n]. [IP] ... [time]\n'
    TIMEOUT,    // results in '???'
    NO_RESPONSE // results in '*'
} RESPONSE_TYPE;

struct response_t
{
    char ip_addres[20];
    RESPONSE_TYPE type;
    int time_ms;
};

void print_as_bytes(unsigned char *buff, ssize_t length);
int validate_packet(struct icmp *icmp_header, pid_t pid, uint16_t seqnum);
int parse_data(struct response_t *response, char ip_addresses[3][20], uint32_t times_ms[3]);
int icmp_receive_packets(int sockfd, pid_t pid, uint16_t seqnum);

#endif // !ICMP_RECEIVER_H