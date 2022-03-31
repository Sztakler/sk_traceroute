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

int icmp_receive_packets(struct response_t *response, int sockfd, pid_t pid, uint16_t seqnum);

int validate_packet(struct icmp *icmp_header, pid_t pid, uint16_t seqnum);
int parse_data(struct response_t *response, char ip_addresses[3][20], uint32_t times_ms[3]);
int check_packet_identity(struct icmp *icmp_header, uint16_t id, uint16_t seq,
                          uint16_t ref_id, uint16_t ref_seq);

struct icmp *get_icmp_header_address_from_ip_header(struct ip *ip_header);
struct ip *get_ip_header_address_from_icmp(struct icmp* icmp_header);

void print_as_bytes(unsigned char *buff, ssize_t length);

#endif // !ICMP_RECEIVER_H