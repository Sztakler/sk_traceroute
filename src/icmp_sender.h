#ifndef ICMP_SENDER_H
#define ICMP_SENDER_H

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

int icmp_send_packets(int sockfd, char *ip_address, int ttl, uint16_t id, uint16_t *seqnum);

u_int16_t compute_icmp_checksum(const void *buff, int length);
void set_ttl(int sockfd, int ttl);

void icmp_configure_sockaddr(struct sockaddr_in *socket_address, char *ip_address);
void icmp_configure_packet_base(struct icmp *header, uint16_t id);
void icmp_configure_packet_seqnum(struct icmp *header, uint16_t *seqnum);
void icmp_configure_packet_chksum(struct icmp *header, int chksum);

#endif // !ICMP_SENDER_H