#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include "icmp_sender.h"
#include "icmp_receiver.h"


int main(int argc, char *argv[])
{
    /* Check program's input. */
    if (argc < 2)
    {
        printf("\033[31mInvalid argument! Usage: %s [IP address].\033[0m\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *ip_address = argv[1];

    /* Create raw socket with ICMP protocol. */
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0)
    {
        printf("socket error: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    pid_t pid = getpid() & 0xFFFF;
    uint16_t seqnum = 0; 

    // printf("pid: %x\nseqnum: %x\n", pid, seqnum);

    for (int ttl = 1; ttl <= 30; ttl++)
    {
        struct response_t *response;
        
        if (icmp_send_packets(sockfd, ip_address, ttl, pid, &seqnum) == EXIT_FAILURE)
            return EXIT_FAILURE;
        if (icmp_receive_packets(response, sockfd, pid, seqnum) == EXIT_FAILURE)
            return EXIT_FAILURE;

        switch (response->type)
        {
            case SUCCESS:
                printf("[%d] IP: %s %dms\n", ttl, response->ip_addresses, response->avg_time_ms);
                break;
            case TIMEOUT:
                printf("[%d] IP: %s ???ms\n", ttl, response->ip_addresses);
                break;
            case NO_RESPONSE:
                printf("[%d] * * *\n", ttl);
                break;
            default:
                printf("unrecognized state\n");
                break;
        }
    }

    return EXIT_SUCCESS;
}