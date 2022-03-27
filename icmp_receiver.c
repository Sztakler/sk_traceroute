#include "icmp_receiver.h"

void print_as_bytes(unsigned char *buff, ssize_t length)
{
    for (ssize_t i = 0; i < length; i++, buff++)
        printf("%.2x ", *buff);
}

int validate_packet(struct icmp *icmp_header, pid_t pid, uint16_t seqnum)
{
    uint16_t seq = 0, id = 0;

    if (icmp_header->icmp_type == ICMP_ECHOREPLY)
    {
        seq = ntohs(icmp_header->icmp_hun.ih_idseq.icd_seq);
        id = ntohs(icmp_header->icmp_hun.ih_idseq.icd_id);
    }
    else if (icmp_header->icmp_type == ICMP_TIME_EXCEEDED)
    {
        // Based on https://datatracker.ietf.org/doc/html/rfc792 [page 6]
        struct ip *echo_ip_header = (struct ip *)((void *)icmp_header + sizeof(struct icmphdr));
        ssize_t echo_ip_header_len = 4 * echo_ip_header->ip_hl;
        struct icmp *echo_icmp_header = (struct icmp *)((void *)echo_ip_header + echo_ip_header_len);

        seq = ntohs(echo_icmp_header->icmp_hun.ih_idseq.icd_seq);
        id = ntohs(echo_icmp_header->icmp_hun.ih_idseq.icd_id);
    }
    else
    {
        return 0;
    }

    printf("ICMP:\n\
\ttype:     %d\n\
\tcode:     %d\n\
\tid:       %d\n\
\tseqnum:   %d\n\
\tcksum:    %d\n\
",
           icmp_header->icmp_type,
           icmp_header->icmp_code,
           id,
           seq,
           icmp_header->icmp_cksum);

    if (id == pid && (seq == seqnum || seq == (seqnum - 1) || seq == (seqnum - 2)))
    {
        return 1;
    }

    return 0;
}

int icmp_receive_packets(int sockfd, pid_t pid, uint16_t seqnum)
{
    /* Use select to wait for packet in socket for given time. */
    fd_set descriptors;
    FD_ZERO(&descriptors);
    FD_SET(sockfd, &descriptors);
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;

    int received_packets = 0;
    int i = 0;

    uint32_t response_times_ms[3];
    char response_ips[3][20] = {"", "", ""};

    while (received_packets < 1)
    {
        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        uint8_t buffer[IP_MAXPACKET];

        int ready = select(sockfd + 1, &descriptors, NULL, NULL, &tv);

        if (ready < 0)
        {
            printf("\033[31mselect: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }
        // error;
        else if (ready == 0) // timeout
        {
            printf("\033[38;5;214m[DEBUG]<icmp_receive_packets>\
            \nReceiving packet[%d]:\
            \n\ttimeout\n\033[0m",
                   i);
            break;
        }
        else // select observed 'ready' descriptors ready to read
        {
            /* Receive packet from socket. */
            ssize_t packet_len = recvfrom(
                sockfd,       // file descriptor of socket
                buffer,       // pointer to buffer
                IP_MAXPACKET, // size of buffer
                0,
                (struct sockaddr *)&sender, // sender info
                &sender_len                 // sender info
            );

            if (packet_len < 0)
            {
                printf("\033[38;5;196mrecvfrom: %s\n", strerror(errno));
                return EXIT_FAILURE;
            }

            printf("\033[38;5;214m[DEBUG]<icmp_receive_packets>\
            \nReceiving packet[%d]:\
            \n\ttimeout\n\033[0m",
                   i);

            // Parse sender's IP address to string
            char sender_ip_string[20]; // sender IP string
            inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_string, sizeof(sender_ip_string));

            struct ip *ip_header = (struct ip *)buffer;
            ssize_t ip_header_len = 4 * ip_header->ip_hl;
            struct icmp *icmp_header = (struct icmp *)(buffer + ip_header_len);

            // printf("icmp_header\n");
            // print_as_bytes((unsigned char*)icmp_header, sizeof(icmp_header));

            if (validate_packet(icmp_header, pid, seqnum))
            {

                printf("valid\n");
                strcpy(response_ips[received_packets], sender_ip_string);
                response_times_ms[received_packets] = 1000 - (tv.tv_usec / 1000);
                printf("tv_msec: %ldms\n", 1000 - tv.tv_usec / 1000);
                received_packets++;
            }
            i++;
        }
    }

    return EXIT_SUCCESS;
}