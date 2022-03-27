#include "icmp_receiver.h"

void print_as_bytes(unsigned char *buff, ssize_t length)
{
    for (ssize_t i = 0; i < length; i++, buff++)
        printf("%.2x ", *buff);
}

int check_ips_uniqueness(char ip_addres[20], char ip_addresses[3][20], int n_unique_ips)
{
    for (int j = 0; j < n_unique_ips ; j++)
    {
        DEBUG_PRINT("\n\
n:      %d\n\
j:      %d\n\
new:    %s\n\
unique: %s\n",
            n_unique_ips, j, ip_addres, ip_addresses[j]);

        if (ip_addres[0] == '\0' || strcmp(ip_addres, ip_addresses[j]) == 0)
        {
            return 0;
        }
    }

    return 1;
}

void make_ip_string(char ip_addresses[3][20], char buffer[3 * 20])
{
    strcpy(buffer, ip_addresses[0]);
    for (int i = 1; i < 3; i++)
    {
        strcat(buffer, " ");
        strcat(buffer, ip_addresses[i]);
    }

    DEBUG_PRINT("buffer: %s\n", buffer);
}


/* Parses response data and populates 'struct response_t response' structure.
 * Returns 0 if all 3 responses were received, 1 if none were received and 2 otherwise.
 */
int parse_data(struct response_t *response, char ip_addresses[3][20], uint32_t times_ms[3])
{
    // printf("Response\n");

    uint64_t response_time_sum = 0;
    RESPONSE_TYPE response_type = SUCCESS;
    int missing_responses = 0;

    char unique_ips[3][20] = {"", "", ""};
    int n_unique_ips = 0;


    for (int i = 0; i < 3; i++)
    {
        DEBUG_PRINT("time_ms: %d\n", times_ms[i]);
        if (times_ms[i] == 0)
        {
            // missing response
            missing_responses++;
        }

        if (check_ips_uniqueness(ip_addresses[i], unique_ips, n_unique_ips))
        {
            strcpy(unique_ips[i], ip_addresses[i]);
            n_unique_ips++;
        }

        response_time_sum += times_ms[i];

        DEBUG_PRINT("\033[38;5;155mIP: %s %d\033[0m\n", ip_addresses[i], times_ms[i]);
    }

    make_ip_string(unique_ips, response->ip_addresses);
    response->avg_time_ms = response_time_sum / 3;

    if (missing_responses == 0)
    {
        response->type = SUCCESS;
        return 0;
    }
    if (missing_responses == 3)
    {
        response->type = NO_RESPONSE;
        return 1;
    }

    response->type = TIMEOUT;
    return 2;
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

    DEBUG_PRINT("\033[38;5;155m\nICMP:\n\
\ttype:     %d (%s)\n\
\tcode:     %d\n\
\tid:       %d\n\
\tseqnum:   %d\n\
\tcksum:    %d\n\
\033[0m",
           icmp_header->icmp_type, 
           icmp_header->icmp_type == ICMP_TIME_EXCEEDED ? "TIME_EXCEEDED" :
                                        icmp_header->icmp_type == ICMP_ECHOREPLY ? "ECHOREPLY" : "OTHER",
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

int icmp_receive_packets(struct response_t *response, int sockfd, pid_t pid, uint16_t seqnum)
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

    // while (received_packets < 3)
    for (int i = 0; i < 3; i++)
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
            DEBUG_PRINT("\033[38;5;155m\n\tReceiving packet[%d]:\
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

//             DEBUG_PRINT("\033[38;5;155m\nReceiving packet[%d]:\
// \n\ttimeout\n\033[0m",
//                    i);

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
                // printf("valid\n");
                DEBUG_PRINT("\033[38;5;155mvalid\n\033[0m");
                strcpy(response_ips[i], sender_ip_string);
                response_times_ms[i] = 1000 - (tv.tv_usec / 1000);
                DEBUG_PRINT("\033[38;5;155mtv_msec: %ldms\n\033[0m", 1000 - tv.tv_usec / 1000);
                // i++;
            }
            // i++;
        }


        DEBUG_PRINT("\033[38;5;155msz_ips: %ld sz_times: %ld\n\033[0m", sizeof(response_ips), sizeof(response_times_ms));
    }

    int parsed_status = parse_data(response, response_ips, response_times_ms);
    
    return EXIT_SUCCESS;
}