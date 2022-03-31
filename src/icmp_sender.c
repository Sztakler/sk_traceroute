/*
Imię i nazwisko: Krystian Jasionek
Numer indeksu:   317806
*/

#include "icmp_sender.h"

int icmp_send_packets(int sockfd, char *ip_address, int ttl, uint16_t id, uint16_t *seqnum)
{
    /* Configure sockaddr_in structure for this particular recipient. */
    struct sockaddr_in recipient;
    icmp_configure_sockaddr(&recipient, ip_address);

    set_ttl(sockfd, ttl);

    /* Configure ICMP packet. */
    struct icmp header;
    icmp_configure_packet_base(&header, id);

    for (int i = 0; i < 3; i++)
    {
        icmp_configure_packet_seqnum(&header, seqnum);
        icmp_configure_packet_chksum(&header, 0);
        /* Send packets. */
        ssize_t bytes_sent = sendto(
            sockfd,
            &header,
            sizeof(header),
            0,
            (struct sockaddr *)&recipient,
            sizeof(recipient));

        if (bytes_sent < 0)
        {
            perror("\033[31sendto() error\033[0m");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

u_int16_t compute_icmp_checksum(const void *buff, int length)
{
    u_int32_t sum;
    const u_int16_t *ptr = buff;
    assert(length % 2 == 0);
    for (sum = 0; length > 0; length -= 2)
        sum += *ptr++;
    sum = (sum >> 16) + (sum & 0xffff);
    return (u_int16_t)(~(sum + (sum >> 16)));
}

void icmp_configure_sockaddr(struct sockaddr_in *socket_address, char *ip_address)
{
    bzero(socket_address, sizeof(*socket_address));
    socket_address->sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &socket_address->sin_addr);
}

void set_ttl(int sockfd, int ttl)
{
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0)
    {
        perror("\033[31setsockopt() error\033[0m");
        exit(EXIT_FAILURE);
    }
}

void icmp_configure_packet_base(struct icmp *header, uint16_t id)
{
    header->icmp_type = ICMP_ECHO;
    header->icmp_code = 0;
    header->icmp_hun.ih_idseq.icd_id = htons(id);
}

void icmp_configure_packet_seqnum(struct icmp *header, uint16_t *seqnum)
{
    header->icmp_hun.ih_idseq.icd_seq = htons((*seqnum)++);
}

void icmp_configure_packet_chksum(struct icmp *header, int chksum)
{
    header->icmp_cksum = chksum;
    header->icmp_cksum = compute_icmp_checksum((uint16_t *)header, sizeof(*header));
}