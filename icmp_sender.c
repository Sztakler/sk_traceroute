#include "icmp_sender.h"

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

int icmp_send_packets(int sockfd, char *ip_address, int ttl, pid_t pid, uint16_t *seqnum)
{
    /* Configure sockaddr_in structure for this particular recipient. */
    struct sockaddr_in recipient;
    bzero(&recipient, sizeof(recipient));
    recipient.sin_family = AF_INET;
    inet_pton(AF_INET, ip_address, &recipient.sin_addr);

    /* Set correct TTL in socket options. */
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(int)) < 0)
    {
        printf("setsockopt: %s\n", strerror(errno));
        return EXIT_FAILURE;
    }

    /* Configure ICMP packet. */
    struct icmp header;
    header.icmp_type = ICMP_ECHO;
    header.icmp_code = 0;
    header.icmp_hun.ih_idseq.icd_id = htons(pid);

    for (int i = 0; i < 1; i++)
    {
        header.icmp_hun.ih_idseq.icd_seq = htons((*seqnum)++);
        header.icmp_cksum = 0;
        header.icmp_cksum = compute_icmp_checksum((uint16_t *)&header, sizeof(header));

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
            printf("\033[31msendto: %s\n", strerror(errno));
            return EXIT_FAILURE;
        }

        printf("\033[38;5;226m[DEBUG]<icmp_send_packets>\
                \nSending packet [%d] to %s:\
                \n\tttl:        %d\
                \n\tpid:        %d\
                \n\tseqnum:     %d\
                \n\tchksum:     %d\
                \n\tbytes_sent: %ld\n\033[0m",
            i,
            ip_address,
            ttl,
            pid,
            *seqnum-1,
            header.icmp_cksum,
            bytes_sent);
    }
    

    return EXIT_SUCCESS;
}