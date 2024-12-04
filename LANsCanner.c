#include <sys/socket.h>
#include <sys/ioctl.h>
#include <asm/types.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <arpa/inet.h>

#define PROTO_ARP 0x0806
#define ETH2_HEADER_LEN 14
#define MAC_LENGTH 6
#define IPV4_LENGTH 4
#define ARP_REQUEST 0x01
#define ARP_REPLY 0x02
#define BUF_SIZE 60

#define LOG_ERROR(msg, ...) fprintf(stderr, msg "\n", ##__VA_ARGS__)
#define LOG_INFO(msg, ...)   printf(msg "\n", ##__VA_ARGS__)

struct arp_header {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_len;
    unsigned char protocol_len;
    unsigned short opcode;
    unsigned char sender_mac[MAC_LENGTH];
    unsigned char sender_ip[IPV4_LENGTH];
    unsigned char target_mac[MAC_LENGTH];
    unsigned char target_ip[IPV4_LENGTH];
};

/* Converts struct sockaddr with an IPv4 address to network byte order uin32_t. Returns 0 on success. */

int int_ip4(struct sockaddr *addr, uint32_t *ip)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        *ip = i->sin_addr.s_addr;
        return 0;
    }
    LOG_ERROR("Not AF_INET");
    return 1;
}

/* Formats sockaddr containing IPv4 address as human readable string. Returns 0 on success. */

int format_ip4(struct sockaddr *addr, char *out)
{
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *i = (struct sockaddr_in *) addr;
        const char *ip = inet_ntoa(i->sin_addr);
        if (!ip) {
            return -2;
        }
        strcpy(out, ip);
        return 0;
    }
    return -1;
}

/* Writes interface IPv4 address as network byte order to ip. Returns 0 on success. */

int get_if_ip4(int fd, const char *ifname, uint32_t *ip) 
{
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(struct ifreq));
    if (strlen(ifname) >= IFNAMSIZ) {
        LOG_ERROR("Too long interface name");
        return -1;
    }
    strcpy(ifr.ifr_name, ifname);
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
        perror("SIOCGIFADDR");
        return -1;
    }

    return int_ip4(&ifr.ifr_addr, ip);
}

/* Gets interface information by name: IPv4, MAC, ifindex */

int get_if_info(const char *ifname, uint32_t *ip, char *mac, int *ifindex)
{
    int sd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sd <= 0) {
        perror("socket()");
        return -1;
    }

    struct ifreq ifr;
    if (strlen(ifname) >= IFNAMSIZ) {
        LOG_ERROR("Too long interface name");
        close(sd);
        return -1;
    }

    strcpy(ifr.ifr_name, ifname);
    if (ioctl(sd, SIOCGIFINDEX, &ifr) == -1) {
        perror("SIOCGIFINDEX");
        close(sd);
        return -1;
    }
    *ifindex = ifr.ifr_ifindex;

    if (ioctl(sd, SIOCGIFHWADDR, &ifr) == -1) {
        perror("SIOCGIFHWADDR");
        close(sd);
        return -1;
    }
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);

    if (get_if_ip4(sd, ifname, ip)) {
        close(sd);
        return -1;
    }
    
    close(sd);
    return 0;
}

/* Creates a raw socket that listens for ARP traffic on specific ifindex. Writes out the socket's FD. Return 0 on success. */

int bind_arp(int ifindex, int *fd)
{
    *fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (*fd < 1) {
        perror("socket()");
        return -1;
    }

    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    if (bind(*fd, (struct sockaddr*) &sll, sizeof(struct sockaddr_ll)) < 0) {
        perror("bind");
        close(*fd);
        return -1;
    }

    return 0;
}

/* Sends an ARP who-has request to dst_ip on interface ifindex, using source mac src_mac and source ip src_ip. */

int send_arp(int fd, int ifindex, const unsigned char *src_mac, uint32_t src_ip, uint32_t dst_ip)
{
    unsigned char buffer[BUF_SIZE] = {0};
    struct sockaddr_ll socket_address = {0};
    socket_address.sll_family = AF_PACKET;
    socket_address.sll_protocol = htons(ETH_P_ARP);
    socket_address.sll_ifindex = ifindex;
    socket_address.sll_hatype = htons(ARPHRD_ETHER);
    socket_address.sll_pkttype = PACKET_BROADCAST;
    socket_address.sll_halen = MAC_LENGTH;

    struct ethhdr *send_req = (struct ethhdr *)buffer;
    struct arp_header *arp_req = (struct arp_header *)(buffer + ETH2_HEADER_LEN);
    /* Broadcat */
    memset(send_req->h_dest, 0xff, MAC_LENGTH);
    
    /* Target MAC Zero */ 
    memset(arp_req->target_mac, 0x00, MAC_LENGTH);
    
    /* Set source mac to our MAC address */
    memcpy(send_req->h_source, src_mac, MAC_LENGTH);
    memcpy(arp_req->sender_mac, src_mac, MAC_LENGTH);

    /* Setting protocol of the packet */
    send_req->h_proto = htons(ETH_P_ARP);

    /* Creating ARP request */
    arp_req->hardware_type = htons(1);
    arp_req->protocol_type = htons(ETH_P_IP);
    arp_req->hardware_len = MAC_LENGTH;
    arp_req->protocol_len = IPV4_LENGTH;
    arp_req->opcode = htons(ARP_REQUEST);
    memcpy(arp_req->sender_ip, &src_ip, sizeof(uint32_t));
    memcpy(arp_req->target_ip, &dst_ip, sizeof(uint32_t));

    return sendto(fd, buffer, 42, 0, (struct sockaddr*)&socket_address, sizeof(socket_address)) == -1 ? -1 : 0;
}

/* Reads a single ARP reply from fd. Return 0 on success. */

int read_arp(int fd)
{
    unsigned char buffer[BUF_SIZE] = {0};
    ssize_t length = recvfrom(fd, buffer, BUF_SIZE, 0, NULL, NULL);
    if (length == -1) {
        perror("recvfrom()");
        return -1;
    }

    struct ethhdr *rcv_resp = (struct ethhdr *)buffer;
    struct arp_header *arp_resp = (struct arp_header *)(buffer + ETH2_HEADER_LEN);
    if (ntohs(rcv_resp->h_proto) != PROTO_ARP || ntohs(arp_resp->opcode) != ARP_REPLY) {
        return -1;
    }

    struct in_addr sender_ip;
    memcpy(&sender_ip.s_addr, arp_resp->sender_ip, sizeof(uint32_t));
    LOG_INFO("Sender IP: %s", inet_ntoa(sender_ip));
    LOG_INFO("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             arp_resp->sender_mac[0], arp_resp->sender_mac[1], arp_resp->sender_mac[2],
             arp_resp->sender_mac[3], arp_resp->sender_mac[4], arp_resp->sender_mac[5]);

    return 0;
}

/* Sample code that sends an ARP who-has request on interface <ifname> to IPv4 address <ip>.Returns 0 on success. */

int test_arping(const char *ifname, const char *ip)
{
    uint32_t dst = inet_addr(ip);
    if (dst == INADDR_NONE) {
        LOG_ERROR("Invalid destination IP");
        return -1;
    }

    uint32_t src_ip;
    int ifindex;
    char mac[MAC_LENGTH];
    if (get_if_info(ifname, &src_ip, mac, &ifindex)) {
        LOG_ERROR("Failed to get interface info");
        return -1;
    }

    int arp_fd;
    if (bind_arp(ifindex, &arp_fd)) {
        LOG_ERROR("Failed to bind ARP socket");
        return -1;
    }

    if (send_arp(arp_fd, ifindex, mac, src_ip, dst)) {
        LOG_ERROR("Failed to send ARP request");
        close(arp_fd);
        return -1;
    }

    while (read_arp(arp_fd) != 0);
    
    LOG_INFO("Received ARP reply");
    close(arp_fd);
    return 0;
}

int main(int argc, const char **argv)
{
    if (argc != 3) {
        LOG_ERROR("Usage: %s <INTERFACE> <DEST_IP>", argv[0]);
        return 1;
    }

    return test_arping(argv[1], argv[2]);
}
