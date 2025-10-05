#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>
#include <string.h>
#include <stdio.h>

#define MAX_RTABLE_SIZE 100000
#define MAX_ARP_SIZE 100
#define MAX_PACKET_LEN 1400
#define IP_PROTOCOL 0x0800

struct route_table_entry rtable[MAX_RTABLE_SIZE];
int rtable_size;

struct arp_table_entry arp_table[MAX_ARP_SIZE];
int arp_table_size;

typedef struct trie_node {
    struct trie_node *zero;
    struct trie_node *one;
    struct route_table_entry *route;
} trie_node;

trie_node *build_routing_trie(struct route_table_entry *rtable, int rtable_size) {
    trie_node *root = calloc(1, sizeof(trie_node));
    for (int i = 0; i < rtable_size; i++) {
        uint32_t prefix = ntohl(rtable[i].prefix);
        uint32_t mask = ntohl(rtable[i].mask);

        trie_node *node = root;
        for (int bit = 31; bit >= 0; bit--) {
            if (!(mask & (1 << bit))) break;

            int direction = (prefix & (1 << bit)) ? 1 : 0;
            if (direction == 0) {
                if (!node->zero) node->zero = calloc(1, sizeof(trie_node));
                node = node->zero;
            } else {
                if (!node->one) node->one = calloc(1, sizeof(trie_node));
                node = node->one;
            }
        }

        node->route = &rtable[i];
    }
    return root;
}

struct route_table_entry *trie_lpm_lookup(trie_node *root, uint32_t ip) {
    ip = ntohl(ip);
    trie_node *node = root;
    struct route_table_entry *best_match = NULL;

    for (int bit = 31; bit >= 0; bit--) {
        if (!node) break;

        if (node->route)
            best_match = node->route;

        int direction = (ip & (1 << bit)) ? 1 : 0;
        node = direction ? node->one : node->zero;
    }

    return best_match;
}

void free_trie(trie_node *node) {
    if (!node) return;
    free_trie(node->zero);
    free_trie(node->one);
    free(node);
}

void send_icmp_error(char *orig_buf, size_t orig_len, uint8_t error_type, uint8_t error_code, int recv_interface) {
    char pkt_buf[MAX_PACKET_LEN];
    memset(pkt_buf, 0, MAX_PACKET_LEN);

    struct ether_hdr *orig_eth = (struct ether_hdr *) orig_buf;
    struct ip_hdr *orig_ip = (struct ip_hdr *) (orig_buf + sizeof(struct ether_hdr));

    size_t appended_data_len = sizeof(struct ip_hdr) + 8;
    if ((orig_len - sizeof(struct ether_hdr)) < appended_data_len)
        appended_data_len = orig_len - sizeof(struct ether_hdr);

    struct ether_hdr *eth_hdr = (struct ether_hdr *) pkt_buf;
    memcpy(eth_hdr->ethr_dhost, orig_eth->ethr_shost, 6);
    uint8_t src_mac[6];
    get_interface_mac(recv_interface, src_mac);
    memcpy(eth_hdr->ethr_shost, src_mac, 6);
    eth_hdr->ethr_type = htons(IP_PROTOCOL);

    struct ip_hdr *ip_hdr = (struct ip_hdr *)(pkt_buf + sizeof(struct ether_hdr));
    ip_hdr->ver = 4;
    ip_hdr->ihl = 5;
    ip_hdr->tos = 0;
    uint16_t icmp_payload_len = 8 + appended_data_len;
    uint16_t total_ip_len = sizeof(struct ip_hdr) + icmp_payload_len;
    ip_hdr->tot_len = htons(total_ip_len);
    ip_hdr->id = htons(0);
    ip_hdr->frag = htons(0);
    ip_hdr->ttl = 64;
    ip_hdr->proto = IPPROTO_ICMP;
    char *src_ip_str = get_interface_ip(recv_interface);
    inet_pton(AF_INET, src_ip_str, &(ip_hdr->source_addr));
    ip_hdr->dest_addr = orig_ip->source_addr;
    ip_hdr->checksum = 0;
    ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *)(pkt_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
    icmp_hdr->mtype = error_type;
    icmp_hdr->mcode = error_code;
    *((uint32_t *)(&icmp_hdr->un_t)) = 0;

    uint8_t *icmp_data = (uint8_t *) (pkt_buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr) + 8);
    memcpy(icmp_data, orig_buf + sizeof(struct ether_hdr), appended_data_len);

    size_t icmp_total_len = 8 + appended_data_len;
    icmp_hdr->check = 0;
    icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_total_len));

    size_t total_pkt_len = sizeof(struct ether_hdr) + total_ip_len;
    send_to_link(total_pkt_len, pkt_buf, recv_interface);
}

void process_icmp_echo(char *buf, size_t len, int recv_interface) {
    struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
    struct ip_hdr *ip_hdr = (struct ip_hdr *) (buf + sizeof(struct ether_hdr));
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr *) (buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));

    char *router_ip_str = get_interface_ip(recv_interface);
    uint32_t router_ip;
    inet_pton(AF_INET, router_ip_str, &router_ip);
    if (ip_hdr->dest_addr != router_ip)
        return;

    if (icmp_hdr->mtype == 8 && icmp_hdr->mcode == 0) {
        printf("Primim Echo Request, trimitem Echo Reply...\n");

        uint32_t temp_ip = ip_hdr->source_addr;
        ip_hdr->source_addr = ip_hdr->dest_addr;
        ip_hdr->dest_addr = temp_ip;

        uint8_t temp_mac[6];
        memcpy(temp_mac, eth_hdr->ethr_shost, 6);
        memcpy(eth_hdr->ethr_shost, eth_hdr->ethr_dhost, 6);
        memcpy(eth_hdr->ethr_dhost, temp_mac, 6);

        icmp_hdr->mtype = 0;
        icmp_hdr->check = 0;
        int icmp_len = len - sizeof(struct ether_hdr) - sizeof(struct ip_hdr);
        icmp_hdr->check = htons(checksum((uint16_t *)icmp_hdr, icmp_len));

        ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

        send_to_link(len, buf, recv_interface);
    }
}

int main(int argc, char *argv[]) {
    char buf[MAX_PACKET_LEN];
    static trie_node *trie_root = NULL;

    init(argv + 2, argc - 2);

    rtable_size = read_rtable(argv[1], rtable);
    DIE(rtable_size < 0, "read_rtable");

    arp_table_size = parse_arp_table("arp_table.txt", arp_table);
    DIE(arp_table_size < 0, "parse_arp_table");

    trie_root = build_routing_trie(rtable, rtable_size);

    while (1) {
        size_t len;
        int recv_interface = recv_from_any_link(buf, &len);
        DIE(recv_interface < 0, "recv_from_any_link");

        struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
        if (ntohs(eth_hdr->ethr_type) != IP_PROTOCOL)
            continue;

        struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

        uint16_t old_checksum = ntohs(ip_hdr->checksum);
        ip_hdr->checksum = 0;
        uint16_t new_checksum = checksum((uint16_t *) ip_hdr, sizeof(struct ip_hdr));
        if (new_checksum != old_checksum)
            continue;
        ip_hdr->checksum = htons(new_checksum);

        if (ip_hdr->ttl <= 1) {
            printf("TTL expirat, trimit mesaj ICMP Time Exceeded\n");
            send_icmp_error(buf, len, 11, 0, recv_interface);
            continue;
        }

        ip_hdr->ttl--;
        ip_hdr->checksum = 0;
        ip_hdr->checksum = htons(checksum((uint16_t *) ip_hdr, sizeof(struct ip_hdr)));

        char *router_ip_str = get_interface_ip(recv_interface);
        uint32_t router_ip;
        inet_pton(AF_INET, router_ip_str, &router_ip);
        if (ip_hdr->dest_addr == router_ip && ip_hdr->proto == IPPROTO_ICMP) {
            process_icmp_echo(buf, len, recv_interface);
            continue;
        }

        struct route_table_entry *route = trie_lpm_lookup(trie_root, ip_hdr->dest_addr);
        if (!route) {
            printf("Routa nu a fost găsită, trimit ICMP Destination Unreachable\n");
            send_icmp_error(buf, len, 3, 0, recv_interface);
            continue;
        }

        uint8_t *next_mac = NULL;
        for (int i = 0; i < arp_table_size; i++) {
            if (ntohl(arp_table[i].ip) == ntohl(route->next_hop)) {
                next_mac = arp_table[i].mac;
                break;
            }
        }
        if (!next_mac)
            continue;

        get_interface_mac(route->interface, eth_hdr->ethr_shost);
        memcpy(eth_hdr->ethr_dhost, next_mac, 6);

        send_to_link(len, buf, route->interface);
    }

    return 0;
}