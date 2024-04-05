#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include "myheader.h"

void got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    struct ethheader *eth = (struct ethheader *)packet;

    printf("Ethernet Header:\n");
    printf("Destination MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->ether_dhost[i]);
        if (i != 5) printf(":");
    }
    printf("\nSource MAC: ");
    for (int i = 0; i < 6; i++) {
        printf("%02x", eth->ether_shost[i]);
        if (i != 5) printf(":");
    }
    printf("\nEther Type: 0x%04x\n\n", ntohs(eth->ether_type));

    if (ntohs(eth->ether_type) == 0x0800) { // IPv4
        struct ipheader *ip = (struct ipheader *)(packet + sizeof(struct ethheader));
        printf("IP Header:\n");
        printf("Version: %d\n", ip->iph_ver);
        printf("Header Length: %d\n", ip->iph_ihl);
        printf("Type of Service: %d\n", ip->iph_tos);
        printf("Total Length: %d\n", ntohs(ip->iph_len));
        printf("Identification: %d\n", ntohs(ip->iph_ident));
        printf("Flags: %d\n", ip->iph_flag);
        printf("Fragment Offset: %d\n", ntohs(ip->iph_offset));
        printf("Time to Live: %d\n", ip->iph_ttl);
        printf("Protocol: %d\n", ip->iph_protocol);
        printf("Header Checksum: %d\n", ntohs(ip->iph_chksum));
        printf("Source IP: %s\n", inet_ntoa(ip->iph_sourceip));
        printf("Destination IP: %s\n\n", inet_ntoa(ip->iph_destip));

        switch (ip->iph_protocol) {
            case IPPROTO_TCP: {
                struct tcpheader *tcp = (struct tcpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
                printf("TCP Header:\n");
                printf("Source Port: %d\n", ntohs(tcp->tcp_sport));
                printf("Destination Port: %d\n", ntohs(tcp->tcp_dport));
                printf("Sequence Number: %u\n", ntohl(tcp->tcp_seq));
                printf("Acknowledgment Number: %u\n", ntohl(tcp->tcp_ack));
                printf("Header Length: %d\n", TH_OFF(tcp) * 4);
                printf("Flags: ");
                if (tcp->tcp_flags & TH_FIN) printf("FIN ");
                if (tcp->tcp_flags & TH_SYN) printf("SYN ");
                if (tcp->tcp_flags & TH_RST) printf("RST ");
                if (tcp->tcp_flags & TH_PUSH) printf("PUSH ");
                if (tcp->tcp_flags & TH_ACK) printf("ACK ");
                if (tcp->tcp_flags & TH_URG) printf("URG ");
                if (tcp->tcp_flags & TH_ECE) printf("ECE ");
                if (tcp->tcp_flags & TH_CWR) printf("CWR ");
                printf("\n");
                printf("Window Size: %d\n", ntohs(tcp->tcp_win));
                printf("Checksum: %d\n", ntohs(tcp->tcp_sum));
                printf("Urgent Pointer: %d\n\n", ntohs(tcp->tcp_urp));
                break;
            }
            case IPPROTO_ICMP: {
                struct icmpheader *icmp = (struct icmpheader *)(packet + sizeof(struct ethheader) + sizeof(struct ipheader));
                printf("ICMP Header:\n");
                printf("Type: %d\n", icmp->icmp_type);
                printf("Code: %d\n", icmp->icmp_code);
                printf("Checksum: %d\n", ntohs(icmp->icmp_chksum));
                printf("Identifier: %d\n", ntohs(icmp->icmp_id));
                printf("Sequence Number: %d\n\n", ntohs(icmp->icmp_seq));
                break;
            }
            default:
                break;
        }
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "ip";
    bpf_u_int32 net;

    // Step 1: Open live pcap session on NIC with name enp0s3
    handle = pcap_open_live("enp0s25", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device enp0s3: %s\n", errbuf);
        exit(EXIT_FAILURE);
    }

    // Step 2: Compile filter_exp into BPF psuedo-code
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        exit(EXIT_FAILURE);
    }

    if (pcap_setfilter(handle, &fp) != 0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    // Step 3: Capture packets
    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}