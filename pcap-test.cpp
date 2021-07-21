#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <pcap.h>
#include <stdio.h>
#include <algorithm>

void usage()
    {
        printf("syntax: pcap-test <interface>\n");
        printf("sample: pcap-test wlan0\n");
    }

typedef struct {
    char* dev_;
} Param;


Param param  = {
    .dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char* argv[]) {
    if (!parse(&param, argc, argv))
        return -1;


    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR  || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        //ether_header 구조체 : /usr/include/net/ethernet.h
        struct ether_header *ether_h;
        ether_h = (struct ether_header *)(packet);
        if (ntohs(ether_h->ether_type) != ETHERTYPE_IP)
            continue;


        struct ip *ip_h;
        ip_h = (struct ip *)(packet + sizeof(ether_header));
        if (ip_h->ip_p != IPPROTO_TCP)
            continue;

        struct tcphdr *tcp_h;
        tcp_h = (struct tcphdr *)(packet + sizeof(ether_header) + ip_h->ip_hl * 4);

        printf("========================= PCAP =========================\n");
        printf("------------Ethernet Header's src mac/dst mac-----------\n");
        printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ether_h->ether_shost[0], ether_h->ether_shost[1], ether_h->ether_shost[2], ether_h->ether_shost[3], ether_h->ether_shost[4], ether_h->ether_shost[5]);

        printf("src mac: %02x:%02x:%02x:%02x:%02x:%02x\n", ether_h->ether_shost[0], ether_h->ether_shost[1], ether_h->ether_shost[2], ether_h->ether_shost[3], ether_h->ether_shost[4], ether_h->ether_shost[5]);
        printf("dst mac: %02x:%02x:%02x:%02x:%02x:%02x\n\n", ether_h->ether_dhost[0], ether_h->ether_dhost[1], ether_h->ether_dhost[2], ether_h->ether_dhost[3], ether_h->ether_dhost[4], ether_h->ether_dhost[5]);



        printf("---------------IP Header's src ip/dst ip----------------\n");
        printf("src ip: %s\n", inet_ntoa(ip_h->ip_src));
        printf("dst ip: %s\n\n", inet_ntoa(ip_h->ip_dst));


        printf("-------------TCP Header's src port/dst port-------------\n");
        printf("src port: %d\n", ntohs(tcp_h->th_sport));
        printf("dst port: %d\n\n", ntohs(tcp_h->th_dport));


        printf("------------Payload(Data)'s hexadecimal value-----------\n");
        printf("payload:");

        const u_char *payload;
        payload = (u_char *)tcp_h + tcp_h->th_off * 4;

        for (int i = 0; i < 8; i++)
            printf(" %02x", payload[i]);

        printf("\n");
        printf("========================================================\n\n");
    }

    pcap_close(pcap);
}

