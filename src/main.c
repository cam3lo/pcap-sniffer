#include <stdio.h>
#include <pcap.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>

int main(int argc, char *argv[]) {
    char *dev, dev_buff[64] = { 0 }, errbuf[PCAP_ERRBUF_SIZE];
    int i = 0;
    pcap_t *descr;
    struct bpf_program fp; // hold compiled program
    bpf_u_int32 pMask;     // subnet mask
    bpf_u_int32 pNet;      // ip address
    pcap_if_t *alldevs, *device;

    // check arguments
    if(argc != 3) {
        printf("\nUsage: %s [protocol] [number-of-packets]\n", argv[0]);
        return 0;
    }

    if(pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    // print available list to user
    printf("PCAP: Finding available network devices...\n");
    printf("PCAP: Here is a list of available devices on your system\n");
    printf("--------------------------------------------------------\n");

    for(device = alldevs; device; device = device->next) {
        printf("%d. %s", ++i, device->name);
        if(device->description)
            printf("\t(%s)\n", device->description);
        else
            printf("\tSorry, no description available for this device)\n");
    }
}
