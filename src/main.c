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

void callback(u_char *useless, 
        const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  static int count = 1;
  printf("\nPacket number [%d], length of this packet is: %d\n", 
          count++, pkthdr->len);
}

void printDevs(pcap_if_t *printDevice, 
        pcap_if_t *listOfDevices) {
    printf("PCAP: Finding available network devices...\n");
    printf("PCAP: Here is a list of available devices on your system\n");
    printf("--------------------------------------------------------\n");
    
    int i = 0;
    for(printDevice = listOfDevices; printDevice; 
            printDevice = printDevice->next) {
        printf("%d. %s", ++i, printDevice->name);
        if(printDevice->description)
            printf("\t\t%s\n", printDevice->description);
        else
            printf("\t\t(Sorry, no description available for this device)\n");
    }
}

int main(int argc, char *argv[]) {
    char *dev, dev_buff[64] = { 0 }, errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program fp; // holds compiled program
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
    printDevs(device, alldevs);

    // ask user to specify interface for sniffing
    printf("\nEnter the interface for sniffing: ");
    fgets(dev_buff, sizeof(dev_buff) - 1, stdin);

    dev_buff[strlen(dev_buff) - 1] = '\0'; // remove trailing newline

    if(strlen(dev_buff)) {
        dev = dev_buff;
        if(dev == NULL) {
            printf("\n[%s]\n", errbuf);
            exit(1);
        } else{
            printf("\n---You chose device [%s] to capture [%d] packets---\n",
                    dev, atoi(argv[2]));
        }
    } else {
        printf("\n---Invalid Entry---\n");
        exit(1);
    }

    // fetch network address and network mask
    pcap_lookupnet(dev, &pNet, &pMask, errbuf);

    // open device for sniffing
    descr = pcap_open_live(dev, BUFSIZ, 0,-1, errbuf);
    if(descr == NULL) {
        printf("\npcap_open_live() failed due to:\n[%s]\n", errbuf);
        return -1;
    }

    // compile the filter expression
    if(pcap_compile(descr, &fp, argv[1], 0, pNet) == -1) {
        printf("\npcap_compile() failed\n");
        return -1;
    }

    // filter compiled expression
    if(pcap_setfilter(descr, &fp) == -1) {
        printf("\npcap_setfilter() failed\n");
        exit(1);
    }

    // for every packet received, call the callback function
    // for now maximum limit on number of packets is specified
    // by user.
    pcap_loop(descr, atoi(argv[2]), callback, NULL);

    printf("\nDone sniffing!\n");
    return 0;
}
