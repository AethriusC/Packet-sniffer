#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> 

struct bpf_program fp;

void packet_handler(u_char* user_data, const struct pcap_pkthdr* pkthdr, const u_char* packet_data)
{
    printf("Packet captured: %d bytes\n", pkthdr->caplen);

    int i;
    for (i = 0; i < 14; i++)
    {
        printf("%02X ", packet_data[i]);
    }
    printf("\n");
}

int main()
{
    pcap_if_t* alldevs;
    pcap_if_t* d;
    int i = 0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char filter_exp[100]; 

    if (pcap_findalldevs(&alldevs, errbuf) == -1)
    {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        exit(1);
    }

    for (d = alldevs; d != NULL; d = d->next)
    {
        printf("%d. %s", ++i, d->name);
        if (d->description)
            printf(" (%s)\n", d->description);
        else
            printf(" (No description available)\n");
    }

    if (i == 0)
    {
        printf("\nNo interfaces found! Make sure WinPcap/Npcap is installed.\n");
        return 1;
    }

    int choice;
    do
    {
        printf("Enter the number of the interface you want to sniff (1-%d): ", i);
        if (scanf_s("%d", &choice) != 1)
        {
            printf("Invalid input. Please enter a number.\n");
            while (getchar() != '\n');
        }
    } while (choice < 1 || choice > i);

    i = 1;
    for (d = alldevs; d != NULL; d = d->next)
    {
        if (i == choice)
        {
            printf("\nSelected interface: %s\n", d->name);
            break;
        }
        i++;
    }

    printf("Enter the filter expression (e.g., 'port 80'): ");
    if (scanf_s("%99s", filter_exp) != 1)
    {
        printf("Invalid input. Exiting.\n");
        return 1;
    }

    pcap_t* handle;
    handle = pcap_open_live(d->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL)
    {
        fprintf(stderr, "Error in pcap_open_live: %s\n", errbuf);
        return 1;
    }

    if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1)
    {
        fprintf(stderr, "Error in pcap_compile: %s\n", pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1)
    {
        fprintf(stderr, "Error in pcap_setfilter: %s\n", pcap_geterr(handle));
        return 1;
    }
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_freealldevs(alldevs);
    pcap_close(handle);
    return 0;
}
