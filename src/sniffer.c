#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <pthread.h>
#include "log.h"
#include "sniffer.h"


int sniffer_create_instance(SNIFFER ** snifferptr, ALOWIT_LOG_INSTANCE *logger, char *tag, char *dev) // 0 on success
{
    tag = tag ? tag : "(null)";
    dev = dev ? dev : "wlan0mon";
    if(snifferptr && logger)
    {
        *snifferptr = (SNIFFER *)malloc(sizeof(SNIFFER));
        if (*snifferptr)
        {
            SNIFFER *sniffer = *snifferptr;
            sniffer->tag = tag;
            sniffer->protoHdlrs_len = 0;
            sniffer->mac_cb = NULL;
            sniffer->logger = logger;
            if (!pthread_mutex_init(&sniffer->macTbl_lock, NULL))
            {
                memset(sniffer->macTbl, NULL, sizeof(sniffer->macTbl));
                char erbuf[2000];
                sniffer->pcap_handle = pcap_open_live(dev, BUFSIZ, 0, 10, erbuf);
                if (sniffer->pcap_handle)
                {
                    struct bpf_program fp; 
                    bpf_u_int32 netp;
                    if(pcap_compile(sniffer->pcap_handle, &fp, PCAP_CAPTURE_FILTER, 0, netp) != -1)
                    {
                        if(pcap_setfilter(sniffer->pcap_handle, &fp) != -1)
                        {
                            //Ready to call pcap_dispatch..
                            alowit_log(logger, __LINE__, __FILE__, ALOWIT_INFO, ALOWIT_MAIN, "Successfully attached to interface %s", dev);
                            return 0;
                        }
                        else
                        {
                            alowit_log(logger, __LINE__, __FILE__, ALOWIT_ERROR, ALOWIT_MAIN, "Error setting pcap filter %s", erbuf);
                            //Error setting filter
                        }
                    }
                    else
                    {
                        alowit_log(logger, __LINE__, __FILE__, ALOWIT_ERROR, ALOWIT_MAIN, "Error compiling pcap filter %s", erbuf);
                        //Error compiling libpcap filter
                    }
                }
                else
                {
                    alowit_log(logger, __LINE__, __FILE__, ALOWIT_ERROR, ALOWIT_MAIN, "Error with pcap_open_live %s", erbuf);
                }
                pthread_mutex_destroy(&sniffer->macTbl_lock);
            }
            free(sniffer);
        }
    }
    return 1;
}

