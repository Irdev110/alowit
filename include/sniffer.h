#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include "log.h"


#define PCAP_CAPTURE_FILTER "wlan type data"

typedef struct alowit_sniffer SNIFFER;

typedef int (*mac_check_cb)(SNIFFER *sniffer, uint8_t *bssid_mac, uint8_t ra_mac, uint8_t ta_mac); //Returns 0 if check passed
typedef void (*protocol_hdlr_cb)(SNIFFER *sniffer, uint8_t *bssid_mac, uint8_t ra_mac, uint8_t ta_mac, void *ippdu, size_t ippdu_len); 


typedef struct alowit_protocol_hdlr{
    uint16_t llc_type;
    uint8_t ip_proto;
    protocol_hdlr_cb cb;
} PROTOCOL_HDLR;

typedef struct alowit_sniffer{
    char *tag;
    pcap_t *pcap_handle;
    mac_check_cb mac_cb;
    void * macTbl[UINT16_MAX];
    pthread_mutex_t macTbl_lock;
    size_t protoHdlrs_len;
    ALOWIT_LOG_INSTANCE *logger;
} SNIFFER;

int sniffer_create_instance(SNIFFER ** snifferptr, ALOWIT_LOG_INSTANCE *logger, char *tag, char *dev);