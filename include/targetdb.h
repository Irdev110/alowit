#pragma once

#include <stdlib.h>
#include <stdint.h>
#include <pcap.h>
#include "ieee80211.h"
#include "sniffer.h"



typedef struct alowit_mac_tbl_entry_cb{
    uint8_t macAddr[IEEE80211_ADDR_LEN];
    void * cb;
} MAC_TABLE_ENTRY __attribute__((packed));


int add_cb_for_mac(SNIFFER *sniffer, uint8_t *mac, void *cb);