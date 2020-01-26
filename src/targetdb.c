#include <stdio.h>
#include <stdlib.h>
#include "targetdb.h"
#include "sniffer.h"
#include "ieee80211.h"

#define CRC16 0x8005

//https://stackoverflow.com/questions/10564491/function-to-calculate-a-crc16-checksum
uint16_t gen_crc16(const uint8_t *data, uint16_t size)
{
    uint16_t out = 0;
    int bits_read = 0, bit_flag;

    /* Sanity check: */
    if(data == NULL)
        return 0;

    while(size > 0)
    {
        bit_flag = out >> 15;

        /* Get next bit: */
        out <<= 1;
        out |= (*data >> bits_read) & 1; // item a) work from the least significant bits

        /* Increment bit counter: */
        bits_read++;
        if(bits_read > 7)
        {
            bits_read = 0;
            data++;
            size--;
        }

        /* Cycle check: */
        if(bit_flag)
            out ^= CRC16;

    }

    // item b) "push out" the last 16 bits
    int i;
    for (i = 0; i < 16; ++i) {
        bit_flag = out >> 15;
        out <<= 1;
        if(bit_flag)
            out ^= CRC16;
    }

    // item c) reverse the bits
    uint16_t crc = 0;
    i = 0x8000;
    int j = 0x0001;
    for (; i != 0; i >>=1, j <<= 1) {
        if (i & out) crc |= j;
    }

    return crc;
}

int remove_cb_for_mac(SNIFFER *sniffer, uint8_t *mac, void *cb)
{
    if (sniffer)
    {
        if (!pthread_mutex_lock(&sniffer->macTbl_lock))
        {
            uint16_t crc = gen_crc16(mac, IEEE80211_ADDR_LEN);
            if (sniffer->macTbl[crc] == NULL)
            {
                //There's nothing to remove!
                return 1;
            }
            else
            {
                
            }
            
        }
    }
    return 1;
}

int add_cb_for_mac(SNIFFER *sniffer, uint8_t *mac, void *cb)
{
    if (sniffer)
    {
        if (!pthread_mutex_lock(&sniffer->macTbl_lock))
        {
            uint16_t crc = gen_crc16(mac, IEEE80211_ADDR_LEN);
            if (sniffer->macTbl[crc] == NULL)
            {
                //Allocate it
                sniffer->macTbl[crc] = malloc(sizeof(MAC_TABLE_ENTRY) + sizeof(uint16_t));
                if(sniffer->macTbl[crc])
                {
                    uint16_t *tblsLen = sniffer->macTbl[crc];
                    *tblsLen = 1;
                    MAC_TABLE_ENTRY *macTblEntry = tblsLen + 1;
                    macTblEntry->cb = cb;
                    int i;
                    for (i = 0; i < IEEE80211_ADDR_LEN; i++)
                        macTblEntry->macAddr[i] = mac[i];
                    alowit_log(sniffer->logger, __LINE__, __FILE__, ALOWIT_INFO, ALOWIT_MAIN, "Allocated new MAC table pointer with CRC %04X", crc);
                }
            }
            else
            {
                //Table already exists!
                void * realloced;
                uint16_t *curLenPtr = sniffer->macTbl[crc];
                realloced = realloc(sniffer->macTbl[crc], (*curLenPtr + 1) * sizeof(MAC_TABLE_ENTRY) + sizeof(uint16_t));
                if (realloced)
                {
                    sniffer->macTbl[crc] = realloced;
                    curLenPtr = sniffer->macTbl[crc];
                    *curLenPtr++;
                    MAC_TABLE_ENTRY *macTblEntry = curLenPtr + 1;
                    macTblEntry += *curLenPtr - 1;
                    macTblEntry->cb = cb;
                    int i;
                    for (i = 0; i < IEEE80211_ADDR_LEN; i++)
                        macTblEntry->macAddr[i] = mac[i];
                    alowit_log(sniffer->logger, __LINE__, __FILE__, ALOWIT_INFO, ALOWIT_MAIN, "Added to existing MAC table pointer with CRC %04X", crc);
                }
            }
            return pthread_mutex_unlock(&sniffer->macTbl_lock);
        }
    }
    return 1;
}