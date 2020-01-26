#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include "sniffer.h"
#include "log.h"
#include "ieee80211.h"
#include "targetdb.h"

void pcapHandler(SNIFFER *sniffer, const struct pcap_pkthdr *header, const unsigned char *packet){
	// This struct is the RadioTap header: https://radiotap.org
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
		uint8_t it_rev; // Revision: Version of RadioTap
		uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
		uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};

	int offset = 0;
	struct radiotap_header *rtaphdr;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len; 
	struct ieee80211_frame *frame = (struct ieee80211_frame *) (packet + offset);

	if((frame->i_fc[0] & IEEE80211_FC0_VERSION_MASK) == IEEE80211_FC0_VERSION_0)
	{
		uint8_t dataType = (frame->i_fc[0] & IEEE80211_FC0_TYPE_MASK);
		uint8_t subType = (frame->i_fc[0] & IEEE80211_FC0_SUBTYPE_MASK);
		if (dataType == IEEE80211_FC0_TYPE_DATA && frame->i_fc[1] & IEEE80211_FC1_DIR_TODS && !(frame->i_fc[1] & IEEE80211_FC1_DIR_FROMDS)) // Must be data and TO DS (STA TO AP for QUANTUM against STA) and not between APs
		{
			size_t dataLen;
			uint8_t *dataPtr;
			
			if(subType == IEEE80211_FC0_SUBTYPE_QOS)
			{
				dataPtr = (struct ieee80211_qosframe *)(frame) + 1;
				alowit_log(sniffer->logger, __LINE__, __FILE__, ALOWIT_INFO, ALOWIT_MAIN, "Got QoS packet");
			}
			else
			{
				dataPtr = frame + 1;
			}
			if (frame->i_fc[1] & IEEE80211_FC1_PROT) 
			{
				dataPtr += 8; //CCMP/TKIP params len
			}
			dataLen = header->caplen - (dataPtr - (uint8_t *)rtaphdr);
			
			printf("Data: %d bytes\n", dataLen);
			int i = 0;
			for (i = 0; i < dataLen; i++)
			{
				printf("%02X", dataPtr[i]);
			}
			printf("\n");
			uint8_t *addr1 = frame->i_addr1; 
			uint8_t *addr2 = frame->i_addr2; 
			uint8_t *addr3 = frame->i_addr3;
			if (sniffer->mac_cb)
			{
				int mac_cb_result = sniffer->mac_cb(sniffer, addr3, addr1, addr2);
				if (!mac_cb_result)
				{
					//Send to handler
				}
			}
			fprintf(stdout,"addr1 string: %02X:%02X:%02X:%02X:%02X:%02X\n",addr1[0],addr1[1],addr1[2],addr1[3],addr1[4],addr1[5]);
			fprintf(stdout,"addr2 string: %02X:%02X:%02X:%02X:%02X:%02X\n",addr2[0],addr2[1],addr2[2],addr2[3],addr2[4],addr2[5]);
			fprintf(stdout,"addr3 string: %02X:%02X:%02X:%02X:%02X:%02X\n",addr3[0],addr3[1],addr3[2],addr3[3],addr3[4],addr3[5]);
		}
	}
	

	return;
}

int main(int argc, char *argv[]) {
	ALOWIT_LOG_INSTANCE *logger;
	if(!alowit_log_instance_init_from_fd(&logger, stdout))
	{
		alowit_log(logger, __LINE__, __FILE__, ALOWIT_INFO, ALOWIT_MAIN, "%s", "Successfully initialized logging");
		SNIFFER *testSniffer;
		sniffer_create_instance(&testSniffer, logger, "testtag", "wlan0mon");
		add_cb_for_mac(testSniffer, "\x00\x01\x02\x03\x04\x06", 0x12345678);
		add_cb_for_mac(testSniffer, "\x00\x01\x02\x03\x04\x05", 0x12345678);
		pcap_loop(testSniffer->pcap_handle, -1, pcapHandler, testSniffer);
		return 0;
	}
}