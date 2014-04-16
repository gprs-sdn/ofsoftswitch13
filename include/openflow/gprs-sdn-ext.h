/*
 *
 */

#ifndef OPENFLOW_GPRS_SDN_EXT_H
#define OPENFLOW_GPRS_SDN_EXT_H 1

#include "openflow/openflow.h"

/*
 * OpenFlow extensions for GPRS applications:
 * http://labss2.fiit.stuba.sk/TeamProject/2013/team04pkss/
 *
 * Structures are aligned to 64-bits.
 */

// TODO:
#define GPRS_SDN_OUI_STR "000042"
#define GPRS_SDN_VENDOR_ID 0x00000042

enum gprs_sdn_action_subtype { /* custom actions */
	GPRS_SDN_PUSH_GPRSNS = 0x1, 
	GPRS_SDN_POP_GPRSNS = 0x2,

	GPRS_SDN_PUSH_UDPIP = 0x3,
	GPRS_SDN_POP_UDPIP = 0x4,

};

#ifndef GSM_IMSI_LEN
#define GSM_IMSI_LEN 8
#endif

struct gprs_sdn_action_push_gprsns {
	uint16_t type;				/* OFPAT_VENDOR */
	uint16_t len;				/* 16 */
	uint32_t vendor;			/* NX_VENDOR_ID */
	uint16_t subtype;			/* 0x0001 */
	uint8_t reserved[2]; 
	uint32_t tlli;				/* TLLI */
	uint16_t bvci;				/* BVCI */
	uint8_t sapi;				/* NSAPI */
	uint8_t nsapi;				/* NSAPI */
	uint16_t drx_param;		/* BSSGP DL-UNITDATA DRX Parameter (EIE 0x0a) */
	uint8_t imsi_len;
	uint8_t imsi[GSM_IMSI_LEN];					/* BSSGP DL-UNITDATA IMSI (EIE 0x0d) -- BCD encoded IMSI (max 8 bytes) */
	uint8_t pad[1];
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_push_gprsns) == 32);

struct gprs_sdn_action_push_udpip {
	uint16_t type;				/* OFPAT_VENDOR */
	uint16_t len;				/* 24 */
	uint32_t vendor;			/* NX_VENDOR_ID */
	uint16_t subtype;			/* 0x0005 */
	uint8_t reserved[2];
	uint32_t dstip;				/* DESTINATION IP */
	uint32_t srcip;				/* SOURCE IP */
	uint16_t dstport;			/* DESTINATION PORT */
	uint16_t srcport;			/* SOURCE PORT */
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_push_udpip) == 24);

struct gprs_sdn_action_header {
	uint16_t type;				/* OFPAT_VENDOR. */
	uint16_t len;				/* 16 */
	uint32_t vendor;			/* NX_VENDOR_ID */
	uint16_t subtype;			/* subtype according to gprs_sdn_action_subtype */
	uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_header) == 16);


#endif /* OPENFLOW_GPRS_SDN_EXT_H */
