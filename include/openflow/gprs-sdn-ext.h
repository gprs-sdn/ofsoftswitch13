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

    GPRS_SDN_PUSH_IP = 0x3,
    GPRS_SDN_POP_IP = 0x4,

    GPRS_SDN_PUSH_UDP = 0x5,
    GPRS_SDN_POP_UDP = 0x6,

    GPRS_SDN_HELLO = 0x0100,
};

struct gprs_sdn_action_push_gprsns {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
    uint16_t bvci;                  /* BVCI */
    uint32_t tlli;					/* TLLI */
    uint8_t sapi;					/* SAPI */
    uint8_t nsapi;					/* NSAPI */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_push_gprsns) == 24);

struct gprs_sdn_action_push_ip {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
    uint8_t reserved[2]; 
    uint32_t dstip;			/* DESTINATION IP */
    uint32_t srcip;			/* SOURCE IP */
    uint8_t pad[4];	
}; 
OFP_ASSERT(sizeof(struct gprs_sdn_action_push_ip) == 24);

struct gprs_sdn_action_push_udp {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
    uint16_t dstport;		/* DESTINATION PORT */
    uint16_t srcport;		/* SOURCE PORT */
    uint8_t pad[2];
    uint32_t dstip;         /* DESTINATION IP NEEDED FOR CRC COMPUTATION*/
    uint32_t srcip;         /* SOURCE IP NEEDED FOR CEC COMPUTATION */
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_push_udp) == 24);

struct gprs_sdn_action_header {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_header) == 16);


#endif /* OPENFLOW_GPRS_SDN_EXT_H */
