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
    GPRS_SDN_PUSH_GPRSNS, 
    GPRS_SDN_POP_GPRSNS,

    GPRS_SDN_PUSH_IP,
    GPRS_SDN_POP_IP,

    GPRS_SDN_PUSH_UDP,
    GPRS_SDN_POP_UDP,

    GPRS_SDN_HELLO = 0x0100,
};

struct gprs_sdn_action_push_gprsns {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
	uint16_t tlli;					/* TLLI */
	uint8_t nsapi;					/* NSAPI */
    uint8_t pad[3];
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_push_gprsns) == 16);

struct gprs_sdn_action_header {
    uint16_t type;                  /* OFPAT_VENDOR. */
    uint16_t len;                   /* Length is 16. */
    uint32_t vendor;                /* NX_VENDOR_ID. */
    uint16_t subtype;               /* NXAST_RESUBMIT. */
    uint8_t pad[6];
};
OFP_ASSERT(sizeof(struct gprs_sdn_action_header) == 16);


#endif /* OPENFLOW_GPRS_SDN_EXT_H */
