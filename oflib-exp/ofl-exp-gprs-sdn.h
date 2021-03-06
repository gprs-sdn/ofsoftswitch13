/* 
 *
 */

#ifndef OFL_EXP_GPRS_SDN_H
#define OFL_EXP_GPRS_SDN_H 1


#include "../oflib/ofl-structs.h"
#include "../oflib/ofl-messages.h"

struct ofl_exp_gprs_sdn_act_header {
    struct ofl_action_experimenter header;

    uint16_t subtype;
};

#ifndef GSM_IMSI_LEN 
#define GSM_IMSI_LEN 8
#endif

struct ofl_exp_gprs_sdn_act_push_gprsns {
    struct ofl_action_experimenter header;

    uint16_t subtype;

    uint16_t bvci;                  /* BVCI */
    uint32_t tlli;					/* TLLI */
    uint8_t sapi;					/* NSAPI */
    uint8_t nsapi;					/* NSAPI */
		uint16_t drx_param;	
		uint8_t imsi_len;
		uint8_t imsi[GSM_IMSI_LEN];
};

struct ofl_exp_gprs_sdn_act_push_udpip {
    struct ofl_action_experimenter header;
    
    uint16_t subtype;

    uint16_t dstport;
    uint16_t srcport;
    uint32_t dstip;
    uint32_t srcip;
};

int
ofl_exp_gprs_sdn_act_pack(struct ofl_action_header *src, struct ofp_action_header *dst);

ofl_err
ofl_exp_gprs_sdn_act_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst);

int
ofl_exp_gprs_sdn_act_free(struct ofl_action_header *act);

size_t
ofl_exp_gprs_sdn_act_ofp_len(struct ofl_action_header *act);

char *
ofl_exp_gprs_sdn_act_to_string(struct ofl_action_header *act);


#endif /* OFL_EXP_GPRS_SDN_H */
