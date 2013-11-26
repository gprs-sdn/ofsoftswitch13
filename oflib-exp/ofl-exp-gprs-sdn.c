/* 
 *
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>

#include "openflow/openflow.h"
#include "openflow/gprs-sdn-ext.h"
#include "ofl-exp-gprs-sdn.h"
#include "../oflib/ofl-print.h"
#include "../oflib/ofl-log.h"

#define LOG_MODULE ofl_exp_gprs_sdn
OFL_LOG_INIT(LOG_MODULE)

int
ofl_exp_gprs_sdn_act_pack(struct ofl_action_header *src, struct ofp_action_header *dst) {
	// TODO
	// aby fungovalo poriadne aj dpctl... 
	// inac je nam vytvaranie packetov na nic
	return -1;
}

ofl_err
ofl_exp_gprs_sdn_act_unpack(struct ofp_action_header *src, size_t *len, struct ofl_action_header **dst)
{
	struct gprs_sdn_action_header *exp = (struct gprs_sdn_action_header*) src;
	bool err_small = false;

	if (*len < sizeof(struct gprs_sdn_action_header)) {
		err_small = true;
	} else {
		switch (ntohs(exp->subtype)) {
		//TODO: others
		case GPRS_SDN_PUSH_GPRSNS:
			if (*len < sizeof(struct gprs_sdn_action_push_gprsns)) {
				err_small = false;
			} else {
				struct ofl_exp_gprs_sdn_act_push_gprsns *ofl;
				struct gprs_sdn_action_push_gprsns *exp2 = (struct gprs_sdn_action_push_gprsns*) exp;
				ofl = (struct ofl_exp_gprs_sdn_act_push_gprsns*) malloc(sizeof(*ofl));
				//TODO naparsovat zvysok ofl struktury
				ofl->subtype = ntohs(exp->subtype);
				ofl->tlli = ntohs(exp2->tlli);
				ofl->nsapi = exp2->nsapi;
				//TODO:
				*dst = (struct ofl_action_header*) ofl;
			}
			break;

		case GPRS_SDN_HELLO:
	 	case GPRS_SDN_PUSH_IP:
		case GPRS_SDN_POP_IP:
		case GPRS_SDN_PUSH_UDP:
		case GPRS_SDN_POP_UDP:
		case GPRS_SDN_POP_GPRSNS: {
			struct ofl_exp_gprs_sdn_act_header *ofl;
		    ofl = (struct exp_gprs_sdn_act_header*) malloc(sizeof(*ofl));
			//TODO: make clean - parsovat niekde inde
			ofl->header.header.type = OFPAT_EXPERIMENTER;
			ofl->header.header.len = ntohs(exp->len);
			ofl->header.experimenter_id = GPRS_SDN_VENDOR_ID;
			ofl->subtype = ntohs(exp->subtype);
			*dst = (struct ofl_action_header*) ofl;
			break;
			}
		}
	}

	if (err_small) {
        OFL_LOG_WARN(LOG_MODULE, "Received EXPERIMENTER action has invalid length (%zu).", *len);
        return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_LEN);
	} else {
		*len -= ntohs(src->len);
	}

	return 0;
}

int
ofl_exp_gprs_sdn_act_free(struct ofl_action_header *act) {
	free(act);
	return 0;
}

size_t
ofl_exp_gprs_sdn_act_ofp_len(struct ofl_action_header *act) {
	struct ofl_exp_gprs_sdn_act_header *exp = (struct ofl_exp_gprs_sdn_act_header*) act;

	switch (exp->subtype) {
	//TODO: other types
	case GPRS_SDN_PUSH_GPRSNS:
		return sizeof(struct gprs_sdn_action_push_gprsns);
	case GPRS_SDN_HELLO:
	case GPRS_SDN_PUSH_IP:
	case GPRS_SDN_POP_IP:
	case GPRS_SDN_PUSH_UDP:
	case GPRS_SDN_POP_UDP:
	case GPRS_SDN_POP_GPRSNS:
	}

	OFL_LOG_WARN(LOG_MODULE, "Getting header size for invalid EXPERIMENTER action");
	return sizeof(struct gprs_sdn_action_header);
}

char *
ofl_exp_gprs_sdn_act_to_string(struct ofl_action_header *act) {
	struct ofl_exp_gprs_sdn_act_header *exp = (struct ofl_exp_gprs_sdn_act_header*) act;
    char *str;
    size_t str_size;
    FILE *stream = open_memstream(&str, &str_size);

	switch(exp->subtype) {
	default:
        fprintf(stream, "exp{gprs_sdn,subtype=\"%u\"}", exp->subtype);
    }

    fclose(stream);
    return str;
}


