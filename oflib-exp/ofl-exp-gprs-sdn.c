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
#include "../lib/packets.h"

#define IP_FMT "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8

#define LOG_MODULE ofl_exp_gprs_sdn
OFL_LOG_INIT(LOG_MODULE)


char imsi_string[GSM_IMSI_LEN*2 + 1];
char bcd_char[] = { '0', '1', '2', '3', '4', '5', '6', '7', 
										'8', '9', 'x', 'x', 'x', 'x', 'x', ' ', };

char *imsi_to_string(uint8_t *imsi, uint8_t imsi_len);


char *imsi_to_string(uint8_t *imsi, uint8_t imsi_len)
{
	int i, digits;
	uint8_t imsi_byte;

	// lower 3 bits tells us, if we are IMSI (0x1)
	// 4th bit tells us, if we have odd numeber of digits
	//  (0x8 for even)
	// upper 4 bits are first BCD digit...
	if ((imsi[0]&0x07) != 0x01) {
		snprintf(imsi_string, sizeof(imsi_string)-1, "NOT-IMSI!");
		return imsi_string;
	}
	digits = imsi_len*2 - ((imsi[0]&0x8) ? 1 : 0);

	memset(imsi_string, 0, sizeof(imsi_string));
	for (i=0; i!=digits; i++) {
		imsi_byte = imsi[(i+1)/2];
		imsi_string[i] = bcd_char[(imsi_byte>>(i%2?0:4))&0xf];
	}

	return imsi_string;
}

int
ofl_exp_gprs_sdn_act_pack(struct ofl_action_header *src UNUSED, struct ofp_action_header *dst UNUSED) {
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
		case GPRS_SDN_PUSH_GPRSNS:
			if (*len < sizeof(struct gprs_sdn_action_push_gprsns)) {
				err_small = false;
			} else {
				struct ofl_exp_gprs_sdn_act_push_gprsns *ofl;
				struct gprs_sdn_action_push_gprsns *exp2 = (struct gprs_sdn_action_push_gprsns*) exp;
				ofl = (struct ofl_exp_gprs_sdn_act_push_gprsns*) malloc(sizeof(*ofl));

				ofl->tlli = ntohl(exp2->tlli);
				ofl->bvci = ntohs(exp2->bvci);
				ofl->nsapi = exp2->nsapi;
				ofl->sapi = exp2->sapi;
				ofl->drx_param = ntohs(exp2->drx_param);
				ofl->imsi_len = exp2->imsi_len;
				memcpy(ofl->imsi, exp2->imsi, sizeof(ofl->imsi));

				*dst = (struct ofl_action_header*) ofl;
			}
			break;

		case GPRS_SDN_PUSH_UDPIP:
			if (*len < sizeof(struct gprs_sdn_action_push_udpip)) {
				err_small = false;
			} else {
				struct ofl_exp_gprs_sdn_act_push_udpip *ofl;
				struct gprs_sdn_action_push_udpip *exp2 = (struct gprs_sdn_action_push_udpip*) exp;
				ofl = (struct ofl_exp_gprs_sdn_act_push_udpip*) malloc(sizeof(*ofl));

				ofl->dstport = ntohs(exp2->dstport);
				ofl->srcport = ntohs(exp2->srcport);
				ofl->dstip = exp2->dstip;
				ofl->srcip = exp2->srcip;

				*dst = (struct ofl_action_header*) ofl;
			}
			break;

		case GPRS_SDN_POP_UDPIP: 
		case GPRS_SDN_POP_GPRSNS: {
			struct ofl_exp_gprs_sdn_act_header *ofl;
			ofl = (struct ofl_exp_gprs_sdn_act_header*) malloc(sizeof(*ofl));

			*dst = (struct ofl_action_header*) ofl;
			}
			break;

        default:
            OFL_LOG_WARN(LOG_MODULE, "Trying to unpack unknown GPRS SDN action (subtype=%u).", ntohs(exp->subtype));
            *len -= ntohs(src->len);
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
		}

		// don't forget to fill in common GPRS action header, if we were successfull
		if (*dst && !err_small) {
            struct ofl_exp_gprs_sdn_act_header *ofl = (struct ofl_exp_gprs_sdn_act_header*) *dst;

			ofl->subtype = ntohs(exp->subtype);
			ofl->header.header.type = OFPAT_EXPERIMENTER;
			ofl->header.header.len = ntohs(exp->len);
			ofl->header.experimenter_id = GPRS_SDN_VENDOR_ID;
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
	case GPRS_SDN_PUSH_GPRSNS:
		return sizeof(struct gprs_sdn_action_push_gprsns);
	case GPRS_SDN_PUSH_UDPIP:
		return sizeof(struct gprs_sdn_action_push_udpip);
	case GPRS_SDN_POP_UDPIP:
	case GPRS_SDN_POP_GPRSNS:
		return sizeof(struct gprs_sdn_action_header);
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
	case GPRS_SDN_POP_UDPIP:
		fprintf(stream, "{gprs_sdn_pop_udpip}");
        break;
	case GPRS_SDN_POP_GPRSNS:
		fprintf(stream, "{gprs_sdn_pop_gprsns}");
        break;
	case GPRS_SDN_PUSH_GPRSNS: {
        struct ofl_exp_gprs_sdn_act_push_gprsns *exp2 = (struct ofl_exp_gprs_sdn_act_push_gprsns*) exp;
		fprintf(stream, "{gprs_sdn_push_gprsns,tlli=0x%x,bvci=%d,sapi=%d,nsapi=%d,imsi_len=%d,imsi=%s,drx_param=0x%04x}",
                exp2->tlli, exp2->bvci, exp2->sapi, exp2->nsapi,exp2->imsi_len,
								imsi_to_string(exp2->imsi, exp2->imsi_len), exp2->drx_param);
        }
        break;
	case GPRS_SDN_PUSH_UDPIP: {
        struct ofl_exp_gprs_sdn_act_push_udpip *exp2 = (struct ofl_exp_gprs_sdn_act_push_udpip*) exp;
        fprintf(stream, "{gprs_sdn_push_udpip,dp=%d,sp=%d,da=\""IP_FMT"\",sa=\""IP_FMT"\"}", 
                exp2->dstport, exp2->srcport, IP_ARGS(&(exp2->dstip)), IP_ARGS(&(exp2->srcip)));
        }
        break;
	default:
		fprintf(stream, "{gprs_sdn,unknown subtype=\"%u\"}", exp->subtype);
	}

	fclose(stream);
	return str;
}

