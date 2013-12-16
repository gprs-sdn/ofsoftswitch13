/* Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of the Ericsson Research nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 *
 * Author: Zoltán Lajos Kis <zoltan.lajos.kis@ericsson.com>
 */

#include <stdlib.h>
#include <string.h>
#include "datapath.h"
#include "dp_exp.h"
#include "packet.h"
#include "oflib/ofl.h"
#include "oflib/ofl-actions.h"
#include "oflib/ofl-structs.h"
#include "oflib/ofl-messages.h"
#include "oflib-exp/ofl-exp-gprs-sdn.h"
#include "oflib-exp/ofl-exp-openflow.h"
#include "oflib-exp/ofl-exp-nicira.h"
#include "openflow/openflow.h"
#include "openflow/gprs-sdn-ext.h"
#include "openflow/openflow-ext.h"
#include "openflow/nicira-ext.h"
#include "vlog.h"

#define LOG_MODULE VLM_dp_exp

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);


//XXX: toto ide niekam inam
void
dp_exp_action_hello_world() {
	printf("ahoj svet\n");
	fflush(stdout);
}

//TODO
void
dp_exp_action_push_gprsns(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){
    
}

void
dp_exp_action_pop_gprsns(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){
    //validate handle
    packet_handle_std_validate(pkt->handle_std);
    //verify packets
    if(pkt->handle_std->proto->gprsns != NULL) {
        struct protocols_std *proto = pkt->handle_std->proto;
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct gprsns_header *gprsns = pkt->handle_std->proto->gprsns;
        size_t move_size;

        move_size = GPRSNS_HEADER_LEN + 
            proto->bssgp_header_len + 
            proto->llc_header_len +
            proto->sndcp_header_len;
   
        pkt->buffer->data = (uint8_t *) pkt->buffer->data + move_size;
        pkt->buffer->size -= move_size;

        //memmove
        //ak je velkost LLC > 0 treba odstranit 3B FCS za pouz. datami
        //skratit dlzku o 3
        if (proto->llc_header_len > 0) pkt->buffer->size -= 3;
        
        //memmove
        move_size = (uint8_t *) gprsns - (uint8_t *) eth; 
        memmove(pkt->buffer->data, eth, move_size);

        //set handle to false
        pkt->handle_std->valid = false;
    }
    //else 
    else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_GPRSNS action on packet with no gprsns.");
    }
}

void
dp_exp_action_push_ip(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){ 
    //
}

void
dp_exp_action_pop_ip(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){
    packet_handle_std_validate(pkt->handle_std);
    if(pkt->handle_std->proto->eth != NULL && pkt->handle_std->proto->ipv4 != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct ip_header *ip = pkt->handle_std->proto->ipv4;
        size_t move_size;
       
        pkt->buffer->data = (uint8_t *)pkt->buffer->data + (4 * IP_IHL(ip->ip_ihl_ver));
        pkt->buffer->size -= (4 * IP_IHL(ip->ip_ihl_ver));
       
        
        move_size = (uint8_t *) ip - (uint8_t *) eth;
        memmove(pkt->buffer->data, eth, move_size);
        pkt->handle_std->valid = false;
    }

    else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_IP action on packet with no ip.");
    }
}

void
dp_exp_action_push_udp(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){

}

void
dp_exp_action_pop_udp(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){
    packet_handle_std_validate(pkt->handle_std);
    if(pkt->handle_std->proto->eth != NULL && pkt->handle_std->proto->ipv4 != NULL && pkt->handle_std->proto->udp != NULL) {
        struct eth_header *eth = pkt->handle_std->proto->eth;
        struct udp_header *udp = pkt->handle_std->proto->udp;
        size_t move_size;
        
        pkt->buffer->data = (uint8_t *)pkt->buffer->data + UDP_HEADER_LEN;
        pkt->buffer->size -= UDP_HEADER_LEN;
        
        move_size = (uint8_t *) udp - (uint8_t *) eth;
        memmove(pkt->buffer->data, eth, move_size);
        pkt->handle_std->valid = false;     
    }

    else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_UDP action on packet with no udp.");
    }
}

void
dp_exp_action(struct packet * pkt, struct ofl_action_experimenter *act) {
	uint16_t subtype;
	uint8_t *data;
	
	printf("experimenter action - vendor=%d, len=%d\n", act->experimenter_id, act->header.len);
	switch(act->experimenter_id) {
	case GPRS_SDN_VENDOR_ID: {
		struct ofl_exp_gprs_sdn_act_header *exp = (struct ofl_exp_gprs_sdn_act_header*) act;
		switch (exp->subtype) {
		//TODO: dalsie subtypy
		case GPRS_SDN_PUSH_GPRSNS:
            return dp_exp_action_push_gprsns(pkt, exp);
        case GPRS_SDN_POP_GPRSNS:
            return dp_exp_action_pop_gprsns(pkt, exp);
        case GPRS_SDN_PUSH_IP:
            return dp_exp_action_push_ip(pkt, exp);
        case GPRS_SDN_POP_IP:
            return dp_exp_action_pop_ip(pkt, exp);
        case GPRS_SDN_PUSH_UDP:
            return dp_exp_action_push_udp(pkt, exp);
        case GPRS_SDN_POP_UDP:
            return dp_exp_action_pop_udp(pkt, exp);
        case GPRS_SDN_HELLO:
            return dp_exp_action_hello_world();
		default:
			VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown GPRS SDN action (%u).", act->experimenter_id);
		}
		return;
		}
	}

	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown experimenter action (%u).", act->experimenter_id);
}

void
dp_exp_inst(struct packet *pkt UNUSED, struct ofl_instruction_experimenter *inst) {
	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute unknown experimenter instruction (%u).", inst->experimenter_id);
}

ofl_err
dp_exp_stats(struct datapath *dp UNUSED,
                                  struct ofl_msg_multipart_request_experimenter *msg,
                                  const struct sender *sender UNUSED) {
	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter stats (%u).", msg->experimenter_id);
    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
}


ofl_err
dp_exp_message(struct datapath *dp,
                                struct ofl_msg_experimenter *msg,
                               const struct sender *sender) {

    switch (msg->experimenter_id) {
		case (OPENFLOW_VENDOR_ID): {
            struct ofl_exp_openflow_msg_header *exp = (struct ofl_exp_openflow_msg_header *)msg;

            switch(exp->type) {
                case (OFP_EXT_QUEUE_MODIFY): {
                    return dp_ports_handle_queue_modify(dp, (struct ofl_exp_openflow_msg_queue *)msg, sender);
                }
                case (OFP_EXT_QUEUE_DELETE): {
                    return dp_ports_handle_queue_delete(dp, (struct ofl_exp_openflow_msg_queue *)msg, sender);
                }
                case (OFP_EXT_SET_DESC): {
                    return dp_handle_set_desc(dp, (struct ofl_exp_openflow_msg_set_dp_desc *)msg, sender);
                }
                default: {
                	VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to handle unknown experimenter type (%u).", exp->type);
                    return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
                }
            }
        }
        default: {
            return ofl_error(OFPET_BAD_REQUEST, OFPBRC_BAD_EXPERIMENTER);
        }
    }
}


