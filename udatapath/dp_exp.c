/*
 Copyright (c) 2011, TrafficLab, Ericsson Research, Hungary
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
 * Author: Tibor Hirjak <hirjak.tibor@gmail.com>
 */

#include <stdlib.h>
#include <string.h>
#include "datapath.h"
#include "packet.h"
#include "packets.h"
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
#include "lib/csum.h"
#include "lib/crc24.h"
#include "vlog.h"
#define LOG_MODULE VLM_dp_exp

#include "dp_exp.h"

static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(60, 60);


//TODO
void
dp_exp_action_push_gprsns(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){
    struct gprsns_header *push_gprsns;
    struct ofl_exp_gprs_sdn_act_push_gprsns *exp = (struct ofl_exp_gprs_sdn_act_push_gprsns *) act;
    int llc_payload_len, o;
    uint32_t crc24;
    uint8_t *llc, *sndcp, *bssgp, *gprsns, *llc_crc;
    uint8_t sizeof_data_to_insert, is_word = 0;

    //validate handle
    packet_handle_std_validate(pkt->handle_std);
    
    sizeof_data_to_insert = GPRSNS_HEADER_LEN 
        + 12  // BSSGP - LLC_PDU 
        + 2   // LLC_PDU TL 
        + 3   // LLC CRC
        + 1   // SAPI 
        + 2   // UI format
        + 1   // NSAPI 
        + 3;  // SNDCP comp + mode + N-PDU
    
    // if (LLC_PDU_length > 127) increment sizeof_data_to_insert by one 
    // because length in LLC_PDU will be 2B
    if (pkt->buffer->size > 127) {
        sizeof_data_to_insert++;
        is_word = 1;
    }

    if (ofpbuf_headroom(pkt->buffer) >= sizeof_data_to_insert) {
        // if headroom has enough space
        // +3 -- LLC CRC is at the end of the packet
        pkt->buffer->data = (uint8_t *) pkt->buffer->data - sizeof_data_to_insert + 3; 
        pkt->buffer->size += sizeof_data_to_insert; 
        
        // memmove not necessary                 
        push_gprsns = (struct gprsns_header *) pkt->buffer->data; 
    }
    else {
        // otherwise, headroom is full. we use tailroom of the packet
        //XXX: ofpbuf_put_uninit might relocate the whole packet
        ofpbuf_put_uninit(pkt->buffer, sizeof_data_to_insert);        
        push_gprsns = (struct gprsns_header *) pkt->buffer->data;                
        
        // push data to create space for GPRSNS header
        memmove((uint8_t *)push_gprsns + sizeof_data_to_insert, push_gprsns, pkt->buffer->size);                            
        //FIXME XXX TODO not sure if correct
        //pkt->buffer->size += sizeof_data_to_insert;    
    }
    
    push_gprsns->type = GPRSNS_TYPE_UNITDATA;
    push_gprsns->control = 0x00; //wireshark XX
    push_gprsns->bvci = exp->bvci;
     
    gprsns = (uint8_t*)pkt->buffer->data;
    bssgp = gprsns+4;                       
    
    // DL-UNITDATA
    bssgp[0] = BSSGP_DL_UNITDATA;
    // a mozno nie htnol, lebo ti ich ryu dalo v network orderi a nik ti ich neparsoval na host ordera
    *((uint32_t*) bssgp+1) = htonl(exp->tlli); 
    bssgp[7] = 0x04; //QoS - 3B
    bssgp[8] = 0x16; //PDU Lifetime - 4B
    bssgp[9] = 0x82; //ext+length - wireshark
    bssgp[10] = 0x03; //constant
    bssgp[11] = 0xe8; //constant

    o = 12;
    // LLC TLV
    bssgp[o] = BSSGP_LLC_PDU; //LLC TLV T
    
    //LLC TLV L
    if (is_word) {
        // LLC_PDU length equals to size of packet buffer minus the 
        // BSSGP and GPRSNS headers, because they are not LLC payload 
        // and are located before the LLC header.
        llc_payload_len = pkt->buffer->size - GPRSNS_HEADER_LEN - 15;
        *((uint16_t*)bssgp[o+1]) = htons(llc_payload_len);
        o += 2;
    } else {
        // if sizeof LLC_PDU length is less than or equal to 127 we set the 
        // first bit of len to 1 
        llc_payload_len = pkt->buffer->size - GPRSNS_HEADER_LEN - 14;
        bssgp[o+1] = llc_payload_len;
        bssgp[o+1] |= 0x80;
        o++;
    }

    llc = bssgp + o; 
    llc[0] = exp->sapi; 
    llc[1] = 0xc0;
    llc[2] = 0x01;
    //XXX:
    
    //SAPI + UI format
    sndcp = llc + 3; 
    sndcp[0] = 0x60 | exp->nsapi;
    sndcp[1] = 0x00; //no compression
    sndcp[2] = 0x00; //unacknowledge mode
    sndcp[3] = 0x00; //FIXME TODO N-PDU nubmers should be incremented in each SNDCP header!!!
    
    crc24 = crc_compute24(llc, llc_payload_len,0);
    llc_crc = llc + llc_payload_len;
    
    llc_crc[0] = (crc24 >> 16) & 0xff;
    llc_crc[1] = (crc24 >> 8) & 0xff;
    llc_crc[2] = (crc24) & 0xff;
    
    //TODO: porovnat vystup.. aj s wiresharkom
    printf("crc24=%08x\n", crc24);
    printf("llc_crc= %02x %02x %02x\n", llc_crc[0], llc_crc[1], llc_crc[2]);

    pkt->handle_std->valid = false;
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
        //if the size of LLC > 0 we need to remove the 3B FCS located after the user data
        //shorten the length by 3
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
    struct ip_header *push_ip;
    struct ofl_exp_gprs_sdn_act_push_ip *exp = (struct ofl_exp_gprs_sdn_act_push_ip *) act;
    
    packet_handle_std_validate(pkt->handle_std);

    //if there's enough space in headroom
    if (ofpbuf_headroom(pkt->buffer) >= IP_HEADER_LEN) {
        
        pkt->buffer->data = (uint8_t *) pkt->buffer->data - IP_HEADER_LEN;
        pkt->buffer->size += IP_HEADER_LEN;
        
        //memmove not necessary 
         
        push_ip = (struct ip_header *) pkt->buffer->data; 
     }   
    
    //headroom full, use the tailroom of the packet
    else {
        //Note: ofpbuf_put_uninit might relocate the whole packet
        ofpbuf_put_uninit(pkt->buffer, IP_HEADER_LEN);
        
        push_ip = (struct ip_header *) pkt->buffer->data;

        //push data to create space for IP header
        memmove((uint8_t *)push_ip + IP_HEADER_LEN, push_ip, pkt->buffer->size);

        //FIXME XXX TODO not sure if correct
        //pkt->buffer->size += IP_HEADER_LEN;
    }
   
    //fill IP header with correct values
    push_ip->ip_ihl_ver = IP_IHL_VER(4,5);
    
    push_ip->ip_tos = 0; //XXX: map to GRE tunnel
    push_ip->ip_tot_len = pkt->buffer->size;
    push_ip->ip_id = 0; //TODO: XXX: FIXME!
    push_ip->ip_frag_off= 0;
    push_ip->ip_ttl = 255;
    push_ip->ip_proto = IP_TYPE_UDP; 
    push_ip->ip_csum = 0; //recalculated after inserting all header values
    push_ip->ip_src = exp->srcip; 
    push_ip->ip_dst = exp->dstip; 
    push_ip->ip_csum = csum(push_ip, IP_HEADER_LEN);
    
    pkt->handle_std->valid = false;
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
    struct udp_header *push_udp;
    struct ofl_exp_gprs_sdn_act_push_udp *exp = (struct ofl_exp_gprs_sdn_act_push_udp *) act;

    packet_handle_std_validate(pkt->handle_std);

    if (ofpbuf_headroom(pkt->buffer) >= UDP_HEADER_LEN){
        
        pkt->buffer->data = (uint8_t *) pkt->buffer->data - UDP_HEADER_LEN;
        pkt->buffer->size += UDP_HEADER_LEN;

        push_udp = (struct udp_header *) pkt->buffer->data;
    }

    else {
        
        ofpbuf_put_uninit(pkt->buffer, UDP_HEADER_LEN);
        
        push_udp = (struct udp_header *) pkt->buffer->data; 
    
        memmove((uint8_t *)push_udp + UDP_HEADER_LEN, push_udp, pkt->buffer->size);
        //FIXME XXX TODO
        //pkt->buffer->size += UDP_HEADER_LEN;
    }
    //fill UDP header with correct values
    push_udp->udp_src = exp->srcport;
    push_udp->udp_dst = exp->dstport;
    push_udp->udp_len = pkt->buffer->size;
    push_udp->udp_csum = 0; //optional, so we set it to zero

    pkt->handle_std->valid = false;
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
	switch(act->experimenter_id) {
	case GPRS_SDN_VENDOR_ID: {
		struct ofl_exp_gprs_sdn_act_header *exp = (struct ofl_exp_gprs_sdn_act_header*) act;
		switch (exp->subtype) {
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
		//TODO: more subtypes
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


