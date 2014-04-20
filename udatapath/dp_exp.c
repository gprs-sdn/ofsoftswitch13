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
 * Author: Jan Skalny <jan@skalny.sk>
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
#include "flow_entry.h"
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

void dp_exp_action_push_gprsns(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act);
void dp_exp_action_pop_gprsns(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act);
void dp_exp_action_push_udpip(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act);
void dp_exp_action_pop_udpip(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act);

void
dp_exp_action_push_gprsns(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act) {
    struct eth_header  *eth;
    struct snap_header *snap;
    struct gprsns_header *gprsns;
    struct ofl_exp_gprs_sdn_act_push_gprsns *exp = (struct ofl_exp_gprs_sdn_act_push_gprsns *) act;
    size_t llc_size, payload_size, eth_size, gprsns_size, bssgp_size, o;
    uint32_t crc24;
    uint8_t *llc, *sndcp, *bssgp, *llc_crc;
    uint8_t llc_is_two_bytes_long = 0;
		uint8_t bssgp_alignment_size, bssgp_alignment = 0;
		uint16_t n_pdu=0, n_u=0;

    packet_handle_std_validate(pkt->handle_std);

    // we need to have an existing ethernet header...
    if (!pkt->handle_std->proto->eth) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute PUSH_GPRSNS action on packet with no eth.");
        return;
    }

    eth = pkt->handle_std->proto->eth;
    snap = pkt->handle_std->proto->eth_snap;

    eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;

    payload_size = pkt->buffer->size - eth_size;
    llc_size = LLC_HEADER_LEN + SNDCP_HEADER_LEN + payload_size + LLC_TRAILER_LEN;
		bssgp_size = 
			1 +				// Type
			4 +				// TLLI
			3 +				// QoS profile
			2 + 2 +		// PDU lifetime
			//2 + 16 +	// RAC
			2 + 2 +		// DRX
			2 + exp->imsi_len; // IMSI
		// next IEI should be aligned to multiple of 32 bits... 
		// how many alignment bytes we need to add?
		if (bssgp_size % 4 != 0) {
			bssgp_alignment = 1;
			/**
			 * dddd|----|----		no alignment needed
			 * dddd|dTTx|----		alignment TLV + 1 byte of stuffing
			 * dddd|ddTT|----		alignment TLV without stuffing
			 * dddd|dddT|Txxx		alignment TLV + 3 bytes of stuffing
			 */
			bssgp_alignment_size = (4-((bssgp_size+2)%4))%4;
			bssgp_size += 2 + bssgp_alignment_size; // TLV + stuffing
		}
		// and finally, LLC IEI is 2 bytes
		bssgp_size += BSSGP_LLC_IEI_LEN;

    gprsns_size = GPRSNS_HEADER_LEN + bssgp_size + llc_size - payload_size;

    // if (LLC_PDU_length > 127) increment gprsns_size by one 
    // because length in LLC_PDU will be 2B
    if (payload_size > 127) {
        gprsns_size++;
        llc_is_two_bytes_long = 1;
    }

    if (ofpbuf_headroom(pkt->buffer) >= gprsns_size) {
        // if headroom has enough space
        // put everything in front of existing packet
        pkt->buffer->data = (uint8_t *) pkt->buffer->data - gprsns_size; 
        pkt->buffer->size += gprsns_size; 
        gprsns = (struct gprsns_header *) ((uint8_t*)pkt->buffer->data + eth_size); 
        // move ethertnet header, to make enough space for GPRS-NS headers
        memmove(pkt->buffer->data, eth, eth_size);
        // move payload to make enough space for LLC trailer 
        memmove((uint8_t *)gprsns + gprsns_size - 3, (uint8_t*)eth + eth_size, payload_size);
    } else {
        // otherwise, headroom is full. we use tailroom of the packet
        // push data to create space for GPRSNS header
        ofpbuf_put_uninit(pkt->buffer, gprsns_size);        
        gprsns = (struct gprsns_header *) ((uint8_t*)pkt->buffer->data + eth_size); 
        // move payload to make space for new GPRS-NS headers
        memmove((uint8_t *)gprsns + gprsns_size - 3, (uint8_t*)eth + eth_size, payload_size);
    }

    // GPRS-NS header
    gprsns->type = GPRSNS_TYPE_UNITDATA;
    gprsns->control = 0x00; 
    gprsns->bvci = htons(exp->bvci);
     
    // BSSGP header
    bssgp = ((uint8_t*)gprsns) + GPRSNS_HEADER_LEN;          
    // DL-UNITDATA
		o = 0;

		// 1B Type -- fixed
    bssgp[o++] = BSSGP_DL_UNITDATA;								

		// 4B TLLI -- fixed
    *((uint32_t*)(bssgp+o)) = htonl(exp->tlli);		
		o+=4;

		// 3B QoS -- fixed
		//XXX: something real
    bssgp[o++] = 0x00;															
		bssgp[o++] = 0x00;
		bssgp[o++] = 0x20;

		// 4B PDU Lifetime -- TLV
    bssgp[o++] = 0x16; 
		bssgp[o++] = 0x82; // ext+length
		*((uint16_t*)(bssgp+o)) = htons(1000);				// delay in centi-seconds :)
		o+=2;

		// 4B DRX param -- TLV
		bssgp[o++] = 0x0a; 
		bssgp[o++] = 0x82; 
		*((uint16_t*)(bssgp+o+2)) = htons(exp->drx_param);
		o+=2;

		// 2+5~8B IMSI param -- TLV
		bssgp[o++] = 0x0d;
		bssgp[o++] = 0x80 | exp->imsi_len;
		memcpy(bssgp+o, exp->imsi, exp->imsi_len);
		o+=exp->imsi_len;

		// 2+0~3B Alignment -- Optiononal TLV
		// TS48.018 -- aligment octets -- 11.3.1
		if (bssgp_alignment) {
			bssgp[o++] = 0x0;
			bssgp[o++] = 0x80 | bssgp_alignment_size;
			if (bssgp_alignment_size)
				memset(bssgp+o, 0, bssgp_alignment_size);
			o+=bssgp_alignment_size;
		}

		// 2+B LLC IEI -- TLV
    bssgp[o++] = BSSGP_LLC_PDU; // Type
    if (llc_is_two_bytes_long) {
        *((uint16_t*)(bssgp+o)) = htons(llc_size);
				o+=2;
    } else {
        // if gprsns_size LLC_PDU length is less than or equal to 127 we set the 
        // first bit of len to 1 
        bssgp[o] = 0x80 | (uint8_t)llc_size;
				o+=1;
    }
		llc = bssgp+o;

		// SNDCP N-PDU sequence number
			if (!pkt->flow_entry) {
			VLOG_WARN_RL(LOG_MODULE, &rl, "Flow entry not found...");
		} else {
			// SNDCP N-PDU sequential number
			n_pdu = (uint16_t)(pkt->flow_entry->stats->packet_count % 4096) ;
		}   
		// LLC N(U) unconfirmed sequence number
		//XXX: since we don't support segmentation on SNDCP layer, this number is
		// same as SNDCP N-PDU sequence number
		n_u = n_pdu%512;

    // LLC header
    llc[0] = exp->sapi; 
    llc[1] = 0xc0 | ((n_u>>6)&0x07);		// UI mode + N(U)
    llc[2] = 0x01 | (((n_u)&0x3f)<<2);	// N(U) + PM bit (FCS)

    // SNDCP header
    sndcp = llc + 3; 
    sndcp[0] = 0x60 | exp->nsapi;		// first segment, SN-UNITDATA, nsapi
    sndcp[1] = 0x00;								// no compression
		sndcp[2] = (n_pdu >> 8) & 0x0f;	// segment=0, n-pdu (bit 11-8)
		sndcp[3] = n_pdu & 0xff;				// n-pdu (bit 7-0)
    
    crc24 = crc_compute24(llc, llc_size-LLC_TRAILER_LEN, 0);

    // LLC trailer
    llc_crc = llc + llc_size - LLC_TRAILER_LEN;
    llc_crc[2] = (crc24 >> 16) & 0xff;
    llc_crc[1] = (crc24 >> 8) & 0xff;
    llc_crc[0] = (crc24) & 0xff;
    
    pkt->handle_std->valid = false;
}


void
dp_exp_action_pop_gprsns(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act UNUSED){
    packet_handle_std_validate(pkt->handle_std);

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
    } else {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_GPRSNS action on packet with no gprsns.");
    }
}

void
dp_exp_action_push_udpip(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act){ 
    struct eth_header  *eth;
    struct snap_header *snap;
    struct udp_header *push_udp;
    struct ip_header *push_ip;
    struct ofl_exp_gprs_sdn_act_push_udpip *exp = (struct ofl_exp_gprs_sdn_act_push_udpip *) act;
    size_t eth_size, new_header_size, payload_size;
    
    packet_handle_std_validate(pkt->handle_std);

    // we need to have an existing ethernet header...
    if (!pkt->handle_std->proto->eth) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute PUSH_IP action on packet with no eth.");
        return;
    }

    eth = pkt->handle_std->proto->eth;
    snap = pkt->handle_std->proto->eth_snap;

    eth_size = snap == NULL
                   ? ETH_HEADER_LEN
                   : ETH_HEADER_LEN + LLC_HEADER_LEN + SNAP_HEADER_LEN;
    //TODO: pozriet ci je velkost spravna.. asi treba radsej pkt->handle_std->nieco
    payload_size = pkt->buffer->size - eth_size;

    new_header_size = IP_HEADER_LEN + UDP_HEADER_LEN;

    if (ofpbuf_headroom(pkt->buffer) >= new_header_size) {
        // if there's enough space in headroom
        // move ethernet header, to make enough space for IP and UDP headers
        pkt->buffer->data = (uint8_t *) pkt->buffer->data - new_header_size;
        pkt->buffer->size += new_header_size;
        memmove(pkt->buffer->data, eth, eth_size);
        push_ip = (struct ip_header *) ((uint8_t*)pkt->buffer->data + eth_size);  
        push_udp = (struct udp_header *) ((uint8_t*)push_ip + IP_HEADER_LEN);
    } else {
        // headroom full, use the tailroom of the packet
        // move entire payload to make space for new IP and UDP headers
        ofpbuf_put_uninit(pkt->buffer, new_header_size);
        push_ip = (struct ip_header *) ((uint8_t*)pkt->buffer->data + eth_size);  
        push_udp = (struct udp_header *) ((uint8_t*)push_ip + IP_HEADER_LEN);
        memmove((uint8_t *)push_ip + new_header_size, push_ip, pkt->buffer->size - eth_size);
    }
 
    //TODO: new_eth and new_snap headers
    // set ethernet type 0x0800

    // fill IP header with correct values
    memset(push_ip, 0, IP_HEADER_LEN);
    push_ip->ip_ihl_ver = IP_IHL_VER(5, IP_VERSION);
    push_ip->ip_tos = 0; //XXX: QoS in here, if something sits between us and bss
    push_ip->ip_tot_len = htons(payload_size + UDP_HEADER_LEN + IP_HEADER_LEN);
    push_ip->ip_id = 0; //TODO: FIXME!
    push_ip->ip_frag_off= 0;
    push_ip->ip_ttl = 255;
    push_ip->ip_proto = IP_TYPE_UDP; 
    push_ip->ip_csum = 0; //recalculated after inserting all header values
    push_ip->ip_src = exp->srcip; 
    push_ip->ip_dst = exp->dstip; 
    push_ip->ip_csum = csum(push_ip, IP_HEADER_LEN);
    
    // fill UDP header with correct values
    memset(push_udp, 0, UDP_HEADER_LEN);
    push_udp->udp_src = htons(exp->srcport);
    push_udp->udp_dst = htons(exp->dstport);
    push_udp->udp_len = htons(payload_size + UDP_HEADER_LEN);
    push_udp->udp_csum = 0; //optional, so we set it to zero

    pkt->handle_std->valid = false;
}

void
dp_exp_action_pop_udpip(struct packet *pkt, struct ofl_exp_gprs_sdn_act_header *act UNUSED){
    struct eth_header *eth; 
    struct ip_header *ip; 
    struct udp_header *udp; 
    size_t move_size;

    packet_handle_std_validate(pkt->handle_std);
 
    eth = pkt->handle_std->proto->eth;
    ip = pkt->handle_std->proto->ipv4;
    udp = pkt->handle_std->proto->udp;

    if (!eth || !ip || !udp) {
        VLOG_WARN_RL(LOG_MODULE, &rl, "Trying to execute POP_UDPIP action on packet with no ip and udp.");
        return;
    }
      
    pkt->buffer->data = (uint8_t *)pkt->buffer->data + (4 * IP_IHL(ip->ip_ihl_ver)) + UDP_HEADER_LEN;
    pkt->buffer->size -= (4 * IP_IHL(ip->ip_ihl_ver)) - UDP_HEADER_LEN;
   
    move_size = (uint8_t *) ip - (uint8_t *) eth;
    memmove(pkt->buffer->data, eth, move_size);
    pkt->handle_std->valid = false;
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
        case GPRS_SDN_PUSH_UDPIP:
            return dp_exp_action_push_udpip(pkt, exp);
        case GPRS_SDN_POP_UDPIP:
            return dp_exp_action_pop_udpip(pkt, exp);
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


