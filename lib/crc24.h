/**
 -----------------------------------------------------------------------------
 "THE BEER-WARE LICENSE":

 <johnny@netvor.sk> wrote this file. As long as you retain this notice you
 can do whatever you want with this stuff. If we meet some day, and you think
 this stuff is worth it, you can buy me a beer (*or Kofola) in return.   

      johnny ^_^ <johnny@netvor.sk>
 -----------------------------------------------------------------------------
 */

#ifndef _CRC24_H
#define _CRC24_H

#define INVERT24(x)(x ^ 0xFFFFFF)

void crc_init_table24();
uint32_t crc_compute24(uint8_t*data, uint32_t len, uint32_t init);

#endif /*_CRC24_H*/
