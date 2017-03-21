//
//  des.h
//  DES_faut_attack
//
//  Created by Ashik Hoovayya Poojari on 3/11/17.
//  Copyright © 2017 Ashik Hoovayya Poojari. All rights reserved.
//

#include <stdio.h>
#ifndef des_h
#define des_h


#define uchar unsigned char // 8-bit byte
#define uint unsigned long // 32-bit word

#define ENCRYPT 1
#define DECRYPT 0

// Obtain bit "b" from the left and shift it "c" places from the right
#define BITNUM(a,b,c) (((a[(b)/8] >> (7 - (b%8))) & 0x01) << (c))
#define BITNUMINTR(a,b,c) ((((a) >> (31 - (b))) & 0x00000001) << (c))
#define BITNUMINTL(a,b,c) ((((a) << (b)) & 0x80000000) >> (c))
#define BITCON(a,b,c,d)(a<<24 | b<< 16 | c << 8 | d)
// This macro converts a 6 bit block with the S-Box row defined as the first and last
// bits to a 6 bit block with the row defined by the first two bits.
#define SBOXBIT(a) (((a) & 0x20) | (((a) & 0x1f) >> 1) | (((a) & 0x01) << 4))


void key_schedule(uchar key[], uchar schedule[][6], uint mode);
void des_crypt(uchar in[], uchar out[], uchar key[][6]);
void des_fault16_crypt(uchar in[], uchar out[], uchar key[][6],uint faultmask);
uint p_inv_sbox(uint statex);
uint sbox_E(uint state, uchar key[]);
void InvIP(uint state[], uchar in[]);
void IP(uint state[], uchar in[]);
uint rhs_s_e_k(uint state, uchar key[]);
uchar delta_r(uchar text[],uchar schedule[][6],uchar key_hack[][16],uint count[][16],uchar pointer[],uint faultmask);
uint duplicate(uchar key[],uchar dup_val, uchar *p);
void map8to6(uchar key8[],uchar key[]);
void display_keys(uchar key[][16]);
void display_count(uint key[][16]);
uint f(uint state, uchar key[]);
void disp6to8(uchar key[]);
void getkey(uchar key16[][16],uint count16[][16],uchar key[]);
void keybrute(uchar in_c[], uchar in_e[], uchar key_hack[][16], uint count[][16],uchar pointer[]);
#endif /* des_h */

