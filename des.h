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

void key_schedule(uchar key[], uchar schedule[][6], uint mode);
void des_crypt(uchar in[], uchar out[], uchar key[][6]);
void des_fault16_crypt(uchar in[], uchar out[], uchar key[][6]);

#endif /* des_h */

