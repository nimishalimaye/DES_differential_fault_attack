//
//  main.c
//  DES_faut_attack
//
//  Created by Ashik Hoovayya Poojari on 3/11/17.
//  Copyright © 2017 Ashik Hoovayya Poojari. All rights reserved.
//

#include <stdio.h>
#include "des.h"

/*
 Output should be:
 c95744256a5ed31d
 0123456789abcde7
 85e813540f0ab405
 0123456789abcdef
 c95744256a5ed31d
 7f1d0a77826b8aff
 */

void printtext(unsigned char hash[])
{
    int i;
    for (i=0; i < 8; i++)
        printf("%02x ",hash[i]);
    printf("\n");
}

int main()
{
    
    uchar text1[8]={0x95,0xF8,0xA5,0xE5,0xDD,0x31,0xD9,0x00};
    uchar key1[8]={0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};

    uchar out[8],out_fault16[8];
    uchar schedule[16][6];
    uint state[2];
	uchar delta_r16[8], p_inv_r16[8], bruteforce_key[8], rhs_xor[8];
	//ENCRYPTION//
    key_schedule(key1,schedule,ENCRYPT);
    des_crypt(text1,out,schedule);
    printtext(out);

    //FAULT ATTACK//
    des_fault16_crypt(text1,out_fault16,schedule);
    printtext(out_fault16);
	xor_r16(out, out_fault16, delta_r16); //xors the correct and faulty ciphertexts
	p_inv(delta_r16, p_inv_r16); //finds inv permutation of delta_r16
	key_brute(bruteforce_key);
	rhs(out, out_fault16, bruteforce_key, rhs_xor);

	//DECRYPTION//
    key_schedule(key1,schedule,DECRYPT);
    des_crypt(out,text1,schedule);
    printtext(text1);
    
    
    getchar();
    return 0;
}
