//
//  main.c
//  DES_faut_attack
//
//  Created by Ashik Hoovayya Poojari on 3/11/17.
//  Copyright © 2017 Ashik Hoovayya Poojari. All rights reserved.
//

#include <stdio.h>
#include <stdlib.h>  /* srand, rand */
#include <time.h>
#include <math.h>
#include "des.h"



void printtext(unsigned char hash[])
{
    int i;
    for (i=0; i < 8; i++)
        printf("%02x ",hash[i]);
    printf("\n");
}

void printkey(unsigned char hash[])
{
    int i;
    for (i=0; i < 6; i++)
        printf("%02x",hash[i]);
    printf("\n");
}

int main()
{
//    
    uchar text1[8]={0x95,0xF8,0xA5,0xE5,0xDD,0x31,0xD9,0x00};
    srand (time(NULL));
//    uchar text1[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
//    uchar text1[8]={ 0x55,0x00,0x40,0x01,0x10,0x00,0x04,0x01 };
//    uchar text1[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uchar key1[8]={0x11,0x77,0x99,0x23,0x67,0x90,0x12,0x78};
//    uchar key1[8]={0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
//    uchar key1[8]={0x80,0x03,0x02,0x01,0x01,0x01,0x01,0x01};
    uchar  out[8];
    uint fault_mask;
    uchar key_hack[8][16],keyhack[6];
    uint count[8][16];
    uchar pointer[8]={0,0,0,0,0,0,0,0};
    uchar schedule[16][6];
    
    for(int l=0;l<8;l++)
    {
        for(int m=0;m<16;m++)
        {
            key_hack[l][m]=0xcc;
            count[l][m]=01;
        }
    }

    key_schedule(key1,schedule,ENCRYPT);
    
    printkey(schedule[15]);

    for(int k=0;k<pow(2,4);k++)
    {
        for(int u=0;u<8;u++)
        {
            text1[u]=(rand()%256);
        }
        fault_mask=(rand()%8<<28)|(rand()%8<<24)|(rand()%8<<20)|(rand()%8<<16)|(rand()%8<<12)|(rand()%8<<8)|(rand()%8<<4)|(rand()%8);
        printf("%x\n",fault_mask);
        delta_r(text1,schedule,key_hack,count,pointer,fault_mask);
//        delta_r(text1,schedule,key_hack,count,pointer,0x22222222);

    }
    
    display_keys(key_hack);
    printf("\n");
    display_count(count);
    getkey(key_hack,count,keyhack);
    printkey(keyhack);
    
    getchar();
    return 0;
}


uchar delta_r(uchar text[],uchar schedule[][6],uchar key_hack[][16],uint count[][16],uchar pointer[],uint faultmask)
{
    uchar out[8],out_fault16[8],key_stat=0;
    uchar delta_i[8],delta_out[8];
    
    des_crypt(text,out,schedule);

    des_fault16_crypt(text,out_fault16,schedule,faultmask);

    keybrute(out,out_fault16,key_hack,count,pointer);
    
    return key_stat;
    
}

void keybrute(uchar in_c[], uchar in_e[], uchar key_hack[][16], uint count[][16],uchar pointer[])
{
    // testing zone
    int i,all_keys=1;
    uchar count_i;
    uchar *p_count = &count_i;
    uint state_c[2],state_e[2], delta,mask;
    IP(state_c,in_c);
    IP(state_e,in_e);

    uchar key8[8]={0x10,0x2e,0x2a,0x0c,0x01,0x36,0x04,0x09},key[6];
    

    uchar key_i=0;
    while (all_keys)
    {
        for(i=0; i<8; i++)
        {
            key8[i]= key_i;
        }


        map8to6(key8,key);

        // fualt equation
        delta = p_inv_sbox(state_c[0]^state_e[0]) ^ ((rhs_s_e_k(state_c[1],key))^(rhs_s_e_k(state_e[1], key)));
        
        mask =0xf0000000;
        for(i=0;i<8;i++)
        {

            if((delta & mask)==0)
            {
                if(duplicate(key_hack[i],key8[i],p_count))
                {
                    count[i][count_i]++;
                }
                else
                {
                    key_hack[i][pointer[i]]=key8[i];
                    if(pointer[i]<15)
                    {
                        pointer[i]++;
                    }

                }
            }
            mask = mask >> 4;
        }
        key_i +=1;
        if(key_i > 0x3f)
        {
            all_keys=0;
        }

    }

    
}

// P inv table for delta_r16 function//
uint p_inv_sbox(uint statex)
{
    uint state_outx;
    state_outx =    BITNUMINTL(statex, 8, 0)    | BITNUMINTL(statex, 16, 1)     | BITNUMINTL(statex, 22, 2)     |
                    BITNUMINTL(statex, 30, 3)   | BITNUMINTL(statex, 12, 4)     | BITNUMINTL(statex, 27, 5)     |
                    BITNUMINTL(statex, 1, 6)    | BITNUMINTL(statex, 17, 7)     | BITNUMINTL(statex, 23, 8)     |
                    BITNUMINTL(statex, 15, 9)   | BITNUMINTL(statex, 29, 10)    | BITNUMINTL(statex, 5, 11)     |
                    BITNUMINTL(statex, 25, 12)  | BITNUMINTL(statex, 19, 13)    | BITNUMINTL(statex, 9, 14)     |
                    BITNUMINTL(statex, 0, 15)   | BITNUMINTL(statex, 7, 16)     | BITNUMINTL(statex, 13, 17)    |
                    BITNUMINTL(statex, 24, 18)  | BITNUMINTL(statex, 2, 19)     | BITNUMINTL(statex, 3, 20)     |
                    BITNUMINTL(statex, 28, 21)  | BITNUMINTL(statex, 10, 22)    | BITNUMINTL(statex, 18, 23)    |
                    BITNUMINTL(statex, 31, 24)  | BITNUMINTL(statex, 11, 25)    | BITNUMINTL(statex, 21, 26)    |
                    BITNUMINTL(statex, 6, 27)   | BITNUMINTL(statex, 4, 28)     | BITNUMINTL(statex, 26, 29)    |
                    BITNUMINTL(statex, 14, 30)  | BITNUMINTL(statex, 20, 31);
    return state_outx;
}



void display_keys(uchar key[][16])
{
    for(int i=0;i<8;i++)
    {
        for(int j=0;j<16;j++)
        {
            printf("%02x\t",key[i][j]);
        }
        printf("\n");
    }
    
}

void display_count(uint key[][16])
{
    for(int i=0;i<8;i++)
    {
        for(int j=0;j<16;j++)
        {
            printf("%d\t",key[i][j]);
        }
        printf("\n");
    }
    
}

uint duplicate(uchar key[],uchar dup_val, uchar *p)
{

    for(int i=0;i<16;i++)
    {
        if(key[i] == dup_val)
        {
            *p = i;
            return 1;
        }
    }
    return 0;
}

void map8to6(uchar key8[],uchar key[])
{
    key[0]=(key8[0] << 2) | (key8[1] >>4);
    key[1]=(key8[1] << 4) | (key8[2] >>2);
    key[2]=(key8[2] << 6) | (key8[3]);
    key[3]=(key8[4] << 2) | (key8[5] >>4);
    key[4]=(key8[5] << 4) | (key8[6] >>2);
    key[5]=(key8[6] << 6) | (key8[7]);

}
void disp6to8(uchar key[])
{
    uchar key8[8];
    
    key8[0]=(key[0]>>2)& 0x3f;
    key8[1]=(key[0]<<4 | key[1] >>4) & 0x3f ;
    key8[2]=(key[1]<<2 | key[2] >>6) & 0x3f;
    key8[3]=key[2] & 0x3f;
    key8[4]=(key[3]>>2)& 0x3f;
    key8[5]=(key[3]<<4 | key[4] >>4) & 0x3f ;
    key8[6]=(key[4]<<2 | key[5] >>6) & 0x3f;
    key8[7]=key[5] & 0x3f;
    
    printf("Key_8:");
    for(int i=0;i<8;i++)
    {
        printf("%02x",key8[i]);
    }
    printf("\n");
}

void getkey(uchar key16[][16],uint count16[][16],uchar key[])
{
    int max;
    uchar key8[8];
    
    for(int i=0;i<8;i++)
    {
        max=0;
        for(int j=0;j<16;j++)
        {
            if(max < count16[i][j])
            {
                max=count16[i][j];
                key8[i]=key16[i][j];
            }
        }
    }
    printtext(key8);
    map8to6(key8,key);
}
