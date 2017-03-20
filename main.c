//
//  main.c
//  DES_faut_attack
//
//  Created by Ashik Hoovayya Poojari on 3/11/17.
//  Copyright © 2017 Ashik Hoovayya Poojari. All rights reserved.
//

#include <stdio.h>
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
        printf("%02x ",hash[i]);
    printf("\n");
}

int main()
{
//    
//    uchar text1[8]={0x95,0xF8,0xA5,0xE5,0xDD,0x31,0xD9,0x00};
    uchar text1[8]={ 0x55,0x00,0x40,0x01,0x10,0x00,0x04,0x01 };
//    uchar text1[8]={0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    uchar key1[8]={0x11,0x77,0x99,0x23,0x67,0x90,0x12,0x78};
//    uchar key1[8]={0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
//    uchar key1[8]={0x80,0x03,0x02,0x01,0x01,0x01,0x01,0x01};
    uchar  out[8],key_hack[8]={0,0,0,0,0,0,0,0};
    uchar key[6];

    uchar schedule[16][6],keystat;
    
    int key_notfound=1,i,value;

    printf("%x",BITNUMINTL(0x00010000,15,0));
    key_schedule(key1,schedule,ENCRYPT);
//    printf("Key: ");
//    for ( i=0; i < 6; i++)
//        key[i]=schedule[15][i];
//    printf("\n");
    disp6to8(schedule[15]);
    
//    des_crypt(text1,out,schedule);
//    printtext(out);
//
//    des_fault16_crypt(text1,out_fault16,schedule);
//    printtext(out_fault16);
    
//    uint state[2];
//    
//    IP(state,key1);
//    printf("%x,%x\n",state[1],state[0]);
//    InvIP(state,key1);
//    printtext(key1);

    
      delta_r(text1,schedule,key_hack);

    
//        key_schedule(key1,schedule,DECRYPT);
//        des_crypt(out,text1,schedule);
//        printtext(text1);
//    
    
    getchar();
    return 0;
}


uchar delta_r(uchar text[],uchar schedule[][6],uchar key_hack[])
{
    uchar out[8],out_fault16[8],key_stat=0;
    uchar delta_i[8],delta_out[8];
    
    des_crypt(text,out,schedule);
    printf("out_i: ");
    printtext(out);
    des_fault16_crypt(text,out_fault16,schedule);
    printf("out_e: ");
    printtext(out_fault16);
    uchar key_f={0,0,0,0,0,0,0,0};
    key_hack=key_f;
//    for (int i=0; i < 8; i++)
//    {
//        delta_i[i] = out[i] ^ out_fault16[i];
//    }
//    
//    p_inv(delta_i,delta_out);
//    printf("%d,%d\n",NOS_ones(delta_i), NOS_ones(delta_out));
//    printf("delta_r: ");
//    printtext(delta_i);
//    printf("Pinv_o: ");
//    printtext(delta_out);
//    key_stat=key_brute(out,out_fault16,delta_out,key_hack);
    
    keybrute(out,out_fault16);
    
    return key_stat;
    
}

void keybrute(uchar in_c[], uchar in_e[])
{
    // testing zone
    uint state_c[2],state_e[2], delta;
    IP(state_c,in_c);
    IP(state_e,in_e);
    
    uchar key8[8]={0x10,0x2e,0x2a,0x0c,0x01,0x36,0x04,0x09},key[6];
    
    map8to6(key8,key);
    
    //    printf("L :%x, Le :%x\n",(rhs_s_e_k(state_c[1], schedule[15])),(rhs_s_e_k(state_e[1], schedule[15])));
    printf("del_l :%x\n",(rhs_s_e_k(state_c[1],key))^(rhs_s_e_k(state_e[1], key)));
    printf("pinverseof: %x",p_inv_sbox(state_c[0]^state_e[0]));
    delta = p_inv_sbox(state_c[0]^state_e[0]) ^ ((rhs_s_e_k(state_c[1],key))^(rhs_s_e_k(state_e[1], key)));
    printf("delta :%x\n",delta);
    printf("keys--->");
    for(int i=0;i<6;i++)
        printf("%02x",key[i]);
    printf("\n");
    
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



void p_inv(uchar in[], uchar out[])
{
    uint state[2]={0,0}, state_out[2]={0,0};
    
    IP(state, in);
////    printtext(in);
//    printf("state: %x,%x\n",state[1],state[0]);
////    x=state[0];
//    state_out[0]=p_inv_sbox(state[0]);
//    printf("state0_ones: %d\n",NOS_ones(state_out[0]));
//    printf("state_outxy: %x,%X\n",x,y);
    state_out[1]=p_inv_sbox(state[1]);
//    printf("state_out: %x,%x\n",state_out[1],state_out[0]);
    InvIP(state_out, out);
    
}


//RHS of equation 3.2//
void rhs(uchar in_c[], uchar in_e[], uchar key[], uchar rhs_out[])
{
    uint state_c[2]={0,0}, state_e[2]={0,0}, state_rhs[2]={0,0};
    
    IP(state_c, in_c);
    IP(state_e, in_e);
    
//    printf("in_c: ");
//    printtext(in_c);
//    printf("in_e: ");
//    printtext(in_e);
    
//    printf("state_c: %x,%x\n",state_c[1],state_c[0]);
//    printf("state_e: %x,%x\n",state_e[1],state_e[0]);

    state_rhs[1] = rhs_s_e_k(state_c[0], key) ^ rhs_s_e_k(state_e[0], key);
//    printf("%x,%x",f(state_c[0], key),f(state_e[0], key));
//    state_rhs[1] = f(state_c[0], key) ^ f(state_e[0], key);
//    printf("state_rhs_ones: %d\n",NOS_ones(state_rhs[1]));
    // Inverse IP
    InvIP(state_rhs, rhs_out);
    
}

/* function to calculate the number of ones*/
int NOS_ones(uchar x[])
{
    
    int ones[16]={0,1,1,2,1,2,2,3,1,2,2,3,2,3,3,4};
    int sum_ones=0;
    for(int i=0; i< 8;i++)
    {
        sum_ones += ones[x[i] & 0x0f] + ones[(x[i] & 0xf0) >> 4];
        
    }
    return sum_ones;
}

uchar key_brute(uchar in_c[], uchar in_e[], uchar delta_out[],uchar key_final[])
{
    uchar key[6],key_stat=0,key_hack[8][16],pointer[8]={0,0,0,0,0,0,0,0},key8[8]={0x10,0x2e,0x2a,0x0c,0x01,0x36,0x04,0x09};
    int key_notfound=1,null_val=0;
    int value,atleastfour;
    int i=0,z=0;
    uint key_32[2];
    uchar rhs_out[8], xor_lhs[8];
    
    value=0;
    
    for(int l=0;l<8;l++)
    {
        for(int m=0;m<16;m++)
        {
            key_hack[l][m]=0xcc;
        }
    }
    
     while(key_notfound)
    {
//        for(int j=7; j>=0; j--)
//        {
//            key8[j]= value;
//        }
//        printtext(key8);

        map8to6(key8,key);
        printf("keys in brute--->");
        for(int i=0;i<6;i++)
            printf("%02x",key[i]);
        printf("\n");
        rhs(in_c,in_e,key,rhs_out);
//        uint f(uint state, uchar key[])
        for(int k=0;k<8;k++)
        {
            xor_lhs[k] = rhs_out[k] ^ delta_out[k];
        }
        
//        for(int t=0; t<6; t++)
//            key_temp[t]=key[t];
//        IP(key_32,key_temp);
        

        
        printf("xor:   ");
        printtext(xor_lhs);
        printf("rhs_out:");
        printtext(rhs_out);
        for(int p=0; p<8; p++)
        {
            z=(p/2+4);
            null_val=xor_lhs[z];
//            printf("null_val: %x\n",null_val);
            if(p%2 ==0)
                null_val &= 0x000000f0;
            else
                null_val &= 0x0000000f;
            
            if(null_val == 0)
            {
                key_stat |= (1 << p);
                if(duplicate(key_hack[p],key8[p]))
                {
                    key_hack[p][pointer[p]] = key8[p];
//                    printf("key0:%x\n",key_hack[p][pointer[0]]);
//                    pointer[p]=(pointer[p]+1)%4;
                    pointer[p]++;
                }
            }

        }
        
        atleastfour=0;
        for(i=0;i<8;i++)
        {
            if(pointer[i]>3)
            {
                atleastfour++;
            }
        }
//        printf("pointer ");
//        printtext(pointer);
//        printf("atleastfour :%d",atleastfour);
//        printf("rhs_out: ");
//        printtext(rhs_out);
//        printf("xor:    ");
//        printtext(xor_lhs);
//        printf("Key: ");
//        printkey(key);
         if(atleastfour >= 8 || value>62)
         {
             key_notfound=0;
             display_keys(key_hack);
         }
         else
         {
             key_notfound=1;
         }
        
        value++;
    }

        
//        for (int k=0; k < 6; k++)
//            printf("%02x ",key[k]);
//        printf("\n");
    return key_stat;
}

void display_keys(uchar key[][16])
{
    for(int i=0;i<8;i++)
    {
        for(int j=0;j<16;j++)
        {
            printf("%x\t",key[i][j]);
        }
        printf("\n");
    }
    
}

uint duplicate(uchar key[],uchar dup_val)
{

    for(int i=0;i<16;i++)
    {
        if(key[i] == dup_val)
            return 0;
    }
    return 1;
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
