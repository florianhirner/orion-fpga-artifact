/* 
 * PRNG-style implementation of trivium (64-bit version).
 * Author: Charles Bouillaguet (charles.bouillaguet@lip6.fr).
 *
 * This version operates on 64-bit words and returns 64 pseudo-random bits.
 *
 * Trivium is a stream cipher (cryptographic-strength RNG) selected by eSTREAM 
 * (part of the the EU ECRYPT project) to be part of a portfolio of secure 
 * algorithms (https://www.ecrypt.eu.org/stream/).
 *
 * Trivium has been designed by Christophe De Cannière and Bart Preneel.
 * This code generates the same output as trivium's reference implementation.
 *
 * The generator takes a 64-bit seed and a 64-bit "sequence number" (this allows
 * to generate independent sequences with the same seed).
 */
#include <stdio.h>
#include <stdint.h> 

#include <inttypes.h>

uint64_t s11, s12, s21, s22, s31, s32;	/* global internal state */

uint64_t trivium64_next()
{
	uint64_t s66 = (s12 << 62) ^ (s11 >> 2);
	uint64_t s93 = (s12 << 35) ^ (s11 >> 29);
	uint64_t s162 = (s22 << 59) ^ (s21 >> 5);
	uint64_t s177 = (s22 << 44) ^ (s21 >> 20);
	uint64_t s243 = (s32 << 62) ^ (s31 >> 2);
	uint64_t s288 = (s32 << 17) ^ (s31 >> 47);
	uint64_t s91 = (s12 << 37) ^ (s11 >> 27);
	uint64_t s92 = (s12 << 36) ^ (s11 >> 28);
	uint64_t s171 = (s22 << 50) ^ (s21 >> 14);
	uint64_t s175 = (s22 << 46) ^ (s21 >> 18);
	uint64_t s176 = (s22 << 45) ^ (s21 >> 19);
	uint64_t s264 = (s32 << 41) ^ (s31 >> 23);
	uint64_t s286 = (s32 << 19) ^ (s31 >> 45);
	uint64_t s287 = (s32 << 18) ^ (s31 >> 46);
	uint64_t s69 = (s12 << 59) ^ (s11 >> 5);
	uint64_t t1 = s66 ^ s93;	/* update */
	uint64_t t2 = s162 ^ s177;
	uint64_t t3 = s243 ^ s288;
	uint64_t z = t1 ^ t2 ^ t3;
	t1 ^= (s91 & s92) ^ s171;
	t2 ^= (s175 & s176) ^ s264;
	t3 ^= (s286 & s287) ^ s69;
	s12 = s11;		/* rotate */
	s11 = t3;
	s22 = s21;
	s21 = t1;
	s32 = s31;
	s31 = t2;
	return z;
}

void trivium64_setseed(uint64_t seed, uint64_t seq)
{
	s11 = seed;
	s12 = 0;
	s21 = seq;
	s22 = 0;
	s31 = 0;
	s32 = 0x700000000000;
	
	for (int i = 0; i < 18; i++)	/* blank rounds */
		trivium64_next();
}

uint64_t trivium64_coeff(uint64_t bit_size, uint64_t q, uint64_t coeff_in)
{
    uint64_t coeff_masked;
    uint64_t coeff_out;
    
    coeff_masked = coeff_in & ((1ULL << bit_size) - 1);
    coeff_out    = (coeff_masked < q) ? coeff_masked : coeff_masked - q;
    
    return coeff_out;
}


int main() {

    /*
    // Single Test
    uint64_t seed = 0x0123456789abcdef ^ 0x0000000000000001;
    uint64_t seq  = 0x0000000000000000;
    
    trivium64_setseed(seed, seq);
    
    uint64_t t_out;
    
    for (int i = 0; i < 8; i++)	{
        t_out = trivium64_next();
        printf("t_out = 0x%llx\n", t_out);    
    }
    */
    
    // MEM TEST
    uint64_t bit_size;
    uint64_t q_index,q;
    uint64_t coeff_t,coeff;
    
    bit_size = 54;
    q_index  = 0;
    q = (q_index == 0) ? 9007199256051713 :
        (q_index == 1) ? 9007199257362433 :
        (q_index == 2) ? 9007199261294593 :
        (q_index == 3) ? 9007199262867457 :
        (q_index == 4) ? 9007199272304641 :
        (q_index == 5) ? 9007199273091073 :
        (q_index == 6) ? 9007199281217537 :
        (q_index == 7) ? 9007199282003969 :
        (q_index == 8) ? 9007199284101121 :
        (q_index == 9) ? 9007199292751873 :
        (q_index == 10) ? 9007199293014017 :
        (q_index == 11) ? 9007199309529089 :
        (q_index == 12) ? 9007199316344833 :
        (q_index == 13) ? 9007199318704129 :
        (q_index == 14) ? 9007199322112001 :
        (q_index == 15) ? 9007199322636289 :
        (q_index == 16) ? 9007199323422721 :
        (q_index == 17) ? 9007199325782017 :
        (q_index == 18) ? 9007199335219201 :
        (q_index == 19) ? 9007199337054209 :
        (q_index == 20) ? 9007199338627073 :
        (q_index == 21) ? 9007199343869953 :
        (q_index == 22) ? 9007199344132097 :
        (q_index == 23) ? 9007199350161409 :
        (q_index == 24) ? 9007199353307137 :
        (q_index == 25) ? 9007199353569281 :
        (q_index == 26) ? 9007199357239297 :
        (q_index == 27) ? 9007199361171457 :
        (q_index == 28) ? 9007199362744321 :
        (q_index == 29) ? 9007199365890049 :
        (q_index == 30) ? 9007199370608641 : 9007199373230081;
        
    uint64_t seed = 0xaad3b38085d8f172;
    uint64_t seq  = 0x0000000000000000;
    
    int i,j;
    
    // set seed
    trivium64_setseed(seed, seq);
    
    for(int i=0; i<16; i++) {
        // generate 64-bit out of Trivium
        coeff_t = trivium64_next();
        // generate coefficient
        coeff = trivium64_coeff(bit_size, q, coeff_t);
        // print coefficient
        // printf("coeff = 0x%llx\n", coeff);
    }
    
    return 0;
}








