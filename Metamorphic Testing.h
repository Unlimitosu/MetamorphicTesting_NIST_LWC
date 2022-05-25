#pragma once

#include <stdio.h>
#include <memory.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <assert.h>

#include "__ascon_ascon.h"
#include "__gift_gift128.h"
#include "__sparkle_sparkle_ref.h"
#include "__sparkle_schwaemm_cfg.h"
#include "__isap_isap.h"
#include "__tinyjambu_ encrypt.h"
#include "__romulusn_romulus_n.h"
#include "__photon_photon.h"
#include "__grain_grain128aead-v2.h"
#include "__elephant_elephant_176.h"
#include "Xoodoo.h"
#include "Xoodyak.h"
#include "api.h" //Xoodoo


#define TAGBYTES 16
#define TAGBYTES256 32
#define EXCLUSION_BYTELEN 16
#define SPARKLE_DIGESTLEN 32
#define SCHWAEMM_CIPHERLEN 32
#define DIGESTLEN 32

void printBlock(uint8_t* b);

/*****************************ASCON*********************************/
void BCT_ASCON(uint8_t* Plaintext, size_t size);
void BCT_ASCON_hash(uint8_t* Plaintext, size_t size);
void BET_ASCON(uint8_t* Plaintext, size_t size);
void BET_ASCON_hash(uint8_t* Plaintext, size_t size);

/****************************Elephant*******************************/
void BCT_Elephant(uint8_t* Plaintext, size_t size);
void BET_Elephant(uint8_t* Plaintext, size_t size);

/***************************GIFT-COFB*******************************/
void BCT_GIFT_COFB(uint8_t* Plaintext, size_t size);
void BET_GIFT_COFB(uint8_t* Plaintext, size_t size);

/**************************Grain-128AEAD****************************/
void BCT_Grain(uint8_t* Plaintext, size_t size);
void BET_Grain(uint8_t* Plaintext, size_t size);

/*****************************ISAP**********************************/
void BCT_ISAP(uint8_t* Plaintext, size_t size);
void BET_ISAP(uint8_t* Plaintext, size_t size);
void UT_ISAP_HASH(uint8_t* Plaintext, size_t size);

/*************************Photon-Beetle*****************************/
void BCT_Photon(uint8_t* Plaintext, size_t size);
void BET_Photon(uint8_t* Plaintext, size_t size);

/****************************Romulus********************************/
void BCT_RomulusT(uint8_t* Plaintext, size_t size);
void BET_RomulusN(uint8_t* Plaintext, size_t size);

/****************************Sparkle********************************/
void BCT_Sparkle_SCHWAEMM(uint8_t* Plaintext, size_t size);
void BET_Sparkle_SCHWAEMM(uint8_t* Plaintext, size_t size);
void BCT_Sparkle_ESCH(uint8_t* Plaintext, size_t size);
void BET_Sparkle_ESCH(uint8_t* Plaintext, size_t size);
void UT_Sparkle_ESCH(uint8_t* Plaintext, size_t size);
void UT_Sparkle_SCHWAEMM(uint8_t* Plaintext, size_t size);

/***************************TinyJAMBU*******************************/
void BCT_Tinyjambu(uint8_t* Plaintext, size_t size);
void BET_Tinyjambu(uint8_t* Plaintext, size_t size);
void UT_Tinyjambu(uint8_t* Plaintext, size_t size);

/****************************Xoodyak********************************/
void BCT_Xoodoo(uint8_t* Plaintext, size_t size);
void BET_Xoodoo(uint8_t* Plaintext, size_t size);
void UT_Xoodoo_Hash(uint8_t* Plaintext, size_t size);

