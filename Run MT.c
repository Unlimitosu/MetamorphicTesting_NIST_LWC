#include "Run MT.h"
#include "Metamorphic Testing.h"

#define GETP() 	uint8_t P[SIZE16] = { 0, };\
				for (int i = 0; i < SIZE16; i++) P[i] = rand() & 0xff;

void ASCON_Test() {
	GETP();

	BCT_ASCON(P, SIZE16);
	BET_ASCON(P, SIZE16);

	BCT_ASCON_hash(P, SIZE16);
	BET_ASCON_hash(P, SIZE16);
	printf("\n\n");
}

void ISAP_Test() {
	GETP();

	BCT_ISAP(P, SIZE16);
	BET_ISAP(P, SIZE16);
	UT_ISAP_HASH(P, SIZE16);
	printf("\n\n");
}
void Sparkle_Test() {
	GETP();

	BCT_Sparkle_SCHWAEMM(P, SIZE16);
	BCT_Sparkle_ESCH(P, SIZE16);
	BET_Sparkle_SCHWAEMM(P, SIZE16);
	BET_Sparkle_ESCH(P, SIZE16);
	UT_Sparkle_SCHWAEMM(P, SIZE16);
	UT_Sparkle_ESCH(P, SIZE16);
	printf("\n\n");
}
void GIFT_Test() {
	GETP();

	BCT_GIFT_COFB(P, SIZE16);
	BET_GIFT_COFB(P, SIZE16);
	printf("\n\n");
}
void TinyJAMBU_Test() {
	GETP();

	BCT_Tinyjambu(P, SIZE16);
	BET_Tinyjambu(P, SIZE16);
	UT_Tinyjambu(P, SIZE16);
	printf("\n\n");
}
void Grain_Test() {
	GETP();

	BCT_Grain(P, SIZE16);
	BET_Grain(P, SIZE16);
	printf("\n\n");
}

void Elephant_Test() {
	GETP();

	BET_Elephant(P, SIZE16);
	BCT_Elephant(P, SIZE16);
	printf("\n\n");
}

void Romulus_Test() {
	GETP();

	BCT_RomulusT(P, SIZE16);
	BET_RomulusN(P, SIZE16);
	printf("\n\n");
}

void Xoodyak_Test() {
	GETP();

	BCT_Xoodoo(P, SIZE16);
	BET_Xoodoo(P, SIZE16);
	UT_Xoodoo_Hash(P, SIZE16);
	printf("\n\n");
}

void Photon_Test() {
	GETP();
	BCT_Photon(P, SIZE16);
	BET_Photon(P, SIZE16);
	printf("\n\n");
}


void Run_MT() {
	ASCON_Test();
	Elephant_Test();
	GIFT_Test();
	Grain_Test();
	ISAP_Test();
	Photon_Test();
	Romulus_Test();
	Sparkle_Test();
	TinyJAMBU_Test();
	Xoodyak_Test();
}