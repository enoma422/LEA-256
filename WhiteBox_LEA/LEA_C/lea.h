// LEA_C.h
#pragma once
#include <stdint.h>

static const uint32_t Key_delta[8];
static int ROL(uint32_t ibit, uint32_t xbit);
static int ROR(uint32_t ibit, uint32_t xbit);
static uint32_t PLUS(uint32_t x, uint32_t y);
static uint32_t MINUS(uint32_t x, uint32_t y);

void LEA_Round_Enc(uint32_t *in_state, uint32_t *out_state, uint32_t *RK_enc);
void LEA_Round_Dec(uint32_t *in_state, uint32_t *out_state, uint32_t *RK_enc);

void KeySchedule_256(unsigned char *K, uint32_t *RoundKey);

void encrypt_lea(int Nr, uint32_t *RK, unsigned char *PT, unsigned char *CT);
void decrypt_lea(int Nr, uint32_t *RK, unsigned char *PT, unsigned char *CT);
