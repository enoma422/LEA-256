// LEA.c
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// 키 스케줄에서 사용되는 상수. 워드 배열
static const uint32_t Key_delta[8] = {
	0xc3efe9db,
	0x44626b02,
	0x79e27c8a,
	0x78df30ec,
	0x715ea49e,
	0xc785da0a,
	0xe04ef22a,
	0xe5c40957
};

// 32비트 비트열 좌측 순환 이동 함수.
static int ROL(uint32_t ibit, uint32_t xbit) {
	return (xbit << ibit) | (xbit >> (32 - ibit));
}

// 32비트 비트열 우측 순환 이동 함수.
static int ROR(uint32_t ibit, uint32_t xbit) {
	return (xbit >> ibit) | (xbit << (32 - ibit));
}

static uint32_t PLUS(uint32_t x, uint32_t y) {
	return (x + y);
}

static uint32_t MINUS(uint32_t x, uint32_t y) {
	return (x - y);
}

// LEA 암호화 라운드 함수
void LEA_Round_Enc(uint32_t *in_state, uint32_t *out_state, uint32_t *RK_enc) {
	out_state[0] = ROL(9, PLUS(in_state[0] ^ RK_enc[0], in_state[1] ^ RK_enc[1]));
	out_state[1] = ROR(5, PLUS(in_state[1] ^ RK_enc[2], in_state[2] ^ RK_enc[3]));
	out_state[2] = ROR(3, PLUS(in_state[2] ^ RK_enc[4], in_state[3] ^ RK_enc[5]));
	out_state[3] = in_state[0];
}

// LEA 복호화 라운드 함수
void LEA_Round_Dec(uint32_t *in_state, uint32_t *out_state, uint32_t *RK_dec) {
	out_state[0] = in_state[3];
	out_state[1] = (MINUS(ROR(9, in_state[0]), out_state[0]^ RK_dec[0]) ^ RK_dec[1]);
	out_state[2] = (MINUS(ROL(5, in_state[1]), out_state[1] ^ RK_dec[2]) ^ RK_dec[3]);
	out_state[3] = (MINUS(ROL(3, in_state[2]), out_state[2] ^ RK_dec[4]) ^ RK_dec[5]);
}

// 키 스케줄 함수
void KeySchedule_256(unsigned char *K, uint32_t *RoundKey) {
	int i;
	uint32_t T[8] = { 0 };

	memcpy(T, K, 32);

	for (i = 0; i < 32; i++) {
		T[(6 * i + 0) % 8] = ROL(1, PLUS(T[(6 * i + 0) % 8], ROL(i, Key_delta[i % 8])));
		T[(6 * i + 1) % 8] = ROL(3, PLUS(T[(6 * i + 1) % 8], ROL(i + 1, Key_delta[i % 8])));
		T[(6 * i + 2) % 8] = ROL(6, PLUS(T[(6 * i + 2) % 8], ROL(i + 2, Key_delta[i % 8])));
		T[(6 * i + 3) % 8] = ROL(11, PLUS(T[(6 * i + 3) % 8], ROL(i + 3, Key_delta[i % 8])));
		T[(6 * i + 4) % 8] = ROL(13, PLUS(T[(6 * i + 4) % 8], ROL(i + 4, Key_delta[i % 8])));
		T[(6 * i + 5) % 8] = ROL(17, PLUS(T[(6 * i + 5) % 8], ROL(i + 5, Key_delta[i % 8])));

		RoundKey[i * 6 + 0] = T[(6 * i + 0) % 8];
		RoundKey[i * 6 + 1] = T[(6 * i + 1) % 8];
		RoundKey[i * 6 + 2] = T[(6 * i + 2) % 8];
		RoundKey[i * 6 + 3] = T[(6 * i + 3) % 8];
		RoundKey[i * 6 + 4] = T[(6 * i + 4) % 8];
		RoundKey[i * 6 + 5] = T[(6 * i + 5) % 8];
	}
}

// LEA-256 암호화 함수
void encrypt_lea(int Nr, uint32_t *RK, unsigned char *PT, unsigned char *CT) {
	int i;
	uint32_t state[4];
	uint32_t next_state[4];

	memcpy(state, PT, 16);

	// Nr = 32
	for (i = 0; i < Nr; i++) {
		LEA_Round_Enc(state, next_state, &RK[i * 6]);
		memcpy(state, next_state, 16);
	}
	memcpy(CT, state, 16);
}

// LEA-256 복호화 함수
void decrypt_lea(int Nr, uint32_t *RK, unsigned char *PT, unsigned char *CT) {
	int i;
	uint32_t next_state[4];
	uint32_t state[4];

	memcpy(state, CT, 16);

	// Nr = 32
	for (i = 0; i < Nr; i++) {
		// 복호화에 사용되는 키는 암호화에서 사용한 키의 인덱스만 다르다.
		LEA_Round_Dec(state, next_state, &RK[(Nr - i - 1) * 6]);
		memcpy(state, next_state, 16);
	}

	memcpy(PT, state, 16);
}
