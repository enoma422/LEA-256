// LEA.c
// 2022-05-27
// FDL Kids ����� { minji0022@kookmin.ac.kr }
#include <stdio.h>
#include <string.h>
#include <stdint.h>

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

static int ROL(uint32_t ibit, uint32_t xbit) {
    return (xbit<<ibit)|(xbit>>(32-ibit));
}

static int ROR(uint32_t ibit, uint32_t xbit) {
    return (xbit>>ibit)|(xbit<<(32-ibit));
}

static uint32_t PLUS(uint32_t x, uint32_t y) {
	return (x + y);
}

static uint32_t MINUS(uint32_t x, uint32_t y) {
	return (x - y);
}

// LEA�� ��ȣȭ ���� �Լ�
void LEA_Round_Enc(uint32_t *in_state, uint32_t *out_state, uint32_t *RK_enc) {
	out_state[0] = ROL(9, PLUS(in_state[0] ^ RK_enc[0], in_state[1] ^ RK_enc[1]));
	out_state[1] = ROL(5, PLUS(in_state[1] ^ RK_enc[2], in_state[2] ^ RK_enc[3]));
	out_state[2] = ROL(3, PLUS(in_state[2] ^ RK_enc[4], in_state[3] ^ RK_enc[5]));
	out_state[3] = in_state[0];
}

void KeySchedule_256_Enc(unsigned char *K, uint32_t *RoundKey){
    int i;
    uint32_t T[8] = {0};

    memcpy(T, K, 32);

    for(i=0;i<32;i++){
        T[(6*i+0)%8] = ROL(1, PLUS(T[(6*i+0)%8],ROL(i,Key_delta[i%8])));
        T[(6*i+1)%8] = ROL(3, PLUS(T[(6*i+1)%8],ROL(i+1,Key_delta[i%8])));
        T[(6*i+2)%8] = ROL(6, PLUS(T[(6*i+2)%8],ROL(i+2,Key_delta[i%8])));
        T[(6*i+3)%8] = ROL(11, PLUS(T[(6*i+3)%8],ROL(i+3,Key_delta[i%8])));
        T[(6*i+4)%8] = ROL(13, PLUS(T[(6*i+4)%8],ROL(i+4,Key_delta[i%8])));
        T[(6*i+5)%8] = ROL(17, PLUS(T[(6*i+5)%8],ROL(i+5,Key_delta[i%8])));

		RoundKey[i*6+0] = T[(6*i+0)%8];
		RoundKey[i*6+1] = T[(6*i+1)%8];
		RoundKey[i*6+2] = T[(6*i+2)%8];
		RoundKey[i*6+3] = T[(6*i+3)%8];
		RoundKey[i*6+4] = T[(6*i+4)%8];
		RoundKey[i*6+5] = T[(6*i+5)%8];
    }
}

void encrypt_lea(int Nr, uint32_t *RK, unsigned char *PT, unsigned char *CT) {
	// state : 128��Ʈ ���� ���º���. ���� �迭�� X = X[0], X[1], X[2], X[3] ���� ǥ��.
	int i;
	uint32_t next_state[4];
	uint32_t state[4];

	memcpy(state, PT, 16);

	for (i = 0; i < Nr; i++) {
		LEA_Round_Enc(state, state, &RK[i * 6]);
		//memcpy(state, next_state, 16);

        printf("\n%d\n",i);

        for(i=0;i<4;i++){
        printf("%02x ", state[i]);
    }
	}

	memcpy(CT, state, 16);
}

void decrypt_lea(int Nr, uint32_t *RK, unsigned char *PT, unsigned char *CT) {
	// state : 128��Ʈ ���� ���º���. ���� �迭�� X = X[0], X[1], X[2], X[3] ���� ǥ��.
	int i;
	uint32_t next_state[4];
	uint32_t state[4];

	memcpy(state, CT, 16);

	for (i = 0; i < Nr; i++) {
		LEA_Round_Enc(next_state, state, &RK[(Nr-i-1) * 6]);
		memcpy(state, next_state, 16);
	}

	memcpy(PT, state, 16);
}

int main() {
    //LEA-256
    int Nr = 16;
    int Nk = 32;
    int Nb = 16;
    int i;

    unsigned char K[32] = // 16 24 32
				{
					0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,
					0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
				};
	uint32_t RoundKey[192] = {0}; // 144 168 192
    unsigned char PT[16]= {0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    unsigned char CT[16] = {0};

    printf("\n");
    printf("LEA-256 Encrypted...\n");

    KeySchedule_256_Enc(K, RoundKey);

    for(i=180;i<192;i++){
        printf("%02x ", RoundKey[i]);
    }

    encrypt_lea(Nr, RoundKey, PT, CT);
    printf("\n");

    for(i=0;i<16;i++){
        printf("%02x ", CT[i]);
    }
	return 0;   
}