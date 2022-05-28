// ------------------------------------------
// LEA-256 - C
// 2022-05-27
// FDL Kids 김민지 { minji0022@kookmin.ac.kr }
// ------------------------------------------
// main.c

#include <stdio.h>
#include <string.h>
#include "lea_c.h"

int main() {
	//LEA-256
	int Nr = 32;
	int Nk = 32;
	int Nb = 16;
	int i, cnt = 0;

	unsigned char K[32] = 
	{
		0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,
		0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f
	};
	uint32_t RoundKey[192] = { 0 }; 
	unsigned char PT[16] = { 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f };
	unsigned char CT[16] = { 0 };
	unsigned char Decrypted[16] = { 0 };

	printf(" [ LEA-256 Encryption ] ");
	
	KeySchedule_256(K, RoundKey);
	encrypt_lea(Nr, RoundKey, PT, CT);
	decrypt_lea(Nr, RoundKey, Decrypted, CT);

	/*printf("\nKey : ");
	for (i = 0; i < Nk; i++) {
		printf("%02x ", K[i]);
	}
	printf("\n\nPlainText : ");
	for (i = 0; i < 16; i++) {
		printf("%02x ", PT[i]);
	}
	printf("\nCipherText : ");
	for (i = 0; i < 16; i++) {
		printf("%02x ", CT[i]);
	}
	printf("\nDecryptedText : ");
	for (i = 0; i < 16; i++) {
		printf("%02x ", Decrypted[i]);
	}
	printf("\n");*/

	// 평문과 복호화된 값이 일치하는지 확인
	for (i = 0; i < 16; i++) {
		if (PT[i] == Decrypted[i]) {
			cnt = 0;
		}
		else {
			cnt += 1;
		}
	}
	if (cnt == 0) {
		printf("\nPT == Decrypted : Success...!");
	}
	return 0;
}
