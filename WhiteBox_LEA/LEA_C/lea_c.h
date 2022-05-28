

#ifndef  __LEA_C_H__
#define  __LEA_C_H__

extern void JsCrypto_LEA_EncryptKeySchedule_256(unsigned char *K, uint32_t *RoundKey);
extern void JsCrypto_LEA_DecryptBlock(int Nr, uint32_t *RoundKey, unsigned char *plaintext, unsigned char *ciphertext);
extern void JsCrypto_LEA_EncryptBlock(int Nr, uint32_t *RoundKey, unsigned char *plaintext, unsigned char *ciphertext);

#endif // __LEA_C_H__