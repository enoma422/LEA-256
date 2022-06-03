/* ----------------------------------------------
 * LEA.java
 * 2022-05-31
 * FDL Kid 김민지 { minji0022@kookmin.ac.kr }
 * ----------------------------------------------
 * */

package LEA;

import java.util.Arrays;

public class LEA {
	// C의 memcpy함수 구현 : 메모리 복사 함수
	public static void memcpy(Object to, Object from, int size) {
		System.arraycopy(from, 0, to, 0, size);
	}
	
	// int -> byte 배열로 변경하는 함수
	public static byte[] intToByteArray(int value) {
		byte[] byteArray = new byte[4];
		byteArray[0] = (byte) (value >> 24);
		byteArray[1] = (byte) (value >> 16);
		byteArray[2] = (byte) (value >> 8);
		byteArray[3] = (byte) (value);
		return byteArray;
	}
	
	// byte -> int로 변경하는 함수
	public static int byteArrayToInt(byte bytes[]) {
		return ((((int) bytes[3] & 0xff) << 24) | (((int) bytes[2] & 0xff) << 16) | (((int) bytes[1] & 0xff) << 8)
				| (((int) bytes[0] & 0xff)));
	}
	
	// 키 스케줄에서 사용되는 상수. 워드 배열
	final static int Key_delta[] = { 0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a,
			0xe04ef22a, 0xe5c40957 };

	// 32비트 비트열 좌측 순환 이동 함수.
	public static int ROL(int ibit, int xbit) {
		return (int) ((xbit << ibit) | (xbit >>> (32 - ibit)));
	}

	// 32비트 비트열 우측 순환 이동 함수.
	public static int ROR(int ibit, int xbit) {
		return (xbit >>> ibit) | (xbit << (32 - ibit));
	}

	public static int PLUS(int x, int y) {
		return x + y;
	}

	public static int MINUS(int x, int y) {
		return x - y;
	}

	// LEA 암호화 라운드 함수
	public static void LEA_Round_Enc(int in_state[], int out_state[], int[] rK) {
		out_state[0] = ROL(9, PLUS(in_state[0] ^ rK[0], in_state[1] ^ rK[1]));
		out_state[1] = ROR(5, PLUS(in_state[1] ^ rK[2], in_state[2] ^ rK[3]));
		out_state[2] = ROR(3, PLUS(in_state[2] ^ rK[4], in_state[3] ^ rK[5]));
		out_state[3] = in_state[0];
	}

	// LEA 복호화 라운드 함수
	public static void LEA_Round_Dec(int in_state[], int out_state[], int RK[]) {
		out_state[0] = in_state[3];
		out_state[1] = (MINUS(ROR(9, in_state[0]), out_state[0] ^ RK[0]) ^ RK[1]);
		out_state[2] = (MINUS(ROL(5, in_state[1]), out_state[1] ^ RK[2]) ^ RK[3]);
		out_state[3] = (MINUS(ROL(3, in_state[2]), out_state[2] ^ RK[4]) ^ RK[5]);
	}

	// 키 스케줄 함수
	public static void KeySchedule_256(int[] k, int RoundKey[]) {
		int i;
		int[] T = new int[8];
		
		memcpy(T, k, 8);

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
	public static void encrypt_lea(int Nr, int RK[], byte[] PT, byte[] CT) {
		int i;
		int[] state = new int[4];
		int[] next_state = new int[4];
		int[] RK_n = { 0 };
		byte[] PT_b = new byte[4];
		byte[] CT_b = new byte[4];
		int[] PT_int = new int[4];
		int[] CT_int = new int[4];
		
		for (i=0;i<4;i++) {
			PT_b = Arrays.copyOfRange(PT, i*4, (i+1)*4);
			PT_int[i] = byteArrayToInt(PT_b);
		}
		
		memcpy(state, PT_int, 4);
		
		// Nr = 32
		for (i = 0; i < Nr; i++) {
			// RK를 슬라이싱 해주는 과정 필요
			RK_n = Arrays.copyOfRange(RK, i * 6, (i+1) * 6);
			LEA_Round_Enc(state, next_state, RK_n);
			memcpy(state, next_state, 4);
		}
		memcpy(CT_int, state, 4);
		
		for (i=0;i<4;i++) {
			CT_b = intToByteArray(CT_int[i]);
			CT[i*4] = CT_b[3];
			CT[i*4+1] = CT_b[2];
			CT[i*4+2] = CT_b[1];
			CT[i*4+3] = CT_b[0];
		}
	}

	// LEA-256 복호화 함수
	public static void decrypt_lea(int Nr, int RK[], byte[] PT, byte[] CT) {
		int i;
		int[] state = new int[4];
		int[] next_state = new int[4];
		int[] RK_n = { 0 };
		byte[] PT_b = new byte[4];
		byte[] CT_b = new byte[4];
		int[] PT_int = new int[4];
		int[] CT_int = new int[4];

		for (i=0;i<4;i++) {
			CT_b = Arrays.copyOfRange(CT, i*4, (i+1)*4);
			CT_int[i] = byteArrayToInt(CT_b);
		}
		
		memcpy(state, CT_int, 4);

		// Nr = 32
		for (i = 0; i < Nr; i++) {
			// RK를 슬라이싱 해주는 과정 필요
			// 복호화에 사용되는 키는 암호화에서 사용한 키의 인덱스만 다르다.
			RK_n = Arrays.copyOfRange(RK, (Nr - i - 1) * 6, (Nr - i) * 6);
			LEA_Round_Dec(state, next_state, RK_n);
			memcpy(state, next_state, 4);
		}
		memcpy(PT_int, state, 4);
		
		for (i=0;i<4;i++) {
			PT_b = intToByteArray(PT_int[i]);
			PT[i*4] = PT_b[3];
			PT[i*4+1] = PT_b[2];
			PT[i*4+2] = PT_b[1];
			PT[i*4+3] = PT_b[0];
		}
	}

	public static void main(String[] args) {
		int Nr = 32;
		int Nk = 32;
		int Nb = 16;
		int i, cnt = 0;
		byte Kn[] = new byte[4];
		
		byte K[] = {
				0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,(byte)0x87,(byte)0x96,(byte)0xa5,(byte)0xb4,(byte)0xc3,(byte)0xd2,(byte)0xe1,(byte)0xf0,
				(byte)0xf0,(byte)0xe1,(byte)0xd2,(byte)0xc3,(byte)0xb4,(byte)0xa5,(byte)0x96,(byte)0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f		};
		int RoundKey[] = new int[192];
		byte PT[] = {	 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f 	};
		byte CT[] = new byte[16];
		byte Decrypted[] = new byte[16];
		int K_int[]= new int[8];
		
		System.out.println(" [LEA-256 Encryption] ");
		
		for (i=0;i<8;i++) {
			Kn = Arrays.copyOfRange(K, i*4, (i+1)*4);
			K_int[i] = byteArrayToInt(Kn);
		}
		
		KeySchedule_256(K_int, RoundKey);
		
//		// 라운드키 확인
//		System.out.println("\nRound key: ");
//		for (i = 0; i < 192; i++) {
//			System.out.printf("%02x ", RoundKey[i]);
//			if (i%6==5) {
//				System.out.printf("\n\n");
//			}
//		}
		
		encrypt_lea(Nr, RoundKey, PT, CT);
		decrypt_lea(Nr, RoundKey, Decrypted, CT);

		System.out.println("key: ");
		for (i = 0; i < Nk; i++) {
			System.out.printf("%02x:", K[i]);
		}
		System.out.println("\nPlainText : ");
		for (i = 0; i < 16; i++) {
			System.out.printf("%02x:", PT[i]);
		}
		System.out.println("\nCipherText : ");
		for (i = 0; i < 16; i++) {
			System.out.printf("%02x:", CT[i]);
		}
		System.out.println("\nDecryptedText : ");
		for (i = 0; i < 16; i++) {
			System.out.printf("%02x:", Decrypted[i]);
		}
		System.out.println("\n");
		
		// 평문과 복호화된 값이 일치하는지 확인
		for (i = 0; i < 16; i++) {
			if (PT[i] == Decrypted[i]) {
				cnt = 0;	}
			else {
				cnt += 1;	}	}
		if (cnt == 0) {
			System.out.println("PT == Decrypted : Success...!");
		}
	}
}
