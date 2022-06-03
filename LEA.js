// ---------------------------------------------------
// LEA.js
// 2022-06-03
// FDL Kid 김민지 { minji0022@kookmin.ac.kr }
//---------------------------------------------------

const Key_delta = [ 0xc3efe9db, 0x44626b02, 0x79e27c8a, 0x78df30ec, 0x715ea49e, 0xc785da0a,
    0xe04ef22a, 0xe5c40957 ];

// int -> byte 배열로 변경하는 함수
function intToByteArray(value) {
    let byteArray = new Uint8Array(4);
    byteArray[0] =  (value >> 24);
    byteArray[1] =  (value >> 16);
    byteArray[2] =  (value >> 8);
    byteArray[3] =  (value);
    return byteArray;
}
// byte -> int로 변경하는 함수
function byteArrayToInt(bytes) {
    return ((( bytes[3] & 0xff) << 24) | (( bytes[2] & 0xff) << 16) | ((bytes[1] & 0xff) << 8) | (( bytes[0] & 0xff)));
}

// 32비트 비트열 좌측 순환 이동 함수.
function ROL(ibit, xbit) {
    return ((xbit << ibit) | (xbit >>> (32 - ibit)));   }
// 32비트 비트열 우측 순환 이동 함수.
function ROR(ibit, xbit) {
    return (xbit >>> ibit) | (xbit << (32 - ibit));     }

function PLUS(x, y) {
    return x+y;     }
function MINUS(x, y) {
    return x-y;     }

// LEA 암호화 라운드 함수
function LEA_Round_Enc(in_state, out_state, rK) {
    out_state[0] = ROL(9, PLUS(in_state[0] ^ rK[0], in_state[1] ^ rK[1]));
    out_state[1] = ROR(5, PLUS(in_state[1] ^ rK[2], in_state[2] ^ rK[3]));
    out_state[2] = ROR(3, PLUS(in_state[2] ^ rK[4], in_state[3] ^ rK[5]));
    out_state[3] = in_state[0];
}
// LEA 복호화 라운드 함수
function LEA_Round_Dec(in_state, out_state, RK) {
    out_state[0] = in_state[3];
    out_state[1] = (MINUS(ROR(9, in_state[0]), out_state[0] ^ RK[0]) ^ RK[1]);
    out_state[2] = (MINUS(ROL(5, in_state[1]), out_state[1] ^ RK[2]) ^ RK[3]);
    out_state[3] = (MINUS(ROL(3, in_state[2]), out_state[2] ^ RK[4]) ^ RK[5]);
}

// 키 스케줄 함수
function KeySchedule_256(k,RoundKey) {
    let i;
    let T = new Uint32Array(8);
    
    for (i = 0; i < 8; i++) {
        T[i] = k[i];
    }

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
function encrypt_lea(Nr, RK, PT, CT) {
    let i, j;
    let state = new Uint32Array(4);
    let next_state = new Uint32Array(4);
    let RK_n = new Uint32Array();
    let PT_b = new Uint32Array(4);
    let CT_b = new Uint32Array(4);

    for (i=0;i<4;i++) {
        PT_b = PT.slice(i*4, (i+1)*4);
        state[i] = byteArrayToInt(PT_b);
    }

    // Nr = 32
    for (i = 0; i < Nr; i++) {
        // RK를 슬라이싱 해주는 과정 필요
        RK_n = RK.slice(i*6, (i+1)*6);
        LEA_Round_Enc(state, next_state, RK_n);

        for(j=0;j<4;j++){
            state[j] = next_state[j];
        }
    }

    for (i=0;i<4;i++) {
        CT_b = intToByteArray(state[i]);
        CT[i*4] = CT_b[3];
        CT[i*4+1] = CT_b[2];
        CT[i*4+2] = CT_b[1];
        CT[i*4+3] = CT_b[0];
    }
}

// LEA-256 암호화 함수
function decrypt_lea(Nr, RK, PT, CT) {
    let i, j;
    let state = new Uint32Array(4);
    let next_state = new Uint32Array(4);
    let RK_n = new Uint32Array();
    let PT_b = new Uint32Array(4);
    let CT_b = new Uint32Array(4);

    for (i=0;i<4;i++) {
        CT_b = CT.slice(i*4, (i+1)*4);
        state[i] = byteArrayToInt(CT_b);
    }
    
    // Nr = 32
    for (i = 0; i < Nr; i++) {
        // RK를 슬라이싱 해주는 과정 필요
        // 복호화에 사용되는 키는 암호화에서 사용한 키의 인덱스만 다르다.
        RK_n = RK.slice((Nr - i - 1) * 6, (Nr - i) * 6);
        LEA_Round_Dec(state, next_state, RK_n);

        for(j=0;j<4;j++){
            state[j] = next_state[j];
        }
    }

    for (i=0;i<4;i++) {
        PT_b = intToByteArray(state[i]);
        PT[i*4] = PT_b[3];
        PT[i*4+1] = PT_b[2];
        PT[i*4+2] = PT_b[1];
        PT[i*4+3] = PT_b[0];
    }
}

const Nr = 32;
const Nk = 32;
const Nb = 16;
let i, cnt = 0;
let Kn = new Uint32Array(4);
let K = [   0x0f,0x1e,0x2d,0x3c,0x4b,0x5a,0x69,0x78,0x87,0x96,0xa5,0xb4,0xc3,0xd2,0xe1,0xf0,
            0xf0,0xe1,0xd2,0xc3,0xb4,0xa5,0x96,0x87,0x78,0x69,0x5a,0x4b,0x3c,0x2d,0x1e,0x0f	];
let RoundKey = new Uint32Array(192);
let PT = [	 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f ];
let CT = new Uint8Array(16);
let Decrypted = new Uint8Array(16);
let K_int = new Uint32Array(8);

console.log(' [LEA-256 Encryption] ');
		
for (i=0;i<8;i++) {
    Kn = K.slice(i*4, (i+1)*4);
    K_int[i] = byteArrayToInt(Kn);
}


KeySchedule_256(K_int, RoundKey);

// // 라운드키 확인
// console.log("\n\nRound key: ")
// for (i = 0; i < 192; i++) {
//     let hex = RoundKey[i].toString(16);
//     process.stdout.write(hex + " ");
//     if(i%6==5){
//         process.stdout.write("\n");
//     }
// }

// process.stdout.write("\n");

encrypt_lea(Nr, RoundKey, PT, CT);
decrypt_lea(Nr, RoundKey, Decrypted, CT);

process.stdout.write("Key: ");
for (i = 0; i < Nk; i++) {
    let hex = K[i].toString(16);
    process.stdout.write(hex + ":");
}
// 평문 확인
process.stdout.write("\nPlaintext: ");
for (i = 0; i < Nb; i++) {
    let hex = PT[i].toString(16);
    process.stdout.write(hex + ":");
}
// 암호문 확인
process.stdout.write("\nCiphertext: ");
for (i = 0; i < Nb; i++) {
    let hex = CT[i].toString(16);
    process.stdout.write(hex + ":");
}
// 복호화된 값 확인
process.stdout.write("\nDecryptedText : ");
for (i = 0; i < Nb; i++) {
    let hex = Decrypted[i].toString(16);
    process.stdout.write(hex + ":");
}

// 평문과 복호화된 값이 일치하는지 확인
for (i = 0; i < 16; i++) {
    if (PT[i] == Decrypted[i]) {
        cnt = 0;	}
    else {
        cnt += 1;	}	}
if (cnt == 0) {
    console.log("\nPT == Decrypted : Success...!")
}
