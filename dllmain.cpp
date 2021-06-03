// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <stdio.h>
#include <stdlib.h>
#include "context_cipher.h"




/////  GLOBAL VARIABLES  /////
#define Sbox_size 256   // 2^8 S-box
struct Cipher* cipher_data;

/////  FUNCTION PROTOTYPES  /////
extern "C" _declspec(dllexport) int init(struct Cipher* cipher_data_param);
extern "C" _declspec(dllexport) int cipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, struct KeyData* key);
extern "C" _declspec(dllexport) int decipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, struct KeyData* key);

/////  AUX FUNCTIONS  /////
void swap(unsigned char* a, unsigned char* b) {
    int tmp = *a;
    *a = *b;
    *b = tmp;
}

//KSA: Key scheduling algorithm
int ksa(unsigned char* key, unsigned char* S) {
    printf("KSA invoked\n");
    int i = 0;
    int keylen = strlen((char *)key);
    //Primero se rellena el array de 256 bytes
    for (i = 0; i < Sbox_size; i++) {
        S[i] = i;
    }
    //A continuacion se intercambian sus valores mezclandolos con la clave
    int j = 0;
    for (i = 0; i < Sbox_size; i++) {
        //La key funciona como semilla que marca los intercambios en S
        j = (j + S[i] + key[i % keylen]) % Sbox_size;
        swap(&S[i], &S[j]);
    }
    return 0;
}

//PRGA: Pseudo Random generation algorithm
int prga(unsigned char* S, char* orig, unsigned char* ciphered) {
    printf("PRGA invoked\n");
    int i = 0, j = 0, n = 0, rnd = 0;

    for (n = 0; n < strlen(orig); n++) {
        i = (i + 1) % Sbox_size;
        j = (j + S[i]) % Sbox_size;

        swap(&S[i], &S[j]);
        rnd = S[(S[i] + S[j]) % Sbox_size]; //rnd es cada byte del keystream

        //El elemento cifrado, es el elemento elegido de S xor Texto plano
        ciphered[n] = rnd ^ orig[n];

    }
    return 0;
}

//RC4
int rc4(unsigned char* key, char* orig, unsigned char* ciphered) {
    printf("RC4 invoked\n");
    int i = 0;
    unsigned char S[Sbox_size];

    ksa(key, S);
    prga(S, orig, ciphered);

    return 0;
}
/////  FUNCTION IMPLEMENTATIONS  /////
//KSA: Key scheduling algorithm
int ksa_aux(unsigned char* key, unsigned char* S) {
    printf("KSA_aux invoked\n");
    int i = 0;
    int keylen = strlen((char*)key);
    //Testing only
    key = (unsigned char*)"Wiki";
    keylen = 4;
    printf("La clave mide %d\n",keylen);
    //Primero se rellena el array de 256 bytes
    for (i = 0; i < Sbox_size; i++) {
        S[i] = i;
    }
    //A continuacion se intercambian sus valores mezclandolos con la clave
    int j = 0;
    for (i = 0; i < Sbox_size; i++) {
        //La key funciona como semilla que marca los intercambios en S
        j = (j + S[i] + key[i % keylen]) % Sbox_size;
        swap(&S[i], &S[j]);
    }
    return 0;
}

//PRGA: Pseudo Random generation algorithm
int prga_aux(unsigned char* S, unsigned char* orig, unsigned char* ciphered) {
    printf("PRGA_aux invoked\n");
    int i = 0, j = 0, n = 0, rnd = 0;

    for (n = 0; n < strlen((char*)orig); n++) {
        i = (i + 1) % Sbox_size;
        j = (j + S[i]) % Sbox_size;

        swap(&S[i], &S[j]);
        rnd = S[(S[i] + S[j]) % Sbox_size]; //rnd es cada byte del keystream

        //El elemento cifrado, es el elemento elegido de S xor Texto plano
        ciphered[n] = rnd ^ orig[n];

    }
    return 0;
}

int rc4_aux(unsigned char* key, LPCVOID in_buf, LPVOID out_buf) {
    printf("RC4_aux invoked\n");
    int i = 0;
    unsigned char S[Sbox_size];
    unsigned char* orig = (unsigned char*)in_buf;
    unsigned char* ciphered = (unsigned char*)out_buf;


    ksa_aux(key, S);
    printf("KSA completed now prga");
    prga_aux(S, orig, ciphered);

    return 0;
}

int init(struct Cipher* cipher_data_param) {
    cipher_data = cipher_data_param;
    printf("Initializing (%ws)\n", cipher_data->file_name);

    return 0;
}

int cipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, struct KeyData* key) {
    printf("Ciphering (%ws)\n", cipher_data->file_name);
    //rc4((unsigned char *)key->data, (char*)in_buf, (unsigned char*)out_buf);
    rc4_aux(key->data, in_buf, out_buf);
    //memcpy(out_buf, in_buf, size);

    return 0;
}

int decipher(LPVOID out_buf, LPCVOID in_buf, DWORD size, struct KeyData* key) {
    printf("Deciphering (%ws)\n", cipher_data->file_name);
    //memcpy(out_buf, in_buf, size);
    rc4((unsigned char*)key->data, (char*)in_buf, (unsigned char*)out_buf);

    return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

