/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "winStruct.h"

// Function to decrypt a PE file buffer using AES
VOID DecAES(BYTE *peBuffer, DWORD bufferLen, BYTE *key, DWORD keyLen) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    HCRYPTKEY hKey;

    // Acquire a cryptographic context and create a hash
    if (CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(hProv, CALG_SHA_512, 0, 0, &hHash) &&
        CryptHashData(hHash, key, keyLen, 0) &&
        CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        
        // Decrypt the buffer
        if (!CryptDecrypt(hKey, 0, TRUE, 0, peBuffer, &bufferLen)) {
            PRINT_WINAPI_ERR("CryptDecrypt");
        }

        // Clean up cryptographic resources
        CryptDestroyKey(hKey);
        CryptDestroyHash(hHash);
    } else {
        PRINT_WINAPI_ERR("Cryptographic context error");
    }

    CryptReleaseContext(hProv, 0);
}

DWORD GetMainThread(DWORD pid) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return 0; // Error
    }

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);

    if (!Thread32First(hSnapshot, &te)) {
        CloseHandle(hSnapshot);
        return 0; // Error
    }

    DWORD mainThreadId = 0;
    do {
        if (te.th32OwnerProcessID == pid) {
            mainThreadId = te.th32ThreadID;
            break;
        }
    } while (Thread32Next(hSnapshot, &te));

    CloseHandle(hSnapshot);
    return mainThreadId;
}