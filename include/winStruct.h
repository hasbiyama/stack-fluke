/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include <Windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <dbghelp.h>

// Define the macro
#define SLEEP_1_SECOND() Sleep(1000)
#define THREAD_SYNC_SLEEP() Sleep(5) // can be increased to reduce CPU usage

// Macro for printing Windows API errors
#define PRINT_WINAPI_ERR(apiName) fprintf(stderr, "[!] %s failed with error: %d\n", apiName, GetLastError())

HHOOK hKeyboardHook;
DWORD oldProtection; // Variable to hold the old memory protection state
HANDLE revertThreadHandle; // Handle for the thread that will revert memory protection
volatile int lastKeyPressed = -1; // Global volatile variable to hold the last key pressed

/* 
    "volatile" tells the compiler NOT to optimize the variable, 
    ensuring the latest value is ALWAYS read from memory, 
    preventing errors in concurrent programming 

*/

// Struct representing a base relocation entry
typedef struct {
    WORD Offset : 12; // Offset within the image
    WORD Type : 4;    // Type of relocation
} BaseRelocationEntry, *PBaseRelocationEntry;

// Struct to hold various PE (Portable Executable) headers
typedef struct {
    PIMAGE_NT_HEADERS ntHeaders;                // Pointer to NT headers
    PIMAGE_SECTION_HEADER sectionHeaders;       // Pointer to section headers
    PIMAGE_DATA_DIRECTORY importDataDirectory;  // Pointer to import data directory
    PIMAGE_DATA_DIRECTORY baseRelocDataDirectory; // Pointer to base relocation directory
    PBYTE fileBuffer;                           // Pointer to the file buffer containing PE data
} PEHeaders, *PPEHeaders;