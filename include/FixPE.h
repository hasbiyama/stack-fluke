/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "VEH.h"

// Function to initialize PE headers from a file buffer
BOOL InitializePEHeaders(PPEHeaders peHeaders, PBYTE fileBuffer) {
    if (!peHeaders || !fileBuffer) return FALSE;

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)fileBuffer;
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

    peHeaders->ntHeaders = (PIMAGE_NT_HEADERS)(fileBuffer + dosHeader->e_lfanew);
    if (peHeaders->ntHeaders->Signature != IMAGE_NT_SIGNATURE) return FALSE;

    peHeaders->sectionHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)&peHeaders->ntHeaders->OptionalHeader + peHeaders->ntHeaders->FileHeader.SizeOfOptionalHeader);
    peHeaders->importDataDirectory = &peHeaders->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    peHeaders->baseRelocDataDirectory = &peHeaders->ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
    peHeaders->fileBuffer = fileBuffer;

    return TRUE;
}

// Function to resolve imports for the PE file
BOOL FixImports(PPEHeaders peHeaders, PBYTE peBaseAddress) {
    if (!peHeaders || !peBaseAddress) return FALSE;

    PIMAGE_DATA_DIRECTORY importDataDirectory = peHeaders->importDataDirectory;
    if (importDataDirectory->VirtualAddress == 0) return TRUE;

    PIMAGE_IMPORT_DESCRIPTOR importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(peBaseAddress + importDataDirectory->VirtualAddress);
    while (importDescriptor->OriginalFirstThunk || importDescriptor->FirstThunk) {
        HMODULE module = LoadLibraryA((LPCSTR)(peBaseAddress + importDescriptor->Name));
        if (!module) {
            PRINT_WINAPI_ERR("LoadLibraryA");
            return FALSE;
        }

        PIMAGE_THUNK_DATA origFirstThunk = (PIMAGE_THUNK_DATA)(peBaseAddress + importDescriptor->OriginalFirstThunk);
        PIMAGE_THUNK_DATA firstThunk = (PIMAGE_THUNK_DATA)(peBaseAddress + importDescriptor->FirstThunk);

        while (origFirstThunk && origFirstThunk->u1.Function) {
            ULONG_PTR funcAddress;
            if (origFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                funcAddress = (ULONG_PTR)GetProcAddress(module, (LPCSTR)IMAGE_ORDINAL(origFirstThunk->u1.Ordinal));
            } else {
                PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(peBaseAddress + origFirstThunk->u1.AddressOfData);
                funcAddress = (ULONG_PTR)GetProcAddress(module, importByName->Name);
            }
            if (!funcAddress) {
                PRINT_WINAPI_ERR("GetProcAddress");
                return FALSE;
            }
            firstThunk->u1.Function = funcAddress;
            origFirstThunk++;
            firstThunk++;
        }
        importDescriptor++;
    }
    return TRUE;
}

// Function to apply base relocations for the PE file
BOOL FixRelocations(PPEHeaders peHeaders, ULONG_PTR peBaseAddress, ULONG_PTR preferredBase) {
    if (!peHeaders || !peBaseAddress) return FALSE;

    PIMAGE_DATA_DIRECTORY relocDataDirectory = peHeaders->baseRelocDataDirectory;
    if (relocDataDirectory->VirtualAddress == 0) return TRUE;

    ULONG_PTR delta = peBaseAddress - preferredBase;
    PIMAGE_BASE_RELOCATION baseRelocation = (PIMAGE_BASE_RELOCATION)(peBaseAddress + relocDataDirectory->VirtualAddress);

    while (baseRelocation && baseRelocation->VirtualAddress && baseRelocation->SizeOfBlock) {
        PBaseRelocationEntry relocEntry = (PBaseRelocationEntry)(baseRelocation + 1);
        DWORD numEntries = (baseRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(BaseRelocationEntry);

        for (DWORD i = 0; i < numEntries; i++) {
            if (relocEntry[i].Type == IMAGE_REL_BASED_DIR64) {
                *(ULONG_PTR*)((PBYTE)peBaseAddress + baseRelocation->VirtualAddress + relocEntry[i].Offset) += delta;
            }
        }
        baseRelocation = (PIMAGE_BASE_RELOCATION)((PBYTE)baseRelocation + baseRelocation->SizeOfBlock);
    }
    return TRUE;
}

// Function to adjust memory permissions to NA
BOOL AdjustMemoryPermissions(ULONG_PTR peBaseAddress, PIMAGE_NT_HEADERS ntHeaders, PIMAGE_SECTION_HEADER sectionHeaders) {
    if (!peBaseAddress || !ntHeaders || !sectionHeaders) return FALSE;

    for (DWORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        DWORD protection = PAGE_NOACCESS;
        if (sectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) {
            protection = PAGE_NOACCESS;
        } else if (sectionHeaders[i].Characteristics & IMAGE_SCN_MEM_EXECUTE) {
            protection = PAGE_NOACCESS;
        }
    }
    return TRUE;
}

// Function to execute the PE file
BOOL ExecutePE(PPEHeaders peHeaders) {
    if (!peHeaders) return FALSE;

    // Add the Vectored Exception Handler
    PVOID vehHandle = AddVectoredExceptionHandler(1, VectoredHandler);
    if (!vehHandle) {
        PRINT_WINAPI_ERR("AddVectoredExceptionHandler");
        return FALSE;
    }

    // Allocate memory for the PE file
    PBYTE baseAddress = (PBYTE)VirtualAlloc(NULL, peHeaders->ntHeaders->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (!baseAddress) {
        PRINT_WINAPI_ERR("VirtualAlloc");
        return FALSE;
    }

    // Copy each section to the allocated memory
    for (DWORD i = 0; i < peHeaders->ntHeaders->FileHeader.NumberOfSections; i++) {
        PIMAGE_SECTION_HEADER sectionHeader = &peHeaders->sectionHeaders[i];
        memcpy(baseAddress + sectionHeader->VirtualAddress, peHeaders->fileBuffer + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData);
    }

    // Fix imports
    if (!FixImports(peHeaders, baseAddress)) {
        VirtualFree(baseAddress, 0, MEM_RELEASE);  // Cleanup on failure
        return FALSE;
    }
    
    // Fix relocations
    if (!FixRelocations(peHeaders, (ULONG_PTR)baseAddress, peHeaders->ntHeaders->OptionalHeader.ImageBase)) {
        VirtualFree(baseAddress, 0, MEM_RELEASE);  // Cleanup on failure
        return FALSE;
    }

    // Adjust memory permissions
    if (!AdjustMemoryPermissions((ULONG_PTR)baseAddress, peHeaders->ntHeaders, peHeaders->sectionHeaders)) {
        VirtualFree(baseAddress, 0, MEM_RELEASE);  // Cleanup on failure
        return FALSE;
    }

    // Get the entry point and execute the PE file
    PVOID entryPoint = baseAddress + peHeaders->ntHeaders->OptionalHeader.AddressOfEntryPoint;
    typedef int (*MAIN)(); // Define the function signature

    // Trigger execution
    printf("[*] Triggering access violation by executing the PE file.\n");
    int result = ((MAIN)entryPoint)(); // Execute the main function
    return result == 0; // Return TRUE if the main function executed successfully
}