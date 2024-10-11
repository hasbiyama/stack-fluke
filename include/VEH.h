/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "stackFrame.h"

// Function to revert memory protection to PAGE_NOACCESS
DWORD WINAPI RevertMemoryProtection(LPVOID lpParam) {
    MEMORY_BASIC_INFORMATION mbi;
    DWORD pid = GetCurrentProcessId();
    DWORD tid = GetMainThread(pid);
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

    // Query memory information for the given address
    if (VirtualQuery(lpParam, &mbi, sizeof(mbi))) {
        SLEEP_1_SECOND(); // Delay for demonstration

        // Set memory protection to PAGE_NOACCESS
        VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_NOACCESS, &oldProtection);
        printf("[*] Memory protection reverted to PAGE_NOACCESS.\n");
        
        // modifying sframes after setting memproc to NA
        ModifyStackFrame(hThread, pid);
    }
    return 0;
}

// Exception handler for access violations
LONG WINAPI VectoredHandler(PEXCEPTION_POINTERS pExceptionInfo) {
    // Check for access violation exception
    if (pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
        PVOID faultAddress = (PVOID)pExceptionInfo->ExceptionRecord->ExceptionInformation[1]; // Fault address
        DWORD violationType = (DWORD)pExceptionInfo->ExceptionRecord->ExceptionInformation[0]; // Type of violation (read, write, execute)

        // Log the fault address and type of access violation
        printf("\n[!] Access violation at address: %p\n", faultAddress);
        switch (violationType) {
            case 0: printf("[!] Violation Type: Read access violation\n"); break;
            case 1: printf("[!] Violation Type: Write access violation\n"); break;
            case 8: printf("[!] Violation Type: Execute access violation\n"); break;
            default: printf("[!] Unknown violation type: %lu\n", violationType); break;
        }

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery(faultAddress, &mbi, sizeof(mbi))) {
            printf("[!] Base address: %p\n", mbi.BaseAddress);
            printf("[!] Size of memory region: %zu bytes\n", mbi.RegionSize);

            DWORD newProtection;
            // Adjust memory protection based on the type of access violation
            if (violationType == 8) { // Execute access violation
                newProtection = PAGE_EXECUTE_READ;
                printf("[*] Changing memory protection to PAGE_EXECUTE_READ.\n");
            } else if (violationType == 1) { // Write access violation
                newProtection = PAGE_READWRITE;
                printf("[*] Changing memory protection to PAGE_READWRITE.\n");
            } else {
                return EXCEPTION_CONTINUE_SEARCH; // If neither, continue searching
            }

            // Restore the new permissions
            if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, newProtection, &oldProtection)) {
                printf("[+] Memory protection changed successfully.\n");

                // Create a thread to revert memory protection after a delay
                revertThreadHandle = CreateThread(NULL, 0, RevertMemoryProtection, mbi.BaseAddress, 0, NULL);
                if (revertThreadHandle == NULL) {
                    printf("[!] Failed to create revert thread.\n");
                }

                return EXCEPTION_CONTINUE_EXECUTION;  // Continue execution after restoring
            } else {
                printf("[!] Error changing memory protection.\n");
            }
        }
    }

    return EXCEPTION_CONTINUE_SEARCH;  // Pass to the next handler if not handled
}