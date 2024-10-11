/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "keyHook.h"

void ModifyStackFrame(HANDLE hThread, DWORD pid) {
    CONTEXT context = {0};
    context.ContextFlags = CONTEXT_FULL;

    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL || !GetThreadContext(hThread, &context)) {
        if (hProcess) CloseHandle(hProcess);
        return;
    }

    STACKFRAME64 stackFrame = {};
    stackFrame.AddrPC.Offset = context.Rip;
    stackFrame.AddrFrame.Offset = context.Rbp;
    stackFrame.AddrStack.Offset = context.Rsp;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Mode = AddrModeFlat;

    /*
        in this case, 
        SymInitialize allows the creation of 
        a new thread for the while() loop, 
        which then communicates with the KeyboardThread
    */

    if (!SymInitialize(hProcess, NULL, TRUE)) {
        CloseHandle(hProcess);
        return;
    }

    STACKFRAME64 validFrames[16];
    int validFrameCount = 0;

    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, hProcess, hThread, &stackFrame, &context, NULL,
                       SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        if (stackFrame.AddrPC.Offset == 0) break;

        DWORD64 moduleBase = SymGetModuleBase64(hProcess, stackFrame.AddrPC.Offset);
        if (moduleBase == 0) {
            if (validFrameCount > 0) {
                // Copy the latest valid frame for potential spoofing
                STACKFRAME64 spoofedFrame = validFrames[validFrameCount];
                LPVOID targetAddress = (LPVOID)(context.Rsp);
                SIZE_T bytesWritten;

                // Write the spoofed frame to the target process
                if (WriteProcessMemory(hProcess, targetAddress, &spoofedFrame, sizeof(spoofedFrame), &bytesWritten)) {
                    context.Rsp += sizeof(STACKFRAME64); // Adjust stack pointer

                    // Read the original frame and offer to revert if desired
                    STACKFRAME64 originalFrame;
                    if (ReadProcessMemory(hProcess, (LPVOID)(stackFrame.AddrStack.Offset - sizeof(STACKFRAME64)), 
                                          &originalFrame, sizeof(originalFrame), NULL)) {
                        WriteProcessMemory(hProcess, (LPVOID)(stackFrame.AddrStack.Offset - sizeof(STACKFRAME64)), 
                                           &spoofedFrame, sizeof(spoofedFrame), &bytesWritten);

                        /*
                            below is done to prevent/delay 
                            multiple execution of the while() loop 
                            if the Enter key is pressed immediately.
                        */
                        SLEEP_1_SECOND();

                        // Continuously check for Enter key press
                        while (TRUE) {
                            if (lastKeyPressed == VK_RETURN) {
                                // MessageBox(NULL, "Enter key pressed!", "Key Detected", MB_OK | MB_ICONINFORMATION);
                                WriteProcessMemory(hProcess, 
                                                   (LPVOID)(stackFrame.AddrStack.Offset - sizeof(STACKFRAME64)), 
                                                   &originalFrame, sizeof(originalFrame), &bytesWritten);
                                SLEEP_1_SECOND();
                                lastKeyPressed = -1;  // Reset the key state so we can detect the next press
                            }
                            THREAD_SYNC_SLEEP(); // Small delay to prevent CPU overuse
                            WriteProcessMemory(hProcess, (LPVOID)(stackFrame.AddrStack.Offset - sizeof(STACKFRAME64)), 
                                           &spoofedFrame, sizeof(spoofedFrame), &bytesWritten);

                            /* 

                            SymCleanup here is very important:
                            - it frees all resources associated with the process handle
                            - without it, the private bytes will bloat

                            */
                            SymCleanup(hProcess);                    
                        }
                    }
                }
            }
        } else if (validFrameCount < 16) {
            validFrames[validFrameCount++] = stackFrame; // Store valid frame
        }
    }

    // Cleanup
    SymCleanup(hProcess);
    CloseHandle(hProcess);
}