/*
    author: 
    hasbiyama (@3xploitZero)
    github.com/hasbiyama

*/

#include "helpFunc.h"

// Keyboard Hook Procedure
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *pKeyBoard = (KBDLLHOOKSTRUCT *)lParam;
        int key = pKeyBoard->vkCode;

        DWORD pid = GetCurrentProcessId();
        DWORD tid = GetMainThread(pid);
        HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, tid);

        // Check if the Enter key is pressed
        if (key == VK_RETURN) {
            lastKeyPressed = key; // Store the last pressed key
            SuspendThread(hThread);
            THREAD_SYNC_SLEEP();
            ResumeThread(hThread);
        }
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

// Function to create a keyboard thread
DWORD WINAPI KeyboardThread(LPVOID lpParam) {
    hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (hKeyboardHook == NULL) {
        PRINT_WINAPI_ERR("SetWindowsHookEx");
        return 1;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    UnhookWindowsHookEx(hKeyboardHook);
    return 0;
}