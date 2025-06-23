




#include <windows.h>
#include <stdio.h>

// Define a type for the hook procedure
typedef LRESULT(CALLBACK* HOOKPROC)(int, WPARAM, LPARAM);

// Globals for hook management
static HMODULE dllHandle = NULL;
static HHOOK procHandle = NULL;

// Hook procedure to be used for DLL injection
LRESULT CALLBACK MouseProc(int nCode, WPARAM wParam, LPARAM lParam) {
    // Hook procedure can be empty or perform additional actions
    // For this example, we'll keep it minimal
    return CallNextHookEx(procHandle, nCode, wParam, lParam);
}

// Function to inject DLL into a process using SetWindowsHookEx
BOOL InjectDLLIntoProcess(const char *dllPath) {
    // Load the DLL into the current process's address space
    dllHandle = LoadLibraryA(dllPath);
    if (dllHandle == NULL) {
        printf("Failed to load DLL. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Get the address of the hook procedure
    HOOKPROC procPointer = (HOOKPROC)GetProcAddress(dllHandle, "MouseProc");
    if (procPointer == NULL) {
        printf("Failed to get hook procedure address. Error: %lu\n", GetLastError());
        FreeLibrary(dllHandle);
        return FALSE;
    }

    // Set the hook for the target process
    procHandle = SetWindowsHookExA(WH_MOUSE, procPointer, dllHandle, 0);
    if (procHandle == NULL) {
        printf("Failed to set hook. Error: %lu\n", GetLastError());
        FreeLibrary(dllHandle);
        return FALSE;
    }

    printf("DLL injected successfully.\n");

    // Unhook the hook procedure and free the DLL
    UnhookWindowsHookEx(procHandle);
    FreeLibrary(dllHandle);

    return TRUE;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: injector.exe <path_to_dll>\n");
        return 1;
    }

    // Attempt to inject DLL into the current process
    if (InjectDLLIntoProcess(argv[1])) {
        printf("Successfully injected the DLL using SetWindowsHookEx.\n");
    } else {
        printf("DLL injection failed.\n");
    }

    return 0;
}
