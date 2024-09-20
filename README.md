# Rootkit Development Project

This project is a foundational exploration into the development of a cohesive rootkit that involves various techniques such as data concealment, detour patching, and IAT hooking. It is currently under development, and contributions or collaborations are welcome to enhance its capabilities.

The project structure is as follows:

```
Rootkit/
│
├── include/               # Header files
│   ├── data_concealment.h
│   ├── detour_patching.h
│   ├── iat_hooking.h
│   ├── memory_resident_rootkit.h
│
├── src/                   # Source code files
│   ├── cohesive_rootkit.c
│   ├── data_concealment.c
│   ├── detour_patching.c
│   ├── iat_hooking.c
│   ├── memory_resident_rootkit.c
│
├── docs/                  # Documentation files
│   ├── architecture.md
│   ├── cohesive_rootkit.md
│   ├── self_healing.md
│   ├── techniques_overview.md
│
├── tests/                 # Unit tests for core functionalities
│   ├── test_data_concealment.c
│   ├── test_detour_patching.c
│   ├── test_iat_hooking.c
│   ├── test_memory_resident.c
│
└── README.md              # This file
```

---

## Overview

This rootkit project is a comprehensive attempt to implement various kernel-level techniques for stealth and system manipulation. The core file `cohesive_rootkit.c` will eventually integrate multiple techniques:

- **Data Concealment (`data_concealment.c`)**: Research and development of techniques to hide data on the system.
- **Detour Patching (`detour_patching.c`)**: Foundation for manipulating control flow in system processes.
- **IAT Hooking (`iat_hooking.c`)**: Interception of function calls at the Import Address Table level.
- **Memory Resident Rootkit (`memory_resident_rootkit.c`)**: Keeps the rootkit resident in memory, allowing continuous operation without leaving traces on disk.

All the above components are research efforts and foundational building blocks for the complete `cohesive_rootkit.c` file, which will combine these techniques into a fully functional rootkit.

---

## Installation

To set up the development environment for this project, you will need the following dependencies:

1. **Windows SDK**: Download and install the [Windows SDK](https://developer.microsoft.com/en-us/windows/downloads/windows-sdk/) to access various system-level libraries and tools needed for kernel-mode programming and debugging.
   
2. **MinGW**: Install MinGW, a minimalist GNU for Windows, to provide a robust compilation environment for the C code in this project. You can install it from [here](http://www.mingw.org/).

3. **Other tools**: If you're working on a Windows platform, additional tools like **Sysinternals** for analyzing and monitoring system calls may also be helpful.

### Steps:

1. Clone the repository:
   ```bash
   git clone https://github.com/Coll76/Rootkit.git
   ```

2. Set up MinGW and add it to your system's PATH.

3. Compile the `memory_resident_rootkit.c` file using the following command:

   ```bash
   gcc -o memory_resident_rootkit.exe memory_resident_rootkit.c -lkernel32 -luser32 -lpsapi
   ```

   This command links the necessary libraries:
   - **kernel32**: For Windows kernel interactions.
   - **user32**: For Windows user interface components.
   - **psapi**: For interacting with process information.

4. Run the compiled executable:
   ```bash
   ./memory_resident_rootkit.exe
   ```

5. As the project progresses, additional `.c` files such as `data_concealment.c`, `detour_patching.c`, and `iat_hooking.c` will be compiled and linked similarly to integrate their functionalities into the cohesive rootkit.

---

## Project Components

### 1. **Cohesive Rootkit (`cohesive_rootkit.c`)**
This is the main file that will integrate the techniques from `data_concealment.c`, `detour_patching.c`, and `iat_hooking.c`. The goal is to create a memory-resident rootkit that incorporates these tactics in a stealthy and effective manner.

### 2. **Data Concealment (`data_concealment.c`)**
This module focuses on methods to hide files, processes, or registry entries from the operating system. It will serve as a key component for ensuring stealth.

### 3. **Detour Patching (`detour_patching.c`)**
This module provides the foundation for detouring or hijacking function calls. It will allow for interception and manipulation of system calls or user-mode function calls.

### 4. **IAT Hooking (`iat_hooking.c`)**
The Import Address Table Hooking file will be the foundation for intercepting Windows API calls by modifying entries in the IAT of loaded executables.

### 5. **Memory Resident Rootkit (`memory_resident_rootkit.c`)**
This is a proof of concept for making the rootkit persist in memory, avoiding disk writes that could be detected by security software.

---

## Documentation

For detailed information on the techniques used and architectural considerations, refer to the documentation files in the `docs/` directory:

- **architecture.md**: Overview of the rootkit's architectural design.
- **cohesive_rootkit.md**: Explanation of the components of the cohesive rootkit.
- **self_healing.md**: Techniques and mechanisms for ensuring rootkit persistence even after attempts at removal.
- **techniques_overview.md**: Overview of the various attack and stealth techniques used.

---

## Testing

Unit tests for each module are provided in the `tests/` directory. These files (`test_data_concealment.c`, `test_detour_patching.c`, etc.) are designed to test the functionality and effectiveness of each component in isolation.

---

## Contributing

We welcome contributions from the community! If you're interested in collaborating, feel free to fork this repository, make your changes, and open a pull request. Whether it's bug fixes, optimization, or extending the functionality, all contributions are welcome.

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
