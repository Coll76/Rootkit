# Rootkit Development Project

## Project Overview

This project is a rootkit development framework, focusing on implementing and researching various techniques such as data concealment, detour patching, IAT (Import Address Table) hooking, and memory resident operations. The ultimate goal is to develop a **cohesive rootkit** that utilizes these foundations to achieve advanced functionality.

While the project is still in development, this repository serves as a collaborative platform where others are encouraged to contribute, provide insights, and participate in the research and development process.

## Project Structure

- **src/**
  - `cohesive_rootkit.c`: This file serves as the core of the rootkit and integrates the techniques developed in the other files. It will consolidate data concealment, detour patching, IAT hooking, and memory-resident functionalities into a single cohesive rootkit.
  - `data_concealment.c`: Research and foundation for techniques related to concealing data in memory and file systems. These techniques will later be integrated into the cohesive rootkit.
  - `detour_patching.c`: Explores detour patching mechanisms to alter program flow dynamically. This is a foundational block for the cohesive rootkit.
  - `iat_hooking.c`: Investigates Import Address Table (IAT) hooking techniques. The research here will be used to enhance the cohesive rootkit.
  - `memory_resident_rootkit.c`: Implements a basic memory-resident rootkit, showcasing how rootkits can persist in memory without detection.

- **include/**
  - Header files for each respective `.c` file, providing function prototypes and shared data structures.

- **tests/**
  - Unit tests for each feature under development to ensure stability and correctness as the rootkit evolves:
    - `test_data_concealment.c`
    - `test_detour_patching.c`
    - `test_iat_hooking.c`
    - `test_memory_resident.c`

- **docs/**
  - Documentation and technical write-ups detailing the approaches, methodologies, and research:
    - `architecture.md`: Explains the architecture and design of the rootkit.
    - `cohesive_rootkit.md`: Detailed notes on how the cohesive rootkit integrates various techniques.
    - `self_healing.md`: A document dedicated to research into self-healing mechanisms, allowing the rootkit to evade detection or restore compromised components.
    - `techniques_overview.md`: General overview of the different techniques explored in this project.

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

3. Use the following commands to compile the project:

   ```bash
   gcc -o cohesive_rootkit src/cohesive_rootkit.c src/data_concealment.c src/detour_patching.c src/iat_hooking.c src/memory_resident_rootkit.c -Iinclude
   ```

4. Run tests to validate individual components:

   ```bash
   gcc -o test_data_concealment tests/test_data_concealment.c -Iinclude
   ./test_data_concealment
   ```

## Contributing

This project is in its early stages and is primarily research-based. Contributions in the form of code, research, or suggestions are welcome! Please follow these guidelines for contributions:

1. Fork the repository and create your branch from `main`.
2. Ensure any new code is covered with unit tests where applicable.
3. Document any new features or modifications in the `docs/` folder.
4. Submit a pull request, and ensure you provide enough information in the description for reviewers.

## Roadmap

- **Research & Development Phase**:  
  - Continue building foundational modules such as data concealment, detour patching, IAT hooking, and memory-resident functionalities.
  - Integrate these techniques into a cohesive rootkit.
  
- **Testing and Stability**:  
  - Build out comprehensive unit tests for each feature.
  - Test on various Windows versions and architectures.

- **Self-Healing Mechanism**:  
  - Develop mechanisms to allow the rootkit to repair itself if detected or disabled.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.


