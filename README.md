# 🛡️ crypty-virus-detector

A multithreaded C++ tool that scans files to search the "crypty" virus signature.

---

## ✅ Prerequisites

- C++17-compatible compiler (e.g., `g++`)

---

## 🧪 1. Compile and Run the Test File

```bash
g++ -std=c++17 -pthread -O2 -o test_scanner.exe test_scanner.cpp
./test_scanner.exe
## 🔍 2. Compile and Run the Main Scanner
```bash
g++ -std=c++17 -pthread -O2 -o find_sig.exe find_sig.cpp

## 🧵 How It Works
  Loads the entire virus signature into memory.
  
  Recursively traverses the given directory.
  
  Identifies ELF binaries via magic number: 0x7F 'E' 'L' 'F'.
  
  Scans each ELF file using a buffered, sliding-window search.
  
  Spawns one scanning thread per CPU core using a custom thread pool.

## ⚠️ Assumptions
  Only ELF binaries can be infected (based on first 4 bytes).
  
  The virus signature must appear exactly as-is in the file.
  
  Signature must fit in memory.

##👩‍💻 Author
Karin Fridkin
