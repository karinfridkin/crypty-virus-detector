/*
 * "crypty" Virus Detector 
 * ----------------------------------------------
 * Author: Karin Fridkin
 *
 * Purpose:
 * This program scans all regular files under a given root directory,
 * identifies ELF files by checking the ELF magic number, and then searches
 * within these binaries for a virus byte signature ("crypty").
 * It uses buffered search and multithreading to handle large numbers of files efficiently.
 *
 *   What it does:
 * - Walks the entire directory tree 
 * - Loads the signature file fully into RAM (must be reasonably small)
 * - Identifies ELF binaries based on the first 4 bytes (0x7F 'E' 'L' 'F')
 * - Scans files using a sliding buffer window to catch cross-boundary matches
 * - Uses a thread pool for parallelism (one thread per core)
 * - Reports infected files, and handles errors per file without crashing
 *
 * Assumptions:
 * - Input signature file can be read fully into memory.
 * - Only ELF files (identified by the first 4 bytes: 0x7F 'E' 'L' 'F') can be infected.
 * - The environment supports C++17 (or later) for <filesystem> and threading facilities.
 *
 * Compilation:
 *    g++ -std=c++17 -pthread -O2 -o find_sig.exe find_sig.cpp
 */

#include <iostream>
#include <iomanip>
#include <fstream>
#include <vector>
#include <string>
#include <filesystem>
#include <algorithm>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <functional>
#include <atomic>
#include <future>

namespace fs = std::filesystem;

constexpr size_t MIN_BUFFER_SIZE = 4096;
constexpr size_t EXTRA_BUFFER = 1024;

// ------------------------- Thread Pool -------------------------
class ThreadPool {
public:
    explicit ThreadPool(size_t threadCount);
    ~ThreadPool();
    void submit(std::function<void()> task);

private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queueMutex;
    std::condition_variable condition;
    std::atomic<bool> stop;

    void workerThread();
};

ThreadPool::ThreadPool(size_t threadCount) : stop(false) {
    for (size_t i = 0; i < threadCount; ++i) {
        workers.emplace_back([this]() { workerThread(); });
    }
}

ThreadPool::~ThreadPool() {
    stop = true;
    condition.notify_all();
    for (auto& t : workers)
        if (t.joinable()) t.join();
}

void ThreadPool::submit(std::function<void()> task) {
    {
        std::lock_guard<std::mutex> lock(queueMutex);
        tasks.push(std::move(task));
    }
    condition.notify_one();
}

void ThreadPool::workerThread() {
    while (true) {
        std::function<void()> task;

        {
            std::unique_lock<std::mutex> lock(queueMutex);
            condition.wait(lock, [this]() {
                return stop || !tasks.empty();
            });

            if (stop && tasks.empty()) return;

            task = std::move(tasks.front());
            tasks.pop();
        }

        try {
            task();
        } catch (...) {
            // Optional: handle uncaught exceptions here
        }
    }
}

// ------------------------- Helpers -------------------------

bool isELFFile(const fs::path& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;

    char header[4];
    file.read(header, 4);
    if (file.gcount() < 4) return false;

    return (header[0] == 0x7F && header[1] == 'E' &&
            header[2] == 'L' && header[3] == 'F');
}

// Load signature into RAM
std::vector<uint8_t> load_signature(const std::string& path) {
    if (!fs::is_regular_file(path))
        throw std::runtime_error("Signature path is not a regular file.");

    std::ifstream file(path, std::ios::binary);
    if (!file) throw std::runtime_error("Cannot open signature file: " + path);

    return std::vector<uint8_t>((std::istreambuf_iterator<char>(file)), {});
}

// Buffered read with sliding window
bool containsSignatureBuffered(const fs::path& path, const std::vector<uint8_t>& signature) {
    if (signature.empty()) return false;

    const size_t OVERLAP = signature.size() - 1;
    std::ifstream file(path, std::ios::binary);
    if (!file) return false;

    //buffer size should be bigger then signature
    size_t buffer_size = std::max(MIN_BUFFER_SIZE, signature.size() + EXTRA_BUFFER);

    std::vector<uint8_t> buffer(buffer_size + OVERLAP);
    size_t bytesRead = 0;

    while (file) {
        if (bytesRead >= OVERLAP) {
            std::copy(buffer.end() - OVERLAP, buffer.end(), buffer.begin());
        } else if (bytesRead > 0) {
            std::copy(buffer.begin() + bytesRead - OVERLAP, buffer.begin() + bytesRead, buffer.begin());
        }

        file.read(reinterpret_cast<char*>(buffer.data() + OVERLAP), buffer_size);
        bytesRead = static_cast<size_t>(file.gcount());
        size_t totalBytes = bytesRead + OVERLAP;

        auto it = std::search(buffer.begin(), buffer.begin() + totalBytes,
                              signature.begin(), signature.end());

        if (it != buffer.begin() + totalBytes) {
            return true;
        }

        if (bytesRead < buffer_size) break;
    }

    return false;
}

// ------------------------- Main -------------------------

int main(int argc, char* argv[]) {
    if (argc != 3) {
        std::cerr << "Usage: " << argv[0] << " <root_directory> <signature_file>\n";
        return 1;
    }

    std::string root_dir = argv[1];
    std::string sig_file = argv[2];
    std::vector<uint8_t> signature;

    try {
        signature = load_signature(sig_file);
        if (signature.empty())
            throw std::runtime_error("Signature file is empty.");
    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
        return 1;
    }

    std::cout << "Scanning started...\n\n";

    std::vector<fs::path> files;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(root_dir)) {
            if (fs::is_regular_file(entry.path()))
                files.push_back(entry.path());
        }
    } catch (const std::exception& e) {
        std::cerr << "Error traversing directory: " << e.what() << "\n";
        return 1;
    }

    std::mutex output_mutex;
    ThreadPool pool(std::thread::hardware_concurrency());

    for (const auto& path : files) {
        pool.submit([&, path]() {
            try {
                if (!isELFFile(path)) return;

                if (containsSignatureBuffered(path, signature)) {
                    std::lock_guard<std::mutex> lock(output_mutex);
                    std::cout << "!!! File " << path << " is infected!\n";
                }

            } catch (const std::exception& e) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cerr << "Error scanning " << path << ": " << e.what() << "\n";
            }
        });
    }

    // Destructor of ThreadPool will wait for all threads
    std::cout << "\nScan completed.\n";
    std::cin.get();
    return 0;
}
