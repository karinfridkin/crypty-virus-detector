// ======== Crypty Virus Detector Test Suite ========
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <set>
#include <map>
#include <filesystem>
#include <cstdlib>
#include <stdexcept>
#include <algorithm> 

namespace fs = std::filesystem;

const std::vector<uint8_t> ELF_MAGIC = {0x7F, 'E', 'L', 'F'};
const std::vector<uint8_t> SIGNATURE = {'c', 'r', 'y', 'p', 't', 'y'};

constexpr size_t BUFFER_SIZE = 4096;

// Utility
void write_binary_file(const fs::path& path, const std::vector<uint8_t>& content) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot create file: " + path.string());
    out.write(reinterpret_cast<const char*>(content.data()), content.size());
}

std::vector<uint8_t> make_elf_with(const std::vector<uint8_t>& content, size_t padding = 0) {
    std::vector<uint8_t> data = ELF_MAGIC;
    data.insert(data.end(), padding, 0);
    data.insert(data.end(), content.begin(), content.end());
    return data;
}

// Test generators
std::map<std::string, std::vector<uint8_t>> generate_test_cases() {
    return {
        {"clean", make_elf_with({}, 512)},
        {"infected_middle", make_elf_with(SIGNATURE, 200)},
        {"infected_start", make_elf_with(SIGNATURE, 0)},
        {"infected_end", make_elf_with(SIGNATURE, 512 - SIGNATURE.size())},
        {"infected_cross_boundary", [] {
            std::vector<uint8_t> data = ELF_MAGIC;
            data.resize(BUFFER_SIZE - 3, 'A');
            data.insert(data.end(), SIGNATURE.begin(), SIGNATURE.end());
            data.resize(BUFFER_SIZE * 2, 'B');
            return data;
        }()},
        {"partial_signature", make_elf_with({ 'c', 'r', 'y' }, 200)},
        {"non_elf", std::vector<uint8_t>{'N', 'O', 'T', '_', 'E', 'L', 'F'}},
        {"empty", {}},
        {"huge_file", [] {
            std::vector<uint8_t> data = ELF_MAGIC;
            data.resize(10 * BUFFER_SIZE, 'A');
            size_t inject_pos = 5 * BUFFER_SIZE;
            data.insert(data.begin() + inject_pos, SIGNATURE.begin(), SIGNATURE.end());
            return data;
        }()},
        {"malformed_elf", [] {
            std::vector<uint8_t> data(512, 0);
            data[0] = 0x7E;  // wrong magic byte
            return data;
        }()},
        {"signature_in_non_elf", SIGNATURE}
    };
}

void build_test_tree(const fs::path& base_dir) {
    // fs::remove_all(base_dir);
    fs::create_directories(base_dir / "samples");

    auto tests = generate_test_cases();
    for (const auto& [name, content] : tests) {
        write_binary_file(base_dir / "samples" / name, content);
    }

    // Add symbolic link
    fs::create_symlink(base_dir / "samples" / "clean", base_dir / "samples" / "symlink_to_clean");

    // Write signature file
    write_binary_file(base_dir / "sig.sig", SIGNATURE);
}

// Scanner runner
std::set<std::string> run_detector(const fs::path& scanner, const fs::path& base_dir) {
    const fs::path output_file = base_dir / "scanner_output.txt";
    std::string cmd = scanner.string() + " " + (base_dir / "samples").string() + " " +
                      (base_dir / "sig.sig").string() + " > " + output_file.string();
    int result = std::system(cmd.c_str());
    if (result != 0) throw std::runtime_error("Scanner failed.");

    std::ifstream in(output_file);
    if (!in) throw std::runtime_error("Cannot read scanner output.");

    std::set<std::string> reported;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("is infected!") != std::string::npos) {
            size_t pos = line.find("File ");
            if (pos != std::string::npos) {
                reported.insert(line.substr(pos + 5));
            }
        }
    }
    return reported;
}

// Before you create expected set:
std::set<std::string> normalize_paths(const std::vector<fs::path>& paths) {
    std::set<std::string> normalized;
    for (const auto& p : paths) {
        std::string s = p.string();
        std::replace(s.begin(), s.end(), '\\', '/');
        normalized.insert(s);
    }
    return normalized;
}

void validate_results(const fs::path& base_dir, const std::set<std::string>& reported) {
    std::vector<fs::path> expected_paths = {
        base_dir / "samples" / "infected_middle",
        base_dir / "samples" / "infected_start",
        base_dir / "samples" / "infected_end",
        base_dir / "samples" / "infected_cross_boundary",
        base_dir / "samples" / "huge_file"
    };

    auto expected = normalize_paths(expected_paths);

    std::cout << "=== Test Results ===\n";
    bool passed = true;

    for (const auto& path : expected) {
        if (reported.count(path)) {
            std::cout << "[OK] Detected: " << path << "\n";
        } else {
            std::cout << "[FAIL] Missed: " << path << "\n";
            passed = false;
        }
    }

    for (const auto& path : reported) {
        if (!expected.count(path)) {
            std::cout << "[FAIL] False Positive: " << path << "\n";
            passed = false;
        }
    }

    if (passed) {
        std::cout << "\n✅ All tests passed.\n";
    } else {
        std::cout << "\n❌ Some tests failed.\n";
    }
}




// Entry
int main() {
    fs::path base_dir = "C:/Users/TESTUSER/OneDrive/Documents/aqua/project/tests";
    fs::path scanner = "./find_sig.exe";

    try {
        build_test_tree(base_dir);
        auto reported = run_detector(scanner, base_dir);
        validate_results(base_dir, reported);
    } catch (const std::exception& ex) {
        std::cerr << "Test failed with exception: " << ex.what() << "\n";
        return 1;
    }

    std::cin.get();
    return 0;
}
