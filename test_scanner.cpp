#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <set>
#include <filesystem>
#include <cstdlib>
#include <stdexcept>

namespace fs = std::filesystem;

const std::vector<uint8_t> ELF_MAGIC = {0x7F, 'E', 'L', 'F'};
const std::vector<uint8_t> SIGNATURE = {'c', 'r', 'y', 'p', 't', 'y'};

void write_binary_file(const std::string& path, const std::vector<uint8_t>& content) {
    std::ofstream out(path, std::ios::binary);
    if (!out) throw std::runtime_error("Cannot create file: " + path);
    out.write(reinterpret_cast<const char*>(content.data()), content.size());
}

std::vector<uint8_t> make_clean_elf() {
    std::vector<uint8_t> data = ELF_MAGIC;
    data.resize(512, 0);
    return data;
}

std::vector<uint8_t> make_infected_elf() {
    std::vector<uint8_t> data = ELF_MAGIC;
    data.insert(data.end(), 200, 0);
    data.insert(data.end(), SIGNATURE.begin(), SIGNATURE.end());
    data.insert(data.end(), 300, 0);
    return data;
}

std::vector<uint8_t> make_elf_with_signature_at_start() {
    std::vector<uint8_t> data = ELF_MAGIC;
    data.insert(data.end(), SIGNATURE.begin(), SIGNATURE.end());
    data.resize(512, 0);
    return data;
}

std::vector<uint8_t> make_elf_with_signature_at_end() {
    std::vector<uint8_t> data = ELF_MAGIC;
    data.resize(512 - SIGNATURE.size());
    data.insert(data.end(), SIGNATURE.begin(), SIGNATURE.end());
    return data;
}

std::vector<uint8_t> make_elf_with_cross_boundary_signature(size_t buffer_size) {
    std::vector<uint8_t> data = ELF_MAGIC;
    data.resize(buffer_size - 2, 'A');  // fill up just before buffer end
    data.insert(data.end(), SIGNATURE.begin(), SIGNATURE.end());
    data.resize(buffer_size * 2, 'B');  // some padding after
    return data;
}

std::vector<uint8_t> make_elf_with_partial_signature() {
    std::vector<uint8_t> data = ELF_MAGIC;
    data.insert(data.end(), {'c', 'r', 'y'});
    data.resize(512, 0);
    return data;
}

std::vector<uint8_t> make_non_elf() {
    return std::vector<uint8_t>{'N', 'O', 'T', '_', 'E', 'L', 'F', '\n'};
}

void build_test_tree(const std::string& base_dir, size_t buffer_size) {
    fs::create_directories(base_dir + "/clean");
    fs::create_directories(base_dir + "/infected");
    fs::create_directories(base_dir + "/falsepositive");
    fs::create_directories(base_dir + "/mixed");
    fs::create_directories(base_dir + "/edgecases");

    write_binary_file(base_dir + "/clean/clean1", make_clean_elf());
    write_binary_file(base_dir + "/infected/inf1", make_infected_elf());
    write_binary_file(base_dir + "/infected/inf2", make_elf_with_signature_at_end());
    write_binary_file(base_dir + "/infected/inf3", make_elf_with_signature_at_start());
    write_binary_file(base_dir + "/infected/inf4", make_elf_with_cross_boundary_signature(buffer_size));
    
    write_binary_file(base_dir + "/falsepositive/partial", make_elf_with_partial_signature());
    write_binary_file(base_dir + "/falsepositive/text.txt", make_non_elf());

    write_binary_file(base_dir + "/edgecases/empty", {});
    write_binary_file(base_dir + "/edgecases/not_elf_sig.txt", SIGNATURE);

    fs::create_directory_symlink(base_dir + "/clean/clean1", base_dir + "/edgecases/symlink");

    // Write the signature file
    write_binary_file(base_dir + "/sig.sig", SIGNATURE);
}

// ------------------ Main Test Logic ------------------
int main() {
    std::string base_dir = "C:/Users/TESTUSER/OneDrive/Documents/aqua/project/test";
    std::string output_file = base_dir + "/scanner_output.txt";
    size_t test_buffer_size = 4096;

    build_test_tree(base_dir, test_buffer_size);
    std::string sig_file = base_dir + "/sig.sig";

    std::string cmd = "./elf_virus_detector " + base_dir + " " + sig_file + " > " + output_file;
    int result = std::system(cmd.c_str());

    if (result != 0) {
        std::cerr << "Scanner exited with error code: " << result << "\n";
        return 1;
    }

    std::ifstream in(output_file);
    if (!in) {
        std::cerr << "Could not open scanner output file.\n";
        return 1;
    }

    std::set<std::string> reported_files;
    std::string line;
    while (std::getline(in, line)) {
        if (line.find("is infected!") != std::string::npos) {
            size_t start = line.find("File ");
            if (start != std::string::npos) {
                reported_files.insert(line.substr(start + 5));
            }
        }
    }

    std::set<std::string> expected_infected = {
        base_dir + "/infected/inf1",
        base_dir + "/infected/inf2",
        base_dir + "/infected/inf3",
        base_dir + "/infected/inf4",
    };

    std::cout << "=== Test Results ===\n";
    bool all_ok = true;

    for (const auto& file : expected_infected) {
        if (reported_files.count(file)) {
            std::cout << "[OK] Detected: " << file << "\n";
        } else {
            std::cout << "[FAIL] Missed: " << file << "\n";
            all_ok = false;
        }
    }

    for (const auto& file : reported_files) {
        if (expected_infected.count(file) == 0) {
            std::cout << "[FAIL] False Positive: " << file << "\n";
            all_ok = false;
        }
    }

    if (all_ok) {
        std::cout << "\n✅ All tests passed.\n";
        std::cin.get();
        return 0;
    } else {
        std::cout << "\n❌ Some tests failed.\n";
        return 1;
    }
}
