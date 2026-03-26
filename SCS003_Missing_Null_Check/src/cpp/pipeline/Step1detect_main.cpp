/*
 * Step1detect_main.cpp — Entry point for Step 1 detection
 * ---------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Usage:
 *     ./Step1detect <slice.json>
 *
 * Example:
 *     ./Step1detect ../../data/SliceFile/CWE476_NULL_Pointer_Dereference__binary_if_01.json
 *
 * Compile:
 *     g++ -o Step1detect Step1detect_main.cpp Step1detect.cpp
 */

#include "../include/Step1detect.hpp"
#include <iostream>
#include <fstream>
#include <sys/stat.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./Step1detect <slice.json>\n";
        return 1;
    }

    std::string json_file = argv[1];

    struct stat st;
    if (stat(json_file.c_str(), &st) != 0) {
        std::cerr << "Error: File not found: " << json_file << "\n";
        return 1;
    }

    std::ifstream f(json_file);
    json slice_profile = json::parse(f);

    std::vector<Finding> findings = detect(slice_profile);
    print_report(findings, json_file);

    return 0;
}
