/*
 * c_to_xml_main.cpp — Entry point for c_to_xml
 * ----------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Usage:
 *     ./c_to_xml <input.c>
 *
 * Example:
 *     ./c_to_xml ../../testsuites/CWE476/binary_if/CWE476_NULL_Pointer_Dereference__binary_if_01.c
 *
 * Compile:
 *     g++ -o c_to_xml c_to_xml_main.cpp c_to_xml.cpp
 */

#include "../include/c_to_xml.hpp"
#include <iostream>
#include <sys/stat.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./c_to_xml <input.c>\n";
        return 1;
    }

    std::string c_file = argv[1];

    struct stat st;
    if (stat(c_file.c_str(), &st) != 0) {
        std::cerr << "Error: File not found: " << c_file << "\n";
        return 1;
    }

    c_to_xml(c_file);
    return 0;
}
