/*
 * xml_to_json_main.cpp — Entry point for xml_to_json
 * -----------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Usage:
 *     ./xml_to_json <input.xml>
 *
 * Example:
 *     ./xml_to_json ../../data/XMLFile/CWE476_NULL_Pointer_Dereference__binary_if_01.xml
 *
 * Compile:
 *     g++ -o xml_to_json xml_to_json_main.cpp xml_to_json.cpp
 */

#include "../include/xml_to_json.hpp"
#include <iostream>
#include <sys/stat.h>

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: ./xml_to_json <input.xml>\n";
        return 1;
    }

    std::string xml_file = argv[1];

    struct stat st;
    if (stat(xml_file.c_str(), &st) != 0) {
        std::cerr << "Error: File not found: " << xml_file << "\n";
        return 1;
    }

    xml_to_json(xml_file);
    return 0;
}
