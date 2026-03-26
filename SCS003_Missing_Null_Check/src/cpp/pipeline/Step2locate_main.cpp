/*
 * Step2locate_main.cpp — Entry point for Step 2 XPath sink locator
 * ------------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if and char scenarios
 *
 * Usage:
 *     ./Step2locate <srcml.xml> <findings.json> [scenario]
 *
 * Example:
 *     ./Step2locate ../../data/XMLFile/CWE476_NULL_Pointer_Dereference__binary_if_01.xml \
 *                   ../../data/SliceFile/CWE476_NULL_Pointer_Dereference__binary_if_01_findings.json \
 *                   binary_if
 *
 * Compile:
 *     g++ -o Step2locate Step2locate_main.cpp Step2locate.cpp -lxml2
 */

#include "../include/Step2locate.hpp"
#include <iostream>
#include <fstream>
#include <sys/stat.h>

const std::string REPORTS_DIR = "../../reports/SCS003_Missing_Null_Check";


int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "Usage: ./Step2locate <srcml.xml> <findings.json> [scenario]\n";
        return 1;
    }

    std::string xml_file      = argv[1];
    std::string findings_file = argv[2];
    std::string scenario      = (argc > 3) ? argv[3] : "binary_if";

    struct stat st;
    if (stat(xml_file.c_str(), &st) != 0) {
        std::cerr << "Error: File not found: " << xml_file << "\n";
        return 1;
    }
    if (stat(findings_file.c_str(), &st) != 0) {
        std::cerr << "Error: File not found: " << findings_file << "\n";
        return 1;
    }

    std::ifstream fin(findings_file);
    json findings = json::parse(fin);

    xmlInitParser();
    xmlDocPtr doc = xmlReadFile(xml_file.c_str(), nullptr, 0);
    if (!doc) {
        std::cerr << "Error: Failed to parse XML: " << xml_file << "\n";
        return 1;
    }

    std::vector<SinkResult> sink_results;
    for (const auto& finding : findings) {
        SinkResult sink = locate(doc, finding, scenario);
        sink_results.push_back(sink);
    }

    print_report(sink_results);
    save_report(sink_results, findings_file, REPORTS_DIR);

    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}
