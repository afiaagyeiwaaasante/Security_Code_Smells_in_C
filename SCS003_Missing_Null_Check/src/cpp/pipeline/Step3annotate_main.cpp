/*
 * Step3annotate_main.cpp — Entry point for Step 3 XML annotation
 * ----------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Usage:
 *     ./Step3annotate <srcml.xml> <sink_report.json> <output.xml>
 *
 * Example:
 *     ./Step3annotate \
 *         ../../data/XMLFile/CWE476_NULL_Pointer_Dereference__binary_if_01.xml \
 *         ../../reports/SCS003_Missing_Null_Check/<sink_report>.json \
 *         ../../data/AttributeFile/CWE476_NULL_Pointer_Dereference__binary_if_01_annotated.xml
 *
 * Compile:
 *     g++ -o Step3annotate Step3annotate_main.cpp Step3annotate.cpp -lxml2
 */

#include "../include/Step3annotate.hpp"
#include "../include/nlohmann/json.hpp"
#include <iostream>
#include <fstream>
#include <sys/stat.h>

using json = nlohmann::json;

const std::string RESULTS_DIR = "../../results/binary_if";


int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: ./Step3annotate <srcml.xml> <sink_report.json> <output.xml>\n";
        return 1;
    }

    std::string xml_file    = argv[1];
    std::string report_file = argv[2];
    std::string output_file = argv[3];

    struct stat st;
    if (stat(xml_file.c_str(), &st) != 0) {
        std::cerr << "Error: File not found: " << xml_file << "\n";
        return 1;
    }
    if (stat(report_file.c_str(), &st) != 0) {
        std::cerr << "Error: File not found: " << report_file << "\n";
        return 1;
    }

    std::ifstream fin(report_file);
    json report = json::parse(fin);

    xmlInitParser();
    xmlDocPtr doc = xmlReadFile(xml_file.c_str(), nullptr, 0);
    if (!doc) {
        std::cerr << "Error: Failed to parse XML: " << xml_file << "\n";
        return 1;
    }

    for (const auto& result : report["results"]) {
        if (!result.value("sink_confirmed", false)) continue;
        std::string use_line = result.value("use_line", "");
        annotate(doc, use_line, output_file);
        save_sink_element(doc, use_line, RESULTS_DIR, report_file);
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();
    return 0;
}
