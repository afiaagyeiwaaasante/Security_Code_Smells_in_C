/*
 * pipeline_main.cpp — Entry point for the main detection pipeline
 * ----------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476)
 *
 * Usage:
 *     ./pipeline <slice.json> <srcml.xml> <output.xml> [scenario]
 *
 * Example:
 *     ./pipeline \
 *         ../../data/SliceFile/CWE476_NULL_Pointer_Dereference__binary_if_01.json \
 *         ../../data/XMLFile/CWE476_NULL_Pointer_Dereference__binary_if_01.xml \
 *         ../../data/AttributeFile/CWE476_NULL_Pointer_Dereference__binary_if_01_annotated.xml \
 *         binary_if
 *
 * Scenarios: binary_if, char
 *
 * Output files:
 *     ../../data/AttributeFile/*_annotated.xml
 *     ../../results/binary_if/*_sink_element.xml
 *     ../../reports/SCS003_Missing_Null_Check/*_sink_report.json
 *     ../../data/SliceFile/*_findings.json
 *
 * Compile:
 *     g++ -o pipeline pipeline_main.cpp pipeline.cpp \
 *         Step1detect.cpp Step2locate.cpp Step3annotate.cpp -lxml2
 */

#include "../include/pipeline.hpp"
#include <iostream>
#include <sys/stat.h>

int main(int argc, char* argv[]) {
    if (argc < 4) {
        std::cerr << "Usage  : ./pipeline <slice.json> <srcml.xml> <output.xml> [scenario]\n";
        std::cerr << "\nScenarios: binary_if, char\n";
        return 1;
    }

    std::string json_file   = argv[1];
    std::string xml_file    = argv[2];
    std::string output_file = argv[3];
    std::string scenario    = (argc > 4) ? argv[4] : "binary_if";

    struct stat st;
    for (const auto& f : {json_file, xml_file}) {
        if (stat(f.c_str(), &st) != 0) {
            std::cerr << "  Error: File not found: " << f << "\n";
            return 1;
        }
    }

    run_pipeline(json_file, xml_file, output_file, scenario);
    return 0;
}
