/*
 * pipeline.cpp — Implementation of the main detection pipeline
 * -------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476)
 *
 * Orchestrates all three detection steps:
 *
 *   Step 1 — Detection Rules (Step1detect)
 *       Reads srcSlice JSON, applies 4 rules, finds candidates
 *
 *   Step 2 — XPath Sink Location (Step2locate)
 *       Reads srcML XML, confirms sink via XPath checks
 *
 *   Step 3 — XML Annotation (Step3annotate)
 *       Annotates confirmed sinks, saves annotated XML and sink element
 */

#include "../include/pipeline.hpp"
#include "../include/Step1detect.hpp"
#include "../include/Step2locate.hpp"
#include "../include/Step3annotate.hpp"
#include "../include/nlohmann/json.hpp"

#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/stat.h>
#include <libgen.h>

using json = nlohmann::json;

const std::string REPORTS_DIR = "../../reports/SCS003_Missing_Null_Check";
const std::string RESULTS_DIR = "../../results/binary_if";


static json finding_to_json(const Finding& f) {
    return {
        {"variable",   f.variable},
        {"type",       f.type},
        {"function",   f.function},
        {"file",       f.file},
        {"defined_at", f.defined_at},
        {"used_at",    f.used_at},
        {"smell",      f.smell},
        {"cwe",        f.cwe},
        {"severity",   f.severity},
        {"rules_hit", {
            {"rule1_is_pointer",      f.rule1_is_pointer},
            {"rule2_no_null_check",   f.rule2_no_null_check},
            {"rule3_pointer_is_used", f.rule3_pointer_is_used},
            {"rule4_in_known_sink",   f.rule4_in_known_sink}
        }}
    };
}


void run_pipeline(const std::string& json_file,
                  const std::string& xml_file,
                  const std::string& output_file,
                  const std::string& scenario) {

    // ══════════════════════════════════════════
    // STEP 1 — DETECTION RULES
    // ══════════════════════════════════════════
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  STEP 1: Detection Rules\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "\n  Loading slice profile: " << json_file << "\n";

    std::ifstream fin(json_file);
    json slice_profile = json::parse(fin);

    std::vector<Finding> findings = detect(slice_profile);
    print_report(findings, json_file);

    if (findings.empty()) {
        std::cout << "  No findings. Exiting pipeline.\n\n";
        return;
    }

    std::string findings_file = json_file;
    size_t pos = findings_file.rfind(".json");
    if (pos != std::string::npos)
        findings_file.replace(pos, 5, "_findings.json");

    json findings_json = json::array();
    for (const auto& f : findings)
        findings_json.push_back(finding_to_json(f));

    std::ofstream fout(findings_file);
    fout << findings_json.dump(4);
    fout.close();
    std::cout << "\n  Findings saved to: " << findings_file << "\n";

    // ══════════════════════════════════════════
    // STEP 2 — SINK LOCATION (XPath)
    // ══════════════════════════════════════════
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  STEP 2: XPath Sink Location\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "\n  Loading srcML XML: " << xml_file << "\n";

    xmlInitParser();
    xmlDocPtr doc = xmlReadFile(xml_file.c_str(), nullptr, 0);
    if (!doc) {
        std::cerr << "  Error: Failed to parse XML: " << xml_file << "\n";
        return;
    }

    std::vector<SinkResult> sink_results;
    for (const auto& f : findings) {
        json finding_json = finding_to_json(f);
        SinkResult sink = locate(doc, finding_json, scenario);
        sink_results.push_back(sink);
    }

    print_report(sink_results);
    save_report(sink_results, json_file, REPORTS_DIR);

    // ══════════════════════════════════════════
    // STEP 3 — XML ANNOTATION
    // ══════════════════════════════════════════
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  STEP 3: XML Annotation\n";
    std::cout << std::string(60, '=') << "\n";

    for (const auto& sink : sink_results) {
        if (!sink.confirmed) continue;
        annotate(doc, sink.use_line, output_file);
        save_sink_element(doc, sink.use_line, RESULTS_DIR, json_file);
    }

    xmlFreeDoc(doc);
    xmlCleanupParser();

    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  Pipeline complete.\n";
    std::cout << std::string(60, '=') << "\n\n";
}
