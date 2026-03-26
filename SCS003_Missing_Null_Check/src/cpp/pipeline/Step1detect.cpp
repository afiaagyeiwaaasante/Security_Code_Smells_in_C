/*
 * Step1detect.cpp — Implementation of Step 1 detection rules
 * ------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Reads a srcSlice JSON profile and applies 4 detection rules
 * to identify candidate pointer variables:
 *
 *   Rule 1: type contains "*"      -> is a pointer
 *   Rule 2: dependence == []       -> no null check
 *   Rule 3: use list not empty     -> pointer is used
 *   Rule 4: function in KNOWN_SINKS -> vulnerable context
 */

#include "../include/Step1detect.hpp"
#include <iostream>
#include <algorithm>

const std::vector<std::string> KNOWN_SINKS = {
    "_bad", "bad", "deref", "use_ptr", "access"
};


std::vector<Finding> detect(const json& slice_profile) {
    std::vector<Finding> findings;

    for (auto& [key, variable] : slice_profile.items()) {

        std::string name       = variable.value("name",     "");
        std::string var_type   = variable.value("type",     "");
        std::string function   = variable.value("function", "");
        std::string filename   = variable.value("file",     "");

        std::vector<std::string> dependence = variable.value("dependence", std::vector<std::string>{});
        std::vector<std::string> use        = variable.value("use",        std::vector<std::string>{});
        std::vector<std::string> definition = variable.value("definition", std::vector<std::string>{});

        bool rule1 = var_type.find('*') != std::string::npos;
        bool rule2 = dependence.empty();
        bool rule3 = !use.empty();

        std::string func_lower = function;
        std::transform(func_lower.begin(), func_lower.end(), func_lower.begin(), ::tolower);

        bool rule4 = false;
        for (const auto& sink : KNOWN_SINKS) {
            if (func_lower.find(sink) != std::string::npos) {
                rule4 = true;
                break;
            }
        }

        if (rule1 && rule2 && rule3 && rule4) {
            Finding f;
            f.variable              = name;
            f.type                  = var_type;
            f.function              = function;
            f.file                  = filename;
            f.defined_at            = definition;
            f.used_at               = use;
            f.smell                 = "null-pointer-dereference";
            f.cwe                   = "CWE-476";
            f.severity              = "HIGH";
            f.rule1_is_pointer      = rule1;
            f.rule2_no_null_check   = rule2;
            f.rule3_pointer_is_used = rule3;
            f.rule4_in_known_sink   = rule4;
            findings.push_back(f);
        }
    }

    return findings;
}


void print_report(const std::vector<Finding>& findings, const std::string& json_file) {
    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  CWE-476 DETECTION REPORT\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "  Input file : " << json_file       << "\n";
    std::cout << "  Findings   : " << findings.size() << "\n";
    std::cout << std::string(60, '=') << "\n";

    if (findings.empty()) {
        std::cout << "\n  No null pointer dereference smell detected.\n\n";
        return;
    }

    int i = 1;
    for (const auto& f : findings) {
        std::cout << "\n  [" << i++ << "] SMELL DETECTED\n";
        std::cout << "  " << std::string(40, '-') << "\n";
        std::cout << "  Variable  : " << f.variable << "\n";
        std::cout << "  Type      : " << f.type     << "\n";
        std::cout << "  Function  : " << f.function << "\n";
        std::cout << "  File      : " << f.file     << "\n";

        std::cout << "  Defined at: ";
        for (size_t j = 0; j < f.defined_at.size(); ++j)
            std::cout << (j ? ", " : "") << f.defined_at[j];
        std::cout << "\n";

        std::cout << "  Used at   : ";
        for (size_t j = 0; j < f.used_at.size(); ++j)
            std::cout << (j ? ", " : "") << f.used_at[j];
        std::cout << "\n";

        std::cout << "  CWE       : " << f.cwe      << "\n";
        std::cout << "  Severity  : " << f.severity << "\n";

        std::cout << "\n  Detection Rules:\n";
        std::cout << "    " << (f.rule1_is_pointer      ? "[PASS]" : "[FAIL]") << "  rule1_is_pointer\n";
        std::cout << "    " << (f.rule2_no_null_check   ? "[PASS]" : "[FAIL]") << "  rule2_no_null_check\n";
        std::cout << "    " << (f.rule3_pointer_is_used ? "[PASS]" : "[FAIL]") << "  rule3_pointer_is_used\n";
        std::cout << "    " << (f.rule4_in_known_sink   ? "[PASS]" : "[FAIL]") << "  rule4_in_known_sink\n";
    }
}
