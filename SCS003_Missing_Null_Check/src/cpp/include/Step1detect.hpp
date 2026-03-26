/*
 * Step1detect.hpp — Declaration for Step 1 detection functions
 * --------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 */

#ifndef STEP1DETECT_HPP_
#define STEP1DETECT_HPP_

#include <string>
#include <vector>
#include "nlohmann/json.hpp"

using json = nlohmann::json;


struct Finding {
    std::string              variable;
    std::string              type;
    std::string              function;
    std::string              file;
    std::vector<std::string> defined_at;
    std::vector<std::string> used_at;
    std::string              smell;
    std::string              cwe;
    std::string              severity;

    // rules
    bool rule1_is_pointer;
    bool rule2_no_null_check;
    bool rule3_pointer_is_used;
    bool rule4_in_known_sink;
};


std::vector<Finding> detect(const json& slice_profile);
void print_report(const std::vector<Finding>& findings, const std::string& json_file);

#endif
