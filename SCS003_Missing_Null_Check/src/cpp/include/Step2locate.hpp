/*
 * Step2locate.hpp — Declaration for Step 2 XPath sink locator
 * -------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if and char scenarios
 */

#ifndef STEP2LOCATE_HPP_
#define STEP2LOCATE_HPP_

#include <string>
#include <vector>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include "nlohmann/json.hpp"

using json = nlohmann::json;


struct SinkResult {
    std::string variable;
    std::string function;
    std::string scenario;
    std::string cwe;
    std::string use_line;

    // binary_if checks
    bool found_if_stmt;
    bool found_bitwise_and;
    bool found_dereference;

    // char checks
    bool found_expr_stmt;
    bool found_array_access;
    bool found_no_null_guard;

    bool confirmed;
};


std::string extract_line(const std::string& location);

SinkResult locate(xmlDocPtr doc, const json& finding, const std::string& scenario = "binary_if");
SinkResult locate_binary_if(xmlDocPtr doc, const json& finding);
SinkResult locate_char(xmlDocPtr doc, const json& finding);

void print_report(const std::vector<SinkResult>& sink_results);
void save_report(const std::vector<SinkResult>& sink_results,
                 const std::string& json_file,
                 const std::string& reports_dir);

#endif
