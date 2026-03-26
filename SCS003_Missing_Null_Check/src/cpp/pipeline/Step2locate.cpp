/*
 * Step2locate.cpp — Implementation of Step 2 XPath sink locator
 * ---------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if and char scenarios
 *
 * Takes findings from Step 1 and runs XPath queries on the srcML
 * XML file to confirm the exact sink location.
 *
 * binary_if:
 *   Check 1: if_stmt exists at use line
 *   Check 2: operator '&' exists (not '&&')
 *   Check 3: operator '->' exists (pointer dereference)
 *
 * char:
 *   Check 1: expr_stmt exists at use line
 *   Check 2: array access variable[0] confirmed
 *   Check 3: NO null guard (if variable != NULL) before access
 */

#include "../include/Step2locate.hpp"
#include <iostream>
#include <fstream>
#include <sys/stat.h>
#include <cstring>
#include <libgen.h>

static const xmlChar* NS_SRC = BAD_CAST "http://www.srcML.org/srcML/src";
static const xmlChar* NS_POS = BAD_CAST "http://www.srcML.org/srcML/position";
static const xmlChar* NS_CPP = BAD_CAST "http://www.srcML.org/srcML/cpp";


std::string extract_line(const std::string& location) {
    size_t last        = location.rfind(':');
    if (last == std::string::npos) return location;
    size_t second_last = location.rfind(':', last - 1);
    if (second_last == std::string::npos) return location;
    return location.substr(second_last + 1, last - second_last - 1);
}

static xmlXPathContextPtr make_xpath_ctx(xmlDocPtr doc) {
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    xmlXPathRegisterNs(ctx, BAD_CAST "src", NS_SRC);
    xmlXPathRegisterNs(ctx, BAD_CAST "pos", NS_POS);
    xmlXPathRegisterNs(ctx, BAD_CAST "cpp", NS_CPP);
    return ctx;
}

static int xpath_count(xmlDocPtr doc, const std::string& expr) {
    xmlXPathContextPtr ctx    = make_xpath_ctx(doc);
    xmlXPathObjectPtr  result = xmlXPathEvalExpression(BAD_CAST expr.c_str(), ctx);

    int count = 0;
    if (result && result->nodesetval)
        count = result->nodesetval->nodeNr;

    xmlXPathFreeObject(result);
    xmlXPathFreeContext(ctx);
    return count;
}


SinkResult locate(xmlDocPtr doc, const json& finding, const std::string& scenario) {
    if (scenario == "binary_if")  return locate_binary_if(doc, finding);
    else if (scenario == "char")  return locate_char(doc, finding);
    else {
        std::cerr << "  [ERROR] Unknown scenario: " << scenario << "\n";
        SinkResult empty{};
        empty.confirmed = false;
        return empty;
    }
}


SinkResult locate_binary_if(xmlDocPtr doc, const json& finding) {
    std::string variable = finding.value("variable", "");
    std::string function = finding.value("function", "");
    std::vector<std::string> used_at = finding.value("used_at", std::vector<std::string>{});

    SinkResult sink{};
    sink.variable          = variable;
    sink.function          = function;
    sink.scenario          = "binary_if";
    sink.cwe               = "CWE-476";
    sink.found_if_stmt     = false;
    sink.found_bitwise_and = false;
    sink.found_dereference = false;
    sink.confirmed         = false;

    if (used_at.empty()) return sink;

    std::string first_use = used_at[0];
    std::string use_line  = extract_line(first_use);
    sink.use_line = use_line;

    std::cout << "\n  Processing  : " << variable << " in " << function << "\n";
    std::cout << "  " << std::string(40, '-') << "\n";
    std::cout << "  Use location: " << first_use << "\n";
    std::cout << "  Line number : " << use_line  << "\n\n";

    std::string xpath1 = "//src:if_stmt[@pos:start[starts-with(.,'" + use_line + ":')]]";
    sink.found_if_stmt = xpath_count(doc, xpath1) > 0;

    if (sink.found_if_stmt)
        std::cout << "  [PASS] if_stmt found at line " << use_line << "\n";
    else {
        std::cout << "  [FAIL] No if_stmt found at line " << use_line << "\n";
        return sink;
    }

    sink.found_bitwise_and = xpath_count(doc, xpath1 + "//src:operator[.='&']") > 0;
    std::cout << "  " << (sink.found_bitwise_and ? "[PASS]" : "[FAIL]") << " Bitwise '&' operator\n";

    sink.found_dereference = xpath_count(doc, xpath1 + "//src:operator[.='->']") > 0;
    std::cout << "  " << (sink.found_dereference ? "[PASS]" : "[FAIL]") << " Pointer dereference '->'\n";

    sink.confirmed = sink.found_if_stmt && sink.found_bitwise_and && sink.found_dereference;
    return sink;
}


SinkResult locate_char(xmlDocPtr doc, const json& finding) {
    std::string variable = finding.value("variable", "");
    std::string function = finding.value("function", "");
    std::vector<std::string> used_at = finding.value("used_at", std::vector<std::string>{});

    SinkResult sink{};
    sink.variable            = variable;
    sink.function            = function;
    sink.scenario            = "char";
    sink.cwe                 = "CWE-476";
    sink.found_expr_stmt     = false;
    sink.found_array_access  = false;
    sink.found_no_null_guard = false;
    sink.confirmed           = false;

    if (used_at.empty()) return sink;

    std::string first_use = used_at[0];
    std::string use_line  = extract_line(first_use);
    sink.use_line = use_line;

    std::cout << "\n  [char] " << variable << " in " << function << "\n";
    std::cout << "  " << std::string(40, '-') << "\n";
    std::cout << "  Use location : " << first_use << "\n";
    std::cout << "  Line number  : " << use_line  << "\n\n";

    std::string xpath1 = "//src:expr_stmt[@pos:start[starts-with(.,'" + use_line + ":')]]";
    sink.found_expr_stmt = xpath_count(doc, xpath1) > 0;

    if (sink.found_expr_stmt)
        std::cout << "  [PASS] expr_stmt found at line " << use_line << "\n";
    else {
        std::cout << "  [FAIL] No expr_stmt found at line " << use_line << "\n";
        return sink;
    }

    sink.found_array_access = xpath_count(doc,
        xpath1 + "//src:name[following-sibling::src:index][.='" + variable + "']") > 0;
    std::cout << "  " << (sink.found_array_access ? "[PASS]" : "[FAIL]") << " Array access " << variable << "[0]\n";

    sink.found_no_null_guard = xpath_count(doc,
        "//src:if_stmt//src:name[.='" + variable + "'][following-sibling::src:operator[.='!=']]") == 0;
    std::cout << "  " << (sink.found_no_null_guard ? "[PASS]" : "[FAIL]") << " No null guard\n";

    sink.confirmed = sink.found_expr_stmt && sink.found_array_access && sink.found_no_null_guard;
    return sink;
}


void print_report(const std::vector<SinkResult>& sink_results) {
    int confirmed = 0;
    for (const auto& s : sink_results)
        if (s.confirmed) confirmed++;

    std::cout << "\n" << std::string(60, '=') << "\n";
    std::cout << "  CWE-476 SINK LOCATION REPORT\n";
    std::cout << std::string(60, '=') << "\n";
    std::cout << "  Sinks confirmed: " << confirmed << " / " << sink_results.size() << "\n";
    std::cout << std::string(60, '=') << "\n";

    int i = 1;
    for (const auto& s : sink_results) {
        std::cout << "\n  [" << i++ << "] Variable : " << s.variable << "\n";
        std::cout << "      Function : " << s.function << "\n";
        std::cout << "      Scenario : " << s.scenario << "\n";
        std::cout << "      Use line : " << s.use_line << "\n";
        std::cout << "      CWE      : " << s.cwe      << "\n";
        std::cout << "\n      XPath Checks:\n";

        if (s.scenario == "binary_if") {
            std::cout << "        " << (s.found_if_stmt     ? "[PASS]" : "[FAIL]") << "  if_stmt at line " << s.use_line << "\n";
            std::cout << "        " << (s.found_bitwise_and ? "[PASS]" : "[FAIL]") << "  operator '&'\n";
            std::cout << "        " << (s.found_dereference ? "[PASS]" : "[FAIL]") << "  '->' dereference\n";
        } else if (s.scenario == "char") {
            std::cout << "        " << (s.found_expr_stmt     ? "[PASS]" : "[FAIL]") << "  expr_stmt at line " << s.use_line << "\n";
            std::cout << "        " << (s.found_array_access  ? "[PASS]" : "[FAIL]") << "  array access " << s.variable << "[0]\n";
            std::cout << "        " << (s.found_no_null_guard ? "[PASS]" : "[FAIL]") << "  no null guard\n";
        }

        std::cout << "\n      " << (s.confirmed ? "SINK CONFIRMED" : "NOT confirmed") << "\n";
    }

    std::cout << "\n" << std::string(60, '=') << "\n\n";
}


void save_report(const std::vector<SinkResult>& sink_results,
                 const std::string& json_file,
                 const std::string& reports_dir) {
    mkdir(reports_dir.c_str(), 0755);

    char* tmp = strdup(json_file.c_str());
    std::string base_name = basename(tmp);
    free(tmp);
    size_t pos = base_name.rfind(".json");
    if (pos != std::string::npos)
        base_name.replace(pos, 5, "_sink_report.json");
    std::string report_file = reports_dir + "/" + base_name;

    int confirmed = 0;
    for (const auto& s : sink_results)
        if (s.confirmed) confirmed++;

    json report;
    report["cwe"]         = "CWE-476";
    report["smell"]       = "null-pointer-dereference";
    report["source_file"] = json_file;
    report["total_sinks"] = sink_results.size();
    report["confirmed"]   = confirmed;
    report["results"]     = json::array();

    for (const auto& s : sink_results) {
        json entry;
        entry["variable"]       = s.variable;
        entry["function"]       = s.function;
        entry["scenario"]       = s.scenario;
        entry["cwe"]            = s.cwe;
        entry["use_line"]       = s.use_line;
        entry["sink_confirmed"] = s.confirmed;

        json checks;
        if (s.scenario == "binary_if") {
            checks["found_if_stmt"]     = s.found_if_stmt;
            checks["found_bitwise_and"] = s.found_bitwise_and;
            checks["found_dereference"] = s.found_dereference;
        } else if (s.scenario == "char") {
            checks["found_expr_stmt"]     = s.found_expr_stmt;
            checks["found_array_access"]  = s.found_array_access;
            checks["found_no_null_guard"] = s.found_no_null_guard;
        }
        entry["xpath_checks"] = checks;
        report["results"].push_back(entry);
    }

    std::ofstream out(report_file);
    out << report.dump(4);
    out.close();

    std::cout << "  Sink report saved to: " << report_file << "\n";
}
