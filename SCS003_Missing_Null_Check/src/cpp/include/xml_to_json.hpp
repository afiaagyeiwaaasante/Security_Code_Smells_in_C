/*
 * xml_to_json.hpp — Declaration for xml_to_json()
 * --------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 */

#ifndef XML_TO_JSON_HPP_
#define XML_TO_JSON_HPP_

#include <string>

std::string xml_to_json(const std::string& xml_file);

#endif
