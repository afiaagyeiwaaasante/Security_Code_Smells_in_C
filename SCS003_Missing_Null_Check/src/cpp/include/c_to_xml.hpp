/*
 * c_to_xml.hpp — Declaration for c_to_xml()
 * -------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 */

#ifndef C_TO_XML_HPP_
#define C_TO_XML_HPP_

#include <string>

std::string c_to_xml(const std::string& c_file);

#endif
