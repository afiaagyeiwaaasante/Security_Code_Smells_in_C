/*
 * Step3annotate.hpp — Declaration for Step 3 XML annotation
 * -----------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 */

#ifndef STEP3ANNOTATE_HPP_
#define STEP3ANNOTATE_HPP_

#include <string>
#include <libxml/parser.h>
#include <libxml/xpath.h>
#include <libxml/xpathInternals.h>
#include <libxml/tree.h>

const std::string SEC_NS         = "security.smells";
const std::string SEC_ATTR_VALUE = "CWE476-null-pointer-dereference-binary-if-high";


void annotate(xmlDocPtr doc,
              const std::string& use_line,
              const std::string& output_file);

void save_sink_element(xmlDocPtr doc,
                       const std::string& use_line,
                       const std::string& results_dir,
                       const std::string& json_file);

#endif
