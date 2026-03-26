/*
 * pipeline.hpp — Declaration for the main detection pipeline
 * ------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476)
 */

#ifndef PIPELINE_HPP_
#define PIPELINE_HPP_

#include <string>

void run_pipeline(const std::string& json_file,
                  const std::string& xml_file,
                  const std::string& output_file,
                  const std::string& scenario);

#endif
