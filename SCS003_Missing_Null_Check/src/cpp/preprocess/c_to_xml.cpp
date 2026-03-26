/*
 * c_to_xml.cpp — Implementation of c_to_xml()
 * ---------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Converts a C source file to srcML XML using:
 *     srcml --position --hash <input.c> -o <output.xml>
 *
 * Output:
 *     ../data/XMLFile/<filename>.xml
 */

#include "../include/c_to_xml.hpp"
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>
#include <libgen.h>
#include <cstring>

const std::string XML_DIR = "../../data/XMLFile";


static void make_dir(const std::string& path) {
    mkdir(path.c_str(), 0755);
}

static std::string basename_of(const std::string& path) {
    char* tmp = strdup(path.c_str());
    std::string base = basename(tmp);
    free(tmp);
    return base;
}


std::string c_to_xml(const std::string& c_file) {
    make_dir(XML_DIR);

    std::string base_name = basename_of(c_file);
    base_name.replace(base_name.find(".c"), 2, ".xml");
    std::string xml_file = XML_DIR + "/" + base_name;

    std::string cmd = "srcml --position --hash " + c_file + " -o " + xml_file;

    std::cout << "Input  : " << c_file   << "\n";
    std::cout << "Output : " << xml_file << "\n";

    int ret = std::system(cmd.c_str());

    if (ret != 0) {
        std::cerr << "Error  : srcml failed (exit code " << ret << ")\n";
        std::exit(1);
    }

    std::cout << "Done.\n";
    return xml_file;
}
