/*
 * xml_to_json.cpp — Implementation of xml_to_json()
 * ----------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Converts a srcML XML file to a srcSlice JSON profile using:
 *     srcslice -i <input.xml> -o <output.json>
 *
 * Output:
 *     ../../data/SliceFile/<filename>.json
 */

#include "../include/xml_to_json.hpp"
#include <iostream>
#include <cstdlib>
#include <sys/stat.h>
#include <libgen.h>
#include <cstring>

const std::string SLICE_DIR = "../../data/SliceFile";


static void make_dir(const std::string& path) {
    mkdir(path.c_str(), 0755);
}

static std::string basename_of(const std::string& path) {
    char* tmp = strdup(path.c_str());
    std::string base = basename(tmp);
    free(tmp);
    return base;
}


std::string xml_to_json(const std::string& xml_file) {
    make_dir(SLICE_DIR);

    std::string base_name = basename_of(xml_file);
    base_name.replace(base_name.find(".xml"), 4, ".json");
    std::string slice_file = SLICE_DIR + "/" + base_name;

    std::string cmd = "srcslice -i " + xml_file + " -o " + slice_file;

    std::cout << "Input  : " << xml_file   << "\n";
    std::cout << "Output : " << slice_file << "\n";

    int ret = std::system(cmd.c_str());

    if (ret != 0) {
        std::cerr << "Error  : srcslice failed (exit code " << ret << ")\n";
        std::exit(1);
    }

    std::cout << "Done.\n";
    return slice_file;
}
