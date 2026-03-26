/*
 * Step3annotate.cpp — Implementation of Step 3 XML annotation
 * -------------------------------------------------------------
 * SCS003: Missing Null Check (CWE-476) — binary_if scenario
 *
 * Takes a confirmed sink from Step 2 and annotates the srcML XML
 * by adding a sec:smell attribute to the sink if_stmt element.
 *
 * Annotation format:
 *   <if_stmt xmlns:sec="security.smells"
 *            sec:smell="CWE476-null-pointer-dereference-binary-if-high"
 *            pos:start="25:9">
 *       ...
 *   </if_stmt>
 */

#include "../include/Step3annotate.hpp"
#include <iostream>
#include <fstream>
#include <cstring>
#include <sys/stat.h>
#include <libgen.h>
#include <libxml/xmlsave.h>

static const xmlChar* NS_SRC = BAD_CAST "http://www.srcML.org/srcML/src";
static const xmlChar* NS_POS = BAD_CAST "http://www.srcML.org/srcML/position";
static const xmlChar* NS_CPP = BAD_CAST "http://www.srcML.org/srcML/cpp";


static xmlNodePtr find_if_stmt(xmlDocPtr doc, const std::string& use_line) {
    xmlXPathContextPtr ctx = xmlXPathNewContext(doc);
    xmlXPathRegisterNs(ctx, BAD_CAST "src", NS_SRC);
    xmlXPathRegisterNs(ctx, BAD_CAST "pos", NS_POS);
    xmlXPathRegisterNs(ctx, BAD_CAST "cpp", NS_CPP);

    std::string expr = "//src:if_stmt[@pos:start[starts-with(.,'" + use_line + ":')]]";
    xmlXPathObjectPtr result = xmlXPathEvalExpression(BAD_CAST expr.c_str(), ctx);

    xmlNodePtr node = nullptr;
    if (result && result->nodesetval && result->nodesetval->nodeNr > 0)
        node = result->nodesetval->nodeTab[0];

    xmlXPathFreeObject(result);
    xmlXPathFreeContext(ctx);
    return node;
}


void annotate(xmlDocPtr doc,
              const std::string& use_line,
              const std::string& output_file) {
    xmlNodePtr node = find_if_stmt(doc, use_line);

    if (!node) {
        std::cout << "  Could not find node to annotate at line " << use_line << "\n";
        return;
    }

    xmlNsPtr sec_ns = xmlNewNs(node, BAD_CAST SEC_NS.c_str(), BAD_CAST "sec");
    xmlSetNsProp(node, sec_ns, BAD_CAST "smell", BAD_CAST SEC_ATTR_VALUE.c_str());

    std::string dir = output_file.substr(0, output_file.rfind('/'));
    if (!dir.empty()) mkdir(dir.c_str(), 0755);

    xmlSaveFormatFileEnc(output_file.c_str(), doc, "UTF-8", 1);

    std::cout << "\n  Annotated XML saved to: " << output_file << "\n";
}


void save_sink_element(xmlDocPtr doc,
                       const std::string& use_line,
                       const std::string& results_dir,
                       const std::string& json_file) {
    xmlNodePtr node = find_if_stmt(doc, use_line);

    if (!node) {
        std::cout << "  Could not find sink element at line " << use_line << "\n";
        return;
    }

    xmlBufferPtr buf = xmlBufferCreate();
    xmlNodeDump(buf, doc, node, 0, 1);

    mkdir(results_dir.c_str(), 0755);

    char* tmp = strdup(json_file.c_str());
    std::string base_name = basename(tmp);
    free(tmp);

    size_t pos = base_name.rfind(".json");
    if (pos != std::string::npos)
        base_name.replace(pos, 5, "_sink_element.xml");

    std::string result_file = results_dir + "/" + base_name;

    std::ofstream out(result_file);
    out << reinterpret_cast<const char*>(xmlBufferContent(buf));
    out.close();

    xmlBufferFree(buf);

    std::cout << "  Sink element saved to: " << result_file << "\n";
}
