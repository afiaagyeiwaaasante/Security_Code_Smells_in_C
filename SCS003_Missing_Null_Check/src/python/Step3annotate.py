#!/usr/bin/env python3
"""
step3_annotate.py — XML Annotation
-------------------------------------
SCS003: Missing Null Check (CWE-476)

Takes confirmed sinks from Step 2 and annotates the
srcML XML file by adding a sec:smell attribute to the
sink if_stmt element.

Also extracts and saves the sink element to a results file.

Annotation format:
    <if_stmt xmlns:sec="security.smells"
             sec:smell="CWE476-null-pointer-dereference-binary-if-high"
             pos:start="25:9">
        ...
    </if_stmt>

Input:
    tree        -- lxml parsed srcML XML tree
    sink        -- confirmed sink dict from step2_locate
    output_file -- path to write annotated XML

Output:
    annotated XML file
    sink element XML file (in results/)
"""

import os
from lxml import etree
from utils import NAMESPACES

# security smell namespace
SEC_NS         = "security.smells"
SEC_ATTR_VALUE = "CWE476-null-pointer-dereference-binary-if-high"


def annotate(tree, sink: dict, output_file: str):
    """
    Adds sec:smell attribute to the confirmed sink if_stmt node.
    Saves the full annotated XML to output_file.

    Args:
        tree:        lxml etree parsed from srcML XML file
        sink:        confirmed sink dict from step2_locate.locate()
        output_file: path to write annotated XML file
    """
    use_line = sink["use_line"]

    # locate the if_stmt node by its own pos:start attribute
    xpath = (
        f"//src:if_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
    )
    nodes = tree.xpath(xpath, namespaces=NAMESPACES)

    if not nodes:
        print(f"  Could not find node to annotate at line {use_line}")
        return

    # annotate the first matching if_stmt
    node = nodes[0]
    node.set(f"{{{SEC_NS}}}smell", SEC_ATTR_VALUE)

    # ensure output directory exists
    os.makedirs(os.path.dirname(output_file) or ".", exist_ok=True)

    # write full annotated XML
    tree.write(
        output_file,
        pretty_print=True,
        xml_declaration=True,
        encoding="UTF-8"
    )
    print(f"\n  Annotated XML saved to: {output_file}")


def save_sink_element(tree, sink: dict, results_dir: str, json_file: str):
    """
    Extracts the annotated if_stmt element and saves it
    as a standalone XML file in the results directory.

    Args:
        tree:        lxml etree parsed from srcML XML file
        sink:        confirmed sink dict from step2_locate.locate()
        results_dir: directory to save the sink element file
        json_file:   original input JSON path (used for filename)
    """
    use_line = sink["use_line"]

    xpath = (
        f"//src:if_stmt[@pos:start"
        f"[starts-with(.,'{use_line}:')]]"
    )
    nodes = tree.xpath(xpath, namespaces=NAMESPACES)

    if not nodes:
        print(f"  Could not find sink element at line {use_line}")
        return

    node = nodes[0]

    # serialize just the if_stmt element
    sink_xml = etree.tostring(
        node,
        pretty_print=True,
        encoding="unicode"
    )

    # save to results directory
    os.makedirs(results_dir, exist_ok=True)
    base_name   = os.path.basename(json_file).replace(".json", "_sink_element.xml")
    result_file = os.path.join(results_dir, base_name)

    with open(result_file, "w", encoding="utf-8") as f:
        f.write(sink_xml)

    print(f"  Sink element saved to: {result_file}")
    return result_file