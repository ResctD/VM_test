#!/usr/bin/env python3
"""
author: Leha
"""

import argparse
import xml.etree.ElementTree as ET
import json


NAMESPACES = {
    'def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
    'red': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#linux',
}


def collect_test_refs(criteria_elem):
    """Рекурсивно собирает все test_ref из дерева критериев."""
    refs = []
    for child in criteria_elem:
        if child.tag == f"{{{NAMESPACES['def']}}}criteria":
            refs.extend(collect_test_refs(child))
        elif child.tag == f"{{{NAMESPACES['def']}}}criterion":
            refs.append(child.get('test_ref'))
    return refs


def main():
    parser = argparse.ArgumentParser(description='OVAL XML to minimal JSON converter')
    parser.add_argument('input_file', help='Path to RHEL8 OVAL XML file')
    parser.add_argument('-o', '--output', help='Output JSON file (stdout if not set)')
    args = parser.parse_args()

    tree = ET.parse(args.input_file)
    root = tree.getroot()

    # Индексация
    tests = {}
    objects = {}
    states = {}

    for test in root.findall('.//red:rpminfo_test', NAMESPACES):
        tests[test.get('id')] = test

    for obj in root.findall('.//red:rpminfo_object', NAMESPACES):
        objects[obj.get('id')] = obj

    for state in root.findall('.//red:rpminfo_state', NAMESPACES):
        states[state.get('id')] = state

    ns_def = 'http://oval.mitre.org/XMLSchema/oval-definitions-5'
    all_defs = root.findall(f'.//{{{ns_def}}}definition')
    patches = [d for d in all_defs if d.get('class') == 'patch']

    result = []

    for definition in patches[:5]:  # первые 5 патчей
        metadata = definition.find('def:metadata', NAMESPACES)
        if metadata is None:
            continue

        title = metadata.findtext('def:title', '', NAMESPACES)
        severity = metadata.findtext('.//def:severity', '', NAMESPACES)

        # CVE
        cve = ''
        cve_elem = metadata.find('.//def:cve', NAMESPACES)
        if cve_elem is not None and cve_elem.text:
            cve = cve_elem.text.strip()
        if not cve:
            ref_elem = metadata.find('def:reference[@source="CVE"]', NAMESPACES)
            if ref_elem is not None:
                cve = ref_elem.get('ref_id', '')

        # Платформы
        platforms = []
        affected = metadata.find('def:affected', NAMESPACES)
        if affected is not None:
            for plat in affected.findall('def:platform', NAMESPACES):
                if plat.text:
                    platforms.append(plat.text.strip())

        criteria = definition.find('def:criteria', NAMESPACES)
        if criteria is None:
            continue

        test_refs = collect_test_refs(criteria)

        packages = []
        seen = set()
        for ref in test_refs:
            test = tests.get(ref)
            if test is None:
                continue

            object_ref = test.find('red:object', NAMESPACES)
            state_ref = test.find('red:state', NAMESPACES)
            if object_ref is None or state_ref is None:
                continue

            obj_id = object_ref.get('object_ref')
            state_id = state_ref.get('state_ref')
            obj = objects.get(obj_id)
            state = states.get(state_id)
            if obj is None or state is None:
                continue

            pkg_name = obj.findtext('red:name', '', NAMESPACES)
            if not pkg_name:
                continue

            # тесты подписи
            if state.find('red:signature_keyid', NAMESPACES) is not None:
                continue

            version_elem = state.find('red:version', NAMESPACES)
            if version_elem is None:
                version_elem = state.find('red:evr', NAMESPACES)
                if version_elem is None:
                    continue

            operator = version_elem.get('operation', '')
            fixed_version = version_elem.text.strip() if version_elem.text else ''
            if not fixed_version:
                continue

            if operator == 'less than':
                comparison = 'less_than'
            elif operator == 'less than or equal':
                comparison = 'less_than_or_equal'
            else:
                comparison = operator

            key = (pkg_name, fixed_version, comparison)
            if key not in seen:
                seen.add(key)
                packages.append({
                    "name": pkg_name,
                    "fixed_version": fixed_version,
                    "comparison": comparison
                })

        if not packages:
            continue

        result.append({
            "id": definition.get('id'),
            "severity": severity,
            "title": title,
            "cve": cve,
            "platforms": platforms,
            "packages": packages
        })

    # Вывод JSON
    json_output = json.dumps(result, indent=2, ensure_ascii=False)

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(json_output)
            f.write('\n')
    else:
        print(json_output)


if __name__ == '__main__':
    main()