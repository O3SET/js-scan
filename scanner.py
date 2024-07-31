import os
import re
import json
import xml.etree.ElementTree as ET
from jinja2 import Template
import argparse
import rules
from termcolor import colored


# 打印工具信息
def print_tool_info():
    print(colored("===================================", 'green'))
    print(colored("        JS安全审计工具", 'cyan', attrs=['bold']))
    print(colored("       工具地址: https://github.com/O3SET/js-scan", 'yellow'))
    print(colored("===================================", 'green'))


# 扫描文件并应用规则
def scan_file(file_path):
    vulnerabilities = []
    with open(file_path, 'r', encoding='utf-8') as file:
        content = file.read()
        for rule_name, pattern, description, exploitation, verify_func in rules.get_rules():
            for match in re.finditer(pattern, content):
                verified = verify_func(content)
                if verified:
                    vulnerability = {
                        'file': file_path,
                        'line': content.count('\n', 0, match.start()) + 1,
                        'column': match.start() - content.rfind('\n', 0, match.start()),
                        'rule': rule_name,
                        'description': description,
                        'exploitation': exploitation,
                        'verified': verified
                    }
                    vulnerabilities.append(vulnerability)
    return vulnerabilities


# 扫描目录中的所有 JavaScript 文件
def scan_directory(directory):
    all_vulnerabilities = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith('.js'):
                file_path = os.path.join(root, file)
                vulnerabilities = scan_file(file_path)
                if vulnerabilities:
                    all_vulnerabilities.extend(vulnerabilities)
    return all_vulnerabilities


# 打印漏洞报告
def print_vulnerability_report(vulnerabilities):
    for vulnerability in vulnerabilities:
        print(f"文件: {vulnerability['file']}, 行: {vulnerability['line']}, 列: {vulnerability['column']}")
        print(f"  规则: {vulnerability['rule']}, 描述: {vulnerability['description']}")
        print(f"  漏洞利用方式: {vulnerability['exploitation']}")
        print(f"  已验证: {'是' if vulnerability['verified'] else '否'}")
        print()


# 生成 JSON 报告
def generate_json_report(vulnerabilities, output_file):
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(vulnerabilities, f, ensure_ascii=False, indent=4)


# 生成 XML 报告
def generate_xml_report(vulnerabilities, output_file):
    root = ET.Element("Vulnerabilities")
    for vuln in vulnerabilities:
        item = ET.SubElement(root, "Vulnerability")
        ET.SubElement(item, "File").text = vuln['file']
        ET.SubElement(item, "Line").text = str(vuln['line'])
        ET.SubElement(item, "Column").text = str(vuln['column'])
        ET.SubElement(item, "Rule").text = vuln['rule']
        ET.SubElement(item, "Description").text = vuln['description']
        ET.SubElement(item, "Exploitation").text = vuln['exploitation']
        ET.SubElement(item, "Verified").text = '是' if vuln['verified'] else '否'
    tree = ET.ElementTree(root)
    tree.write(output_file, encoding='utf-8', xml_declaration=True)


# 生成 HTML 报告
def generate_html_report(vulnerabilities, output_file):
    template = Template("""
    <html>
    <head>
        <title>漏洞报告</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            h1 { color: #333; }
            .vuln { margin-bottom: 20px; padding: 10px; border: 1px solid #ccc; border-radius: 5px; }
            .file { font-size: 18px; font-weight: bold; color: #0066cc; }
            .details { margin-left: 20px; }
            .detail { margin-bottom: 10px; }
            .label { font-weight: bold; }
            .verified { color: green; }
            .not-verified { color: red; }
        </style>
    </head>
    <body>
        <h1>漏洞报告</h1>
        {% for vuln in vulnerabilities %}
        <div class="vuln">
            <div class="file">文件: {{ vuln.file }}</div>
            <div class="details">
                <div class="detail"><span class="label">行:</span> {{ vuln.line }}, <span class="label">列:</span> {{ vuln.column }}</div>
                <div class="detail"><span class="label">规则:</span> {{ vuln.rule }}</div>
                <div class="detail"><span class="label">描述:</span> {{ vuln.description }}</div>
                <div class="detail"><span class="label">漏洞利用方式:</span> {{ vuln.exploitation }}</div>
                <div class="detail"><span class="label">已验证:</span> <span class="{{ 'verified' if vuln.verified else 'not-verified' }}">{{ '是' if vuln.verified else '否' }}</span></div>
            </div>
        </div>
        {% endfor %}
    </body>
    </html>
    """)
    html_content = template.render(vulnerabilities=vulnerabilities)
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_content)


# 主函数
if __name__ == "__main__":
    print_tool_info()

    parser = argparse.ArgumentParser(description="JavaScript 漏洞审查工具")
    parser.add_argument('--dir', help="要扫描的目录")
    parser.add_argument('--file', help="要扫描的文件")
    parser.add_argument('--format', choices=['json', 'xml', 'html'], default='json', help="报告格式")
    parser.add_argument('--output', help="报告文件名", required=True)
    args = parser.parse_args()

    if args.dir:
        vulnerabilities = scan_directory(args.dir)
    elif args.file:
        vulnerabilities = scan_file(args.file)
    else:
        print("请指定 --dir 或 --file 参数")
        exit(1)

    if args.format == 'json':
        generate_json_report(vulnerabilities, args.output)
    elif args.format == 'xml':
        generate_xml_report(vulnerabilities, args.output)
    elif args.format == 'html':
        generate_html_report(vulnerabilities, args.output)

    print("扫描完成。报告已生成。")
