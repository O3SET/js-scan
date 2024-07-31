# rules.py

import execjs
import re

# 初始化 esprima
ctx = execjs.compile("""
    var esprima = require('esprima');
    function parse(code) {
        return esprima.parseScript(code, { tolerant: true, loc: true });
    }
""")

# 定义初始规则，规则格式为 (规则名称, 正则表达式, 说明, 漏洞利用方式, 验证函数)
rules = [
    ('eval_usage', r'\beval\(', '使用 eval 函数，这可能导致代码注入漏洞。', '避免使用 eval 函数，使用更安全的替代方法。', lambda code: verify_eval_usage(code)),
    ('innerHTML_usage', r'\binnerHTML\b', '使用 innerHTML，这可能导致 XSS 攻击。', '使用 textContent 或其他安全的方法来操作 DOM。', lambda code: verify_innerHTML_usage(code)),
    ('document_write', r'\bdocument\.write\(', '使用 document.write，这可能导致 XSS 攻击。', '避免使用 document.write，改用更安全的 DOM 操作方法。', lambda code: verify_document_write(code)),
    ('setTimeout_string', r'\bsetTimeout\([^,]+,\s*[\'"]', '向 setTimeout 传递字符串，这可能导致代码注入漏洞。', '使用函数而不是字符串作为参数。', lambda code: verify_setTimeout_string(code)),
    ('setInterval_string', r'\bsetInterval\([^,]+,\s*[\'"]', '向 setInterval 传递字符串，这可能导致代码注入漏洞。', '使用函数而不是字符串作为参数。', lambda code: verify_setInterval_string(code)),
    ('Function_constructor', r'\bnew Function\(', '使用 Function 构造函数，这可能导致代码注入漏洞。', '避免使用 Function 构造函数。', lambda code: verify_Function_constructor(code)),
    ('localStorage_usage', r'\blocalStorage\b', '使用 localStorage，如果数据未正确消毒，可能导致安全问题。', '确保存储到 localStorage 的数据是安全的。', lambda code: verify_localStorage_usage(code)),
    ('sessionStorage_usage', r'\bsessionStorage\b', '使用 sessionStorage，如果数据未正确消毒，可能导致安全问题。', '确保存储到 sessionStorage 的数据是安全的。', lambda code: verify_sessionStorage_usage(code)),
    ('cookie_manipulation', r'\bdocument\.cookie\b', '直接操作 cookie 可能导致安全问题。', '使用安全的库来操作 cookie。', lambda code: verify_cookie_manipulation(code)),
    ('XHR_open', r'\bXMLHttpRequest\.open\(', '不正确处理的 XMLHttpRequest 可能导致安全漏洞。', '确保 XMLHttpRequest 请求是安全的。', lambda code: verify_XHR_open(code)),
    ('fetch_usage', r'\bfetch\(', '不正确处理的 fetch 请求可能导致安全漏洞。', '确保 fetch 请求是安全的。', lambda code: verify_fetch_usage(code)),
    ('jquery_html', r'\$\([^)]*\)\.html\(', '使用 jQuery 的 html() 方法可能导致 XSS 攻击。', '使用安全的方法来插入 HTML。', lambda code: verify_jquery_html(code)),
    ('jquery_append', r'\$\([^)]*\)\.append\(', '使用 jQuery 的 append() 方法可能导致 XSS 攻击。', '使用安全的方法来插入 HTML。', lambda code: verify_jquery_append(code)),
    ('jquery_prepend', r'\$\([^)]*\)\.prepend\(', '使用 jQuery 的 prepend() 方法可能导致 XSS 攻击。', '使用安全的方法来插入 HTML。', lambda code: verify_jquery_prepend(code)),
    ('jquery_after', r'\$\([^)]*\)\.after\(', '使用 jQuery 的 after() 方法可能导致 XSS 攻击。', '使用安全的方法来插入 HTML。', lambda code: verify_jquery_after(code)),
    ('jquery_before', r'\$\([^)]*\)\.before\(', '使用 jQuery 的 before() 方法可能导致 XSS 攻击。', '使用安全的方法来插入 HTML。', lambda code: verify_jquery_before(code)),
    ('info_leakage', r'console\.(log|debug|info|warn|error)\(', '可能存在信息泄露。', '避免在生产环境中使用 console 打印敏感信息。', lambda code: verify_info_leakage(code)),
    ('plain_text_login', r'\bpassword\s*=\s*[\'"][^\'"]*[\'"]', '明文密码登录，存在安全风险。', '避免在代码中硬编码密码，使用安全的凭证管理机制。', lambda code: verify_plain_text_login(code))
]

def get_rules():
    return rules

def add_rule(rule_name, pattern, description, exploitation, verify_func):
    rules.append((rule_name, pattern, description, exploitation, verify_func))

def verify_eval_usage(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'CallExpression':
                callee = node['expression']['callee']
                if callee['type'] == 'Identifier' and callee['name'] == 'eval':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying eval usage: {e}")
        return False

def verify_innerHTML_usage(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'AssignmentExpression':
                left = node['expression']['left']
                if left['type'] == 'MemberExpression' and left['property']['name'] == 'innerHTML':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying innerHTML usage: {e}")
        return False

def verify_document_write(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'CallExpression':
                callee = node['expression']['callee']
                if callee['type'] == 'MemberExpression' and callee['property']['name'] == 'write' and callee['object']['name'] == 'document':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying document.write usage: {e}")
        return False

def verify_setTimeout_string(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'CallExpression':
                callee = node['expression']['callee']
                if callee['type'] == 'Identifier' and callee['name'] == 'setTimeout':
                    arg = node['expression']['arguments'][0]
                    if arg['type'] == 'Literal' and isinstance(arg['value'], str):
                        return True
        return False
    except Exception as e:
        print(f"Error verifying setTimeout string usage: {e}")
        return False

def verify_setInterval_string(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'CallExpression':
                callee = node['expression']['callee']
                if callee['type'] == 'Identifier' and callee['name'] == 'setInterval':
                    arg = node['expression']['arguments'][0]
                    if arg['type'] == 'Literal' and isinstance(arg['value'], str):
                        return True
        return False
    except Exception as e:
        print(f"Error verifying setInterval string usage: {e}")
        return False

def verify_Function_constructor(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'NewExpression':
                callee = node['expression']['callee']
                if callee['type'] == 'Identifier' and callee['name'] == 'Function':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying Function constructor usage: {e}")
        return False

def verify_localStorage_usage(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'MemberExpression':
                if node['expression']['object']['type'] == 'Identifier' and node['expression']['object']['name'] == 'localStorage':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying localStorage usage: {e}")
        return False

def verify_sessionStorage_usage(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'MemberExpression':
                if node['expression']['object']['type'] == 'Identifier' and node['expression']['object']['name'] == 'sessionStorage':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying sessionStorage usage: {e}")
        return False

def verify_cookie_manipulation(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'MemberExpression':
                if node['expression']['object']['type'] == 'Identifier' and node['expression']['object']['name'] == 'document' and node['expression']['property']['name'] == 'cookie':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying cookie manipulation: {e}")
        return False

def verify_XHR_open(code):
    try:
        tree = ctx.call("parse", code)
        for node in tree['body']:
            if node['type'] == 'ExpressionStatement' and node['expression']['type'] == 'CallExpression':
                callee = node['expression']['callee']
                if callee['type'] == 'MemberExpression' and callee['property']['name'] == 'open' and callee['object']['type'] == 'NewExpression' and callee['object']['callee']['name'] == 'XMLHttpRequest':
                    return True
        return False
    except Exception as e:
        print(f"Error verifying XMLHttpRequest open usage: {e}")
        return False

def verify_fetch_usage(code):
    try:
        return bool(re.search(r'\bfetch\(', code))
    except Exception as e:
        print(f"Error verifying fetch usage: {e}")
        return False

def verify_jquery_html(code):
    try:
        return bool(re.search(r'\$\([^)]*\)\.html\(', code))
    except Exception as e:
        print(f"Error verifying jQuery html usage: {e}")
        return False

def verify_jquery_append(code):
    try:
        return bool(re.search(r'\$\([^)]*\)\.append\(', code))
    except Exception as e:
        print(f"Error verifying jQuery append usage: {e}")
        return False

def verify_jquery_prepend(code):
    try:
        return bool(re.search(r'\$\([^)]*\)\.prepend\(', code))
    except Exception as e:
        print(f"Error verifying jQuery prepend usage: {e}")
        return False

def verify_jquery_after(code):
    try:
        return bool(re.search(r'\$\([^)]*\)\.after\(', code))
    except Exception as e:
        print(f"Error verifying jQuery after usage: {e}")
        return False

def verify_jquery_before(code):
    try:
        return bool(re.search(r'\$\([^)]*\)\.before\(', code))
    except Exception as e:
        print(f"Error verifying jQuery before usage: {e}")
        return False

def verify_info_leakage(code):
    try:
        return bool(re.search(r'console\.(log|debug|info|warn|error)\(', code))
    except Exception as e:
        print(f"Error verifying info leakage: {e}")
        return False

def verify_plain_text_login(code):
    try:
        return bool(re.search(r'\bpassword\s*=\s*[\'"][^\'"]*[\'"]', code))
    except Exception as e:
        print(f"Error verifying plain text login: {e}")
        return False
