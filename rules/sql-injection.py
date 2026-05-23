# SQL Injection Risk - Python check script
# Uses structured ScriptContext — no string parsing needed!
#
# Key fields on each param:
#   param.isExternalInput  → bool, 是否有外部输入
#   param.isHardcoded      → bool, 是否有硬编码
#   param.isTainted        → bool, 是否受污染 (= isExternalInput)
#   param.composite        → "direct"|"concat"|"method_return"|"field"|"unknown"
#   param.parts[]          → 每个组成部分
#     part.kind            → "hardcoded"|"external_input"|"method_return"|"field"|"variable"|"unknown"
#     part.value           → 硬编码的值 (kind=hardcoded)
#     part.source          → "method_parameter"|... (kind=external_input)
#     part.name            → 变量/参数名 (kind=external_input/variable)
#     part.type            → 类型 (kind=external_input)
#     part.crossFile       → 是否跨文件 (kind=external_input)
#     part.callerMethod    → 跨文件调用者方法 (kind=external_input)
#     part.callerFile      → 跨文件调用者文件 (kind=external_input)
#     part.methodSignature → 方法签名 (kind=method_return)
#     part.fieldName       → 字段名 (kind=field)

import json
import sys


def check(ctx):
    sink = ctx['sink']
    params = ctx.get('params', [])
    obj_hist = ctx.get('objHistory')
    ret_usage = ctx.get('retUsage')
    taint = ctx.get('taintChain')

    full_class = sink['packageName'] + '.' + sink['className'] if sink['packageName'] else sink['className']
    method_name = sink['methodName']

    # PreparedStatement is safe — no alert
    if full_class == 'java.sql.PreparedStatement':
        return {"alert": False}

    # ── Analyze parameter sources (structured, no string parsing!) ──────

    # Collect external input details
    external_parts = []
    hardcoded_parts = []

    for p in params:
        for part in p.get('parts', []):
            if part['kind'] == 'external_input':
                external_parts.append(part)
            elif part['kind'] == 'hardcoded':
                hardcoded_parts.append(part)

    has_external = len(external_parts) > 0
    has_hardcoded = len(hardcoded_parts) > 0

    # ── Build message using structured data ──────────────────────────────

    # Connection.createStatement() creates an unsafe Statement
    if full_class == 'java.sql.Connection' and method_name == 'createStatement':
        msg = 'Connection.createStatement() creates an unsafe Statement — use prepareStatement() instead'
        conf = 'medium'

        if has_external:
            desc = _describe_external(external_parts[0])
            msg += f' [External input: {desc}]'
            conf = 'high'
        elif taint:
            msg += f' [Taint from {taint["sourceMethod"]}() via {taint["propagationPath"]}]'
            conf = 'high'

        return {"alert": True, "message": msg, "confidence": conf}

    # Statement.execute/executeQuery/executeUpdate — the dangerous calls
    if full_class == 'java.sql.Statement':
        if has_external and has_hardcoded:
            # Most dangerous: string concatenation with external input
            sql_fragment = ' + '.join(h['value'] for h in hardcoded_parts if h.get('value'))
            ext_desc = _describe_external(external_parts[0])
            msg = (f'Statement.{method_name}() with SQL concatenation: '
                   f'"{sql_fragment}" + {ext_desc} — confirmed SQL injection')
            conf = 'high'
        elif has_external:
            ext_desc = _describe_external(external_parts[0])
            msg = f'Statement.{method_name}() with external input ({ext_desc}) — confirmed SQL injection'
            conf = 'high'
        elif has_hardcoded:
            msg = f'Statement.{method_name}() with hardcoded values only — low risk but use PreparedStatement'
            conf = 'low'
        elif taint:
            msg = (f'Statement.{method_name}() — taint from {taint["sourceMethod"]}() '
                   f'via {taint["propagationPath"]} — confirmed SQL injection')
            conf = 'high'
        else:
            msg = f'Statement.{method_name}() uses non-parameterized SQL — use PreparedStatement instead'
            conf = 'medium'

        # Enrich with object history
        if obj_hist and obj_hist.get('priorCalls'):
            prior = [r['signature'] for r in obj_hist['priorCalls']]
            msg += f' [Object history: {" → ".join(prior)}]'

        # Enrich with return value usage
        if ret_usage and ret_usage.get('subsequentCalls'):
            ret_uses = [r['signature'] for r in ret_usage['subsequentCalls']]
            msg += f' [Return used by: {", ".join(ret_uses)}]'

        return {"alert": True, "message": msg, "confidence": conf}

    # Other execute-like calls
    if 'execute' in method_name:
        return {"alert": True, "message": f'{full_class}.{method_name}() — verify parameterized queries', "confidence": "low"}

    return {"alert": False}


def _describe_external(part):
    """从结构化的 external_input part 生成人类可读的描述"""
    name = part.get('name', '?')
    source = part.get('source', 'unknown')

    if part.get('crossFile'):
        caller = part.get('callerMethod', '?')
        return f'{name} (cross-file from {caller})'
    elif source == 'method_parameter':
        return f'{name} (method parameter)'
    elif source == 'variable_pattern':
        return f'{name} (variable name pattern)'
    else:
        return name


if __name__ == '__main__':
    with open(sys.argv[1]) as f:
        ctx = json.load(f)
    result = check(ctx)
    print(json.dumps(result))