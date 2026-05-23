/**
 * JS Engine — Node.js require() 方式执行脚本
 *
 * 最快、最直接的执行方式。脚本通过 module.exports.check = function(context) {}
 * 导出检查函数，引擎直接 require() 调用。
 *
 * 优势：无需序列化/反序列化，直接传递 JS 对象，零延迟
 */

import * as fs from 'fs';
import * as path from 'path';
import { ScriptEngine } from './script-engine';
import { ScriptContext, ScriptCheckResult } from './script-context';

export class JsEngine implements ScriptEngine {
  name = 'js';

  // 缓存已加载的脚本模块（避免反复 require）
  private moduleCache = new Map<string, any>();

  isAvailable(): boolean {
    // JS 引擎始终可用（运行在 Node.js 中）
    return true;
  }

  execute(scriptPath: string, context: ScriptContext): ScriptCheckResult {
    if (!fs.existsSync(scriptPath)) {
      return { alert: true, message: `Script not found: ${scriptPath}`, confidence: 'low' };
    }

    try {
      // 清除 require 缓存，确保脚本更新后能重新加载
      delete require.cache[require.resolve(scriptPath)];

      const checkModule = require(scriptPath);

      if (typeof checkModule.check === 'function') {
        const result = checkModule.check(context);
        if (result && typeof result.alert === 'boolean') {
          return {
            alert: result.alert,
            message: result.message,
            confidence: result.confidence,
          };
        }
        return { alert: true, message: 'Script returned unexpected format', confidence: 'low' };
      }

      return { alert: true, message: 'Script has no check() function', confidence: 'low' };
    } catch (e) {
      return {
        alert: true,
        message: `JS script error: ${(e as Error).message}`,
        confidence: 'low',
      };
    }
  }
}