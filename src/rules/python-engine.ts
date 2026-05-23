/**
 * Python Engine — 通过 Python 子进程执行脚本
 *
 * 调用方式：
 *   1. 将 ScriptContext 序列化为 JSON 临时文件
 *   2. 启动 python3 子进程，传入脚本路径和 JSON 文件路径
 *   3. 脚本读取 JSON、执行检查、将结果以 JSON 行输出到 stdout
 *   4. 引擎解析 stdout 获得 ScriptCheckResult
 *
 * Python 脚本模板：
 *   import json, sys
 *
 *   def check(ctx):
 *       # ctx['sink'], ctx['method'], ctx['params'], ctx['objHistory'], ctx['retUsage'], ctx['taintChain']
 *       return {"alert": True, "message": "...", "confidence": "high"}
 *
 *   if __name__ == '__main__':
 *       with open(sys.argv[1]) as f:
 *           ctx = json.load(f)
 *       result = check(ctx)
 *       print(json.dumps(result))
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { ScriptEngine } from './script-engine';
import { ScriptContext, ScriptCheckResult } from './script-context';

export class PythonEngine implements ScriptEngine {
  name = 'python';
  private pythonPath: string | null = null;
  private availableChecked = false;
  private isAvailableFlag = false;

  isAvailable(): boolean {
    if (this.availableChecked) return this.isAvailableFlag;
    this.availableChecked = true;

    try {
      // 检查 python3 是否在 PATH 中
      const result = execFileSync('which', ['python3'], {
        timeout: 3000,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      if (result && fs.existsSync(result)) {
        this.pythonPath = result;
        this.isAvailableFlag = true;
      }
    } catch {
      this.isAvailableFlag = false;
    }

    return this.isAvailableFlag;
  }

  execute(scriptPath: string, context: ScriptContext): ScriptCheckResult {
    if (!this.isAvailable()) {
      return { alert: false, message: 'Python engine not available' };
    }

    if (!fs.existsSync(scriptPath)) {
      return { alert: true, message: `Script not found: ${scriptPath}`, confidence: 'low' };
    }

    // 1. 将 context 序列化为临时 JSON 文件
    const tmpFile = path.join(os.tmpdir(), `javalint-ctx-${Date.now()}.json`);
    try {
      fs.writeFileSync(tmpFile, JSON.stringify(context), 'utf-8');

      // 2. 执行 Python 脚本
      const stdout = execFileSync(this.pythonPath!, [scriptPath, tmpFile], {
        timeout: 30000,  // 30秒超时
        encoding: 'utf-8',
        maxBuffer: 1024 * 1024,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      // 3. 解析输出（脚本输出一行 JSON）
      const resultLine = stdout.trim().split('\n').pop();
      if (!resultLine) {
        return { alert: false, message: 'Python script produced no output' };
      }

      const parsed = JSON.parse(resultLine);
      return {
        alert: !!parsed.alert,
        message: parsed.message,
        confidence: parsed.confidence,
      };
    } catch (e) {
      const errMsg = (e as Error).message;
      if (errMsg.includes('ENOENT')) {
        return { alert: false, message: 'Python3 not found' };
      }
      return {
        alert: true,
        message: `Python script error: ${errMsg.substring(0, 200)}`,
        confidence: 'low',
      };
    } finally {
      // 清理临时文件
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    }
  }
}