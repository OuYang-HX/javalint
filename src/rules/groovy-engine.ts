/**
 * Groovy Engine — 通过 Groovy Shell 子进程执行脚本
 *
 * 调用方式：
 *   1. 将 ScriptContext 序列化为 JSON 临时文件
 *   2. 启动 groovy 子进程，传入脚本路径和 JSON 文件路径
 *   3. 脚本读取 JSON、执行检查、将结果以 JSON 行输出到 stdout
 *   4. 引擎解析 stdout 获得 ScriptCheckResult
 *
 * Groovy 脚本模板：
 *   @Grab('org.codehaus.groovy/groovy-json')  // 如果需要
 *   def context = new groovy.json.JsonSlurper().parse(new File(args[0]))
 *   def result = check(context)
 *   println new groovy.json.JsonBuilder(result)
 *
 *   def check(ctx) {
 *     // ctx.sink, ctx.method, ctx.params, ctx.objHistory, ctx.retUsage, ctx.taintChain
 *     return [alert: true, message: "...", confidence: "high"]
 *   }
 */

import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { execFileSync } from 'child_process';
import { ScriptEngine } from './script-engine';
import { ScriptContext, ScriptCheckResult } from './script-context';

export class GroovyEngine implements ScriptEngine {
  name = 'groovy';
  private groovyPath: string | null = null;
  private availableChecked = false;
  private isAvailableFlag = false;

  isAvailable(): boolean {
    if (this.availableChecked) return this.isAvailableFlag;
    this.availableChecked = true;

    try {
      // 检查 groovy 是否在 PATH 中
      const result = execFileSync('which', ['groovy'], {
        timeout: 3000,
        encoding: 'utf-8',
        stdio: ['pipe', 'pipe', 'pipe'],
      }).trim();

      if (result && fs.existsSync(result)) {
        this.groovyPath = result;
        this.isAvailableFlag = true;
      }
    } catch {
      this.isAvailableFlag = false;
    }

    return this.isAvailableFlag;
  }

  execute(scriptPath: string, context: ScriptContext): ScriptCheckResult {
    if (!this.isAvailable()) {
      return { alert: false, message: 'Groovy engine not available' };
    }

    if (!fs.existsSync(scriptPath)) {
      return { alert: true, message: `Script not found: ${scriptPath}`, confidence: 'low' };
    }

    // 1. 将 context 序列化为临时 JSON 文件
    const tmpFile = path.join(os.tmpdir(), `javalint-ctx-${Date.now()}.json`);
    try {
      fs.writeFileSync(tmpFile, JSON.stringify(context), 'utf-8');

      // 2. 执行 Groovy 脚本
      const stdout = execFileSync(this.groovyPath!, [scriptPath, tmpFile], {
        timeout: 30000,  // 30秒超时
        encoding: 'utf-8',
        maxBuffer: 1024 * 1024,
        stdio: ['pipe', 'pipe', 'pipe'],
      });

      // 3. 解析输出（脚本输出一行 JSON）
      const resultLine = stdout.trim().split('\n').pop();
      if (!resultLine) {
        return { alert: false, message: 'Groovy script produced no output' };
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
        return { alert: false, message: 'Groovy not found' };
      }
      return {
        alert: true,
        message: `Groovy script error: ${errMsg.substring(0, 200)}`,
        confidence: 'low',
      };
    } finally {
      // 清理临时文件
      try { fs.unlinkSync(tmpFile); } catch { /* ignore */ }
    }
  }
}