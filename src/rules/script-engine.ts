/**
 * ScriptEngine — 多语言脚本执行引擎接口
 *
 * 设计原则：
 *   1. 统一接口：所有引擎接受相同的 ScriptContext JSON，返回相同的 ScriptCheckResult JSON
 *   2. 语言适配：每种语言有自己最佳的执行方式（JS=require, Groovy/Python=subprocess）
 *   3. 优雅降级：引擎不可用时跳过，不影响其他规则
 *
 * 调用流程：
 *   RuleEngine → ScriptEngineRegistry → 具体Engine → ScriptContext(JSON) → 脚本 → CheckResult(JSON)
 */

import { ScriptContext, ScriptCheckResult } from './script-context';

export interface ScriptEngine {
  /** 引擎名称，如 "js", "groovy", "python" */
  name: string;

  /** 检查引擎是否可用（运行时/解释器是否存在） */
  isAvailable(): boolean;

  /**
   * 执行脚本检查
   *
   * @param scriptPath 脚本文件的绝对路径
   * @param context 传递给脚本的上下文（JSON 序列化后传入）
   * @returns 检查结果
   */
  execute(scriptPath: string, context: ScriptContext): ScriptCheckResult;
}

// ─── 引擎注册表 ──────────────────────────────────────────────────────

export class ScriptEngineRegistry {
  private engines = new Map<string, ScriptEngine>();

  register(engine: ScriptEngine): void {
    this.engines.set(engine.name, engine);
  }

  get(name: string): ScriptEngine | undefined {
    return this.engines.get(name);
  }

  /** 根据脚本文件扩展名自动选择引擎 */
  getEngineForScript(scriptPath: string): ScriptEngine | undefined {
    const ext = scriptPath.split('.').pop()!.toLowerCase();

    // 根据扩展名映射引擎
    const engineMap: Record<string, string> = {
      'js': 'js',
      'groovy': 'groovy',
      'py': 'python',
    };

    const engineName = engineMap[ext];
    if (!engineName) return undefined;

    const engine = this.engines.get(engineName);
    if (!engine || !engine.isAvailable()) return undefined;

    return engine;
  }

  listAvailable(): string[] {
    return [...this.engines.values()]
      .filter(e => e.isAvailable())
      .map(e => e.name);
  }
}