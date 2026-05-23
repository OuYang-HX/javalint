#!/usr/bin/env node

/**
 * JavaLint CLI - Commander-based command line interface
 *
 * Commands:
 *   analyze [path]     分析 Java 项目（可指定文件或目录）
 *   list-rules         列出所有可用规则
 *   graph [path]       显示 CodeGraph 跨文件调用图
 *   build-index        构建 JDK/依赖 API 索引
 *
 * Options:
 *   --pom <path>       指定 pom.xml 自动发现依赖 jar
 *   --settings <path>  指定 Maven settings.xml（获取本地仓库路径）
 */

import { Command } from 'commander';
import { JavaLint } from '../index';
import { execSync } from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

const program = new Command();

program
  .name('javalint')
  .description('Java static code analysis powered by CodeGraph')
  .version('0.2.0');

program
  .command('analyze [path]')
  .description('Analyze a Java project for security violations')
  .option('-r, --rules <dir>', 'Custom rules directory')
  .option('--severity <level>', 'Minimum severity to report (critical, high, medium, low, info)', 'medium')
  .option('--format <fmt>', 'Output format: text, json', 'text')
  .option('--clear', 'Clear previous alerts before analysis', false)
  .option('--no-taint', 'Disable cross-file taint analysis', false)
  .option('--pom <path>', 'Path to pom.xml for dependency resolution')
  .option('--settings <path>', 'Path to Maven settings.xml')
  .action(async (projectPath?: string, options?: any) => {
    const target = projectPath || process.cwd();

    // 确定是文件还是目录
    const isFile = fs.existsSync(target) && fs.statSync(target).isFile();
    // 项目根目录：如果是文件，往上找到包含 .codegraph 的目录，否则用文件所在目录
    let root: string;
    if (isFile) {
      // 从文件所在目录往上搜索 .codegraph
      let dir = path.dirname(target);
      root = dir;
      for (let i = 0; i < 5; i++) {
        if (fs.existsSync(path.join(dir, '.codegraph'))) {
          root = dir;
          break;
        }
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
      }
    } else {
      root = target;
    }

    console.log(`\n🛡️  JavaLint v0.2.1 - Java Static Code Analysis`);
    console.log(`   ${isFile ? 'File' : 'Project'}: ${target}`);

    const lint = new JavaLint(root, options?.rules, isFile ? target : undefined);

    try {
      await lint.init();

      if (options?.clear) {
        console.log('   Clearing previous alerts...');
      }

      const result = await lint.analyze(isFile ? target : undefined);

      // 过滤：如果指定了单个文件，只显示该文件的告警
      if (isFile && result.alerts) {
        const relTarget = path.relative(root, target);
        result.alerts = result.alerts.filter(a => {
          const relAlert = path.relative(root, a.filePath);
          return relAlert === relTarget || target.endsWith(a.filePath);
        });
        result.alertCount = result.alerts.length;
      }

      if (options?.format === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else {
        lint.printResults(result);
      }

      // 退出码
      const criticalCount = result.alerts.filter(a =>
        a.severity === 'critical' || a.severity === 'high'
      ).length;

      lint.close();

      if (criticalCount > 0) {
        process.exit(1);
      }
    } catch (e) {
      console.error('\n❌ Error:', (e as Error).message);
      lint.close();
      process.exit(2);
    }
  });

program
  .command('list-rules')
  .description('List all available rules')
  .option('-r, --rules <dir>', 'Custom rules directory')
  .action(async (options?: any) => {
    const lint = new JavaLint(process.cwd(), options?.rules);
    const engine = lint.getRuleEngine();
    const count = engine.loadRules();
    const rules = engine.getRules();

    console.log(`\n📚 Available Rules (${count}):\n`);
    for (const rule of rules) {
      const taintBadge = rule.requiresTaintAnalysis ? ' [cross-file]' : '';
      console.log(`  [${rule.id}] ${rule.name} [${rule.severity}]${taintBadge}`);
      console.log(`    ${rule.description}`);
      console.log(`    Patterns: ${rule.signaturePatterns.join(', ')}`);
      if (rule.tags.length > 0) {
        console.log(`    Tags: ${rule.tags.join(', ')}`);
      }
      console.log('');
    }
  });

program
  .command('graph [path]')
  .description('Show CodeGraph cross-file call graph for the project')
  .option('--depth <number>', 'Maximum traversal depth', '3')
  .option('--method <name>', 'Focus on a specific method')
  .action(async (projectPath?: string, options?: any) => {
    const root = projectPath || process.cwd();

    const lint = new JavaLint(root);

    try {
      await lint.init();

      const traverser = lint.getCodeGraphTraverser();
      if (!traverser) {
        console.error('\n❌ CodeGraph index not found. Run `codegraph index` first.');
        lint.close();
        process.exit(2);
      }

      const depth = parseInt(options?.depth || '3', 10);

      if (options?.method) {
        // Focus on a specific method
        const methods = traverser.getAllJavaMethods();
        const found = methods.filter(m => m.name === options.method || m.qualifiedName.includes(options.method));

        if (found.length === 0) {
          console.log(`\n❌ Method "${options.method}" not found`);
          lint.close();
          return;
        }

        for (const method of found) {
          console.log(`\n🔍 ${method.qualifiedName} [${method.filePath}:${method.startLine}]`);

          // Callers
          const callers = traverser.getCallers(method.id, depth);
          if (callers.length > 0) {
            console.log(`\n   📥 Callers (who calls this):`);
            printCallers(callers, '     ');
          }

          // Callees
          const callees = traverser.getCallees(method.id, depth);
          if (callees.length > 0) {
            console.log(`\n   📤 Callees (what this calls):`);
            printCallers(callees, '     ');
          }
        }
      } else {
        // Show project overview
        const methods = traverser.getAllJavaMethods();
        const classes = traverser.getAllJavaClasses();

        console.log(`\n📊 CodeGraph Overview`);
        console.log(`   ${classes.length} classes, ${methods.length} methods`);

        // Show cross-file call edges
        console.log(`\n   Cross-file call edges:`);
        for (const method of methods) {
          const callees = traverser.getCallees(method.id, 1);
          for (const callee of callees) {
            if (callee.caller.filePath !== method.filePath) {
              console.log(`   ${method.name}() [${method.filePath}] → ${callee.caller.name}() [${callee.caller.filePath}]`);
            }
          }
        }
      }

      lint.close();
    } catch (e) {
      console.error('\n❌ Error:', (e as Error).message);
      lint.close();
      process.exit(2);
    }
  });

program
  .command('build-index [path]')
  .description('Build API index from JDK and/or project Maven dependencies')
  .option('--pom <path>', 'Path to pom.xml for dependency resolution')
  .option('--settings <path>', 'Path to Maven settings.xml')
  .option('--maven', 'Scan entire Maven local repo (legacy, slow)')
  .option('-o, --output <path>', 'Output JSON path')
  .option('-p, --repo <path>', 'Maven repo path')
  .action(async (projectPath?: string, options?: any) => {
    const root = projectPath || process.cwd();
    const scriptPath = path.join(__dirname, '..', '..', 'scripts', 'build-jdk-index.js');

    const args = ['node', scriptPath];
    if (options?.pom) args.push('--pom', options.pom);
    if (options?.settings) args.push('--settings', options.settings);
    if (options?.maven) args.push('--maven');
    if (options?.output) args.push('-o', options.output);
    if (options?.repo) args.push('-p', options.repo);

    try {
      execSync(args.join(' '), { stdio: 'inherit' });
    } catch (e) {
      process.exit((e as any).status || 2);
    }
  });

function printCallers(callers: any[], indent: string, depth: number = 0): void {
  if (depth > 2) return;
  for (const info of callers) {
    const node = info.caller;
    const edge = info.edge;
    const line = edge.line ? `:${edge.line}` : '';
    console.log(`${indent}→ ${node.name}() [${node.filePath}${line}]`);
    if (info.transitiveCallers && info.transitiveCallers.length > 0) {
      printCallers(info.transitiveCallers, indent + '  ', depth + 1);
    }
  }
}

program.parse();