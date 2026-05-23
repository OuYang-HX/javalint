#!/usr/bin/env node

/**
 * JavaLint CLI - Commander-based command line interface
 *
 * Extended with cross-file taint analysis and CodeGraph graph queries.
 */

import { Command } from 'commander';
import { JavaLint } from '../index';

const program = new Command();

program
  .name('javalint')
  .description('Java static code analysis powered by CodeGraph')
  .version('0.2.0');

program
  .command('analyze [path]')
  .description('Analyze a Java project for violations')
  .option('-r, --rules <dir>', 'Custom rules directory')
  .option('--severity <level>', 'Minimum severity to report (critical, high, medium, low, info)', 'medium')
  .option('--format <fmt>', 'Output format: text, json', 'text')
  .option('--clear', 'Clear previous alerts before analysis', false)
  .option('--no-taint', 'Disable cross-file taint analysis', false)
  .action(async (projectPath?: string, options?: any) => {
    const root = projectPath || process.cwd();
    const rulesDir = options?.rules;

    console.log(`\n🛡️  JavaLint - Java Static Code Analysis`);
    console.log(`   Project: ${root}`);

    const lint = new JavaLint(root, rulesDir);

    try {
      await lint.init();

      if (options?.clear) {
        console.log('   Clearing previous alerts...');
      }

      const result = await lint.analyze();

      if (options?.format === 'json') {
        console.log(JSON.stringify(result, null, 2));
      } else {
        lint.printResults(result);
      }

      // Exit with error code if there are critical/high alerts
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
      console.log(`  ${rule.id} - ${rule.name} [${rule.severity}]${taintBadge}`);
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
        // Show call graph for a specific method
        const methods = traverser.findMethodNodes(options.method);
        if (methods.length === 0) {
          console.error(`No method found with name: ${options.method}`);
          lint.close();
          process.exit(1);
        }

        for (const method of methods) {
          console.log(`\n📊 Call graph for ${method.qualifiedName} (${method.filePath}:${method.startLine})`);
          console.log(`   Signature: ${method.signature || 'N/A'}`);

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
