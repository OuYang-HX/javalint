#!/usr/bin/env node

/**
 * Maven Dependency Resolver — 从 pom.xml 解析项目依赖 jar 包
 *
 * 工作流程:
 *   1. 解析 settings.xml 获取本地仓库路径
 *   2. 解析 pom.xml 提取依赖坐标 (groupId:artifactId:version)
 *   3. 在本地仓库中定位对应 jar 包
 *   4. 可选: 解析 pom 中的 parent/dependencyManagement 传递依赖
 *
 * Usage:
 *   const resolver = new MavenResolver(settingsXmlPath, mavenRepoPath);
 *   const jars = resolver.resolveJars(pomXmlPath);
 */

const fs = require('fs');
const path = require('path');
const { execSync } = require('child_process');

class MavenResolver {
  constructor(settingsXmlPath, mavenRepoPath) {
    this.settingsXmlPath = settingsXmlPath;
    this.mavenRepoPath = mavenRepoPath;
    this.profileRepos = [];
  }

  /**
   * 从 settings.xml 解析本地仓库路径和 profile 仓库
   */
  parseSettings() {
    if (!fs.existsSync(this.settingsXmlPath)) {
      console.log(`  settings.xml not found: ${this.settingsXmlPath}`);
      return;
    }

    const content = fs.readFileSync(this.settingsXmlPath, 'utf-8');

    // 本地仓库路径
    const localRepoMatch = content.match(/<localRepository>\s*([^<]+)\s*<\/localRepository>/);
    if (localRepoMatch) {
      this.mavenRepoPath = localRepoMatch[1].trim();
      console.log(`  Local repository from settings.xml: ${this.mavenRepoPath}`);
    }

    // Profile 仓库（用于后续远程解析）
    const profileRepos = [];
    const repoRegex = /<repository>\s*<id>\s*([^<]+)\s*<\/id>\s*<url>\s*([^<]+)\s*<\/url>/g;
    let match;
    while ((match = repoRegex.exec(content)) !== null) {
      profileRepos.push({ id: match[1].trim(), url: match[2].trim() });
    }
    this.profileRepos = profileRepos;
  }

  /**
   * 解析 pom.xml 提取直接依赖
   */
  parsePom(pomPath) {
    if (!fs.existsSync(pomPath)) {
      console.log(`  pom.xml not found: ${pomPath}`);
      return [];
    }

    const content = fs.readFileSync(pomPath, 'utf-8');

    // 提取 properties (用于版本变量替换)
    const properties = {};
    const propRegex = /<([\w.]+)>\s*([^<]+)\s*<\/\1>/g;
    const propsSection = content.match(/<properties>[\s\S]*?<\/properties>/);
    if (propsSection) {
      let propMatch;
      while ((propMatch = propRegex.exec(propsSection[0])) !== null) {
        properties[propMatch[1]] = propMatch[2].trim();
      }
    }

    // 提取 GAV 坐标
    const deps = [];
    const depRegex = /<dependency>\s*([\s\S]*?)<\/dependency>/g;
    let depMatch;
    while ((depMatch = depRegex.exec(content)) !== null) {
      const block = depMatch[1];
      const groupId = this._extractTag(block, 'groupId');
      const artifactId = this._extractTag(block, 'artifactId');
      let version = this._extractTag(block, 'version');
      const scope = this._extractTag(block, 'scope') || 'compile';

      // 跳过 test/provided 作用域
      if (scope === 'test' || scope === 'provided' || scope === 'system') continue;

      // 替换版本变量 ${xxx}
      if (version && version.match(/^\$\{(.+)\}$/)) {
        const varName = version.match(/^\$\{(.+)\}$/)[1];
        version = properties[varName] || null;
      }

      if (groupId && artifactId) {
        deps.push({ groupId, artifactId, version });
      }
    }

    return deps;
  }

  /**
   * 递归解析 pom 及其 parent pom 的依赖
   */
  parsePomWithParents(pomPath, maxDepth = 5) {
    const allDeps = [];
    const visited = new Set();
    const self = this;

    function walk(pom, depth) {
      if (depth > maxDepth) return;
      const realPath = self._resolvePomPath(pom);
      if (!realPath || visited.has(realPath)) return;
      visited.add(realPath);

      const deps = self.parsePom(realPath);
      allDeps.push(...deps);

      // 解析 parent pom
      const content = fs.readFileSync(realPath, 'utf-8');
      const parentSection = content.match(/<parent>\s*([\s\S]*?)<\/parent>/);
      if (parentSection) {
        const block = parentSection[1];
        const pg = self._extractTag(block, 'groupId');
        const pa = self._extractTag(block, 'artifactId');
        const pv = self._extractTag(block, 'version');
        if (pg && pa && pv) {
          const parentPom = path.join(
            self.mavenRepoPath,
            ...pg.split('.'),
            pa, pv, `${pa}-${pv}.pom`
          );
          if (fs.existsSync(parentPom)) {
            walk(parentPom, depth + 1);
          }
        }
      }
    }

    walk(pomPath, 0);
    return this._dedupDeps(allDeps);
  }

  /**
   * 根据依赖坐标在本地仓库中定位 jar 包
   */
  resolveJars(deps) {
    const jars = [];
    const missing = [];

    for (const dep of deps) {
      const jarDir = path.join(
        this.mavenRepoPath,
        ...dep.groupId.split('.'),
        dep.artifactId,
        dep.version || ''
      );

      // 尝试精确版本
      if (dep.version) {
        const jarName = `${dep.artifactId}-${dep.version}.jar`;
        const jarPath = path.join(jarDir, jarName);
        if (fs.existsSync(jarPath)) {
          jars.push(jarPath);
          continue;
        }
      }

      // 尝试找到目录下最新版本
      if (fs.existsSync(jarDir)) {
        const files = fs.readdirSync(jarDir).filter(f => f.endsWith('.jar') && !f.includes('sources') && !f.includes('javadoc'));
        if (files.length > 0) {
          jars.push(path.join(jarDir, files[files.length - 1]));
          continue;
        }
      }

      // 版本未指定时，尝试在 artifactId 目录下搜索
      if (!dep.version) {
        const artifactDir = path.join(
          this.mavenRepoPath,
          ...dep.groupId.split('.'),
          dep.artifactId
        );
        if (fs.existsSync(artifactDir)) {
          const versions = fs.readdirSync(artifactDir)
            .filter(f => fs.statSync(path.join(artifactDir, f)).isDirectory())
            .sort();
          if (versions.length > 0) {
            const latestVer = versions[versions.length - 1];
            const jarName = `${dep.artifactId}-${latestVer}.jar`;
            const jarPath = path.join(artifactDir, latestVer, jarName);
            if (fs.existsSync(jarPath)) {
              jars.push(jarPath);
              continue;
            }
          }
        }
      }

      missing.push(`${dep.groupId}:${dep.artifactId}:${dep.version || '?'}`);
    }

    if (missing.length > 0) {
      console.log(`  ⚠ Missing ${missing.length} dependencies:`);
      missing.slice(0, 10).forEach(m => console.log(`    - ${m}`));
      if (missing.length > 10) console.log(`    ... and ${missing.length - 10} more`);
    }

    return jars;
  }

  /**
   * 从 jar 包中提取类名列表
   */
  extractClassNames(jarPath) {
    try {
      const listing = execSync(`jar tf "${jarPath}" 2>/dev/null`, {
        encoding: 'utf-8',
        timeout: 5000,
      });
      const classes = [];
      for (const line of listing.split('\n')) {
        const m = line.trim().match(/^([\w/$]+)\.class$/);
        if (m && !m[1].includes('$')) {
          classes.push(m[1].replace(/\//g, '.'));
        }
      }
      return classes;
    } catch {
      return [];
    }
  }

  /**
   * 一站式: 从 pom.xml 解析依赖 → 定位 jar → 提取所有类名
   * @returns {{ classNames: string[], classpath: string, jars: string[] }}
   */
  resolveProjectClasses(pomPath) {
    console.log('\n📦 Resolving Maven dependencies...');

    // 1. 解析 settings.xml
    if (this.settingsXmlPath) {
      this.parseSettings();
    }
    console.log(`  Maven repo: ${this.mavenRepoPath}`);

    // 2. 解析 pom.xml (含 parent)
    const deps = this.parsePomWithParents(pomPath);
    console.log(`  Found ${deps.length} dependencies in pom.xml`);

    // 3. 定位 jar 包
    const jars = this.resolveJars(deps);
    console.log(`  Resolved ${jars.length} jar files`);

    // 4. 提取类名
    const classNames = [];
    for (const jar of jars) {
      const classes = this.extractClassNames(jar);
      classNames.push(...classes);
    }
    const uniqueClasses = [...new Set(classNames)];
    console.log(`  Extracted ${uniqueClasses.length} unique classes`);

    return {
      classNames: uniqueClasses,
      classpath: jars.join(':'),
      jars,
    };
  }

  // ─── helpers ──────────────────────────────────────────────────

  _extractTag(block, tagName) {
    const m = block.match(new RegExp(`<${tagName}>\\s*([^<]+)\\s*<\\/${tagName}>`));
    return m ? m[1].trim() : null;
  }

  _resolvePomPath(pomPath) {
    if (fs.existsSync(pomPath)) return pomPath;
    // 如果只给目录，找目录下的 pom.xml
    const candidate = path.join(pomPath, 'pom.xml');
    if (fs.existsSync(candidate)) return candidate;
    return null;
  }

  _dedupDeps(deps) {
    const seen = new Set();
    return deps.filter(d => {
      const key = `${d.groupId}:${d.artifactId}`;
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    });
  }
}

module.exports = { MavenResolver };