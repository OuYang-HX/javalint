/**
 * Variable Type Resolver
 *
 * Resolves the precise type of local variables by tracking assignment chains
 * within Java method bodies. This enables distinguishing, for example,
 * `java.sql.Statement.executeQuery()` from `java.sql.PreparedStatement.executeQuery()`.
 *
 * Resolution sources (in priority order):
 *
 *   1. Local variable declaration with explicit type:
 *        Statement stmt = conn.createStatement();
 *        PreparedStatement pstmt = conn.prepareStatement(sql);
 *
 *   2. Try-with-resources variable with explicit type:
 *        try (Statement stmt = conn.createStatement()) { ... }
 *
 *   3. Object instantiation (new):
 *        FileInputStream fis = new FileInputStream(path);
 *        ObjectInputStream ois = new java.io.ObjectInputStream(fis);
 *
 *   4. Class field declaration (tracked at class scope):
 *        private Connection dbConnection;
 *
 *   5. Fully-qualified constructor:
 *        new java.io.ObjectInputStream(fis)  → type is java.io.ObjectInputStream
 *
 * The resolver operates on tree-sitter AST nodes so it can extract type info
 * from the same parse tree used for call extraction — no extra parse needed.
 */

import { resolveTypeName } from '../utils/java-utils';

/** Resolved variable type */
export interface VarType {
  /** Full qualified class name, e.g. "java.sql.Statement" */
  fullClassName: string;
  /** Package part, e.g. "java.sql" */
  packageName: string;
  /** Short class name, e.g. "Statement" */
  className: string;
}

/**
 * Build a variable→type map for a single Java file.
 *
 * @param rootNode  - tree-sitter root node for the file
 * @param source    - the full source text
 * @param imports   - shortName → fullQualifiedName (already extracted)
 * @returns Map keyed by "className.methodName" → Map<varName, VarType>
 *          Also includes "className.<fields>" for field declarations.
 */
export function buildVariableTypeMap(
  rootNode: any,
  source: string,
  imports: Map<string, string>,
): Map<string, Map<string, VarType>> {
  // scope key → (varName → VarType)
  // scope key format: "ClassName.methodName" for locals, "ClassName.<fields>" for fields
  const scopeMap = new Map<string, Map<string, VarType>>();

  // Walk top-level: find class declarations, then their members
  for (let i = 0; i < rootNode.childCount; i++) {
    const child = rootNode.child(i);
    if (!child) continue;

    if (child.type === 'class_declaration' || child.type === 'interface_declaration' || child.type === 'enum_declaration') {
      const className = extractNodeName(child, source);
      if (!className) continue;

      // 1. Collect field declarations (class scope)
      const fieldsScope = new Map<string, VarType>();
      collectFields(child, source, imports, fieldsScope);
      scopeMap.set(`${className}.<fields>`, fieldsScope);

      // 2. Collect local variable declarations inside each method
      collectMethodLocals(child, source, imports, className, scopeMap);
    }
  }

  return scopeMap;
}

// ─── Field collection ────────────────────────────────────────────────────

function collectFields(
  classNode: any,
  source: string,
  imports: Map<string, string>,
  fieldsScope: Map<string, VarType>,
): void {
  const body = classNode.childForFieldName('body');
  if (!body) return;

  for (let i = 0; i < body.childCount; i++) {
    const member = body.child(i);
    if (!member) continue;

    // Field declaration: "private Connection dbConnection;"
    if (member.type === 'field_declaration') {
      extractVarDeclFromNode(member, source, imports, fieldsScope);
    }
  }
}

// ─── Method local variable collection ────────────────────────────────────

function collectMethodLocals(
  classNode: any,
  source: string,
  imports: Map<string, string>,
  className: string,
  scopeMap: Map<string, Map<string, VarType>>,
): void {
  const body = classNode.childForFieldName('body');
  if (!body) return;

  for (let i = 0; i < body.childCount; i++) {
    const member = body.child(i);
    if (!member) continue;

    // Method or constructor
    if (member.type === 'method_declaration' || member.type === 'constructor_declaration') {
      const methodName = extractNodeName(member, source) || '<constructor>';
      const scopeKey = `${className}.${methodName}`;
      const locals = new Map<string, VarType>();

      // Recursively walk the method body for variable declarations & assignments
      walkForVarDecls(member, source, imports, locals);

      scopeMap.set(scopeKey, locals);
    }
  }
}

/**
 * Recursively walk a method body looking for:
 *   - local_variable_declaration: "Type varName = expr;"
 *   - try_with_resources: "try (Type varName = expr) { ... }"
 */
function walkForVarDecls(
  node: any,
  source: string,
  imports: Map<string, string>,
  locals: Map<string, VarType>,
): void {
  if (!node) return;

  // local_variable_declaration: "Statement stmt = conn.createStatement();"
  if (node.type === 'local_variable_declaration') {
    extractVarDeclFromNode(node, source, imports, locals);
  }

  // Method/constructor formal parameters: "Long id", "String username"
  if (node.type === 'method_declaration' || node.type === 'constructor_declaration') {
    const params = node.childForFieldName('parameters');
    if (params) {
      for (let i = 0; i < params.childCount; i++) {
        const param = params.child(i);
        if (param && param.type === 'formal_parameter') {
          const typeNode = param.childForFieldName('type');
          const nameNode = param.childForFieldName('name');
          if (typeNode && nameNode) {
            const typeText = source.substring(typeNode.startIndex, typeNode.endIndex).trim();
            const varName = source.substring(nameNode.startIndex, nameNode.endIndex).trim();
            const resolved = resolveTypeText(typeText, imports);
            if (resolved) locals.set(varName, resolved);
          }
        }
      }
    }
  }

  // Catch clause parameter: "catch (Exception e)"
  if (node.type === 'catch_clause') {
    // tree-sitter uses catch_formal_parameter, not formal_parameter
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && (child.type === 'catch_formal_parameter' || child.type === 'formal_parameter')) {
        // Try .name and .type fields
        const nameNode = child.childForFieldName('name');
        // Type can be in .type or .catch_type
        let typeNode = child.childForFieldName('type');
        if (!typeNode) {
          // catch_formal_parameter has a catch_type child
          for (let j = 0; j < child.childCount; j++) {
            const gc = child.child(j);
            if (gc && (gc.type === 'catch_type' || gc.type === 'type_identifier')) {
              typeNode = gc;
              break;
            }
          }
        }
        if (typeNode && nameNode) {
          const typeText = source.substring(typeNode.startIndex, typeNode.endIndex).trim();
          const varName = source.substring(nameNode.startIndex, nameNode.endIndex).trim();
          const resolved = resolveTypeText(typeText, imports);
          if (resolved) locals.set(varName, resolved);
        }
      }
    }
  }

  // try_with_resources clause
  if (node.type === 'try_statement' || node.type === 'try_with_resources_statement') {
    for (let i = 0; i < node.childCount; i++) {
      const child = node.child(i);
      if (child && child.type === 'resource_specification') {
        for (let j = 0; j < child.childCount; j++) {
          const res = child.child(j);
          if (!res) continue;
          if (res.type === 'resource') {
            extractResourceDecl(res, source, imports, locals);
          }
          if (res.type === 'local_variable_declaration') {
            extractVarDeclFromNode(res, source, imports, locals);
          }
          if (res.type === 'assignment_expression') {
            extractAssignmentType(res, source, imports, locals);
          }
        }
      }
    }
  }

  // assignment_expression: "stmt = conn.createStatement();" (reassignment, less common for new vars)
  // We only track if the variable was already declared — don't override a known type

  // Recurse into children
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child) {
      walkForVarDecls(child, source, imports, locals);
    }
  }
}

// ─── Core: extract variable name + type from a declaration node ──────────

/**
 * Extract variable declarations from a local_variable_declaration or field_declaration node.
 *
 * Handles:
 *   - "Statement stmt = conn.createStatement();"       → stmt: Statement
 *   - "PreparedStatement stmt = conn.prepareStatement(sql);" → stmt: PreparedStatement
 *   - "FileInputStream fis = new FileInputStream(path);"     → fis: FileInputStream
 *   - "ObjectInputStream ois = new java.io.ObjectInputStream(fis);" → ois: java.io.ObjectInputStream
 *   - "ResultSet rs = stmt.executeQuery();"                  → rs: ResultSet
 *   - "String sql = \"...\";"                                → sql: String
 */
function extractVarDeclFromNode(
  node: any,
  source: string,
  imports: Map<string, string>,
  scope: Map<string, VarType>,
): void {
  // The structure is: [modifiers] type declarator [= value] ;
  // We need to find the type node and the variable name(s).

  const typeNode = node.childForFieldName('type');
  if (!typeNode) return;

  const typeText = source.substring(typeNode.startIndex, typeNode.endIndex).trim();

  // Resolve the declared type (left-hand side)
  const resolvedType = resolveTypeText(typeText, imports);
  if (!resolvedType) return; // Can't resolve type, skip

  // Find variable declarators
  const declaratorNode = node.childForFieldName('declarator');
  if (declaratorNode) {
    extractDeclarator(declaratorNode, source, imports, resolvedType, scope);
  }

  // Some tree-sitter versions nest differently: look for variable_declarator children
  for (let i = 0; i < node.childCount; i++) {
    const child = node.child(i);
    if (child && child.type === 'variable_declarator') {
      extractDeclarator(child, source, imports, resolvedType, scope);
    }
  }
}

/**
 * Extract from a variable_declarator node:
 *   varName = initializer
 */
function extractDeclarator(
  declarator: any,
  source: string,
  imports: Map<string, string>,
  declaredType: VarType,
  scope: Map<string, VarType>,
): void {
  const nameNode = declarator.childForFieldName('name');
  if (!nameNode) return;

  const varName = source.substring(nameNode.startIndex, nameNode.endIndex).trim();

  // Check the initializer — it may override the declared type if it's a
  // fully-qualified constructor like "new java.io.ObjectInputStream(fis)"
  const valueNode = declarator.childForFieldName('value');
  if (valueNode) {
    const overrideType = tryResolveFromInitializer(valueNode, source, imports);
    if (overrideType) {
      scope.set(varName, overrideType);
      return;
    }
  }

  // Use declared type
  scope.set(varName, declaredType);
}

/**
 * Try to resolve type from the initializer expression.
 *
 * Key patterns:
 *   - new SomeClass(...)        → type is SomeClass (resolved via imports)
 *   - new some.pkg.SomeClass(...) → type is some.pkg.SomeClass
 *   - someVar.someMethod(...)   → type depends on method return type (not tracked here)
 */
function tryResolveFromInitializer(
  valueNode: any,
  source: string,
  imports: Map<string, string>,
): VarType | null {
  // Handle: new SomeClass(...)
  if (valueNode.type === 'object_creation_expression') {
    return resolveNewExpression(valueNode, source, imports);
  }

  // Handle: someExpr.new InnerClass(...)
  if (valueNode.type === 'inner_class_creation_expression') {
    return resolveNewExpression(valueNode, source, imports);
  }

  // Handle: method call like conn.createStatement() — can't determine return type
  // without a type system, but we could do common patterns.
  // For now, return null (use declared type instead).
  return null;
}

/**
 * Resolve type from "new SomeClass(...)" or "new some.pkg.SomeClass(...)"
 */
function resolveNewExpression(
  node: any,
  source: string,
  imports: Map<string, string>,
): VarType | null {
  const typeField = node.childForFieldName('type');
  if (!typeField) return null;

  const typeText = source.substring(typeField.startIndex, typeField.endIndex).trim();
  return resolveTypeText(typeText, imports);
}

/**
 * Extract variable name + type from a resource node in try-with-resources.
 *
 * tree-sitter Java grammar's `resource` node doesn't always have
 * standardized child fields, so we parse from the text.
 *
 * Patterns:
 *   "PreparedStatement stmt = dbConnection.prepareStatement(sql)"
 *   "Statement stmt = dbConnection.createStatement()"
 *   "java.io.FileInputStream fis = new java.io.FileInputStream(path)"
 *   "java.io.ObjectInputStream ois = new java.io.ObjectInputStream(fis)"
 */
function extractResourceDecl(
  node: any,
  source: string,
  imports: Map<string, string>,
  scope: Map<string, VarType>,
): void {
  const text = source.substring(node.startIndex, node.endIndex).trim();

  // Try to parse:  Type varName = initializer
  // The type could be simple ("Statement"), qualified ("java.io.ObjectInputStream"),
  // or generic ("List<User>").
  const match = text.match(/^([A-Za-z_][\w.<>,\s]*?)\s+(\w+)\s*=/);
  if (!match) return;

  const typeText = match[1].trim();
  const varName = match[2];

  // Resolve the declared type
  const resolvedType = resolveTypeText(typeText, imports);
  if (!resolvedType) return;

  // Check the initializer for a fully-qualified constructor that overrides
  const eqIdx = text.indexOf('=');
  if (eqIdx > 0) {
    const initText = text.substring(eqIdx + 1).trim();
    // "new java.io.ObjectInputStream(fis)" → extract type
    const newMatch = initText.match(/new\s+([a-zA-Z_][\w.]*)/);
    if (newMatch && newMatch[1]) {
      const overrideType = resolveTypeText(newMatch[1], imports);
      if (overrideType) {
        scope.set(varName, overrideType);
        return;
      }
    }
  }

  scope.set(varName, resolvedType);
}

// ─── Assignment expression (less common) ─────────────────────────────────

function extractAssignmentType(
  node: any,
  source: string,
  imports: Map<string, string>,
  scope: Map<string, VarType>,
): void {
  const leftNode = node.childForFieldName('left');
  const rightNode = node.childForFieldName('right');
  if (!leftNode || !rightNode) return;

  const varName = source.substring(leftNode.startIndex, leftNode.endIndex).trim();
  // Only set if not already known (first declaration wins)
  if (scope.has(varName)) return;

  const overrideType = tryResolveFromInitializer(rightNode, source, imports);
  if (overrideType) {
    scope.set(varName, overrideType);
  }
}

// ─── Type text resolution ────────────────────────────────────────────────

/**
 * Resolve a type text to a VarType.
 *
 * Handles:
 *   - "Statement"                     → via imports → java.sql.Statement
 *   - "java.sql.Statement"            → directly → { java.sql, Statement }
 *   - "PreparedStatement"             → via imports → java.sql.PreparedStatement
 *   - "Connection"                    → via imports → java.sql.Connection
 *   - Generic types like "List<User>" → extract "List", resolve
 */
function resolveTypeText(typeText: string, imports: Map<string, string>): VarType | null {
  // Strip generics: "List<User>" → "List"
  let cleanType = typeText.replace(/<.*>/, '').trim();

  // Strip array brackets: "String[]" → "String"
  cleanType = cleanType.replace(/\[\]$/, '').trim();

  // Handle varargs: "String..." → "String"
  cleanType = cleanType.replace(/\.\.\.+$/, '').trim();

  if (!cleanType) return null;

  // Case 1: Fully qualified name with dots starting with lowercase package segment
  // "java.sql.Statement" or "java.io.ObjectInputStream"
  if (cleanType.includes('.')) {
    const lastDot = cleanType.lastIndexOf('.');
    const pkg = cleanType.substring(0, lastDot);
    const cls = cleanType.substring(lastDot + 1);
    if (pkg && cls && /^[a-z]/.test(pkg)) {
      return { fullClassName: cleanType, packageName: pkg, className: cls };
    }
  }

  // Case 2: Short name → resolve via imports or JAVA_BOXED_MAP
  const resolved = resolveTypeName(cleanType, imports);

  if (resolved.includes('.')) {
    const lastDot = resolved.lastIndexOf('.');
    return {
      fullClassName: resolved,
      packageName: resolved.substring(0, lastDot),
      className: resolved.substring(lastDot + 1),
    };
  }

  // Case 3: Unknown type — return with just className (no package)
  return { fullClassName: resolved, packageName: '', className: resolved };
}

// ─── Helpers ─────────────────────────────────────────────────────────────

function extractNodeName(node: any, source: string): string | null {
  const nameNode = node.childForFieldName('name');
  if (!nameNode) return null;
  return source.substring(nameNode.startIndex, nameNode.endIndex);
}

/**
 * Look up the type of a variable in the scope chain.
 *
 * Search order:
 *   1. Method-local scope (className.methodName)
 *   2. Class fields scope (className.<fields>)
 *
 * @returns VarType if found, null otherwise
 */
export function lookupVariableType(
  varName: string,
  enclosingClass: string,
  enclosingMethod: string,
  scopeMap: Map<string, Map<string, VarType>>,
): VarType | null {
  // 1. Local scope
  const localScope = scopeMap.get(`${enclosingClass}.${enclosingMethod}`);
  if (localScope && localScope.has(varName)) {
    return localScope.get(varName)!;
  }

  // 2. Field scope
  const fieldScope = scopeMap.get(`${enclosingClass}.<fields>`);
  if (fieldScope && fieldScope.has(varName)) {
    return fieldScope.get(varName)!;
  }

  return null;
}
