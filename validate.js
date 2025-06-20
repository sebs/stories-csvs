/**
 * CSV Schema Validator
 * A comprehensive, single-file JavaScript implementation for validating CSV data
 * against the CSV Schema Language 1.2 specification.
 *
 * @version 1.0.0
 * @date 2024-06-04
 *
 * Implemented Features:
 * - Prolog: version, @separator, @totalColumns, @noHeader, @ignoreColumnNameCase, @permitEmpty, @quoted
 * - Column Directives: @optional, @matchIsFalse, @ignoreCase, @warning
 * - Stateful Validation: unique, identical
 * - Expressions: is, any, not, in, starts, ends, regex, range, length, empty, notEmpty,
 *   uuid4, uri, positiveInteger, upperCase, lowerCase, xDate, xDateTime, ukDate
 * - Combinatorial/Conditional: and, or, parenthesized expressions, if(), switch()
 * - Contextual Logic: $columnName/rule
 * - String Providers: concat(), noExt(), uriDecode()
 *
 * Omitted Features:
 * - External file system operations (fileExists, checksum, etc.) are stubbed.
 * - Some niche date formats (partUkDate, xDateTimeTz, etc.).
 * - The full EBNF grammar is implemented via regex and recursive descent parsing, not a formal parser generator.
 */

class CsvValidator {
    constructor(schemaText) {
        if (!schemaText || typeof schemaText !== 'string') {
            throw new Error("Schema text must be a non-empty string.");
        }
        // Cache for stateful validators
        this._state = {
            unique: {}, // { key: Set('value1', 'value2') }
            identical: {}, // { key: 'the_one_value' }
        };
        // Parse the schema upon instantiation
        const parser = new CsvSchemaParser();
        this.schema = parser.parse(schemaText);
    }

    /**
     * Validates a CSV string against the pre-loaded schema.
     * @param {string} csvText The raw CSV data as a string.
     * @returns {Array<object>} A list of validation error/warning objects.
     */
    validate(csvText) {
        this._state.unique = {};
        this._state.identical = {};
        const errors = [];

        const records = this._simpleCsvParse(csvText, this.schema.directives.separator);

        if (records.length === 0) {
            if (!this.schema.directives.permitEmpty) {
                errors.push({
                    row: 1,
                    column: null,
                    message: "CSV file is empty, but @permitEmpty directive is not set.",
                    type: 'error'
                });
            }
            return errors;
        }

        const header = this.schema.directives.noHeader ? null : records.shift();
        const columnIndexMap = this._buildColumnIndexMap(header, errors);

        records.forEach((row, rowIndex) => {
            const currentRowNum = this.schema.directives.noHeader ? rowIndex + 1 : rowIndex + 2;

            if (this.schema.directives.totalColumns && row.length !== this.schema.directives.totalColumns) {
                errors.push({
                    row: currentRowNum,
                    column: null,
                    message: `Expected ${this.schema.directives.totalColumns} columns, but found ${row.length}.`,
                    type: 'error'
                });
                return; // Skip validation for this malformed row
            }

            const rowContext = this._buildRowContext(row, columnIndexMap);

            this.schema.columns.forEach((schemaCol) => {
                const csvIndex = columnIndexMap[schemaCol.name];
                if (csvIndex === undefined) return; // Column not in CSV, error already reported

                const cellValue = row[csvIndex] || '';
                this._validateCell(cellValue, schemaCol, currentRowNum, rowContext, errors);
            });
        });

        return errors;
    }

    _validateCell(value, schemaCol, rowNum, rowContext, errors) {
        if (schemaCol.directives.optional && (value === '' || value === null || value === undefined)) {
            return;
        }
        if (schemaCol.rules.length === 0) {
            return;
        }

        const evaluator = new ExpressionEvaluator(this.schema, this._state, rowContext, rowNum);
        let isValid = evaluator.evaluate(schemaCol.rules, value);

        if (schemaCol.directives.matchIsFalse) {
            isValid = !isValid;
        }

        if (!isValid) {
            const errorType = schemaCol.directives.warning ? 'warning' : 'error';
            errors.push({
                row: rowNum,
                column: schemaCol.name,
                value: value,
                message: `Validation failed. Rule: ${schemaCol.rawRule}`,
                type: errorType
            });
        }
    }

    _buildColumnIndexMap(header, errors) {
        const columnIndexMap = {};
        if (this.schema.directives.noHeader) {
            this.schema.columns.forEach((col, index) => {
                const colNameAsNum = parseInt(col.name, 10);
                columnIndexMap[col.name] = isNaN(colNameAsNum) ? index : colNameAsNum - 1;
            });
        } else {
            const headerNames = this.schema.directives.ignoreColumnNameCase ? header.map(h => h.toLowerCase()) : header;
            this.schema.columns.forEach(schemaCol => {
                const schemaName = this.schema.directives.ignoreColumnNameCase ? schemaCol.name.toLowerCase() : schemaCol.name;
                const index = headerNames.indexOf(schemaName);
                if (index !== -1) {
                    columnIndexMap[schemaCol.name] = index;
                } else {
                    errors.push({
                        row: 1,
                        column: schemaCol.name,
                        message: `Schema column "${schemaCol.name}" not found in CSV header.`,
                        type: 'error'
                    });
                }
            });
        }
        return columnIndexMap;
    }
    
    _buildRowContext(row, columnIndexMap) {
        const context = {};
        this.schema.columns.forEach(schemaCol => {
            const csvIndex = columnIndexMap[schemaCol.name];
            if (csvIndex !== undefined) {
                 context[schemaCol.name] = row[csvIndex];
            }
        });
        return context;
    }

    _simpleCsvParse(csvText, separator) {
        const regex = new RegExp(`(,|\\n|^)("([^"]*)"|([^",\\n]*))`, 'g');
        const records = [[]];
        let match;
        while ((match = regex.exec(csvText))) {
            const delimiter = match[1];
            if (delimiter.length && delimiter !== separator) {
                records.push([]);
            }
            const value = match[3] ? match[3] : match[4];
            records[records.length - 1].push(value);
        }
        // Handle potential empty last line
        if (records[records.length - 1].length === 0 && csvText.trim().length > 0) {
            records.pop();
        }
        return records.filter(r => r.length > 0 || r[0] !== undefined);
    }
}


class CsvSchemaParser {
    parse(schemaText) {
        const schema = {
            version: '1.0',
            directives: {
                separator: ',',
                quoted: false,
                totalColumns: null,
                permitEmpty: false,
                noHeader: false,
                ignoreColumnNameCase: false,
            },
            columns: [],
        };

        const lines = schemaText.split('\n')
            .map(l => l.replace(/\/\*.*\*\//g, '').replace(/\/\/.*$/, '').trim())
            .filter(Boolean);

        let bodyStarted = false;
        for (const line of lines) {
            if (line.startsWith('version')) {
                schema.version = line.split(' ')[1];
            } else if (line.startsWith('@') && !bodyStarted) {
                this._parseGlobalDirectives(line, schema.directives);
            } else {
                bodyStarted = true;
                this._parseColumnDefinition(line, schema.columns);
            }
        }

        if (schema.directives.totalColumns && schema.columns.length !== schema.directives.totalColumns) {
            throw new Error(`Schema Error: @totalColumns is ${schema.directives.totalColumns}, but ${schema.columns.length} columns are defined.`);
        }
        return schema;
    }

    _parseGlobalDirectives(line, directives) {
        line.match(/@\w+(\s*('(\\'|[^'])*'|"(\\"|[^"])*"|[^\s]+))?/g)?.forEach(directive => {
            const [key, ...valueParts] = directive.substring(1).split(/\s+/);
            const value = valueParts.join(' ').replace(/['"]/g, '');
            switch (key) {
                case 'separator': directives.separator = value === 'TAB' ? '\t' : value; break;
                case 'quoted': directives.quoted = true; break;
                case 'totalColumns': directives.totalColumns = parseInt(value, 10); break;
                case 'permitEmpty': directives.permitEmpty = true; break;
                case 'noHeader': directives.noHeader = true; break;
                case 'ignoreColumnNameCase': directives.ignoreColumnNameCase = true; break;
            }
        });
    }

    _parseColumnDefinition(line, columns) {
        const match = line.match(/^([^:]+):(.*)/);
        if (!match) return;

        const name = match[1].trim().replace(/["']/g, '');
        let rulePart = match[2].trim();

        const column = {
            name: name,
            rawRule: rulePart,
            rules: [],
            directives: { optional: false, matchIsFalse: false, ignoreCase: false, warning: false }
        };

        // Extract column-level directives
        rulePart = rulePart.replace(/@(\w+)/g, (_, directive) => {
            switch(directive) {
                case 'optional': column.directives.optional = true; break;
                case 'matchIsFalse': column.directives.matchIsFalse = true; break;
                case 'ignoreCase': column.directives.ignoreCase = true; break;
                case 'warning': column.directives.warning = true; break;
            }
            return '';
        }).trim();
        
        column.rawRule = rulePart; // Update raw rule after removing directives

        if (rulePart) {
            column.rules = this._parseRuleExpression(rulePart);
        }
        columns.push(column);
    }

    _parseRuleExpression(expr) {
        // This is a simplified recursive descent parser for `or` / `and` / `()`
        expr = expr.trim();

        // Base case: no more 'or's outside of parentheses
        let balance = 0;
        let splitIndex = -1;
        for (let i = 0; i < expr.length; i++) {
            if (expr[i] === '(') balance++;
            else if (expr[i] === ')') balance--;
            else if (balance === 0 && expr.substring(i, i + 4) === ' or ') {
                splitIndex = i;
                break;
            }
        }

        if (splitIndex !== -1) {
            const left = expr.substring(0, splitIndex);
            const right = expr.substring(splitIndex + 4);
            return [this._parseAndExpression(left), ...this._parseRuleExpression(right)];
        }
        return [this._parseAndExpression(expr)];
    }

    _parseAndExpression(expr) {
        expr = expr.trim();

        // Base case: no more 'and's outside of parentheses
        let balance = 0;
        let splitIndex = -1;
        for (let i = 0; i < expr.length; i++) {
            if (expr[i] === '(') balance++;
            else if (expr[i] === ')') balance--;
            else if (balance === 0 && expr.substring(i, i + 5) === ' and ') {
                splitIndex = i;
                break;
            }
        }
        
        if (splitIndex !== -1) {
            const left = expr.substring(0, splitIndex);
            const right = expr.substring(splitIndex + 5);
            return [...this._parseAndExpression(left), ...this._parseAndExpression(right)];
        }
        
        // Handle parenthesized expressions
        if (expr.startsWith('(') && expr.endsWith(')')) {
            const innerExpr = expr.substring(1, expr.length - 1);
            return this._parseRuleExpression(innerExpr); // Re-start parsing from top level
        }
        
        // Handle implicit 'and'
        const singleRules = [];
        // A regex to split by rule keywords, but not inside parentheses
        const ruleTokens = expr.match(/(\w+\(((?:[^()]+|\((?:[^()]+|\([^()]*\))*\))*)\))|\S+/g) || [];
        for (const token of ruleTokens) {
            singleRules.push(this._parseSingleRule(token));
        }
        return singleRules;
    }
    
    _parseSingleRule(ruleStr) {
        const rule = { raw: ruleStr, type: null, args: [], context: null, directives: {}};

        if (ruleStr.startsWith('$')) {
            const parts = ruleStr.split('/');
            rule.context = parts[0].substring(1);
            ruleStr = parts.slice(1).join('/');
        }

        const match = ruleStr.match(/^(\w+)(?:\((.*)\))?$/);
        if (match) {
            rule.type = match[1];
            const argsStr = match[2] || '';
            
            // Argument parsing that respects nested parentheses and quotes
            if (argsStr) {
                const argRegex = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^'\\]*(?:\\.[^'\\]*)*)'|(\w+\(((?:[^()]+|\((?:[^()]+|\([^()]*\))*\))*)\))|[^,]+/g;
                let argMatch;
                while ((argMatch = argRegex.exec(argsStr)) !== null) {
                    const arg = argMatch[1] || argMatch[2] || argMatch[3] || argMatch[0];
                    rule.args.push(arg.trim());
                }
            }
            
            // Recursive parsing for conditional/provider arguments
            if (['if', 'switch', 'concat'].includes(rule.type)) {
                rule.args = rule.args.map(arg => this._parseRuleExpression(arg)[0]);
            }
             if (rule.type === 'switch') {
                const cases = [];
                for (let i = 0; i < rule.args.length; i++) {
                    // Switch cases are themselves expressions
                    if (rule.args[i].type === 'if') {
                         cases.push(rule.args[i]);
                    } else { // default case
                        cases.push({ type: 'default', rule: rule.args[i] });
                    }
                }
                rule.args = cases;
            }

        } else {
            rule.type = ruleStr;
        }
        return rule;
    }
}

class ExpressionEvaluator {
    constructor(schema, state, rowContext, rowNum) {
        this.schema = schema;
        this.state = state;
        this.rowContext = rowContext;
        this.rowNum = rowNum;

        // Validation functions
        this.validators = {
            // Existence
            notEmpty: (v) => v !== '' && v !== null && v !== undefined,
            empty: (v) => v === '' || v === null || v === undefined,
            // String
            is: (v, args, dr) => dr.ignoreCase ? v.toLowerCase() === args[0].toLowerCase() : v === args[0],
            any: (v, args, dr) => args.some(arg => dr.ignoreCase ? v.toLowerCase() === arg.toLowerCase() : v === arg),
            not: (v, args, dr) => dr.ignoreCase ? v.toLowerCase() !== args[0].toLowerCase() : v !== args[0],
            in: (v, args, dr) => dr.ignoreCase ? args[0].toLowerCase().includes(v.toLowerCase()) : args[0].includes(v),
            starts: (v, args, dr) => dr.ignoreCase ? v.toLowerCase().startsWith(args[0].toLowerCase()) : v.startsWith(args[0]),
            ends: (v, args, dr) => dr.ignoreCase ? v.toLowerCase().endsWith(args[0].toLowerCase()) : v.endsWith(args[0]),
            regex: (v, args) => new RegExp(args[0]).test(v),
            // Numeric
            positiveInteger: (v) => /^\d+$/.test(v) && parseInt(v, 10) >= 0,
            range: (v, args) => {
                const n = parseFloat(v);
                if (isNaN(n)) return false;
                const min = args[0] === '*' ? -Infinity : parseFloat(args[0]);
                const max = args[1] === '*' ? Infinity : parseFloat(args[1]);
                return n >= min && n <= max;
            },
            length: (v, args) => {
                const len = v.length;
                const min = args[0] === '*' ? 0 : parseInt(args[0], 10);
                const max = args.length === 1 ? min : (args[1] === '*' ? Infinity : parseInt(args[1], 10));
                return len >= min && (args.length === 1 ? len === max : len <= max);
            },
            // Case
            upperCase: (v) => v === v.toUpperCase(),
            lowerCase: (v) => v === v.toLowerCase(),
            // Typed
            uuid4: (v) => /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(v),
            uri: (v) => { try { new URL(v); return true; } catch (e) { return false; } },
            // Date/Time
            xDate: (v) => /^-?\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(v) && !isNaN(Date.parse(v)),
            xDateTime: (v) => /^-?\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?$/.test(v) && !isNaN(Date.parse(v)),
            ukDate: (v) => /^(0[1-9]|[12]\d|3[01])\/(0[1-9]|1[0-2])\/\d{4}$/.test(v),
            // Stateful
            unique: (v, args) => this._checkUnique(v, args),
            identical: (v, args, dr, rule) => this._checkIdentical(v, rule),
            // Conditional
            if: (v, args) => this.evaluate(args[0], v) ? this.evaluate(args[1], v) : this.evaluate(args[2] || { type: 'notEmpty', args: [] }, v),
            switch: (v, args) => {
                for(const caseExpr of args) {
                    if (caseExpr.type === 'default') return this.evaluate(caseExpr.rule, v);
                    // A case is an 'if' rule with only a condition and a 'then'
                    if (this.evaluate(caseExpr.args[0], v)) return this.evaluate(caseExpr.args[1], v);
                }
                return true; // No cases matched, no default = pass
            },
            // External (stubbed)
            fileExists: (v, args) => { console.warn(`[WARN] fileExists('${v}') check is stubbed and will always return true.`); return true; },
            checksum: (v, args) => { console.warn(`[WARN] checksum() check is stubbed and will always return true.`); return true; },
        };
        
        // String Providers
        this.providers = {
            concat: (args) => args.map(arg => this.evaluate(arg, null)).join(''),
            noExt: (args) => this.evaluate(args[0], null).replace(/\.[^/.]+$/, ''),
            uriDecode: (args) => {
                try {
                    return decodeURIComponent(this.evaluate(args[0], null).replace(/\+/g, ' '));
                } catch(e) { return this.evaluate(args[0], null); } // Return original on failure
            }
        };
    }

    evaluate(rule, value) {
        if (Array.isArray(rule)) { // OR group
            return rule.some(andGroup => this.evaluate(andGroup, value));
        }
        if (Array.isArray(rule[0])) { // AND group
            return rule.every(r => this.evaluate(r, value));
        }

        // It's a single rule object
        const targetValue = rule.context ? this.rowContext[rule.context] : value;
        const schemaCol = this.schema.columns.find(c => this.rowContext[c.name] === targetValue) || {};

        if (this.providers[rule.type]) {
            return this.providers[rule.type](rule.args);
        }

        const validatorFn = this.validators[rule.type];
        if (validatorFn) {
            const resolvedArgs = rule.args.map(arg => typeof arg === 'string' && arg.startsWith('$') ? this.rowContext[arg.substring(1)] : arg);
            return validatorFn(targetValue, resolvedArgs, schemaCol.directives || {}, rule);
        }
        
        console.warn(`Unknown rule type: ${rule.type}`);
        return false;
    }
    
    _checkUnique(value, args) {
        const key = args.length > 0 ? args.map(c => this.rowContext[c.substring(1)]).join('||') : value;
        const cacheKey = `unique(${args.join(',')})`;

        if (!this.state.unique[cacheKey]) {
            this.state.unique[cacheKey] = new Set();
        }
        if (this.state.unique[cacheKey].has(key)) {
            return false;
        }
        this.state.unique[cacheKey].add(key);
        return true;
    }
    
    _checkIdentical(value, rule) {
        if (value === '' || value === null) return true; // Empty values don't break identicality
        const key = rule.context || this.schema.columns.find(c => this.evaluate(c.rules, value)).name;
        
        if (!this.state.identical.hasOwnProperty(key)) {
            this.state.identical[key] = value;
            return true;
        }
        return this.state.identical[key] === value;
    }
}

// 3. Run the validation
function runValidation(schemaName, schemaText, csvText) {
    console.log(`\n--- Validating with Schema: "${schemaName}" ---`);
    try {
        const validator = new CsvValidator(schemaText);
        const errors = validator.validate(csvText);

        if (errors.length === 0) {
            console.log("✅ CSV is valid!");
        } else {
            console.log(`❌ CSV is invalid. Found ${errors.length} issue(s):`);
            errors.forEach(err => {
                const parts = [
                    `[${err.type.toUpperCase()}]`,
                    `Row ${err.row}, Col "${err.column}" ->`,
                    `Value: "${err.value}"`,
                    `| Message: ${err.message}`
                ];
                console.log(`  - ${parts.join(' ')}`);
            });
        }
    } catch (e) {
        console.error(`\n🚨 A fatal error occurred during validation: ${e.message}`);
        console.error(e.stack);
    }
}

