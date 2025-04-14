const optimizeTAC = (tac) => {
    const used = new Set(), exprs = {}, copies = {};
    
    // Mark final result as used (assuming last instruction's result is important)
    if (tac.length > 0 && tac[tac.length - 1].result) {
        used.add(tac[tac.length - 1].result);
    }
    
    // Dead code elimination (backward pass)
    for (let i = tac.length - 1; i >= 0; i--) {
        const instr = tac[i];
        if (instr.result && !used.has(instr.result)) {
            tac.splice(i, 1); // Remove unused assignments
            continue;
        }
        if (instr.arg1) used.add(instr.arg1);
        if (instr.arg2) used.add(instr.arg2);
    }
    
    // Common subexpression elimination & constant folding
    for (let instr of tac) {
        if (instr.op && instr.arg1 && instr.arg2 && instr.result) {
            const expr = `${instr.arg1} ${instr.op} ${instr.arg2}`;
            if (exprs[expr] !== undefined) {
                instr.op = '=';
                instr.arg1 = exprs[expr];
                instr.arg2 = null;
            } else {
                exprs[expr] = instr.result;
            }
            
            // Constant folding
            if (typeof instr.arg1 === 'number' && typeof instr.arg2 === 'number') {
                let res;
                switch (instr.op) {
                    case '+': res = instr.arg1 + instr.arg2; break;
                    case '-': res = instr.arg1 - instr.arg2; break;
                    case '*': res = instr.arg1 * instr.arg2; break;
                    case '/': res = instr.arg1 / instr.arg2; break;
                }
                if (res !== undefined) {
                    instr.op = '=';
                    instr.arg1 = res;
                    instr.arg2 = null;
                }
            }
        }
        
        // Copy propagation
        if (instr.op === '=' && instr.arg2 === null) {
            copies[instr.result] = instr.arg1;
        }
        if (instr.arg1 && copies[instr.arg1]) {
            instr.arg1 = copies[instr.arg1];
        }
        if (instr.arg2 && copies[instr.arg2]) {
            instr.arg2 = copies[instr.arg2];
        }
    }
    
    return tac;
};
const exampleTAC = [
    { result: 'a', arg1: 5, arg2: null, op: '=' },       // a = 5
    { result: 'b', arg1: 3, arg2: null, op: '=' },       // b = 3
    { result: 't1', arg1: 'a', arg2: 'b', op: '+' },     // t1 = a + b
    { result: 't2', arg1: 'a', arg2: 'b', op: '+' },     // t2 = a + b (redundant)
    { result: 't3', arg1: 't1', arg2: 't2', op: '*' },   // t3 = t1 * t2
    { result: 't4', arg1: 10, arg2: 2, op: '+' },        // t4 = 10 + 2 (constant expr)
    { result: 't5', arg1: 't4', arg2: null, op: '=' },   // t5 = t4 (copy)
    { result: 't6', arg1: 't5', arg2: null, op: '=' },   // t6 = t5 (redundant copy)
    { result: 'result', arg1: 't3', arg2: null, op: '=' } // result = t3 (final output)
  ];
  console.log(optimizeTAC(exampleTAC));
  /**
   * [
  { result: 'a', arg1: 5, arg2: null, op: '=' },
  { result: 'b', arg1: 3, arg2: null, op: '=' },
  { result: 't1', arg1: 5, arg2: 3, op: '+' },
  { result: 't2', arg1: 't1', arg2: null, op: '=' },
  { result: 't3', arg1: 't1', arg2: 't1', op: '*' },
  { result: 'result', arg1: 't3', arg2: null, op: '=' }
]
   */