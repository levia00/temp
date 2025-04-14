function generateIR(expr) {
    const prec = { '+': 1, '-': 1, '*': 2, '/': 2 }, stack = [], out = [], triples = [], quad = [], indir = [];
    let temp = 0;
  
    // Infix to Postfix
    expr = expr.replace(/\s+/g, '');
    for (let c of expr) {
      if (/[a-z]/i.test(c)) out.push(c);
      else if (c === '(') stack.push(c);
      else if (c === ')'){
         while (stack.at(-1) !== '(') out.push(stack.pop()); stack.pop();
      }
      else {
        while (prec[c] <= prec[stack.at(-1)] || false) out.push(stack.pop());
        stack.push(c);
      }
    }
    while (stack.length) out.push(stack.pop());
  
    const evalStack = [];
    for (let tok of out) {
      if (/[a-z]/i.test(tok)) evalStack.push(tok);
      else {
        const op2 = evalStack.pop(), op1 = evalStack.pop();
        const idx1 = isNaN(op1) ? op1 : `(${op1})`, idx2 = isNaN(op2) ? op2 : `(${op2})`;
        triples.push([tok, op1, op2]);
        quad.push([tok, op1, op2, `t${temp}`]);
        indir.push(triples.length - 1);
        evalStack.push(temp++);
      }
    }
    return { triples, quadruples: quad, indirectTriples: indir.map(i => triples[i]) };
  }
  
  // Example
  console.log(generateIR("a + b * (c - d)"));
  