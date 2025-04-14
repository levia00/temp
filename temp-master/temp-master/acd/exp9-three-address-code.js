function generateTAC(expr) {
    const prec = { '+': 1, '-': 1, '*': 2, '/': 2 }, stack = [], output = [], tac = [];
    let tempCount = 1;
  
    // Infix to Postfix (Shunting Yard)
    for (let t of expr.replace(/\s+/g, '')) {
      if (/[a-zA-Z]/.test(t)) output.push(t);
      else if (t === '(') stack.push(t);
      else if (t === ')') {
        while (stack.length && stack.at(-1) !== '(') output.push(stack.pop());
        stack.pop();
      }
      else {
        while (stack.length && prec[t] <= prec[stack.at(-1)]) output.push(stack.pop());
        stack.push(t);
      }
    }
    while (stack.length) output.push(stack.pop());
  
    // Generate TAC from Postfix
    const evalStack = [];
    for (let t of output) {
      if (/[a-zA-Z]/.test(t)) evalStack.push(t);
      else {
        const b = evalStack.pop(), a = evalStack.pop(), temp = `t${tempCount++}`;
        tac.push(`${temp} = ${a} ${t} ${b}`);
        evalStack.push(temp);
      }
    }
    return tac;
  }
  
  // Example
  console.log(generateTAC("a + b * (c - d)"));

