function slrParsingTable(grammar) {
    const nts = Object.keys(grammar), ts = new Set(), states = [], C = [], action = {}, goTo = {};
    nts.forEach(nt => grammar[nt].forEach(p => p.forEach(s => { if (!grammar[s] && s !== 'ε') ts.add(s); })));
    const augStart = nts[0] + "'", startProd = [[nts[0]]];
    grammar[augStart] = startProd;
    const closure = I => {
      const items = [...I], seen = new Set(items.map(([A, a, dot]) => A + a.join(',') + dot));
      for (let i = 0; i < items.length; i++) {
        let [A, a, dot] = items[i];
        if (dot < a.length && grammar[a[dot]]) grammar[a[dot]].forEach(b => {
          const key = a[dot] + b.join(',') + 0;
          if (!seen.has(key)) items.push([a[dot], b, 0]), seen.add(key);
        });
      }
      return items;
    };
    const go = (I, X) => closure(I.filter(([A, a, d]) => a[d] === X).map(([A, a, d]) => [A, a, d + 1]));
    const eq = (a, b) => a.length === b.length && a.every((x, i) => x[0] === b[i][0] && x[1].join() === b[i][1].join() && x[2] === b[i][2]);
    const indexOfState = I => states.findIndex(s => eq(s, I));
    const start = closure([[augStart, ...startProd, 0]]);
    states.push(start);
    for (let i = 0; i < states.length; i++) {
      const I = states[i]; C[i] = {};
      [...ts, ...nts].forEach(X => {
        const J = go(I, X);
        if (J.length) {
          let j = indexOfState(J); if (j === -1) j = states.push(J) - 1;
          C[i][X] = j;
        }
      });
    }
    states.forEach((I, i) => {
      action[i] = {}; goTo[i] = {};
      I.forEach(([A, a, d]) => {
        if (d < a.length && ts.has(a[d])) action[i][a[d]] = ['s', C[i][a[d]]];
        else if (d === a.length) {
          if (A === augStart) action[i]['$'] = ['acc'];
          else FOLLOW[A].forEach(t => action[i][t] = ['r', A, a]);
        }
      });
      nts.forEach(N => { if (C[i][N] !== undefined) goTo[i][N] = C[i][N]; });
    });
    return { action, goTo };
  }
//example usage for above code
//   const grammar = {
//     S: [["A"]],
//     A: [["a", "A"], ["b"]]
//   };
//   const FIRST = { S: new Set(["a", "b"]), A: new Set(["a", "b"]) };
//   const FOLLOW = { S: new Set(["$"]), A: new Set(["$"]) };
  
//   const { action, goTo } = slrParsingTable(grammar);
//   console.log("ACTION TABLE:", action);
//   console.log("GOTO TABLE:", goTo);
    