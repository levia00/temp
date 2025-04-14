const grammar = {
    S: [["A", "B"]],
    A: [["a"], ["ε"]],
    B: [["b"]]
  };
  const nonTerminals = Object.keys(grammar);
  const FIRST = {}, FOLLOW = {}, terminals = new Set();
  nonTerminals.forEach(nt => (FIRST[nt] = new Set(), FOLLOW[nt] = new Set()));
  FOLLOW[nonTerminals[0]].add("$");
  
  const addSet = (from, to) => {
    let changed = false;
    from.forEach(v => !to.has(v) && (to.add(v), changed = true));
    return changed;
  };
  
  const computeFirst = symbol => {
    if (!nonTerminals.includes(symbol)) return new Set([symbol]);
    const res = FIRST[symbol];
    for (const prod of grammar[symbol]) {
      for (let i = 0; i < prod.length; i++) {
        const symFirst = computeFirst(prod[i]);
        addSet(new Set([...symFirst].filter(x => x !== "ε")), res);
        if (!symFirst.has("ε")) break;
        if (i === prod.length - 1) res.add("ε");
      }
    }
    return res;
  };
  
  nonTerminals.forEach(nt => computeFirst(nt));
  
  let updated = true;
  while (updated) {
    updated = false;
    for (const lhs in grammar) {
      for (const prod of grammar[lhs]) {
        for (let i = 0; i < prod.length; i++) {
          const B = prod[i];
          if (nonTerminals.includes(B)) {
            const followB = FOLLOW[B], firstBeta = new Set();
            let hasEpsilon = true;
            for (let j = i + 1; j < prod.length; j++) {
              const symFirst = computeFirst(prod[j]);
              addSet(new Set([...symFirst].filter(x => x !== "ε")), firstBeta);
              if (!symFirst.has("ε")) { hasEpsilon = false; break; }
            }
            if (i + 1 === prod.length || hasEpsilon) updated |= addSet(FOLLOW[lhs], followB);
            updated |= addSet(firstBeta, followB);
          }
        }
      }
    }
  }

//same but even more compact
/**
 * const grammar = { S: [["A", "B"]], A: [["a"], ["ε"]], B: [["b"]] }, nts = Object.keys(grammar), FIRST = {}, FOLLOW = {};
nts.forEach(nt => (FIRST[nt] = new Set(), FOLLOW[nt] = new Set())); FOLLOW[nts[0]].add("$");
const add = (f, t) => [...f].reduce((c, x) => (t.has(x) ? c : (t.add(x), 1)), 0), first = s => {
  if (!nts.includes(s)) return new Set([s]);
  if (FIRST[s].size) return FIRST[s];
  for (let p of grammar[s]) {
    let i = 0, eps = true;
    while (i < p.length && eps) {
      let f = first(p[i++]);
      eps = f.has("ε");
      add(new Set([...f].filter(x => x !== "ε")), FIRST[s]);
    }
    if (eps) FIRST[s].add("ε");
  }
  return FIRST[s];
};
nts.forEach(first);
let upd = true;
while (upd) {
  upd = false;
  for (let A in grammar) for (let p of grammar[A]) for (let i = 0; i < p.length; i++) {
    let B = p[i];
    if (!nts.includes(B)) continue;
    let fBeta = new Set(), eps = true;
    for (let j = i + 1; j < p.length && eps; j++) {
      let f = first(p[j]);
      eps = f.has("ε");
      add(new Set([...f].filter(x => x !== "ε")), fBeta);
    }
    if (eps || i + 1 === p.length) upd |= add(FOLLOW[A], FOLLOW[B]);
    upd |= add(fBeta, FOLLOW[B]);
  }
}
 */

