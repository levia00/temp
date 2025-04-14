const parsingTable = {};

function constructParsingTable(grammar) {
  for (let [nonTerminal, productions] of Object.entries(grammar)) {
    parsingTable[nonTerminal] = {};
    for (let production of productions) {
      let symbols = production.split(" ");
      let firstSet = new Set();

      for (let symbol of symbols) {
        if (!grammar[symbol]) {
          firstSet.add(symbol);
          break;
        } else {
          FIRST[symbol].forEach(item => firstSet.add(item));
          if (!FIRST[symbol].has("ε")) break;
        }
      }

      firstSet.forEach(terminal => {
        if (terminal !== "ε") {
          parsingTable[nonTerminal][terminal] = production;
        }
      });

      if (firstSet.has("ε")) {
        FOLLOW[nonTerminal].forEach(terminal => {
          parsingTable[nonTerminal][terminal] = "ε";
        });
      }
    }
  }
}

constructParsingTable(grammar);
console.log("Parsing Table:", parsingTable);

/**
 * same but compact code for predictive parsing table
 * const parsingTable = {};
const constructParsingTable = g => {
  for (let nt in g) {
    parsingTable[nt] = {};
    for (let prod of g[nt]) {
      let f = new Set(), i = 0;
      while (i < prod.length) {
        let sym = prod[i++];
        if (!g[sym]) { f.add(sym); break; }
        FIRST[sym].forEach(x => f.add(x));
        if (!FIRST[sym].has("ε")) break;
      }
      f.forEach(t => t !== "ε" && (parsingTable[nt][t] = prod));
      if (f.has("ε")) FOLLOW[nt].forEach(t => parsingTable[nt][t] = ["ε"]);
    }
  }
};
constructParsingTable(grammar);
console.log("Parsing Table:", parsingTable);
 */