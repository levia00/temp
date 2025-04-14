function generate8086Assembly(threeAddressCode) {
    const lines = threeAddressCode.trim().split('\n');
    let assembly = [];
    let registerMap = {};
    let regPool = ['AX', 'BX', 'CX', 'DX'];
    let regIndex = 0;

    const getRegister = (operand) => {
        if (!isNaN(operand)) return operand; // immediate value
        if (!registerMap[operand]) {
            if (regIndex < regPool.length) {
                registerMap[operand] = regPool[regIndex++];
            } else {
                registerMap[operand] = 'AX';
            }
        }
        return registerMap[operand];
    };

    for (const line of lines) {
        const match = line.match(/(\w+)\s*=\s*(\w+)\s*([\+\-\*\/])\s*(\w+)/);
        if (!match) {
            console.warn(`Invalid format: ${line}`);
            continue;
        }

        const [_, result, op1, operator, op2] = match;
        const reg1 = getRegister(op1);
        const reg2 = getRegister(op2);
        const destReg = getRegister(result);

        if (operator === '+') {
            assembly.push(`MOV ${destReg}, ${reg1}`);
            assembly.push(`ADD ${destReg}, ${reg2}`);
        } else if (operator === '-') {
            assembly.push(`MOV ${destReg}, ${reg1}`);
            assembly.push(`SUB ${destReg}, ${reg2}`);
        } else if (operator === '*') {
            if (destReg !== 'AX') assembly.push(`MOV AX, ${reg1}`);
            else assembly.push(`MOV ${destReg}, ${reg1}`);
            assembly.push(`MUL ${reg2}`); 
            if (destReg !== 'AX') assembly.push(`MOV ${destReg}, AX`);
        } else if (operator === '/') {
            assembly.push(`MOV AX, ${reg1}`);
            assembly.push(`MOV DX, 0`);
            assembly.push(`DIV ${reg2}`);
            if (destReg !== 'AX') assembly.push(`MOV ${destReg}, AX`);
        }
    }

    return assembly.join('\n');
}

const tac = `
t1 = a + b
t2 = t1 - c
t3 = t2 * d
t4 = t3 / e
`;

console.log(generate8086Assembly(tac));
//sample output
/**
 * MOV CX, AX
ADD CX, BX
MOV AX, CX
SUB AX, DX
MOV AX, AX
MUL AX
MOV AX, AX
MOV DX, 0
DIV AX
 */
