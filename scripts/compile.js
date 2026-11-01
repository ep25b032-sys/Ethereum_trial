const solc = require(process.env.SOLC || 'solc'); const fs = require('fs');
const out = {};
for (const f of ['TestToken','Vault']) {
  const input = {language:'Solidity', sources:{[f+'.sol']:{content:fs.readFileSync(__dirname+'/../contracts/'+f+'.sol','utf8')}},
    settings:{evmVersion:'paris', optimizer:{enabled:true,runs:200}, outputSelection:{'*':{'*':['abi','evm.bytecode.object']}}}};
  const r = JSON.parse(solc.compile(JSON.stringify(input)));
  if (r.errors && r.errors.some(e=>e.severity==='error')) { console.error(r.errors); process.exit(1); }
  const c = r.contracts[f+'.sol'][f]; out[f] = {abi:c.abi, bytecode:'0x'+c.evm.bytecode.object};
}
fs.writeFileSync(__dirname+'/../build/contracts.json', JSON.stringify(out));
console.log('compiled', Object.keys(out));
