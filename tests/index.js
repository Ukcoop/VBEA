const vbea = require("../VBEA.js");
const decloration = require("./independince.js");
const testStr = "one small step for man, one gient leap for mankined."; 

let vbeaCrypt = new vbea(20);

console.log('testing random key...');

let prKey = vbeaCrypt.genKey();
let pbKey = vbeaCrypt.getPubKey(prKey);
let pbKeyEncoded = vbeaCrypt.encodePubKey(pbKey);
let prKeyEncoded = vbeaCrypt.encodePrivKey(prKey);
let data = vbeaCrypt.encrypt(decloration,pbKeyEncoded);
let decrypted = vbeaCrypt.decrypt(data,prKeyEncoded);
let test1 = (decrypted == decloration) == true ? "PASS" : "FAIL";
console.log(test1);

console.log('testing sedded key...');

prKey = vbeaCrypt.SeedGenKey(testStr);
pbKey = vbeaCrypt.getPubKey(prKey);
pbKeyEncoded = vbeaCrypt.encodePubKey(pbKey);
prKeyEncoded = vbeaCrypt.encodePrivKey(prKey);
data = vbeaCrypt.encrypt(decloration,pbKeyEncoded);
decrypted = vbeaCrypt.decrypt(data,prKeyEncoded);
let test2 = (decrypted == decloration) == true ? "PASS" : "FAIL";
console.log(test2);

console.log('testing string compression...');

let testString = vbeaCrypt.compressString(testStr);
let decompressed = vbeaCrypt.decompressString(testString);
let test3 = (decompressed == testStr) == true ? "PASS" : "FAIL";
console.log(test3);