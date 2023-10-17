const mapNumRange = (num, inMin, inMax, outMin, outMax) =>
  ((num - inMin) * (outMax - outMin)) / (inMax - inMin) + outMin;

/**
 * the Vector Based Encryption Algorithm (VBEA)
 * origional code by Alexander L. cooper
 */
class vbea {
    constructor(keyLength = 1000) {
        this.keyLength = keyLength;
        this.genKey = () => {
            let module = new generateKey(keyLength);
            let sha256 = new sha256Comp().hasher;
            let bcrypt = new bcryptComp().hasher();
            let randArr = new secRandomArray().getArray;
            let hasher = (string) => {
               return new secureSha256Comp().hasher(string, bcrypt, sha256);
            }
            return module.genKey(randArr, hasher, sha256);
        }
        this.SeedGenKey = (seed) => {
            let module = new seddedGenrateKey(keyLength);
            let sha256 = new sha256Comp().hasher;
            let bcrypt = new bcryptComp().hasher();
            let secRand = new secRandomArray().getArray;
            let hasher = (string) => {
               return new secureSha256Comp().hasher(string, bcrypt, sha256);
            }
            return module.SeedGenKey(seed, hasher, sha256, secRand);
        }
        this.getPubKey = (PrivKey) => {
            let module = new getPubKey();
            return module.getPubKey(PrivKey);
        }
        this.encodePrivKey = (PrivKey) => {
            let module = new encodePrivKey(keyLength);
            let compressComp = new compressString().compress;
            return module.encodePrivKey(PrivKey, compressComp);
        }
        this.decodePrivKey = (encodedPrivKey) => {
            let module = new decodePrivKey(keyLength);
            let decompressComp = new decompressString().decompress;
            return module.decodePrivKey(encodedPrivKey, decompressComp);
        }
        this.encodePubKey = (PubKey) => {
            let module = new encodePubKey(keyLength);
            let compressComp = new compressString().compress;
            return module.encodePubKey(PubKey, compressComp);
        }
        this.decodePubKey = (pbStr) => {
            let module = new decodePubKey(keyLength);
            let decompressComp = new decompressString().decompress;
            return module.decodePubKey(pbStr, decompressComp);
        }
        this.encodeData = (anyEncodedDataor) => {
            let module = new encodeData(keyLength);
            let compressComp = new compressString().compress;
            return module.encodeData(anyEncodedDataor, compressComp);
        }
        this.decodeData = (encodedData) => {
            let module = new decodeData();
            let decompressComp = new decompressString().decompress;
            return module.decodeData(encodedData, decompressComp);
        }
        this.encrypt = (encodedData, anyPubKey, returnEncoded) => {
            let module = new encryptData(keyLength);
            let textToVect = new textToVector().textToVect;
            return module.encrypt(encodedData, anyPubKey, returnEncoded, this.decodePubKey, this.encodeData, textToVect);
        }
        this.decrypt = (anyEncodedData, anyPrivKey) => {
            let module = new decryptData(keyLength);
            let vectToTxt = new vectorToText().vectToTxt;
            return module.decrypt(anyEncodedData, anyPrivKey, this.decodeData, this.decodePrivKey, vectToTxt);
        }
        this.compressString = (binaryString) => {
            let module = new compressString();
            return module.compress(binaryString, { outputEncoding: "Base64" });
        }
        this.decompressString = (string) => {
            let module = new decompressString();
            return module.decompress(string, { inputEncoding: "Base64" });
        }
    }
}

class compressString {
    compress(data, options) {
        return require('./lib/lzutf8.min.js').compress(data, options);
    }
}

class decompressString {
    decompress(data, options) {
        return require('./lib/lzutf8.min.js').decompress(data, options);
    }
}

class textToVector {
    textToVect(text) {
        text = text.split("");
        let length = text.length;
        let output = [];
        for (var i = 0; i < length; i++) {
            output.push(text[i].charCodeAt() + 1);
        }
        return output;
    }
}

class vectorToText {
    vectToTxt(anyEncodedData) {
        let res = [];
        for (let i = 0; i < anyEncodedData.length; i++) {
            res.push(String.fromCharCode(anyEncodedData[i] - 1));
        }
        return res.join('');
    }
}

class bcryptComp {
    hasher() {
        return require("./lib/bcrypt.min.js");
    }
}

class secureSha256Comp {
    hasher(string, bcrypt, sha256) {
        //let salt = "$2a$13$NzIwMTMzYjZmNDE3MzU0NA"
        let salt = `$2a$10$${sha256(string).slice(0,22)}`;
        return sha256(bcrypt.hashSync(string, salt));
    }
}

class sha256Comp {
    hasher(s) {
        /**
        * Secure Hash Algorithm (SHA256)
        * http://www.webtoolkit.info/
        * Original code by Angel Marin, Paul Johnston
        **/
        var chrsz = 8;
        var hexcase = 0;

        const safe_add = (x, y) => {
            var lsw = (x & 0xFFFF) + (y & 0xFFFF);
            var msw = (x >> 16) + (y >> 16) + (lsw >> 16);
            return (msw << 16) | (lsw & 0xFFFF);
        }

        const S = (X, n) => { return (X >>> n) | (X << (32 - n)); }
        const R = (X, n) => { return (X >>> n); }
        const Ch = (x, y, z) => { return ((x & y) ^ ((~x) & z)); }
        const Maj = (x, y, z) => { return ((x & y) ^ (x & z) ^ (y & z)); }
        const Sigma0256 = (x) => { return (S(x, 2) ^ S(x, 13) ^ S(x, 22)); }
        const Sigma1256 = (x) => { return (S(x, 6) ^ S(x, 11) ^ S(x, 25)); }
        const Gamma0256 = (x) => { return (S(x, 7) ^ S(x, 18) ^ R(x, 3)); }
        const Gamma1256 = (x) => { return (S(x, 17) ^ S(x, 19) ^ R(x, 10)); }

        const core_sha256 = (m, l) => {
            var K = new Array(0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5, 0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5, 0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3, 0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174, 0xE49B69C1, 0xEFBE4786, 0xFC19DC6, 0x240CA1CC, 0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA, 0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7, 0xC6E00BF3, 0xD5A79147, 0x6CA6351, 0x14292967, 0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13, 0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85, 0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3, 0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070, 0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5, 0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3, 0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208, 0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2);
            var HASH = new Array(0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19);
            var W = new Array(64);
            var a, b, c, d, e, f, g, h, i, j;
            var T1, T2;

            m[l >> 5] |= 0x80 << (24 - l % 32);
            m[((l + 64 >> 9) << 4) + 15] = l;

            for (var i = 0; i < m.length; i += 16) {
                a = HASH[0];
                b = HASH[1];
                c = HASH[2];
                d = HASH[3];
                e = HASH[4];
                f = HASH[5];
                g = HASH[6];
                h = HASH[7];

                for (var j = 0; j < 64; j++) {
                    if (j < 16) W[j] = m[j + i];
                    else W[j] = safe_add(safe_add(safe_add(Gamma1256(W[j - 2]), W[j - 7]), Gamma0256(W[j - 15])), W[j - 16]);

                    T1 = safe_add(safe_add(safe_add(safe_add(h, Sigma1256(e)), Ch(e, f, g)), K[j]), W[j]);
                    T2 = safe_add(Sigma0256(a), Maj(a, b, c));

                    h = g;
                    g = f;
                    f = e;
                    e = safe_add(d, T1);
                    d = c;
                    c = b;
                    b = a;
                    a = safe_add(T1, T2);
                }

                HASH[0] = safe_add(a, HASH[0]);
                HASH[1] = safe_add(b, HASH[1]);
                HASH[2] = safe_add(c, HASH[2]);
                HASH[3] = safe_add(d, HASH[3]);
                HASH[4] = safe_add(e, HASH[4]);
                HASH[5] = safe_add(f, HASH[5]);
                HASH[6] = safe_add(g, HASH[6]);
                HASH[7] = safe_add(h, HASH[7]);
            }
            return HASH;
        }

        const str2binb = (str) => {
            var bin = Array();
            var mask = (1 << chrsz) - 1;
            for (var i = 0; i < str.length * chrsz; i += chrsz) {
                bin[i >> 5] |= (str.charCodeAt(i / chrsz) & mask) << (24 - i % 32);
            }
            return bin;
        }

        const Utf8Encode = (string) => {
            string = string.replace(/\r\n/g, '\n');
            var utftext = '';

            for (var n = 0; n < string.length; n++) {

                var c = string.charCodeAt(n);

                if (c < 128) {
                    utftext += String.fromCharCode(c);
                }
                else if ((c > 127) && (c < 2048)) {
                    utftext += String.fromCharCode((c >> 6) | 192);
                    utftext += String.fromCharCode((c & 63) | 128);
                }
                else {
                    utftext += String.fromCharCode((c >> 12) | 224);
                    utftext += String.fromCharCode(((c >> 6) & 63) | 128);
                    utftext += String.fromCharCode((c & 63) | 128);
                }

            }

            return utftext;
        }

        const binb2hex = (binarray) => {
            var hex_tab = hexcase ? '0123456789ABCDEF' : '0123456789abcdef';
            var str = '';
            for (var i = 0; i < binarray.length * 4; i++) {
                str += hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8 + 4)) & 0xF) +
                    hex_tab.charAt((binarray[i >> 2] >> ((3 - i % 4) * 8)) & 0xF);
            }
            return str;
        }

        s = Utf8Encode(s);
        return binb2hex(core_sha256(str2binb(s), s.length * chrsz));
    }

}

class secRandomArray {
    getArray(length, seed, min, max, hasher, sha256, exclude0, rand) {
        let res = [];
        let maxHash = '';
        let maxHashSize = 0;
        let hash = '';
        if(seed = '' && rand !== undefined) {
            seed = `${rand(0, 900719930000000)}`;
        }
        seed = hasher(seed);
        while(hash.split('').length < ((max - min).toString(16).split('').length * length)) {
            hash = hash + sha256(seed);
        }
        for(let i = 0; i < (max - min).toString(16).split('').length; i++) {
            maxHash = maxHash + "F";
        }
        maxHashSize = parseInt(maxHash, 16);
        for(let i = 0; i < length; i++) {
            let value = parseInt(mapNumRange((parseInt(hash.slice(i, i + (max - min).toString(16).split('').length), 16)), 0, maxHashSize, min, max).toFixed(0));
            value = value == 0 && exclude0 == true ? 1 : value;
            res.push(value);
        }
        return res;
    }
}

class generateKey {
    constructor(keyLength) {
        this.keyLength = keyLength;
    }
    genKey(randArr, hasher, sha256) {
        let key = [];
        let pbParams = [];
        key = randArr(this.keyLength, '', -102400000000, 102400000000, hasher, sha256, true);
        for (let i = 0; i < this.keyLength; i++) {
            key[i] = parseFloat((key[i] / 100000000).toFixed(8));
        }
        for (let i = 0; i < this.keyLength; i++) {
            let res = 0;
            let tmp = randArr(this.keyLength, '', -256, 256, hasher, sha256, true);
            for (let j = 0; j < this.keyLength; j++) {
                res += key[j] * tmp[j];
            }
            pbParams.push(parseFloat((res / key[i]).toFixed(4)));
        }
        return [key, pbParams];
    }
}

class seddedGenrateKey {
    constructor(keyLength) {
        this.keyLength = keyLength;
    }
    SeedGenKey(seed, hasher, sha256, secRand) {
        let base =  secRand(this.keyLength, seed, -102400000000, 102400000000, hasher, sha256, true);
        let pbParams = [];
        for(let i = 0; i < base.length; i++) {
            base[i] = parseFloat((base[i] / 100000000).toFixed(8));
        }
        for (let i = 0; i < this.keyLength; i++) {
            let res = 0;
            let tmp = secRand(this.keyLength, '', -256, 256, hasher, sha256, true);
            for (let j = 0; j < this.keyLength; j++) {
                res += base[j] * tmp[j];
            }
            pbParams.push(parseFloat((res / base[i]).toFixed(4)));
        }
        return [base, pbParams];
    }
}

class getPubKey {
    getPubKey(PrivKey) {
        let PubKey = [];
        for (let i = 0; i < PrivKey[0].length; i++) {
            PubKey.push(parseFloat((PrivKey[0][i] * PrivKey[1][i]).toFixed(4)));
        }
        return PubKey;
    }
}

class encodePrivKey {
    constructor(keyLength) {
        this.keyLength = keyLength;

    }
    encodePrivKey(PrivKey, compress) {
        let res = `VBEA-PRK.${this.keyLength}.`;
        let pbParams = '';
        let key = '';
        for (let i = 0; i < PrivKey[0].length; i++) {
            key = key + `${PrivKey[0][i]}` + ',';
            pbParams = pbParams + `${PrivKey[1][i]}` + ',';
        }
        res = res +
            compress(pbParams, { outputEncoding: "Base64" }) +
            '.' +
            compress(key, { outputEncoding: "Base64" });
        return res;
    }
}

class decodePrivKey {
    constructor(keyLength) {
        this.keyLength = keyLength;

    }
    decodePrivKey(encodedPrivKey, decompress) {
        let pbParams = encodedPrivKey.split(".")[2];
        let key = encodedPrivKey.split(".")[3];
        let res = [[], []];
        pbParams = decompress(pbParams, { inputEncoding: "Base64" }).split(",");
        key = decompress(key, { inputEncoding: "Base64" }).split(",");
        for (let i = 0; i < pbParams.length; i++) {
            if (key[i] !== '') {
                res[0].push(parseFloat(key[i]));
            }
            if (pbParams[i] !== '') {
                res[1].push(parseFloat(pbParams[i]));
            }
        }
        return res;
    }
}

class encodePubKey {
    constructor(keyLength) {
        this.keyLength = keyLength;
    }
    encodePubKey(PubKey, compress) {
        let res = `VBEA-PBK.${this.keyLength}.`;
        let data = '';
        for (let i = 0; i < PubKey.length; i++) {
            data = data + `${PubKey[i]}` + ',';
        }
        res = res + compress(data, { outputEncoding: "Base64" });
        return res;
    }
}

class decodePubKey {
    constructor(keyLength) {
        this.keyLength = keyLength;

    }
    decodePubKey(pbStr, decompress) {
        let tmp = pbStr.split(".")[2];
        let res = [];
        tmp = decompress(tmp, { inputEncoding: "Base64" }).split(",");
        for (let i = 0; i < tmp.length; i++) {
            if (tmp[i] !== '') {
                res.push(parseFloat(tmp[i]));
            }
        }
        return res;
    }
}

class encodeData {
    constructor(keyLength) {
        this.keyLength = keyLength;

    }
    encodeData(anyEncodedDataor, compress) {
        let res = `VBEA-data.${this.keyLength}.`;
        let data = '';
        for (let i = 0; i < vect.length; i++) {
            data = data + `${vect[i]}` + ',';
        }
        res = res + compress(data, { outputEncoding: "Base64" });
        return res;
    }
}

class decodeData {
    decodeData(encodedData, decompress) {
        let tmp = encodedData.split(".")[2];
        let res = [];
        tmp = decompress(tmp, { inputEncoding: "Base64" }).split(",");
        for (let i = 0; i < tmp.length; i++) {
            if (tmp[i] !== '') {
                res.push(parseFloat(tmp[i]));
            }
        }
        return res;
    }
}

class encryptData {
    constructor(keyLength) {
        this.keyLength = keyLength;
    }
    encrypt(encodedData, PubKey, returnEncoded, decodePubKey, encodeData, textToVect) {
        if (typeof PubKey == "string") {
            PubKey = decodePubKey(PubKey);
        }
        let res = textToVect(encodedData);
        for (let i = 0; i < (res.length % this.keyLength); i++) {
            res.push(255);
        }
        for (let i = 0; i < res.length; i++) {
            let tmp = randomFromRange((PubKey[i % this.keyLength] * 0.45), -(PubKey[i % this.keyLength] * 0.45));
            res[i] = parseFloat((res[i] * PubKey[i % this.keyLength] + tmp).toFixed(5));
        }
        if (returnEncoded) {
            res = encodeData(res);
        }
        return res;
    }
}

class decryptData {
    constructor(keyLength) {
        this.keyLength = keyLength;
    }
    decrypt(anyEncodedData, PrivKey, decodeData, decodePrivKey, vectToTxt) {
        if (typeof PrivKey == "string") {
            PrivKey = decodePrivKey(PrivKey);
        }
        if (typeof anyEncodedData == "string") {
            anyEncodedData = decodeData(anyEncodedData);
        }
        let res = [];
        let count = 0;
        for (let i = 0; i < anyEncodedData.length; i++) {
            anyEncodedData[i] = anyEncodedData[i] / PrivKey[1][i % this.keyLength];
            let tmp = parseInt((anyEncodedData[i] / PrivKey[0][i % this.keyLength]).toFixed(0));
            if (tmp !== 255) {
                count++;
            }
            res.push(tmp);
        }
        res = res.splice(0, count);
        return vectToTxt(res);
    }
}

const randomFromRange = (lowest, highest) => {
    let adjustedHigh = (highest - lowest) + 1;
    return Math.floor(Math.random() * adjustedHigh) + parseFloat(lowest);
}

class toBinary {
    toBinary(n, l) {
        n = Number(n);
        if (n == 0) return '0';
        var r = '';
        while (n != 0) {
            r = ((n & 1) ? '1' : '0') + r;
            n = n >>> 1;
        }
        let res = r.split('');
        let added = "";
        if (l > 0) {
            if (res.length < l) {
                for (let i = 0; i < (l - res.length); i++) {
                    added = added + '0';
                }
            }
        }
        res = added + res.join('');
        return res;
    }
}

module.exports = vbea;