# the Vector Based Encryption Algorithm

This is an implementation of a quantum-resistant encryption algorithm developed from a NIST competition and implemented by Alexander L Cooper (the owner of this github account).

# what could be added?
One thing that i would add in the future is a way to sign messages since that is a function of RSA and would be used in the security of a blockhain network.

# usage
---
This is how you import the library.

```js
//if useing node, import this first
const VBEA = reqire('./VBEA.js');

//default length is 1000 (and is recomended)
const encryption = new VBEA(keyLength);
```

## genKey()
---
```js
encryption.genKey();
```
This function takes no arguments and returns a key in vector format, which you can convert to string format with encodePrKey().

NOTE: for a 1000 length key, it may take ~131 seconds, this is becouse it uses the bcrypt hashing algorithm to be more or less uncrackable

## seddedGenKey()
---
```js
encryption.seddedGenKey();
```
This function takes a seed as a string and returns a key in vector format, which you can convert to string format with encodePrKey().

NOTE: for a 1000 length key, it may take ~131 seconds, this is becouse it uses the bcrypt hashing algorithm to be more or less uncrackable

## getPubKey()
---
```js
encryption.getPubKey(PrivKey);
```
This function accepts a private key and returns the public key that corresponds to that private key.

## encodePrivKey()
---
```js
encryption.encodePrivKey(PrivKey);
```
This function encodes a private key into the string format.

## decodePrivKey()
---
```js
encryption.decodePrivKey(encodedPrivKey);
```
This function converts the string format of a private key to vector format.

## encodePubKey()
---
```js
encryption.encodePubKey(PubKey);
```
This function encodes a public key in the string format.

## decodePubKey()
---
```js
encryption.decodePubKey(encodedPubKey);
```
This function converts the string format of a public key to vector format.

## encodeData()
---
```js
encryption.encodeData(dataVector);
```
This function encodes a vector of encrypted data in string format from a vector of encrypted data.

## decodePrKey()
---
```js
encryption.decodeData(encodedData);
```
This method converts an encrypted piece of data in the string format into vector format.

## encrypt()
---
```js
encryption.encrypt(string, anyPubKey, returnEncoded);
```
This function accepts a string to encode, a public key for either the string or vector format, and a boolean indicating whether you want to receive the encoded data as a string or a vector. And returns the encrypted data piece.

## decrypt()
---
```js
encryption.decrypt(anyEncodedData, anyPrivKey);
```
This function takes an encrypted piece of data in either string or vector format and a private key in either string or vector format and returns the decrypted string.

## compressString()
---
```js
encryption.compressString(string);
```

This function takes a string (such as one containing binary) and compresses it into base64; it is not directly base 64; instead, it employs a compression method.

## decompressString()
---
```js
encryption.decompressString(string);
```

The function takes a base64-compressed string from compressString() and decompresses it back into what it was compressed into.