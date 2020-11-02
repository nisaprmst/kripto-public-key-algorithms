// const BigNum = require('bignumber.js');
// import BigNum from 'bignumber.js';
import {BigInteger} from 'big-integer'
import * as BigNum from 'big-integer'
import {Buffer} from 'buffer';

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
const RSAPubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAggkHbIGbXhM2in0tvxdYqq7dsdwI4MLoptwLw7zBdn34o+/3WUhksXKPmpmUC7g9490/z6ArV9m/O8iIoPRxklmx0FsxmY7XOLE7hLI9ZIt5+tRCgMW9lWo0AIJPn/hFOztTHWwzCdm9achB0TuTSF65HBz90rtRNYkrez4RnSWT9UhRBdN8INt2wU4vAuAJI959hCswKpmZz9He5JrPc2i5TYy2FEJzjl/M7RqCg0PW9rM9dk25OYDkJhei5TlBb1fcTxtI0GvwH/nHj63AiPbjWMQpMAjPFEk68sO3Irp4AIwOGvpg3EUjUKf3QqRY4sdLq8PvsEyYMYKlhhdCcQICxw==";

export function randomPrime() {
    let min = BigNum.one.shiftLeft(1023)
    let max = BigNum.one.shiftLeft(1024).prev()
    let isFound = false;
    let prime;
    while (!isFound) {
        let num = BigNum.randBetween(min, max)
        if (num.isProbablePrime(256)) {
            prime = num;
            isFound = true;
        }
    }
    return prime;
}

export function randomPrimeFromBitSize(bitSize) {
    let min = BigNum.one.shiftLeft(bitSize - 1)
    let max = BigNum.one.shiftLeft(bitSize).prev()
    let isFound = false;
    let prime;
    while (!isFound) {
        let num = BigNum.randBetween(min, max)
        if (num.isProbablePrime(1024)) {
            prime = num;
            isFound = true;
        }
    }
    return prime;
}


export function totient(a: BigInteger, b: BigInteger): BigInteger {
    return BigNum.lcm(a.prev(), b.prev());
}

export function generate_RSA(p: BigInteger, q: BigInteger) {
    console.log("Generating keypairs");
    let t = totient(p, q);
    let n = p.multiply(q);
    let e = BigNum(200)
    while (BigNum.gcd(e, t).notEquals(1) || t.lesserOrEquals(e)) {
        e = e.prev();
    }
    let pri = e.modInv(t);
    console.log("Success generating keypairs");
    return {
        pub : {
            n,
            e
        },
        pri : {
            d : pri
        }
    }
}

function RSA_keys_to_base64(pub, pri) {
    const exponent = pub.e as BigInteger;
    const modulus = pub.n as BigInteger;
    const privateModulus = pri.d as BigInteger;
    return {
        pub: {
            n: modulus.toArray(256),
            e: exponent.toArray(256)
        },
        pri: {
            d: privateModulus.toArray(256)
        }
    }
}

function buildPEMKey(pub) {
    const modulus = pub.n as BigNum.BaseArray;
    const exponent = pub.e as BigNum.BaseArray;
    const RSA_header = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
    console.log(modulus.value)
    const header_base64 = Buffer.from(RSA_header)
    const modulus_base64 = Buffer.from(modulus.value)
    const mid_header_base64 = Buffer.from([0x02, 0x02])
    const exponent_base64 = Buffer.from(exponent.value)
    const rsa_string = Buffer.concat([modulus_base64, mid_header_base64, exponent_base64]).toString('base64')
    // console.log(modulus_base64);
    // console.log(exponent_base64);
    // console.log(RSA_header+rsa_string);
    return RSA_header + rsa_string;
}

function buildPriKey(pri) {
    const modulus = pri.d as BigNum.BaseArray;
    const modulus_base64 = Buffer.from(modulus.value)
    const rsa_string = Buffer.concat([modulus_base64]).toString('base64')
    return rsa_string
}

function rsa_pubkey_to_obj(pub_string: string) {
    const RSA_header = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
    if (pub_string.substr(0, RSA_header.length) === RSA_header) {
        const rsa_content = pub_string.slice(RSA_header.length);
        const rsa_bin = Buffer.from(rsa_content, 'base64');
        const rsa_modulus = Buffer.from(rsa_bin.subarray(0, 256)).toJSON().data;
        const rsa_exp = Buffer.from(rsa_bin.subarray(rsa_bin.length - 1, rsa_bin.length)).toJSON().data;
        const modulus = BigNum.fromArray(rsa_modulus, 256);
        const exponent = BigNum.fromArray(rsa_exp, 256);
        // console.log(modulus);
        // console.log(exponent)
        // console.log(rsa_exp)
        // console.log("modulus length: ", rsa_modulus.length)
        return {
            n: modulus,
            e: exponent
        }
    } else {
        console.log("Not a valid RSA Pub Key");
    }
}

function rsa_prikey_to_obj(private_string: string) {
    const rsa_bin = Buffer.from(private_string, 'base64');
    const modulus = BigNum.fromArray(rsa_bin.toJSON().data);
    return {
        d: modulus
    }
}

function splitMessages(message: string){
    let arr = []
    for (let i = 0; i < message.length; i++) {
        let hex = Number(message.charCodeAt(i)).toString(16)
        arr.push(hex);
    }
    let hexString = arr.join('')
    return hexString.match(/.{1,512}/g)
}

export function toASCII(message: string) {
    let arr = []
    for (let i = 0; i < message.length; i += 2) {
        let char = String.fromCharCode(parseInt(message.substr(i, 2), 16));
        arr.push(char)
    }
    return arr.join('')
}

export function encrypt_rsa(message: string, n: BigInteger, e: BigInteger) {
    /* console.log("Generating two random primes...");
    const p = randomPrime();
    const q = randomPrime();
    console.log("Random primes were choosen");
    const {pub, pri} = generate_RSA(p, q); */
    const arr_message = splitMessages(message);
    // console.log(pub);
    // console.log(pri);
    const out_arr = [];
    for (const chunks of arr_message) {
        const val = BigNum(chunks, 16).modPow(e, n);
        out_arr.push(val.toString());
    }
    return out_arr;
    /* console.log('Encrypted data: ')
    console.log(out_arr);
    const decrypted_arr = [];
    for (const chunks of out_arr) {
        decrypted_arr.push(BigNum(chunks).modPow(pri.d, pub.n).toString(16))
    }
    console.log('Decrypted data: ')
    console.log(decrypted_arr);
    console.log('Original data: ')
    console.log(arr_message)
    let total_corrupt = 0;
    for (let i = 0; i < decrypted_arr.length; i++) {
        if (decrypted_arr[i] === arr_message[i]) {
            // console.log(`Index ${i} equal`);
        } else {
            console.log(`Index ${i} AAAAAAAAAAAAAAAAAAAAA`);
            total_corrupt++;
        }
    } */
}

export function decrypt_RSA(encrypted_arr: Array<string>, pub, pri) {
    const decrypted_arr = [];
    for (const chunk of encrypted_arr) {
        decrypted_arr.push(BigNum(chunk).modPow(pri.d, pub.n).toString(16))
    }
    return decrypted_arr;
}

export function decryptedArr2String(decryptedArr: Array<string>) {
    let full_decrypted_string = '';
    for (const decrypted of decryptedArr) {
        full_decrypted_string += toASCII(decrypted)
    }
    return full_decrypted_string;
}

export function diffieHellman(p: BigInteger, g: BigInteger) {
    const a = randomPrimeFromBitSize(8)
    const b = randomPrimeFromBitSize(8)
    const x = g.pow(a).mod(p)
    const y = g.pow(b).mod(p)
    return {x,y, aliceKey: a, bobKey: b}
}

export function getDiffieHellmanSecret(pub: BigInteger, pri: BigInteger, x: BigInteger) {
    return x.pow(pri).mod(pub)
}

export function generate_elgamal() {
    console.log("Generating elgamal keys...");
    var p = BigNum(0);
    while (!p.isPrime()) {
        p = BigNum.randBetween(2000, 6000);
    }
    // console.log(p);
    var g = BigNum.randBetween(1, p);
    var x = BigNum.randBetween(1, p.minus(1));
    var y = g.modPow(x, p);

    return  {
        "public" : {
            g,
            y,
            p
        },
        "private" : {
            x,
            p
        }
    };
}
export function encryptElgamal(pub_key, message) {
    console.log("Encrypting...");
    const p = pub_key.p;
    var messages = [];
    for (var i = 0; i < message.length; i++){  
        messages.push(BigNum(message.charCodeAt(i)));
    }
    // console.log(messages);
    var k = BigNum.randBetween(1, p.minus(1));
    var ctext = "";
    for (var i = 0; i < messages.length; i++) {
        var a = pub_key.g.modPow(k, p);
        var b = messages[i].multiply(pub_key.y.modPow(k, p)).mod(p);
        ctext = ctext + a + '-' + b;
        if (i < messages.length-1) {
            ctext += ' ';
        }
    }    
    return ctext;
}

export function decryptElgamal(priv_key, ctext) {
    console.log("Decrypting...");
    var plain = "";
    const p = priv_key.p;
    const messages = ctext.split(' ');

    for (var i = 0; i < messages.length; i++) {
        console.log(messages[i]);
        const mes = messages[i].split('-');
        console.log(mes[0]);
        let a = BigNum(parseInt(mes[0]));
        let b = BigNum(parseInt(mes[1]));
        let dec = b.multiply(a.modPow(priv_key.x, p).modInv(p)).mod(p); 
        console.log(dec);
        plain += String.fromCharCode(parseInt(dec.toString()));
    }
    return plain;
}

export function fromStr(ctext) {
    var splitted = ctext.split(' ');
}

const short_text = "Aku benci javascript."
const not_so_short_text="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
// console.log(splitMessages(long_text));
// encryptElgamal(not_so_short_text)

export function demoDH() {
    console.log("Attempting DH Key Exchange")
    const p = randomPrimeFromBitSize(256)
    const q = randomPrimeFromBitSize(256)
    console.log('P:', p)
    console.log('Q:', q)

    const dhKeys = diffieHellman(p, q)
    const secretAlice = getDiffieHellmanSecret(p, dhKeys.aliceKey, dhKeys.y)
    const secretBob = getDiffieHellmanSecret(p, dhKeys.bobKey, dhKeys.x)
    console.log(secretAlice, secretBob)
}

export function demoRSA() {
    const p = randomPrime();
    const q = randomPrime();
    const keys = generate_RSA(p, q);
    const encryptedArr = encrypt_rsa(short_text, keys.pub.n, keys.pub.e);
    console.log('Encrypted Number Array: ', encryptedArr);
    const decryptedArr = decrypt_RSA(encryptedArr, keys.pub, keys.pri);
    const decryptedString = decryptedArr2String(decryptedArr);
    console.log('Decrypted string: ', decryptedString);
}

function demoGenRSA() {
    const p = randomPrime();
    const q = randomPrime();
    const keys = generate_RSA(p,q);
    const base64Keys = RSA_keys_to_base64(keys.pub, keys.pri);
    console.log(base64Keys);
    return base64Keys;
}

function demoGeneratePubPriKey(base64Keys) {
    const out_keys = {
        pub: buildPEMKey(base64Keys.pub),
        pri: buildPriKey(base64Keys.pri)
    }
    console.log("demogeneratepubprikeey: ", out_keys)
    return out_keys
}

function demoMakePubRSA() {
    const p = randomPrime()
    const q = randomPrime()
    const keys = generate_RSA(p, q)
    const base64keys = RSA_keys_to_base64(keys.pub, keys.pri)
    buildPEMKey(base64keys.pub);
}

function demoElgamal() {
    console.log("");
    var keys = generate_elgamal();
    var ctext = encryptElgamal(keys.public, short_text);
    console.log("This is the encrypted message:");
    console.log(ctext);
    var plain = decryptElgamal(keys.private, ctext);
    console.log("Plain text:");
    console.log(plain);
}

// demoDH()
// demoRSA()
// demoMakePubRSA()
// demoGenRSA()
// demoElgamal();

// console.log(rsa_pubkey_to_obj(RSAPubKey))
const rawKeys = demoGenRSA();
const encodedkeys = demoGeneratePubPriKey(rawKeys);
const decodedKeys = {
    pub: rsa_pubkey_to_obj(encodedkeys.pub),
    pri: rsa_prikey_to_obj(encodedkeys.pri)
}
// console.log("Raw", rawKeys)
console.log(BigNum.fromArray(rawKeys.pub.n.value, 256))
console.log("FromRaw", decodedKeys)


// export default generate_elgamal;
// const a = BigNum('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
// const b = BigNum('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
// const c = a.multiply(b)
// console.log(c.toString())
