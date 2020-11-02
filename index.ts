// const BigNum = require('bignumber.js');
// import BigNum from 'bignumber.js';
import {BigInteger} from 'big-integer'
import * as BigNum from 'big-integer'

const base64Alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

function randomPrime() {
    let min = BigNum.one.shiftLeft(1023)
    let max = BigNum.one.shiftLeft(1024).prev()
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

function randomPrimeFromBitSize(bitSize) {
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


function totient(a: BigInteger, b: BigInteger): BigInteger {
    return BigNum.lcm(a.prev(), b.prev());
}

function generate_RSA(p: BigInteger, q: BigInteger) {
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
            n: modulus.toString(64, base64Alphabet),
            e: exponent.toString(64, base64Alphabet)
        },
        pri: {
            d: privateModulus.toString(64, base64Alphabet)
        }
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

function toASCII(message: string) {
    let arr = []
    for (let i = 0; i < message.length; i += 2) {
        let char = String.fromCharCode(parseInt(message.substr(i, 2), 16));
        arr.push(char)
    }
    return arr.join('')
}

function encrypt_rsa(message: string, n: BigInteger, e: BigInteger) {
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

function decrypt_RSA(encrypted_arr: Array<string>, pub, pri) {
    const decrypted_arr = [];
    for (const chunk of encrypted_arr) {
        decrypted_arr.push(BigNum(chunk).modPow(pri.d, pub.n).toString(16))
    }
    return decrypted_arr;
}

function decryptedArr2String(decryptedArr: Array<string>) {
    let full_decrypted_string = '';
    for (const decrypted of decryptedArr) {
        full_decrypted_string += toASCII(decrypted)
    }
    return full_decrypted_string;
}

function diffieHellman(p: BigInteger, g: BigInteger) {
    const a = randomPrimeFromBitSize(8)
    const b = randomPrimeFromBitSize(8)
    const x = g.pow(a).mod(p)
    const y = g.pow(b).mod(p)
    return {x,y, aliceKey: a, bobKey: b}
}

function getDiffieHellmanSecret(pub: BigInteger, pri: BigInteger, x: BigInteger) {
    return x.pow(pri).mod(pub)
}

function generate_elgamal() {
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
function encryptElgamal(pub_key, message) {
    console.log("Encrypting...");
    const p = pub_key.p;
    var messages = [];
    for (var i = 0; i < message.length; i++){  
        messages.push(BigNum(message.charCodeAt(i)));
    }
    // console.log(messages);
    var k = BigNum.randBetween(1, p.minus(1));
    var ctext = [];
    for (var i = 0; i < messages.length; i++) {
        var a = pub_key.g.modPow(k, p);
        var b = messages[i].multiply(pub_key.y.modPow(k, p)).mod(p);
        ctext.push({
            a,
            b
        });
    }    
    return ctext;
}

function decryptElgamal(priv_key, messages) {
    console.log("Decrypting...");
    var plain = "";
    const p = priv_key.p;
    for (var i = 0; i < messages.length; i++) {
        let a = messages[i].a;
        let b = messages[i].b;
        let dec = b.multiply(a.modPow(priv_key.x, p).modInv(p)).mod(p); 
        plain += String.fromCharCode(dec);
    }
    return plain;
}


const short_text = "Aku benci javascript."
const not_so_short_text="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
// console.log(splitMessages(long_text));
// encryptElgamal(not_so_short_text)

function demoDH() {
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

function demoRSA() {
    const p = randomPrime();
    const q = randomPrime();
    const keys = generate_RSA(p, q);
    const encryptedArr = encrypt_rsa(not_so_short_text, keys.pub.n, keys.pub.e);
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

// demoGenRSA()
demoElgamal();

const a = BigNum('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
const b = BigNum('100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')
const c = a.multiply(b)
console.log(c.toString())