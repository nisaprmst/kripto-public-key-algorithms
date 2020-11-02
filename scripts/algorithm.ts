// const BigNum = require('bignumber.js');
// import BigNum from 'bignumber.js';
import {BigInteger} from 'big-integer'
import * as BigNum from 'big-integer'

export function randomPrime() {
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

export function splitMessages(message: string){
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

export function demoElgamal() {
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
demoElgamal();

// export default generate_elgamal;