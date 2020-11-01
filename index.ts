// const BigNum = require('bignumber.js');
// import BigNum from 'bignumber.js';
import {BigInteger} from 'big-integer'
import * as BigNum from 'big-integer'

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

function encrypt(message: string) {
    console.log("Generating two random primes...");
    const p = randomPrime();
    const q = randomPrime();
    // const p = BigNum(99991);
    // const q = BigNum(99989);
    console.log("Random primes were choosen");
    const {pub, pri} = generate_RSA(p, q);
    const arr_message = splitMessages(message);
    console.log(pub);
    console.log(pri);
    const out_arr = [];
    for (const chunks of arr_message) {
        const val = BigNum(chunks, 16).modPow(pub.e, pub.n);
        out_arr.push(val.toString());
    }
    // console.log('Encrypted data: ')
    // console.log(out_arr);
    const decrypted_arr = [];
    for (const chunks of out_arr) {
        decrypted_arr.push(BigNum(chunks).modPow(pri.d, pub.n).toString(16))
    }
    // console.log('Decrypted data: ')
    // console.log(decrypted_arr);
    // console.log('Original data: ')
    // console.log(arr_message)
    let total_corrupt = 0;
    for (let i = 0; i < decrypted_arr.length; i++) {
        if (decrypted_arr[i] === arr_message[i]) {
            // console.log(`Index ${i} equal`);
        } else {
            console.log(`Index ${i} AAAAAAAAAAAAAAAAAAAAA`);
            total_corrupt++;
        }
    }
    let full_decrypted_string = '';
    for (const decrypted of decrypted_arr) {
        full_decrypted_string += toASCII(decrypted)
    }
    console.log('Returned back to ASCII: ', full_decrypted_string);
    console.log('Corrupt rate: ', total_corrupt/decrypted_arr.length)
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

const short_text = "Aku benci javascript."
const not_so_short_text="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
// console.log(splitMessages(long_text));
// encrypt(not_so_short_text)

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

demoDH()

