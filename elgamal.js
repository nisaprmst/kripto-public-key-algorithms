var bigInt = require("big-integer");


function generate_keys() {
    var p = bigInt(0);
    while (!p.isPrime()) {
        p = bigInt.randBetween(2000, 6000);
    }
    // console.log(p);
    var g = bigInt.randBetween(1, p);
    var x = bigInt.randBetween(1, p.minus(1));
    var y = g.modPow(x, p);

    return  {
        "public" : {
            "g" : g,
            "y" : y,
            "p" : p
        },
        "private" : {
            "x" : x,
            "p" : p
        }
    };
}



function encrypt(pub_key, message) {
    const p = pub_key.p;

    // var m = bigInt(message);
    var messages = [];
    // while(!m.lesser(p)) {
    //     let num = bigInt.randBetween(0, p);
    //     messages.push(num);
    //     m = bigInt(m-num);
    //     console.log("lebih");
    //     console.log(m);
    // }
    // if (!m.isZero()) {
    //     messages.push(m);
    // }
    for (var i = 0; i < message.length; i++){  
        messages.push(bigInt(message.charCodeAt(i)));
    }
    console.log(messages);
    var k = bigInt.randBetween(1, p.minus(1));
    k = bigInt(1520);
    var ctext = [];
    for (var i = 0; i < messages.length; i++) {
        var a = pub_key.g.modPow(k, p);
        var b = messages[i].multiply(pub_key.y.modPow(k, p)).mod(p);
        ctext.push({
            "a" : a,
            "b" : b
        });
    }    
    return ctext;
}

function decrypt(priv_key, messages) {
    var plain = "";
    const p = priv_key.p;
    for (var i = 0; i < messages.length; i++) {
        let a = messages[i].a;
        let b = messages[i].b;
        let dec = b.multiply(a.modPow(priv_key.x, p).modInv(p)).mod(p); 
        console.log(dec);
        plain += String.fromCharCode(dec);
    }
    return plain;
}

console.log("lala");

var keys = generate_keys();

var ctext = encrypt(keys.public, "ksfdbk");
console.log(ctext);

var plain = decrypt(keys.private, ctext);
console.log(plain);
// console.log(keys.public.p);