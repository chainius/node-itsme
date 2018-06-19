//Based on pem-jwk library
//https://github.com/dannycoates/pem-jwk

const bignum = require('bn.js');
const crypto = require('crypto');
const forge  = require('node-forge');

const zero  = new bignum(0)
const one   = new bignum(1)
const two   = new bignum(2)

function rand(low, high) {
    do {
        var b = new bignum(crypto.randomBytes(high.byteLength()))
    } while (b.cmp(low) <= 0 || b.cmp(high) >= 0)
    return b
}

function odd(n) {
    if (n.cmp(zero) === 0) {
        return zero
    }
    var r = n
    while (r.isEven()) {
        r = r.div(two)
    }
    return r
}

function rootOne(x, r, n) {
    var i = x.toRed(bignum.red(n)).redPow(r).fromRed()
    var o = zero
    while (i.cmp(one) !== 0) {
        o = i
        i = i.mul(i).mod(n)
    }
    if (o.cmp(n.sub(one)) === 0) {
        return zero
    }
    return o
}

function factor(e, d, n) {
    var k = e.mul(d).sub(one)
    var r = odd(k)
    do {
        var y = rootOne(rand(two, n), r, n)
    } while (y.cmp(zero) === 0)

    var p = y.sub(one).gcd(n)
    return {
        p: p,
        q: n.div(p)
    }
}

function recomputePrimes(jwk, enc) {
    enc = enc || 'hex'
    jwk = parse(jwk)

    var pq = factor(jwk.e, jwk.d, jwk.n)
    var p = pq.p
    var q = pq.q
    var dp = jwk.d.mod(p.sub(one))
    var dq = jwk.d.mod(q.sub(one))
    var qi = q.invm(p)

    if(enc === 'base64') {
        return {
            n: jwk.n.toBuffer().toString('base64'),
            e: jwk.e.toBuffer().toString('base64'),
            d: jwk.d.toBuffer().toString('base64'),
            p: p.toBuffer().toString('base64'),
            q: q.toBuffer().toString('base64'),
            dp: dp.toBuffer().toString('base64'),
            dq: dq.toBuffer().toString('base64'),
            qi: qi.toBuffer().toString('base64'),
        }
    }
    
    return {
        n: jwk.n.toString(enc),
        e: jwk.e.toString(enc),
        d: jwk.d.toString(enc),
        p: p.toString(enc),
        q: q.toString(enc),
        dp: dp.toString(enc),
        dq: dq.toString(enc),
        qi: qi.toString(enc)
    }
}

function parse(jwk) {
    return {
        n: string2bn(jwk.n),
        e: string2bn(jwk.e),
        d: jwk.d && string2bn(jwk.d),
        p: jwk.p && string2bn(jwk.p),
        q: jwk.q && string2bn(jwk.q),
        dp: jwk.dp && string2bn(jwk.dp),
        dq: jwk.dq && string2bn(jwk.dq),
        qi: jwk.qi && string2bn(jwk.qi)
    }
}

function string2bn(str) {
    if (/^[0-9]+$/.test(str)) {
        return new bignum(str, 10)
    }
    return new bignum(Buffer(str, 'base64'))
}

function transformBuffer(k, enc) {
    enc = enc || 'hex';
    if(!k)
        return '';
    
    return new Buffer(k, 'base64').toString(enc);
}

function jwkHexParse(jwk) {
    if(!jwk.p && jwk.d) {
        return recomputePrimes(jwk);
    }

    if(!jwk.d) {
        return {
            n: transformBuffer(jwk['n']),
            e: transformBuffer(jwk['e']),
        }
    }

    return {
        n: transformBuffer(jwk['n']),
        e: transformBuffer(jwk['e']),
        d: transformBuffer(jwk['d']),
        p: transformBuffer(jwk['p']),
        q: transformBuffer(jwk['q']),
        dp: transformBuffer(jwk['dp']),
        dq: transformBuffer(jwk['dq']),
        qi: transformBuffer(jwk['qi']),
    }
}

function jwkBase64Regenerate(jwk) {
    if(!jwk.p && jwk.d) {
        return recomputePrimes(jwk, 'base64');
    }

    return jwk
}

function parseJwk(jwk) {
    const key = jwkHexParse(jwk);

    const BigInteger = forge.jsbn.BigInteger;

    return forge.pki.setRsaPrivateKey(
        new BigInteger(key.n, 16),
        new BigInteger(key.e, 16),
        new BigInteger(key.d, 16),
        new BigInteger(key.p, 16),
        new BigInteger(key.q, 16),
        new BigInteger(key.dp, 16),
        new BigInteger(key.dq, 16),
        new BigInteger(key.qi, 16));
}

module.exports = {
    jwkHexParse,
    jwkBase64Regenerate,
    parseJwk
}