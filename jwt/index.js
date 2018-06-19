const crypto = require('crypto');
const forge  = require('node-forge');
const jws    = require('jws-jwk');

const { parseJwk, jwkBase64Regenerate } = require('./key.js');

class JWT {

    constructor(payload) {
        if(payload)
            this.setPayload(payload);
    }

    setPayload(payload) {
        payload = payload.split(".");
        const protect = (new Buffer(payload[0], "base64")).toString("utf8");
        
        if(payload.length !== 5)
            throw('Wrong token provided')

        this.headers        = JSON.parse(protect);
        this.encrypted_key  = new Buffer(payload[1], "base64");
        this.iv             = new Buffer(payload[2], "base64");
        this.ciphertext     = new Buffer(payload[3], "base64");
        this.tag            = new Buffer(payload[4], "base64");
    }

    loadPem(path) {
        const fs = require('fs');
        const pem = fs.readFileSync(path).toString();
        return this.setPem(pem);
    }

    setPem(pem) {
        this.privateKey = forge.pki.privateKeyFromPem(pem);
    }

    setJwk(jwk) {
        this.privateKey = parseJwk(jwk);
    }
    
    setIssuerKey(key) {
        this.issuerKey = key;
    }

    decryptKeys() {
        const key = this.privateKey.decrypt(this.encrypted_key, 'RSA-OAEP', {
            md: forge.md.sha1.create(),
            mgf1: {
                md: forge.md.sha1.create()
            }
        });

        // https://tools.ietf.org/html/rfc7516#appendix-A.4.2
        const buff = new Buffer(key, 'binary');
        return {
            mac: buff.slice(0, 16),
            aes: buff.slice(16, 32)
        }
    }

    decrypt() {
        const keys = this.decryptKeys();
        
        const encryptdata = this.ciphertext; //.toString('binary');

        var decipher = crypto.createDecipheriv('aes-128-cbc', keys.aes, this.iv),
            dec = decipher.update(encryptdata, 'binary', 'utf-8');
        dec += decipher.final('utf-8');
        return dec;
    }

    parse(shouldVerify = true) {
        const decrypted = this.decrypt();
        let results = decrypted.split(".");
        var result = {
            header: JSON.parse(forge.util.decode64(results[0]).split('\u0000').join('')),
            payload: JSON.parse(forge.util.decode64(results[1]).split('\u0000').join('')),
            signature: results[2],
        };

        if(!shouldVerify)
            return result;
        
        if(!this.issuerKey)
            throw('Issuer key not found, the given jwt signature could not be verified');

        if (!jws.verify(decrypted, this.issuerKey))
            throw('Wrong jwt signature found.')

        return result
    }
}

JWT.parseJwk = parseJwk;
JWT.jwkBase64Regenerate = jwkBase64Regenerate
module.exports = JWT