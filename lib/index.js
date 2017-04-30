import fs from "fs"
import crypto from "crypto"

const singleton = Symbol();
const singletonEnforcer = Symbol()

const algorithmMap = {
    RS256: 'RSA-SHA256'
}

class JWT {

    version = "0.0.1"

    constructor() {}

    encode(payload, key, algorithm = 'RS256') {
        const self = this

        let header = {
            "alg": algorithm,
            "typ": "JWT"
        }

        const signingAlgorithm = algorithmMap[algorithm]
        const encodedHeader = self.encodeBase64(JSON.stringify(header))
        const encodedPayload = self.encodeBase64(JSON.stringify(payload))
        const encodedSignature = self.sign([encodedHeader, encodedPayload].join('.'), key, signingAlgorithm)

        return [encodedHeader, encodedPayload, encodedSignature].join('.')
    }

    decode(token, key) {
        const self = this

        if (!token) {
            throw new Error("No token supplied.")
        }

        const segments = token.split('.')

        if (segments.length !== 3) {
            throw new Error("Token is invalid.")
        }

        const encodedHeader = segments[0]
        const encodedPayload = segments[1]
        const encodedSignature = segments[2]
        const header = JSON.parse(self.decodeBase64(encodedHeader))
        const payload = JSON.parse(self.decodeBase64(encodedPayload))
        const algorithm = header['alg']
        const signingAlgorithm = algorithmMap[algorithm]

        if(!self.verify([encodedHeader, encodedPayload].join('.'), key, signingAlgorithm, encodedSignature)) {
            throw new Error('Signature verification failed.')
        }

        if (payload.nbf && Date.now() < payload.nbf * 1000) {
            throw new Error('Token has not been activated.')
        }

        if (payload.exp && Date.now() > payload.exp * 1000) {
            throw new Error('Token has expired.')
        }

        return payload
    }

    sign(payload, key, algorithm) {
        const self = this
        return self.escapeBase64url(crypto.createSign(algorithm).update(payload).sign(key, 'base64'))
    }

    verify(payload, key, algorithm, signature) {
        const self = this
        return crypto.createVerify(algorithm).update(payload).verify(key, self.unescapeBase64url(signature), 'base64')
    }

    encodeBase64(input) {
        const self = this
        return self.escapeBase64url(new Buffer(input).toString('base64'))
    }

    decodeBase64(input) {
        const self = this
        return new Buffer(self.unescapeBase64url(input), 'base64').toString()
    }

    unescapeBase64url(str) {
        str += new Array(5 - str.length % 4).join('=');
        return str.replace(/\-/g, '+').replace(/_/g, '/');
    }

    escapeBase64url(str) {
        return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    }
}

export default new JWT()
