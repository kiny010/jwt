import crypto from "crypto"

const singleton = Symbol()
const singletonEnforcer = Symbol()

class JWT {

    version = "1.0.0"

    algorithmMap = {
        RS256: 'RSA-SHA256',
        RS384: 'RSA-SHA384',
        RS512: 'RSA-SHA512'
    }

    static get instance() {
        const self = this
        if(!self[singleton]) {
            self[singleton] = new JWT(singletonEnforcer)
        }
        return self[singleton]
    }

    constructor(enforcer) {
        if(enforcer !== singletonEnforcer) {
            throw "Failed to construct singleton."
        }
    }

    encode(payload, key, algorithm = 'RS512') {
        const self = this

        let header = {
            "alg": algorithm,
            "typ": "JWT"
        }

        const signingAlgorithm = self.algorithmMap[algorithm]

        const encodedHeader = self.encodeBase64(JSON.stringify(header))
        const encodedPayload = self.encodeBase64(JSON.stringify(payload))
        const encodedSignature = self.encodeBase64(self.sign([encodedHeader, encodedPayload].join('.'), key, signingAlgorithm))

        return [encodedHeader, encodedPayload, encodedSignature].join('.')
    }

    decode(token, key) {
        const self = this

        // Check token is supplied.
        if (!token) {
            throw new Error("No token supplied.")
        }

        // Check token supplied is valid.
        const segments = token.split('.')
        if (segments.length !== 3) {
            throw new Error("Token is invalid.")
        }

        const encodedHeader = segments[0]
        const encodedPayload = segments[1]

        const signature = self.decodeBase64(segments[2])
        const header = JSON.parse(self.decodeBase64(encodedHeader))
        const payload = JSON.parse(self.decodeBase64(encodedPayload))

        const algorithm = header['alg']
        const signingAlgorithm = self.algorithmMap[algorithm]

        if(!self.verify([encodedHeader, encodedPayload].join('.'), key, signingAlgorithm, signature)) {
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
        return crypto.createSign(algorithm).update(payload).sign(key, 'hex')
    }

    verify(payload, key, algorithm, signature) {
        const self = this
        return crypto.createVerify(algorithm).update(payload).verify(key, signature, 'hex')
    }

    encodeBase64(data) {
        const self = this
        return self.escapeBase64url(new Buffer(data).toString('base64'))
    }

    decodeBase64(data) {
        const self = this
        return new Buffer(self.unescapeBase64url(data), 'base64').toString('utf8')
    }

    unescapeBase64url(str) {
        return (str + '==='.slice((str.length + 3) % 4)).replace(/\-/g, '+').replace(/_/g, '/')
    }

    escapeBase64url(str) {
        return str.replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '')
    }
}

export default JWT.instance
