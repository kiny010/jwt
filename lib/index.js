import fs from "fs"
import crypto from "crypto"

const algorithmMap = {
    "HS256": 'sha256',
    "HS384": 'sha384',
    "HS512": 'sha512',
    "RS256": 'RSA-SHA256'
}

const typeMap = {
    "HS256": 'hmac',
    "HS384": 'hmac',
    "HS512": 'hmac',
    "RS256": 'sign'
}

class JWT {

    constructor() { }

    encode(payload, key, algorithm = 'RS256') {
        let header = {
            "alg": algorithm,
            "typ": "JWT"
        }

        const signingAlgorithm = algorithmMap[algorithm]
        const signingType  = typeMap[algorithm]

        const encodedHeader = this.encodeBase64(JSON.stringify(header))
        const encodedPayload = this.encodeBase64(JSON.stringify(payload))
        const encodedSignature = this.sign([encodedHeader, encodedPayload].join('.'), key, signingAlgorithm)

        return encodedHeader + '.' + encodedPayload + '.' + encodedSignature
    }

    decode(token, key) {
        const segments = token.split('.')

        const encodedHeader = segments[0]
        const encodedPayload = segments[1]
        const encodedSignature = segments[2]

        const header = JSON.parse(this.decodeBase64(encodedHeader))
        const payload = JSON.parse(this.decodeBase64(encodedPayload))

        const algorithm = header['alg']
        const signingMethod = algorithmMap[algorithm]

        if(!this.verify([encodedHeader, encodedPayload].join('.'), key, signingMethod, encodedSignature)) {
            throw new Error('Signature verification failed.')
        }

        return payload
    }

    sign(payload, key, method) {
        return crypto.createSign(method).update(payload).sign(key, 'base64')
    }

    verify(payload, key, method, signature) {
        return crypto.createVerify(method).update(payload).verify(key, signature, 'base64')
    }

    encodeBase64(input) {
        return new Buffer(input).toString('base64')
    }

    decodeBase64(input) {
        return new Buffer(input, 'base64').toString()
    }
}

export let jwt = new JWT()

var payload = {
  "sub": "Brian",
  "iss": "https:\/\/oauth.example.com",
  "exp": 1357255788,
  "admin": true
}

let publicKey = fs.readFileSync('./lib/jwtRS256.key.pub', 'utf8')
let privateKey = fs.readFileSync('./lib/jwtRS256.key', 'utf8')
let token = jwt.encode(payload, privateKey)
// console.log(token)
let decoded = jwt.decode(token, publicKey)
console.log(decoded)
