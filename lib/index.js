/**
  * Json Web Token Library written in ECMAScript 6.
  *
  * index.js
  *
  * @author Brian K. Lau, https://christa.io
  * @version 1.0.0
  * Copyright (c) 2017. All rights reserved.
  */

import crypto from "crypto"
import base64url from "christa-base64url"

const singleton = Symbol()
const singletonEnforcer = Symbol()

const algorithmMap = {
    "RS256": 'RSA-SHA256',
    "RS384": 'RSA-SHA384',
    "RS512": 'RSA-SHA512'
}

class JSONWebToken {

    /**
     * Returns a shared instance of class (singleton)
     * @return {Class}
     */
    static get instance() {
        const self = this
        if(!self[singleton]) {
            self[singleton] = new JSONWebToken(singletonEnforcer)
        }
        return self[singleton]
    }

    /**
     * Constructs class instance
     * @param  {Symbol} enforcer
     * @return {Class}
     */
    constructor(enforcer) {
        const self = this
        if(enforcer !== singletonEnforcer) {
            throw "Failed to construct singleton."
        }
    }

    /**
     * Returns encoded token.
     * @param  {Object} payload
     * @param  {String} key
     * @param  {String} alg
     * @return {String}
     */
    encode(payload, key, alg = 'RS512') {
        const self = this

        let header = {
            "alg": alg,
            "typ": "JWT"
        }

        const signingAlgorithm = algorithmMap[alg]

        const encodedHeader = base64url.encode(JSON.stringify(header))
        const encodedPayload = base64url.encode(JSON.stringify(payload))
        const encodedSignature = base64url.encode(self.sign([encodedHeader, encodedPayload].join('.'), key, signingAlgorithm))

        return [encodedHeader, encodedPayload, encodedSignature].join('.')
    }

    /**
     * Returns decoded payload
     * @param  {String} token
     * @param  {String} key
     * @return {Object}
     */
    decode(token, key) {
        const self = this

        const segments = token.split('.')

        if (!token) {
            throw new Error("No token supplied.")
        }

        if (segments.length !== 3) {
            throw new Error("Token is invalid.")
        }

        const encodedHeader = segments[0]
        const encodedPayload = segments[1]
        const encodedSignature = segments[2]

        const signature = base64url.decode(encodedSignature)
        const header = JSON.parse(base64url.decode(encodedHeader))
        const payload = JSON.parse(base64url.decode(encodedPayload))

        const alg = header['alg']
        const signingAlgorithm = algorithmMap[alg]

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

    /**
     * Returns signature
     * @param  {Object} payload
     * @param  {String} key
     * @param  {String} alg
     * @return {String}
     */
    sign(payload, key, alg) {
        const self = this
        return crypto.createSign(alg)
            .update(payload)
            .sign(key, 'hex')
    }

    /**
     * Returns true if signature verification succeeded, or false
     * if verification failed.
     * @param  {Object} payload
     * @param  {String} key
     * @param  {String} alg
     * @param  {String} signature
     * @return {Boolean}
     */
    verify(payload, key, alg, signature) {
        const self = this
        return crypto.createVerify(alg)
            .update(payload)
            .verify(key, signature, 'hex')
    }
}

export default JSONWebToken.instance
