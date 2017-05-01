import assert from "assert"
import fs from "fs"
import jwt from "./../lib/index"

describe('jwt library', () => {

    const publicKey = fs.readFileSync('./test/secret.key.pub', 'utf8')
    const privateKey = fs.readFileSync('./test/secret.key', 'utf8')

    const payload = {
        "iss": "https:\/\/oauth.example.com",
        "sub": "Brian",
        "exp": 1494017009789
    }

    describe('decode', () => {
        it('should return a payload json', () => {
            assert.deepEqual(payload, jwt.decode(jwt.encode(payload, privateKey), publicKey))
        })
    })
})
