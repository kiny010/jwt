import assert from "assert"
import fs from "fs"
import jwt from "./../lib/index"

describe('jwt library', () => {
    const publicKey = fs.readFileSync('./test/public.key.pub', 'utf8')
    const privateKey = fs.readFileSync('./test/private.key', 'utf8')

    const payload = {
        "iss": "https:\/\/oauth.example.com",
        "sub": "Brian",
        "exp": 1494017009789
    }

    console.log(jwt.version)

    describe('encode', () => {
        it('should return a jwt token', () => {
            assert.equal("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwczovL29hdXRoLmV4YW1wbGUuY29tIiwic3ViIjoiQnJpYW4iLCJleHAiOjE0OTQwMTcwMDk3ODl9.XQO0o5xh9Z32SR81P6AZ_6oKZMNq-zuinM0vY3HudRThZAlSVJNinNWan0VrdG6z3Q0hvEDvuQSaLrR9FuVFvfYEpFyq1iN5cvGXSEH41ufN1Ff2ylgPbCoNiKusvPdf4u76lJ3dYS0Q_hY2oopNDzVY1-BOjkM7rSrwfU-uFSc", jwt.encode(payload, privateKey))
        })
    })

    describe('decode', () => {
        it('should return a payload json', () => {
            let token = jwt.encode(payload, privateKey)
            assert.deepEqual(payload, jwt.decode(token, publicKey))
        })
    })
})
