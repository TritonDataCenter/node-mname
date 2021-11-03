/*
 * Copyright (c) 2017 Joyent, Inc
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/*
 * SIG(0) Signatures for DNS (see RFC2931) -- public key signatures over
 * DNS requests and responses.
 *
 * Structurally almost identical to TSIG signatures -- but with different
 * backing crypto.
 */

module.exports = {
        isSupportedKey: isSupportedKey,
        signRequest: signRequest,
        signResponse: signResponse,
        signTcpContinuation: signTcpContinuation,
        verifyRequest: verifyRequest,
        verifyResponse: verifyResponse,
        verifyTcpContinuation: verifyTcpContinuation
};

var protocol = require('./protocol');
var assert = require('assert-plus');
var crypto = require('crypto');

var ALGOS = {
        'rsa-sha1' : 5,
        'rsa-sha256' : 8,
        'rsa-sha512' : 10,
        'ecdsa-p256-sha256' : 13,
        'ecdsa-p384-sha384' : 14,
        'ed25519' : 15
};

var ALGOREV = {};
Object.keys(ALGOS).forEach(function (k) {
        ALGOREV[ALGOS[k]] = k.toUpperCase();
});

function assertKey(key) {
        assert.string(key.name, 'key.name');
        assert.string(key.algorithm, 'key.algorithm');
        assert.buffer(key.publicKey, 'key.data');
        assert.number(ALGOS[key.algorithm], 'supported algorithm');
}

function isSupportedKey(key) {
        return (key.name && key.algorithm && key.privateKey &&
            key.publicKey && ALGOS[key.algorithm]);
}

function verifyRequest(msg, keys) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'sig0SignDataReq'));
}

function verifyResponse(msg, keys, reqMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.object(reqMsg, 'signedRequestMessage');
        assert.object(reqMsg.header, 'signedRequestMessage.header');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'sig0SignDataResp', reqMsg));
}

function verifyTcpContinuation(msg, keys, lastMsg) {
        throw (new Error('SIG0 continuations for TCP not supported'));
}

function signRequest(msg, key) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        return (sign(msg, key, 'sig0SignDataReq'));
}

function signResponse(msg, key, reqMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        return (sign(msg, key, 'sig0SignDataResp', reqMsg));
}

function signTcpContinuation(msg, key, lastMsg) {
        throw (new Error('SIG0 continuations for TCP not supported'));
}

/*
 * SIG0 verify works slightly different from TSIG verify:
 *
 * dns_dnssec_verifymessage() in:
 * https://github.com/openbsd/src/blob/master/usr.sbin/bind/lib/dns/dnssec.c
 * vs
 * https://github.com/openbsd/src/blob/master/usr.sbin/bind/lib/dns/tsig.c#L831
 *
 * Basically, we feed our hash with the bare-SIG0, followed by the
 * query chain with SIG0 removed. TSIG does this sort of the other way
 * around.
 */
function verify(msg, keys, format, reqMsg) {
        // deep-copy our message, with intact headers.
        var newMsg =
            protocol.decode(protocol.encode(msg, 'message'), 'message');
        var sig0 = newMsg.additional.pop();
        assert.strictEqual(sig0.rtype, protocol.queryTypes.SIG0);
        newMsg.header.arCount--;

        var kname = sig0.rdata.signername;
        var key = keys[kname];
        if (key === undefined)
                throw (new Error('Unknown SIG0 key "' + kname + '"'));
        assertKey(key);

        var algo = sig0.rdata.algorithm;
        assert.strictEqual(algo, ALGOS[key.algorithm], 'matching algorithm');

        var signature = sig0.rdata.signature; // Save what we're verifying.
        sig0.rdata.signature = Buffer(0);

        var blob = protocol.encode(sig0, format); // digest SIG0
        assert.buffer(blob);

        var verifier = crypto.createVerify(ALGOREV[algo]);
        verifier.update(blob);

        // consume the request, if any
        if (reqMsg !== undefined) {
                blob = protocol.encode(reqMsg, 'message');
                assert.buffer(blob);
                verifier.update(blob);
        }
        blob = protocol.encode(newMsg, 'message');
        verifier.update(blob);

        var cryptoVerified = verifier.verify(key.publicKey, signature);

        // check expiration against issuance/inception and expiration.
        var now = new Date().getTime() / 1000;
        var validTimeSignature =
            (now < sig0.rdata.expiration && now > sig0.rdata.inception);

        return (cryptoVerified && validTimeSignature);
}

/*
 * SIG0 signing works slightly differently from TSIG signing.
 *
 * Feed the hash our SIG0 header, then the query (if any), then the
 * header and body of the current message.
 */
function sign(msg, key, format, reqMsg) {
        var algo = ALGOS[key.algorithm];

        var sig0 = {};
        sig0.name = ''; // single zero octet, per RFC
        sig0.rtype = protocol.queryTypes.SIG0;
        sig0.rclass = protocol.qClasses.ANY;
        sig0.rdata = {};
        sig0.rdata.typecovered = 0;
        sig0.rdata.algorithm = algo;
        sig0.rdata.labels = 0;
        sig0.rdata.originalttl = 0;
        sig0.rdata.keytag = key.tag;
        sig0.rdata.signername = key.name;

        var fudge = 300;
        var now = new Date().getTime() / 1000;
        sig0.rdata.expiration = now + fudge;
        sig0.rdata.inception = now - fudge;
        sig0.rdata.signature = new Buffer(0);

        var blob = protocol.encode(sig0, format);
        assert.buffer(blob);

        var signer = crypto.createSign(ALGOREV[algo]);
        signer.update(blob);

        // consume the request, if any
        if (reqMsg !== undefined) {
                blob = protocol.encode(reqMsg, 'message');
                assert.buffer(blob);
                signer.update(blob);
        }
        blob = protocol.encode(msg, 'message');
        assert.buffer(blob);
        signer.update(blob);
        var signature_data = signer.sign(key.privateKey);

        var signature = {};
        signature.name = ''; // single zero octet, per RFC
        signature.rtype = protocol.queryTypes.SIG0;
        signature.rclass = protocol.qClasses.ANY;
        signature.rttl = 0;
        signature.rdata = {};
        signature.rdata.signername = sig0.rdata.signername;
        signature.rdata.keytag = sig0.rdata.keytag;
        signature.rdata.labels = sig0.rdata.labels;
        signature.rdata.typecovered = 0;
        signature.rdata.originalttl = sig0.rdata.originalttl;
        signature.rdata.algorithm = sig0.rdata.algorithm;
        signature.rdata.expiration = sig0.rdata.expiration;
        signature.rdata.inception = sig0.rdata.inception;
        signature.rdata.signature = signature_data;

        msg.header.arCount++;
        msg.additional.push(signature);
}
