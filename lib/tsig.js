/*
 * Copyright (c) 2016 Joyent, Inc
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
 * Transaction Signatures for DNS (see RFC2845)
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
        'hmac-md5': 'md5',
        'hmac-md5.sig-alg.reg.int': 'md5',
        'hmac-sha1': 'sha1',
        'hmac-sha256': 'sha256',
        'hmac-sha384': 'sha384',
        'hmac-sha512': 'sha512'
};
var ALGOREV = {};
Object.keys(ALGOS).forEach(function (k) {
        ALGOREV[ALGOS[k]] = k;
});

function assertKey(key) {
        assert.string(key.name, 'key.name');
        assert.string(key.algorithm, 'key.algorithm');
        assert.buffer(key.data, 'key.data');
        assert.string(ALGOS[key.algorithm], 'supported algorithm');
}

function isSupportedKey(key) {
        return (key.name && key.algorithm && key.data && ALGOS[key.algorithm]);
}

function verifyRequest(msg, keys) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'tsigSignDataReq'));
}

function verifyResponse(msg, keys, reqMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.object(reqMsg, 'signedRequestMessage');
        assert.object(reqMsg.header, 'signedRequestMessage.header');
        assert.arrayOfObject(reqMsg.additional,
            'signedRequestMessage.additional');
        var tsigs = reqMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.TSIG);
        });
        assert.ok(tsigs.length === 1, 'signedRequestMessage TSIG signature');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'tsigSignDataResp', tsigs[0].rdata.mac));
}

function verifyTcpContinuation(msg, keys, lastMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assert.object(keys, 'keys');
        assert.object(lastMsg, 'signedLastMessage');
        assert.object(lastMsg.header, 'signedLastMessage.header');
        assert.arrayOfObject(lastMsg.additional,
            'signedLastMessage.additional');
        var tsigs = lastMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.TSIG);
        });
        assert.ok(tsigs.length === 1, 'signedLastMessage TSIG signature');
        assert.ok(Object.keys(keys).length > 0, 'non-empty keys object');
        return (verify(msg, keys, 'tsigSignTcp', tsigs[0].rdata.mac));
}

function signRequest(msg, key) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        return (sign(msg, key, 'tsigSignDataReq'));
}

function signResponse(msg, key, reqMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        assert.object(reqMsg.header, 'signedRequestMessage.header');
        assert.arrayOfObject(reqMsg.additional,
            'signedRequestMessage.additional');
        var tsigs = reqMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.TSIG);
        });
        assert.ok(tsigs.length === 1, 'signedRequestMessage TSIG signature');
        return (sign(msg, key, 'tsigSignDataResp', tsigs[0].rdata.mac));
}

function signTcpContinuation(msg, key, lastMsg) {
        assert.object(msg, 'message');
        assert.object(msg.header, 'message.header');
        assertKey(key);
        assert.object(lastMsg.header, 'signedLastMessage.header');
        assert.arrayOfObject(lastMsg.additional,
            'signedLastMessage.additional');
        var tsigs = lastMsg.additional.filter(function (rr) {
                return (rr.rtype === protocol.queryTypes.TSIG);
        });
        assert.ok(tsigs.length === 1, 'signedLastMessage TSIG signature');
        return (sign(msg, key, 'tsigSignTcp', tsigs[0].rdata.mac));
}

function verify(msg, keys, format, reqMac) {
        var newMsg = Object.create(msg);
        newMsg.header = Object.create(msg.header);
        newMsg.additional = msg.additional.slice();
        var tsig = newMsg.additional.pop();
        assert.strictEqual(tsig.rtype, protocol.queryTypes.TSIG);
        newMsg.header.arCount--;

        var kname = tsig.name;
        var key = keys[kname];
        if (key === undefined)
                throw (new Error('Unknown TSIG key "' + kname + '"'));
        assertKey(key);

        var algo = ALGOS[tsig.rdata.algorithm];
        assert.strictEqual(algo, ALGOS[key.algorithm], 'matching algorithm');

        var tsign = {};
        tsign.message = protocol.encode(newMsg, 'message');
        tsign.rname = tsig.name;
        assert.strictEqual(tsig.rclass, protocol.qClasses.ANY);
        tsign.rclass = tsig.rclass;
        assert.strictEqual(tsig.rttl, 0);
        tsign.rttl = tsig.rttl;

        tsign.algorithm = tsig.rdata.algorithm;
        tsign.time = tsig.rdata.time;
        tsign.fudge = tsig.rdata.fudge;
        tsign.error = tsig.rdata.error;
        tsign.other = tsig.rdata.other;
        if (reqMac !== undefined)
                tsign.rmac = reqMac;

        var now = new Date();
        var delta = now.getTime() - tsign.time.getTime();

        var blob = protocol.encode(tsign, format);
        assert.buffer(blob);

        var hmac = crypto.createHmac(algo, key.data);
        hmac.update(blob);
        var digest = hmac.digest();

        var comp1 = crypto.createHmac(algo, key.data).
            update(tsig.rdata.mac).digest().toString('base64');
        var comp2 = crypto.createHmac(algo, key.data).
            update(digest).digest().toString('base64');

        return (comp1 === comp2 && delta > 0 && delta < tsign.fudge * 1000);
}

function sign(msg, key, format, reqMac) {
        var algo = ALGOS[key.algorithm];

        var tsign = {};
        if (reqMac !== undefined)
                tsign.rmac = reqMac;

        tsign.message = protocol.encode(msg, 'message');
        tsign.rname = key.name;
        tsign.rclass = protocol.qClasses.ANY;
        tsign.rttl = 0;

        tsign.algorithm = ALGOREV[algo];
        tsign.time = new Date();
        tsign.fudge = 300;
        tsign.error = 0;
        tsign.other = new Buffer(0);

        var blob = protocol.encode(tsign, format);
        assert.buffer(blob);

        var hmac = crypto.createHmac(algo, key.data);
        hmac.update(blob);
        var digest = hmac.digest();

        var tsig = {};
        tsig.name = tsign.rname;
        tsig.rtype = protocol.queryTypes.TSIG;
        tsig.rclass = tsign.rclass;
        tsig.rttl = tsign.rttl;
        tsig.rdata = {};
        tsig.rdata.algorithm = tsign.algorithm;
        tsig.rdata.time = tsign.time;
        tsig.rdata.fudge = tsign.fudge;
        tsig.rdata.origid = msg.header.id;
        tsig.rdata.error = tsign.error;
        tsig.rdata.other = tsign.other;

        tsig.rdata.mac = digest;

        msg.header.arCount++;
        msg.additional.push(tsig);
}
