/*
 * Copyright (c) 2015 Trevor Orsztynowicz
 * Copyright (c) 2015 Joyent, Inc
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
var protocol = require('./protocol');
var ipaddr = require('ipaddr.js');
var queryTypes = protocol.queryTypes;
var nsRecord = require('./records/ns');
var soaRecord = require('./records/soa');
var assert = require('assert-plus');
var mod_tsig = require('./tsig');
var mod_sig0 = require('./sig0');

function Query(opts) {
        assert.object(opts, 'options');
        assert.buffer(opts.data, 'options.data');
        assert.string(opts.family, 'options.family');

        var q = protocol.decode(opts.data, 'message');
        assert.object(q);

        delete (opts.data);
        this.src = opts;
        this.family = opts.family;

        this.id = q.header.id;
        this.query = q;
        this.envelopeCount = 1;
        this.tsigKey = undefined;
        this.sig0Key = undefined;
        this.lastResponse = undefined;

        this.reset();
        this.response.header.qdCount = q.header.qdCount;
        assert.arrayOfObject(q.question);
        assert.strictEqual(q.question.length, 1);
        this.response.question = q.question;
}

Query.prototype.reset = function () {
        var q = this.query;
        this.lastResponse = this.response;
        var r = this.response = {};
        ++this.envelopeCount;

        r.header = {
                id: q.header.id,
                qdCount: 0,
                anCount: 0,
                nsCount: 0,
                arCount: 0
        };
        r.question = [];
        r.answer = [];
        r.authority = [];
        r.additional = [];

        /* Inherit the query's flags until we override them */
        r.header.flags = Object.create(q.header.flags);

        /* Respond with NOTIMP unless we set otherwise */
        r.header.flags.rcode = protocol.rCodes.NOTIMP;
        r.header.flags.qr = true;

        parseEdns.call(this);
};

function parseEdns() {
        var q = this.query;
        var r = this.response;

        if (this.family === 'udp')
                this.maxReplySize = 512;
        else
                this.maxReplySize = 65530;

        if (typeof (q.additional) === 'object') {
                var add = q.additional;
                if (!Array.isArray(add))
                        add = [add];

                var edns = add.filter(function (a) {
                        return (a.rtype === queryTypes['OPT']);
                }).pop();

                if (edns) {
                        var maxReplySize = this.maxReplySize;
                        maxReplySize = edns.rclass;
                        if (maxReplySize > 1470)
                                maxReplySize = 1470;
                        r.additional.push({
                                name: '.',
                                rtype: queryTypes['OPT'],
                                rclass: maxReplySize,
                                rttl: 0,
                                rdata: { options: [] }
                        });
                        r.header.arCount++;
                        if (this.family === 'udp')
                                this.maxReplySize = maxReplySize;
                }
        }
}

Query.prototype.answers = function answers() {
        return this.response.answer.map(function (r) {
                return {
                        name: r.name,
                        type: queryTypes[r.rtype],
                        record: r.rdata,
                        ttl: r.rttl
                };
        });
};

Query.prototype.name = function () {
        return (this.query.question[0].name);
};

Query.prototype.type = function type() {
        return (queryTypes[this.query.question[0].type]);
};

var FLAGS = {
        qr: true, aa: true, rd: true, ra: true, ad: true, cd: true,
        response: 'qr', authoritative: 'aa', recursionDesired: 'rd',
        recursionAvailable: 'ra', authenticated: 'ad', noChecking: 'cd',
        checkingDisabled: 'cd'
};

Query.prototype.testFlag = function testFlag(flag) {
        if (typeof (FLAGS[flag]) === 'string')
                flag = FLAGS[flag];
        if (FLAGS[flag] !== true)
                throw (new Error('Invalid DNS header flag "' + flag + '"'));
        return (this.query.header.flags[flag] === true);
};

Query.prototype.setFlag = function setFlag(flag) {
        if (typeof (FLAGS[flag]) === 'string')
                flag = FLAGS[flag];
        if (FLAGS[flag] !== true)
                throw (new Error('Invalid DNS header flag "' + flag + '"'));
        this.response.header.flags[flag] = true;
};

Query.prototype.clearFlag = function clearFlag(flag) {
        if (typeof (FLAGS[flag]) === 'string')
                flag = FLAGS[flag];
        if (FLAGS[flag] !== true)
                throw (new Error('Invalid DNS header flag "' + flag + '"'));
        this.response.header.flags[flag] = false;
};

Query.prototype.ixfrBase = function ixfrBase() {
        var q = this.query;
        assert.strictEqual(q.question[0].type, queryTypes['IXFR']);
        assert.arrayOfObject(q.authority);
        assert.strictEqual(q.authority[0].rtype, queryTypes['SOA']);
        return (q.authority[0].rdata.serial);
};

Query.prototype.isSigned = function isSigned() {
        var sig = this.query.additional[this.query.additional.length - 1];
        return (sig && (sig.rtype === queryTypes.TSIG ||
            sig.rtype === queryTypes.SIG0));
};

Query.prototype.verify = function verify(keys, req) {
        var result = false;
        var sig = this.query.additional[this.query.additional.length - 1];
        switch (sig.rtype) {
        case queryTypes.TSIG:
                try {
                        result = mod_tsig.verifyRequest(this.query, keys);
                } catch (err) {
                        var log = this._log || this.log;
                        if (log) {
                                log.warn({err: err}, 'error processing TSIG');
                        }
                        return (false);
                }
                /*
                 * When we get a signed shared-secret message, sign
                 * any response with the same secret.
                 */
                if (result)
                        this.tsigKey = keys[sig.name];
                return (result);
        case queryTypes.SIG0:
                try {
                        if (this.testFlag('qr')) {
                                result = mod_sig0.verifyResponse(
                                        this.query, keys, req);
                        } else {
                                result = mod_sig0.verifyRequest(
                                        this.query, keys);
                        }
                } catch (err) {
                        var log = this._log || this.log;
                        if (log) {
                                log.warn({err: err}, 'error processing SIG0');
                        }
                }
                return (result);
        default:
                return (false);
        }

};

Query.prototype.setError = function setError(name) {
        var code = protocol.rCodes[name.toUpperCase()];
        if (code === undefined) {
                // Try stripping off a leading E.
                code = protocol.rCodes[name.toUpperCase().slice(1)];
                if (code === undefined)
                        throw new Error('invalid error code %s', name);
        }
        this.response.header.flags.rcode = code;
};

Query.prototype.error = function () {
        var code = protocol.rCodes[this.response.header.flags.rcode];
        return code.toLowerCase();
};

Query.prototype.operation = function operation() {
        var h = this.query.header;
        var op = protocol.opCodes[h.flags.opcode];
        if (op === undefined)
                throw new Error('invalid operation %d', h.flags.opcode);
        if (op === 'IQUERY')
                throw new Error('iquery operations are obselete');
        return (op.toLowerCase());
};

Query.prototype.encode = function encode(recur) {
        if (this.tsigKey !== undefined) {
                if (this.lastResponse === undefined) {
                        mod_tsig.signResponse(this.response, this.tsigKey,
                            this.query);
                } else {
                        mod_tsig.signTcpContinuation(this.response,
                            this.tsigKey, this.lastResponse);
                }
        }
        if (this.sig0Key !== undefined) {
                if (this.lastResponse === undefined) {
                        mod_sig0.signResponse(this.response, this.sig0Key,
                            this.query);
                } else {
                        mod_sig0.signTcpContinuation(this.response,
                            this.sig0Key, this.lastResponse);
                }
        }

        var encoded = protocol.encode(this.response, 'message');

        if (encoded.length > this.maxReplySize) {
                if (recur || this.family !== 'udp')
                        throw (new Error('Truncated answer message ' +
                            'too large to send: ' + encoded.length + ' bytes'));

                var log = this._log || this.log;
                if (log) {
                        log.info({
                                len: encoded.length,
                                max_len: this.maxReplySize
                        }, 'truncated response sent');
                }

                var r = this.response;
                r.header.flags.tc = true;
                r.header.anCount = 0;
                r.header.nsCount = 0;
                r.header.arCount = 0;
                r.answer = [];
                r.authority = [];
                r.additional = [];
                return (encode.call(this, true));
        }
        return (encoded);
};
Query.prototype.addAuthority = function (name, record, ttl) {
        assert.string(name, 'name');
        assert.object(record, 'record');
        assert.optionalNumber(ttl, 'ttl');

        var authority = {
                name:   name,
                rclass: 1,  // INET
                rttl:   ttl || 5,
                rdata:  record
        };
        if (record instanceof nsRecord)
                authority.rtype = queryTypes['NS'];
        else if (record instanceof soaRecord)
                authority.rtype = queryTypes['SOA'];
        else
                throw (new TypeError('invalid type for authority section ' +
                    'record'));

        var r = this.response;
        r.authority.push(authority);
        r.header.nsCount++;
        // This is not great, but is necessary to be backwards compatible.
        r.header.flags.aa = true;
};
Query.prototype.addAdditional = function (name, record, ttl) {
        assert.string(name, 'name');
        assert.object(record, 'record');
        assert.optionalNumber(ttl, 'ttl');

        var add = {
                name:   name,
                rtype:  queryTypes[record._type],
                rclass: 1,  // INET
                rttl:   ttl || 5,
                rdata:  record
        };

        var r = this.response;
        r.additional.push(add);
        r.header.arCount++;
};

Query.prototype.addAnswer = function (name, record, ttl) {
        assert.string(name, 'name');
        assert.object(record, 'record');
        assert.optionalNumber(ttl, 'ttl');

        if (!queryTypes.hasOwnProperty(record._type))
                throw (new TypeError('unknown queryType: ' + record._type));

        var r = this.response;
        // return ok, we have an answer
        r.header.flags.rcode = protocol.rCodes.NOERROR;
        var answer = {
                name:   name,
                rtype:  queryTypes[record._type],
                rclass: 1,  // INET
                rttl:   ttl || 5,
                rdata:  record
        };

        r.answer.push(answer);
        r.header.anCount++;
};

function parseQuery(opts) {
        return (new Query(opts));
}

module.exports = {
        parse: parseQuery
};
