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
/*
 *  # Protocol
 *
 *  Stores protocol definitions and their primitives as well as any other
 *  associated protocol constants
 *
 *  ## References
 *
 *  http://tools.ietf.org/html/rfc1035
 *  http://tools.ietf.org/html/rfc4408
 *  http://tools.ietf.org/html/rfc2782
 *  http://tools.ietf.org/html/rfc3596
 *
 *  ## Notes
 *
 *  - Even though RFC1035 says that questions should support multiple queries
 *    the reality is *nobody* does this. MS DNS doesn't support it and
 *    apparently BIND doesn't support it as well. That implies no client side
 *    tools do either - so we will not worry about that complication.
 *
 *  - DNS Extensions have been proposed, but another case of chicken-and-egg.
 *    These extensions make it _possible_ to have DNS queries over 512 bytes in
 *    length, but because it is not universally supported, nobody does it.
 */


var ipaddr = require('ipaddr.js');
var assert = require('assert-plus');
var DNSBuffer = require('./dns-buffer');
var util = require('util');

function DNSProtoBuffer(opts) {
        assert.object(opts, 'options');
        assert.optionalBuffer(opts.buffer, 'options.buffer');
        DNSBuffer.call(this, opts);
}
util.inherits(DNSProtoBuffer, DNSBuffer);

DNSProtoBuffer.prototype.readRecord = function (ctx) {
        var r = {};
        var kctx = { parent: ctx };
        kctx.name = (r.name = this.readName());
        kctx.rtype = (r.rtype = this.readUInt16());
        r.rclass = this.readUInt16();
        r.rttl = this.readUInt32();
        r.rdata = this.readNSData(kctx);
        return (r);
};

DNSProtoBuffer.prototype.writeRecord = function (v, ctx) {
        assert.object(v, 'record');
        this.writeName(v.name);
        this.writeUInt16(v.rtype);
        this.writeUInt16(v.rclass);
        this.writeUInt32(v.rttl);
        var kctx = { parent: ctx, rtype: v.rtype, name: v.name };
        this.writeNSData(v.rdata, kctx);
};

DNSProtoBuffer.prototype.readQuestion = function (ctx) {
        var r = {};
        r.name = this.readName();
        r.type = this.readUInt16();
        r.qclass = this.readUInt16();
        return (r);
};

DNSProtoBuffer.prototype.writeQuestion = function (v, ctx) {
        assert.object(v, 'question');
        this.writeName(v.name);
        this.writeUInt16(v.type);
        this.writeUInt16(v.qclass);
};

DNSProtoBuffer.prototype.readHeader = function (ctx) {
        var r = {};
        r.id = this.readUInt16();
        r.flags = this.readNSFlags(ctx);
        r.qdCount = this.readUInt16();
        r.anCount = this.readUInt16();
        r.nsCount = this.readUInt16();
        r.arCount = this.readUInt16();
        return (r);
};

DNSProtoBuffer.prototype.writeHeader = function (v, ctx) {
        assert.object(v, 'header');
        this.writeUInt16(v.id);
        this.writeNSFlags(v.flags, { parent: ctx });
        this.writeUInt16(v.qdCount);
        this.writeUInt16(v.anCount);
        this.writeUInt16(v.nsCount);
        this.writeUInt16(v.arCount);
};

DNSProtoBuffer.prototype.readSOA = function (ctx) {
        var r = {};
        r.host = this.readName();
        r.admin = this.readName();
        r.serial = this.readUInt32();
        r.refresh = this.readUInt32();
        r.retry = this.readUInt32();
        r.expire = this.readUInt32();
        r.ttl = this.readUInt32();
        return (r);
};

DNSProtoBuffer.prototype.writeSOA = function (v, ctx) {
        assert.object(v, 'soa');
        this.writeName(v.host);
        this.writeName(v.admin);
        this.writeUInt32(v.serial);
        this.writeUInt32(v.refresh);
        this.writeUInt32(v.retry);
        this.writeUInt32(v.expire);
        this.writeUInt32(v.ttl);
};

DNSProtoBuffer.prototype.readMX = function (ctx) {
        var r = {};
        r.priority = this.readUInt16();
        r.exchange = this.readName();
        return (r);
};

DNSProtoBuffer.prototype.writeMX = function (v, ctx) {
        assert.object(v, 'mx');
        this.writeUInt16(v.priority);
        this.writeName(v.exchange);
};

DNSProtoBuffer.prototype.readSRV = function (ctx) {
        var r = {};
        r.priority = this.readUInt16();
        r.weight = this.readUInt16();
        r.port = this.readUInt16();
        r.target = this.readName();
        return (r);
};

DNSProtoBuffer.prototype.writeSRV = function (v, ctx) {
        assert.object(v, 'srv');
        this.writeUInt16(v.priority);
        this.writeUInt16(v.weight);
        this.writeUInt16(v.port);
        this.writeName(v.target);
};

DNSProtoBuffer.prototype.readTSIG = function (ctx) {
        var r = {};
        r.algorithm = this.readName();
        r.time = this.readDateTime48();
        r.fudge = this.readUInt16();
        r.mac = this.readLengthPrefixed(2, function (cbuf) {
                return (cbuf.remainder());
        });
        r.origid = this.readUInt16();
        r.error = this.readUInt16();
        r.other = this.readLengthPrefixed(2, function (cbuf) {
                return (cbuf.remainder());
        });
        return (r);
};

DNSProtoBuffer.prototype.writeTSIG = function (v, ctx) {
        assert.object(v, 'tsig');
        this.writeNamePlain(v.algorithm);
        this.writeDateTime48(v.time, 'tsig.time');
        this.writeUInt16(v.fudge);
        this.writeUInt16(v.mac.length);
        this.write(v.mac);
        this.writeUInt16(v.origid);
        this.writeUInt16(v.error);
        this.writeUInt16(v.other.length);
        this.write(v.other);
};

DNSProtoBuffer.prototype.writeTSIGSignData = function (v, ctx) {
        assert.object(v, 'tsigSignData');
        this.writeNamePlain(v.rname);
        this.writeUInt16(v.rclass);
        this.writeUInt32(v.rttl);
        this.writeNamePlain(v.algorithm);
        this.writeDateTime48(v.time, 'tsig.time');
        this.writeUInt16(v.fudge);
        this.writeUInt16(v.error);
        this.writeUInt16(v.other.length);
        this.write(v.other);
};

DNSProtoBuffer.prototype.writeTSIGSignDataReq = function (v, ctx) {
        assert.object(v, 'tsigSignData');
        this.write(v.message);
        this.writeTSIGSignData(v, ctx);
};

DNSProtoBuffer.prototype.writeTSIGSignDataResp = function (v, ctx) {
        assert.object(v, 'tsigSignData');
        this.writeLengthPrefixed(2, function (cbuf) {
                cbuf.write(v.rmac);
        });
        this.write(v.message);
        this.writeTSIGSignData(v, ctx);
};

DNSProtoBuffer.prototype.writeTSIGSignTCP = function (v, ctx) {
        assert.object(v, 'tsigSignDataTcp');
        this.writeLengthPrefixed(2, function (cbuf) {
                cbuf.write(v.rmac);
        });
        this.write(v.message);
        this.writeDateTime48(v.time, 'tsig.time');
        this.writeUInt16(v.fudge);
};

DNSProtoBuffer.prototype.readSIG0 = function (ctx) {
        var r = {};
        r.typecovered = this.readUInt16();
        r.algorithm = this.readUInt8();
        r.labels = this.readUInt8();
        r.originalttl = this.readUInt32();
        r.expiration = this.readUInt32();
        r.inception = this.readUInt32();
        r.keytag = this.readUInt16();
        r.signername = this.readName();
        r.signature = this.remainder();
        return (r);
};

DNSProtoBuffer.prototype.writeSIG0 = function (v, ctx) {
        assert.object(v, 'sig0');
        this.writeUInt16(v.typecovered);
        this.writeUInt8(v.algorithm);
        this.writeUInt8(v.labels);
        this.writeUInt32(v.originalttl);
        this.writeUInt32(v.expiration);
        this.writeUInt32(v.inception);
        this.writeUInt16(v.keytag);
        this.writeNamePlain(v.signername);
        this.write(v.signature);
};

DNSProtoBuffer.prototype.writeSIG0SignData = function (v, ctx) {
        assert.object(v, 'sig0SignData');
        this.writeUInt16(v.rdata.typecovered);
        this.writeUInt8(v.rdata.algorithm);
        this.writeUInt8(v.rdata.labels);
        this.writeUInt32(v.rdata.originalttl);
        this.writeUInt32(v.rdata.expiration);
        this.writeUInt32(v.rdata.inception);
        this.writeUInt16(v.rdata.keytag);
        this.writeNamePlain(v.rdata.signername);
        this.write(v.rdata.signature);
};

DNSProtoBuffer.prototype.writeSIG0SignDataReq = function (v, ctx) {
        assert.object(v, 'sig0SignData');
        this.writeSIG0SignData(v, ctx);
};

DNSProtoBuffer.prototype.writeSIG0SignDataResp = function (v, ctx) {
        assert.object(v, 'sig0SignData');
        this.writeSIG0SignData(v, ctx);
};

DNSProtoBuffer.prototype.writeSIG0SignTCP = function (v, ctx) {
        throw (new Error('SIG0 continuations for TCP not supported'));
};

DNSProtoBuffer.prototype.readMessage = function (ctx) {
        var r = {}, i;
        r.header = this.readHeader(ctx);
        r.question = [];
        r.answer = [];
        r.authority = [];
        r.additional = [];
        for (i = 0; i < r.header.qdCount; ++i)
                r.question.push(this.readQuestion(ctx));
        for (i = 0; i < r.header.anCount; ++i)
                r.answer.push(this.readRecord(ctx));
        for (i = 0; i < r.header.nsCount; ++i)
                r.authority.push(this.readRecord(ctx));
        for (i = 0; i < r.header.arCount && !this.atEnd(); ++i)
                r.additional.push(this.readRecord(ctx));
        return (r);
};

DNSProtoBuffer.prototype.writeMessage = function (v, ctx) {
        var i;
        assert.object(v, 'message');
        this.writeHeader(v.header, ctx);
        for (i = 0; i < v.header.qdCount; ++i)
                this.writeQuestion(v.question[i], ctx);
        for (i = 0; i < v.header.anCount; ++i)
                this.writeRecord(v.answer[i], ctx);
        for (i = 0; i < v.header.nsCount; ++i)
                this.writeRecord(v.authority[i], ctx);
        for (i = 0; i < v.header.arCount; ++i)
                this.writeRecord(v.additional[i], ctx);
};

/*
 * Turns an IPv4 address in dotted-decimal notation into a UInt32BE. This gets
 * very hot in a lot of cases, so it's worth avoiding unnecessary memory
 * allocation and optimizing this pretty heavily.
 */
function parseIPv4(addr) {
        assert.string(addr);
        var b = new Buffer(4);
        var i = -1, j, k = 0, temp;
        while (i < addr.length && k < 4) {
                j = addr.indexOf('.', i + 1);
                if (j === -1)
                        j = addr.length;
                temp = parseInt(addr.slice(i + 1, j), 10);
                if (!isFinite(temp) || temp < 0 || temp > 255)
                        throw (new TypeError('valid IP address required'));
                b[k++] = temp;
                i = j;
        }
        if (k !== 4)
                throw (new TypeError('valid IP address required'));
        return (b.readUInt32BE(0));
}


function parseIPv6(addr) {
        assert.string(addr);
        var a;
        try {
                a = ipaddr.parse(addr);
        } catch (e) {
                return false;
        }
        return (a.parts);

}

DNSProtoBuffer.prototype.readDateTime48 = function () {
        var highPart = this.readUInt16();
        var lowPart = this.readUInt32();
        var d = new Date();
        d.setTime((highPart * 4294967296 + lowPart) * 1000);
        return (d);
};

DNSProtoBuffer.prototype.writeDateTime48 = function (v, name) {
        assert.date(v, name);
        var secs = v.getTime() / 1000;
        var highPart = Math.floor(secs / 4294967296);
        var lowPart = secs & 0xffffffff;
        this.writeUInt16(highPart);
        this.writeUInt32(lowPart);
};

DNSProtoBuffer.prototype.readNSFlags = function (ctx) {
        var flags = this.readUInt16();
        var f = {
                qr:     ((flags & 0x8000) !== 0),
                opcode: ((flags & 0x7800) >> 11),
                aa:     ((flags & 0x0400) !== 0),
                tc:     ((flags & 0x0200) !== 0),
                rd:     ((flags & 0x0100) !== 0),
                ra:     ((flags & 0x0080) !== 0),
                z:      ((flags & 0x0040) !== 0),
                ad:     ((flags & 0x0020) !== 0),
                cd:     ((flags & 0x0010) !== 0),
                rcode:  ((flags & 0x000F))
        };
        return (f);
};

DNSProtoBuffer.prototype.writeNSFlags = function (v, ctx) {
        assert.object(v, 'flags');
        var f = 0x0000;
        f = f | (v.qr << 15);
        f = f | (v.opcode << 11);
        f = f | (v.aa << 10);
        f = f | (v.tc << 9);
        f = f | (v.rd << 8);
        f = f | (v.ra << 7);
        f = f | (v.z  << 6);
        f = f | (v.ad << 5);
        f = f | (v.cd << 4);
        f = f | v.rcode;
        this.writeUInt16(f);
};

DNSProtoBuffer.prototype.readIP4 = function (ctx) {
        var parts = [];
        for (var i = 0; i < 4; ++i)
                parts[i] = this.readUInt8().toString(10);
        return (parts.join('.'));
};

DNSProtoBuffer.prototype.writeIP4 = function (v, ctx) {
        assert.string(v, 'ipv4');
        var a = parseIPv4(v);
        this.writeUInt32(a);
};

DNSProtoBuffer.prototype.readIP6 = function (ctx) {
        var parts = [];
        for (var i = 0; i < 8; ++i)
                parts[i] = this.readUInt16().toString(16);
        return (parts.join(':'));
};

DNSProtoBuffer.prototype.writeIP6 = function (v, ctx) {
        assert.string(v, 'ipv6');
        var a = parseIPv6(v);
        for (var i = 0; i < 8; i++)
                this.writeUInt16(a[i]);
};

DNSProtoBuffer.prototype.readOPT = function (ctx) {
        var opts = [];
        while (!this.atEnd()) {
                var opt = {};
                opt.code = this.readUInt16();
                this.readLengthPrefixed(2, function (cbuf) {
                        opt.data = cbuf.remainder();
                });
                opts.push(opt);
        }

        return ({ options: opts });
};

DNSProtoBuffer.prototype.writeOPT = function (v, ctx) {
        assert.object(v, 'edns opt');
        assert.optionalArrayOfObject(v.options, 'edns options');
        if (v.options === undefined)
                return;
        var self = this;
        v.options.forEach(function (opt) {
                assert.number(opt.code);
                assert.buffer(opt.data);
                self.writeUInt16(opt.code);
                self.writeLengthPrefixed(2, function (cbuf) {
                        cbuf.write(opt.data);
                });
        });
};

DNSProtoBuffer.prototype.readNSText = function (ctx) {
        var r;
        this.readLengthPrefixed(1, function (cbuf) {
                r = cbuf.remainder().toString('binary');
        });
        return (r);
};

DNSProtoBuffer.prototype.writeNSText = function (v, ctx) {
        assert.string(v);
        this.writeUInt8(v.length);
        this.write(new Buffer(v, 'binary'));
};

DNSProtoBuffer.prototype.readNSData = function (ctx) {
        var res = this.readLengthPrefixed(2, function (cbuf) {
                var r;
                switch (ctx.rtype) {
                case queryTypes['A']:
                        r = { target: cbuf.readIP4(ctx) };
                        break;
                case queryTypes['AAAA']:
                        r = { target: cbuf.readIP6(ctx) };
                        break;
                case queryTypes['CNAME']:
                case queryTypes['NS']:
                case queryTypes['PTR']:
                        r = { target: cbuf.readName(ctx) };
                        break;
                case queryTypes['TXT']:
                        r = { target: cbuf.readNSText(ctx) };
                        break;
                case queryTypes['SOA']:
                        r = cbuf.readSOA(ctx);
                        break;
                case queryTypes['MX']:
                        r = cbuf.readMX(ctx);
                        break;
                case queryTypes['SRV']:
                        r = cbuf.readSRV(ctx);
                        break;
                case queryTypes['OPT']:
                        r = cbuf.readOPT(ctx);
                        break;
                case queryTypes['TSIG']:
                        r = cbuf.readTSIG(ctx);
                        break;
                case queryTypes['SIG0']:
                        r = cbuf.readSIG0(ctx);
                        break;
                default:
                        throw (new Error('unsupported nsdata type: ' +
                            queryTypes[ctx.rtype]));
                }
                return (r);
        });
        return (res);
};

DNSProtoBuffer.prototype.writeNSData = function (v, ctx) {
        this.writeLengthPrefixed(2, function (cbuf) {
                switch (ctx.rtype) {
                case queryTypes['A']:
                        cbuf.writeIP4(v.target, ctx);
                        break;
                case queryTypes['AAAA']:
                        cbuf.writeIP6(v.target, ctx);
                        break;
                case queryTypes['CNAME']:
                case queryTypes['NS']:
                case queryTypes['PTR']:
                        cbuf.writeName(v.target);
                        break;
                case queryTypes['TXT']:
                        cbuf.writeNSText(v.target, ctx);
                        break;
                case queryTypes['SOA']:
                        cbuf.writeSOA(v, ctx);
                        break;
                case queryTypes['MX']:
                        cbuf.writeMX(v, ctx);
                        break;
                case queryTypes['SRV']:
                        cbuf.writeSRV(v, ctx);
                        break;
                case queryTypes['OPT']:
                        cbuf.writeOPT(v, ctx);
                        break;
                case queryTypes['TSIG']:
                        cbuf.writeTSIG(v, ctx);
                        break;
                case queryTypes['SIG0']:
                        cbuf.writeSIG0(v, ctx);
                        break;
                default:
                        throw new Error('unrecognized nsdata type');
                }
        });
};

function encode(obj, format) {
        var buf = new DNSProtoBuffer({});
        switch (format) {
        case 'message':
        /* These are legacy aliases for compatibility. */
        case 'queryMessage':
        case 'answerMessage':
        case 'answerMessageNoQ':
                buf.writeMessage(obj, {});
                break;
        case 'tsigSignDataReq':
                buf.writeTSIGSignDataReq(obj, {});
                break;
        case 'tsigSignDataResp':
                buf.writeTSIGSignDataResp(obj, {});
                break;
        case 'tsigSignTcp':
                buf.writeTSIGSignTCP(obj, {});
                break;
        /*
         * sig0 is just like tsig, but with a different packet format
         * (and different crypto)
         */
        case 'sig0SignDataReq':
                buf.writeSIG0SignDataReq(obj, {});
                break;
        case 'sig0SignDataResp':
                buf.writeSIG0SignDataResp(obj, {});
                break;
        case 'sig0SignTcp':
                buf.writeSIG0SignTCP(obj, {});
                break;
        default:
                throw (new Error('Unknown format: ' + format));
        }
        return (buf.toBuffer());
}

function decode(raw, format) {
        var buf = new DNSProtoBuffer({ buffer: raw });
        switch (format) {
        case 'message':
        case 'queryMessage':
        case 'answerMessage':
        case 'answerMessageNoQ':
                return (buf.readMessage({}));
        default:
                throw (new Error('Unknown format: ' + format));
        }
}

var opCodes = {
        QUERY  : 0,
        IQUERY : 1,
        STATUS : 2,
        NOTIFY : 4,
        UPDATE : 5,
        0      : 'QUERY',
        1      : 'IQUERY',
        2      : 'STATUS',
        4      : 'NOTIFY',
        5      : 'UPDATE'
};

var rCodes = {
        NOERROR  : 0,
        FORMERR  : 1,
        SERVFAIL : 2,
        NXDOMAIN : 3,
        NOTIMP   : 4,
        REFUSED  : 5,
        YXDOMAIN : 6,
        XRRSET   : 7,
        NOTAUTH  : 9,
        NOTZONE  : 10,

        ESERVER  : 2,    // alias of SERVFAIL
        NONAME   : 3,    // alias of NXDOMAIN
        NOERR    : 0,    // alias of NOERROR
        REFUSE   : 5,    // alias of REFUSED

        0        : 'NOERROR',
        1        : 'FORMERR',
        2        : 'SERVFAIL',
        3        : 'NXDOMAIN',
        4        : 'NOTIMP',
        5        : 'REFUSED',
        6        : 'YXDOMAIN',
        7        : 'XRRSET',
        9        : 'NOTAUTH',
        10       : 'NOTZONE'
};

var qClasses = {
        IN   : 0x01, // the internet
        CS   : 0x02, // obsolete
        CH   : 0x03, // chaos class. yes this actually exists
        HS   : 0x04, // Hesiod
        ANY  : 0xff,
        0x01 : 'IN',
        0x02 : 'CS',
        0x03 : 'CH',
        0x04 : 'HS',
        0xff : 'ANY'
};

var queryTypes = {
        A     : 0x01,    // ipv4 address
        NS    : 0x02,    // nameserver
        MD    : 0x03,    // obsolete
        MF    : 0x04,    // obsolete
        CNAME : 0x05,    // alias
        SOA   : 0x06,    // start of authority
        MB    : 0x07,    // experimental
        MG    : 0x08,    // experimental
        MR    : 0x09,    // experimental
        NULL  : 0x0A,    // experimental null RR
        WKS   : 0x0B,    // service description
        PTR   : 0x0C,    // reverse entry (inaddr.arpa)
        HINFO : 0x0D,    // host information
        MINFO : 0x0E,    // mailbox or mail list information
        MX    : 0x0F,    // mail exchange
        TXT   : 0x10,    // text strings
        SIG0  : 0x18,    // asymmetric transaction signatures (RFC2931)
        AAAA  : 0x1C,    // ipv6 address
        SRV   : 0x21,    // srv records
        OPT   : 0x29,
        TKEY  : 0xF9,
        TSIG  : 0xFA,    // transaction signatures (RFC2845)
        IXFR  : 0xFB,    // request for incremental transfer
        AXFR  : 0xFC,    // request to transfer entire zone
        MAILA : 0xFE,    // request for mailbox related records
        MAILB : 0xFD,    // request for mail agent RRs
        ANY   : 0xFF,    // any class
        0x01  : 'A',     // ipv4 address
        0x02  : 'NS',    // nameserver
        0x03  : 'MD',    // obsolete
        0x04  : 'MF',    // obsolete
        0x05  : 'CNAME', // alias
        0x06  : 'SOA',   // start of authority
        0x07  : 'MB',    // experimental
        0x08  : 'MG',    // experimental
        0x09  : 'MR',    // experimental
        0x0A  : 'NULL',  // experimental null RR
        0x0B  : 'WKS',   // service description
        0x0C  : 'PTR',   // reverse entry (inaddr.arpa)
        0x0D  : 'HINFO', // host information
        0x0E  : 'MINFO', // mailbox or mail list information
        0x0F  : 'MX',    // mail exchange
        0x10  : 'TXT',   // text strings
        0x18  : 'SIG0',  // asymmetric transaction signatures (RFC2931)
        0x1C  : 'AAAA',  // ipv6 address
        0x21  : 'SRV',   // srv records
        0x29  : 'OPT',
        0xF9  : 'TKEY',
        0xFA  : 'TSIG',  // transaction signatures (RFC2845)
        0xFB  : 'IXFR',  // req for incremental transfer
        0xFC  : 'AXFR',  // request to transfer entire zone
        0xFE  : 'MAILA', // request for mailbox related records
        0xFD  : 'MAILB', // request for mail agent RRs
        0xFF  : 'ANY'    // any class
};

module.exports = {
        encode: encode,
        decode: decode,
        queryTypes: queryTypes,
        opCodes: opCodes,
        rCodes: rCodes,
        qClasses: qClasses
};
