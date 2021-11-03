/*
 * This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 */

/*
 * Basic test/example of sig0 RSA-SHA1 signatures on DNS reords.
 */

var mod_mname = require('../lib');
var mod_sig0 = require('../lib/sig0');
var protocol = require('../lib/protocol');
var Query = require('../lib/Query');
var dig = require('./dig');
var mod_crypto = require('crypto');
var dgram = require('dgram');

if (require.cache[__dirname + '/helper.js'])
        delete require.cache[__dirname + '/helper.js']
var helper = require('./helper');

var test = helper.test;
var before = helper.before;
var after = helper.after;

var options = { port: 9999, server: '::1' };

// 'dnssec-keygen -T KEY -a rsasha1 -b 1024 -n USER testroot'
// 'dnssec2pem Ktestroot.+005+37511.private'
var SERVER_TEST_KEY = {
        name: 'testroot',
        tag: 37511,
        algorithm: 'rsa-sha1',
        privateKey: Buffer.from(
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIICXAIBAAKBgQCiZLRiwmTWHy2dBvu6Q2fo3WTRqiW4XfSXBX50bKtACPfWIDPP\n" +
                        "YYRLPt6I6dFtuMS/6HxSHwXALLovvhrVOjIp3qixm0O427icUgdQl60r1JhBeuDn\n" +
                        "2feFKECmOKbfqh4vMtYKuSXro5QFb9iPDNITvaBhIpjd9N5zsVV/YerpRQIDAQAB\n" +
                        "AoGAaWZDTfYtzGvgBxMJPxOQ1ascTJjKcqdIoNyH/ripTZ6EfQ3ZkrgQTWY4uVRJ\n" +
                        "AZXy3TvftM09xkVBcstITyy+cTW9TvEpXYPk3VAwrHbFfrcyechugnI5/3zOdwYJ\n" +
                        "W6yfYXmKlILHjjAb5ro4t8F+AJteSfS46TjNVPnc7r7WVOECQQDXXiCjFZEmR+PQ\n" +
                        "JBPAA1ntD5O4zBtdc7REOgiU8w7MmJ+edEgc0lqCi9KevJeAaS8wAzaoMEI89etd\n" +
                        "fE+S/Q/zAkEAx/BzvmfFqGbLJcNxn46KPyIYNYMo784swnbDgrjJdl3pMbPKS1zG\n" +
                        "B2HGRMx0LOGMt+DTLAnK19clZOpfLsG/ywJBAIH6pBXpEUYaQyq+a1EKdL53FT+F\n" +
                        "p8pZ52T55W4H11mxjzwxj8gdSFTbkE0PIxxz3u/KMLWHEqL6BIfSW7ApnPMCQHdF\n" +
                        "OlaQYvnlcDQz1fkft9qXhSeO+YGsVUkgPdsiTpP8y5pprTitvDg1HGh4KqmHV0Ft\n" +
                        "ratsoAOIBXeg1Gz5CWcCQEKZ5U1GcIcjJ5CoZPe5LlnDl0VVLN/khkwGtjYt/QZY\n" +
                        "bcO1Pfgqw0MZ9QajhkjktixpAOBTrZ8g8iev5eWgRHo=\n" +
                        "-----END RSA PRIVATE KEY-----"
        ),
        publicKey: Buffer.from(
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiZLRiwmTWHy2dBvu6Q2fo3WTR\n" +
                        "qiW4XfSXBX50bKtACPfWIDPPYYRLPt6I6dFtuMS/6HxSHwXALLovvhrVOjIp3qix\n" +
                        "m0O427icUgdQl60r1JhBeuDn2feFKECmOKbfqh4vMtYKuSXro5QFb9iPDNITvaBh\n" +
                        "Ipjd9N5zsVV/YerpRQIDAQAB\n" +
                        "-----END PUBLIC KEY-----"
        )
};

var CLIENT_IDENTITY_KEY = {
        name: 'testclient',
        tag: 5536,
        algorithm: 'rsa-sha1',
        privateKey: Buffer.from(''), // empty
        publicKey: Buffer.from(
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwBScUzQMiBzCDimdcn1E+2xey\n" +
                        "xat6mZgDpw02yKn5zq90rXK7p2Vzpe/3yOz0O4rqCP/liWfwm+vU0d0EdQyP7ypV\n" +
                        "SACrhLf7IDVEfQO0JFw2yzg9XEpBQMbLqib1QesT+6pfY8kwLwHBDSalqDgK0+Rh\n" +
                        "ayvZ9ZwG3KdLRtPoSQIDAQAB\n" +
                        "-----END PUBLIC KEY-----"
        )
};

var KEYS = {
        'testroot': SERVER_TEST_KEY,
        'testclient' : CLIENT_IDENTITY_KEY
};

before(function (callback) {
        this.server = mod_mname.createServer({
                log: helper.getLog('server')
        });
        var server = this.server;

        this.server.on('query', function (query, cb) {
                if (!query.isSigned() || !query.verify(KEYS)) {
                        query.setError('notauth');
                        query.send();
                        cb();
                        return;
                }
                var domain = query.name();
                var record;
                if (query.type() === 'AXFR') {
                        var soa = new mod_mname.SOARecord(domain);
                        query.addAnswer(domain, soa, 300);
                        query.send();
                        record = new mod_mname.ARecord('127.0.0.1');
                        query.addAnswer(domain, record, 300);
                        query.send();
                        query.addAnswer(domain, soa, 300);
                        query.send();
                        cb();
                } else {
                        record = new mod_mname.ARecord('127.0.0.1');
                        query.addAnswer(domain, record, 300);
                        query.send();
                        cb();
                }
        });

        this.server.listenUdp({port: options.port, address: options.server},
            function () {
                server.listenTcp({port: options.port, address: options.server},
                    function () {
                            server.signResponses(SERVER_TEST_KEY, callback);
                });
            });
});

after(function (cb) {
        this.server.close(cb);
});

/*
 * Quick & Dirty pure-js simple-query generator
 */
function simpleDnsQuery(name, type, qclass) {
        var req = {};
        req.header = {};
        req.header.id = 1234;
        req.header.flags = {
                qr:     false,
                opcode: 0,
                aa:     false,
                tc:     false,
                rd:     false,
                ra:     false,
                z:      false,
                ad:     false,
                cd:     false,
                rcode:  0
        };
        req.header.qdCount = 1;
        req.header.anCount = 0;
        req.header.nsCount = 0;
        req.header.arCount = 0;
        req.question = [];
        req.answer = [];
        req.authority = [];
        req.additional = [];

        var question = {};
        question.name = name;
        question.type = type;
        question.qclass = qclass;
        req.question.push(question);

        return (req);
}

function sendMessage(c, m) {
        c.send(m, 0, m.length, options.port, options.server,
                    function(err, bytes) {
                            if (err) throw err;
                    });
}

test('reject unauthed requests', function (t) {
        dig('example.com', 'A', options, function (err, results) {
                t.ifError(err);
                t.equal(results.status, 'notauth');
                t.end();
        });
});

var CLIENT_SIGNING_KEY = {
        name: 'testclient',
        tag: 5536,
        algorithm: 'rsa-sha1',
        privateKey: Buffer.from(
                "-----BEGIN RSA PRIVATE KEY-----\n" +
                        "MIICXQIBAAKBgQCwBScUzQMiBzCDimdcn1E+2xeyxat6mZgDpw02yKn5zq90rXK7\n" +
                        "p2Vzpe/3yOz0O4rqCP/liWfwm+vU0d0EdQyP7ypVSACrhLf7IDVEfQO0JFw2yzg9\n" +
                        "XEpBQMbLqib1QesT+6pfY8kwLwHBDSalqDgK0+RhayvZ9ZwG3KdLRtPoSQIDAQAB\n" +
                        "AoGALWoW7EH89fGe7cFu67HbV3lVwvVHSgmI9CBMw37AhEh0cokx2gLVpSICKQ85\n" +
                        "O8aFD98kjweFvsmr7iv7d2PvymGiJzbQCKv0+Mz7l+88BINNT8UEufNm2v8w7Yta\n" +
                        "u3G60BQ3iwAR8kwkAAvqgYDyVTxWSw493BP1w6XwPaMpG4ECQQDsv/Re1VNIhx2F\n" +
                        "ZxpKu29F/dXglfmoJQxZfRSc2TzchR+YTmdlnj/+Mveh+iiFUJ4od8lvPLDlx5nC\n" +
                        "3E+HCq2NAkEAxUDUS+3dMLB5dzsGzTBBBCmoy/DN1G+EQ6rmOwxLu3UujF45uIFw\n" +
                        "6ttXd51bHhrb4EIAKKhwAIfnuFDMHY9z3QJBAIOthBqW5hqJ5BaFsO7t70brluCy\n" +
                        "Kcimyoafdi6C+UHh3R/WQ9YWPZuB94+k1pLHsx/o+CWhiPZUnSXvaWA/xSUCQDFp\n" +
                        "cQToPA1zV6ofdi+2U8MYMHmOA/GgUdClofDOvrXhv9xXyjvG6SNb+Mg0+dtLvSKr\n" +
                        "ReDpeM0ZPlm0m70X710CQQDij+JEuX0GXCcZtSB4vlPpJvnCt3NDfzGAqNaE9HDo\n" +
                        "e6d0ZxHnxN5+ikjmZ10HiUhNMUtfoDzlrvflhCb7u6ac\n" +
                        "-----END RSA PRIVATE KEY-----"
        ),
        publicKey: Buffer.from(
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCwBScUzQMiBzCDimdcn1E+2xey\n" +
                        "xat6mZgDpw02yKn5zq90rXK7p2Vzpe/3yOz0O4rqCP/liWfwm+vU0d0EdQyP7ypV\n" +
                        "SACrhLf7IDVEfQO0JFw2yzg9XEpBQMbLqib1QesT+6pfY8kwLwHBDSalqDgK0+Rh\n" +
                        "ayvZ9ZwG3KdLRtPoSQIDAQAB\n" +
                        "-----END PUBLIC KEY-----"
        )
};

var SERVER_IDENTITY_KEY = {
        name: 'testroot',
        tag: 37511,
        algorithm: 'rsa-sha1',
        privateKey: Buffer.from(''), // empty
        publicKey: Buffer.from(
                "-----BEGIN PUBLIC KEY-----\n" +
                        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCiZLRiwmTWHy2dBvu6Q2fo3WTR\n" +
                        "qiW4XfSXBX50bKtACPfWIDPPYYRLPt6I6dFtuMS/6HxSHwXALLovvhrVOjIp3qix\n" +
                        "m0O427icUgdQl60r1JhBeuDn2feFKECmOKbfqh4vMtYKuSXro5QFb9iPDNITvaBh\n" +
                        "Ipjd9N5zsVV/YerpRQIDAQAB\n" +
                        "-----END PUBLIC KEY-----"
        )
};

var CLIENT_KEYS = {
        'testroot': SERVER_IDENTITY_KEY
};

test('accepts signed requests, emits signed response', function(t) {
        var req = simpleDnsQuery('example.com', protocol.queryTypes.A, protocol.qClasses.ANY);
        mod_sig0.signRequest(req, CLIENT_SIGNING_KEY);
        var client = dgram.createSocket('udp6');
        client.on('message', function (message, remote) {
                var qopts = {
                        family: 'udp',
                        address: remote.address,
                        port: remote.port,
                        data: message
                };

                var reply = Query.parse(qopts);
                t.ok(reply.query.header.flags.rcode == protocol.rCodes.NOERROR,
                    'expected success');
                t.ok(reply.isSigned(), 'signed');
                t.ok(reply.verify(CLIENT_KEYS, req));
                t.end();
                client.close();
        });

        var serializedReq = protocol.encode(req, 'message');
        sendMessage(client, serializedReq);
});

test('rejects corrupt signed requests', function(t) {
        var req = simpleDnsQuery('example.com', protocol.queryTypes.A, protocol.qClasses.ANY);
        mod_sig0.signRequest(req, CLIENT_SIGNING_KEY);
        var client = dgram.createSocket('udp6');
        client.on('message', function (message, remote) {
                var qopts = {
                        family: 'udp',
                        address: remote.address,
                        port: remote.port,
                        data: message
                };

                var reply = Query.parse(qopts);
                t.ok(reply.query.header.flags.rcode == protocol.rCodes.NOTAUTH,
                     'expected auth fail');
                t.end();
                client.close();
        });

        var serializedReq = protocol.encode(req, 'message');

        // Corrupt our buffer
        // modify a byte in the middle somewhere.
        var offset = serializedReq.length / 2
        var val = serializedReq.readUInt8(offset);
        val = val ^ 1; // flip a bit
        serializedReq.writeUInt8(val, offset);
        sendMessage(client, serializedReq);
});

test('client rejects corrupt signed responses', function(t) {
        var req = simpleDnsQuery('example.com', protocol.queryTypes.A, protocol.qClasses.ANY);
        mod_sig0.signRequest(req, CLIENT_SIGNING_KEY);
        var client = dgram.createSocket('udp6');
        client.on('message', function (message, remote) {
                // Corrupt our receive buffer
                // modify a byte in the middle somewhere.
                var offset = message.length / 2
                var val = message.readUInt8(offset);
                val = val ^ 1; // flip a bit
                message.writeUInt8(val, offset);
                var qopts = {
                        family: 'udp',
                        address: remote.address,
                        port: remote.port,
                        data: message
                };

                var reply = Query.parse(qopts);
                t.ok(reply.query.header.flags.rcode == protocol.rCodes.NOERROR,
                     'expected success');
                t.ok(reply.isSigned(), 'signed');
                t.ok(!reply.verify(CLIENT_KEYS, req));
                t.end();
                client.close();
        });

        var serializedReq = protocol.encode(req, 'message');
        sendMessage(client, serializedReq);
});
