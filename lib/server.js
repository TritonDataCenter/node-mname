/*
 * Copyright (c) 2015 Trevor Orsztynowicz
 * Copyright (c) 2018, Joyent, Inc
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
var assert = require('assert-plus');
var dgram = require('dgram');
var net = require('net');
var EventEmitter = require('events').EventEmitter;
var util = require('util');
var crypto = require('crypto');
var vasync = require('vasync');

var protocol = require('./protocol');
var balancer = require('./balancer');
var Query = require('./query');
var DnsError = require('./errors');



///--- Globals

var sprintf = util.format;

var ExceptionError = DnsError.ExceptionError;
var ProtocolError = DnsError.ProtocolError;



///--- API

function Server(options) {
        assert.object(options, 'options');
        assert.object(options.log, 'options.log');
        assert.optionalString(options.name, 'options.name');
        assert.optionalNumber(options.timeout, 'options.timeout');

        this._log = options.log.child({component: 'named.Server'}, true);
        this._name = options.name || 'named';
        this._socket = null;
        this._notifies = {};
        this._timeout = options.timeout;
        if (this._timeout === undefined || this._timeout === null)
                this._timeout = 5000;
        this._closing = false;
        this._closed = false;
        this._closeq = null;
}
util.inherits(Server, EventEmitter);


Server.prototype.close = function close(cb) {
        var self = this;

        if (self._closed) {
                /*
                 * The server is already closed.
                 */
                if (cb) {
                        setImmediate(cb);
                }
                return;
        }

        if (self._closing) {
                /*
                 * The close operation is already in progress.  Join the queue.
                 */
                if (cb) {
                        self._closeq.push(cb);
                }
                return;
        }

        /*
         * Start the close operation.
         */
        self._closing = true;
        self._closeq = [];
        if (cb) {
                self._closeq.push(cb);
        }

        /*
         * Close each of the UDP, TCP, and load balancer sockets if they have
         * been connected.
         */
        vasync.forEachPipeline({ inputs: [ '_socket', '_server', '_balancer' ],
            func: function (prop, next) {
                if (!self[prop]) {
                        setImmediate(next);
                        return;
                }

                self[prop].on('close', function () {
                        delete (self[prop]);
                        next();
                });
                self[prop].close();

        }}, function () {
                self._closed = true;
                self._closeq.forEach(function (qcb) {
                        qcb();
                });
                self._closeq = null;
        });
};

/*
 * Listen on "path", a local UNIX socket path.  Note that this routine will
 * generally fail if called with a socket path which already exists; the
 * consumer is responsible for unlinking a stale socket if required.
 *
 * The socket listens for requests from the "mname-balancer" load balancer,
 * which will pass encapsulated TCP and UDP connections from clients with a
 * custom protocol.  Outbound responses are similarly encapsulated and passed
 * back through the load balancer to the remote peer.  More detail on the
 * protocol appears in "lib/balancer.js".
 */
Server.prototype.listenBalancer = function listenBalancer(opts, callback) {
        assert.object(opts, 'options');
        assert.string(opts.path, 'path');
        assert.optionalFunc(callback, 'callback');

        /*
         * Create a fake TCP listen socket through which we will emit TCP
         * connections forwarded from the balancer.
         */
        var tcpEmul = new EventEmitter();
        this.listenTcpCommon({ server: tcpEmul, isBalancer: true });

        var self = this;
        assert.ok(!this._closing, 'listen after close()');
        assert.strictEqual(this._balancer, undefined,
            'listenBalancer can only be called once');
        this._balancer = net.createServer({
                allowHalfOpen: true
        });
        this._balancer.listen({ path: opts.path }, callback);
        this._balancer.on('error', function (err) {
                self.emit('error', err);
        });
        this._balancer.on('connection', function (sock) {
                var log = self._log.child({
                        from: 'balancer'
                });
                log.trace('accepted balancer connection');

                var t = balancer.wrapBalancerConnection({ log: log,
                    sock: sock, tcpEmul: tcpEmul });

                t.on('error', function (err) {
                        log.warn(err, 'protocol error on balancer connection');
                        sock.destroy();
                });

                t.on('inbound_tcp', function (tcp) {
                        tcpEmul.emit('connection', tcp);
                });

                t.on('inbound_udp', function (rinfo, buffer, reply) {
                        self.onUdpMessage(buffer, rinfo, reply);
                });
        });
};

Server.prototype.listenTcp = function listenTcp(opts, callback) {
        assert.object(opts, 'options');
        assert.number(opts.port, 'port');
        if (opts.address === undefined)
                opts.address = '0.0.0.0';
        assert.string(opts.address, 'address');
        assert.optionalFunc(callback, 'callback');

        var self = this;

        assert.ok(!this._closing, 'listen after close()');
        assert.strictEqual(this._server, undefined,
            'listenTcp can only be called once');
        this._server = net.createServer({
                allowHalfOpen: true
        });

        this.listenTcpCommon({ server: this._server, isBalancer: false });

        this._server.on('error', function (err) {
                self.emit('error', err);
        });

        this._server.on('listening', function () {
                self.emit('listeningTcp');
        });

        this._server.listen(opts.port, opts.address, callback);
};

Server.prototype.listenTcpCommon = function listenTcpCommon(opts) {
        assert.object(opts, 'options');
        assert.object(opts.server, 'server');
        assert.bool(opts.isBalancer, 'isBalancer');

        var self = this;

        opts.server.on('connection', function (sock) {
                var log = self._log.child({
                        balancer: opts.isBalancer ? true : undefined,
                        from: sprintf('tcp/%s:%d', sock.remoteAddress,
                            sock.remotePort)
                });
                log.trace('accepted tcp connection');

                var qbuf = new Buffer(0);
                var qs = {};
                var theyEnded = false;
                sock.on('timeout', function () {
                        var reqs = Object.keys(qs).length;
                        if (reqs < 1) {
                                sock.end();
                                setTimeout(function () {
                                        if (!theyEnded) {
                                                log.debug('remote side left ' +
                                                    'connection dangling, ' +
                                                    'destroying it');
                                                sock.destroy();
                                        }
                                }, self._timeout);
                        } else {
                                log.debug('timeout on tcp socket with %d ' +
                                    'reqs outstanding', reqs);
                        }
                });
                sock.setTimeout(self._timeout);
                sock.on('end', function () {
                        theyEnded = true;
                        /* Close our end too if no outstanding requests. */
                        if (Object.keys(qs).length < 1)
                                sock.end();
                });
                sock.on('error', function (err) {
                        log.warn(err, 'error on tcp connection');
                        sock.destroy();
                        qbuf = undefined;
                });
                sock.on('readable', function () {
                        var b, bs = [qbuf];
                        while ((b = sock.read()) !== null)
                                bs.push(b);
                        if (qbuf)
                                qbuf = Buffer.concat(bs);

                        var pkts = [];
                        while (qbuf && qbuf.length > 2) {
                                var len = qbuf.readUInt16BE(0);
                                if (qbuf.length >= len + 2) {
                                        var pkt = qbuf.slice(2, len + 2);
                                        qbuf = qbuf.slice(len + 2);
                                        pkts.push(pkt);
                                } else {
                                        break;
                                }
                        }
                        if (qbuf && qbuf.length > 0)
                                qs.pending = true;
                        else
                                delete qs.pending;

                        pkts.forEach(onMessage);
                });
                function onMessage(pkt) {
                        var query;
                        var qopts = {
                                family: 'tcp',
                                address: sock.remoteAddress,
                                port: sock.remotePort,
                                socket: sock,
                                data: pkt
                        };

                        try {
                                query = Query.parse(qopts);
                                qs[query.id] = true;
                                /*
                                 * Note that it's important we call the
                                 * query.operation() function under the try{}
                                 * block here (it can throw).
                                 */
                                log = log.child({
                                        qId: query.id,
                                        qName: query.name(),
                                        qType: query.type(),
                                        qOp: query.operation()
                                });
                                query._log = log;
                        } catch (e) {
                                if (EventEmitter.listenerCount(self,
                                    'clientError') <= 0) {
                                        log.warn(e, 'query failed to parse');
                                } else {
                                        var err = new ProtocolError(
                                            'invalid DNS datagram');
                                        err.client = {
                                                address: sock.remoteAddress
                                        };
                                        err.innerError = e;
                                        self.emit('clientError', err);
                                }
                                sock.destroy();
                                return;
                        }

                        if (query === undefined || query === null) {
                                sock.destroy();
                                return;
                        }

                        sock.on('close', function () {
                                delete query.src;
                        });

                        query.respond = query.send = function respond() {
                                if (query.src === undefined ||
                                    qbuf === undefined) {
                                        log.debug('dropping query response, ' +
                                            'tcp socket already closed');
                                        return (false);
                                }
                                self.send(query);
                                return (true);
                        };

                        query.end = function end() {
                                log.trace('end() called');
                                self.emit('after', query);
                                delete qs[query.id];
                                delete query.src;

                                /*
                                 * Close the socket only if no more pipelined
                                 * queries are left.
                                 */
                                if (theyEnded && Object.keys(qs).length < 1) {
                                        sock.end();
                                }
                        };

                        self.emit('query', query, query.end);
                }
                sock.on('close', function () {
                        log.trace('tcp socket closed');
                        qbuf = undefined;
                });
        });
};

Server.prototype.listenUdp = function listenUdp(opts, callback) {
        assert.object(opts, 'options');
        assert.number(opts.port, 'port');
        if (opts.address === undefined)
                opts.address = '0.0.0.0';
        assert.string(opts.address, 'address');
        if (opts.family === undefined)
                opts.family = 'udp6';
        assert.string(opts.family, 'family');
        assert.optionalFunc(callback, 'callback');

        var self = this;
        assert.ok(!this._closing, 'listen after close()');
        assert.strictEqual(this._socket, null,
            'listen can only be called once');

        this._socket = dgram.createSocket(opts.family);
        this._socket.once('listening', function () {
                self.emit('listening');
                if (typeof (callback) === 'function')
                        process.nextTick(callback);
        });
        this._socket.on('error', function onSocketError(err) {
                if (self._socket.bound || opts.family === 'udp4') {
                        self.emit('error', err);
                } else {
                        if (err.code && err.code === 'EINVAL') {
                                self._log.debug(err,
                                    '%s socket failed to bind, falling ' +
                                    'back to udp4', opts.family);
                                delete (self._socket);
                                self._socket = null;
                                var opts2 = {family: 'udp4'};
                                Object.setPrototypeOf(opts2, opts);
                                self.listenUdp(opts2, callback);
                        } else {
                                self.emit('error', err);
                        }
                }
        });
        this._socket.on('message', function (buffer, rinfo) {
                self.onUdpMessage(buffer, rinfo, null);
        });
        this._socket.bind(opts.port, opts.address, function () {
                self._socket.bound = true;
        });
};

Server.prototype.onUdpMessage = function onUdpMessage(buffer, rinfo, reply) {
        var self = this;

        var query;

        var qopts = {
                family: 'udp',
                address: rinfo.address,
                port: rinfo.port,
                data: buffer
        };

        var log = self._log.child({
                from: sprintf('udp/%s:%d', rinfo.address, rinfo.port)
        });

        try {
                query = Query.parse(qopts);
                /*
                 * Note that it's important we call the
                 * query.operation() function under the try{}
                 * block here (it can throw).
                 */
                log = log.child({
                        qId: query.id,
                        qName: query.name(),
                        qType: query.type(),
                        qOp: query.operation()
                });
                query._log = log;
        } catch (e) {
                if (EventEmitter.listenerCount(self, 'clientError') <= 0) {
                        log.warn(e, 'query failed to parse');
                } else {
                        var err = new ProtocolError('invalid DNS datagram');
                        err.client = {
                                address: rinfo.address,
                                port: rinfo.port
                        };
                        err.innerError = e;
                        self.emit('clientError', err);
                }
                return;
        }

        if (query === undefined || query === null) {
                return;
        }

        if (query.operation() === 'notify') {
                var n = self._notifies[query.id];
                if (n !== undefined) {
                        clearTimeout(n._timerRef);
                        delete n._timerRef;
                        query.response.header.flags = Object.create(
                            query.query.header.flags);
                        n.emit('response', query);
                        delete self._notifies[query.id];
                        return;
                }
        }

        query.respond = query.send = function respond() {
                var opts = {};

                if (reply) {
                        opts.balancer = { send: reply };
                }

                self.send(query, opts);
        };

        query.end = function end() {
                log.trace('end() called, destroying');
                self.emit('after', query);
                delete query.src;
        };

        self.emit('query', query, query.end);
};

Server.prototype.listen = function listen(port, address, callback) {
        var opts = {};
        if (typeof (port) === 'string')
                opts.port = parseInt(port, 10);
        else
                opts.port = port;
        if (typeof (address) === 'function')
                callback = address;
        else
                opts.address = address;
        return (this.listenUdp(opts, callback));
};


Server.prototype.send = function send(res, opts) {
        assert.object(res, 'a query object');

        assert.func(res.encode, 'a query object with .encode');

        assert.object(res.src, 'an open query');
        assert.string(res.src.address, 'query.src.address');
        assert.string(res.src.family, 'query.src.family');

        var buf = res.encode();

        var log = res._log || this._log.child({
                from: sprintf('%s/%s:%d', res.src.family, res.src.address,
                    res.src.port)
        });

        var self = this;
        var family = res.src.family;
        var len = buf.length;

        switch (family) {
        case 'udp':
                assert.number(res.src.port);

                var addr = res.src.address;
                var port = res.src.port;

                var type = 'socket';
                var s = this._socket;
                res.bytesSent = len;

                if (opts && opts.balancer) {
                        s = opts.balancer;
                        type = 'balancer';
                }

                log.trace({
                        len: len
                }, 'send: writing DNS message to %s', type);

                s.send(buf, 0, len, port, addr, function (err, bytes) {
                        if (err) {
                                log.warn(err, 'send: unable to send response');
                                self.emit('error',
                                    new ExceptionError(err.message));
                        }
                });
                break;

        case 'tcp':
                var sock = res.src.socket;
                if (!sock) {
                        log.debug('send: connection already closed, ' +
                            ' dropping data');
                        break;
                }

                /*
                 * Per RFC 7766, the message is prepended with the two-octet
                 * length field.
                 */
                res.bytesSent = buf.length + 2;

                log.trace({len: len},
                    'send: writing DNS message to TCP socket');
                var lenbuf = new Buffer(2);
                lenbuf.writeUInt16BE(buf.length, 0);
                sock.write(Buffer.concat([lenbuf, buf]));

                res.reset();
                break;

        default:
                throw new Error('Unknown protocol family ' + family);
        }
};

Server.prototype.createNotify = function (opts) {
        assert.object(opts, 'options');
        assert.string(opts.zone, 'options.zone');
        assert.string(opts.address, 'options.address');
        assert.optionalNumber(opts.port, 'options.port');
        assert.optionalNumber(opts.timeout, 'options.timeout');
        if (opts.port === undefined)
                opts.port = 53;
        if (opts.timeout === undefined)
                opts.timeout = 5000;

        var id = crypto.randomBytes(2).readUInt16BE(0);
        var packet = {};
        packet.header = {
                id: id,
                flags: {
                        opcode: protocol.opCodes.NOTIFY,
                        rcode: protocol.rCodes.NOERROR
                },
                qdCount: 1,
                anCount: 0,
                nsCount: 0,
                arCount: 0
        };
        packet.question = [
                {
                        name: opts.zone,
                        type: protocol.queryTypes.SOA,
                        qclass: protocol.qClasses.IN
                }
        ];
        packet.answer = [];
        packet.authority = [];
        packet.additional = [];

        var packetBuf = protocol.encode(packet, 'message');
        assert.buffer(packetBuf);

        var ev = new EventEmitter();
        this._notifies[id] = ev;

        var self = this;
        ev.send = function (cb) {
                assert.ok(self._socket, 'server must be listening on UDP');
                assert.func(self._socket.send);
                if (typeof (cb) === 'function')
                        ev.once('sent', cb);
                self._socket.send(packetBuf, 0, packetBuf.length,
                    opts.port, opts.address, function (err) {
                        if (err) {
                                ev.emit('error', err);
                                clearTimeout(ev._timerRef);
                                delete ev._timerRef;
                                delete self._notifies[id];
                                return;
                        }
                        ev.emit('sent');
                });
                ev._timerRef = setTimeout(function () {
                        ev.emit('error', new Error('Timed out waiting for ' +
                             'remote server response'));
                        delete ev._timerRef;
                        delete self._notifies[id];
                }, opts.timeout);
        };

        return (ev);
};


Server.prototype.toString = function toString() {
        var str = '[object named.Server <';
        str += sprintf('name=%s, ', this._name);
        str += sprintf('socket=%j', this._socket ? this._socket.address() : {});
        str += '>]';
        return (str);
};



///--- Exports

module.exports = Server;
