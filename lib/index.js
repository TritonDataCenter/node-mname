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

var fs = require('fs');
var path = require('path');
var assert = require('assert-plus');

var bunyan = require('bunyan');

var Server = require('./server');
var Query = require('./query');
var Protocol = require('./protocol');
var tsig = require('./tsig');



////--- Globals

var BUNYAN_SERIALIZERS = {
        err: bunyan.stdSerializers.err,
        query: function serializeQuery(q) {
                var out = {
                        domain: q.name(),
                        operation: q.operation(),
                        type: q.type()
                };
                return (out);
        }
};



///--- Exports
module.exports = {

        createServer: function createServer(options) {
                options = options || {};
                assert.object(options);

                var opts = {
                        name: options.name || 'named',
                        log: options.log || bunyan.createLogger({
                                name: 'named',
                                level: 'warn',
                                serializers: BUNYAN_SERIALIZERS
                        })
                };
                return (new Server(opts));
        },

        Query: Query,

        Protocol: Protocol,

        tsig: tsig,

        bunyan: { serializers: BUNYAN_SERIALIZERS }

};

/* Export all the record types at the top-level */
module.exports.ARecord = require('./records/a');
module.exports.AAAARecord = require('./records/aaaa');
module.exports.CNAMERecord = require('./records/cname');
module.exports.MXRecord = require('./records/mx');
module.exports.NSRecord = require('./records/ns');
module.exports.PTRRecord = require('./records/ptr');
module.exports.SOARecord = require('./records/soa');
module.exports.SRVRecord = require('./records/srv');
module.exports.TXTRecord = require('./records/txt');
