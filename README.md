# node-mname - DNS Server in Node.js

`mname` is a fork of the `node-named` library, which enables the development of
DNS servers in node.js.

This fork adds the following features:
 - Queries over TCP connections
 - AXFR, IXFR zone transfers
 - PTR records
 - Name compression
 - EDNS 1.0

## Creating a DNS Server

```js
var named = require('./lib/index');
var server = named.createServer();
var ttl = 300;

server.listenUdp(9999, '127.0.0.1', function() {
  console.log('DNS server started on port 9999');
});

server.on('query', function(query, done) {
  var domain = query.name();
  console.log('DNS Query: %s', domain)
  var target = new SOARecord(domain, {serial: 12345});
  query.addAnswer(domain, target, ttl);
  query.respond();
  done();
});
```

## Creating DNS Records

node-named provides helper functions for creating DNS records.
The records are available under 'named.record.NAME' where NAME is one
of ['A', 'AAAA', 'CNAME', 'SOA', 'MX', 'TXT, 'SRV']. It is important to
remember that these DNS records are not permanently added to the server.
They only exist for the length of the particular request. After that, they are
destroyed. This means you have to create your own lookup mechanism.

```js
var named = require('node-named');

var soaRecord = named.SOARecord('example.com', {serial: 201205150000});
console.log(soaRecord);
```

### Supported Record Types

The following record types are supported

 * A (ipv4)
 * AAAA (ipv6)
 * CNAME (aliases)
 * SOA (start of authority)
 * MX (mail server records)
 * TXT (arbitrary text entries)
 * SRV (service discovery)

## Logging

node-named uses [http://github.com/trentm/node-bunyan](bunyan) for logging.
It's a lot nicer to use if you npm install bunyan and put the bunyan tool in
your path. Otherwise, you will end up with JSON formatted log output by default.

### Replacing the default logger

You can pass in an alternate logger if you wish. If you do not, then it will use
bunyan by default. Your logger must expose the functions 'info', 'debug',
'warn', 'trace', 'error', and 'notice'.

## Tell me even more...

When DNS was designed it was designed prior
to the web existing, so many of the features in the RFC are either never used,
or were never implemented. This server aims to be RFC compliant, but does not
implement any other protocol other than INET (the one we're all used to), and
only supports a handful of record types (the ones that are in use on a regular
basis).

## Signatures over requests/responses

Two schemes are supported:

 * TSIG (symmetric HMAC key, shared between server and client)
 * SIG0 (asymmetric, separate signing keys by server and client)

Both schemes have tests which also serve as examples for use of the Signatures.

In addition to internal tests, it is possible to verify implementations by
using other implementations to issue requests. Perl's Net::DNS::SEC module
supports TSIG and SIG0. A sig0 test using Bind's nsupdate as a client
against a server running on 127.0.0.1:9999 might look like:

```
dnssec-keygen -T KEY -a rsasha1 -b 1024 -n USER testclient
nsupdate -k Ktestclient.+005+*.private << EOF
debug
server 127.0.0.1 9999
update add www1.example.com 86400 a 10.1.1.1
show
send
EOF
```
