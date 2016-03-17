var sip = require('sip');
var JsSIP = require('jssip');
var CryptoJS = require('crypto-js');
var crypto = require('crypto');
var fs = require('fs');
var _sip = require('sipcore');
var btoa = require('btoa');


var m = sip.parse(['INVITE sip:bob@biloxi.com SIP/2.0', 'Via: SIP/2.0/TLS pc33.atlanta.example.com;branch=z9hG4bKnashds8', 'To: Bob <sip:+12155551213@biloxi.com; user=phone>', 'From: Alice <sip:+12155551212@atlanta.com; user=phone>;tag=1928301774', 'Call-ID: a84b4c76e66710', 'CSeq: 314159 INVITE', 'Max-Fowards: 70', 'Date: Thu, 21 Feb 2002 12:02:03 GMT', 'Contact: <sip:alice@pc33.atlanta.example.com>', 'Content-Type: application/sdp', 'Content-Length: 147', '\r\n'].join('\r\n'));

//token header obj
var header = {"typ":"passport",
               "algo":"RS256", 
               "x5u":"https://cert.example.org/passport.crt"};

//get date and convert to milliseconds
var date = Date.parse(m["headers"]["date"]);

//strip extras from to header
var to = m["headers"]["to"]["uri"].substring(5, 16);

var from = m["headers"]["from"]["uri"].substring(5, 16);

//token claim obj
var payload = {"iat": date,
               "orig": to,
               "term": from};

//privateKey
var privateKey = "-----BEGIN RSA PRIVATE KEY-----\
   MIICXQIBAAKBgQDPPMBtHVoPkXV+Z6jq1LsgfTELVWpy2BVUffJMPH06LL0cJSQO\
   aIeVzIojzWtpauB7IylZKlAjB5f429tRuoUiedCwMLKblWAqZt6eHWpCNZJ7lONc\
   IEwnmh2nAccKk83Lp/VH3tgAS/43DQoX2sndnYh+g8522Pzwg7EGWspzzwIDAQAB\
   AoGBAK0W3tnEFD7AjVQAnJNXDtx59Aa1Vu2JEXe6oi+OrkFysJjbZJwsLmKtrgtt\
   PXOU8t2mZpi0wK4hX4tZhntiwGKkUPC3h9Bjp+GerifP341RMyMO+6fPgjqOzUDw\
   +rPjjMpwD7AkcEcqDgbTrZnWv/QnCSaaF3xkUGfFkLx5OKcRAkEA7UxnsE8XaT30\
   tP/UUc51gNk2KGKgxQQTHopBcew9yfeCRFhvdL7jpaGatEi5iZwGGQQDVOVHUN1H\
   0YLpHQjRowJBAN+R2bvA/Nimq464ZgnelEDPqaEAZWaD3kOfhS9+vL7oqES+u5E0\
   J7kXb7ZkiSVUg9XU/8PxMKx/DAz0dUmOL+UCQH8C9ETUMI2uEbqHbBdVUGNk364C\
   DFcndSxVh+34KqJdjiYSx6VPPv26X9m7S0OydTkSgs3/4ooPxo8HaMqXm80CQB+r\
   xbB3UlpOohcBwFK9mTrlMB6Cs9ql66KgwnlL9ukEhHHYozGatdXeoBCyhUsogdSU\
   6/aSAFcvWEGtj7/vyJECQQCCS1lKgEXoNQPqONalvYhyyMZRXFLdD4gbwRPK1uXK\
   Ypk3CkfFzOyfjeLcGPxXzq2qzuHzGTDxZ9PAepwX4RSk\
   -----END RSA PRIVATE KEY-----";

//JWS reference: https://tools.ietf.org/html/rfc7515#appendix-C

//base64 encode objects
var encodedHeader = btoa(JSON.stringify(header));
var encodedPayload = btoa(JSON.stringify(payload));

var sig = encodedHeader || '.' || encodedPayload;
var hash = CryptoJS.HmacSHA256(sig, privateKey);
var encodedHash = btoa(JSON.stringify(hash));

//create new header
var identityHeader = "Identity: " + encodedHash

console.log(encodedHash);
//convert back to string
var stringifiedSIP = sip.stringify(m);


//stringifiedSIP = stringifiedSIP + ['Identity: ' + signedIdentityDigest];

//console.log(stringifiedSIP);


