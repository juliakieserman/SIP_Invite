var sip = require('sip');
var JsSIP = require('jssip');
var CryptoJS = require("crypto-js");
var r = require('jsrsasign');


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
   -----END RSA PRIVATE KEY-----"


//make sure SIP library will put it back in teh right order when reconstructing the string 
//insert new stuff in JSON obj

var m = sip.parse(['INVITE sip:bob@biloxi.com SIP/2.0', 'Via: SIP/2.0/TLS pc33.atlanta.example.com;branch=z9hG4bKnashds8', 'To: Bob <sip:bob@bioloxi.example.org>', 'From: Alice <sip:alice@atlanta.example.com>;tag=1928301774', 'Call-ID: a84b4c76e66710', 'CSeq: 314159 INVITE', 'Max-Fowards: 70', 'Date: Thu, 21 Feb 2002 12:02:03 GMT', 'Contact: <sip:alice@pc33.atlanta.example.com>', 'Content-Type: application/sdp', 'Content-Length: 147', '\r\n'].join('\r\n'));
var addrSpecContact = m["headers"]["to"]["uri"];

/*create the string:
sip:alice@atlanta.example.com|sip:bob@biloxi.example.org|
   a84b4c76e66710|314159 INVITE|Thu, 21 Feb 2002 13:02:03 GMT|
   sip:alice@pc33.atlanta.example.com*/
var digestString = m["headers"]["from"]["uri"] + "|" + addrSpecContact + "|" + m["headers"]["call-id"] + "|" + m["headers"]["cseq"]["seq"] + ' ' + m["headers"]["cseq"]["method"] + "|" + m["headers"]["date"] + "|" + addrSpecContact;

//initialize
var sig = new KJUR.crypto.Signature({"alg": "SHA1withRSA", "prov": "cryptojs/jsrsa"});
//initialize for signature generation
sig.initSign(privateKey);
//update data
sig.updateString(digestString);
//calculate signature
var sigValueHex = sig.sign();

//hash 
//var hash = CryptoJS.SHA256(digestString);

//sign hash with certificate


//console.log(digestString);


//convert back to string


//console.log(m);

