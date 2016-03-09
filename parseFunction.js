var sip = require('sip');
var JsSIP = require('jssip');
var CryptoJS = require('crypto-js');
var crypto = require('crypto');
var fs = require('fs');
var r = require('jsrsasign');
var _sip = require('sipcore');


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
var claims = {"iat": date,
               "orig": to,
               "term": from};


//merge two json objects
var token = {"header":header, 
             "claims": claims};



//convert back to string
var value = sip.stringify(m);

console.log(token);
//console.log(m);


