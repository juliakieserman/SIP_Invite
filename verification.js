var sip = require('sip');
var JsSIP = require('jssip');
var CryptoJS = require('crypto-js');
var crypto = require('crypto');
var fs = require('fs');
var _sip = require('sipcore');
var btoa = require('btoa');

var m = sip.parse(['INVITE sip:bob@biloxi.com SIP/2.0', 'Via: SIP/2.0/TLS pc33.atlanta.example.com;branch=z9hG4bKnashds8', 'To: Bob <sip:+12155551213@biloxi.com; user=phone>', 'From: Alice <sip:+12155551212@atlanta.com; user=phone>;tag=1928301774', 'Call-ID: a84b4c76e66710', 'CSeq: 314159 INVITE', 'Max-Fowards: 70', 'Date: Thu, 21 Feb 2002 12:02:03 GMT', 'Contact: <sip:alice@pc33.atlanta.example.com>', 'Content-Type: application/sdp', 'Content-Length: 147', 'Identity: eyJ3b3JkcyI6Wy01MTkwNzY4OTQsMTc2Nzk1NDc1NCwyMDU0NDUwNDc1LC0xOTE4NjE1MTY3LDE3MDY3MTI5MjIsMTYwODkwNzg0NCwxMTk2MjU0OTk3LC0xMjY5NDk0NzM2XSwic2lnQnl0ZXMiOjMyfQ==', '\r\n'].join('\r\n'));

console.log(m);