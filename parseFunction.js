var sip = require('sip');
var JsSIP = require('jssip');
var CryptoJS = require("crypto-js");
var r = require('jsrsasign');

//parse invite message into JSON obj
//invite message broken into headers
var m = sip.parse(['INVITE sip:bob@biloxi.com SIP/2.0', 'Via: SIP/2.0/UDP pc33.atlanta.com;branch=z9hG4bK776asdhds', 'Max-Forwards: 70', 'To: Bob <sip:bob@biloxi.com>', 'From: Alice <sip:alice@atlanta.com>;tag=1928301774', 'Call-ID: a84b4c76e66710@pc33.atlanta.com', 'CSeq: 314159 INVITE', 'Contact: <sip:alice@pc33.atlanta.com>', 'Content-Type: application/sdp', 'Content-Length: 142', 'Authorization: Digest username="Alice", realm="atlanta.com", nonce="84a4cc6f3082121f32b42a2187831a9e", response="7587245234b3434cc3412213e5f113a5432"', 'Proxy-Authorization: Digest username="Alice", realm="atlanta.com", nonce="84a4cc6f3082121f32b42a2187831a9e", response="7587245234b3434cc3412213e5f113a5432"', 'WWW-Authenticate: Digest realm="atlanta.com", nonce="84a4cc6f3082121f32b42a2187831a9e"', 'Authentication-Info: nextnonce="1234"', 'Refer-To: sip:100@somewhere.net', '\r\n'].join('\r\n'));

//invite message NOT broken into headers
//does NOT parse correctly -- missing elements
var invite = sip.parse(['INVITE sip:service@172.16.2.2:5060 SIP/2.0 Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-1075-1-0 From: sipp <sip:sipp@127.0.1.1:5060>;tag=1075SIPpTag001  To: sut <sip:service@172.16.2.2:5060> Call-ID: 1-1075@127.0.1.1 CSeq: 1 INVITE Contact: sip:sipp@127.0.1.1:5060 Max-Forwards: 70 Subject: Performance Test Content-Type: application/sdp Content-Length:   127 v=0 o=user1 53655765 2353687637 IN IP4 127.0.1.1 s=- c=IN IP4 127.0.1.1 t=0 0 m=audio 6000 RTP/AVP 0 a=rtpmap:0 PCMU/8000', '\r\n'].join('\r\n'));

//extract components for canonical string:
//1. AoR of UA sending message or addr-spec of the From header field
var addrFrom = m["headers"]["from"]["uri"];

//2. addr-spec of the To header field
var addrTo = m["headers"]["to"]["uri"];

//3. the callid from Call-Id header field
var callID = m["headers"]["call-id"];

//4. digit and method portions from CSeq header
var cseq = m["headers"]["cseq"]["seq"] + ' ' + m["headers"]["cseq"]["method"];

//5. date header field
//CANNOT FIND THIS IN INVITE

//6. addr-spec component of Contact header field
var contact = "";
//if this header exists, get property value. otherwise, add blank space to digest string
if (m.hasOwnProperty("headers"))
	contact = m["headers"]["contact"];

//7. message-body
// DONT KNOW WHAT THIS REFERS TO 

var digestString = addrFrom + "|" + addrTo + "|" + callID;

//hash 
var hash = CryptoJS.SHA1(digestString);

//sign hash with certificate


//console.log(digestString);
//console.log(hash);

console.log(m);

