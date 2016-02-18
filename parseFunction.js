var sip = require('sip');
var JsSIP = require('jssip');

var invite = "INVITE sip:service@172.16.2.2:5060 SIP/2.0 \
Via: SIP/2.0/UDP 127.0.1.1:5060;branch=z9hG4bK-1075-1-0 \
From: sipp <sip:sipp@127.0.1.1:5060>;tag=1075SIPpTag001 \
To: sut <sip:service@172.16.2.2:5060> \
Call-ID: 1-1075@127.0.1.1 \
CSeq: 1 INVITE \
Contact: sip:sipp@127.0.1.1:5060 \
Max-Forwards: 70 \
Subject: Performance Test \
Content-Type: application/sdp \
Content-Length:   127 \
\
v=0\
o=user1 53655765 2353687637 IN IP4 127.0.1.1\
s=-\
c=IN IP4 127.0.1.1\
t=0 0\
m=audio 6000 RTP/AVP 0\
a=rtpmap:0 PCMU/8000";

var example = "sip:alice@atlanta.com";

var obj = sip.parse(invite);
console.log(obj);

var uri = JsSIP.URI.parse(example);

console.log(uri);

//invite = sip.parse(invite);

//console.log(invite);