var fs = require('fs');
var hash = require('json-hash');
var r = require('jsrsasign');
var sipf = require('./sipfunctions.js');

exports.verify = function(invite) {

	//certificates created from: https://devcenter.heroku.com/articles/ssl-certificate-self
	var publicKey = fs.readFileSync('server.crt', 'utf-8');

	var m = sipf.parse(invite);

	//if parse returns with an error
	if (m == undefined || m == false || m == null) 
		return false;

	//if no identity header is present, send back an error
	if (!(m["headers"].hasOwnProperty("identity")) ) {
		return false;
	}

	//step 4: make sure date is fresh
	var date = m["headers"]["date"];
	var currentTime = (new Date()).toUTCString();

	if (date > currentTime+60 || date < currentTime-60)
		return false;

	//reconstruct the passport object
	//token header obj
	var header = {"typ":"passport",
		               "alg":"RS256", 
		               "x5u":"https://cert.example.org/passport.crt"};
	var claims = {};

	if (m["headers"]["from"]["uri"] == null || m["headers"]["from"]["uri"] == 'undefined')
    	return false;
  	else
    	var origin = m["headers"]["from"]["uri"];

	//regex for phone numbers
  	var phoneno1 = /^\d{10}$/;
  	var phoneno2 = /^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/; 
  	var phoneno3 = /^\+?([0-9]{2})\)?[-. ]?([0-9]{4})[-. ]?([0-9]{4})$/;  

  	//if not telephone, "ouri" key for AoR vaue in From header field
  	if (origin != phoneno1 && origin != phoneno2 && origin != phoneno3)
    	claims["ouri"] = origin;
  	//if telephone, "otn" key for telephone number value
  	else 
  		claims["otn"] = origin;

  	//check user portion of from 
 	if (m["headers"]["to"]["uri"] == null) {
    	return false;
 	}
  	else {
    	var destination = m["headers"]["to"]["uri"];
  	}

  	//if destination identity is telephone number
  	if (destination != phoneno1 && destination != phoneno2 && destination != phoneno3)
    	claims["duri"] = destination;
  	else 
    	claims["dtn"] = destination;

	//get date and convert to milliseconds
	var date = Date.parse(m["headers"]["date"]);
	claims["iat"] = date;

	//hash the header and claims objects with sha256
	var hashedHeader = hash.digest(header, 'sha256');
	var hashedClaims = hash.digest(claims, 'sha256');

	var concatednatedHash = hashedHeader || '.' || hashedClaims;

	var receivedDigest = m["headers"]["identity"];
	
	receivedDigest = receivedDigest.split(/;(.+)?/)[0];

	//referenced from: https://github.com/kjur/jsrsasign/wiki/Tutorial-for-Signature-class
	var sig = new KJUR.crypto.Signature({"alg":"SHA256withRSA"});
	sig.init(publicKey);
	sig.updateString(concatednatedHash);
	var isValid = sig.verify(receivedDigest);
	
	if (isValid == true)
		return "good";
	else 
		return "bad";
}

