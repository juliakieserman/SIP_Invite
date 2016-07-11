var fs = require('fs');
var hash = require('json-hash');
var r = require('jsrsasign');
var sipf = require('./sipfunctions.js');

exports.authenticate = function(invite) {

  //get private key from file
  var privateKey = fs.readFileSync('server.key', 'utf-8');

  //parse invite
  var m = sipf.parse(invite);

  //if parse returns with a error
  if (m == false || m == null || m == undefined) {
    return false;
  }

  //NOTE: Steps 1 & 2 in draft 4474bis-08 not included here

  //Step 3: check that date header is accurate
  var date = m["headers"]["date"];
  var currentTime = (new Date()).toUTCString();
  if (date > currentTime+60 || date < currentTime-60){
    //reject with 403 error code
    res.status(403).send("Date header inaccurate");
  }

  //Step 4: create PASSporT object
  var certURI = "https://cert.example.org/passport.crt";

  //passport header object
  var header = {"typ":"passport",
                   "alg":"RS256", 
                   "x5u":certURI};

  //passport claims object
  var claims = {};

  //Canonicalization Procedures
  //step 1: check user portion of URI
  if (m["headers"]["from"]["uri"] == null || m["headers"]["from"]["uri"] == 'undefined')
    return false;
  else
    var origin = m["headers"]["from"]["uri"];

  //referenced from: http://www.w3resource.com/javascript/form/phone-no-validation.php
  //regex for phone numbers
  var phoneno1 = /^\d{10}$/;
  var phoneno2 = /^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/; 
  var phoneno3 = /^\+?([0-9]{2})\)?[-. ]?([0-9]{4})[-. ]?([0-9]{4})$/;  

  //if not telephone, "ouri" key for AoR vaue in From header field
  if (origin != phoneno1 && origin != phoneno2 && origin != phoneno3) {
    claims["ouri"] = origin;
  }
  //if telephone, "otn" key for telephone number value
  else {
    claims["otn"] = origin;
  }

  //check user portion of from 
  if (m["headers"]["to"]["uri"] == null)
    return false;
  else
    var destination = m["headers"]["to"]["uri"];

  //if destination identity is telephone number
  if (destination != phoneno1 && destination != phoneno2 && destination != phoneno3)
    claims["duri"] = destination;
  else 
    claims["dtn"] = destination;

  //get date and convert to milliseconds
  var date = Date.parse(m["headers"]["date"]);
  claims["iat"] = date;

  //referenced from: https://www.npmjs.com/package/json-hash
  //hash the header and claims objects with sha256
  var hashedHeader = hash.digest(header, 'sha256');
  var hashedClaims = hash.digest(claims, 'sha256');

  var concatednatedHash = hashedHeader + '.' + hashedClaims;

  //referenced from: https://github.com/kjur/jsrsasign/wiki/Tutorial-for-Signature-class
  //initialize
  var sig = new KJUR.crypto.Signature({"alg": "SHA256withRSA"});
  //initialize for signature generation
  sig.init(privateKey);
  //update data
  sig.updateString(concatednatedHash);
  //calculate signature
  var signedDigest = sig.sign();

  //create identity header
  var info = "info=<" + certURI + ">;";
  var alg = "alg=RS256";

  var identityHeader = signedDigest + ";" + info + alg;

  //add identity header to INVITE
  m["headers"]["identity"] = identityHeader;

  var updatedInvite = sipf.stringify(m);
  
  return updatedInvite;

};


