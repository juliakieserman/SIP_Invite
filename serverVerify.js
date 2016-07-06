var express = require('express');
var app = express();
var http = require('http');
var bodyParser = require('body-parser');
var server = http.createServer(app);
var v = require('./verify.js');

var inputArray = []
var inputString;

app.use(bodyParser.text({type:'*/*'}));

app.post('/', function(req, res) {
	
	inputString = req.body;

	inputArray = inputString.split("\n");

	var success = v.verify(inputArray);

	//if there was a problem when parsing the invite
	if (success == false) 
		var body = "SIP/2.0 400 Bad Invite";
	//if the identity header is valid
	else if (success == "good")  
		var body = "SIP/2.0 200 Valid Identity Header";
	//if the identity header is invalid
	else if (success == "bad")
		var body = "SIP/2.0 438 Invalid Identity Header";

	res.writeHead(200, "OK");
	res.end(body + '\n');
	
});

server.listen(1080, function() {
	console.log('listening on port 1080');
});

