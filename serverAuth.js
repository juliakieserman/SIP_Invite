var express = require('express');
var app = express();
var http = require('http');
var bodyParser = require('body-parser');
var server = http.createServer(app);
var auth = require('./authenticate.js');

var inputArray = []
var inputString;

app.use(bodyParser.text({type:'*/*'}));

app.post('/', function(req, res) {
  
  inputString = req.body;

  inputArray = inputString.split("\n");

  var success = auth.authenticate(inputArray);

  if (success == false) 
    var body = "SIP/2.0 400 Bad Invite";
  else 
    var body = success;

  res.writeHead(200, "OK");
  res.end(body + '\n');
  
});

server.listen(9000, function() {
  console.log('listening on port 9000');
});

    
