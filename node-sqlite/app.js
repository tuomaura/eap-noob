/*var express = require('express');
var app = express();*/
var bodyParser = require('body-parser');
var api = require('./api');

var fs = require('fs');
var https = require('https');
var app = require('express')();
var options = {
    key: fs.readFileSync('./ssl/server.key'),
    cert: fs.readFileSync('./ssl/server.crt'),
    ca: fs.readFileSync('./ssl/ca.crt'),
    requestCert: true,
    rejectUnauthorized: false
};


app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());


app.use('/api', api);

var port = process.env.PORT || 8080;

https.createServer(options, app).listen(8080, function () {
   console.log('Started!');
});


//app.listen(port);

console.log('App is running on port ' + port);
