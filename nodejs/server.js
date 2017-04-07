// server.js

// set up ======================================================================
// get all the tools we need
var express  = require('express');
var app      = express();
var port     = process.env.PORT || 8080;
var passport = require('passport');
var flash    = require('connect-flash');

var morgan       = require('morgan');
var cookieParser = require('cookie-parser');
var bodyParser   = require('body-parser');
var session      = require('express-session');

var sqlite3 = require('sqlite3').verbose();
var db;

var configDB = require('./config/database.js');
var conn_str = configDB.dbPath;

var fs = require('fs');
var https = require('https');
var options = {
    key: fs.readFileSync('./ssl/server.key'),
    cert: fs.readFileSync('./ssl/server.crt'),
    ca: fs.readFileSync('./ssl/ca.crt'),
    requestCert: true,
    rejectUnauthorized: false
};

app.use(express.static(__dirname + '/public'));

require('./config/passport')(passport); // pass passport for configuration

// set up our express application
app.use(morgan('dev')); // log every request to the console
app.use(cookieParser()); // read cookies (needed for auth)
app.use(bodyParser()); // get information from html forms

app.set('view engine', 'ejs'); // set up ejs for templating

// required for passport
app.use(session({ secret: 'herehereherehrehrerherherherherherherherhe' })); // session secret
app.use(passport.initialize());
app.use(passport.session()); // persistent login sessions
app.use(flash()); // use connect-flash for flash messages stored in session

// routes ======================================================================
require('./app/routes.js')(app, passport); // load our routes and pass in our app and fully configured passport

// launch ======================================================================
  db = new sqlite3.Database(conn_str);
  db.serialize(function() {
        db.run('DROP TABLE IF EXISTS roles');
        db.run('DROP TABLE IF EXISTS roleAccessLevel');
        db.run('DROP TABLE IF EXISTS fqdnACLevel');
        db.run('DROP TABLE IF EXISTS roleBasedAC');
        //db.run('DROP TABLE IF EXISTS logs');
        //db.run('DROP TABLE IF EXISTS users');

	
  	db.run('CREATE TABLE  IF NOT EXISTS logs ( id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, srcMAC TEXT, src TEXT, dst TEXT, UNIQUE(srcMAC,dst));');	

  	db.run('CREATE TABLE  IF NOT EXISTS roles ( role_id INTEGER PRIMARY KEY, roleDesc TEXT);');	
	db.run('INSERT INTO roles VALUES (1,"Student")');
	db.run('INSERT INTO roles VALUES (2, "Professor")');
	db.run('INSERT INTO roles VALUES (3, "Admin")');

  	db.run('CREATE TABLE  IF NOT EXISTS roleAccessLevel ( id INTEGER PRIMARY KEY AUTOINCREMENT, role INTEGER, accessLevel INTEGER, FOREIGN KEY(role) REFERENCES roles(role_id));');
	db.run('INSERT INTO roleAccessLevel(role,accessLevel) VALUES (1, 1)');
	db.run('INSERT INTO roleAccessLevel(role,accessLevel) VALUES (2, 2)');
	db.run('INSERT INTO roleAccessLevel(role,accessLevel) VALUES (3, 4)');

	db.run('CREATE TABLE IF NOT EXISTS fqdnACLevel (id INTEGER PRIMARY KEY AUTOINCREMENT, fqdn TEXT, accessLevel INTEGER, FOREIGN KEY(accessLevel) REFERENCES roleAccessLevel(accessLevel))');
	db.run('INSERT INTO fqdnACLevel(fqdn,accessLevel) VALUES ("iot.aalto.fi", 2)');
	db.run('INSERT INTO fqdnACLevel(fqdn,accessLevel) VALUES ("guest.aalto.fi", 1)');

  	db.run('CREATE TABLE  IF NOT EXISTS roleBasedAC ( id INTEGER PRIMARY KEY AUTOINCREMENT, calledSID TEXT, fqdn TEXT, FOREIGN KEY (fqdn) REFERENCES fqdnACLevel(fqdn));');
	db.run('INSERT INTO roleBasedAC(calledSID,fqdn) VALUES ("6C-19-8F-83-C2-90:Noob2","iot.aalto.fi")');
	db.run('INSERT INTO roleBasedAC(calledSID,fqdn) VALUES ("6C-19-8F-83-C2-80:Noob1","guest.aalto.fi")');
  	
	db.run('CREATE TABLE IF NOT EXISTS radius (called_st_id TEXT, calling_st_id  TEXT, NAS_id TEXT, user_name TEXT PRIMARY KEY);');	


  	db.run('CREATE TABLE  IF NOT EXISTS users ( id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT, password TEXT, role INTEGER DEFAULT 1, isAdmin BOOLEAN DEFAULT FALSE,  FOREIGN KEY(role) REFERENCES roles(role_id) );');
  	db.run('CREATE TABLE  IF NOT EXISTS devices (PeerID TEXT, serv_state INTEGER, PeerInfo TEXT, Noob TEXT, Hoob TEXT, Hint TEXT,errorCode INTEGER ,UserName TEXT, PRIMARY KEY (PeerID, UserName));');




  	db.close();
  });

https.createServer(options, app).listen(8080, function () {
   console.log('Started!');
});


//app.listen(port);

//console.log('App is running on port ' + port);
