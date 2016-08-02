// app/routes.js
var sqlite3 = require('sqlite3').verbose();
var db;

var configDB = require('../config/database.js');
var conn_str = configDB.dbPath;

var url = require('url');
var state_array = ['Unregistered','OOB Waiting', 'OOB Received' ,'Reconnect Exchange', 'Registered'];
var error_info = [ "No error",
                             "Invalid NAI or peer state",
                             "Invalid message structure",
                             "Invalid data",
                             "Unexpected message type",
                             "Unexpected peer identifier",
                             "Invalid ECDH key",
                             "Unwanted peer",
                             "State mismatch, user action required",
                             "No mutually supported protocol version",
                             "No mutually supported cryptosuite",
                             "No mutually supported OOB direction",
                             "MAC verification failure"];
module.exports = function(app, passport) {

    // =====================================
    // HOME PAGE (with login links) ========
    // =====================================
    app.get('/', function(req, res) {
        res.render('index.ejs'); // load the index.ejs file
    });

    // =====================================
    // LOGIN ===============================
    // =====================================
    app.get('/login', function(req, res) {

        // render the page and pass in any flash data if it exists
	//console.log(req.session.returnTo);
        res.render('login.ejs', { message: req.flash('loginMessage')}); 
    });


    // =====================================
    // SIGNUP ==============================
    // =====================================
    app.get('/signup', function(req, res) {

        res.render('signup.ejs', { message: req.flash('signupMessage') });
    });


    // =====================================
    // PROFILE SECTION =====================
    // =====================================
    app.get('/profile', isLoggedIn, function(req, res) {
	var userDetails = new Array();
	var i;
	var parseJson;
	var d = new Date();
	var seconds = Math.ceil(d.getTime() / 1000);
	var val = 0;
	console.log(seconds);
	i = 0;
	db = new sqlite3.Database(conn_str);
	db.all('SELECT PeerID, PeerInfo, serv_state,sleepTime,errorCode FROM peers_connected where userName = ?', req.user.username , function(err,rows){
		if(!err){
			rows.forEach(function(row) {
				userDetails[i] = new Object();
        			userDetails[i].peer_id = row.PeerID;
				parseJson= JSON.parse(row.PeerInfo);
        			userDetails[i].peer_name = parseJson['PeerName'];
				userDetails[i].peer_num = parseJson['PeerSNum'];
				if(row.errorCode){
					userDetails[i].state_num = '0';
					userDetails[i].state = error_info[parseInt(row.errorCode)];
				}
				else{ 
					userDetails[i].state = state_array[parseInt(row.serv_state,10)];
					userDetails[i].state_num = row.serv_state;
				}
				if(row.sleepTime)
				val = parseInt(row.sleepTime) - seconds; 
				console.log(val);
				if(row.sleepTime && parseInt(row.serv_state) != 4 && parseInt(val) > 0){
					val = parseInt(val) + 60;
					userDetails[i].sTime = val;
				}else{
					userDetails[i].sTime = '0';
				}	
				
				i++;
			});
		
		 	res.render('profile.ejs', {
            			user : req.user, userInfo : userDetails, url : configDB.url, message: req.flash('profileMessage') // get the user out of session and pass to template
        		});
		}else{
		 	res.render('profile.ejs', {
            			user : req.user,userInfo :'', url : configDB.url,  message: req.flash('profileMessage') // get the user out of session and pass to template
        		});
			
		}
		db.close();
	});
    });

    // =====================================
    // LOGOUT ==============================
    // =====================================
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });

    // process the signup form
    app.post('/signup', passport.authenticate('local-signup', {
        successRedirect : '/profile', // redirect to the secure profile section
        failureRedirect : '/signup', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages
    }));

    // process the login form
    app.post('/login', passport.authenticate('local-login', {
        failureRedirect : '/login', // redirect back to the signup page if there is an error
        failureFlash : true // allow flash messages   
    }),function (req, res) { 
	if(req.session.returnTo){       
          res.redirect(req.session.returnTo || '/');  delete req.session.returnTo; 
	}else{
          res.redirect('/profile');
	}  
	});

    // process QR-code
    app.get('/QRcode/',isLoggedIn, function (req, res) {
        var peer_id = req.query.PeerId;
        var noob = req.query.Noob;
        var hoob = req.query.Hoob;
        var queryObject = url.parse(req.url,true).query;
        var len = Object.keys(queryObject).length;
	
        if(len != 3 || peer_id == undefined || noob == undefined || hoob == undefined)
        {
	   req.flash('profileMessage','Wrong query String! Please try again with proper Query!!' );
	   res.redirect('/profile');
        }else if(noob.length != 22 || hoob.length != 22){

     	   console.log("Updating Error!!!" + peer_id);
     	   db = new sqlite3.Database(conn_str);
     	
            db.serialize(function() {
       		 var stmt = db.prepare("UPDATE peers_connected SET OOB_RECEIVED_FLAG = ?, Noob = ?, Hoob = ?, errorCode = ?, userName = ?, serv_state = ? WHERE PeerID = ?");
       		 stmt.run(1234,"","",3,req.user.username,2,peer_id);
		 stmt.finalize();
    	    });

	db.close();
	req.flash('profileMessage','Invalid Data');
     	res.redirect('/profile');

        }else{

     	   db = new sqlite3.Database(conn_str);
     	
            db.serialize(function() {
       		 var stmt = db.prepare("UPDATE peers_connected SET OOB_RECEIVED_FLAG = ?, Noob = ?, Hoob = ?, userName = ?, serv_state = ? WHERE PeerID = ?");
       		 stmt.run(1234,noob,hoob,req.user.username,2,peer_id);
		 stmt.finalize();
    	    });

	db.close();
	req.flash('profileMessage','Received Successfully');
     	res.redirect('/profile');
       }
    });
    app.get('/stateUpdate', function(req, res) {
        var peer_id = req.query.PeerId;
        var state = req.query.State;
        var queryObject = url.parse(req.url,true).query;
        var len = Object.keys(queryObject).length;
	
        if(len != 2 || peer_id == undefined || state == undefined)
        {
    	   console.log("Its wrong Query");
	   res.json({"error":"Wrong Query."});
        }else{
    	   console.log('req received');
	    db = new sqlite3.Database(conn_str);
            db.get('SELECT serv_state,errorCode FROM peers_connected WHERE PeerID = ?', peer_id, function(err, row) {

            	db.close();
                if (!row){res.json({"state": "No record found.","state_num":"0"});}
		else if(row.errorCode) { res.json({"state":error_info[parseInt(row.errorCode)], "state_num":"0"}); console.log(row.errorCode) }
                else if(parseInt(row.serv_state) == parseInt(state)) {res.json({"state":""});}
		else {res.json({"state": state_array[parseInt(row.serv_state)], "state_num": row.serv_state});}
            });
	}
    });

    app.get('/deleteDevice', function(req, res) {
    	//console.log(req);
        var peer_id = req.query.PeerId;
        var queryObject = url.parse(req.url,true).query;
        var len = Object.keys(queryObject).length;
	
        if(len != 1 || peer_id == undefined)
        {
	   res.json({"status":"failed"});
        }else{
    	   console.log('req received');

	    db = new sqlite3.Database(conn_str);
            db.get('SELECT count(*) AS rowCount FROM peers_connected WHERE PeerID = ?', peer_id, function(err, row) {

            	
                if (err){res.json({"status": "failed"});}
		else if(row.rowCount != 1) {res.json({"status": "refresh"});}
		else {
            		db.get('DELETE FROM peers_connected WHERE PeerID = ?', peer_id, function(err, row) {
            			db.close();
                		if (err){res.json({"status": "failed"});}
				else {res.json({"status": "success"});}
            		});
		}
            });

	}
    });
};


// route middleware to make sure a user is logged in
function isLoggedIn(req, res, next) {

    // if user is authenticated in the session, carry on 
    if (req.isAuthenticated())
        return next();

    var str = req.path;

    var peer_id = req.query.PeerId;

    var noob = req.query.Noob;

    var hoob = req.query.Hoob;

    if(peer_id != undefined)  str = str + '?PeerId=' + peer_id;
    if(noob != undefined)  str = str + '&Noob=' + noob;
    if(hoob != undefined)  str = str + '&Hoob=' + hoob;
    req.session.returnTo = str;
    res.redirect('/login');
}
