// app/routes.js
var base64url = require('base64url');
var crypto = require('crypto');
var sqlite3 = require('sqlite3').verbose();
var db;

var configDB = require('../config/database.js');
var conn_str = configDB.dbPath;

var PythonShell = require('python-shell');

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

    
    app.get('/getDevices', isLoggedIn, function(req, res) {
	
        var device_info = req.query.DeviceInfo;
        var queryObject = url.parse(req.url,true).query;
        var len = Object.keys(queryObject).length;
	
        if(len != 1 || device_info == undefined)
        {
		console.log("Its wrong Query");
		res.json({"error":"Wrong Query."});
        }else{
		var deviceDetails = new Array();
		var i= 0;
		var parseJson;
		var devInfoParam = '%' + device_info + '%';
		db = new sqlite3.Database(conn_str);
		db.all('SELECT PeerID, PeerInfo FROM peers_connected where peerInfo LIKE ? AND serv_state = ? AND userName IS NULL', devInfoParam, 1, function(err,rows){ //check for error conditions too
			db.close();
			if(!err){
				rows.forEach(function(row) {
					deviceDetails[i] = new Object();
					deviceDetails[i].peer_id = row.PeerID;
					parseJson= JSON.parse(row.PeerInfo);
					deviceDetails[i].peer_name = parseJson['PeerName'];
					deviceDetails[i].peer_num = parseJson['PeerSNum'];
					deviceDetails[i].peer_ssid = parseJson['PeerSSID'];
					deviceDetails[i].peer_bssid = parseJson['PeerBSSID'];
					
					i++;
				});
				console.log(JSON.stringify(deviceDetails));	
				res.send(JSON.stringify(deviceDetails));
			}else{
				res.send(JSON.stringify(deviceDetails));
				
			}
		});
	}
    });

    
    app.get('/insertDevice', function(req, res) {
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
            db.get('SELECT count(*) AS rowCount, PeerID, serv_state, PeerInfo, errorCode FROM peers_connected WHERE PeerID = ?', peer_id, function(err, row) {
            	
                if (err){res.json({"status": "failed"});}
		else if(row.rowCount != 1) {console.log(row.length);res.json({"status": "refresh"});}
		else {

			var options = {
  				mode: 'text',
  				pythonPath: '/usr/bin/python',
  				pythonOptions: ['-u'],
  				scriptPath: configDB.ooblibPath,
  				args: ['-o', peer_id]
			};
			var parseJ;
        		PythonShell.run('oobmessage.py', options, function (err,results) {
                		if (err){console.log("results : ",results); res.json({"status": "failed"});}
				else{
					parseJ = JSON.parse(results);
					var noob = parseJ['noob'];
					var hoob = parseJ['hoob'];
					var hash = crypto.createHash('sha256');
					var hash_str = noob+'AFARMERLIVEDUNDERTHEMOUNTAINANDGREWTURNIPSFORALIVING'
					//console.log(hash_str);
  					hash.update(hash_str);
  					var hint =  base64url.encode(hash.digest());
					//console.log(hint.slice(0,22));
					//console.log(hint.slice(0,32));
            				db.get('INSERT INTO devices (PeerID, serv_state, PeerInfo, Noob, Hoob,Hint,errorCode, username) values(?,?,?,?,?,?,?,?)', peer_id, row.serv_state, row.PeerInfo, noob, hoob, hint.slice(0,32),0, req.user.username, function(err, row) {
            					db.close();
                				if (err){console.log(err);res.json({"status": "failed"});}
						else {res.json({"status": "success"});}
            				});
				}
        		});
		}
            });

	}
    });

    app.get('/python', function(req, res) {

        // render the page and pass in any flash data if it exists
        //console.log(req.session.returnTo)i;
	var parseJ;
        PythonShell.run('oobmessage.py', options, function (err,results) {
                if (err) console.log (err);
                res.send("Its Successful");
		//parseJ = JSON.parse(results);
                console.log('results:', results);
        });
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
	var deviceDetails = new Array();
	var i,j;
	var parseJson;
	var parseJson1;
	var d = new Date();
	var seconds = Math.ceil(d.getTime() / 1000);
	var val = 0;
	var dev_status = ['Up to date','Update required','Obsolete, update now!']
	console.log(seconds);
	i = 0;
	j = 0;
	db = new sqlite3.Database(conn_str);
	db.all('SELECT PeerID, PeerInfo, serv_state,sleepTime,errorCode,DevUpdate FROM peers_connected where userName = ?', req.user.username , function(err,rows){
		if(!err){
			db.all('SELECT PeerID, PeerInfo, serv_state, errorCode, Noob, Hoob FROM devices where userName = ?', req.user.username , function(err1,rows1){
				if(!err1){
					db.close();
					rows1.forEach(function(row1) {
						deviceDetails[j] = new Object();
        					deviceDetails[j].peer_id = row1.PeerID;
						parseJson1= JSON.parse(row1.PeerInfo);
        					deviceDetails[j].peer_name = parseJson1['PeerName'];
						deviceDetails[j].peer_num = parseJson1['PeerSNum'];
						//deviceDetails[j].dev_update = dev_status[parseInt(row1.DevUpdate)];
						deviceDetails[j].noob = row1.Noob;
						deviceDetails[j].hoob = row1.Hoob;
						if(row1.errorCode){
							deviceDetails[j].state_num = '0';
							deviceDetails[j].state = error_info[parseInt(row.errorCode)];
						}
						else{ 
							deviceDetails[j].state = state_array[parseInt(row1.serv_state,10)];
							deviceDetails[j].state_num = row1.serv_state;
						}
						deviceDetails[j].sTime = '0';	
						j++;
					});	
					rows.forEach(function(row) {
						userDetails[i] = new Object();
        					userDetails[i].peer_id = row.PeerID;
						parseJson= JSON.parse(row.PeerInfo);
						userDetails[i].peer_num = parseJson['PeerSNum'];
        					userDetails[i].peer_name = parseJson['PeerName'];
						userDetails[i].dev_update = dev_status[parseInt(row.DevUpdate)];
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
						if(row.sleepTime && parseInt(row.serv_state) != 4 && parseInt(val) > 0){
							val = parseInt(val) + 60;
							userDetails[i].sTime = val;
						}else{
							userDetails[i].sTime = '0';
						}	
				
						i++;
					});
		
		 			res.render('profile.ejs', {
            				user : req.user, userInfo : userDetails, deviceInfo : deviceDetails,  url : configDB.url, message: req.flash('profileMessage') // get the user out of session and pass to template
        				});
				}else{
					db.close();
		 			res.render('profile.ejs', {
            				user : req.user, userInfo : userDetails, deviceInfo : '',  url : configDB.url,  message: req.flash('profileMessage') // get the user out of session and pass to template
        				});
				}
			});
		}else{
			db.close();
		 	res.render('profile.ejs', {
            			user : req.user, userInfo :'', deviceInfo : '', url : configDB.url,  message: req.flash('profileMessage') // get the user out of session and pass to template
        		});
			
		}
		//db.close();
	});
	//db.close();
    });

    // =====================================
    // LOGOUT ==============================
    // =====================================
    app.get('/logout', function(req, res) {
        req.logout();
        res.redirect('/');
    });

    app.get('/addDevice',isLoggedIn, function(req, res) {
        res.render('deviceAdd.ejs',{url : configDB.url});
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
