// app/routes.js
var sqlite3 = require('sqlite3').verbose();
var db;
var conn_str = '/home/cloud-user/7july_testing/eapnoobimplementation/hostapd-2.5/hostapd/peer_connection_db';
var url = require('url');
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
    // show the login form
    app.get('/login', function(req, res) {

        // render the page and pass in any flash data if it exists
	//console.log(req.session.returnTo);
        res.render('login.ejs', { message: req.flash('loginMessage')}); 
    });

    // process the login form
    // app.post('/login', do all our passport stuff here);

    // =====================================
    // SIGNUP ==============================
    // =====================================
    // show the signup form
    app.get('/signup', function(req, res) {

        // render the page and pass in any flash data if it exists
        res.render('signup.ejs', { message: req.flash('signupMessage') });
    });

    // process the signup form
    // app.post('/signup', do all our passport stuff here);

    // =====================================
    // PROFILE SECTION =====================
    // =====================================
    // we will want this protected so you have to be logged in to visit
    // we will use route middleware to verify this (the isLoggedIn function)
    app.get('/profile', isLoggedIn, function(req, res) {
	var userDetails = new Array();
	var i;
	var state = ['Unregistered','OOB Waiting', 'OOB Received' ,'Reconnect Exchange', 'Registered'];
	var parseJson;
	i = 0;
	db = new sqlite3.Database(conn_str);
	db.all('SELECT PeerID, PeerInfo, serv_state FROM peers_connected where userName = ?', req.user.username , function(err,rows){
		if(!err){
			rows.forEach(function(row) {
				userDetails[i] = new Object();
        			userDetails[i].peer_id = row.PeerID;
				parseJson= JSON.parse(row.PeerInfo);
        			userDetails[i].peer_name = parseJson['PeerName'];
				userDetails[i].peer_num = parseJson['PeerSNum'];
				userDetails[i].state = state[parseInt(row.serv_state,10)];
				i++;
			});
		
		 	res.render('profile.ejs', {
            			user : req.user, userInfo : userDetails, message: req.flash('profileMessage') // get the user out of session and pass to template
        		});
		}else{
		 	res.render('profile.ejs', {
            			user : req.user,userInfo :'',  message: req.flash('profileMessage') // get the user out of session and pass to template
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
        //successRedirect : '/profile', // redirect to the secure profile section
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
    	   //console.log("Its wrong Query");
	   req.flash('profileMessage','Wrong query String! Please try again with proper Query!!' );
	   res.redirect('/profile');
	   //res.json({message: 'Wrong query String! Please try again with proper Query!!'});
        }else{

     	   //console.log("Get Called!!!" + peer_id +" "+ noob +" "+ hoob);
     	   console.log("Inserting!!!" + peer_id);
     	   db = new sqlite3.Database(conn_str);
     	
            db.serialize(function() {
       		 var stmt = db.prepare("UPDATE peers_connected SET OOB_RECEIVED_FLAG = ?, Noob = ?, Hoob = ?, userName = ?, serv_state = ? WHERE PeerID = ?");
       		 stmt.run(1234,noob,hoob,req.user.username,2,peer_id);
		 stmt.finalize();

       		  /*db.each("SELECT PeerID, OOB_RECEIVED_FLAG FROM peers_connected", function(err, row) {
       			console.log(row.PeerID + ": " + row.OOB_RECEIVED_FLAG);     
                  });*/
    	    });

	db.close();
	req.flash('profileMessage','Received Successfully');
     	res.redirect('/profile');
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
    // if they aren't redirect them to the home page
    res.redirect('/login');
}
