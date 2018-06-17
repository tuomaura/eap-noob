
var base64url = require('base64url');
var crypto = require('crypto');
var sqlite3 = require('sqlite3').verbose();
var db;

var common = require('../common');
var connMap = common.connMap;

var configDB = require('../config/database.js');
var conn_str = configDB.dbPath;

var rad_cli_path = configDB.radCliPath;

var enableAC = parseInt(configDB.enableAccessControl,10);

var OobRetries =  parseInt(configDB.OobRetries,10);
var noob_timeout = parseInt(configDB.NoobTimeout,10) * 1000; //converting to milliseconds

var PythonShell = require('python-shell');

var fs = require('fs');
var lineReader = require('line-reader');

var parse = require('csv-parse');

var multer  =   require('multer');
var storage =   multer.diskStorage({
    destination: function (req, file, callback) {
        callback(null, './uploads');
    },
    filename: function (req, file, callback) {
        callback(null, file.fieldname +'.csv');
    }
});
//var sleep = require('sleep');
var upload = multer({ storage : storage}).single('logFile');

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
            //res.json({"error":"Wrong Query."});
            res.render('deviceAdd.ejs',{url : configDB.url});
        }else{
            var deviceDetails = new Array();
            var i= 0;
            var parseJson;
            var devInfoParam = '%' + device_info + '%';
            db = new sqlite3.Database(conn_str);
            db.all('SELECT p.PeerID, p.PeerInfo FROM peers_connected p where p.peerInfo LIKE ? AND p.serv_state = ? AND p.UserName IS NULL AND p.PeerID NOT IN (SELECT d.PeerID FROM devices d WHERE d.UserName = ?)',
                    devInfoParam, 1,req.user.username, function(err,rows){ //check for error conditions too
                        db.close();
                        if(!err){
                            rows.forEach(function(row) {
                                deviceDetails[i] = new Object();
                                deviceDetails[i].peer_id = row.PeerID;
                                parseJson= JSON.parse(row.PeerInfo);
                                deviceDetails[i].peer_name = parseJson['Make'];
                                deviceDetails[i].peer_num = parseJson['Serial'];
                                deviceDetails[i].peer_ssid = parseJson['SSID'];
                                deviceDetails[i].peer_bssid = parseJson['BSSID'];

                                i++;
                            });
                            console.log(JSON.stringify(deviceDetails));	
                            res.send(JSON.stringify(deviceDetails));
                        }else{
                            console.log("Some error" + err);
                            res.send(JSON.stringify(deviceDetails));

                        }
                    });
        }
    });

    function noobTimeoutCallback (peer_id,noob_id) {
        console.log('Noob Timeout Called  '+peer_id +"  "+noob_id);
        db = new sqlite3.Database(conn_str);

        db.serialize(function() {
            var stmt = db.prepare("DELETE FROM devices WHERE PeerID = ? AND Hint = ?");
            stmt.run(peer_id,noob_id);
            stmt.finalize();
        });

        db.close();
        console.log('Noob Timeout Deleted the expired noob');	
    }

    app.get('/deletePeers',isLoggedIn,function(req, res) {
        console.log('Delete peers Called');
        db = new sqlite3.Database(conn_str);

        db.serialize(function() {
            var stmt = db.prepare("DELETE FROM peers_connected where serv_state != 4 AND serv_state != 3");
            stmt.run();
            stmt.finalize();
        });

        db.close();
        console.log('Deleted');

        res.redirect('/profile');
    });

    app.post('/control', isLoggedIn, function(req, res) {
        var query = req._parsedUrl.query;
        var parts = query.split('&');
        var userID;
        var deviceID;
        var contentType;
        var action;
        var tmpParts;

        tmpParts = parts[0].split('=');
        peerID = tmpParts[1];
        db = new sqlite3.Database(conn_str);
        db.get('select deviceId from devicesSocket where peerId = ? AND userName = ?', peerID, req.user.username, function (err,row){
            if(err || row == undefined || row.deviceId == undefined){
                res.json({'status': 'fail'});
            }else{
                tmpParts = parts[1].split('=');
                contentType = tmpParts[1];
                tmpParts = parts[2].split('=');
                action = tmpParts[1];

                var softwareName = 'Text File';
                var softwareList = [];

                // var content = base64_encode('file.txt');
                // var content;

                var jsonData = {
                    'peerID': peerID,
                    'type': contentType,
                    'action': action,
                    'software_list': softwareList,
                    'software_name': softwareName
                };

                console.log('Ready to send control json' + peerID);
                console.log(jsonData);

                connMap[row.deviceId].send(JSON.stringify(jsonData));
                res.json({'status': 'success'});	
            }
        });	
    });

    app.get('/insertDevice',isLoggedIn,function(req, res) {
        console.log("InsertDevice"+req);
        var peer_id = req.query.PeerId;
        var queryObject = url.parse(req.url,true).query;
        var len = Object.keys(queryObject).length;

        if(len != 1 || peer_id == undefined)
        {
            res.json({"status":"failed"});
        }else{
            console.log('req received');

            db = new sqlite3.Database(conn_str);
            db.get('SELECT count(*) AS rowCount, PeerID, serv_state, PeerInfo, errorCode FROM peers_connected WHERE PeerID = ? AND UserName IS NULL', peer_id, function(err, row) {
                if (err){res.json({"status": "failed"});}
                else if(row.rowCount != 1) {console.log(row.length);res.json({"status": "refresh"});}
                else{
                    db.get('SELECT a.accessLevel AS al1, b.accessLevel AS al2 FROM roleAccessLevel a,fqdnACLevel b WHERE (b.fqdn = (SELECT NAS_id FROM radius WHERE user_name = ?)  OR b.fqdn = (SELECT d.fqdn FROM roleBasedAC d WHERE calledSID = (SELECT called_st_id FROM radius WHERE user_name = ?))) and a.role = (SELECT c.role FROM users c WHERE username = ?)', peer_id,peer_id,req.user.username, function(err, row1) {
                        if(err){res.json({"status": "failed"});}
                        else if(enableAC == 0 || row1.al1 >= row1.al2){
                            var options = {
                                mode: 'text',
                                pythonPath: '/usr/bin/python',
                                pythonOptions: ['-u'],
                                scriptPath: configDB.ooblibPath,
                                args: ['-i', peer_id, '-p', conn_str]
                            };
                            console.log("Peer id is " + peer_id)
                                var parseJ;
                            PythonShell.run('oobmessage.py', options, function (err,results) {
                                if (err){console.log("error" + err); res.json({"status": "failed"});}
                                else{
                                    parseJ = JSON.parse(results);
                                    var noob = parseJ['noob'];
                                    var hoob = parseJ['hoob'];
                                    var hash = crypto.createHash('sha256');
                                    var hash_str = 'NoobId'+noob;
                                    hash.update(hash_str,'utf8');
                                    var digest = new Buffer(hash.digest());
                                    digest = digest.slice(0,16);
                                    var hint =  base64url.encode(digest);
                                    db.get('INSERT INTO devices (PeerID, serv_state, PeerInfo, Noob, Hoob,Hint,errorCode, username) values(?,?,?,?,?,?,?,?)', peer_id, row.serv_state, row.PeerInfo, noob, hoob, hint.slice(0,32),0, req.user.username, function(err, row) {
                                        db.close();

                                        if (err){console.log(err);res.json({"status": "failed"});}
                                        else {
                                            setTimeout(noobTimeoutCallback, noob_timeout, peer_id, hint.slice(0,32)); 
                                            res.json({"status": "success"});
                                        }
                                    });
                                }
                            });
                        }

                        else{res.json({"status":"deny"});}
                    });}
            });
        }
    });

    app.get('/python',isLoggedIn, function(req, res) {
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

    app.post('/logReport',function(req,res){
        console.log("RECEIVED LOG");
        upload(req,res,function(err) {
            if(err) {
                console.log("Error"+err);
                res.json({"status":"Error uploading file."});
            }

            res.json({"src":"130.233.193.111"});
            db = new sqlite3.Database(conn_str);
            db.serialize(function() {
                db.run("begin transaction");
                //var stmt = db.prepare("insert into data values (?)");
                // Three different methods of doing a bulk insert
                var inputFile = './uploads/logFile.csv'
                    var parser = parse({delimiter: '\t'}, function (err, data) {
                        // when all countries are available,then process them
                        // note: array element at index 0 contains the row of headers that we should skip
                        data.forEach(function(line) {
                            // create country object out of parsed fields
                            db.run("insert or ignore into logs (time,srcMAC,src,dst) values (?,?,?,?)", line[0],line[1],line[2],line[3]);
                            //process.exit(1);
                            console.log(line[3]);
                        });
                        //sleep.sleep(30);
                        fs.exists(inputFile, function(exists) {
                            if(exists) {
                                //Show in green
                                console.log('File exists. Deleting now ...');
                                fs.unlink(inputFile);
                            } else {
                                //Show in red
                                console.log('File not found, so not deleting.');
                            }
                        });
                    });

                // read the inputFile, feed the contents to the parser
                fs.createReadStream(inputFile).pipe(parser);

                db.run("commit");
            });
        });
    });

    /*
       app.post('/logReport', function(req, res) {
//var file = req.files.file;
console.log(req);
console.log("Received");
res.json({"status":"Success"});
});
*/

// =====================================
// PROFILE SECTION =====================
// =====================================
app.get('/profile', isLoggedIn, function(req, res) {
    var userDetails = new Array();
    var PeerInfo_row, PeerInfo_j, PeerCount = 0;
    var d = new Date();
    var seconds = Math.ceil(d.getTime() / 1000);
    var val = 0;
    var dev_status = ['Up to date','Update required','Obsolete', 'Update available!']
    var deviceDetails = new Array();
    var db;
    function callback(dDetails, Peers) {
        deviceDetails.push(dDetails);
        if (deviceDetails.length == Peers) {
            db.close();
            res.render('profile.ejs', {
                user : req.user, userInfo :'', deviceInfo : deviceDetails, url : configDB.url,  message: req.flash('profileMessage')
            });
        }
    }
    db = new sqlite3.Database(conn_str);
    db.all('SELECT PeerId From UserDevices WHERE Username=?', req.user.username, function(err, rows0) {
                        console.log('1'+rows0.length);
if(rows0.length==0)
{
console.log('inside else added');
            db.close();
            res.render('profile.ejs', {
                user : req.user, userInfo :'', deviceInfo : '', url : configDB.url,  message: req.flash('profileMessage')
            });
}
       else if(!err ) {
            rows0.forEach(function(row0) {
                db.all('SELECT PeerInfo From EphemeralState WHERE PeerId=?', row0.PeerId, function(err, rows1) {
                    if (!err && rows1.length == 0) {
                        db.all('SELECT PeerInfo From PersistentState WHERE PeerId=?', row0.PeerId, function(err, rows2) {
                            if (!err && rows2.length == 0) {
                                db.close();
                        console.log('inside2');

                                res.render('profile.ejs', {
                                    user : req.user, userInfo :'', deviceInfo : '', url : configDB.url,  message: req.flash('profileMessage')
                                });
                            } else if (rows2.length > 0) {
                        console.log('inside 3');

                                deviceInfo = new Object();
                                deviceInfo.peer_id = row0.PeerId;
                                PeerInfo_row = rows2;
                                PeerInfo_j= JSON.parse(PeerInfo_row[0]['PeerInfo']);
                                deviceInfo.peer_name = PeerInfo_j['Make'];
                                deviceInfo.peer_num = PeerInfo_j['Serial'];
                                callback(deviceInfo, rows0.length);
                            }
			else{
                        console.log('inside else added');
                        db.close();
                        res.render('profile.ejs', {
                        user : req.user, userInfo :'', deviceInfo : '', url : configDB.url,  message: req.flash('profileMessage')
                            });

                        }

                        });
                    } else if (rows1.length > 0 ) {
                        deviceInfo = new Object();
                        console.log('inside 4');

                        deviceInfo.peer_id = row0.PeerId;
                        PeerInfo_row = rows1;
                        PeerInfo_j= JSON.parse(PeerInfo_row[0]['PeerInfo']);
                        deviceInfo.peer_name = PeerInfo_j['Make'];
                        deviceInfo.peer_num = PeerInfo_j['Serial'];
                        callback(deviceInfo, rows0.length);
                    }
			else{
			console.log('inside 5');
			db.close();
	        	res.render('profile.ejs', {
        	        user : req.user, userInfo :'', deviceInfo : '', url : configDB.url,  message: req.flash('profileMessage')
		            });

			}
                });
            });
        } else{
            console.log('inside else added');
            db.close();
            res.render('profile.ejs', {
                user : req.user, userInfo :'', deviceInfo : '', url : configDB.url,  message: req.flash('profileMessage')
            });
        }
    });
    /* res.render('profile.ejs', {
        user : req.user, userInfo :'', deviceInfo : '', url : configDB.url,  message: req.flash('profileMessage')
    }); */
});
                //db.all('SELECT * from EphemeralState WHERE PeerId=?', row0.PeerId, function(err, rows1) {
                /* if(!err1){
                    db.close();
                    rows1.forEach(function(row1) {
                        deviceDetails[j] = new Object();
                        deviceDetails[j].peer_id = row1.PeerID;
                        parseJson1= JSON.parse(row1.PeerInfo);
                        deviceDetails[j].peer_name = parseJson1['Make'];
                        deviceDetails[j].peer_num = parseJson1['Serial'];
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
                        deviceDetails[j].sTime = 150;	
                        j++;
                    });	
                    rows.forEach(function(row) {
                        userDetails[i] = new Object();
                        userDetails[i].peer_id = row.PeerID;
                        parseJson= JSON.parse(row.PeerInfo);
                        userDetails[i].peer_num = parseJson['Serial'];
                        userDetails[i].peer_name = parseJson['Make'];
                        //userDetails[i].dev_update = dev_status[parseInt(row.DevUpdate)];
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
                        if(parseInt(row.serv_state) != 4){
                            val = 150;
                            userDetails[i].sTime = val;
                        }else{
                            userDetails[i].sTime = '0';
                        }	

                        i++;
                    });

                    res.render('profile.ejs', {
                        user : req.user, userInfo : userDetails, deviceInfo : deviceDetails,  url : configDB.url, message: req.flash('profileMessage') // get the user out of session and pass to template
                    }); 
                else{
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
});  */

// =====================================
// LOGOUT ==============================
// =====================================
app.get('/logout', function(req, res) {
    req.logout();
    res.redirect('/');
});

app.get('/addDevice',isLoggedIn, function(req, res) {
    res.render('deviceAdd.ejs',{url : configDB.url, user : req.user});
});

app.get('/accessControl',isLoggedIn, isAdmin, function(req, res) {
    res.render('accessControl.ejs',{url : configDB.url, user : req.user});
});

app.get('/manage',isLoggedIn, isAdmin, function(req, res) {
    var macs = new Array();
    var ip = new Array();
    var dest = new Array();

    db = new sqlite3.Database(conn_str);

    db.all('SELECT DISTINCT srcMAC FROM logs', function(err, rows) {

        //db.close();
        if (err){db.close();res.render('management.ejs',{url : configDB.url, user : req.user});}
        else {
            macs = rows;
            //console.log(macs.length);
            //console.log(macs[0].srcMAC);

            function ip_loop(row_num,col_num,col,row,count){
                if(row >= row_num){res.render('management.ejs',{url : configDB.url, user : req.user, macs : macs, ips : ip, dests : dest}); return ;}
                db.all('SELECT time,dst FROM logs WHERE src = ?',ip[row][col].src,function(err,rows2){
                    if(err) {res.render('management.ejs',{url : configDB.url, user : req.user});return;}
                    else{

                        dest [count] = new Array();
                        dest[count] = rows2;
                        //console.log(rows2);
                        //console.log(ip[row][col].src);
                        count ++; col ++;
                        if(col >= col_num){
                            row++;
                            if(row >= row_num){
                                //console.log(ip) ;
                                //console.log(dest);
                                res.render('management.ejs',{url : configDB.url, user : req.user, macs : macs, ips : ip, dests : dest});
                                return;
                            } 
                            col = 0;
                            col_num = ip[row].length;

                        }
                        return ip_loop(row_num,col_num,col,row,count);
                    }
                });



            }
            function init_ip_loop(){
                return ip_loop(macs.length,ip[0].length,0,0,0);

            }
            function macs_loop (low,max){
                if(low >= max) return init_ip_loop();	
                db.all('SELECT DISTINCT src FROM logs WHERE srcMAC = ?',macs[low].srcMAC, function(err, rows1){
                    if (err){ res.render('management.ejs',{url : configDB.url, user : req.user});return; }
                    else{
                        ip[low] = new Array();
                        ip[low] = rows1;	
                        //console.log(ip[low]);
                        //console.log(low);
                        low++;
                        return macs_loop(low,macs.length);
                    }
                });

            }
            macs_loop(0,macs.length);

            db.close();
            //console.log(macs);
            //res.render('management.ejs',{url : configDB.url, user : req.user, macs : macs, ips : ip, dests : dest});
        }

    });

});

app.get('/configRadClients',isLoggedIn,isAdmin, function(req, res) {
    var radiusClients = new Array();
    var j = 0;
    var splitStr = new Array();

    lineReader.eachLine(rad_cli_path, function(line,last) {
        if(!line.startsWith('#')){
            splitStr = line.split("\t");
            radiusClients[j] = new Object();
            radiusClients[j].ip_addr = splitStr[0];
            radiusClients[j].secret = splitStr[1];
            console.log(splitStr[0] + "," +splitStr[1]);
            j++;
        }
        if(last){

            res.render('configRadClients.ejs',{url : configDB.url, clients : radiusClients});
        }
    });

});

app.get('/saveRadClients',isLoggedIn,isAdmin, function(req, res) { //need to add length validation for all values
    console.log(req.query.RadiusClients);
    var clients =  JSON.parse(req.query.RadiusClients);
    var queryObject = url.parse(req.url,true).query;
    var len = Object.keys(queryObject).length;

    if(len != 1 || clients == undefined)
    {
        res.json({"status":"failed"});
    }else if(clients.length == 0){
        var i = 0, n = clients.length;
        var str = "# RADIUS client configuration for the RADIUS server\n";

        var stream = fs.createWriteStream(rad_cli_path);
        stream.once('open', function(fd) {
            stream.write(str);
            stream.end();
            res.json({"status":"success"});
        });
        console.log(str);

    }else{
        var i = 0, n = clients.length;
        var str = "# RADIUS client configuration for the RADIUS server\n";

        for (i = 0; i<n; i++){
            str += clients[i].ip_addr + "\t" + clients[i].secret + "\n";
        }

        var stream = fs.createWriteStream("/home/shiva/Desktop/eap-noob/hostapd-2.5/hostapd/hostapd.radius_clients");
        stream.once('open', function(fd) {
            stream.write(str);
            stream.end();
            res.json({"status":"success"});
        });

        console.log(str);

    }

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
        //setTimeout(myFunc, 1500, 'funky', 'fun');
        //console.log("Here called");	
        res.redirect('/profile');
    }  
});


app.get('/regLater', function (req, res) {
    console.log("Called Later");
    if(req.session.returnTo){
        var queryObject = url.parse(req.session.returnTo,true).query;

        delete req.session.returnTo;

        var peer_id = queryObject["PeerId"];
        var noob = queryObject["Noob"];
        var hoob = queryObject["Hoob"];

        if(Object.keys(queryObject).length != 3 || peer_id == undefined || noob == undefined || hoob == undefined){
            req.flash('loginMessage','Wrong OOB query!');
            res.redirect('/login');

        }else if(noob.length != 22 || hoob.length != 22){
            console.log("Updating Error!!!" + peer_id);
            db = new sqlite3.Database(conn_str);

            db.serialize(function() {
                var stmt = db.prepare("UPDATE peers_connected SET OOB_RECEIVED_FLAG = ?, Noob = ?, Hoob = ?, errorCode = ?, serv_state = ? WHERE PeerID = ?");
                stmt.run(1234,"","",3,2,peer_id);
                stmt.finalize();
            });

            db.close();
            req.flash('loginMessage','Invalid Data');
            res.redirect('/login');		

        }else{

            db.serialize(function() {
                var stmt = db.prepare("UPDATE peers_connected SET OOB_RECEIVED_FLAG = ?, Noob = ?, Hoob = ?, serv_state = ? WHERE PeerID = ?");
                stmt.run(1234,noob,hoob,2,peer_id);
                stmt.finalize();
            });

            db.close();
            req.flash('loginMessage','Received Successfully');
            res.redirect('/login');
        }

    }else{

        req.flash('loginMessage','Wrong OOB query!');
        res.redirect('/login');

    }
});

function myFunc (arg1,arg2) {
    console.log('arg was => ' + arg1 + arg2);
}

// process QR-code
app.get('/sendOOB/',isLoggedIn, function (req, res) {
    var peer_id = req.query.P;
    var noob = req.query.N;
    var hoob = req.query.H;
    var queryObject = url.parse(req.url,true).query;
    var len = Object.keys(queryObject).length;
    var options;
    var hash;
    var hash_str;
    var hint;

    if(len != 3 || peer_id == undefined || noob == undefined || hoob == undefined)
    {
        req.flash('profileMessage','Wrong query String! Please try again with proper Query!!' );
        res.redirect('/profile');
    } else if(noob.length != 22 || hoob.length != 22){

        console.log("Updating Error!!!" + peer_id);
        db = new sqlite3.Database(conn_str);

        db.serialize(function() {
            var stmt = db.prepare("UPDATE EphemeralState SET ErrorCode = ? WHERE PeerID = ?");
            stmt.run(3,peer_id);
            stmt.finalize();
            req.flash('profileMessage','Invalid Data');
            res.redirect('/profile');
        });

        db.close();
    } else {
        //console.log(peer_id +' '+ noob +' ' + hoob);
        hash = crypto.createHash('sha256');
        hash_str = 'NoobId'+noob;
        hash.update(hash_str,'utf8');
        var digest = new Buffer(hash.digest());
        digest = digest.slice(0,16);
        hint =  base64url.encode(digest);

        options = {
            mode: 'text',
            pythonPath: '/usr/bin/python',
            pythonOptions: ['-u'],
            scriptPath: configDB.ooblibPath,
            args: ['-i', peer_id, '-p', conn_str,'-n', noob,'-t', OobRetries, '-r',hoob]
        };
        db = new sqlite3.Database(conn_str);
        db.get('SELECT a.accessLevel AS al1, b.accessLevel AS al2 FROM roleAccessLevel a,fqdnACLevel b WHERE (b.fqdn = (SELECT NAS_id FROM radius WHERE user_name = ?) OR b.fqdn = (SELECT d.fqdn FROM roleBasedAC d WHERE calledSID = (SELECT called_st_id FROM radius WHERE user_name = ?))) and a.role = (SELECT c.role FROM users c WHERE username = ?)', peer_id,peer_id,req.user.username, function(err, row1) {
            if(err){res.json({"ProfileMessage": "Failed because of Error!"});}
            else if(enableAC == 0 || row1.al1 >= row1.al2){
                db.get('SELECT ServerState, ErrorCode FROM EphemeralState WHERE PeerId = ?', peer_id, function(err, row2) {
                    db.get('SELECT count(*) as rowCount FROM EphemeralNoob WHERE PeerId = ?', peer_id, function(err, row3) {
                        if (!row2 || row3.rowCount != 0){req.flash('profileMessage','Some Error contact admin!');res.redirect('/profile');console.log("Internal Error");}
                        else if(row2.error_code) {req.flash('profileMessage','Error: ' + error_info[parseInt(row2.errorCode)] +'!!');res.redirect('/profile');console.log("Error" + row2.errorCode);}
                        else if(parseInt(row2.ServerState) != 1) {req.flash('profileMessage','Error: state mismatch. Reset device');res.redirect('/profile');console.log("state mismatch");}
                        else {
                            var parseJ;
                            var err_p;
                            var hoob_cmp_res;
			    console.log("HOOB="+hoob);
			    console.log("NOOB="+noob);	
                            PythonShell.run('oobmessage.py', options, function (err_pr,results) {
                                if (err_pr){console.log("Error in python:" + err_pr); res.json({"status": "Internal error !!"});}
                                else{
                                    parseJ = JSON.parse(results);
                                    err_p = parseJ['err'];
                                    hoob_cmp_res = parseJ['res'];

                                    if(hoob_cmp_res != '8001'){
                                        if(hoob_cmp_res == '8000'){
                                            req.flash('profileMessage','Max OOB tries reaches!');
                                            res.redirect('/profile');
                                            console.log("Max tries reached");
                                        }else{
                                            req.flash('profileMessage','Wrong OOB received!');
                                            res.redirect('/profile');
                                            console.log(" Unrecognized Hoob received Here"+hoob_cmp_res);
                                        }
                                    }else{
                                        db.serialize(function() {
                                            var stmt = db.prepare("INSERT INTO EphemeralNoob(PeerId, NoobId, Noob, sent_time) VALUES(?,?,?,?)");
                                            stmt.run(peer_id, hint, noob, 1234);
                                            stmt.finalize();
                                        });
                                        db.serialize(function() {
                                            var stmt = db.prepare("UPDATE EphemeralState SET ServerState= ? WHERE PeerId = ?");
                                            stmt.run(2, peer_id);
                                            stmt.finalize();
                                        });
                                        db.serialize(function() {
                                            var stmt = db.prepare("INSERT INTO UserDevices(Username, PeerId) VALUES(?,?)");
                                            stmt.run(req.user.username, peer_id);
                                            stmt.finalize();
                                        });
                                        db.close();
                                        req.flash('profileMessage','Message Received Successfully');
                                        res.redirect('/profile');
                                    }
                                }
                            });
                        }
                    });
                });

            }
            else{req.flash('profileMessage','Access denied! Please contact admin.'); res.redirect('/profile'); }
        });
    }
});

app.get('/stateUpdate',isLoggedIn, function(req, res) {
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

app.get('/deleteDeviceTemp',isLoggedIn, function(req, res) {
    var peer_id = req.query.PeerId;
    var queryObject = url.parse(req.url,true).query;
    var len = Object.keys(queryObject).length;
    console.log(req.user.username + " " + peer_id);	
    if(len != 1 || peer_id == undefined)
    {
        res.json({"status":"failed"});
    }else{
        console.log('req received');

        db = new sqlite3.Database(conn_str);
        db.get('SELECT count(*) AS rowCount FROM devices WHERE PeerID = ? AND UserName = ?', peer_id, req.user.username, function(err, row) {

            console.log(req.user.username + " " + peer_id);	
            if (err){res.json({"status": "failed"});}
            else if(row.rowCount != 1) {res.json({"status": "refresh"});}
            else {
                db.get('DELETE FROM devices WHERE PeerID = ? AND UserName = ?', peer_id, req.user.username, function(err, row) {
                    db.close();
                    if (err){res.json({"status": "failed"});}
                    else {res.json({"status": "success"});}
                });
            }
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
    //console.log("called islogged");
    // if user is authenticated in the session, carry on 
    if (req.isAuthenticated())
        return next();

    var str = req.path;

    var peer_id = req.query.P;

    var noob = req.query.N;

    var hoob = req.query.H;

    if(str == "/sendOOB/") req.flash('loginMessage','Login to register device');

    if(peer_id != undefined)  str = str + '?P=' + peer_id;
    if(noob != undefined)  str = str + '&N=' + noob;
    if(hoob != undefined)  str = str + '&H=' + hoob;
    req.session.returnTo = str;
    res.redirect('/login');
}

// route middleware to make sure a user is admin
function isAdmin(req, res, next) {
    //console.log("Called is Admin " + req.user.isAdmin + req.user.username);
    // if user is authenticated and is admin, carry on 
    if  (req.user.isAdmin == "TRUE")
        return next();

    res.redirect('/profile');
}
