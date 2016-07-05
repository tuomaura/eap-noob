var express = require('express');
var bodyParser = require('body-parser');
var path = require('path');
var sqlite3 = require('sqlite3').verbose();
var db;
var url = require('url');

var router = express.Router();


/*
router.get('/QRcode', function (req, res) {
     var id = req.query.id;
     var par = req.query.name;
     var queryObject = url.parse(req.url,true).query;
     console.log(Object.keys(queryObject).length);
     if(par == undefined)
	console.log("Its undefined");
     console.log("Get Called!!!" + id +" " + par);
     res.json({message: 'Successfull Received'});
});
*/

router.get('/QRcode/', function (req, res) {
     
     var peer_id = req.query.PeerId;
     var noob = req.query.Noob;
     var hoob = req.query.Hoob;
     var queryObject = url.parse(req.url,true).query;
     var len = Object.keys(queryObject).length;
	
     if(len != 3 || peer_id == undefined || noob == undefined || hoob == undefined)
     {
    	console.log("Its wrong Query");
	res.json({message: 'Wrong query String! Please try again with proper Query!!'});
     }else{

     	//console.log("Get Called!!!" + peer_id +" "+ noob +" "+ hoob);
     	console.log("Inserting!!!" + peer_id);
     	db = new sqlite3.Database('/home/mudugor1/EAP-NOOB/new_code/3july_config_read/for_checkin/eap-oob-2016/hostapd-2.5/hostapd/peer_connection_db')
     	
        db.serialize(function() {
       		var stmt = db.prepare("UPDATE peers_connected SET OOB_RECEIVED_FLAG = ?, Noob = ?, Hoob = ? WHERE PeerID = ?");
       		stmt.run(1234,noob,hoob,peer_id);
		stmt.finalize();

       		db.each("SELECT PeerID, OOB_RECEIVED_FLAG FROM peers_connected", function(err, row) {
       			console.log(row.PeerID + ": " + row.OOB_RECEIVED_FLAG);     
       		});
    	});

	db.close();
     	res.json({message: 'Received Successfully'});
    }
});

router.get('/QRcode/:peer_id/:noob/:hoob', function (req, res) {
     console.log("Get Called!!!" + req.params.peer_id +" "+ req.params.noob +" "+ req.params.hoob);
     console.log("Inserting!!!" + req.params.peer_id);
     db = new sqlite3.Database('/home/kserver/Desktop/hostapd-2.5/hostapd/peer_connection_db')
     db.serialize(function() {
       var stmt = db.prepare("UPDATE peers_connected SET OOB_RECEIVED_FLAG = ?, Noob = ?, Hoob = ? WHERE PeerID = ?");
       stmt.run(1234,req.params.noob,req.params.hoob,req.params.peer_id);
       stmt.finalize();
       db.each("SELECT PeerID, OOB_RECEIVED_FLAG FROM peers_connected", function(err, row) {
       console.log(row.PeerID + ": " + row.OOB_RECEIVED_FLAG);
     
       });
    });
	db.close();
     res.json({message: 'Received Successfully'});
});

/*
router.post('/QRcode', function (req, res) {
     console.log("Inserting!!!" + req.body.peer_id);
     
     db.serialize(function() {
       var stmt = db.prepare("UPDATE peers_connected SET OOB_received = ? WHERE PeerID = ?");
       stmt.run(parseInt(req.body.qr_code),req.body.peer_id);
       stmt.finalize();
       db.each("SELECT PeerID, OOB_received FROM peers_connected", function(err, row) {
       console.log(row.PeerID + ": " + row.OOB_received);
     
       });
    });
	db.close();
	res.json({message: 'Received Successfully'});	
});
*/

module.exports = router;
