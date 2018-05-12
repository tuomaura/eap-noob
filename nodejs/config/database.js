// config/database.js
module.exports = {

    'ooblibPath' : '/home/mudugor1/x25519/hostapd-2.6/hostapd',
    'dbPath' : '/etc/peer_connection_db',
    'url'    : '',
    'radCliPath' : '/home/mudugor1/x25519/hostapd-2.6/hostapd/hostapd.radius_clients',
    'enableAccessControl' : '0', //set '1' to enable
    'OobRetries' : '5', //number of times to try sending OOB before sending failure to peer
    'NoobTimeout' : '30', //noob timeout in seconds
    'NoobInterval' : '1800' //noob interval in seconds(Currently not required as generated on demand.)
};
