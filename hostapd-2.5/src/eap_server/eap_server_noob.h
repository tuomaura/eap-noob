#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <time.h>


#ifndef EAPOOB_H
#define EAPOOB_H


/*Configuration file*/
#define CONF_FILE 		"eapoob.conf"
#define JSON_ARRAY_FOREACH json_array_foreach
#include <jansson.h>

typedef json_t 		noob_json_t;	
typedef json_int_t 	noob_json_int_t;
typedef char		noob_json_str_t;
typedef json_error_t 	noob_json_error_t;

/* All the pre-processors of EAP-NOOB*/

#define NUM_OF_VERSIONS  	1
#define PEER_ID_DEFAULT_REALM 	"noob@eap-noob.net"
#define PEER_ID_DEFAULT	 	"noob"
#define DOMAIN		    	"eap-noob.net"
#define SERVER_INFO		"Believe_me_i_am_an_authenticated_server"
#define PUBLIC_KEY      	"A Very secret public key"
#define VERSION_ONE 		1
#define SUITE_ONE 		1
#define EAP_NOOB_NONCE_LEN      16
#define EAP_SHARED_SECRET_LEN   32
#define ALGORITHM_ID		"EAP-NOOB"
#define ALGORITHM_ID_LEN    	8

/*MAX values for fields*/
#define MAX_SUP_VER		1
#define MAX_SUP_CSUITES		1
#define MAX_CONF_LEN    	500
#define MAX_INFO_LEN		500
#define MAX_PEER_ID_LEN 	60
#define MAX_LINE_SIZE		1000

#define KDF_LEN			192
#define MSK_LEN     		64
#define EMSK_LEN		64
#define KZ_LEN			32
#define KMS_LEN			16
#define KMP_LEN			16
#define MAC_LEN			16
#define FIXED_LENGTH             6

#define HASH_LEN     		16

/* Valid or Invalid states*/
	
#define INVALID 		0
#define VALID   		1
#define NUM_OF_STATES   	5
#define MAX_MSG_TYPES   	8

/*OOB DIRECTIONS*/
#define PEER_TO_SERV 		1
#define SERV_TO_PEER		2
#define BOTH_DIR		3

#define SUCCESS         	1
#define FAILURE         	0

#define DONE			1
#define NOT_DONE		0

/*Maximum allowed waiting exchages*/
#define MAX_WAIT_EXCHNG_TRIES 	10

/*keywords for json encoding and decoding*/

#define TYPE 			"Type"
#define ERR_INFO		"ErrorInfo"
#define ERR_CODE		"ErrorCode"

#define VERSION_SERV 		"Vers"
#define CSUITES_SERV		"Cryptosuites"
#define DIRECTION_SERV		"Dirs"
#define NONCE_SERV		"Ns"
#define MINSLEEP		"minsleep"
#define PEERID			"PeerID"
#define PUBLICKEY_SERV		"PKs"
#define SERV_INFO		"ServerInfo"
#define MACs			"MACs"

#define PEER_NAME                       "PeerName"
#define PEER_SERIAL_NUM                 "PeerSNum"
 

#define VERSION_PEER 		"Verp"
#define CSUITES_PEER		"Cryptosuitep"
#define DIRECTION_PEER		"Dirp"
#define NONCE_PEER		"Np"
#define PUBLICKEY_PEER		"PKp"
#define PEER_INFO		"PeerInfo"
#define PEERSTATE       	"state"
#define HINT			"Hint"
#define MACp			"MACp" 
#define X_COORDINATE    	"x"
#define Y_COORDINATE    	"y"
#define JSON_WEB_KEY    	"jwk"
#define KEY_TYPE        	"kty"
#define CURVE           	"crv"
#define ECDH_KDF_MAX 		(1 << 30)

#define SERV_NAME		"ServName"
#define SERV_URL		"ServUrl"

#define PEERID_RCVD 		0x0001
#define DIRECTION_RCVD 		0x0002
#define CSUITE_RCVD		0x0004
#define VERSION_RCVD		0x0008
#define NONCE_RCVD		0x0010
#define MAC_RCVD		0x0020
#define PKEY_RCVD		0x0040
#define INFO_RCVD		0x0080
#define STATE_RCVD		0x0100
#define MINSLP_RCVD		0x0200
#define SERV_NAME_RCVD		0x0400
#define SERV_URL_RCVD		0x0800
#define HINT_RCVD		0x1000



#define TYPE_ONE_PARAMS		(PEERID_RCVD|VERSION_RCVD|CSUITE_RCVD|DIRECTION_RCVD|INFO_RCVD) 
#define TYPE_TWO_PARAMS		(PEERID_RCVD|NONCE_RCVD|PKEY_RCVD)
#define TYPE_THREE_PARAMS	(PEERID_RCVD)
#define TYPE_FOUR_PARAMS	(PEERID_RCVD|MAC_RCVD)
#define TYPE_FIVE_PARAMS        (PEERID_RCVD|CSUITE_RCVD|INFO_RCVD)
#define TYPE_SIX_PARAMS		(PEERID_RCVD|NONCE_RCVD)
#define TYPE_SEVEN_PARAMS       (PEERID_RCVD|MAC_RCVD)
#define TYPE_HINT_PARAMS        (PEERID_RCVD|HINT_RCVD)

#define CONF_PARAMS             (DIRECTION_RCVD|CSUITE_RCVD|VERSION_RCVD|SERV_NAME_RCVD|SERV_URL_RCVD)

#define DEVICE_TABLE		"devices"

/*SQL query to create peer connection database*/
#define CREATE_CONNECTION_TABLE "CREATE TABLE IF NOT EXISTS peers_connected(\
                                PeerID TEXT PRIMARY KEY,\
                                Verp INTEGER,\
                                Vers INTEGER,\
                                peer_state INTEGER,\
                                serv_state INTEGER,\
                                Csuites INTEGER,\
                                Csuitep INTEGER,\
                                Dirp INTEGER,\
                                Dirs INTEGER,\
                                nonce_serv TEXT,\
                                nonce_peer TEXT,\
                                PeerInfo TEXT,\
                                ServInfo TEXT,\
				SharedSecret TEXT,\
				Noob TEXT,\
				Hoob TEXT,\
				MINSLP_count INTEGER,\
				OOB_RECEIVED_FLAG INTEGER,\
				kms TEXt,\
				kmp TEXT,\
				kz TEXT,\
				pub_key_serv TEXT,\
				pub_key_peer TEXT,\
				UserName TEXT,\
				DevUpdate INTEGER ,\
				sleepTime UNSIGNED BIG INT,\
				errorCode INTEGER)" 




enum{COMPLETION_EXCHANGE, RECONNECT_EXCHANGE, RECONNECT_EXCHANGE_NEW}; //Flag used during KDF and MAC generation
enum {UNREG, WAITING, OOB, RECONNECT,REGISTERED};
enum {NONE, EAP_NOOB_TYPE_1,EAP_NOOB_TYPE_2,EAP_NOOB_TYPE_3,EAP_NOOB_TYPE_4,EAP_NOOB_TYPE_5,EAP_NOOB_TYPE_6,EAP_NOOB_TYPE_7, EAP_NOOB_TYPE_HINT};
enum {UPDATE_ALL,UPDATE_STATE,UPDATE_STATE_MINSLP, UPDATE_PERSISTENT_KEYS_SECRET,UPDATE_STATE_ERROR, UPDATE_OOB};
enum eap_noob_err_code{NO_ERROR,E1001,E1002,E1003,E1004,E1005,E1006,E2001,E2002,E3001,E3002,E3003,E4001}; 
enum {HOOB,MACS,MACP};

struct eap_noob_serv_config_params{

        char * Serv_name;
        char * Serv_URL;

};

struct eap_noob_serv_context{

        struct eap_noob_peer_data *peer_attr;
	struct eap_noob_server_data *server_attr;
        char * db_name;
        char * db_table_name;
	sqlite3 * servDB;
};

struct eap_noob_ecdh_kdf_nonce{

        u8 * nonce_serv;
        char * nonce_serv_b64;
        u8 * nonce_peer;
        char * nonce_peer_b64;

};

struct eap_noob_ecdh_kdf_out{

        u8 * msk;
        char * msk_b64;
        u8 * emsk;
        char * emsk_b64;
        u8 * kms;
        char * kms_b64;
        u8 * kmp;
        char * kmp_b64;
        u8 * kz;
        char * kz_b64;
};

struct eap_noob_ecdh_key_exchange{

        EVP_PKEY *dh_key;

        char * x_peer_b64;
        char * y_peer_b64;

        char * x_b64;
        size_t x_len;
        char * y_b64;
        size_t y_len;

        noob_json_t * jwk_serv;
        noob_json_t * jwk_peer;

        u8 * shared_key;
        char * shared_key_b64;
        size_t shared_key_b64_len;

};

struct eap_noob_oob_data{

        char * noob_b64;
	size_t noob_len;
        u8 * noob;

        char * hoob_b64;
	size_t hoob_len;
        u8 * hoob;

	char * hint_b64;
	size_t hint_len;
	u8 * hint;
};



struct eap_noob_peer_data{

        u32 version; 
        u32 cryptosuite;
        u32 dir;
        u32 minsleep; 
	u32 recv_msg;
	u32 rcvd_params;
	u32 minslp_count;
	int oob_recv;	

        u8 peer_state;
        u8 serv_state;
	u8 next_req;
	u8 is_done;
	u8 is_success;

        char * peerID_rcvd;
        char * peerID_gen;
	char * peer_info;
	char * peer_snum;
	char * NAI;
	char * user_name_peer;
	char * realm;
	char * mac;
	char * user_info;
	Boolean record_present;

	enum eap_noob_err_code err_code;
	
	struct timespec sleep_time;

        struct eap_noob_ecdh_key_exchange * ecdh_exchange_data;
        struct eap_noob_oob_data * oob_data;
        struct eap_noob_ecdh_kdf_nonce * kdf_nonce_data;
        struct eap_noob_ecdh_kdf_out * kdf_out;

	
};


struct eap_noob_server_data{

        u32 version[MAX_SUP_VER];
        u32 cryptosuite[MAX_SUP_CSUITES];
        u32 dir;
	char * serv_info;
	
	u32 config_params;
        struct eap_noob_serv_config_params * serv_config_params;

};

const int error_code[] = {0,1001,1002,1003,1004,1005,1006,2001,2002,3001,3002,3003,4001};

const char *error_info[] = { "No error",	
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
			     "MAC verification failure"};


/*This 2-D arry is used for state validation. Cloumn number represents the state of Peer and the row number represents the server state*/

/*The states are in squence as: {UNREG, WAITING, OOB, RECONNECT, REGISTERED} for both peer and server */
const int state_machine[][5] = {{VALID, INVALID, INVALID, INVALID, INVALID},
			       {VALID, VALID, VALID, INVALID, INVALID},
			       {VALID, VALID, VALID, INVALID,INVALID},
 			       {VALID, INVALID, INVALID, VALID, VALID},
 		 	       {VALID, INVALID, INVALID, VALID, INVALID}
			      };

const int next_request_type[] = {EAP_NOOB_TYPE_1, NONE, NONE, NONE, NONE, 
                                 EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_3, EAP_NOOB_TYPE_4, NONE, NONE,
                                 EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_4, EAP_NOOB_TYPE_4, NONE, NONE,
				 EAP_NOOB_TYPE_1, NONE, NONE,EAP_NOOB_TYPE_5, EAP_NOOB_TYPE_5,
				 EAP_NOOB_TYPE_1, NONE, NONE, EAP_NOOB_TYPE_5, NONE};


/*server state vs message type matrix*/
const int state_message_check[NUM_OF_STATES][MAX_MSG_TYPES] = {
	{VALID,VALID,VALID,INVALID,INVALID,INVALID,INVALID,INVALID}, 	//UNREG
	{VALID,VALID,VALID,VALID,VALID,INVALID,INVALID,INVALID}, 	//WAITING
	{VALID,VALID,VALID,INVALID,VALID,INVALID,INVALID,INVALID}, 	//OOB
	{VALID,INVALID,INVALID,INVALID,INVALID,VALID,VALID,VALID},  	//RECONNECT
	{VALID,INVALID,INVALID,INVALID,VALID,INVALID,INVALID,INVALID},//REGISTERED
};
/*Function prototypes*/
static noob_json_t * eap_noob_prepare_vers_arr(const struct eap_noob_serv_context * data);
static noob_json_t * eap_noob_prepare_csuites_arr(const struct eap_noob_serv_context * data);
static void eap_noob_set_done(struct eap_noob_serv_context *,u8 );
static void eap_noob_set_success(struct eap_noob_serv_context *, u8);

#endif 
