#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>

#ifndef EAPOOB_H
#define EAPOOB_H

/*Configuration file*/
#define CONF_FILE "eapoob.conf"

/* All the pre-processors of EAP-NOOB*/

#define NUM_OF_VERSIONS 		 1
#define PEER_ID_DEFAULT 		"noob@eap-noob.net"	 
#define MAX_PATH_LEN			256
#define MAX_QUERY_LEN			2048
#define SHORT_QUERY_LEN			500
#define DOMAIN		    		"@eap-noob.net"
#define VERSION_ONE 			1
#define SUITE_ONE 			1
#define TABLE_NAME			"connections"
#define DB_NAME				"peer_connection_db"
#define HINT_SALT			"AFARMERLIVEDUNDERTHEMOUNTAINANDGREWTURNIPSFORALIVING"
#define EAP_NOOB_NONCE_LEN      	16
#define EAP_SHARED_SECRET_LEN   	32
#define ECDH_KDF_MAX 			(1 << 30)

#define ALGORITHM_ID			"EAP-NOOB"
#define ALGORITHM_ID_LEN    		8

/*MAX values for the fields*/
#define MAX_SUP_VER             	1
#define MAX_SUP_CSUITES			1
#define MAX_PEER_ID_LEN 		60
#define MAX_CONF_LEN			500
#define MAX_INFO_LEN			500

#define KDF_LEN				192
#define MSK_LEN     			64
#define EMSK_LEN			64
#define KZ_LEN				32
#define KMS_LEN				16
#define KMP_LEN				16
#define MAC_LEN				16
#define FIXED_LENGTH             	6

#define HASH_LEN     			16
#define NUM_OF_STATES           	5
#define MAX_MSG_TYPES           	8

/*OOB DIRECTIONS*/
#define PEER_TO_SERV 			1
#define SERV_TO_PEER			2
#define BOTH_DIR			3



#define SUCCESS 			1
#define FAILURE 			0

#define INVALID                 	0
#define VALID                   	1

/*keywords for json encoding and decoding*/

#define TYPE 				"Type"
#define VERSION_SERV 			"Vers"
#define CSUITES_SERV			"Cryptosuites"
#define DIRECTION_SERV			"Dirs"
#define NONCE_SERV			"Ns"
#define MINSLEEP			"minsleep"
#define PEERID				"PeerID"
#define PUBLICKEY_SERV			"PKs"
#define SERV_INFO			"ServerInfo"
#define MAC_SERVER			"MACs"
#define HINT				"Hint"

#define VERSION_PEER 			"Verp"
#define CSUITES_PEER			"Cryptosuitep"
#define DIRECTION_PEER			"Dirp"
#define NONCE_PEER			"Np"
#define PUBLICKEY_PEER			"PKp"
#define PEERINFO			"PeerInfo"
#define MAC_PEER			"MACp"

#define ERR_INFO        		"ErrorInfo"
#define ERR_CODE        		"ErrorCode"
#define X_COORDINATE    		"x"
#define Y_COORDINATE    		"y"
#define JSON_WEB_KEY    		"jwk"
#define KEY_TYPE        		"kty"
#define CURVE           		"crv"

#define PEER_NAME			"PeerName"
#define PEER_SERIAL_NUM			"PeerSNum"
#define PEER_SSID			"PeerSSID"
#define PEER_BSSID			"PeerBSSID"


/*bit masks to validate message structure*/
#define PEERID_RCVD            		0x0001
#define DIRECTION_RCVD         		0x0002
#define CSUITE_RCVD             	0x0004
#define VERSION_RCVD            	0x0008
#define NONCE_RCVD              	0x0010
#define MAC_RCVD                	0x0020
#define PKEY_RCVD               	0x0040
#define INFO_RCVD               	0x0080
#define STATE_RCVD              	0x0100
#define MINSLP_RCVD             	0x0200
#define PEER_NAME_RCVD			0x0400
#define PEER_ID_NUM_RCVD		0x0800

#define TYPE_ONE_PARAMS         	(PEERID_RCVD|VERSION_RCVD|CSUITE_RCVD|DIRECTION_RCVD|INFO_RCVD) 
#define TYPE_TWO_PARAMS         	(PEERID_RCVD|NONCE_RCVD|PKEY_RCVD)
#define TYPE_THREE_PARAMS       	(PEERID_RCVD|MINSLP_RCVD)
#define TYPE_FOUR_PARAMS        	(PEERID_RCVD|MAC_RCVD)
#define TYPE_FIVE_PARAMS        	(PEERID_RCVD|CSUITE_RCVD|INFO_RCVD)
#define TYPE_SIX_PARAMS         	(PEERID_RCVD|NONCE_RCVD)
#define TYPE_SEVEN_PARAMS       	(PEERID_RCVD|MAC_RCVD)
#define TYPE_HINT_PARAMS			(PEERID_RCVD)
#define CONF_PARAMS			(DIRECTION_RCVD|CSUITE_RCVD|VERSION_RCVD|PEER_NAME_RCVD|PEER_ID_NUM_RCVD)


#if 1
#define JSON_ARRAY_FOREACH json_array_foreach
#include <jansson.h>

typedef json_t 		noob_json_t;	
typedef json_int_t 	noob_json_int_t;
typedef char		noob_json_str_t;
typedef json_error_t 	noob_json_error_t;
#endif

/*SQL query to create peer connection database*/
#define CREATE_CONNECTION_TABLE "CREATE TABLE connections(\
					ssid TEXT PRIMARY KEY,\
					PeerID TEXT,\
					Vers INTEGER,\
					Verp INTEGER,\
					state INTEGER,\
					Csuites INTEGER,\
					Csuitep INTEGER,\
					Dirs INTEGER,\
					Dirp INTEGER,\
					nonce_peer TEXT,\
					nonce_serv TEXT,\
					minsleep INTEGER,\
					ServInfo TEXT,\
					PeerInfo TEXT,\
					SharedSecret TEXT,\
					Noob TEXT,\
					Hoob TEXT,\
					OOB_RECEIVED_FLAG INTEGER,\
					kms TEXt,\
					kmp TEXT,\
					kz TEXT,\
					pub_key_serv TEXT,\
					pub_key_peer TEXT,\
					err_code INTEGER,\
					show_OOB INTEGER)"  

/*SQL Query to check peerID data*/


/*SQL query to check number of rows*/
#define CHECK_NUMBER_OF_ROWS 		"SELECT COUNT(*) FROM connections;"


/*server state vs message type matrix*/ 
const int state_message_check[NUM_OF_STATES][MAX_MSG_TYPES] = {
	        {VALID,VALID,VALID,INVALID,INVALID,INVALID,INVALID,INVALID},  //UNREG
       		{VALID,VALID,VALID,VALID,VALID,INVALID,INVALID,INVALID},      //WAITING
        	{VALID,VALID,VALID,INVALID,VALID,INVALID,INVALID,INVALID},    //OOB
        	{VALID,INVALID,INVALID,INVALID,INVALID,VALID,VALID,VALID},  //RECONNECT
        	{VALID,INVALID,INVALID,INVALID,VALID,INVALID,INVALID,INVALID},//REGISTERED
};


enum	{COMPLETION_EXCHANGE, RECONNECT_EXCHANGE, RECONNECT_EXCHANGE_NEW}; //Flag used during KDF and MAC generation
enum 	{UNREG, WAITING, OOB, RECONNECT,REGISTERED};
enum	{NONE, EAP_NOOB_TYPE_1,EAP_NOOB_TYPE_2,EAP_NOOB_TYPE_3,EAP_NOOB_TYPE_4,EAP_NOOB_TYPE_5,EAP_NOOB_TYPE_6,EAP_NOOB_TYPE_7,EAP_NOOB_HINT};
enum 	eap_noob_err_code{NO_ERROR,E1001,E1002,E1003,E1004,E1005,E1006,E2001,E2002,E3001,E3002,E3003,E4001};
enum 	{HOOB,MACS,MACP};
enum    {UPDATE_ALL,UPDATE_STATE,UPDATE_STATE_MINSLP, UPDATE_PERSISTENT_KEYS_SECRET,UPDATE_STATE_ERROR,UPDATE_OOB};
struct eap_noob_peer_config_params{	

	char * Peer_name;
	char * Peer_ID_Num;

};

struct eap_noob_peer_context{

        struct eap_noob_peer_data *peer_attr;
	struct eap_noob_serv_data *serv_attr;
        char * db_name;
        char * db_table_name;
	sqlite3 * peerDB;
};


struct eap_noob_peer_data{

        u32 version;
        u32 state;
        u32 cryptosuite;
        u32 dir;
        u32 minsleep;
	u32 config_params;

        char * peerID;
	char * peer_info;
	char * MAC;

	struct eap_noob_peer_config_params * peer_config_params;
	
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

	char * x_serv_b64;
	char * y_serv_b64;
	
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
	u8 * noob;
	char * hoob_b64;
	u8 * hoob;
};


struct eap_noob_serv_data{

        u32 version[MAX_SUP_VER];
        u32 state;
        u32 cryptosuite[MAX_SUP_CSUITES];
        u32 dir;
        u32 minsleep;
	u32 rcvd_params;

	char * serv_info;
	char * NAI;
	char * MAC;
        char * ssid;
        char * peerID;

   	enum eap_noob_err_code err_code; 
	Boolean record_present;
	
	struct eap_noob_ecdh_key_exchange * ecdh_exchange_data;
	struct eap_noob_oob_data * oob_data;
	struct eap_noob_ecdh_kdf_nonce * kdf_nonce_data;
	struct eap_noob_ecdh_kdf_out * kdf_out;

		
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


/*Function prototypes*/

static noob_json_t * eap_noob_json_array();
static u32  eap_noob_json_array_append(noob_json_t * arr, noob_json_t * value);
static noob_json_t * eap_noob_json_integer(noob_json_int_t value);
static noob_json_int_t eap_noob_json_integer_value(noob_json_t * value);
static u32 eap_noob_json_is_integer(const noob_json_t * value);
static noob_json_t * eap_noob_json_string(const noob_json_str_t * value);
static noob_json_str_t * eap_noob_json_string_value(noob_json_t * value);
static noob_json_t * eap_noob_json_object();
static u32 eap_noob_json_object_set_new (noob_json_t * obj, const char* key, noob_json_t * value);
static char * eap_noob_json_dumps(noob_json_t * root, size_t flags);
static noob_json_t * eap_noob_json_loads(const char * input, size_t flags, noob_json_error_t * error);
static u32 eap_noob_json_is_object(noob_json_t * obj);
static noob_json_t * eap_noob_json_object_get(noob_json_t * obj, const char * key);
static u32 eap_noob_json_typeof(const noob_json_t * value);
//static int eap_noob_sendUpdateSignal();
static void eap_noob_gen_KDF(struct eap_noob_peer_context * data, int state);
static noob_json_t * eap_noob_prepare_peer_info_json(struct eap_sm *sm,struct eap_noob_peer_config_params * data);
static char * eap_noob_prepare_mac_arr(const struct eap_noob_peer_context * data, int type, int state);
static u8 * eap_noob_gen_MAC(const struct eap_noob_peer_context * data,int type, u8 * key, int keylen, int state);
static int eap_noob_get_noob(struct eap_noob_peer_context *data);
static int eap_noob_send_oob(struct eap_noob_peer_context *data);
size_t eap_noob_calcDecodeLength(const char* b64input);
int eap_noob_Base64Decode(char* b64message, unsigned char** buffer, size_t* length);
int eap_noob_Base64Encode(const unsigned char* buffer, size_t length, char** b64text);
int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
                const unsigned char *Z, size_t Zlen,
                const unsigned char *algorithm_id, size_t algorithm_id_len,
                const unsigned char * partyUinfo, size_t partyUinfo_len,
                const unsigned char * partyVinfo, size_t partyVinfo_len,
                const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
                const EVP_MD *md);
static char * eap_noob_prepare_hoob_arr(const struct eap_noob_peer_context * data);
static int eap_noob_get_hoob(struct eap_noob_peer_context *data,unsigned char *out, size_t outlen);
static int eap_noob_derive_secret(struct eap_noob_peer_context *data, size_t *secret_len);
static int eap_noob_get_key(struct eap_noob_serv_data *data);
static void eap_noob_verify_param_len(struct eap_noob_serv_data * data);
static void  eap_noob_decode_obj(struct eap_noob_serv_data * data ,noob_json_t * req_obj);
static void eap_noob_assign_waittime(struct eap_sm *sm,struct eap_noob_peer_context *data);
int eap_noob_check_compatibility(struct eap_noob_peer_context *data);
static void eap_noob_config_change(struct eap_sm *sm , struct eap_noob_peer_context *data);
int eap_noob_db_entry_check(void * priv , int argc, char **argv, char **azColName);
int eap_noob_callback(void * priv , int argc, char **argv, char **azColName);
static int eap_noob_exec_query(const char * query, int(*callback)(void*, int ,char **, char ** ),
                void * argv, struct eap_noob_peer_context *data);
static int eap_noob_db_update (struct eap_noob_peer_context *data, u8 type);
static int eap_noob_db_entry(struct eap_sm *sm,struct eap_noob_peer_context *data);
static struct wpabuf * eap_noob_err_msg(struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_verify_peerID(struct eap_noob_peer_context * data, u8  id);
static struct wpabuf * eap_noob_rsp_type_four(const struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_rsp_type_three(const struct eap_noob_peer_context *data, u8 id);
static int eap_noob_build_JWK( noob_json_t ** jwk, const char * x_b64, const char * y_b64);
static struct wpabuf * eap_noob_rsp_type_two(struct eap_noob_peer_context *data, u8 id);
static int eap_noob_build_JWK( noob_json_t ** jwk, const char * x_b64, const char * y_b64);
static struct wpabuf * eap_noob_rsp_type_two(struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_rsp_type_one(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_rsp_type_five(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_rsp_type_six(struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_rsp_type_seven(const struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_req_type_seven(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_req_type_six(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_req_type_five(struct eap_sm *sm,noob_json_t * req_obj , struct eap_noob_peer_context *data,
                u8 id);
static struct wpabuf * eap_noob_req_type_four(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_req_type_three(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_req_type_two(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id);
static struct wpabuf * eap_noob_req_type_one(struct eap_sm *sm,noob_json_t * req_obj , struct eap_noob_peer_context *data,
                u8 id);
static void eap_noob_req_err_handling(struct eap_sm *sm,noob_json_t * req_obj , struct eap_noob_peer_context *data,
                u8 id);
static struct wpabuf * eap_noob_process (struct eap_sm *sm, void *priv,
                struct eap_method_ret *ret,
                const struct wpabuf *reqData);
static void eap_noob_free_ctx(struct eap_noob_peer_context * data);
static void eap_noob_deinit(struct eap_sm *sm, void *priv);
static int eap_noob_create_db(struct eap_sm *sm,struct eap_noob_peer_context * data);
static void eap_noob_assign_config(char * conf_name,char * conf_value,struct eap_noob_peer_data * data);
static void eap_noob_parse_config(char * buff,struct eap_noob_peer_data * data);
static int eap_noob_handle_incomplete_conf(struct eap_noob_peer_context * data);
static int eap_noob_prepare_peer_info_obj(struct eap_noob_peer_data * data);
static int eap_noob_read_config(struct eap_sm *sm,struct eap_noob_peer_context * data);
static int eap_noob_peer_ctxt_alloc(struct eap_sm *sm,  struct eap_noob_peer_context * data);
static int eap_noob_peer_ctxt_init(struct eap_sm *sm,  struct eap_noob_peer_context * data);
static void * eap_noob_init(struct eap_sm *sm);
static Boolean eap_noob_isKeyAvailable(struct eap_sm *sm, void *priv);
static u8 * eap_noob_getKey(struct eap_sm *sm, void *priv, size_t *len);
static u8 * eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len);
static void eap_noob_deinit_for_reauth(struct eap_sm *sm, void *priv);
static Boolean eap_noob_has_reauth_data(struct eap_sm *sm, void *priv);
int eap_peer_noob_register(void);


#endif 
