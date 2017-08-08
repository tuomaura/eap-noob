#ifndef EAPOOB_H
#define EAPOOB_H


/* Configuration file */
#define CONF_FILE               "eapoob.conf"

/* All the pre-processors of EAP-NOOB */

#if 0
/* Unused macros */
#define NUM_OF_VERSIONS 		 1
#define PEER_ID_DEFAULT 		"noob@eap-noob.net"
#define HINT_SALT			"AFARMERLIVEDUNDERTHEMOUNTAINANDGREWTURNIPSFORALIVING"
#define JSON_WEB_KEY          "jwk"
#endif

#define MAX_PATH_LEN                256
#define MAX_QUERY_LEN               2048
#define SHORT_QUERY_LEN             500
#define DOMAIN                      "@eap-noob.net"
#define DEFAULT_REALM               "eap-noob.net"
#define VERSION_ONE                 1
#define SUITE_ONE                   1
#define TABLE_NAME                  "connections"
#define DB_NAME                     "peer_connection_db"
#define EAP_NOOB_NOOB_LEN           16
#define EAP_NOOB_NONCE_LEN          32
#define EAP_SHARED_SECRET_LEN       32
#define ECDH_KDF_MAX                (1 << 30)
#define MAX_URL_LEN                 60
#define ALGORITHM_ID                "EAP-NOOB"
#define ALGORITHM_ID_LEN            8
#define FORMAT_BASE64URL            1

/*MAX values for the fields*/
#define MAX_SUP_VER             1
#define MAX_SUP_CSUITES         1
#define MAX_PEER_ID_LEN         22
#define MAX_CONF_LEN            500
#define MAX_INFO_LEN            500
#define MAX_LINE_SIZE           1000

#define KDF_LEN                 288
#define MSK_LEN                 64
#define EMSK_LEN                64
#define AMSK_LEN                64
#define KZ_LEN                  32
#define KMS_LEN                 32
#define KMP_LEN                 32
#define MAC_LEN                 16
#define FIXED_LENGTH            6
#define MAX_X25519_LEN          48

#define HASH_LEN                16
#define NUM_OF_STATES           5
#define MAX_MSG_TYPES           8

/* OOB DIRECTIONS */
#define PEER_TO_SERV            1
#define SERV_TO_PEER            2
#define BOTH_DIR                3

#define SUCCESS                 1
#define FAILURE                 0

#define INVALID                 0
#define VALID                   1

/* keywords for json encoding and decoding */
#define TYPE                    "Type"
#define ERRORINFO               "ErrorInfo"
#define ERRORCODE               "ErrorCode"
#define VERS                    "Vers"
#define CRYPTOSUITES            "Cryptosuites"
#define DIRS                    "Dirs"
#define NS                      "Ns"
#define SLEEPTIME               "SleepTime"
#define PEERID                  "PeerId"
#define PKS                     "PKs"
#define SERVERINFO              "ServerInfo"
#define MACS                    "MACs"

#define HINT_PEER               "NoobId"
#define HINT_SERV               "NoobId"

#define VERP                    "Verp"
#define CRYPTOSUITEP            "Cryptosuitep"
#define DIRP                    "Dirp"
#define NP                      "Np"
#define PKP                     "PKp"
#define PEERINFO                "PeerInfo"
#define MACP                    "MACp"

#define X_COORDINATE            "x"
#define Y_COORDINATE            "y"
#define REALM                   "Realm"
#define KEY_TYPE                "kty"
#define CURVE                   "crv"

#define PEER_SERIAL_NUM         "Serial"
#define PEER_SSID               "SSID"
#define PEER_BSSID              "BSSID"
#define PEER_TYPE               "Type"
#define PEER_MAKE               "Make"

/*bit masks to validate message structure*/
#define PEERID_RCVD                 0x0001
#define DIRS_RCVD                   0x0002
#define CRYPTOSUITES_RCVD           0x0004
#define VERSION_RCVD                0x0008
#define NONCE_RCVD                  0x0010
#define MAC_RCVD                    0x0020
#define PKEY_RCVD                   0x0040
#define INFO_RCVD                   0x0080
#define STATE_RCVD                  0x0100
#define MINSLP_RCVD                 0x0200
#define PEER_MAKE_RCVD              0x0400
#define PEER_ID_NUM_RCVD            0x0800
#define HINT_RCVD                   0x1000
#define DEF_MIN_SLEEP_RCVD          0x2000
#define MSG_ENC_FMT_RCVD            0x4000
#define PEER_TYPE_RCVD              0x8000


#define TYPE_ONE_PARAMS             (PEERID_RCVD|VERSION_RCVD|CRYPTOSUITES_RCVD|DIRS_RCVD|INFO_RCVD)
#define TYPE_TWO_PARAMS             (PEERID_RCVD|NONCE_RCVD|PKEY_RCVD)
#define TYPE_THREE_PARAMS           (PEERID_RCVD)
#define TYPE_FOUR_PARAMS            (PEERID_RCVD|MAC_RCVD|HINT_RCVD)
#define TYPE_FIVE_PARAMS            (PEERID_RCVD|CRYPTOSUITES_RCVD|INFO_RCVD)
#define TYPE_SIX_PARAMS             (PEERID_RCVD|NONCE_RCVD)
#define TYPE_SEVEN_PARAMS           (PEERID_RCVD|MAC_RCVD)
#define TYPE_HINT_PARAMS            (PEERID_RCVD)
#define CONF_PARAMS                 (DIRS_RCVD|CRYPTOSUITES_RCVD|VERSION_RCVD|PEER_TYPE_RCVD|PEER_ID_NUM_RCVD|PEER_TYPE_RCVD)


/* SQL query to create peer connection database
 * TODO check crytposuites type */
#define CREATE_CONNECTION_TABLE                         \
    "CREATE TABLE connections(                          \
    ssid TEXT PRIMARY KEY,                              \
    PeerID TEXT,                                        \
    Vers INTEGER,                                       \
    Verp INTEGER,                                       \
    state INTEGER,                                      \
    Csuites INTEGER,                                    \
    Csuitep INTEGER,                                    \
    Dirs INTEGER,                                       \
    Dirp INTEGER,                                       \
    Np TEXT,                                            \
    Ns TEXT,                                            \
    minsleep INTEGER,                                   \
    ServInfo TEXT,                                      \
    PeerInfo TEXT,                                      \
    SharedSecret TEXT,                                  \
    Noob TEXT,                                          \
    Hoob TEXT,                                          \
    OOB_RECEIVED_FLAG INTEGER,                          \
    Kms TEXt,                                           \
    Kmp TEXT,                                           \
    Kz TEXT,                                            \
    pub_key_serv TEXT,                                  \
    pub_key_peer TEXT,                                  \
    err_code INTEGER,                                   \
    show_OOB INTEGER,                                   \
    gen_OOB INTEGER,                                    \
    hint_server TEXT,                                   \
    OobRetries INTEGER DEFAULT 0,                       \
    Realm TEXT)                                         \
    "

/* SQL query to check number of rows */
#define CHECK_NUMBER_OF_ROWS  "SELECT COUNT(*) FROM connections;"

#define EAP_NOOB_FREE(_D)                           \
    if (_D) {                                       \
        os_free(_D);                                \
        (_D) = NULL;                                \
    }

#define EAP_NOOB_FREE_MALLOC(_D,_l)                 \
    EAP_NOOB_FREE(_D)                               \
    (_D)=os_malloc(_l)


#define EAP_NOOB_CB_GET_B64(_D64,_D,_l)             \
    EAP_NOOB_FREE(_D64)                             \
    EAP_NOOB_FREE(_D)                               \
    _D64 = os_strdup(fieldValue[i]);                \
    _l = eap_noob_Base64Decode(_D64,&_D)


#define EAP_NOOB_SET_DONE(_data,_v)                 \
    (_data)->peer_attr->is_done = (_v)


#define EAP_NOOB_SET_SUCCESS(_data,_v)              \
    (_data)->peer_attr->is_success = (_v)


#define EAP_NOOB_SET_ERROR(_pdata,_v)               \
    if (_pdata) {                                   \
        (_pdata)->next_req = NONE;                  \
        (_pdata)->err_code = _v;                    \
    }

#define EAP_NOOB_CHANGE_STATE(_data,_s)             \
    if ((_data) && ((_data)->peer_attr)) {          \
        (_data)->peer_attr->server_state = (_s);      \
    }


enum {UNREGISTERED_STATE, WAITING_FOR_OOB_STATE, OOB_RECEIVED_STATE,
      RECONNECTING_STATE, REGISTERED_STATE};

/* Flag used during KDF and MAC generation */
enum {COMPLETION_EXCHANGE, RECONNECT_EXCHANGE, RECONNECT_EXCHANGE_NEW};

enum {NONE, EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_2, EAP_NOOB_TYPE_3, EAP_NOOB_TYPE_4, EAP_NOOB_TYPE_5,
      EAP_NOOB_TYPE_6, EAP_NOOB_TYPE_7, EAP_NOOB_HINT};

enum eap_noob_err_code {NO_ERROR, E1001, E1002, E1003, E1004, E1005, E1006, E1007, E2001, E2002,
                        E3001, E3002, E3003, E4001, E5001, E5002, E5003};

enum {HOOB_TYPE, MACS_TYPE, MACP_TYPE};

enum {UPDATE_ALL, UPDATE_STATE, UPDATE_STATE_MINSLP, UPDATE_PERSISTENT_KEYS_SECRET, UPDATE_STATE_ERROR,
      UPDATE_OOB, DELETE_EXPIRED_NOOB, DELETE_SSID};

enum sql_datatypes {TEXT, INT, UNSIGNED_BIG_INT, BLOB};

/* server state vs message type matrix */
const int state_message_check[NUM_OF_STATES][MAX_MSG_TYPES] =  {
     {VALID, VALID,   VALID,   INVALID,  INVALID,  INVALID,  INVALID,  INVALID}, //UNREGISTERED_STATE
     {VALID, VALID,   VALID,   VALID,    VALID,    INVALID,  INVALID,  INVALID}, //WAITING_FOR_OOB_STATE
     {VALID, VALID,   VALID,   INVALID,  VALID,    INVALID,  INVALID,  INVALID}, //OOB_RECEIVED_STATE
     {VALID, INVALID, INVALID, INVALID,  INVALID,  VALID,    VALID,    VALID},   //RECONNECT
     {VALID, INVALID, INVALID, INVALID,  VALID,    INVALID,  INVALID,  INVALID}, //REGISTERED_STATE
};


struct eap_noob_globle_conf {
    u32 default_minsleep;
    u32 oob_enc_fmt;
    char * peer_type;
    u32 read_conf;
};

struct eap_noob_ecdh_kdf_out {

    u8 * msk;
    char * msk_b64;
    u8 * emsk;
    char * emsk_b64;
    u8 * amsk;
    char * amsk_b64;
    u8 * Kms;
    char * kms_b64;
    u8 * Kmp;
    char * kmp_b64;
    u8 * Kz;
    char * kz_b64;
};

struct eap_noob_ecdh_kdf_nonce {

    u8 * nonce_serv;
    char * nonce_serv_b64;
    u8 * nonce_peer;
    char * nonce_peer_b64;
};


struct eap_noob_oob_data {

    char * noob_b64;
    u8 * noob;
    char * hoob_b64;
    u8 * hoob;

    char * hint_b64;
    size_t hint_len;
    u8 * hint;
};

struct eap_noob_ecdh_key_exchange {

    EVP_PKEY * dh_key;

    char * x_serv_b64;
    char * y_serv_b64;

    char * x_b64;
    size_t x_len;
    char * y_b64;
    size_t y_len;

    json_t * jwk_serv;
    json_t * jwk_peer;

    u8 * shared_key;
    char * shared_key_b64;
    size_t shared_key_b64_len;
};

struct eap_noob_server_data {

    u32 version[MAX_SUP_VER];
    u32 state;
    u32 cryptosuite[MAX_SUP_CSUITES];
    u32 dir;
    u32 minsleep;
    u32 rcvd_params;

    char * serv_info;
    //char * NAI;
    char * MAC;
    char * ssid;
    char * peerId;
    char * realm;

    enum eap_noob_err_code err_code;
    Boolean record_present;

    struct eap_noob_ecdh_key_exchange * ecdh_exchange_data;
    struct eap_noob_oob_data * oob_data;
    struct eap_noob_ecdh_kdf_nonce * kdf_nonce_data;
    struct eap_noob_ecdh_kdf_out * kdf_out;
};

struct eap_noob_peer_config_params {
    char * Peer_name;
    char * Peer_ID_Num;
};

struct eap_noob_peer_data {

    u32 version;
    u32 state;
    u32 cryptosuite;
    u32 dir;
    u32 minsleep;
    u32 config_params;

    char * peerId;
    char * peer_info;
    char * MAC;
    char * realm;

    struct eap_noob_peer_config_params * peer_config_params;
};


struct eap_noob_peer_context {
    struct eap_noob_peer_data * peer_attr;
    struct eap_noob_server_data * server_attr;
    char * db_name;
    char * db_table_name;
    sqlite3 * peer_db;
    int wired;
};


const int error_code[] =  {0,1001,1002,1003,1004,1005,1006,1007,2001,2002,3001,3002,3003,4001,5001,5002,5003};

const char *error_info[] =  {
    "No error",
    "Invalid NAI or peer state",
    "Invalid message structure",
    "Invalid data",
    "Unexpected message type",
    "Unexpected peer identifier",
    "Unrecognized OOB message identifier",
    "Invalid ECDH key",
    "Unwanted peer",
    "State mismatch, user action required",
    "No mutually supported protocol version",
    "No mutually supported cryptosuite",
    "No mutually supported OOB direction",
    "MAC verification failure",
    "Application-specific error",
    "Invalid server info",
    "Invalid server URL"};

#endif
