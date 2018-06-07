#ifndef EAPOOB_H
#define EAPOOB_H


/* Configuration file */
#define CONF_FILE               "eapnoob.conf"

/* All the pre-processors of EAP-NOOB */

#define MAX_QUERY_LEN               2048
#define DEFAULT_REALM               "eap-noob.net"
#define VERSION_ONE                 1
#define SUITE_ONE                   1
#define DB_NAME                     "/etc/peer_connection_db"
#define NOOB_LEN                    16
#define NOOBID_LEN                  16
#define NONCE_LEN                   32
#define ECDH_SHARED_SECRET_LEN      32
#define ECDH_KDF_MAX                (1 << 30)
#define MAX_URL_LEN                 60
#define ALGORITHM_ID                "EAP-NOOB"
#define ALGORITHM_ID_LEN            8
#define FORMAT_BASE64URL            1

/* MAX values for the fields */
#define MAX_SUP_VER             1
#define MAX_SUP_CSUITES         1
#define MAX_PEER_ID_LEN         22
#define MAX_CONF_LEN            500
#define MAX_INFO_LEN            500

#define KDF_LEN                 320
#define MSK_LEN                 64
#define EMSK_LEN                64
#define AMSK_LEN                64
#define METHOD_ID_LEN           32
#define KZ_LEN                  32
#define KMS_LEN                 32
#define KMP_LEN                 32
#define MAC_LEN                 32
#define MAX_X25519_LEN          48

#define NUM_OF_STATES           5
#define MAX_MSG_TYPES           8

/* OOB DIRECTIONS */
#define PEER_TO_SERV            1
#define SERV_TO_PEER            2
#define BOTH_DIR                3

#define SUCCESS                 1
#define FAILURE                 -1
#define EMPTY                   0

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


#define CREATE_TABLES_EPHEMERALSTATE                \
    "CREATE TABLE IF NOT EXISTS EphemeralState(     \
    Ssid TEXT PRIMARY KEY,                          \
    PeerId TEXT,                                    \
    Vers TEXT NOT NULL,                             \
    Cryptosuites TEXT NOT NULL,                     \
    Realm TEXT,                                     \
    Dirs INTEGER,                                   \
    ServerInfo TEXT,                                \
    Ns BLOB,                                        \
    Np BLOB,                                        \
    Z BLOB,                                         \
    MacInput TEXT,                                  \
    creation_time  BIGINT,                          \
    ErrorCode INT,                                  \
    PeerState INTEGER);                             \
                                                    \
    CREATE TABLE IF NOT EXISTS EphemeralNoob(       \
    Ssid TEXT NOT NULL REFERENCES EphemeralState(Ssid), \
    PeerId TEXT NOT NULL,                           \
    NoobId TEXT NOT NULL,                           \
    Noob TEXT NOT NULL,                             \
    Hoob TEXT NOT NULL,                             \
    sent_time BIGINT NOT NULL,                      \
    UNIQUE(Peerid,NoobId));"

#define CREATE_TABLES_PERSISTENTSTATE               \
    "CREATE TABLE IF NOT EXISTS PersistentState(    \
    Ssid TEXT NOT NULL,                             \
    PeerId TEXT NOT NULL,                           \
    Vers TEXT NOT NULL,                             \
    Cryptosuites TEXT NOT NULL,                     \
    Realm TEXT,                                     \
    Kz BLOB NOT NULL,                               \
    PeerState INT,                                  \
    creation_time BIGINT,                           \
    last_used_time BIGINT)"

/*
#define DELETE_EPHEMERAL_FOR_SSID                   \
    "DELETE FROM EphemeralNoob WHERE Ssid=?;        \
    DELETE FROM EphemeralState WHERE Ssid=?;"
*/

#define DELETE_EPHEMERAL_FOR_ALL                    \
    "DELETE FROM EphemeralNoob;                     \
    DELETE FROM EphemeralState;"

#define QUERY_EPHEMERALSTATE                        \
    "SELECT * FROM EphemeralState WHERE Ssid=?;"

#define QUERY_EPHEMERALNOOB                         \
    "SELECT * FROM EphemeralNoob WHERE Ssid=?;"

#define QUERY_PERSISTENTSTATE                       \
    "SELECT * FROM PersistentState WHERE Ssid=?;"


#define EAP_NOOB_FREE(_D)                           \
    if (_D) {                                       \
        os_free(_D);                                \
        (_D) = NULL;                                \
    }

enum {UNREGISTERED_STATE, WAITING_FOR_OOB_STATE, OOB_RECEIVED_STATE, RECONNECTING_STATE, REGISTERED_STATE};

/* Flag used during KDF and MAC generation */
enum {COMPLETION_EXCHANGE, RECONNECT_EXCHANGE, RECONNECT_EXCHANGE_NEW};

enum {NONE, EAP_NOOB_TYPE_1, EAP_NOOB_TYPE_2, EAP_NOOB_TYPE_3, EAP_NOOB_TYPE_4, EAP_NOOB_TYPE_5,
      EAP_NOOB_TYPE_6, EAP_NOOB_TYPE_7, EAP_NOOB_HINT};

enum eap_noob_err_code {NO_ERROR, E1001, E1002, E1003, E1004, E1005, E1006, E1007, E2001, E2002,
                        E3001, E3002, E3003, E4001, E5001, E5002, E5003};

enum {MACS_TYPE, MACP_TYPE};

enum {UPDATE_PERSISTENT_STATE, UPDATE_STATE_ERROR, DELETE_SSID};

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
    u8 * emsk;
    u8 * amsk;
    u8 * MethodId;    
    u8 * Kms;
    u8 * Kmp;
    u8 * Kz;
};

struct eap_noob_ecdh_kdf_nonce {

    u8 * Ns;
    u8 * Np;
};


struct eap_noob_oob_data {

    char * Noob_b64;
    char * Hoob_b64;
    char * NoobId_b64;
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

    char * server_info;
    char * MAC;
    char * ssid;
    char * PeerId;
    char * Realm;

    json_t * mac_input;
    char * mac_input_str;

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

    char * PeerId;
    json_t * PeerInfo;
    char * MAC;
    char * Realm;

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
