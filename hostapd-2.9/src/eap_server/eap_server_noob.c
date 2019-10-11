/*
 * EAP server method: EAP-NOOB
 *  Copyright (c) 2016, Aalto University
 *  All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *  * Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  * Neither the name of the Aalto University nor the
 *    names of its contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 *  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL AALTO UNIVERSITY BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 *  LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *  (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  See CONTRIBUTORS for more information.
 */

#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>

#include "utils/base64.c"
#include "includes.h"
#include "common.h"
#include "eap_i.h"
#include "eap_server_noob.h"

static struct eap_noob_global_conf server_conf;

static inline void eap_noob_set_done(struct eap_noob_server_context * data, int val)
{
    data->peer_attr->is_done = val;
}

static inline void eap_noob_set_success(struct eap_noob_server_context * data, int val)
{
    data->peer_attr->is_success = val;
}

static inline void eap_noob_set_error(struct eap_noob_peer_data * peer_attr, int val)
{
    peer_attr->next_req = NONE;
    peer_attr->err_code = val;
}

static inline void eap_noob_change_state(struct eap_noob_server_context * data, int val)
{
    data->peer_attr->server_state = val;
}

/**
 * eap_noob_verify_peerId : Compares recived PeerId with the assigned one
 * @data : server context
 * @return : SUCCESS or FAILURE
 **/
static int eap_noob_verify_peerId(struct eap_noob_server_context * data)
{
    if (NULL == data || NULL == data->peer_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context null in %s", __func__);
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (0 != strcmp(data->peer_attr->PeerId, data->peer_attr->peerid_rcvd)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Verification of PeerId failed, setting error E1005");
        eap_noob_set_error(data->peer_attr, E1005); return FAILURE;
    }
    return SUCCESS;
}

/**
 * eap_noob_Base64Decode : Decodes a base64url string.
 * @b64message : input base64url string
 * @buffer : output
 * Returns : Len of decoded string
**/
static int eap_noob_Base64Decode(const char * b64message, unsigned char ** buffer)
{
    fprintf(stderr, "ENTER B64DECODE FUN\n");
    size_t len = os_strlen(b64message);
    size_t b64pad = 4*((len + 3)/4) - len;
    unsigned char *temp = os_zalloc(len + b64pad + 1);
    if (temp == NULL)
            return -1;
    os_memcpy(temp, b64message, len);
    for(int i = 0; i < len; i++) {
            if (temp[i] == '-')
                    temp[i] = '+';
            else if (temp[i] == '_')
                    temp[i] = '/';
    }
    for(int i = 0; i < b64pad; i++)
            temp[len + i] = '=';
    size_t decodeLen;
    unsigned char *tempX;
    tempX = base64_decode(temp, len + b64pad, &decodeLen);
    if (tempX == NULL)
            return -1;
    *buffer = os_zalloc(decodeLen + 1);
    memcpy(*buffer, tempX, decodeLen);
    return decodeLen;
}

/**
 * eap_noob_Base64Encode : Encode an ascii string to base64url. Dealloc b64text
 * as needed from the caller.
 * @buffer : input buffer
 * @length : input buffer length
 * @b64text : converted base64url text
 * Returns : SUCCESS/FAILURE
 **/
int eap_noob_Base64Encode(const unsigned char * buffer, size_t length, char ** b64text)
{
    size_t len = 0;
    unsigned char *tmp;
    tmp = base64_encode(buffer, length, &len);
    if (tmp == NULL)
            return -1;
    for(int i = 0; i < len; i++) {
            if (tmp[i] == '+')
                    tmp[i] = '-';
            else if (tmp[i] == '/')
                    tmp[i] = '_';
            else if (tmp[i] == '=') {
                    tmp[i] = '\0';
                    len = i;
                    break;
            }
    }

    *b64text = os_zalloc(len);
    if (*b64text == NULL)
            return -1;
    os_memcpy(*b64text, tmp, len);

    return SUCCESS;
}


/**
 * eap_noob_db_statements : execute one or more sql statements that do not return rows
 * @db : open sqlite3 database handle
 * @query : query to be executed
 * Returns  :  SUCCESS/FAILURE
 **/
static int eap_noob_db_statements(sqlite3 * db, const char * query)
{
    int nByte = os_strlen(query);
    sqlite3_stmt * stmt;
    const char * tail = query;
    const char * sql_error;
    int ret = SUCCESS;

    if (NULL == db || NULL == query) return FAILURE;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    /* Loop through multiple SQL statements in sqlite3 */
    while (tail < query + nByte) {
        if (SQLITE_OK != sqlite3_prepare_v2(db, tail, -1, &stmt, &tail)
            || NULL == stmt) {
            ret = FAILURE; goto EXIT; }
        if (SQLITE_DONE != sqlite3_step(stmt)) {
            ret = FAILURE; goto EXIT; }
    }
EXIT:
    if (ret == FAILURE) {
        sql_error = sqlite3_errmsg(db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s", sql_error);
    }
    /* if (stmt) */ sqlite3_finalize(stmt);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d",__func__, ret);
    return ret;
}


static void columns_persistentstate(struct eap_noob_server_context * data, sqlite3_stmt * stmt)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: In %s", __func__);
    data->peer_attr->version = sqlite3_column_int(stmt, 1);
    data->peer_attr->cryptosuite = sqlite3_column_int(stmt, 2);
    data->peer_attr->Realm = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->peer_attr->Kz = os_memdup(sqlite3_column_blob(stmt, 4), KZ_LEN);
    data->peer_attr->server_state = sqlite3_column_int(stmt, 5);
    data->peer_attr->creation_time = (uint64_t) sqlite3_column_int64(stmt, 6);
    data->peer_attr->last_used_time = (uint64_t) sqlite3_column_int64(stmt, 7);
}

static void columns_ephemeralstate(struct eap_noob_server_context * data, sqlite3_stmt * stmt)
{
    data->peer_attr->version = sqlite3_column_int(stmt, 1);
    data->peer_attr->cryptosuite = sqlite3_column_int(stmt, 2);
    data->peer_attr->Realm = os_strdup((char *) sqlite3_column_text(stmt, 3));
    data->peer_attr->dir = sqlite3_column_int(stmt, 4);
    data->peer_attr->peerinfo = os_strdup((char *) sqlite3_column_text(stmt, 5));
    data->peer_attr->kdf_nonce_data->Ns = os_memdup(sqlite3_column_blob(stmt, 6), NONCE_LEN);
    data->peer_attr->kdf_nonce_data->Np = os_memdup(sqlite3_column_blob(stmt, 7), NONCE_LEN);
    data->peer_attr->ecdh_exchange_data->shared_key = os_memdup(sqlite3_column_blob(stmt, 8), ECDH_SHARED_SECRET_LEN);
    data->peer_attr->mac_input_str = os_strdup((char *) sqlite3_column_text(stmt, 9));
    data->peer_attr->creation_time = (uint64_t) sqlite3_column_int64(stmt, 10);
    data->peer_attr->err_code = sqlite3_column_int(stmt, 11);
    data->peer_attr->sleep_count = sqlite3_column_int(stmt, 12);
    data->peer_attr->server_state = sqlite3_column_int(stmt, 13);
}

static void columns_ephemeralnoob(struct eap_noob_server_context * data, sqlite3_stmt * stmt)
{
    data->peer_attr->oob_data->NoobId_b64 = os_strdup((char *)sqlite3_column_text(stmt, 1));
    data->peer_attr->oob_data->Noob_b64 = os_strdup((char *)sqlite3_column_text(stmt, 2));
    data->peer_attr->oob_data->sent_time = (uint64_t) sqlite3_column_int64(stmt, 3);
}

/**
 * eap_noob_exec_query : Function to execute a sql query. Prepapres, binds and steps.
 * Takes variable number of arguments (TYPE, VAL). For Blob, (TYPE, LEN, VAL)
 * @data : Server context
 * @query : query to be executed
 * @callback : pointer to callback function
 * @num_args : number of variable inputs to function
 * Returns  :  SUCCESS/FAILURE
 **/
static int eap_noob_exec_query(struct eap_noob_server_context * data, const char * query,
                               void (*callback)(struct eap_noob_server_context *, sqlite3_stmt *),
                               int num_args, ...)
{
    sqlite3_stmt * stmt = NULL;
    va_list args;
    int ret, i, indx = 0, ival, bval_len;
    char * sval = NULL;
    u8 * bval = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, query - (%s), Number of arguments (%d)", __func__, query, num_args);
    if (SQLITE_OK != (ret = sqlite3_prepare_v2(data->server_db, query, strlen(query)+1, &stmt, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error preparing statement, ret (%d)", ret);
        ret = FAILURE; goto EXIT;
    }

    va_start(args, num_args);

    for (i = 0; i < num_args; i+=2, ++indx) {
        enum sql_datatypes type = va_arg(args, enum sql_datatypes);
        switch(type) {
            case INT:
                ival = va_arg(args, int);
                if (SQLITE_OK != sqlite3_bind_int(stmt, (indx+1), ival)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %d at index %d", ival, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case UNSIGNED_BIG_INT: /* TODO */
                break;
            case TEXT:
                sval = va_arg(args, char *);
                if (SQLITE_OK != sqlite3_bind_text(stmt, (indx+1), sval, strlen(sval), NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB:Error binding %s at index %d", sval, i+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case BLOB:
                bval_len = va_arg(args, int);
                bval = va_arg(args, u8 *);
                if (SQLITE_OK != sqlite3_bind_blob(stmt, (indx+1), (void *)bval, bval_len, NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %.*s at index %d", bval_len, bval, indx+1);
                    ret = FAILURE; goto EXIT;
                } i++;
                break;
            default:
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Wrong data type");
                ret = FAILURE; goto EXIT;
        }
    }

    while(1) {
        ret = sqlite3_step(stmt);
        if (ret == SQLITE_DONE) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Done executing the query, ret (%d)\n", ret);
            ret = SUCCESS; break;
        } else if (ret != SQLITE_ROW) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in step, ret (%d)", ret);
            ret = FAILURE; goto EXIT;
        }
        if (NULL != callback) callback(data, stmt);
    }

EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d", __func__, ret);
    if (ret == FAILURE) {
        char * sql_error = (char *)sqlite3_errmsg(data->server_db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
    }
    va_end(args);
    sqlite3_finalize(stmt);
    return ret;
}

/**
 * eap_noob_db_functions : Execute various DB queries
 * @data : server context
 * @type : type of update
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_db_functions(struct eap_noob_server_context * data, u8 type)
{
    char query[MAX_LINE_SIZE] = {0};
    char * dump_str;
    int ret = FAILURE;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL"); return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
    switch(type) {
        case UPDATE_PERSISTENT_STATE:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE PersistentState SET ServerState=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->peer_attr->server_state,
                  TEXT, data->peer_attr->PeerId);
            break;
        case UPDATE_STATE_ERROR:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET ServerState=?, ErrorCode=? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 6, INT, data->peer_attr->server_state, INT,
                  data->peer_attr->err_code, TEXT, data->peer_attr->PeerId);
            break;
        case UPDATE_STATE_MINSLP:
            os_snprintf(query, MAX_LINE_SIZE, "UPDATE EphemeralState SET ServerState=?, SleepCount =? where PeerId=?");
            ret = eap_noob_exec_query(data, query, NULL, 6, INT, data->peer_attr->server_state, INT,
                  data->peer_attr->sleep_count, TEXT, data->peer_attr->PeerId);
            break;
        case UPDATE_PERSISTENT_KEYS_SECRET:
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralState WHERE PeerId=?");
            if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peer_attr->PeerId))
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in deleting entry in EphemeralState");
            os_snprintf(query, MAX_LINE_SIZE, "DELETE FROM EphemeralNoob WHERE PeerId=?");
            if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, TEXT, data->peer_attr->PeerId))
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in deleting entry in EphemeralNoob");
            os_snprintf(query, MAX_LINE_SIZE, "INSERT INTO PersistentState (PeerId, Verp, Cryptosuitep, Realm, Kz, "
                    "ServerState, PeerInfo) VALUES(?, ?, ?, ?, ?, ?, ?)");
            ret = eap_noob_exec_query(data, query, NULL, 14, TEXT, data->peer_attr->PeerId, INT, data->peer_attr->version,
                  INT, data->peer_attr->cryptosuite, TEXT, server_conf.realm, BLOB, KZ_LEN, data->peer_attr->kdf_out->Kz, INT,
                  data->peer_attr->server_state, TEXT, data->peer_attr->peerinfo);
            break;
        case UPDATE_INITIALEXCHANGE_INFO:
            dump_str = json_dumps(data->peer_attr->mac_input, JSON_COMPACT|JSON_PRESERVE_ORDER);
            os_snprintf(query, MAX_LINE_SIZE, "INSERT INTO EphemeralState ( PeerId, Verp, Cryptosuitep, Realm, Dirp, PeerInfo, "
                  "Ns, Np, Z, MacInput, SleepCount, ServerState) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            ret = eap_noob_exec_query(data, query, NULL, 27, TEXT, data->peer_attr->PeerId, INT, data->peer_attr->version,
                  INT, data->peer_attr->cryptosuite, TEXT, server_conf.realm, INT, data->peer_attr->dir, TEXT,
                  data->peer_attr->peerinfo, BLOB, NONCE_LEN, data->peer_attr->kdf_nonce_data->Ns, BLOB, NONCE_LEN,
                  data->peer_attr->kdf_nonce_data->Np, BLOB, ECDH_SHARED_SECRET_LEN, data->peer_attr->ecdh_exchange_data->shared_key,
                  TEXT, dump_str, INT, data->peer_attr->sleep_count, INT, data->peer_attr->server_state);
            os_free(dump_str);
            break;
        case GET_NOOBID:
            os_snprintf(query, MAX_LINE_SIZE, "SELECT * FROM EphemeralNoob WHERE PeerId=? AND NoobId=?;");
            ret = eap_noob_exec_query(data, query, columns_ephemeralnoob, 4, TEXT, data->peer_attr->PeerId, TEXT,
                  data->peer_attr->oob_data->NoobId_b64);
            break;
        default:
            wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
            return FAILURE;
    }

    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value update failed");
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret = SUCCESS", __func__);
    return SUCCESS;
}

/**
 * eap_noob_get_next_req :
 * @data :
 * Returns : NONE or next req type
 **/
static int eap_noob_get_next_req(struct eap_noob_server_context * data)
{
    int retval = NONE;
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return retval;
    }
    if (EAP_NOOB_STATE_VALID) {
        retval = next_request_type[(data->peer_attr->server_state * NUM_OF_STATES) \
                 + data->peer_attr->peer_state];
    }
    wpa_printf (MSG_DEBUG,"EAP-NOOB:Serv state = %d, Peer state = %d, Next req =%d",
                data->peer_attr->server_state, data->peer_attr->peer_state, retval);
    if (retval == EAP_NOOB_TYPE_5) {
        data->peer_attr->server_state = RECONNECTING_STATE;
        if (FAILURE == eap_noob_db_functions(data, UPDATE_PERSISTENT_STATE))
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error updating state to Reconnecting");
    }

    if ((data->peer_attr->dir == SERVER_TO_PEER)  && (retval == EAP_NOOB_TYPE_4)) {
        retval = EAP_NOOB_TYPE_8;
        wpa_printf(MSG_DEBUG,"EAP-NOOB: NoobId Required: True");
    }

    if (retval == EAP_NOOB_TYPE_3) { //checking for max WE count if type is 3
        if (server_conf.max_we_count <= data->peer_attr->sleep_count) {
            eap_noob_set_error(data->peer_attr, E2001); return NONE;
        } else {
            data->peer_attr->sleep_count++;
            if (FAILURE == eap_noob_db_functions(data, UPDATE_STATE_MINSLP)) {
                wpa_printf(MSG_DEBUG,"EAP-NOOB: Min Sleep DB update Error");
                eap_noob_set_error(data->peer_attr,E2001); return NONE;
            }
        }
    }
    return retval;
}

/**
 * eap_noob_parse_NAI: Parse NAI
 * @data : server context
 * @NAI  : Network Access Identifier
 * Returns : FAILURE/SUCCESS
 **/
static int eap_noob_parse_NAI(struct eap_noob_server_context * data, const char * NAI)
{
    char * user_name_peer = NULL, * realm = NULL, * _NAI = NULL;

    if (NULL == NAI || NULL == data) {
        eap_noob_set_error(data->peer_attr, E1001); return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, parsing NAI (%s)",__func__, NAI);
    _NAI = (char *)NAI;

    if (os_strstr(_NAI, RESERVED_DOMAIN) || os_strstr(_NAI, server_conf.realm)) {
        user_name_peer = strsep(&_NAI, "@"); realm = strsep(&_NAI, "@");
        if (strlen(user_name_peer) > (MAX_PEERID_LEN + 3)) {
            /* plus 3 for '+','s' and state number */
            eap_noob_set_error(data->peer_attr,E1001); return FAILURE;
        }

        /* Peer State */
        if (os_strstr(user_name_peer, "+") && (0 == strcmp(realm, server_conf.realm))) {
            data->peer_attr->peerid_rcvd = os_strdup(strsep(&user_name_peer, "+"));
            if (*user_name_peer != 's') {
                eap_noob_set_error(data->peer_attr, E1001); return FAILURE;
            }
            data->peer_attr->peer_state = (int) strtol(user_name_peer+1, NULL, 10);
            return SUCCESS;
        }
        else if (0 == strcmp("noob", user_name_peer) && 0 == strcmp(realm, RESERVED_DOMAIN)) {
            data->peer_attr->peer_state = UNREGISTERED_STATE; return SUCCESS;
        }
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, setting error E1001",__func__);
    eap_noob_set_error(data->peer_attr, E1001);
    return FAILURE;
}

static int eap_noob_query_ephemeralstate(struct eap_noob_server_context * data)
{
    if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                   TEXT, data->peer_attr->peerid_rcvd)) {
        wpa_printf(MSG_DEBUG, "Peer not found in ephemeral table");
        if (FAILURE == eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                   TEXT, data->peer_attr->peerid_rcvd)) {
            eap_noob_set_error(data->peer_attr, E1005); /* Unexpected peerId */
            return FAILURE;
        } else {
            eap_noob_set_error(data->peer_attr, E1001); /* Invalid NAI or peer state */
            return FAILURE;
        }
    }

    if (data->peer_attr->server_state == OOB_RECEIVED_STATE) {
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALNOOB, columns_ephemeralnoob, 2,
                TEXT, data->peer_attr->peerid_rcvd)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in retreiving NoobId");
            return FAILURE;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: PeerId %s", data->peer_attr->peerid_rcvd);
    }
    return SUCCESS;
}

static int eap_noob_query_persistentstate(struct eap_noob_server_context * data)
{
    if (FAILURE == eap_noob_exec_query(data, QUERY_PERSISTENTSTATE, columns_persistentstate, 2,
                   TEXT, data->peer_attr->peerid_rcvd)) {
        if (FAILURE == eap_noob_exec_query(data, QUERY_EPHEMERALSTATE, columns_ephemeralstate, 2,
                    TEXT, data->peer_attr->peerid_rcvd)) {
            eap_noob_set_error(data->peer_attr, E1005);
            return FAILURE;
        } else {
            eap_noob_set_error(data->peer_attr, E1001);
            return FAILURE;
        }
    }
    return SUCCESS;
}

/**
 * eap_noob_create_db : Creates a new DB or opens the existing DB and
 *                      populates the context
 * @data : server context
 * returns : SUCCESS/FAILURE
 **/
static int eap_noob_create_db(struct eap_noob_server_context * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (SQLITE_OK != sqlite3_open_v2(data->db_name, &data->server_db,
                SQLITE_OPEN_READWRITE| SQLITE_OPEN_CREATE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to open and Create Table");
        return FAILURE;
    }

    if (FAILURE == eap_noob_db_statements(data->server_db, CREATE_TABLES_EPHEMERALSTATE) ||
        FAILURE == eap_noob_db_statements(data->server_db, CREATE_TABLES_PERSISTENTSTATE) ||
        FAILURE == eap_noob_db_statements(data->server_db, CREATE_TABLES_RADIUS)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected error in table creation");
        return FAILURE;
    }
    /* Based on peer_state, decide which table to query */
    if (data->peer_attr->peerid_rcvd) {
        data->peer_attr->PeerId = os_strdup(data->peer_attr->peerid_rcvd);
        if (data->peer_attr->peer_state <= OOB_RECEIVED_STATE)
            return eap_noob_query_ephemeralstate(data);
        else
            return eap_noob_query_persistentstate(data);
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
    return SUCCESS;
}

/**
 * eap_noob_assign_config:
 * @conf_name :
 * @conf_value :
 * @data : server context
 **/
static void eap_noob_assign_config(char * conf_name, char * conf_value, struct eap_noob_server_data * data)
{
    if (NULL == conf_name || NULL == conf_value || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    /*TODO : version and csuite are directly converted to integer.
     * This needs to be changed if more than one csuite or version is supported. */
    wpa_printf(MSG_DEBUG, "EAP-NOOB: CONF Name = %s %d", conf_name, (int)strlen(conf_name));
    if (0 == strcmp("Version", conf_name)) {
        data->version[0] = (int) strtol(conf_value, NULL, 10); data->config_params |= VERSION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->version[0]);
    }
    else if (0 == strcmp("Csuite",conf_name)) {
        data->cryptosuite[0] = (int) strtol(conf_value, NULL, 10); data->config_params |= CRYPTOSUITEP_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->cryptosuite[0]);
    }
    else if (0 == strcmp("OobDirs",conf_name)) {
        data->dir = (int) strtol(conf_value, NULL, 10); data->config_params |= DIRP_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->dir);
    }
    else if (0 == strcmp("ServerName", conf_name)) {
        data->server_config_params->ServerName = os_strdup(conf_value); data->config_params |= SERVER_NAME_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s\n", data->server_config_params->ServerName);
    }
    else if (0 == strcmp("ServerUrl", conf_name)) {
        data->server_config_params->ServerURL = os_strdup(conf_value); data->config_params |= SERVER_URL_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s", data->server_config_params->ServerURL);
    }
    else if (0 == strcmp("Max_WE", conf_name)) {
        server_conf.max_we_count = (int) strtol(conf_value, NULL, 10);
        data->config_params |= WE_COUNT_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", server_conf.max_we_count);
        /* assign some default value if user has given wrong value */
        if (server_conf.max_we_count == 0) server_conf.max_we_count = MAX_WAIT_EXCHNG_TRIES;
    }
    else if (0 == strcmp("Realm", conf_name)) {
        EAP_NOOB_FREE(server_conf.realm);
        server_conf.len_realm = strlen(conf_value);
        server_conf.realm = (char *) os_strdup(conf_value);
        data->config_params |= REALM_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s", server_conf.realm);
    }
    else if (0 == strcmp("OobMessageEncoding", conf_name)) {
        server_conf.oob_encode = (int) strtol(conf_value, NULL, 10);
        data->config_params |= ENCODE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", server_conf.oob_encode);
    }
}

/**
 * eap_noob_parse_config : parse each line from the config file
 * @buff : read line
 * @data :
 * data : server_context
**/
static void eap_noob_parse_config(char * buff, struct eap_noob_server_data * data)
{
    char * pos = NULL, * conf_name = NULL, * conf_value = NULL, * token = NULL;
    if (NULL == buff || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return;
    }

    pos = buff; server_conf.read_conf = 1;
    for (; *pos == ' ' || *pos == '\t' ; pos++);
    if (*pos == '#') return;

    if (os_strstr(pos, "=")) {
        conf_name = strsep(&pos, "=");
        /* handle if there are any space after the conf item name*/
        token = conf_name;
        for (; (*token != ' ' && *token != 0 && *token != '\t'); token++);
        *token = '\0';

        token = strsep(&pos,"=");
        /* handle if there are any space before the conf item value*/
        for (; (*token == ' ' || *token == '\t' ); token++);

        /* handle if there are any comments after the conf item value*/
        conf_value = token;

        for (; (*token != '\n' && *token != '\t'); token++);
        *token = '\0';
        eap_noob_assign_config(conf_name,conf_value, data);
    }
}

/**
 * eap_noob_handle_incomplete_conf :  assigns defult value if the configuration is incomplete
 * @data : server config
 * Returs : FAILURE/SUCCESS
 **/
static int eap_noob_handle_incomplete_conf(struct eap_noob_server_context * data)
{
    if (NULL == data || NULL == data->server_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return FAILURE;
    }

    if (0 == (data->server_attr->config_params & SERVER_URL_RCVD) ||
        0 == (data->server_attr->config_params & SERVER_NAME_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: ServerName or ServerURL missing"); return FAILURE;
    }

    if (0 == (data->server_attr->config_params & ENCODE_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Encoding Scheme not specified"); return FAILURE;
    }

    /* set default values if not provided via config */
    if (0 == (data->server_attr->config_params & VERSION_RCVD))
        data->server_attr->version[0] = VERSION_ONE;

    if (0 == (data->server_attr->config_params & CRYPTOSUITEP_RCVD))
        data->server_attr->cryptosuite[0] = SUITE_ONE;

    if (0 == (data->server_attr->config_params & DIRP_RCVD))
        data->server_attr->dir = BOTH_DIRECTIONS;

    if (0 == (data->server_attr->config_params & WE_COUNT_RCVD))
        server_conf.max_we_count = MAX_WAIT_EXCHNG_TRIES;

    if (0 == (data->server_attr->config_params & REALM_RCVD))
        server_conf.realm = os_strdup(RESERVED_DOMAIN);

    return SUCCESS;
}

/**
 * eap_noob_serverinfo:
 * @data : server config
 * Returs : json object. Has to be freed using json_decref at the caller.
 **/
static json_t * eap_noob_serverinfo(struct eap_noob_server_config_params * data)
{
    json_t * info_obj = NULL, * urljson = NULL, * namejson = NULL;
    char * serverinfo = NULL;
    int err = 0;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    err -= (NULL == (info_obj = json_object()));
    err -= (NULL == (namejson = json_string(data->ServerName)));
    err -= (NULL == (urljson = json_string(data->ServerURL)));
    err += json_object_set_new(info_obj, SERVERINFO_NAME, namejson);
    err += json_object_set_new(info_obj, SERVERINFO_URL, urljson);
    err -= (NULL == (serverinfo = json_dumps(info_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (strlen(serverinfo) > MAX_INFO_LEN) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: ServerInfo too long.");
        err--;
    }

    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Creation of ServerInfo failed.");
        json_decref(namejson); json_decref(urljson); json_decref(info_obj);
        return NULL;
    }
    return info_obj;
}

/**
 * eap_noob_read_config : read configuraions from config file
 * @data : server context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_read_config(struct eap_noob_server_context * data)
{
    FILE * conf_file = NULL;
    char * buff = NULL;
    int ret = SUCCESS;
    json_t * serverinfo = NULL;

    if (NULL == data || NULL == data->server_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        ret = FAILURE; goto ERROR_EXIT;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);

    if (NULL == (conf_file = fopen(CONF_FILE, "r"))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Configuration file not found");
        ret = FAILURE; goto ERROR_EXIT;
    }

    if (NULL == (buff = os_malloc(MAX_CONF_LEN))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory.");
        ret = FAILURE; goto ERROR_EXIT;
    }
    if (NULL == (data->server_attr->server_config_params =
            os_malloc(sizeof(struct eap_noob_server_config_params)))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory.");
        ret = FAILURE; goto ERROR_EXIT;
    }

    data->server_attr->config_params = 0;
    while(!feof(conf_file)) {
        if (fgets(buff, MAX_CONF_LEN, conf_file)) {
            eap_noob_parse_config(buff, data->server_attr);
            memset(buff, 0, MAX_CONF_LEN);
        }
    }

    if ((data->server_attr->version[0] > MAX_SUP_VER) || (data->server_attr->cryptosuite[0] > MAX_SUP_CSUITES) ||
        (data->server_attr->dir > BOTH_DIRECTIONS)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");
        ret = FAILURE; goto ERROR_EXIT;
    }

    if (data->server_attr->config_params != CONF_PARAMS && FAILURE == eap_noob_handle_incomplete_conf(data)) {
        ret = FAILURE; goto ERROR_EXIT;
    }

    serverinfo =  eap_noob_serverinfo(data->server_attr->server_config_params);
    if(serverinfo == NULL){
        ret = FAILURE; goto ERROR_EXIT;
    }
    data->server_attr->serverinfo = json_dumps(serverinfo, JSON_COMPACT|JSON_PRESERVE_ORDER);
    json_decref(serverinfo);

ERROR_EXIT:
    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->server_attr->server_config_params);
    EAP_NOOB_FREE(buff);
    fclose(conf_file);
    return ret;
}

/**
 * eap_noob_get_id_peer - generate PEER ID
 * @str: pointer to PEER ID
 * @size: PEER ID Length
 **/
int eap_noob_get_id_peer(char * str, size_t size)
{
    const u8 charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    time_t t = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Generating PeerId");
    srand((unsigned)time(&t));

    int charset_size = (int)(sizeof(charset) - 1);

    /* To-Do: Check whether the generated Peer ID is already in db */
    if (size) {
        size_t n;
        for (n = 0; n < size; n++) {
            int key = rand() % charset_size;
            str[n] = charset[key];
        }
        str[n] = '\0';
    }

    if (str != NULL)
        return 0;

    return 1;
}


/**
 * eap_noob_ECDH_KDF_X9_63: generates KDF
 * @out:
 * @outlen:
 * @Z:
 * @Zlen:
 * @alorithm_id:
 * @alorithm_id_len:
 * @partyUinfo:
 * @partyUinfo_len:
 * @partyVinfo:
 * @partyVinfo_len
 * @suppPrivinfo:
 * @suppPrivinfo_len:
 * @EVP_MD:
 * @Returns:
 **/

int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
        const unsigned char * Z, size_t Zlen,
        const unsigned char * algorithm_id, size_t algorithm_id_len,
        const unsigned char * partyUinfo, size_t partyUinfo_len,
        const unsigned char * partyVinfo, size_t partyVinfo_len,
        const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
        const EVP_MD *md)
{
    EVP_MD_CTX * mctx = NULL;
    unsigned char ctr[4] = {0};
    unsigned int i = 0;
    size_t mdlen = 0;
    int rv = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: KDF start");
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Value:", Z, Zlen);

    if (algorithm_id_len > ECDH_KDF_MAX || outlen > ECDH_KDF_MAX ||
        Zlen > ECDH_KDF_MAX || partyUinfo_len > ECDH_KDF_MAX ||
        partyVinfo_len > ECDH_KDF_MAX || suppPrivinfo_len > ECDH_KDF_MAX)
        return 0;

    mctx = EVP_MD_CTX_create();
    if (mctx == NULL)
        return 0;

    mdlen = EVP_MD_size(md);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: KDF begin %d", (int)mdlen);
    for (i = 1;; i++) {
        unsigned char mtmp[EVP_MAX_MD_SIZE];
        EVP_DigestInit_ex(mctx, md, NULL);
        ctr[3] = i & 0xFF;
        ctr[2] = (i >> 8) & 0xFF;
        ctr[1] = (i >> 16) & 0xFF;
        ctr[0] = (i >> 24) & 0xFF;
       if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
            goto err;
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(mctx, algorithm_id, algorithm_id_len))
            goto err;
        if (!EVP_DigestUpdate(mctx, partyUinfo, partyUinfo_len))
            goto err;
        if (!EVP_DigestUpdate(mctx, partyVinfo, partyVinfo_len))
            goto err;

        if (suppPrivinfo != NULL)
            if (!EVP_DigestUpdate(mctx, suppPrivinfo, suppPrivinfo_len))
                goto err;

        if (outlen >= mdlen) {
            if (!EVP_DigestFinal(mctx, out, NULL))
                goto err;
            outlen -= mdlen;
            if (outlen == 0)
                break;
            out += mdlen;
        } else {
            if (!EVP_DigestFinal(mctx, mtmp, NULL))
                goto err;
            memcpy(out, mtmp, outlen);
            OPENSSL_cleanse(mtmp, mdlen);
            break;
        }
    }
    rv = 1;
err:
    wpa_printf(MSG_DEBUG,"EAP-NOOB:KDF finished %d",rv);
    EVP_MD_CTX_destroy(mctx);
    return rv;
}

/**
 * eap_noob_gen_KDF : generates and updates the KDF inside the peer context.
 * @data  : peer context.
 * @state : EAP_NOOB state
 * Returns:
 **/
static int eap_noob_gen_KDF(struct eap_noob_server_context * data, int state)
{
    const EVP_MD * md = EVP_sha256();
    unsigned char * out = os_zalloc(KDF_LEN);
    int counter = 0, len = 0;
    u8 * Noob;	
//TODO: Check that these are not null before proceeding to kdf
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: ALGORITH ID:", ALGORITHM_ID, ALGORITHM_ID_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Peer_NONCE:", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Serv_NONCE:", data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Shared Key:", data->peer_attr->ecdh_exchange_data->shared_key,
                      ECDH_SHARED_SECRET_LEN);

    if (state == COMPLETION_EXCHANGE) {
        len = eap_noob_Base64Decode(data->peer_attr->oob_data->Noob_b64, &Noob);
	if (len != NOOB_LEN) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode Noob");
		return FAILURE;
	}
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: NOOB:", Noob, NOOB_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->peer_attr->ecdh_exchange_data->shared_key, ECDH_SHARED_SECRET_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->peer_attr->kdf_nonce_data->Np, NONCE_LEN,
                data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN,
                Noob, NOOB_LEN, md);
    } else {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Kz:", data->peer_attr->Kz, KZ_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->peer_attr->Kz, KZ_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->peer_attr->kdf_nonce_data->Np, NONCE_LEN,
                data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN,
                NULL,0, md);
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KDF", out, KDF_LEN);

    if (out != NULL) {
        data->peer_attr->kdf_out->msk = os_zalloc(MSK_LEN);
        data->peer_attr->kdf_out->emsk = os_zalloc(EMSK_LEN);
        data->peer_attr->kdf_out->amsk = os_zalloc(AMSK_LEN);
        data->peer_attr->kdf_out->MethodId = os_zalloc(METHOD_ID_LEN);
        data->peer_attr->kdf_out->Kms = os_zalloc(KMS_LEN);
        data->peer_attr->kdf_out->Kmp = os_zalloc(KMP_LEN);
        data->peer_attr->kdf_out->Kz = os_zalloc(KZ_LEN);

        memcpy(data->peer_attr->kdf_out->msk, out, MSK_LEN);
        counter += MSK_LEN;
        memcpy(data->peer_attr->kdf_out->emsk, out + counter, EMSK_LEN);
        counter += EMSK_LEN;
        memcpy(data->peer_attr->kdf_out->amsk, out + counter, AMSK_LEN);
        counter += AMSK_LEN;
        memcpy(data->peer_attr->kdf_out->MethodId, out + counter, METHOD_ID_LEN);
        counter += METHOD_ID_LEN;
        memcpy(data->peer_attr->kdf_out->Kms, out + counter, KMS_LEN);
        counter += KMS_LEN;
        memcpy(data->peer_attr->kdf_out->Kmp, out + counter, KMP_LEN);
        counter += KMP_LEN;
        memcpy(data->peer_attr->kdf_out->Kz, out + counter, KZ_LEN);
        if(state == COMPLETION_EXCHANGE) {
	   data->peer_attr->Kz = os_zalloc(KZ_LEN);
	   memcpy(data->peer_attr->Kz, out + counter, KZ_LEN);
	}
        counter += KZ_LEN;
        os_free(out);
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory, %s", __func__);
	return FAILURE;
    }
    return SUCCESS;
}

static void eap_noob_get_sid(struct eap_sm * sm, struct eap_noob_server_context * data)
{
    char *query = NULL;
    if ((NULL == sm->rad_attr) || (NULL == sm->rad_attr->calledSID) ||
        (NULL == sm->rad_attr->callingSID) || (NULL == sm->rad_attr->nasId)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    if(NULL == (query = (char *)malloc(500))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating memory in %s", __func__);
        return;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, Values Received: %s,%s", __func__,
               sm->rad_attr->calledSID, sm->rad_attr->callingSID);

    os_snprintf(query, 500, "INSERT INTO radius (user_name, called_st_id, calling_st_id, NAS_id) VALUES (?, ?, ?, ?)");
    if (FAILURE == eap_noob_exec_query(data, query, NULL, 8, TEXT, data->peer_attr->PeerId, TEXT, sm->rad_attr->calledSID,
            TEXT, sm->rad_attr->callingSID, TEXT, sm->rad_attr->nasId)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
    }

    EAP_NOOB_FREE(sm->rad_attr->callingSID);
    EAP_NOOB_FREE(sm->rad_attr->calledSID);
    EAP_NOOB_FREE(sm->rad_attr->nasId);
    EAP_NOOB_FREE(sm->rad_attr);
    EAP_NOOB_FREE(query);
}

static int eap_noob_derive_session_secret(struct eap_noob_server_context * data, size_t * secret_len)
{
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * peerkey = NULL;
    unsigned char * peer_pub_key = NULL;
    size_t skeylen = 0, len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);
    if (NULL == data || NULL == secret_len) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }
    
    EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->shared_key);
    len = eap_noob_Base64Decode(data->peer_attr->ecdh_exchange_data->x_peer_b64, &peer_pub_key);
    if (len == 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode public key of peer");
        ret = FAILURE; goto EXIT;
    }

    peerkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pub_key, len);
    if(peerkey == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize public key of peer");
        ret = FAILURE; goto EXIT;
    }

    ctx = EVP_PKEY_CTX_new(data->peer_attr->ecdh_exchange_data->dh_key, NULL);
    if (!ctx) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create context");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to init key derivation");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive_set_peer(ctx, peerkey) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to set peer key");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, NULL, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get secret key len");
        ret = FAILURE; goto EXIT;
    }

    data->peer_attr->ecdh_exchange_data->shared_key  = OPENSSL_malloc(skeylen);

    if (!data->peer_attr->ecdh_exchange_data->shared_key) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for secret");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, data->peer_attr->ecdh_exchange_data->shared_key, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to derive secret key");
        ret = FAILURE; goto EXIT;
    }

    (*secret_len) = skeylen;

    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",
            data->peer_attr->ecdh_exchange_data->shared_key, *secret_len);

EXIT:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    EAP_NOOB_FREE(peer_pub_key);

    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->shared_key);

    return ret;
}
static int eap_noob_get_key(struct eap_noob_server_context * data)
{
    EVP_PKEY_CTX * pctx = NULL;
    BIO * mem_pub = BIO_new(BIO_s_mem());
    unsigned char * pub_key_char = NULL;
    size_t pub_key_len = 0;
    int ret = SUCCESS;

/*
    Uncomment the next 6 lines of code for using the test vectors of Curve25519 in RFC 7748.
    Peer = Bob
    Server = Alice
*/


    char * priv_key_test_vector = "MC4CAQAwBQYDK2VuBCIEIHcHbQpzGKV9PBbBclGyZkXfTC+H68CZKrF3+6UduSwq";
    BIO* b641 = BIO_new(BIO_f_base64());
    BIO* mem1 = BIO_new(BIO_s_mem());   
    BIO_set_flags(b641,BIO_FLAGS_BASE64_NO_NL);
    BIO_puts(mem1,priv_key_test_vector);
    mem1 = BIO_push(b641,mem1);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: entering %s", __func__);

    /* Initialize context to generate keys - Curve25519 */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
        ret = FAILURE; goto EXIT;
    }

    EVP_PKEY_keygen_init(pctx);

    /* Generate X25519 key pair */
   //EVP_PKEY_keygen(pctx, &data->peer_attr->ecdh_exchange_data->dh_key);

/*
    If you are using the RFC 7748 test vector, you do not need to generate a key pair. Instead you use the
    private key from the RFC. For using the test vector, comment out the line above and 
    uncomment the following line code
*/
    d2i_PrivateKey_bio(mem1,&data->peer_attr->ecdh_exchange_data->dh_key);

    PEM_write_PrivateKey(stdout, data->peer_attr->ecdh_exchange_data->dh_key,
                         NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(stdout, data->peer_attr->ecdh_exchange_data->dh_key);

    /* Get public key */
    if (1 != i2d_PUBKEY_bio(mem_pub, data->peer_attr->ecdh_exchange_data->dh_key)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to copy public key to bio.");
        ret = FAILURE; goto EXIT;
    }

    pub_key_char = os_zalloc(MAX_X25519_LEN);
    pub_key_len = BIO_read(mem_pub, pub_key_char, MAX_X25519_LEN);

/*
 * This code removes the openssl internal ASN encoding and only keeps the 32 bytes of curve25519 
 * public key which is then encoded in the JWK format and sent to the other party. This code may
 * need to be updated when openssl changes its internal format for public-key encoded in PEM.
*/
    unsigned char * pub_key_char_asn_removed = pub_key_char + (pub_key_len-32);
    pub_key_len = 32;

    EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->x_b64);
    eap_noob_Base64Encode(pub_key_char_asn_removed, pub_key_len, &data->peer_attr->ecdh_exchange_data->x_b64);

EXIT:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    EAP_NOOB_FREE(pub_key_char);
    BIO_free_all(mem_pub);
    return ret;
}

static int eap_noob_get_sleeptime(struct eap_noob_server_context * data)
{
    /* TODO:  Include actual implementation for calculating the waiting time.
     * return  \
     * (int)((eap_noob_cal_pow(2,data->peer_attr->sleep_count))* (rand()%8) + 1) % 3600 ; */
    return 60;
}

/**
 * eap_noob_err_msg : prepares error message
 * @data : server context
 * @id   : response message id
 * Returns : pointer to message buffer or null
 **/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_server_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf *req = NULL;
    char * req_json = NULL;
    size_t len = 0 ;
    int code = 0, err = 0;

    if (NULL == data || NULL == data->peer_attr || 0 == (code = data->peer_attr->err_code)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error request");

    err -= (NULL == (req_obj = json_object()));
    if (data->peer_attr->PeerId && code != E1001)
        err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    else
        err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->peerid_rcvd));
    err += json_object_set_new(req_obj, TYPE, json_integer(NONE));
    err += json_object_set_new(req_obj, ERRORCODE, json_integer(error_code[code]));
    err += json_object_set_new(req_obj, ERRORINFO, json_string(error_info[code]));
    err -= (NULL == (req_json = json_dumps(req_obj,JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error forming error message!"); goto EXIT;
    }
    len = strlen(req_json)+1;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: ERROR message = %s == %d", req_json, (int)len);
    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for NOOB ERROR message");
        goto EXIT;
    }

    if (code != E1001 && FAILURE == eap_noob_db_functions(data, UPDATE_STATE_ERROR))
        wpa_printf(MSG_DEBUG,"Fail to Write Error to DB");

    wpabuf_put_data(req, req_json, len);
    eap_noob_set_done(data, DONE); eap_noob_set_success(data, FAILURE);
    data->peer_attr->err_code = NO_ERROR;
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 * eap_noob_gen_MAC : generate a HMAC for authentication. Do not free mac
 * from the calling function
 * @data : server context
 * type  : MAC type
 * @key  : key to generate MAC
 * @keylen: key length
 * @state : EAP_NOOB state
 * Returns : MAC on success or NULL on error.
**/
static u8 * eap_noob_gen_MAC(struct eap_noob_server_context * data, int type, u8 * key, int keylen, int state)
{
    u8 * mac = NULL; int err = 0;
    json_t * mac_array, * emptystr = json_string(""); 
    json_error_t error;
    char * mac_str = os_zalloc(500);
    
    if(state == RECONNECT_EXCHANGE) {
	data->peer_attr->mac_input_str=json_dumps(data->peer_attr->mac_input, JSON_COMPACT|JSON_PRESERVE_ORDER);
    }


    if (NULL == data || NULL == data->peer_attr || NULL == data->peer_attr->mac_input_str || NULL == key) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return NULL;
    }

    err -= (NULL == (mac_array = json_loads(data->peer_attr->mac_input_str, JSON_COMPACT|JSON_PRESERVE_ORDER, &error)));
    if (type == MACS_TYPE)
        err += json_array_set_new(mac_array, 0, json_integer(2));
    else
        err += json_array_set_new(mac_array, 0, json_integer(1));

    if(state == RECONNECT_EXCHANGE) {
        err += json_array_append_new(mac_array, emptystr);
    }
    else {
	err += json_array_append_new(mac_array, json_string(data->peer_attr->oob_data->Noob_b64));
    }

    err -= (NULL == (mac_str = json_dumps(mac_array, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in setting MAC");

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, MAC len = %d, MAC = %s",__func__,
               (int)os_strlen(mac_str), mac_str);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KEY:", key, keylen);
    mac = HMAC(EVP_sha256(), key, keylen, (u8 *)mac_str,
               os_strlen(mac_str), NULL, NULL);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MAC", mac, 32);
    os_free(mac_str);
    return mac;
}

/**
 * eap_noob_req_type_seven :
 * @data : server context
 * @id  :
 * Returns :
**/
static struct wpabuf * eap_noob_req_type_seven(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * req = NULL;
    char * req_json = NULL, * mac_b64 = NULL;
    u8 * mac = NULL;
    json_t * req_obj = NULL;
    size_t len = 0; int err = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 3/Fast Reconnect");

    if (SUCCESS != eap_noob_gen_KDF(data, RECONNECT_EXCHANGE)) {
	wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-FR"); goto EXIT;
    }
    mac = eap_noob_gen_MAC(data, MACS_TYPE, data->peer_attr->kdf_out->Kms, KMS_LEN, RECONNECT_EXCHANGE);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB type 7 request",mac,MAC_LEN);    

    err += (SUCCESS == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64));
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj,TYPE, json_integer(EAP_NOOB_TYPE_7));


    err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));


    err += json_object_set_new(req_obj, MACS2, json_string(mac_b64));

    err -= (NULL == (req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));

    if (err < 0) {
       wpa_printf(MSG_ERROR, "EAP-NOOB: Error in JSON"); 
       goto EXIT;
     }

    len = strlen(req_json)+1;
    err -= (NULL == (req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id)));
    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-FR"); goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request Sending = %s = %d", req_json, (int)strlen(req_json));
    wpabuf_put_data(req, req_json, len);
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    EAP_NOOB_FREE(mac_b64);
    return req;
}  

/**
 * eap_oob_req_type_six - Build the EAP-Request/Fast Reconnect 2.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_six(struct eap_noob_server_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf *req = NULL;
    char * req_json = NULL, * base64_nonce = NULL;
    size_t len = 0; int rc, err = 0; unsigned long error;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 2/Fast Reconnect");

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    data->peer_attr->kdf_nonce_data->Ns = os_malloc(NONCE_LEN);
    rc = RAND_bytes(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN); error = ERR_get_error();
    if (rc != 1) wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu", error);

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN);
    err -= (FAILURE == eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN, &base64_nonce));
    wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s", base64_nonce);

    /* TODO: Based on the previous and the current versions of cryptosuites of peers,
     * decide whether new public key has to be generated
     * TODO: change get key params and finally store only base 64 encoded public key */
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_6));
    err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    err += json_object_set_new(req_obj, NS2, json_string(base64_nonce));
    err -= (NULL == (req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) goto EXIT;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: request %s",req_json);
    len = strlen(req_json)+1;
    if (NULL == (req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-FR"); goto EXIT;
    }
    wpabuf_put_data(req, req_json, len);
    //err += json_array_set(data->peer_attr->mac_input, 11, data->peer_attr->ecdh_exchange_data->jwk_serv);
    err += json_array_set_new(data->peer_attr->mac_input, 12, json_string(base64_nonce));
    if (err < 0) wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in setting MAC values");
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 * TODO send Cryptosuites only if it has changed;
 * eap_oob_req_type_five - Build the EAP-Request/Fast Reconnect 1.
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_five(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * req = NULL;
    char * req_json = NULL;
    json_t * Vers = NULL, * macinput = NULL, * req_obj = NULL;
    json_t * Cryptosuites = NULL, * ServerInfo = NULL, * Realm = NULL;
    json_t * PeerId = NULL, * emptystr = json_string("");
    size_t len = 0; int err = 0, i;
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering func %s", __func__);

    err -= (NULL == (Vers = json_array()));
    for (i = 0; i < MAX_SUP_VER ; i++) {
        if (data->server_attr->version[i] > 0)
            err += json_array_append_new(Vers, json_integer(data->server_attr->version[i]));
    }

    PeerId = json_string(data->peer_attr->PeerId);
    err -= (NULL == (Cryptosuites = json_array()));
    for (i = 0; i < MAX_SUP_CSUITES ; i++) {
        if (data->server_attr->cryptosuite[i] > 0)
            err += json_array_append_new(Cryptosuites, json_integer(data->server_attr->cryptosuite[i]));
    }
    err -= (NULL == (ServerInfo = eap_noob_serverinfo(data->server_attr->server_config_params)));
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_5));
    err += json_object_set_new(req_obj, PEERID, PeerId);
    err += json_object_set_new(req_obj, CRYPTOSUITES, Cryptosuites);
    err += json_object_set_new(req_obj, SERVERINFO, ServerInfo);
    if (0 != strcmp(server_conf.realm, RESERVED_DOMAIN)) {
        err -= (NULL == (Realm = json_string(server_conf.realm)));
        err += json_object_set_new(req_obj, REALM, Realm);
    }
    else
        Realm = emptystr;

    err -= (NULL == (req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected JSON processing error when creating request type 5.");
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request Sending = %s = %d", req_json, (int)strlen(req_json));
    len = strlen(req_json)+1;
    if (NULL == (req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-FR"); goto EXIT;
    }
    wpabuf_put_data(req, req_json, len);

    json_decref(data->peer_attr->mac_input);
    err -= (NULL == (macinput = json_array()));
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, Vers);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, PeerId);
    err += json_array_append(macinput, Cryptosuites);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, ServerInfo);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, Realm);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    data->peer_attr->mac_input = macinput;
    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected JSON processing error when creating mac input template.");
        goto EXIT;
    }
EXIT:
    json_decref(req_obj); json_decref(emptystr);
    EAP_NOOB_FREE(req_json);
    if (err < 0) {
        json_decref(macinput);
        data->peer_attr->mac_input = NULL;
        wpabuf_free(req);
        return NULL;
    }
    return req;
}

/**
 * eap_oob_req_type_four - Build the EAP-Request
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_four(struct eap_noob_server_context * data, u8 id)
{
    json_t * req_obj =NULL;
    struct wpabuf * req = NULL;
    char * mac_b64 = NULL, * req_json = NULL;
    u8 * mac = NULL; size_t len = 0; int err = 0;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context NULL in %s", __func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    if (SUCCESS != eap_noob_gen_KDF(data, COMPLETION_EXCHANGE)) {
	wpa_printf(MSG_ERROR, "EAP-NOOB: Error in KDF during Request/NOOB-CE"); goto EXIT;
    }
    if (NULL == (mac = eap_noob_gen_MAC(data, MACS_TYPE, data->peer_attr->kdf_out->Kms,
                 KMS_LEN,COMPLETION_EXCHANGE))) goto EXIT;
    wpa_hexdump(MSG_DEBUG, "EAP-NOOB: MAC calculated and sending out", mac, 32);
    err -= (FAILURE == eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64));
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_4));
    err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    err += json_object_set_new(req_obj, NOOBID, json_string(data->peer_attr->oob_data->NoobId_b64));
    err += json_object_set_new(req_obj, MACS, json_string(mac_b64));
    err -= (NULL == (req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) goto EXIT;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Type 4 request = %s", req_json);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Type 4 NoobId = %s", data->peer_attr->oob_data->NoobId_b64);
    len = strlen(req_json)+1;
    if (NULL == (req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-CE"); goto EXIT;
    }
    wpabuf_put_data(req, req_json, len);
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    EAP_NOOB_FREE(mac_b64);
    return req;
}

/**
 * eap_oob_req_type_three - Build the EAP-Request
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_three(struct eap_noob_server_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf *req = NULL;
    char * req_json = NULL;
    size_t len = 0; int err = 0;
    struct timespec time;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 3/Waiting Exchange");
    data->peer_attr->sleeptime = eap_noob_get_sleeptime(data);
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_3));
    err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    err += json_object_set_new(req_obj, SLEEPTIME, json_integer(data->peer_attr->sleeptime));
    clock_gettime(CLOCK_REALTIME, &time);
    data->peer_attr->last_used_time = time.tv_sec;
    wpa_printf(MSG_DEBUG, "Current Time is %ld", data->peer_attr->last_used_time);
    //data->peer_attr->last_used_time = data->peer_attr->last_used_time + data->peer_attr->sleeptime;
    err -= (NULL == (req_json = json_dumps(req_obj,JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) goto EXIT;

    len = strlen(req_json)+1;
    if (NULL == (req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-WE");
        goto EXIT;
    }
    wpabuf_put_data(req, req_json, len);
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 *  eap_noob_build_JWK : Builds a JWK object to send in the inband message
 *  @jwk : output json object
 *  @x_64 : x co-ordinate in base64url format
 *  @y_64 : y co-ordinate in base64url format
 *  Returns : FAILURE/SUCCESS
**/
int eap_noob_build_JWK(json_t ** jwk, const char * x_b64)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    if (NULL != ((*jwk) = json_object())) {
        json_object_set_new((*jwk), KEY_TYPE, json_string("EC"));
        json_object_set_new((*jwk), CURVE, json_string("P-256"));
    }
    else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in JWK");
        return FAILURE;
    }

    if (NULL == x_b64) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: CO-ORDINATES are NULL!!");
        return FAILURE;

    }
    json_object_set_new((*jwk), X_COORDINATE, json_string(x_b64));
    //json_object_set_new((*jwk), Y_COORDINATE, json_string(y_b64));
    char * dump_str = json_dumps((*jwk), JSON_COMPACT|JSON_PRESERVE_ORDER);
    if (dump_str) {
        wpa_printf(MSG_DEBUG, "JWK Key %s", dump_str); os_free(dump_str);
    }
    return SUCCESS;
}

/**
 * eap_oob_req_type_two - Build the EAP-Request/Initial Exchange 2.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_two(struct eap_noob_server_context *data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf * req = NULL;
    char * req_json = NULL, * base64_nonce = NULL;
    size_t len = 0; int rc, err = 0;
    unsigned long error;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 2/Initial Exchange");
    if (NULL == data || NULL == data->peer_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    data->peer_attr->kdf_nonce_data->Ns = os_malloc(NONCE_LEN);
    rc = RAND_bytes(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN); error = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. Error Code = %lu", error);
        goto EXIT;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN);
    eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->Ns, NONCE_LEN, &base64_nonce);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s", base64_nonce);

    /* Generate Key material */
    if (eap_noob_get_key(data) == FAILURE) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
        eap_noob_set_done(data, DONE);
        eap_noob_set_success(data, FAILURE); goto EXIT;
    }

    if (FAILURE == eap_noob_build_JWK(&data->peer_attr->ecdh_exchange_data->jwk_serv,
                   data->peer_attr->ecdh_exchange_data->x_b64)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate JWK"); goto EXIT;
    }
    data->peer_attr->sleeptime = eap_noob_get_sleeptime(data);
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_2));
    err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    err += json_object_set_new(req_obj, NS, json_string(base64_nonce));
    err += json_object_set(req_obj, PKS, data->peer_attr->ecdh_exchange_data->jwk_serv);
    err += json_object_set_new(req_obj, SLEEPTIME, json_integer(data->peer_attr->sleeptime));
    err -= (NULL == (req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) goto EXIT;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: request %s =  %d",req_json,(int)strlen(req_json));
    len = strlen(req_json)+1;
    if (NULL == (req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-IE"); goto EXIT;
    }
    wpabuf_put_data(req, req_json, len);
    err += json_array_set(data->peer_attr->mac_input, 11, data->peer_attr->ecdh_exchange_data->jwk_serv);
    err += json_array_set_new(data->peer_attr->mac_input, 12, json_string(base64_nonce));
    if (err < 0) wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in setting MAC values");
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    if (err < 0) {
        wpabuf_free(req);
        return NULL;
    }
    return req;
}

/**
 * eap_oob_req_type_one - Build the EAP-Request/Initial Exchange 1.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_one(struct eap_noob_server_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf * req = NULL;
    size_t len = 0;
    json_t * emptystr = json_string("");
    int err = 0;
    json_t * Vers = NULL, * macinput= NULL;
    json_t * Cryptosuites, * Dirs,* ServerInfo, * Realm;
    json_t * PeerId;
    char * req_json;
    int i;

    /* (Type=1, PeerId, CryptoSuites, Dirs ,ServerInfo) */
    if (NULL == data || NULL == data->server_attr || NULL == data->peer_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 1/Initial Exchange");

    EAP_NOOB_FREE(data->peer_attr->PeerId); data->peer_attr->PeerId = os_malloc(MAX_PEERID_LEN);
    if (eap_noob_get_id_peer(data->peer_attr->PeerId, MAX_PEERID_LEN)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to generate PeerId");
        return NULL;
    }

    err -= (NULL == (Vers = json_array()));
    for (i = 0; i < MAX_SUP_VER ; i++) {
        if (data->server_attr->version[i] > 0)
            err += json_array_append_new(Vers, json_integer(data->server_attr->version[i]));
    }

    PeerId = json_string(data->peer_attr->PeerId);
    err -= (NULL == (Cryptosuites = json_array()));
    for (i = 0; i < MAX_SUP_CSUITES ; i++) {
        if (data->server_attr->cryptosuite[i] > 0)
            err += json_array_append_new(Cryptosuites, json_integer(data->server_attr->cryptosuite[i]));
    }
    err -= (NULL == (Dirs = json_integer(data->server_attr->dir)));
    err -= (NULL == (ServerInfo = eap_noob_serverinfo(data->server_attr->server_config_params)));

    /* Create request */
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_1));
    err += json_object_set_new(req_obj, VERS, Vers);
    err += json_object_set_new(req_obj, PEERID, PeerId);
    err += json_object_set_new(req_obj, CRYPTOSUITES, Cryptosuites);
    err += json_object_set_new(req_obj, DIRS, Dirs);
    err += json_object_set_new(req_obj, SERVERINFO, ServerInfo);
    if (0 != strcmp(server_conf.realm, RESERVED_DOMAIN)) {
        err -= (NULL == (Realm = json_string(server_conf.realm)));
        err += json_object_set_new(req_obj, REALM, Realm);
    }
    else
        Realm = emptystr;

    err -= (NULL == (req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected JSON processing error when creating request type 1.");
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request Sending = %s = %d", req_json, (int)strlen(req_json));
    len = strlen(req_json);

    if (NULL == (req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len+1, EAP_CODE_REQUEST, id))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-IE");
        goto EXIT;
    }
    wpabuf_put_data(req, req_json, len+1);

    /* Create MAC imput template */
    /* 1/2,Vers,Verp,PeerId,Cryptosuites,Dirs,ServerInfo,Cryptosuitep,Dirp,[Realm],PeerInfo,PKs,Ns,PKp,Np,Noob */
    err -= (NULL == (macinput = json_array()));
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, Vers);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, PeerId);
    err += json_array_append(macinput, Cryptosuites);
    err += json_array_append(macinput, Dirs);
    err += json_array_append(macinput, ServerInfo);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, Realm);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    err += json_array_append(macinput, emptystr);
    data->peer_attr->mac_input = macinput;
    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected JSON processing error when creating mac input template.");
        goto EXIT;
    }

EXIT:
    EAP_NOOB_FREE(req_json);
    json_decref(req_obj); json_decref(emptystr);
    if (err < 0) {
        json_decref(macinput);
        data->peer_attr->mac_input = NULL;
        wpabuf_free(req);
        return NULL;
    }
    return req;
}

/**
 * eap_noob_req_noobid -
 * @data: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_noobid(struct eap_noob_server_context * data, u8 id)
{
    struct wpabuf * req = NULL;
    json_t * req_obj = NULL;
    char * req_json = NULL;
    size_t len = 0; int err = 0;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__); return NULL;
    }

    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_8));
    err += json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    err -= (NULL == (req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (err < 0) { wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in preapring JSON obj");
        goto EXIT; }

    len = strlen(req_json)+1; wpa_printf(MSG_DEBUG, "EAP-NOOB: REQ Received = %s", req_json);
    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory for Request/NOOB-ID");
        goto EXIT; }
    wpabuf_put_data(req, req_json, len);
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 * eap_noob_buildReq - Build the EAP-Request packets.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_buildReq(struct eap_sm * sm, void * priv, u8 id)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: BUILDREQ SERVER");
    struct eap_noob_server_context *data = NULL;

    if (NULL == sm || NULL == priv) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    data = priv;

    printf("next req = %d\n", data->peer_attr->next_req);
    //TODO : replce switch case with function pointers.
    switch (data->peer_attr->next_req) {
        case NONE:
            return eap_noob_err_msg(data,id);

        case EAP_NOOB_TYPE_1:
            return eap_noob_req_type_one(data, id);

        case EAP_NOOB_TYPE_2:
            return eap_noob_req_type_two(data, id);

        case EAP_NOOB_TYPE_3:
            return eap_noob_req_type_three(data, id);

        case EAP_NOOB_TYPE_4:
            return eap_noob_req_type_four(data, id);

        case EAP_NOOB_TYPE_5:
            return eap_noob_req_type_five(data, id);

        case EAP_NOOB_TYPE_6:
            return eap_noob_req_type_six(data, id);

        case EAP_NOOB_TYPE_7:
            return eap_noob_req_type_seven(data, id);

        case EAP_NOOB_TYPE_8:
            return eap_noob_req_noobid(data, id);
        default:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unknown type in buildReq");
            break;
    }
    return NULL;
}


/**
 * eap_oob_check - Check the EAP-Response is valid.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @respData: EAP response to be processed (eapRespData)
 * Returns: False if response is valid, True otherwise.
 **/
static Boolean eap_noob_check(struct eap_sm * sm, void * priv,
                              struct wpabuf * respData)
{
    struct eap_noob_server_context * data = NULL;
    json_t * resp_obj = NULL, * resp_type = NULL;
    const u8 * pos = NULL;
    json_error_t error;
    u32 state = 0;
    size_t len = 0;
    Boolean ret = FALSE;

    if (NULL == priv || NULL == sm || NULL == respData) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return TRUE;
    }
    wpa_printf(MSG_INFO, "EAP-NOOB: Checking EAP-Response packet.");
    data = priv; state = data->peer_attr->server_state;
    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);
    resp_obj = json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);

    if ((NULL != resp_obj) && (json_is_object(resp_obj) > 0)) {
        resp_type = json_object_get(resp_obj, TYPE);

        if ((NULL != resp_type) && (json_is_integer(resp_type) > 0)) {
            data->peer_attr->recv_msg = json_integer_value(resp_type);
        }
        else {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown message type");
            eap_noob_set_error(data->peer_attr, E1002);
            ret = TRUE; goto EXIT;
        }
    }
    else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
        eap_noob_set_error(data->peer_attr, E1002);
        ret = TRUE; goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received frame: opcode = %d", data->peer_attr->recv_msg);
    wpa_printf(MSG_DEBUG, "STATE = %d",data->peer_attr->server_state);
    wpa_printf(MSG_DEBUG, "VERIFY STATE SERV = %d PEER = %d",
            data->peer_attr->server_state, data->peer_attr->peer_state);

    if ((NONE != data->peer_attr->recv_msg) && ((state >= NUM_OF_STATES) ||
       (data->peer_attr->recv_msg > MAX_MSG_TYPES) ||
       (VALID != state_message_check[state][data->peer_attr->recv_msg]))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Setting error in received message."
                "state (%d), message type (%d), state received (%d)",
                state, data->peer_attr->recv_msg,
                state_message_check[state][data->peer_attr->recv_msg]);
        eap_noob_set_error(data->peer_attr,E1004);
        ret = TRUE; goto EXIT;
    }

EXIT:
    if (resp_type)
        json_decref(resp_type);
    else
        json_decref(resp_obj);
    return ret;
}

/**
 * eap_noob_del_temp_tuples :
 * @data : peer context
 * retures: FAILURE/SUCCESS
 **/
static int eap_noob_del_temp_tuples(struct eap_noob_server_context * data)
{
    char * query = os_malloc(MAX_LINE_SIZE);
    int ret = SUCCESS;

    if (NULL == data || NULL == query) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null or malloc failed.", __func__);
        ret = FAILURE; goto EXIT;
    }

    os_snprintf(query, MAX_LINE_SIZE, "Delete from %s WHERE PeerId=?", DEVICE_TABLE);
    if (FAILURE == eap_noob_exec_query(data, query, NULL, 2, data->peer_attr->peerid_rcvd)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB tuple deletion failed");
        ret = FAILURE; goto EXIT;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: TEMP Tuples removed");
EXIT:
    EAP_NOOB_FREE(query);
    return ret;
}

/**
 * eap_noob_verify_param_len : verify lengths of string type parameters
 * @data : peer context
 **/
static void eap_noob_verify_param_len(struct eap_noob_peer_data * data)
{
    u32 count  = 0;
    u32 pos = 0x01;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    for (count  = 0; count < 32; count++) {
        if (data->rcvd_params & pos) {
            switch(pos) {
                case PEERID_RCVD:
                    if (strlen(data->peerid_rcvd) > MAX_PEERID_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case NONCE_RCVD:
                    if (strlen((char *)data->kdf_nonce_data->Np) > NONCE_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case MAC_RCVD:
                    if (strlen(data->mac) > MAC_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
                case INFO_RCVD:
                    if (strlen(data->peerinfo) > MAX_INFO_LEN) {
                        eap_noob_set_error(data, E1003);
                    }
                    break;
            }
        }
        pos = pos<<1;
    }
}

/**
 * eap_noob_FindIndex :
 * @val :
 * returns:
 **/
int eap_noob_FindIndex(int value)
{
    int index = 0;
    while (index < 13 && error_code[index] != value) ++index;
    return index;
}

/**
 * eap_noob_decode_obj : Decode parameters from incoming messages
 * @data : peer context
 * @req_obj : incoming json object with message parameters
 **/
static void  eap_noob_decode_obj(struct eap_noob_peer_data * data, json_t * resp_obj)
{
    const char * key = NULL, * retval_char = NULL;
    char * PKp_str = NULL;
    json_t * value = NULL;
    json_error_t error;
    size_t decode_length = 0;
    int retval_int = 0;

    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return;
    }
    json_object_foreach (resp_obj, key, value) {
        switch (json_typeof(value)) {
            case JSON_OBJECT:
                if (0 == strcmp(key, PKP)) {
                    PKp_str = json_dumps(value, JSON_COMPACT|JSON_PRESERVE_ORDER);
                    data->ecdh_exchange_data->jwk_peer = json_loads(PKp_str, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
                    os_free(PKp_str); data->rcvd_params |= PKEY_RCVD;
                } else if (0 == strcmp(key, PEERINFO)) {
                    data->peerinfo = json_dumps(value, JSON_COMPACT|JSON_PRESERVE_ORDER);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Peer Info: %s", data->peerinfo);
                    data->rcvd_params |= INFO_RCVD;
                }
                eap_noob_decode_obj(data, value);
                break;
            case JSON_INTEGER:
                if (0 == (retval_int = json_integer_value(value)) &&
                        (0 != strcmp(key,TYPE))) {
                    eap_noob_set_error(data, E1003); return;
                }
                if (0 == strcmp(key, VERP)) {
                    data->version = retval_int; data->rcvd_params |= VERSION_RCVD;
                } else if (0 == strcmp(key, CRYPTOSUITEP)) {
                    data->cryptosuite = retval_int; data->rcvd_params |= CRYPTOSUITEP_RCVD;
                } else if (0 == strcmp(key, DIRP)) {
                    data->dir = retval_int; data->rcvd_params |= DIRP_RCVD;
                }
                else if (0 == strcmp(key, ERRORCODE)) {
                    eap_noob_set_error(data, eap_noob_FindIndex(retval_int));
                }
                break;
            case JSON_STRING:
                if (NULL == (retval_char = json_string_value(value))) {
                    eap_noob_set_error(data,E1003); return;
                }
                if (0 == strcmp(key, PEERID)) {
                    EAP_NOOB_FREE(data->peerid_rcvd); data->peerid_rcvd = os_strdup(retval_char);
                    data->rcvd_params |= PEERID_RCVD;
                } else if (0 == strcmp(key, NOOBID)) {
                    EAP_NOOB_FREE(data->oob_data->NoobId_b64); 
                    data->oob_data->NoobId_b64 = os_strdup(retval_char);
                    data->rcvd_params |= NOOBID_RCVD;
                } else if (0 == strcmp(key, PEERINFO_SERIAL)) {
                    data->peer_snum = os_strdup(retval_char);
                } else if ((0 == strcmp(key, NP)) || (0 == strcmp(key, NP2))) {
                    data->kdf_nonce_data->nonce_peer_b64 = os_strdup(retval_char);
                    decode_length = eap_noob_Base64Decode((char *)data->kdf_nonce_data->nonce_peer_b64, &data->kdf_nonce_data->Np);
                    if (0 == decode_length)
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode peer nonce");
                    else data->rcvd_params |= NONCE_RCVD;
                } else if ((0 == strcmp(key, MACP)) || (0 == strcmp(key, MACP2))) {
                    decode_length = eap_noob_Base64Decode((char *)retval_char, (u8**)&data->mac);
                    if (0 == decode_length) wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode MAC");
                    else data->rcvd_params |= MAC_RCVD;
                } else if (0 == strcmp(key, X_COORDINATE)) {
                    data->ecdh_exchange_data->x_peer_b64 = os_strdup(json_string_value(value));
                    wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->x_peer_b64);
                } else if (0 == strcmp(key, Y_COORDINATE)) {
                    data->ecdh_exchange_data->y_peer_b64 = os_strdup(json_string_value(value));
                    wpa_printf(MSG_DEBUG, "Y coordinate %s", data->ecdh_exchange_data->y_peer_b64);
                }
                break;
            case JSON_REAL:
            case JSON_TRUE:
            case JSON_FALSE:
            case JSON_NULL:
            case JSON_ARRAY:
                break;
        }
    }
    eap_noob_verify_param_len(data);
}

/**
 * eap_oob_rsp_type_seven - Process EAP-Response
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_seven(struct eap_noob_server_context * data,
                                    json_t * resp_obj)
{
    u8 * mac = NULL; char * mac_b64 = NULL;

    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        return;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-3");
    eap_noob_decode_obj(data->peer_attr, resp_obj);

    /* TODO :  validate MAC address along with peerID */
    if (data->peer_attr->rcvd_params != TYPE_SEVEN_PARAMS) {
        eap_noob_set_error(data->peer_attr, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data)) {
        mac = eap_noob_gen_MAC(data, MACP_TYPE, data->peer_attr->kdf_out->Kmp, KMP_LEN, RECONNECT_EXCHANGE);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);
        if (0 != strcmp(data->peer_attr->mac, (char *)mac)) {
            eap_noob_set_error(data->peer_attr,E4001);
            eap_noob_set_done(data, NOT_DONE); goto EXIT;
        }
        eap_noob_change_state(data, REGISTERED_STATE);
        if (FAILURE == eap_noob_db_functions(data, UPDATE_PERSISTENT_STATE)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed ");
            goto EXIT;
        }
        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE); eap_noob_set_success(data, SUCCESS);
    }
EXIT:
    EAP_NOOB_FREE(mac_b64);
    return;
}


/**
 * eap_oob_rsp_type_six - Process EAP-Response/Fast Reconnect 2
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_six(struct eap_noob_server_context * data,
                                  json_t * resp_obj)
{
    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-2");
    eap_noob_decode_obj(data->peer_attr, resp_obj);
    if (data->peer_attr->rcvd_params != TYPE_SIX_PARAMS) {
        eap_noob_set_error(data->peer_attr, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
    if (eap_noob_verify_peerId(data)) {
        data->peer_attr->next_req = EAP_NOOB_TYPE_7;
        eap_noob_set_done(data, NOT_DONE); data->peer_attr->rcvd_params = 0;
    }
    //json_array_set(data->peer_attr->mac_input, 13, data->peer_attr->ecdh_exchange_data->jwk_peer);
    json_array_set_new(data->peer_attr->mac_input, 14, json_string(data->peer_attr->kdf_nonce_data->nonce_peer_b64));
}

/**
 * eap_oob_rsp_type_five - Process EAP-Response Type 5
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_five(struct eap_noob_server_context * data,
                                   json_t * resp_obj)
{
    json_t * PeerInfo; json_error_t error;
    int err = 0;
    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-1");
    /* TODO: Check for the current cryptosuite and the previous to
     * decide whether new key exchange has to be done. */
    eap_noob_decode_obj(data->peer_attr, resp_obj);
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (data->peer_attr->rcvd_params != TYPE_FIVE_PARAMS) {
        eap_noob_set_error(data->peer_attr, E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data))
        data->peer_attr->next_req = EAP_NOOB_TYPE_6;

    eap_noob_set_done(data, NOT_DONE);
    data->peer_attr->rcvd_params = 0;

    err -= (NULL == (PeerInfo = json_loads(data->peer_attr->peerinfo, JSON_COMPACT|JSON_PRESERVE_ORDER, &error)));
    err += json_array_set_new(data->peer_attr->mac_input, 2, json_integer(data->peer_attr->version));
    err += json_array_set_new(data->peer_attr->mac_input, 7, json_integer(data->peer_attr->cryptosuite));
    err += json_array_set_new(data->peer_attr->mac_input, 10, PeerInfo);
    if (err < 0) wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected JSON error in MAC input");
}

/**
 * eap_oob_rsp_type_four - Process EAP-Response Type 4
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_four(struct eap_noob_server_context * data,
                                   json_t * resp_obj)
{
    u8 * mac = NULL; char * mac_b64 = NULL; int dir = 0;

    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);
    dir = (data->server_attr->dir & data->peer_attr->dir);
    eap_noob_decode_obj(data->peer_attr, resp_obj);
    /* TODO :  validate MAC address along with peerID */
    if (data->peer_attr->rcvd_params != TYPE_FOUR_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }

    if (eap_noob_verify_peerId(data)) {
        mac = eap_noob_gen_MAC(data, MACP_TYPE, data->peer_attr->kdf_out->Kmp, KMP_LEN, COMPLETION_EXCHANGE);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);
        if (0 != strcmp(data->peer_attr->mac, (char *)mac)) {
            eap_noob_set_error(data->peer_attr,E4001); eap_noob_set_done(data, NOT_DONE); goto EXIT;
        }
        eap_noob_change_state(data, REGISTERED_STATE);
        if (FAILURE == eap_noob_db_functions(data,UPDATE_PERSISTENT_KEYS_SECRET)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed "); goto EXIT;
        }
        if (dir == SERVER_TO_PEER) eap_noob_del_temp_tuples(data);

        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE); eap_noob_set_success(data, SUCCESS);
    }
EXIT:
    EAP_NOOB_FREE(mac_b64);
}

/**
 * eap_oob_rsp_type_three - Process EAP-Response Type 3
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_three(struct eap_noob_server_context * data,
                                    json_t * resp_obj)
{
    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-WE-3");

    eap_noob_decode_obj(data->peer_attr,resp_obj);
    if (data->peer_attr->rcvd_params != TYPE_THREE_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerId(data)) {
        eap_noob_change_state(data, WAITING_FOR_OOB_STATE);
        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE);
        eap_noob_set_success(data, FAILURE);
    }
}

/**
 * eap_oob_rsp_type_two - Process EAP-Response/Initial Exchange 2
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_two(struct eap_noob_server_context * data, json_t * resp_obj)
{
    size_t secret_len = ECDH_SHARED_SECRET_LEN;

    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-2");
    eap_noob_decode_obj(data->peer_attr,resp_obj);

    if (data->peer_attr->rcvd_params != TYPE_TWO_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }

    if (eap_noob_verify_peerId(data)) {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->kdf_nonce_data->Np, NONCE_LEN);
        if (eap_noob_derive_session_secret(data,&secret_len) != SUCCESS) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in deriving shared key"); return;
        }
        eap_noob_Base64Encode(data->peer_attr->ecdh_exchange_data->shared_key,
          ECDH_SHARED_SECRET_LEN, &data->peer_attr->ecdh_exchange_data->shared_key_b64);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Shared secret %s", data->peer_attr->ecdh_exchange_data->shared_key_b64);
        eap_noob_change_state(data, WAITING_FOR_OOB_STATE);

        /* Set MAC input before updating DB */
        json_array_set(data->peer_attr->mac_input, 13, data->peer_attr->ecdh_exchange_data->jwk_peer);
        json_array_set_new(data->peer_attr->mac_input, 14, json_string(data->peer_attr->kdf_nonce_data->nonce_peer_b64));
        if (FAILURE == eap_noob_db_functions(data, UPDATE_INITIALEXCHANGE_INFO)) {
            eap_noob_set_done(data, DONE); eap_noob_set_success(data,FAILURE); return;
        }
        data->peer_attr->next_req = NONE;
        eap_noob_set_done(data, DONE); eap_noob_set_success(data, FAILURE);
    }
}

/**
 * eap_oob_rsp_type_one - Process EAP-Response/Initial Exchange 1
 * @data: Pointer to private EAP-NOOB data
 * @payload: EAP data received from the peer
 * @payloadlen: Length of the payload
 **/
static void eap_noob_rsp_type_one(struct eap_sm * sm, struct eap_noob_server_context * data,
                                  json_t * resp_obj)
{
    json_error_t error;
    json_t * PeerInfo; int err = 0;

    /* Check for the supporting cryptosuites, PeerId, version, direction*/
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-1");

    if (NULL == resp_obj || NULL == data || NULL == sm) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    eap_noob_decode_obj(data->peer_attr, resp_obj);
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (data->peer_attr->rcvd_params != TYPE_ONE_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE); return;
    }
    if (eap_noob_verify_peerId(data)) {
        data->peer_attr->next_req = EAP_NOOB_TYPE_2;
    }
    eap_noob_get_sid(sm, data); eap_noob_set_done(data, NOT_DONE);
    data->peer_attr->rcvd_params = 0;
    /* Set mac_input values received from peer in type 1 message */
    err -= (NULL == (PeerInfo = json_loads(data->peer_attr->peerinfo, JSON_COMPACT|JSON_PRESERVE_ORDER, &error)));
    err += json_array_set_new(data->peer_attr->mac_input, 2, json_integer(data->peer_attr->version));
    err += json_array_set_new(data->peer_attr->mac_input, 7, json_integer(data->peer_attr->cryptosuite));
    err += json_array_set_new(data->peer_attr->mac_input, 8, json_integer(data->peer_attr->dir));
    err += json_array_set_new(data->peer_attr->mac_input, 10, PeerInfo);
    if (err < 0) wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected JSON error in MAC input");
}

static void eap_noob_rsp_noobid(struct eap_noob_server_context * data, json_t * resp_obj)
{
    eap_noob_decode_obj(data->peer_attr,resp_obj);
    if ((data->peer_attr->err_code != NO_ERROR)) {
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (data->peer_attr->rcvd_params != TYPE_EIGHT_PARAMS) {
        eap_noob_set_error(data->peer_attr,E1002);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (!eap_noob_verify_peerId(data)) {
        eap_noob_set_error(data->peer_attr,E1005);
        eap_noob_set_done(data, NOT_DONE);
        return;
    }

    if (!eap_noob_db_functions(data, GET_NOOBID) || NULL == data->peer_attr->oob_data->NoobId_b64) {
        eap_noob_set_error(data->peer_attr,E1006);
        eap_noob_set_done(data,NOT_DONE);
    } else {
        eap_noob_set_done(data, NOT_DONE);
        data->peer_attr->next_req = EAP_NOOB_TYPE_4;
    }

    data->peer_attr->rcvd_params = 0;
}

/**
 * eap_oob_process - Control Process EAP-Response.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @respData: EAP response to be processed (eapRespData)
 **/
static void eap_noob_process(struct eap_sm * sm, void * priv, struct wpabuf * respData)
{
    struct eap_noob_server_context * data = NULL;
    json_t * resp_obj = NULL;
    const u8 * pos = NULL;
    char * dump_str = NULL;
    size_t len = 0;
    json_error_t error;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: PROCESS SERVER");

    if (NULL == sm || NULL == priv || NULL == respData) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return;
    }

    data = priv;
    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);

    if (NULL == pos || len < 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in eap header validation, %s",__func__);
        return;
    }

    if (data->peer_attr->err_code != NO_ERROR) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error not none, exiting, %s", __func__);
        return;
    }

    json_decref(resp_obj);
    resp_obj = json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
    if (NULL == resp_obj) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating json obj, %s", __func__);
        return;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: RECEIVED RESPONSE = %s", pos);
    /* TODO : replce switch case with function pointers. */
    switch (data->peer_attr->recv_msg) {
        case EAP_NOOB_TYPE_1:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 1");
            eap_noob_rsp_type_one(sm, data, resp_obj);
            break;

        case EAP_NOOB_TYPE_2:
            dump_str = json_dumps(resp_obj,
                       JSON_COMPACT|JSON_PRESERVE_ORDER);
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 2 %s",
                       dump_str);
            os_free(dump_str);
            eap_noob_rsp_type_two(data, resp_obj);
            break;

        case EAP_NOOB_TYPE_3:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 3");
            eap_noob_rsp_type_three(data, resp_obj);
            break;

        case EAP_NOOB_TYPE_4:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 4");
            eap_noob_rsp_type_four(data, resp_obj);
            break;

        case EAP_NOOB_TYPE_5:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 5");
            eap_noob_rsp_type_five(data, resp_obj);
            break;

        case EAP_NOOB_TYPE_6:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 6");
            eap_noob_rsp_type_six(data, resp_obj);
            break;

        case EAP_NOOB_TYPE_7:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 7");
            eap_noob_rsp_type_seven(data, resp_obj);
            break;
        case EAP_NOOB_TYPE_8:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE NoobId");
            eap_noob_rsp_noobid(data, resp_obj);
            break;

        case NONE:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ERROR received");
            eap_noob_decode_obj(data->peer_attr, resp_obj);
            if (FAILURE == eap_noob_db_functions(data,UPDATE_STATE_ERROR)) {
                wpa_printf(MSG_DEBUG,"Fail to Write Error to DB");
            }

            eap_noob_set_done(data, DONE);
            eap_noob_set_success(data, FAILURE);
            break;
    }
    data->peer_attr->recv_msg = 0;
    json_decref(resp_obj);
}


static Boolean eap_noob_isDone(struct eap_sm *sm, void *priv)
{

    struct eap_noob_server_context *data = priv;
    printf("DONE   = %d\n",data->peer_attr->is_done);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: IS Done? %d",(data->peer_attr->is_done == DONE));
    return (data->peer_attr->is_done == DONE);
}

/**
 * eap_oob_isSuccess - Check EAP-NOOB was successful.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * Returns: True if EAP-NOOB is successful, False otherwise.
 **/
static Boolean eap_noob_isSuccess(struct eap_sm *sm, void *priv)
{
    struct eap_noob_server_context *data = priv;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: IS SUCCESS? %d",(data->peer_attr->is_success == SUCCESS));
    return (data->peer_attr->is_success == SUCCESS);
}

/**
 * eap_noob_getKey : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns MSK or NULL
**/
static u8 * eap_noob_getKey(struct eap_sm * sm, void * priv, size_t * len)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: GET KEY");
    struct eap_noob_server_context *data = NULL;
    u8 *key = NULL;

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->peer_attr->server_state != REGISTERED_STATE) || (!data->peer_attr->kdf_out->msk))
        return NULL;

    //Base64Decode((char *)data->peer_attr->kdf_out->msk_b64, &data->peer_attr->kdf_out->msk, len);
    if (NULL == (key = os_malloc(MSK_LEN)))
        return NULL;

    *len = MSK_LEN;
    os_memcpy(key, data->peer_attr->kdf_out->msk, MSK_LEN);
    //memset(key,1,64);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MSK Derived", key, MSK_LEN);
    return key;
}


/**
 * eap_noob_get_session_id : gets the session id if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : session id len
 * Returns Session Id or NULL
**/
static u8 * eap_noob_get_session_id(struct eap_sm *sm, void *priv, size_t *len)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB:Get Session ID called");
    struct eap_noob_server_context *data = NULL;
    u8 *session_id = NULL;

    if (!priv || !sm || !len) return NULL;
  	data = priv;

    if ((data->peer_attr->server_state != REGISTERED_STATE) || (!data->peer_attr->kdf_out->MethodId))
        return NULL;
    
    if (NULL == (session_id = os_malloc(1 + METHOD_ID_LEN)))
        return NULL;


    *len = 1 + METHOD_ID_LEN;

    session_id[0] = EAP_TYPE_NOOB;
    os_memcpy(session_id + 1, data->peer_attr->kdf_out->MethodId, METHOD_ID_LEN);
    wpa_hexdump(MSG_DEBUG, "EAP-NOOB: Derived Session-Id", session_id, *len);

    return session_id;
}

/**
 * eap_noob_get_emsk : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns EMSK or NULL
**/
static u8 * eap_noob_get_emsk(struct eap_sm * sm, void * priv, size_t * len)
{
    struct eap_noob_server_context * data = NULL;
    u8 * emsk = NULL;
    wpa_printf(MSG_DEBUG, "EAP-NOOB:Get EMSK called");

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->peer_attr->server_state != REGISTERED_STATE) || (!data->peer_attr->kdf_out->emsk))
        return NULL;
    if (NULL == (emsk = os_malloc(EAP_EMSK_LEN)))
        return NULL;
    os_memcpy(emsk, data->peer_attr->kdf_out->emsk, EAP_EMSK_LEN);
    if (emsk) {
        *len = EAP_EMSK_LEN; wpa_hexdump(MSG_DEBUG, "EAP-NOOB: Copied EMSK", emsk, EAP_EMSK_LEN);
    } else
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to fetch EMSK");

    return emsk;
}


static int eap_noob_getTimeout(struct eap_sm *sm, void *priv)
{
    //struct eap_oob_server_context *data = priv;

    printf("In function %s\n",__func__);
    /* Recommended retransmit times: retransmit timeout 5 seconds,
     * per-message timeout 15 seconds, i.e., 3 tries. */
    sm->MaxRetrans = 0; /* total 3 attempts */
    return 1;
}

/**
 * eap_noob_server_ctxt_alloc : Allocates the subcontexts inside the peer context
 * @sm : eap method context
 * @peer : server context
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_server_ctxt_alloc(struct eap_sm * sm, struct eap_noob_server_context * data)
{
    if (!data || !sm) return FAILURE;

    if (NULL == (data->peer_attr = \
          os_zalloc(sizeof (struct eap_noob_peer_data)))) {
        return FAILURE;
    }

    if ((NULL == (data->server_attr = \
           os_zalloc(sizeof (struct eap_noob_server_data))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->ecdh_exchange_data = \
           os_zalloc(sizeof (struct eap_noob_ecdh_key_exchange))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->oob_data = \
           os_zalloc(sizeof (struct eap_noob_oob_data))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->kdf_out = \
           os_zalloc(sizeof (struct eap_noob_ecdh_kdf_out))))) {
        return FAILURE;
    }

    if ((NULL == (data->peer_attr->kdf_nonce_data = \
           os_zalloc(sizeof (struct eap_noob_ecdh_kdf_nonce))))) {
        return FAILURE;
    }

    return SUCCESS;
}

/**
 * eap_noob_server_ctxt_init -Supporting Initializer for EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @data: Pointer to EAP-NOOB data
 * @sm : eap method context
 **/
static int eap_noob_server_ctxt_init(struct eap_noob_server_context * data, struct eap_sm * sm)
{
    char * NAI = NULL;
    int retval = FAILURE;

    if (FAILURE == eap_noob_server_ctxt_alloc(sm, data))
        return FAILURE;

    data->peer_attr->server_state = UNREGISTERED_STATE;
    data->peer_attr->peer_state = UNREGISTERED_STATE;
    data->peer_attr->err_code = NO_ERROR;
    data->peer_attr->rcvd_params = 0;
    data->peer_attr->sleep_count = 0;

    /* Setup DB. DB file name for the server */
    data->db_name = (char *) os_strdup(DB_NAME);

    if (server_conf.read_conf == 0 && FAILURE == eap_noob_read_config(data)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
        return FAILURE;
    }

    if (sm->identity) {
        NAI = os_zalloc(sm->identity_len+1);
        if (NULL == NAI) {
            eap_noob_set_error(data->peer_attr, E1001);
            return FAILURE;
        }
        os_memcpy(NAI, sm->identity, sm->identity_len);
        strcat(NAI, "\0");
    }

    if (SUCCESS == (retval = eap_noob_parse_NAI(data, NAI))) {
        if (!(retval = eap_noob_create_db(data)))
            goto EXIT;

        if (data->peer_attr->err_code == NO_ERROR) {
            data->peer_attr->next_req = eap_noob_get_next_req(data);
        }

        if (data->peer_attr->server_state == UNREGISTERED_STATE ||
            data->peer_attr->server_state == RECONNECTING_STATE) {
            if (FAILURE == (retval = eap_noob_read_config(data)))
                goto EXIT;
        }
    }
EXIT:
    EAP_NOOB_FREE(NAI);
    if (retval == FAILURE)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
    return retval;
}

/**
 * eap_noob_free_ctx : Free up all memory in server context
 * @data: Pointer to EAP-NOOB data
 **/
static void eap_noob_free_ctx(struct eap_noob_server_context * data)
{
    if (NULL == data)
        return;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    struct eap_noob_peer_data * peer = data->peer_attr;
    struct eap_noob_server_data * serv = data->server_attr;

    if (serv) {
        EAP_NOOB_FREE(serv->serverinfo);
        if (serv->server_config_params) {
            EAP_NOOB_FREE(serv->server_config_params->ServerName);
            EAP_NOOB_FREE(serv->server_config_params->ServerURL);
            os_free(serv->server_config_params);
            serv->server_config_params = NULL;
        }
        os_free(serv); serv = NULL;
    }
    if (peer) {
        EAP_NOOB_FREE(peer->PeerId);
        EAP_NOOB_FREE(peer->peerid_rcvd);
        EAP_NOOB_FREE(peer->peerinfo);
        EAP_NOOB_FREE(peer->peer_snum);
        EAP_NOOB_FREE(peer->mac);
        if (peer->kdf_nonce_data) {
            EAP_NOOB_FREE(peer->kdf_nonce_data->Np);
            EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_peer_b64);
            EAP_NOOB_FREE(peer->kdf_nonce_data->Ns);
            //EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_server_b64);
            os_free(peer->kdf_nonce_data);
            peer->kdf_nonce_data = NULL;
        }
        if (peer->ecdh_exchange_data) {
            EVP_PKEY_free(peer->ecdh_exchange_data->dh_key);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->shared_key);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->shared_key_b64);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->x_peer_b64);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->y_peer_b64);
            EAP_NOOB_FREE(peer->ecdh_exchange_data->x_b64);
            //EAP_NOOB_FREE(peer->ecdh_exchange_data->y_b64);
            json_decref(peer->ecdh_exchange_data->jwk_serv);
            json_decref(peer->ecdh_exchange_data->jwk_peer);
            os_free(peer->ecdh_exchange_data);
            peer->ecdh_exchange_data = NULL;
        }
        if (peer->oob_data) {
            EAP_NOOB_FREE(peer->oob_data->Noob_b64);
            EAP_NOOB_FREE(peer->oob_data->NoobId_b64);
            os_free(peer->oob_data); peer->oob_data = NULL;
        }
        if (peer->kdf_out) {
            EAP_NOOB_FREE(peer->kdf_out->msk);
            EAP_NOOB_FREE(peer->kdf_out->emsk);
            EAP_NOOB_FREE(peer->kdf_out->amsk);
            EAP_NOOB_FREE(peer->kdf_out->MethodId);
            EAP_NOOB_FREE(peer->kdf_out->Kms);
            EAP_NOOB_FREE(peer->kdf_out->Kmp);
            EAP_NOOB_FREE(peer->kdf_out->Kz);
            os_free(peer->kdf_out); peer->kdf_out = NULL;
        }
        os_free(peer); peer = NULL;
    }

    if (SQLITE_OK != sqlite3_close_v2(data->server_db)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error closing DB");
        char * sql_error = (char *)sqlite3_errmsg(data->server_db);
        if (sql_error != NULL)
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
    }

    EAP_NOOB_FREE(data->db_name); 
    os_free(data); data = NULL;
}

/**
 * eap_oob_reset - Release/Reset EAP-NOOB data that is not needed.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 **/
static void eap_noob_reset(struct eap_sm * sm, void * priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: RESET SERVER");
    struct eap_noob_server_context *data = priv;

    eap_noob_free_ctx(data);
}

/**
 * eap_noob_init - Initialize the EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @sm: Pointer to EAP State Machine data
 **/
static void * eap_noob_init(struct eap_sm *sm)
{
    struct eap_noob_server_context * data = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER");

    if (NULL == (data = os_zalloc( sizeof (struct eap_noob_server_context)))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER Fail to Allocate Memory");
        return NULL;
    }

    //TODO: check if hard coded initialization can be avoided
    if (FAILURE == eap_noob_server_ctxt_init(data,sm) && data->peer_attr->err_code == NO_ERROR) {
        wpa_printf(MSG_DEBUG,"EAP-NOOB: INIT SERVER Fail to initialize context");
        eap_noob_free_ctx(data);
        return NULL;
    }

    return data;
}

/**
 * eap_server_noob_register - Register EAP-NOOB as a supported EAP peer method.
 * Returns: 0 on success, -1 on invalid method, or -2 if a matching EAP
 * method has already been registered
 **/
int eap_server_noob_register(void)
{
    struct eap_method *eap = NULL;

    eap = eap_server_method_alloc(EAP_SERVER_METHOD_INTERFACE_VERSION,
            EAP_VENDOR_IETF, EAP_TYPE_NOOB, "NOOB");
    if (eap == NULL)
        return -1;

    eap->init = eap_noob_init;
    eap->reset = eap_noob_reset;
    eap->buildReq = eap_noob_buildReq;
    eap->check = eap_noob_check;
    eap->process = eap_noob_process;
    eap->isDone = eap_noob_isDone;
    eap->getKey = eap_noob_getKey;
    eap->get_emsk = eap_noob_get_emsk;
    eap->isSuccess = eap_noob_isSuccess;
    eap->getSessionId = eap_noob_get_session_id;
    eap->getTimeout = eap_noob_getTimeout;

    return eap_server_method_register(eap);
}
