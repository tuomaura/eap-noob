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

#include <stdint.h>
#include <unistd.h>
#include <sqlite3.h>
#include <jansson.h>
#include <time.h>

#include "includes.h"
#include "common.h"
#include "eap_i.h"
#include "eap_server_noob.h"

static struct eap_noob_global_conf server_conf;


/*
Imported from jansson.h:
static json_t * json_array();
static u32  json_array_append(json_t * arr, json_t * value);
static u32  json_array_append_new(json_t * arr, json_t * value):
static json_t * json_integer(json_int_t value);
static json_int_t json_integer_value(json_t * value):
static u32 json_is_integer(const json_t * value);
static json_t * json_string(const char * value);
static char * json_string_value(json_t * value);
static json_t * json_object();
static u32 json_object_set(json_t * obj, const char* key, json_t * value);
static u32 json_object_set_new (json_t * obj, const char* key, json_t * value);
static char * json_dumps(json_t * root, size_t flags);
static json_t * json_loads(const char * input, size_t flags, json_error_t * error);
static void json_decref(json_t * obj);
static u32 json_is_object(json_t * obj);
static json_t * json_object_get(json_t * obj, const char * key);
static u32 json_typeof(const json_t * value);
*/


/**
 * eap_noob_verify_peerID : Compares recived PeerId with the assigned one
 * @data : server context
 * @return : SUCCESS or FAILURE
 **/
static int eap_noob_verify_peerID(struct eap_noob_serv_context * data)
{
    if (NULL == data || NULL == data->peer_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context null in %s", __func__);
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    if (0 != strcmp(data->peer_attr->PeerId,
             data->peer_attr->peerID_rcvd)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Verification of PeerId failed, "
                "setting error E1005");
        EAP_NOOB_SET_ERROR(data->peer_attr, E1005);
        return FAILURE;
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
    BIO * bio = NULL, * b64 = NULL;
    int decodeLen = 0, len = 0;
    char * temp = NULL;

    if (NULL == b64message || NULL == buffer) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return 0;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    len = os_strlen(b64message);

    /* Convert base64url to base64 encoding. */
    int b64pad = 4*((len+3)/4)-len; 
    temp = os_zalloc(len + b64pad);
    strcpy(temp, b64message);
    if (b64pad == 3) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB Input to %s is incorrect", __func__);
            return 0;
    }
    for (int i=0; i < len; i++) {
        if (temp[i] == '-') 
            temp[i] = '+';
        else if (temp[i] == '_') 
            temp[i] = '/';
    }
    for (int i=0; i<b64pad; i++) 
        temp[len+i] = '=';

    decodeLen = (len * 3)/4;
    *buffer = (unsigned char*)os_zalloc(decodeLen);

    bio = BIO_new_mem_buf(temp, -1);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    len = BIO_read(bio, *buffer, os_strlen(b64message));

    /* Length should equal decodeLen, else something goes horribly wrong */
    if (len != decodeLen) {
        decodeLen = 0;
        os_free(*buffer);
        *buffer = NULL;
    }
    os_free(temp);
    BIO_free_all(bio);

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
    BIO * bio = NULL, * b64 = NULL;
    BUF_MEM * bufferPtr = NULL;
    int i = 0;

    if (NULL == buffer || NULL == b64text) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return 0;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, buffer, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);
    BIO_set_close(bio, BIO_NOCLOSE);

    int outlen = bufferPtr->length;
    *b64text = (char *) os_zalloc(outlen + 1);
    os_memcpy(*b64text, bufferPtr->data, outlen);
    (*b64text)[outlen] = '\0';

    /* Convert base64 to base64url encoding. */
    while (outlen > 0 && (*b64text)[outlen - 1]=='=') {
        (*b64text)[outlen - 1] = '\0';
        outlen--;
    }
    for (i = 0; i < outlen; i++) {
        if ((*b64text)[i] == '+') 
            (*b64text)[i] = '-';
        else if ((*b64text)[i] == '/')
            (*b64text)[i] = '_';
    }

    BIO_free_all(bio); 
    return SUCCESS;
}

/**
 * eap_noob_decode_vers_array : assigns the values of Vers JSON array to version array
 * @data: Server context
 * @array: Vers JSON array
 * Returns: SUCCESS/FAILURE
 **/
static int eap_noob_decode_vers_array(char * array, struct eap_noob_server_data * data)
{
    json_t * ver_arr = NULL, * value = NULL;
    size_t index = 0;

    if (NULL == array || NULL == data ||
        NULL == (ver_arr = json_loads(array, JSON_COMPACT, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting function %s, invalid input or "
                "unable to allocated json object", __func__);
        return FAILURE;
    }

    json_array_foreach(ver_arr, index, value) {
        if (index > MAX_SUP_VER) break; /* reject the rest */
        data->version[index] = json_integer_value(value);
    }
    json_decref(ver_arr);

    return SUCCESS;
}

/**
 * eap_noob_decode_csuites_array : assigns the values of Cryptosuites JSON array to csuite array
 * @data: Server context
 * @array: Cryptosuites JSON array
 * Returns: SUCCESS/FAILURE
 **/
static int eap_noob_decode_csuites_array(char * array, struct eap_noob_server_data *data)
{
    json_t * csuites_arr = NULL;
    json_t * value = NULL;
    size_t index = 0;

    if (NULL == array || NULL == data ||
       NULL == (csuites_arr = json_loads(array, JSON_COMPACT, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting function %s, invalid input or "
                "unable to allocated json object", __func__);
        return FAILURE;
    }

    json_array_foreach(csuites_arr, index, value) {
        if (index > MAX_SUP_CSUITES) break; /* reject the rest */
        data->cryptosuite[index] = json_integer_value(value);
    }
    json_decref(csuites_arr);

    return SUCCESS;
}

/**
 * eap_noob_callback : Repopulate the peer context when method re initializes
 * @priv : peer context
 * @fieldCount : argument count
 * @fieldValue : argument 2d array
 * @fieldName : colomn name 2d arra
 **/
int eap_noob_callback(void * priv , int fieldCount, char ** fieldValue, char ** fieldName)
{
    struct eap_noob_server_data * serv_attr = NULL;
    struct eap_noob_peer_data * peer_attr = NULL;
    char * dump_str = NULL;
    int i  = 0;
    size_t len = 0;
    json_error_t error;

    if (NULL == priv || NULL == fieldValue || NULL == fieldName) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return FAILURE;
    }
    serv_attr = ((struct eap_noob_serv_context *)priv)->server_attr;
    peer_attr = ((struct eap_noob_serv_context *)priv)->peer_attr;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    for (i = 0; i < fieldCount; i++) {
        if (fieldValue[i]) {
            if (os_strcmp(fieldName[i], "PeerId") == 0) {
                EAP_NOOB_FREE_MALLOC(peer_attr->PeerId,
                        (os_strlen(fieldValue[i]) + 1));
                strcpy(peer_attr->PeerId, fieldValue[i]);
            }
            else if (os_strcmp(fieldName[i], "Verp") == 0) {
                peer_attr->version = (int) strtol(fieldValue[i], NULL, 10);
            }
            else if (os_strcmp(fieldName[i], "Vers") == 0) {
                eap_noob_decode_vers_array(fieldValue[i], serv_attr);
            }
            else if (os_strcmp(fieldName[i], "serv_state") == 0) {
                peer_attr->serv_state = (int) strtol(fieldValue[i], NULL, 10);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Server state in DB = %d",
                        peer_attr->serv_state);
            }
            else if (os_strcmp(fieldName[i], "Cryptosuitep") == 0) {
                peer_attr->cryptosuite = (int) strtol(fieldValue[i], NULL, 10);
            }
            else if (os_strcmp(fieldName[i], "Cryptosuites") == 0) {
                eap_noob_decode_csuites_array(fieldValue[i], serv_attr);
            }
            else if (os_strcmp(fieldName[i], "Dirp") == 0) {
                peer_attr->dir = (int) strtol(fieldValue[i], NULL, 10);
            }
            else if (os_strcmp(fieldName[i], "Dirs") == 0) {
                serv_attr->dir = (int) strtol(fieldValue[i], NULL, 10);
            }
            else if (os_strcmp(fieldName[i], "Mac1Input") == 0) {
                EAP_NOOB_FREE_MALLOC(peer_attr->Mac1Input, (os_strlen(fieldValue[i]) + 1));
                strcpy(peer_attr->Mac1Input, fieldValue[i]);
            }
            else if (os_strcmp(fieldName[i], "Mac2Input") == 0) {
                 EAP_NOOB_FREE_MALLOC(peer_attr->Mac2Input, (os_strlen(fieldValue[i]) + 1));
                 strcpy(peer_attr->Mac2Input, fieldValue[i]);
            }
            else if (os_strcmp(fieldName[i], "nonce_peer") == 0  &&
                     os_strlen(fieldValue[i]) > 0) {
                /* TODO: The following macro changes the value of len.
                   This is unexpected from the syntax and needs fixing. */
                EAP_NOOB_CB_GET_B64(peer_attr->kdf_nonce_data->nonce_peer_b64,
                        peer_attr->kdf_nonce_data->nonce_peer, len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB nonce_peer");
            }
            else if (os_strcmp(fieldName[i], "nonce_serv") == 0  &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->kdf_nonce_data->nonce_serv_b64,
                                peer_attr->kdf_nonce_data->nonce_serv, len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB nonce_serv");
            }
            else if (os_strcmp(fieldName[i], "UserName") == 0) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB UserInfo");
                EAP_NOOB_FREE_MALLOC(peer_attr->user_info,
                        (os_strlen(fieldValue[i]) + 1));
                strcpy(peer_attr->user_info, fieldValue[i]);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Username = %s", peer_attr->user_info);
            }
            else if (os_strcmp(fieldName[i], "PeerInfo") == 0) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB PeerInfo");
                EAP_NOOB_FREE_MALLOC(peer_attr->peer_info,
                        (os_strlen(fieldValue[i]) + 1));
                strcpy(peer_attr->peer_info, fieldValue[i]);
            }
            else if (os_strcmp(fieldName[i], "ServerInfo") == 0) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB ServerInfo");
                EAP_NOOB_FREE_MALLOC(serv_attr->serv_info,
                        (os_strlen(fieldValue[i]) + 1));
                strcpy(serv_attr->serv_info, fieldValue[i]);
            }
            else if (os_strcmp(fieldName[i], "SharedSecret") == 0 &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->ecdh_exchange_data->shared_key_b64,
                                peer_attr->ecdh_exchange_data->shared_key, len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB shared_key");
            }
            else if (os_strcmp(fieldName[i], "Hint") == 0  &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->oob_data->hint_b64,
                                peer_attr->oob_data->hint, len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB noob %d",
                          (int)os_strlen(fieldValue[i]));
            }
            else if (os_strcmp(fieldName[i], "Noob") == 0  &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->oob_data->noob_b64,
                      peer_attr->oob_data->noob, peer_attr->oob_data->noob_len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB noob %d",
                     (int)os_strlen(fieldValue[i]));
            }
            else if (os_strcmp(fieldName[i], "Hoob") == 0  &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->oob_data->hoob_b64,
                     peer_attr->oob_data->hoob, peer_attr->oob_data->hoob_len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB hoob %s",
                     peer_attr->oob_data->hoob_b64);
            }
            else if (os_strcmp(fieldName[i], "hint_peer") == 0  &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->oob_data->hint_b64,
                     peer_attr->oob_data->hint, peer_attr->oob_data->hint_len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB noob %d",
                          (int)os_strlen(fieldValue[i]));
            }
            else if (os_strcmp(fieldName[i], "OOB_RECEIVED_FLAG") == 0 &&
                    (peer_attr->peer_state != RECONNECT && peer_attr->serv_state != RECONNECT)) {
                /*TODO: This has to be properly checked and not only oob received flag */
                peer_attr->oob_recv = (int) strtol(fieldValue[i],NULL,10);
                /* if (peer_attr->oob_recv == 1234) {
                   wpa_printf(MSG_DEBUG,"EAP-NOOB: Received oob!!");
                   peer_attr->serv_state = OOB;
                   peer_attr->peer_state = OOB;
                   }else if (peer_attr->serv_state == WAITING) {
                   wpa_printf(MSG_DEBUG,"EAP-NOOB: Still waiting stage");
                   peer_attr->peer_state = WAITING;
                 } */
            }
            else if (os_strcmp(fieldName[i], "MINSLP_count") == 0) {
                peer_attr->minslp_count = (int )strtol(fieldValue[i],NULL,10);
            }
            else if (os_strcmp(fieldName[i], "pub_key_serv") == 0) {
                EAP_NOOB_JSON_FREE(peer_attr->ecdh_exchange_data->jwk_serv);
                peer_attr->ecdh_exchange_data->jwk_serv = \
                     json_loads(fieldValue[i], JSON_COMPACT, &error);
                dump_str = json_dumps(peer_attr->ecdh_exchange_data->jwk_serv,
                     JSON_COMPACT|JSON_PRESERVE_ORDER);
                wpa_printf(MSG_DEBUG,"EAP-NOOB: Serv_Key: %s", dump_str);
                os_free(dump_str);
            }
            else if (os_strcmp(fieldName[i], "pub_key_peer") == 0) {
                EAP_NOOB_JSON_FREE(peer_attr->ecdh_exchange_data->jwk_peer);
                peer_attr->ecdh_exchange_data->jwk_peer = \
                    json_loads(fieldValue[i],
                    JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
                dump_str = json_dumps(peer_attr->ecdh_exchange_data->jwk_peer,
                    JSON_COMPACT|JSON_PRESERVE_ORDER);
                wpa_printf(MSG_DEBUG,"EAP-NOOB: Peer_Key: %s", dump_str);
                os_free(dump_str);
            }
            else if (os_strcmp(fieldName[i], "kms") == 0 &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->kdf_out->kms_b64,
                                    peer_attr->kdf_out->kms, len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kms");
            }
            else if (os_strcmp(fieldName[i], "kmp") == 0 &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->kdf_out->kmp_b64,
                                    peer_attr->kdf_out->kmp, len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kmp");
            }
            else if (os_strcmp(fieldName[i], "kz") == 0 &&
                     os_strlen(fieldValue[i]) > 0) {
                EAP_NOOB_CB_GET_B64(peer_attr->kdf_out->kz_b64,
                                    peer_attr->kdf_out->kz, len);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kz");
            }
            else if (os_strcmp(fieldName[i], "errorCode") == 0 &&
                     os_strlen(fieldValue[i]) > 0) {
                //peer_attr->err_code = (int) strtol(fieldValue[i],NULL,10);
                //EAP_NOOB_SET_ERROR(peer_attr,peer_attr->err_code);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB Error during OOB");
            }
        }
    }
    return 0;
}

/**
 * eap_noob_exec_query : wrapper function to execute a sql query
 * @query : query to be executed
 * @callback : pointer to callback function
 * @data : server context
 * Returns  :  SUCCESS/FAILURE
 **/
static int eap_noob_exec_query(const char * query,
                               int(*callback)(void*, int ,char **, char ** ),
                               struct eap_noob_serv_context * data)
{
    char * sql_error = NULL;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }

    if (SQLITE_OK != sqlite3_open_v2(data->db_name, &data->servDB,
                SQLITE_OPEN_READWRITE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
        return FAILURE;
    }

    if (SQLITE_OK != sqlite3_exec(data->servDB, query, callback,
                data, &sql_error)) {
        if (sql_error != NULL) {
            wpa_printf(MSG_DEBUG,"EAP-NOOB: SQL error : %s\n", sql_error);
            sqlite3_free(sql_error);
        }
        ret = FAILURE;
    }
    if (SQLITE_OK != sqlite3_close(data->servDB)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error closing DB");
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d",__func__, ret);
    return ret;
}

/**
 * eap_noob_db_update : prepare a DB update query
 * @data : server context
 * @type : type of update
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_db_update(struct eap_noob_serv_context * data, u8 type)
{
    char query[MAX_LINE_SIZE] = {0};
    int len = MAX_LINE_SIZE;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    switch(type) {
        case UPDATE_ALL:
            snprintf(query, len, "UPDATE '%s' SET Verp=%d , serv_state=%d, Csuite=%d,"
                    "Dirp=%d, nonce='%s', PeerInfo='%s' WHERE PeerId='%s'",
                    data->db_table_name, data->peer_attr->version,
                    data->peer_attr->serv_state, data->peer_attr->cryptosuite,
                    data->peer_attr->dir,data->peer_attr->kdf_nonce_data->nonce_peer,
                    data->peer_attr->peer_info, data->peer_attr->PeerId);
            break;
        case UPDATE_STATE:
            snprintf(query,len,"UPDATE '%s' SET serv_state=%d WHERE PeerId='%s'",
                    data->db_table_name, data->peer_attr->serv_state,
                    data->peer_attr->PeerId);
            break;
        case UPDATE_STATE_ERROR:
            snprintf(query,len,"UPDATE '%s' SET serv_state=%d, errorCode=%d  "
                    "WHERE PeerId='%s'", data->db_table_name,data->peer_attr->serv_state,
                    data->peer_attr->err_code,data->peer_attr->PeerId);
            break;
        case UPDATE_STATE_MINSLP:
            snprintf(query,len,"UPDATE '%s' SET serv_state=%d, MINSLP_count =%d, "
                    "sleepTime = %ld  WHERE PeerId='%s'",
                    data->db_table_name,data->peer_attr->serv_state,
                    data->peer_attr->minslp_count,
                    data->peer_attr->sleep_time.tv_sec, data->peer_attr->PeerId);
            break;
        case UPDATE_PERSISTENT_KEYS_SECRET:
            snprintf(query,len,"UPDATE '%s' SET kms='%s', kmp='%s', kz='%s', "
                    "serv_state=%d  WHERE PeerId='%s'",
                    data->db_table_name,data->peer_attr->kdf_out->kms_b64,
                    data->peer_attr->kdf_out->kmp_b64, data->peer_attr->kdf_out->kz_b64,
                    data->peer_attr->serv_state, data->peer_attr->PeerId);
            break;
        case UPDATE_OOB:
            snprintf(query, MAX_LINE_SIZE, "UPDATE '%s' SET noob='%s',hoob='%s',"
                    "username='%s' WHERE PeerId='%s'",
                    data->db_table_name,data->peer_attr->oob_data->noob_b64,
                    data->peer_attr->oob_data->hoob_b64, data->peer_attr->user_info,
                    data->peer_attr->PeerId);
            break;
        default:
            wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
            return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Query = %s",query);
    if (FAILURE == eap_noob_exec_query(query, NULL, data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value update failed");
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret = SUCCESS",__func__);
    return SUCCESS;
}

/**
 * eap_noob_exec_no_hint_queries :
 * @data :
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_exec_no_hint_queries(struct eap_noob_serv_context * data)
{
    char query[MAX_LINE_SIZE] = {0};

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }
    snprintf(query, MAX_LINE_SIZE, "SELECT * from %s where PeerId='%s'",
             DEVICE_TABLE, data->peer_attr->PeerId);
    wpa_printf(MSG_DEBUG, "Query = %s\n", query);
    if (eap_noob_exec_query(query, eap_noob_callback, data)) {
        return eap_noob_db_update(data, UPDATE_OOB);
    }
    return FAILURE;
}

#if 0
int eap_noob_hint_request_check(void * priv , int fieldCount, char **fieldValue, char **fieldName)
{
    int res = 0;
    struct eap_noob_serv_context *data = priv;

    if ((res = strtol(fieldValue[0],NULL,10)) > 1 && data->peer_attr->dir == SERV_TO_PEER) {
        data->peer_attr->hint_required = TRUE;
    }else {
        data->peer_attr->hint_required = FALSE;
    }

    return 0;
}

int eap_noob_is_hint_required(struct eap_noob_serv_context * data)
{
    char buff[200] = {0}; //TODO : replace this with dynamic allocation
    os_snprintf(buff,200,"SELECT COUNT(*) from %s WHERE  PeerId = '%s'",
            DEVICE_TABLE,data->peer_attr->peerID_rcvd);
    return (eap_noob_exec_query(buff, eap_noob_hint_request_check,
                data));
}
#endif

/**
 * eap_noob_get_next_req :
 * @data :
 * Returns : NONE or next req type
 **/
static int eap_noob_get_next_req(struct eap_noob_serv_context * data)
{
    int retval = NONE;
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return retval;
    }
    if (EAP_NOOB_STATE_VALID) {
        retval = next_request_type[(data->peer_attr->serv_state * NUM_OF_STATES) \
                 + data->peer_attr->peer_state];
    }

    wpa_printf (MSG_DEBUG,"EAP-NOOB:Serv state = %d, Peer state = %d, Next req =%d",
                data->peer_attr->serv_state, data->peer_attr->peer_state, retval);
    if (retval == EAP_NOOB_TYPE_5) {
        data->peer_attr->serv_state = RECONNECT;
    }
    /* code change to include the hint message for serv_to_peer direction*/
    /* if ((data->peer_attr->dir == SERV_TO_PEER)  &&
     * (retval == EAP_NOOB_TYPE_4) &&
     * FAILURE != eap_noob_is_hint_required(data) &&
     * data->peer_attr->hint_required) { */
    if ((data->peer_attr->dir == SERV_TO_PEER)  && (retval == EAP_NOOB_TYPE_4)) {
        retval = EAP_NOOB_TYPE_HINT;
        wpa_printf(MSG_DEBUG,"EAP-NOOB: Hint Required: True");
    }
    else if ((data->peer_attr->dir == SERV_TO_PEER)  &&
             (retval == EAP_NOOB_TYPE_4) &&
             !data->peer_attr->hint_required) {
        eap_noob_exec_no_hint_queries(data);
        wpa_printf(MSG_DEBUG,"EAP-NOOB: Hint Required: False");
    }

    if (retval == EAP_NOOB_TYPE_3) {
         //checking for max WE count if type is 3
        if (server_conf.max_we_count <= data->peer_attr->minslp_count) {
            EAP_NOOB_SET_ERROR(data->peer_attr, E2001);
            retval = NONE;
        }
        else {
            data->peer_attr->minslp_count++;
            if (FAILURE == eap_noob_db_update(data, UPDATE_STATE_MINSLP)) {
                wpa_printf(MSG_DEBUG,"EAP-NOOB: Min Sleep DB update Error");
                EAP_NOOB_SET_ERROR(data->peer_attr,E2001);
                retval = NONE;
            }
        }
    }
    return retval;
}

/**
 * eap_noob_db_entry_check :
 * @data :
 * Returns : Only 0
 **/
int eap_noob_db_entry_check(void * priv , int fieldCount, char ** fieldValue, char ** fieldName)
{
    struct eap_noob_serv_context * data = NULL;

    if (NULL == priv) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL in %s", __func__);
        return 0;
    }
    data = priv;
    if (strtol(fieldValue[0], NULL, 10) == 1) {
        data->peer_attr->record_present = TRUE;
    }
    return 0;
}

#if 0
/**
 * eap_noob_verify_oob_msg_len :
 * @data :
 * Returns :
 **/
int eap_noob_verify_oob_msg_len(struct eap_noob_peer_data *data)
{
    if (!data || !data->oob_data) return FAILURE;
    if (data->oob_data->noob &&
       data->oob_data->noob_len > EAP_NOOB_NONCE_LEN) {
        EAP_NOOB_SET_ERROR(data,E1003);
        return FAILURE;
    }

    if (data->oob_data->hoob &&
       data->oob_data->hoob_len > HASH_LEN) {
        EAP_NOOB_SET_ERROR(data,E1003);
        return FAILURE;
    }
    return SUCCESS;
}
#endif


/*
 * eap_noob_db_entry : Make an entery of the current peer context inside the DB
 * @data : server context
 * Returns : FAILURE/SUCCESS
 **/
static int eap_noob_db_entry(struct eap_noob_serv_context *data)
{
    struct eap_noob_peer_data * peer_attr = NULL;
    char query[MAX_LINE_SIZE] = {0};
    char * dump_str1 = NULL, * dump_str2 = NULL;
    char * dump_str3 = NULL, * dump_str4 = NULL;
    json_t * ver_arr = NULL;
    json_t * csuite_arr = NULL;
    json_t * mac_input;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return FAILURE;
    }
    peer_attr = data->peer_attr;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    if ((ver_arr = eap_noob_prepare_vers_arr(data)) == NULL)
        return FAILURE;

    if ((csuite_arr = eap_noob_prepare_csuites_arr(data)) == NULL) {
        json_decref(ver_arr);
        return FAILURE;
    }

    if (NULL == (mac_input = json_array())) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null",  __func__);
        return NULL;
    }
    /*prepare the json array*/
    for (int i = 0; i < MAX_SUP_VER ; i++) {
        json_array_append_new(ver_arr,
           json_integer(data->server_attr->version[i]));
    }

    dump_str1 = json_dumps(ver_arr, JSON_COMPACT);
    dump_str2 = json_dumps(csuite_arr, JSON_COMPACT);
    dump_str3 = json_dumps(peer_attr->ecdh_exchange_data->jwk_serv,
            JSON_COMPACT|JSON_PRESERVE_ORDER);
    dump_str4 = json_dumps(peer_attr->ecdh_exchange_data->jwk_peer,
            JSON_COMPACT|JSON_PRESERVE_ORDER);

    snprintf(query, MAX_LINE_SIZE ,
       "INSERT INTO %s ( PeerId, Mac1Input, Mac2Input, Verp,Vers, serv_state, "
       "Cryptosuitep, Cryptosuites, Dirp, Dirs, nonce_serv, nonce_peer, PeerInfo,ServerInfo,"
       "SharedSecret, Noob, Hoob, OOB_RECEIVED_FLAG,MINSLP_count, pub_key_serv, "
       "pub_key_peer, kms, kmp, kz,DevUpdate) VALUES ( '%s','%s','%s',%d ,'%s', %d, %d, "
       "'%s', %d, %d, '%s','%s', '%s','%s','%s','%s','%s', %d, %d, '%s', '%s', "
       "'%s', '%s', '%s',%d)",
       data->db_table_name, peer_attr->PeerId,mac_input,NULL, peer_attr->version,
       dump_str1, peer_attr->serv_state, peer_attr->cryptosuite, dump_str2,
       peer_attr->dir,data->server_attr->dir, peer_attr->kdf_nonce_data->nonce_serv_b64,
       peer_attr->kdf_nonce_data->nonce_peer_b64, peer_attr->peer_info,
       data->server_attr->serv_info, peer_attr->ecdh_exchange_data->shared_key_b64,
       "", "", 0, peer_attr->minslp_count, dump_str3, dump_str4, "","","",0);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: QUERY = %s", query);

    os_free(dump_str1); os_free(dump_str2); os_free(dump_str3); os_free(dump_str4);
    /* os_free on json objects which has reference of other objects will
     * not free up everything. Ex., prepare_vers_arr uses append_new
     * which has the refernce of the argument json object transferred to it. */
    json_decref(ver_arr); json_decref(csuite_arr);

    if (FAILURE == eap_noob_exec_query(query, NULL, data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
        return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
    return SUCCESS;
}

/**
 * eap_noob_parse_NAI: Parse NAI
 * @data : server context
 * @NAI  : Network Access Identifier
 * Returns : FAILURE/SUCCESS
 **/
static int eap_noob_parse_NAI(struct eap_noob_serv_context * data,
                              const char * NAI)
{
    char * user_name_peer = NULL, * realm = NULL, * _NAI = NULL;

    if (NULL == NAI || NULL == data) {
        EAP_NOOB_SET_ERROR(data->peer_attr, E1001);
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, parsing NAI (%s)",__func__, NAI);
    _NAI = (char *)NAI;

    if (os_strstr(_NAI, RESERVED_DOMAIN) ||
        os_strstr(_NAI, server_conf.realm)) {
        user_name_peer = strsep(&_NAI, "@");
        realm = strsep(&_NAI, "@");

        if (strlen(user_name_peer) > (MAX_PEER_ID_LEN + 3)) {
            /* plus 3 for '+','s' and state number */
            EAP_NOOB_SET_ERROR(data->peer_attr,E1001);
            return FAILURE;
        }

        /* Peer State */
        if (os_strstr(user_name_peer, "+") &&
           (0 == strcmp(realm, server_conf.realm))) {
            data->peer_attr->peerID_rcvd = os_strdup(strsep(&user_name_peer, "+"));

            if (*user_name_peer != 's') {
                EAP_NOOB_SET_ERROR(data->peer_attr, E1001);
                return FAILURE;
            }
            data->peer_attr->peer_state = (int) strtol(user_name_peer+1, NULL, 10);
            return SUCCESS;
        }
        else if (0 == strcmp("noob", user_name_peer) &&
                0 == strcmp(realm, RESERVED_DOMAIN)) {
            data->peer_attr->peer_state = UNREG;
            return SUCCESS;
        }
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
    EAP_NOOB_SET_ERROR(data->peer_attr, E1001);
    return FAILURE;
}

/**
 * eap_noob_check_for_oob :
 * @data : server context
 **/
static void eap_noob_check_for_oob(struct eap_noob_serv_context * data)
{
    int dir = 0;
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return;
    }

    dir = (data->server_attr->dir & data->peer_attr->dir);
    /* TODO hardcoded 1234 ? */
    if ((dir == PEER_TO_SERV) && (data->peer_attr->oob_recv == 1234) &&
       (data->peer_attr->serv_state != REGISTERED)) {
        wpa_printf(MSG_DEBUG,"EAP-NOOB: Received oob!!");
        data->peer_attr->serv_state = OOB;
    }
}

/**
 * eap_noob_create_db : Creates a new DB or opens the existing DB and
 *                      populates the context
 * @data : server context
 * returns : SUCCESS/FAILURE
 **/
static int eap_noob_create_db(struct eap_noob_serv_context * data)
{
#define TMP_BUF_LEN     200
    char buff[TMP_BUF_LEN] = {0};

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    /* check for the peer ID inside the DB */
    /*  TODO: handle condition where there are two tuples for same peer id */

    if (SQLITE_OK != sqlite3_open_v2(data->db_name, &data->servDB,
                SQLITE_OPEN_READWRITE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to open and Create Table");
        return FAILURE;
    }

    if (SQLITE_OK != sqlite3_close(data->servDB)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
        return FAILURE;
    }

    if (FAILURE == eap_noob_exec_query(CREATE_CONNECTION_TABLE, NULL, data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: connections Table creation failed");
        return FAILURE;
    }

    if (FAILURE == eap_noob_exec_query(CREATE_RADIUS_TABLE, NULL, data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: connections Table creation failed");
        return FAILURE;
    }

    if (data->peer_attr->peerID_rcvd) {
        os_snprintf(buff, TMP_BUF_LEN, "SELECT COUNT(*) from %s WHERE  PeerId = '%s'",
                data->db_table_name, data->peer_attr->peerID_rcvd);

        if (FAILURE != eap_noob_exec_query(buff, eap_noob_db_entry_check,
                    data) && (data->peer_attr->record_present)) {
            memset(buff, 0, sizeof(buff));
            os_snprintf(buff, TMP_BUF_LEN, "SELECT * from %s WHERE  PeerId = '%s'",
                    data->db_table_name, data->peer_attr->peerID_rcvd);

            if (eap_noob_exec_query(buff, eap_noob_callback, data)) {
                eap_noob_check_for_oob(data);
            }

        } else {
            wpa_printf(MSG_ERROR, "EAP-NOOB: No record found ");

            if (data->peer_attr->peer_state != REGISTERED &&
                    data->peer_attr->peer_state != RECONNECT) {
                data->peer_attr->peer_state = UNREG;
                return SUCCESS;
            }
            EAP_NOOB_SET_ERROR(data->peer_attr,E1005);
            return FAILURE;
        }
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
static void eap_noob_assign_config(char * conf_name, char * conf_value,
                                   struct eap_noob_server_data * data)
{
    if (NULL == conf_name || NULL == conf_value || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    /*TODO : version and csuite are directly converted to integer.
     * This needs to be changed if more than one csuite or version is supported. */

    wpa_printf(MSG_DEBUG, "EAP-NOOB: CONF Name = %s %d", conf_name,
              (int)strlen(conf_name));
    if (0 == strcmp("Version", conf_name)) {
        data->version[0] = (int) strtol(conf_value, NULL, 10);
        data->config_params |= VERSION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->version[0]);
    }
    else if (0 == strcmp("Csuite",conf_name)) {
        data->cryptosuite[0] = (int) strtol(conf_value, NULL, 10);
        data->config_params |= CSUITE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->cryptosuite[0]);
    }
    else if (0 == strcmp("OobDirs",conf_name)) {
        data->dir = (int) strtol(conf_value, NULL, 10);
        data->config_params |= DIRECTION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d", data->dir);
    }
    else if (0 == strcmp("ServName", conf_name)) {
        data->serv_config_params->Serv_name = os_strdup(conf_value);
        data->config_params |= SERV_NAME_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s\n",
                   data->serv_config_params->Serv_name);
    }
    else if (0 == strcmp("ServUrl", conf_name)) {
        data->serv_config_params->Serv_URL = os_strdup(conf_value);
        data->config_params |= SERV_URL_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",
                   data->serv_config_params->Serv_URL);
    }
    else if (0 == strcmp("Max_WE", conf_name)) {
        server_conf.max_we_count = (int) strtol(conf_value, NULL, 10);
        data->config_params |= WE_COUNT_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",
                   server_conf.max_we_count);
        /* assign some default value if user has given wrong value */
        if (server_conf.max_we_count == 0)
            server_conf.max_we_count = MAX_WAIT_EXCHNG_TRIES;
    }
    else if (0 == strcmp("Realm", conf_name)) {
        EAP_NOOB_FREE(server_conf.realm);
        server_conf.len_realm = strlen(conf_value);
        server_conf.realm = (char *) os_strdup(conf_value);
        data->config_params |= REALM_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",
                   server_conf.realm);
    }
    else if (0 == strcmp("OobMessageEncoding", conf_name)) {
        server_conf.oob_encode = (int) strtol(conf_value, NULL, 10);
        data->config_params |= ENCODE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",
                   server_conf.oob_encode);
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
    char * pos = NULL;
    char * conf_name = NULL;
    char * conf_value = NULL;
    char * token = NULL;

    if (NULL == buff || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }

    pos = buff; server_conf.read_conf = 1;

    for (; *pos == ' ' || *pos == '\t' ; pos++);

    if (*pos == '#')
        return;

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
static int eap_noob_handle_incomplete_conf(struct eap_noob_serv_context * data)
{
    if (NULL == data || NULL == data->server_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return FAILURE;
    }

    if (0 == (data->server_attr->config_params & SERV_URL_RCVD) ||
        0 == (data->server_attr->config_params & SERV_NAME_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Server name or Server URL missing");
        return FAILURE;
    }

    if (0 == (data->server_attr->config_params & ENCODE_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Encoding Scheme not specified");
        return FAILURE;
    }

    /* set default values if not provided via config */
    if (0 == (data->server_attr->config_params & VERSION_RCVD))
        data->server_attr->version[0] = VERSION_ONE;

    if (0 == (data->server_attr->config_params & CSUITE_RCVD))
        data->server_attr->cryptosuite[0] = SUITE_ONE;

    if (0 == (data->server_attr->config_params & DIRECTION_RCVD))
        data->server_attr->dir = BOTH_DIR;

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
static json_t * eap_noob_serverinfo(struct eap_noob_serv_config_params * data)
{
    json_t * info_obj = NULL;
    int err = 0;
    json_t * namejson, * urljson;
    char * serverinfo;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    
    err -= (NULL == (info_obj = json_object()));
    err -= (NULL == (namejson = json_string(data->Serv_name)));
    err -= (NULL == (urljson = json_string(data->Serv_URL)));
    err += json_object_set_new(info_obj, SERV_NAME, namejson);
    err += json_object_set_new(info_obj, SERV_URL, urljson);

    err -= (NULL == (serverinfo = json_dumps(info_obj, JSON_COMPACT|JSON_PRESERVE_ORDER)));
    if (strlen(serverinfo) > MAX_INFO_LEN) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: ServerInfo too long.");
        err--;
    }

    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Creation of ServerInfo failed.");
        json_decref(namejson);
        json_decref(urljson);
        json_decref(info_obj);
        return NULL;
    }

    return info_obj;
}


/**
 * eap_noob_serverinfo : Create a Json object for peer information.
 * @data : server context.
 * returns : SUCCESS or FAILURE.
**/
/*
static int eap_noob_serverinfo(struct eap_noob_server_data * data)
{
    json_t * info_obj = NULL;
    int ret = SUCCESS;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return FAILURE;
    }
    EAP_NOOB_FREE(data->serv_info);

    if (NULL != (info_obj = json_object())) {
        json_object_set_new(info_obj,SERV_NAME,
                json_string(data->serv_config_params->Serv_name));
        json_object_set_new(info_obj,SERV_URL,
                json_string(data->serv_config_params->Serv_URL));

        if (NULL == (data->serv_info = json_dumps(info_obj,
                     JSON_COMPACT|JSON_PRESERVE_ORDER)) ||
           (strlen(data->serv_info) > MAX_INFO_LEN)) {
            wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no server info");
            ret = FAILURE;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: PEER INFO = %s", data->serv_info);
    }
    json_decref(info_obj);
    return ret;
}
*/

/**
 * eap_noob_read_config : read configuraions from config file
 * @data : server context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_read_config(struct eap_noob_serv_context * data)
{
    FILE * conf_file = NULL;
    char * buff = NULL;
    int ret = SUCCESS;

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
    if (NULL == (data->server_attr->serv_config_params =
            os_malloc(sizeof(struct eap_noob_serv_config_params)))) {
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

    if ((data->server_attr->version[0] > MAX_SUP_VER) ||
        (data->server_attr->cryptosuite[0] > MAX_SUP_CSUITES) ||
        (data->server_attr->dir > BOTH_DIR)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");
        ret = FAILURE; goto ERROR_EXIT;
    }

    if (data->server_attr->config_params != CONF_PARAMS &&
        FAILURE == eap_noob_handle_incomplete_conf(data)) {
        ret = FAILURE; goto ERROR_EXIT;
    }

    ret  = eap_noob_serverinfo(data->server_attr);

ERROR_EXIT:
    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->server_attr->serv_config_params);
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
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-OOB: Value:", Z, Zlen);

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
        if (!EVP_DigestUpdate(mctx, Z, Zlen))
            goto err;
        if (!EVP_DigestUpdate(mctx, ctr, sizeof(ctr)))
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

static void eap_noob_get_sid(struct eap_sm * sm, struct eap_noob_serv_context * data)
{
    char *query = NULL;
    if ((NULL == sm->rad_attr) ||
            (NULL == sm->rad_attr->calledSID) ||
            (NULL == sm->rad_attr->callingSID) ||
            (NULL == sm->rad_attr->nasId)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input tot %s is null", __func__);
        return;
    }

    if(NULL == (query = (char *)malloc(500))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating memory in %s", __func__);
        return;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, Values Received: %s,%s", __func__,
               sm->rad_attr->calledSID, sm->rad_attr->callingSID);

    snprintf(query, 500, "INSERT INTO radius (user_name, called_st_id, "
            "calling_st_id, NAS_id) VALUES ('%s','%s','%s','%s')",
            data->peer_attr->PeerId, sm->rad_attr->calledSID,
            sm->rad_attr->callingSID, sm->rad_attr->nasId);

    if (FAILURE == eap_noob_exec_query(query, NULL, data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
    }

    EAP_NOOB_FREE(sm->rad_attr->callingSID);
    EAP_NOOB_FREE(sm->rad_attr->calledSID);
    EAP_NOOB_FREE(sm->rad_attr->nasId);
    EAP_NOOB_FREE(sm->rad_attr);
    EAP_NOOB_FREE(query);
}

static int eap_noob_derive_session_secret(struct eap_noob_serv_context * data, size_t * secret_len)
{
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * peerkey = NULL;
    BIO * mem_pub_peer = NULL;
    unsigned char * peer_pub_key = NULL;
    size_t skeylen = 0, len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);
    if (NULL == data || NULL == secret_len) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }
    mem_pub_peer = BIO_new(BIO_s_mem());
    if (NULL == mem_pub_peer) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating memory in BIO");
        return FAILURE;
    }
    EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->shared_key);
    len = eap_noob_Base64Decode(data->peer_attr->ecdh_exchange_data->x_peer_b64, &peer_pub_key);
    if (len == 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode");
        ret = FAILURE; goto EXIT;
    }

    BIO_write(mem_pub_peer, peer_pub_key, len);
    if (NULL == d2i_PUBKEY_bio(mem_pub_peer, &peerkey)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get peer public key");
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

    if (NULL != mem_pub_peer)
        BIO_free_all(mem_pub_peer);

    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->shared_key);

    return ret;
}

#if 0

/**
 * eap_noob_derive_session_secret : Generates secret using public keys ogf both the entities
 * @data : server context
 * @secret_len : Secret length
 * returns FAILURE/SUCCESS
**/


static int eap_noob_derive_session_secret(struct eap_noob_serv_context *data, size_t *secret_len) //ToDo: Rename this function as secret_key
{

    EC_KEY *ec_pub_peer; // public key of peer
    EC_POINT *ecpoint_pub_peer; // public key points of peer
    const EC_GROUP *ec_group; // group
    EVP_PKEY *evp_peer = NULL ;

    EVP_PKEY_CTX *ctx;//context for derivation
    EVP_PKEY_CTX *pctx;//context for peer key


    unsigned char * x;
    unsigned char * y;
    size_t x_len;
    size_t y_len;
    size_t len;
    BIGNUM * x_big = NULL;
    BIGNUM * y_big = NULL;
    x_len = eap_noob_Base64Decode(data->peer_attr->ecdh_exchange_data->x_peer_b64, &x, &len);
    y_len = eap_noob_Base64Decode(data->peer_attr->ecdh_exchange_data->y_peer_b64, &y, &len);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: deriving NID_secp256k1.");
    ec_pub_peer = EC_KEY_new_by_curve_name(NID_secp256k1);

    if (ec_pub_peer == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create EC_KEYs");
        return 1;
    }

    /* Get the group used */
    ec_group = EC_KEY_get0_group(ec_pub_peer);
    if (ec_group == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get GROUP");
        return 1;
    }

    x_big = BN_bin2bn(x,x_len,NULL);
    y_big = BN_bin2bn(y,y_len,NULL);


    wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_POINT_bn2point");
    ecpoint_pub_peer = EC_POINT_new(ec_group);

    if (EC_POINT_set_affine_coordinates_GFp(ec_group, ecpoint_pub_peer, x_big, y_big,NULL) ==0)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in affine coordinate setting");



    wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key");

    if (!EC_KEY_set_public_key(ec_pub_peer, ecpoint_pub_peer)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to SET Peer PUB KEY EC_POINT to EC_KEY.");
        return 1;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: EVP_PKEY_set1_EC_KEY");

    /* Create the context for parameter generation */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
        return 1;
    }

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(pctx)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to initialize parameter generation.");
        return 1;
    }

    /* We're going to use the ANSI X9.62 Prime 256k1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_secp256k1)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to select the curve.");
        return 1;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key done before");

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &evp_peer)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create parameter object params.");
        return 1;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key done");


    if (!EVP_PKEY_set1_EC_KEY(evp_peer, ec_pub_peer)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to CONVERT EC_KEY to EVP_PKEY.");
        return 1;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret!.");


    /* Derive the secret */

    /* Create the context for the shared secret derivation */
    if (NULL == (ctx = EVP_PKEY_CTX_new(data->peer_attr->ecdh_exchange_data->dh_key, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to create EVP_PKEY_CTX_new.");
        return 1;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 2.");
    /* Initialise */
    if (1 != EVP_PKEY_derive_init(ctx)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to EVP_PKEY_derive_init.");
        return 1;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 3.");
    /* Provide the peer public key */
    if (1 != EVP_PKEY_derive_set_peer(ctx, evp_peer)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to EVP_PKEY_derive_set_peer.");
        return 1;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 4.");
    /* Determine buffer length for shared secret */
    if (1 != EVP_PKEY_derive(ctx, NULL, secret_len)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to determine buffer length EVP_PKEY_derive.");
        return 1;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 5.");

    /* Create the buffer */
    if (NULL == (data->peer_attr->ecdh_exchange_data->shared_key = OPENSSL_malloc(*secret_len))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to create buffer OPENSSL_malloc.");
        return 1;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 6.");

    /* Derive the shared secret */
    if (1 != (EVP_PKEY_derive(ctx, data->peer_attr->ecdh_exchange_data->shared_key, secret_len))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to derive key EVP_PKEY_derive.");
        return 1;
    }
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",data->peer_attr->ecdh_exchange_data->shared_key,*secret_len);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(evp_peer);

    return 0;
}
#endif

static int eap_noob_get_key(struct eap_noob_serv_context * data)
{
    EVP_PKEY_CTX * pctx = NULL;
    BIO * mem_pub = BIO_new(BIO_s_mem());
    unsigned char * pub_key_char = NULL;
    size_t pub_key_len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: entering %s", __func__);

    /* Initialize context to generate keys - Curve25519 */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(NID_X25519, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
        ret = FAILURE; goto EXIT;
    }

    EVP_PKEY_keygen_init(pctx);

    /* Generate X25519 key pair */
    EVP_PKEY_keygen(pctx, &data->peer_attr->ecdh_exchange_data->dh_key);
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

    EAP_NOOB_FREE(data->peer_attr->ecdh_exchange_data->x_b64);
    eap_noob_Base64Encode(pub_key_char, pub_key_len, &data->peer_attr->ecdh_exchange_data->x_b64);

EXIT:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    EAP_NOOB_FREE(pub_key_char);
    BIO_free_all(mem_pub);
    return ret;
}

#if 0
/**
 * eap_noob_get_key - Generate Priv/Pub key pair based on the Csuite selected.
 * @data: Pointer to EAP-NOOB data
 * Returns: 1 if keys generated and stored successfully, or 0 if not
 **/
static int eap_noob_get_key(struct eap_noob_serv_context *data)
{
    //BIGNUM *big_pub = NULL;
    //size_t big_pub_len;

    //const BIGNUM *big_priv;
    //size_t big_priv_len;

    const EC_POINT *pub;
    const EC_GROUP *group;
    //point_conversion_form_t form;


    wpa_printf(MSG_DEBUG, "EAP-NOOB: secp256k1 cryptosuite selected.");

    EVP_PKEY_CTX *pctx, *kctx;
    EVP_PKEY *params = NULL;
    EC_KEY * key;
    BIGNUM *x = BN_new();
    BIGNUM *y = BN_new();
    size_t x_len;
    size_t y_len;
    unsigned char * x_val;
    unsigned char * y_val;
    //char * x_val_b64;
    //char * y_val_b64;

    BN_CTX *ctx;
    ctx = BN_CTX_new();
    if (!ctx)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: BN_CTX Error");


    /* Create the context for parameter generation */
    if (NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
        return 0;
    }

    /* Initialise the parameter generation */
    if (1 != EVP_PKEY_paramgen_init(pctx)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to initialize parameter generation.");
        return 0;
    }

    /* We're going to use the ANSI X9.62 Prime 256k1 curve */
    if (1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_secp256k1)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to select the curve.");
        return 0;
    }

    /* Create the parameter object params */
    if (!EVP_PKEY_paramgen(pctx, &params)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create parameter object params.");
        return 0;
    }

    /* Create the context for the key generation */
    if (NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for key generation.");
        return 0;
    }

    /* Generate the key */
    if (1 != EVP_PKEY_keygen_init(kctx)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to initialize to generate keys.");
        return 0;
    }
    if (1 != EVP_PKEY_keygen(kctx, &data->peer_attr->ecdh_exchange_data->dh_key)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to generate keys.");
        return 0;
    }

    key = EVP_PKEY_get1_EC_KEY(data->peer_attr->ecdh_exchange_data->dh_key);

    if (key == NULL)
    {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: No Key Returned from EVP.");
        return 0;
    }

    /* Get the group used */
    group = EC_KEY_get0_group(key);
    if (group == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get GROUP");
        return 0;
    }
    /* Get public key in pub */
    pub = EC_KEY_get0_public_key(key);
    if (pub == NULL) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get PUB KEY");
        return 0;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Before extract points");
    if (EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, ctx) != 1)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in coordinates");

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", x, 32);

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", y, 32);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Before mem alloc");
    x_len = BN_num_bytes(x);
    y_len = BN_num_bytes(y);
    x_val = os_zalloc(x_len);
    y_val = os_zalloc(y_len);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Before bin conversion");
    if (BN_bn2bin(x,x_val) == 0 || BN_bn2bin(y,y_val) == 0)
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error converting to Bin");

    eap_noob_Base64Encode(x_val,x_len, &data->peer_attr->ecdh_exchange_data->x_b64);
    eap_noob_Base64Encode(y_val,y_len, &data->peer_attr->ecdh_exchange_data->y_b64);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: X and Y %s,%s",data->peer_attr->ecdh_exchange_data->x_b64, data->peer_attr->ecdh_exchange_data->y_b64);

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", x_val, x_len);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Y coordinate", y_val, y_len);

    BN_CTX_free(ctx);
    return 1;
}

static int eap_noob_cal_pow(u32 num, u32 pow)
{
    long  p;
    long  r;

    p = num;
    r = 1.0;
    while (pow > 0)
    {
        if (pow % 2 == 1)
            r *= p;
        p *= p;
        pow /= 2;
    }

    return (int)r;
}
#endif

static int eap_noob_get_minsleep(struct eap_noob_serv_context *data)
{
    /* TODO:  Include actual implementation for calculating the waiting time.
     * return  \
     * (int)((eap_noob_cal_pow(2,data->peer_attr->minslp_count))* (rand()%8) + 1) % 3600 ; */
    return 60;
}

/**
 * eap_noob_err_msg : prepares error message
 * @data : server context
 * @id   : response message id
 * Returns : pointer to message buffer or null
 **/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_serv_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf *req = NULL;
    char * req_json = NULL;
    size_t len = 0 ;
    int code = 0;

    if (NULL == data || NULL == data->peer_attr || 0 == (code = data->peer_attr->err_code)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error request");

    if (NULL == (req_obj = json_object()))
        goto EXIT;
    if (data->peer_attr->PeerId && code != E1001) {
        json_object_set_new(req_obj, PEERID,
                json_string(data->peer_attr->PeerId));
    } else {
        json_object_set_new(req_obj, PEERID,
                json_string(data->peer_attr->peerID_rcvd));
    }
    json_object_set_new(req_obj, TYPE, json_integer(NONE));
    json_object_set_new(req_obj, ERR_CODE,
            json_integer(error_code[code]));
    json_object_set_new(req_obj, ERR_INFO,
            json_string(error_info[code]));

    req_json = json_dumps(req_obj,JSON_COMPACT);
    if (NULL == req_json)
        goto EXIT;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: ERROR message = %s == %d", req_json, (int)strlen(req_json));
    len = strlen(req_json)+1;
    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for NOOB ERROR message");
        goto EXIT;
    }

    if (code != E1001 && FAILURE == eap_noob_db_update(data, UPDATE_STATE_ERROR)) {
        /* eap_oob_set_error(); //Internal error
        set_done(data, NOT_DONE); */
        wpa_printf(MSG_DEBUG,"Fail to Write Error to DB");
    }

    wpabuf_put_data(req, req_json, len);
    EAP_NOOB_SET_DONE(data, DONE);
    EAP_NOOB_SET_SUCCESS(data, FAILURE);
    data->peer_attr->err_code = NO_ERROR;
EXIT:
    EAP_NOOB_JSON_FREE(req_obj);
    EAP_NOOB_FREE(req_json);

    return req;
}

/**
 * eap_noob_gen_KDF : generates and updates the KDF inside the peer context.
 * @data  : peer context.
 * @state : EAP_NOOB state
 * Returns:
 **/
static void eap_noob_gen_KDF(struct eap_noob_serv_context * data, int state)
{
    const EVP_MD * md = EVP_sha256();
    unsigned char * out = os_zalloc(KDF_LEN);
    int counter = 0;

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: ALGORITH ID:",
                      ALGORITHM_ID, ALGORITHM_ID_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Peer_NONCE:",
                      data->peer_attr->kdf_nonce_data->nonce_peer,
                      EAP_NOOB_NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Serv_NONCE:",
                      data->peer_attr->kdf_nonce_data->nonce_serv,
                      EAP_NOOB_NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Shared Key:",
                      data->peer_attr->ecdh_exchange_data->shared_key,
                      EAP_SHARED_SECRET_LEN);

    if (state == COMPLETION_EXCHANGE) {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: NOOB:", data->peer_attr->oob_data->noob,
                          EAP_NOOB_NOOB_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->peer_attr->ecdh_exchange_data->shared_key, EAP_SHARED_SECRET_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->peer_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN,
                data->peer_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN,
                data->peer_attr->oob_data->noob, EAP_NOOB_NOOB_LEN, md);
    } else {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: kz:", data->peer_attr->kdf_out->kz, KZ_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->peer_attr->kdf_out->kz, KZ_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->peer_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN,
                data->peer_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN,
                NULL, 0, md);
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KDF", out, KDF_LEN);

    if (out != NULL) {
        data->peer_attr->kdf_out->msk = os_zalloc(MSK_LEN);
        data->peer_attr->kdf_out->emsk = os_zalloc(EMSK_LEN);
        data->peer_attr->kdf_out->amsk = os_zalloc(AMSK_LEN);
        data->peer_attr->kdf_out->kms = os_zalloc(KMS_LEN);
        data->peer_attr->kdf_out->kmp = os_zalloc(KMP_LEN);
        data->peer_attr->kdf_out->kz = os_zalloc(KZ_LEN);

        memcpy(data->peer_attr->kdf_out->msk, out, MSK_LEN);
        counter += MSK_LEN;
        memcpy(data->peer_attr->kdf_out->emsk, out + counter, EMSK_LEN);
        counter += EMSK_LEN;
        memcpy(data->peer_attr->kdf_out->amsk, out + counter, AMSK_LEN);
        counter += AMSK_LEN;
        memcpy(data->peer_attr->kdf_out->kms, out + counter, KMS_LEN);
        counter += KMS_LEN;
        memcpy(data->peer_attr->kdf_out->kmp, out + counter, KMP_LEN);
        counter += KMP_LEN;
        memcpy(data->peer_attr->kdf_out->kz, out + counter, KZ_LEN);
        counter += KZ_LEN;
        os_free(out);
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory, %s",
                            __func__);
    }
}

#if 0
static char * eap_noob_prepare_hoob_arr(struct eap_noob_serv_context * data)
{
    json_t * hoob_arr = NULL;
    json_t * ver_arr = NULL;
    json_t * csuite_arr = NULL;
    char * hoob_str = NULL;
    json_error_t error;
    int dir = (data->server_attr->dir & data->peer_attr->dir);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
    if (NULL != (hoob_arr = json_array())) {

        json_array_append(hoob_arr,json_integer(dir));

        if ((ver_arr = eap_noob_prepare_vers_arr(data)) == NULL)
            return NULL;


        json_array_append(hoob_arr,ver_arr);

        json_array_append(hoob_arr,json_integer(data->peer_attr->version));

        json_array_append(hoob_arr,json_string(data->peer_attr->PeerId));

        if ((csuite_arr = eap_noob_prepare_csuites_arr(data)) == NULL)
            return NULL;

        json_array_append(hoob_arr,csuite_arr);

        json_array_append(hoob_arr,json_integer(data->server_attr->dir));

        json_array_append(hoob_arr,json_string(data->server_attr->serv_info));

        json_array_append(hoob_arr,json_integer(data->peer_attr->cryptosuite));

        json_array_append(hoob_arr,json_integer(data->peer_attr->dir));

        json_array_append(hoob_arr,json_string(data->peer_attr->peer_info));

        json_array_append(hoob_arr,json_loads(json_dumps(data->peer_attr->ecdh_exchange_data->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER),
                    JSON_COMPACT|JSON_PRESERVE_ORDER,&error));

        json_array_append(hoob_arr,json_string(data->peer_attr->kdf_nonce_data->nonce_serv_b64));

        json_array_append(hoob_arr,json_loads(json_dumps(data->peer_attr->ecdh_exchange_data->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER),
                    JSON_COMPACT|JSON_PRESERVE_ORDER,&error));

        json_array_append(hoob_arr,json_string(data->peer_attr->kdf_nonce_data->nonce_peer_b64));

        json_array_append(hoob_arr,json_string(data->peer_attr->oob_data->noob_b64));

        hoob_str = json_dumps(hoob_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
    }

    free(ver_arr);
    free(csuite_arr);
    return hoob_str;
}

static int eap_noob_get_hoob(struct eap_noob_serv_context *data,unsigned char *out, size_t outlen)
{
    const EVP_MD *md = EVP_sha256();
    EVP_MD_CTX *mctx = NULL;
    int rv = 0;
    size_t mdlen;

    char * mac_string = NULL; //TODO : allocate memory dynamically
    int mac_str_len= 0;

    mac_string = eap_noob_prepare_hoob_arr(data);

    mac_str_len = os_strlen(mac_string);

    printf("HOOB string  = %s\n length  = %d\n",mac_string,mac_str_len);

    wpa_printf(MSG_DEBUG,"EAP-NOOB: HOOB start ");
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-OOB: Value:",mac_string, mac_str_len);

    if (outlen > ECDH_KDF_MAX || mac_str_len > ECDH_KDF_MAX)
        return 0;
    mctx = EVP_MD_CTX_create();
    if (mctx == NULL)
        return 0;
    mdlen = EVP_MD_size(md);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: HOOB begin %d",(int)mdlen);

    unsigned char mtmp[EVP_MAX_MD_SIZE];
    EVP_DigestInit_ex(mctx, md, NULL);

    if (!EVP_DigestUpdate(mctx, mac_string, mac_str_len))
        goto err;
    if (!EVP_DigestFinal(mctx, mtmp, NULL))
        goto err;

    memcpy(out, mtmp, outlen);
    OPENSSL_cleanse(mtmp, mdlen);
    rv = 1;
err:
    wpa_printf(MSG_DEBUG,"EAP-NOOB:HOOB finished %d",rv);
    EVP_MD_CTX_destroy(mctx);
    return rv;
}
#endif

/**
 * eap_noob_prepare_vers_arr : prepares a JSON array for Vers
 * @data: peer context
 * return : Json array/NULL
 **/
static json_t * eap_noob_prepare_vers_arr(const struct eap_noob_serv_context * data)
{
    json_t * ver_arr = NULL;
    u32 i  = 0;

    if (NULL == data || NULL == (ver_arr = json_array())) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null",  __func__);
        return NULL;
    }
    for (i = 0; i < MAX_SUP_VER ; i++) {
        json_array_append_new(ver_arr,
           json_integer(data->server_attr->version[i]));
    }
    return ver_arr;
}


/**
 * eap_noob_prepare_csuites_arr : prepares a JSON array for Cryptosuites
 * @data: peer context
 * return : Json array/NULL
 **/
static json_t * eap_noob_prepare_csuites_arr(const struct eap_noob_serv_context * data)
{
    json_t * csuite_arr = NULL;
    u32 i = 0;

    if (NULL == data || NULL == (csuite_arr = json_array())) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null",  __func__);
        return NULL;
    }

    for (i = 0; i < MAX_SUP_CSUITES ; i++) {
        json_array_append_new(csuite_arr,
          json_integer(data->server_attr->cryptosuite[i]));
    }
    return csuite_arr;
}

/**
 * eap_noob_prepare_mac_input: Prepare a JSON array to generate MAC.
 * @data  : server context
 * @type  : MAC type
 * state  : EAP_NOOB state
 * returns: MAC string. The caller function has to free the returned string.
 **/
static char * eap_noob_prepare_mac_input(struct eap_noob_serv_context * data, int type, int state)
{
    json_t * mac_input = NULL;
    char * mac_input_str = NULL;
    char * query = NULL;
    json_error_t error;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        goto EXIT;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

    if (NULL == (mac_input = json_array())) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating json array");
        goto EXIT;
    }

    query = os_zalloc(MAX_LINE_SIZE);
    snprintf(query, MAX_LINE_SIZE, "SELECT %s from %s where PeerId='%s' ", 
        (state < RECONNECT) ? "Mac1Input" : "Mac2Input", PEER_TABLE, data->peer_attr->PeerId); 
    if (eap_noob_exec_query(query, eap_noob_callback, data))
        goto EXIT;
    
    mac_input = json_loads(data->peer_attr->Mac1Input, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);

    if (type == MACP)
        json_array_insert_new(mac_input,0,json_integer(1));
    else if (type == MACS)
        json_array_insert_new(mac_input,0,json_integer(2));
    mac_input_str = json_dumps(mac_input, JSON_COMPACT|JSON_PRESERVE_ORDER);

EXIT:
    os_free(query);
    EAP_NOOB_JSON_FREE(mac_input);
    return mac_input_str;
}

/**
 * eap_noob_gen_MAC : generate a HMAC for user authentication. Do not free mac
 * from the calling function
 * @data : server context
 * type  : MAC type
 * @key  : key to generate MAC
 * @keylen: key length
 * @state : EAP_NOOB state
 * Returns : MAC on success or NULL on error.
**/
static u8 * eap_noob_gen_MAC(struct eap_noob_serv_context * data, int type, u8 * key, int keylen, int state)
{
    char * mac_str = NULL;
    u8 * mac = NULL;

    if (NULL == data || NULL == key) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);

    if (NULL != (mac_str = eap_noob_prepare_mac_input(data, type, state))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: MAC_STR = %s", mac_str);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: LENGTH = %d", (int)strlen(mac_str));
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KEY:",key,keylen);
        mac = HMAC(EVP_sha256(), key, keylen, (u8 *)mac_str, strlen(mac_str), NULL, NULL);
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MACp", mac, 32);

        /* Free up mac_str allocated in prepare_mac_arr */
        os_free(mac_str);
    }

    return mac;
}

/**
 * eap_noob_req_type_seven :
 * @data : server context
 * @id  :
 * Returns :
**/
static struct wpabuf * eap_noob_req_type_seven(struct eap_noob_serv_context * data, u8 id)
{
    struct wpabuf * req = NULL;
    char * req_json = NULL, * mac_b64 = NULL;
    u8 * mac = NULL;
    json_t * req_obj = NULL;
    size_t len = 0 ;

    /* generate KDF */
    eap_noob_gen_KDF(data, RECONNECT_EXCHANGE);

    /* generate MAC */
    mac = eap_noob_gen_MAC(data, MACS, data->peer_attr->kdf_out->kms,
            KMS_LEN, RECONNECT_EXCHANGE);
    eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

    /*TODO : calculate MAC for encoding */
    if (NULL == (req_obj = json_object()))
        goto EXIT;

    json_object_set_new(req_obj,TYPE,
            json_integer(EAP_NOOB_TYPE_7));
    json_object_set_new(req_obj, PEERID,
            json_string(data->peer_attr->PeerId));
    json_object_set_new(req_obj, MACs,
            json_string(mac_b64));

    req_json = json_dumps(req_obj, JSON_COMPACT);
    len = strlen(req_json)+1;

    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,
            len, EAP_CODE_REQUEST, id);

    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Request/NOOB-FR");
        goto EXIT;
    }

    wpabuf_put_data(req, req_json, len);

EXIT:
    EAP_NOOB_JSON_FREE(req_obj);
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
static struct wpabuf * eap_noob_req_type_six(struct eap_noob_serv_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf *req = NULL;
    char * req_json = NULL, * base64_nonce = NULL;
    size_t len = 0 ;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 2/Fast Reconnect");

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    EAP_NOOB_FREE_MALLOC(data->peer_attr->kdf_nonce_data->nonce_serv,
            EAP_NOOB_NONCE_LEN);

    int rc = RAND_bytes(data->peer_attr->kdf_nonce_data->nonce_serv,
             EAP_NOOB_NONCE_LEN); /* To-Do base64 encoding */
    unsigned long err = ERR_get_error();

    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu", err);
    }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce",
            data->peer_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN);

    /* TODO: Based on the previous and the current versions of cryptosuites of peers,
     * decide whether new public key has to be generated
     * TODO: change get key params and finally store only base 64 encoded public key */
    eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->nonce_serv,
            EAP_NOOB_NONCE_LEN, &base64_nonce);
    wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s", base64_nonce);

    EAP_NOOB_FREE(data->peer_attr->kdf_nonce_data->nonce_serv_b64);
    data->peer_attr->kdf_nonce_data->nonce_serv_b64 = base64_nonce;

    if (NULL == (req_obj = json_object()))
        goto EXIT;

    json_object_set_new(req_obj, TYPE,
            json_integer(EAP_NOOB_TYPE_6));
    json_object_set_new(req_obj, PEERID,
            json_string(data->peer_attr->PeerId));
    json_object_set_new(req_obj, NONCE_SERV,
            json_string(base64_nonce));

    req_json = json_dumps(req_obj,JSON_COMPACT);

    wpa_printf(MSG_DEBUG, "EAP-NOOB: request %s",req_json);
    len = strlen(req_json)+1; //check here

    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,
            len, EAP_CODE_REQUEST, id);

    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Request/NOOB-FR");
        goto EXIT;
    }
    wpabuf_put_data(req,req_json,len);
EXIT:
    /* Do not free base64_nonce as its value is stored in
     * nonce_data->nonce_serv_b64 */
    EAP_NOOB_JSON_FREE(req_obj);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 * eap_oob_req_type_five - Build the EAP-Request/Fast Reconnect 1.
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_five(struct eap_noob_serv_context * data, u8 id)
{
    struct wpabuf * req = NULL;
    char * req_json = NULL;
    json_t * req_obj = NULL, * csuite_arr = NULL;
    size_t len = 0;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }
    /* (Type=1, PeerId, CryptoSuites, Dirs, ServerInfo) */
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering func %s", __func__);

    if (NULL == (req_obj = json_object()))
        goto EXIT;

    if (NULL == (csuite_arr = eap_noob_prepare_csuites_arr(data)))
        goto EXIT;

    json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_5));
    json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    json_object_set_new(req_obj, CRYPTOSUITES, csuite_arr);
    /* TODO send this only if changed (check even at peer side) */
    json_object_set_new(req_obj, SERVERINFO,
            eap_noob_serverinfo(data->server_attr->serv_config_params));

    req_json = json_dumps(req_obj, JSON_COMPACT);
    if (!req_json) goto EXIT;

    len = strlen(req_json);
    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len+1 , EAP_CODE_REQUEST, id);
    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Request/NOOB-FR");
        goto EXIT;
    }
    wpabuf_put_data(req, req_json, len+1);

EXIT:
    EAP_NOOB_JSON_FREE(req_obj);
    EAP_NOOB_JSON_FREE(csuite_arr);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 * eap_oob_req_type_four - Build the EAP-Request
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_four(struct eap_noob_serv_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf * req = NULL;
    char * mac_b64 = NULL, * req_json = NULL;
    u8 * mac = NULL;
    size_t len = 0 ;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context NULL in %s", __func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    /* generate KDF */
    eap_noob_gen_KDF(data, COMPLETION_EXCHANGE);

    /* generate MAC */
    mac = eap_noob_gen_MAC(data, MACS, data->peer_attr->kdf_out->kms, KMS_LEN,COMPLETION_EXCHANGE);
    if (NULL == mac) goto EXIT;

    eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);
    eap_noob_Base64Encode(data->peer_attr->kdf_out->kms, KMS_LEN, &data->peer_attr->kdf_out->kms_b64);
    eap_noob_Base64Encode(data->peer_attr->kdf_out->kmp, KMP_LEN, &data->peer_attr->kdf_out->kmp_b64);
    eap_noob_Base64Encode(data->peer_attr->kdf_out->kz, KZ_LEN, &data->peer_attr->kdf_out->kz_b64);

    /* TODO : calculate MAC for encoding */
    if (NULL == (req_obj = json_object()))
        goto EXIT;

    json_object_set_new(req_obj, TYPE,
            json_integer(EAP_NOOB_TYPE_4));
    json_object_set_new(req_obj, PEERID,
            json_string(data->peer_attr->PeerId));
    json_object_set_new(req_obj, HINT_SERV,
            json_string(data->peer_attr->oob_data->hint_b64));
    json_object_set_new(req_obj, MACs, json_string(mac_b64));

    req_json = json_dumps(req_obj, JSON_COMPACT);
    if (NULL == req_json) goto EXIT;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Type 4 request = %s", req_json);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Type 4 hint = %s", data->peer_attr->oob_data->hint_b64);

    len = strlen(req_json)+1;
    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);

    if (NULL == req) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Request/NOOB-CE");
        goto EXIT;
    }
    wpabuf_put_data(req, req_json, len);
EXIT:
    EAP_NOOB_JSON_FREE(req_obj);
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
static struct wpabuf * eap_noob_req_type_three(struct eap_noob_serv_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf *req = NULL;
    char * req_json = NULL;
    size_t len = 0;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 3/Waiting Exchange");
    if (NULL == (req_obj = json_object()))
        goto EXIT;

    data->peer_attr->minsleep = eap_noob_get_minsleep(data);
    json_object_set_new(req_obj, TYPE,
        json_integer(EAP_NOOB_TYPE_3));
    json_object_set_new(req_obj, PEERID,
        json_string(data->peer_attr->PeerId));
    json_object_set_new(req_obj, MINSLEEP,
        json_integer(data->peer_attr->minsleep));
    clock_gettime(CLOCK_REALTIME, &data->peer_attr->sleep_time);
    wpa_printf(MSG_DEBUG, "Current Time is %ld", data->peer_attr->sleep_time.tv_sec);
    data->peer_attr->sleep_time.tv_sec = data->peer_attr->sleep_time.tv_sec + data->peer_attr->minsleep;

    req_json = json_dumps(req_obj,JSON_COMPACT);
    if (!req_json) goto EXIT;

    len = strlen(req_json)+1;
    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);
    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Request/NOOB-WE");
        goto EXIT;
    }
    wpabuf_put_data(req, req_json, len);
EXIT:
    EAP_NOOB_JSON_FREE(req_obj);
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
        json_object_set_new((*jwk), CURVE, json_string("Curve25519"));
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

    char * dump_str = json_dumps((*jwk), JSON_COMPACT);
    if (dump_str) {
        wpa_printf(MSG_DEBUG, "JWK Key %s", dump_str);
        os_free(dump_str);
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
static struct wpabuf * eap_noob_req_type_two(struct eap_noob_serv_context *data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf * req = NULL;
    char * req_json = NULL, * base64_nonce = NULL;
    size_t len = 0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 2/Initial Exchange");
    if (NULL == data || NULL == data->peer_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    EAP_NOOB_FREE_MALLOC(data->peer_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN);

    int rc = RAND_bytes(data->peer_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN);
    unsigned long err = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce. "
                              "Error Code = %lu", err);
        goto EXIT;
    }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce",
            data->peer_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN);

    /* Generate Key material */
    if (eap_noob_get_key(data) == FAILURE) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
        EAP_NOOB_SET_DONE(data, DONE);
        EAP_NOOB_SET_SUCCESS(data, FAILURE);
        goto EXIT;
    }

    if (FAILURE == eap_noob_build_JWK(&data->peer_attr->ecdh_exchange_data->jwk_serv,
                   data->peer_attr->ecdh_exchange_data->x_b64)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate JWK");
        goto EXIT;
    }

    /* TODO: change get key params and finally store only base 64 encoded public key */
    eap_noob_Base64Encode(data->peer_attr->kdf_nonce_data->nonce_serv,
                          EAP_NOOB_NONCE_LEN, &base64_nonce);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Nonce %s", base64_nonce);

    data->peer_attr->kdf_nonce_data->nonce_serv_b64 = base64_nonce;
    data->peer_attr->minsleep = eap_noob_get_minsleep(data);

    if (NULL == (req_obj = json_object()))
        goto EXIT;

    json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_2));
    json_object_set_new(req_obj, PEERID, json_string(data->peer_attr->PeerId));
    json_object_set_new(req_obj, NONCE_SERV, json_string(base64_nonce));
    json_object_set(req_obj, JSON_WEB_KEY, data->peer_attr->ecdh_exchange_data->jwk_serv);
    json_object_set_new(req_obj, MINSLEEP, json_integer(data->peer_attr->minsleep));

    req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER);
    if (!req_json) goto EXIT;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: request %s =  %d",req_json,(int)strlen(req_json));
    len = strlen(req_json)+1;

    req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_REQUEST, id);
    if (req == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Request/NOOB-IE");
        goto EXIT;
    }

    wpabuf_put_data(req, req_json, len);
EXIT:
    EAP_NOOB_JSON_FREE(req_obj);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 * eap_oob_req_type_one - Build the EAP-Request/Initial Exchange 1.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_one(struct eap_noob_serv_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf * req = NULL;
    size_t len = 0;
    json_t * emptystr = json_string("");
    int err = 0;
    json_t * Vers, *macinput;
    json_t * Cryptosuites, *Dirs,*ServerInfo, *Realm;
    json_t * PeerId;
    char * req_json;

    /* (Type=1, PeerId, CryptoSuites, Dirs ,ServerInfo) */

    if (NULL == data || NULL == data->server_attr || NULL == data->peer_attr) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 1/Initial Exchange");
     
    EAP_NOOB_FREE(data->peer_attr->PeerId);
    if (eap_noob_get_id_peer(data->peer_attr->PeerId, MAX_PEER_ID_LEN)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to generate PeerId");
        return NULL;
    }

    err -= (NULL == (Vers = json_array()));
    for (int i = 0; i < MAX_SUP_VER ; i++) {
        if (data->server_attr->version[i] > 0)
            err += json_array_append_new(Vers, json_integer(data->server_attr->version[i]));
    }

    PeerId = json_string(data->peer_attr->PeerId);

    err -= (NULL == (Cryptosuites = json_array()));
    for (int i = 0; i < MAX_SUP_CSUITES ; i++) {
        if (data->server_attr->cryptosuite[i] > 0)
            err += json_array_append_new(Cryptosuites,
               json_integer(data->server_attr->cryptosuite[i]));
    }
    err -= (NULL == (Dirs = json_integer(data->server_attr->dir)));
    err -= (NULL == (ServerInfo = eap_noob_serverinfo(data->server_attr->serv_config_params)));

    /* Create request */
    err -= (NULL == (req_obj = json_object()));
    err += json_object_set_new(req_obj, TYPE, json_integer(EAP_NOOB_TYPE_1));
    err += json_object_set_new(req_obj, VERSION_SERV, Vers);
    err += json_object_set_new(req_obj, PEERID, PeerId);
    err += json_object_set_new(req_obj, CRYPTOSUITES, Cryptosuites);
    err += json_object_set_new(req_obj, DIRECTION_SERV, Dirs);
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

    printf("Request Sending = %s = %d\n", req_json, (int)strlen(req_json));
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
    data->peer_attr->Mac1Input = macinput;
    if (err < 0) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unexpected JSON processing error when creating mac input template.");
        goto EXIT;
    }

EXIT:
    EAP_NOOB_FREE(req_json);
    json_decref(req_obj);
    if (err < 0) {
        json_decref(macinput);
        data->peer_attr->Mac1Input = NULL;
        wpabuf_free(req);
        return NULL;
    }
    return req;
}

/**
 * eap_noob_req_hint -
 * @data: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_hint(struct eap_noob_serv_context * data, u8 id)
{
    struct wpabuf * req = NULL;
    json_t * req_obj = NULL;
    char * req_json = NULL;
    size_t len = 0;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }

    if (NULL != (req_obj = json_object())) {
        json_object_set_new(req_obj, TYPE,
                json_integer(EAP_NOOB_TYPE_HINT));
        json_object_set_new(req_obj, PEERID,
                json_string(data->peer_attr->PeerId));

        req_json = json_dumps(req_obj, JSON_COMPACT|JSON_PRESERVE_ORDER);
        if (!req_json) goto EXIT;

        wpa_printf(MSG_DEBUG, "EAP-NOOB: REQ Received = %s", req_json);
        len = strlen(req_json);

        req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len+1, EAP_CODE_REQUEST, id);
        if (req == NULL) {
            wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                    "for Request/NOOB-IE");
            goto EXIT;
        }

        wpabuf_put_data(req, req_json, len+1);
    }
EXIT:
    EAP_NOOB_JSON_FREE(req_obj);
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
    struct eap_noob_serv_context *data = NULL;

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

        case EAP_NOOB_TYPE_HINT:
            return eap_noob_req_hint(data, id);
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
    struct eap_noob_serv_context * data = NULL;
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
    data = priv; state = data->peer_attr->serv_state;
    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);
    resp_obj = json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);

    if ((NULL != resp_obj) && (json_is_object(resp_obj) > 0)) {
        resp_type = json_object_get(resp_obj, TYPE);

        if ((NULL != resp_type) && (json_is_integer(resp_type) > 0)) {
            data->peer_attr->recv_msg = json_integer_value(resp_type);
        }
        else {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown message type");
            EAP_NOOB_SET_ERROR(data->peer_attr, E1002);
            ret = TRUE; goto EXIT;
        }
    }
    else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
        EAP_NOOB_SET_ERROR(data->peer_attr, E1002);
        ret = TRUE; goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received frame: opcode = %d", data->peer_attr->recv_msg);
    wpa_printf(MSG_DEBUG, "STATE = %d",data->peer_attr->serv_state);
    wpa_printf(MSG_DEBUG, "VERIFY STATE SERV = %d PEER = %d",
            data->peer_attr->serv_state, data->peer_attr->peer_state);

    if ((NONE != data->peer_attr->recv_msg) && ((state >= NUM_OF_STATES) ||
       (data->peer_attr->recv_msg > MAX_MSG_TYPES) ||
       (VALID != state_message_check[state][data->peer_attr->recv_msg]))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Setting error in received message."
                "state (%d), message type (%d), state received (%d)",
                state, data->peer_attr->recv_msg,
                state_message_check[state][data->peer_attr->recv_msg]);
        EAP_NOOB_SET_ERROR(data->peer_attr,E1004);
        ret = TRUE; goto EXIT;
    }

EXIT:
    EAP_NOOB_FREE(resp_obj);
    EAP_NOOB_FREE(resp_type);
    /* TODO check -- Rohan, why did you remove the security checks? */
    /* return FALSE; */
    return ret;
}


/**
 * eap_noob_del_temp_tuples :
 * @data : peer context
 * retures: FAILURE/SUCCESS
 **/
static int eap_noob_del_temp_tuples(struct eap_noob_serv_context * data)
{
    char * query = os_malloc(MAX_LINE_SIZE);
    int ret = SUCCESS;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        ret = FAILURE; goto EXIT;
    }

    if (query) {
        snprintf(query, MAX_LINE_SIZE, "Delete from %s WHERE PeerId='%s'",
                 DEVICE_TABLE, data->peer_attr->peerID_rcvd);
        if (FAILURE == eap_noob_exec_query(query, NULL, data)) {
            wpa_printf(MSG_ERROR, "EAP-NOOB: DB tuple deletion failed");
            ret = FAILURE; goto EXIT;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: TEMP Tuples removed");
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory to query, %s",
                   __func__);
        ret = FAILURE;
    }
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
                    if (strlen(data->peerID_rcvd) > MAX_PEER_ID_LEN) {
                        EAP_NOOB_SET_ERROR(data, E1003);
                    }
                    break;
                case NONCE_RCVD:
                    if (strlen((char *)data->kdf_nonce_data->nonce_peer) > EAP_NOOB_NONCE_LEN) {
                        EAP_NOOB_SET_ERROR(data, E1003);
                    }
                    break;
                case MAC_RCVD:
                    if (strlen(data->mac) > MAC_LEN) {
                        EAP_NOOB_SET_ERROR(data, E1003);
                    }
                    break;
                case INFO_RCVD:
                    if (strlen(data->peer_info) > MAX_INFO_LEN) {
                        EAP_NOOB_SET_ERROR(data, E1003);
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
int eap_noob_FindIndex( int value )
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
    const char * key = NULL;
    const char * retval_char = NULL;
    char * dump_str = NULL;
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
                if (0 == strcmp(key, JSON_WEB_KEY)) {
                    dump_str = json_dumps(value, JSON_COMPACT|JSON_PRESERVE_ORDER);
                    data->ecdh_exchange_data->jwk_peer = json_loads(dump_str,
                            JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
                    os_free(dump_str);
                    data->rcvd_params |= PKEY_RCVD;
                } else if (0 == strcmp(key, PEER_INFO)) {
                    data->peer_info = json_dumps(value, JSON_COMPACT|JSON_PRESERVE_ORDER);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Peer Info: %s", data->peer_info);
                    data->rcvd_params |= INFO_RCVD;
                }
                eap_noob_decode_obj(data, value);
                break;

            case JSON_INTEGER:
                if (0 == (retval_int = json_integer_value(value)) &&
                   (0 != strcmp(key,TYPE))) {
                    EAP_NOOB_SET_ERROR(data, E1003);
                    return;
                }

                if (0 == strcmp(key, VERSION_PEER)) {
                    data->version = retval_int;
                    data->rcvd_params |= VERSION_RCVD;
                }
                else if (0 == strcmp(key, CRYPTOSUITEP)) {
                    data->cryptosuite = retval_int;
                    data->rcvd_params |= CSUITE_RCVD;
                }
                else if (0 == strcmp(key, DIRECTION_PEER)) {
                    data->dir = retval_int;
                    data->rcvd_params |= DIRECTION_RCVD;
                }
                else if (0 == strcmp(key, ERR_CODE)) {
                    EAP_NOOB_SET_ERROR(data, eap_noob_FindIndex(retval_int));
                }
                break;

            case JSON_STRING:
                if (NULL == (retval_char = json_string_value(value))) {
                    EAP_NOOB_SET_ERROR(data,E1003);
                    return;
                }

                if (0 == strcmp(key, PEERID)) {
                    EAP_NOOB_FREE(data->peerID_rcvd);
                    data->peerID_rcvd = os_strdup(retval_char);
                    data->rcvd_params |= PEERID_RCVD;
                }
                else if (0 == strcmp(key, HINT_PEER)) {
                    EAP_NOOB_FREE(data->oob_data->hint_b64);
                    EAP_NOOB_FREE(data->oob_data->hint);
                    data->oob_data->hint_b64 = os_strdup(retval_char);
                    data->oob_data->hint_len = \
                        eap_noob_Base64Decode(data->oob_data->hint_b64, &data->oob_data->hint);
                    if (0 == data->oob_data->hint_b64)
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode hint");
                    else
                        data->rcvd_params |= HINT_RCVD;
                }
                else if (0 == strcmp(key, PEER_SERIAL_NUM)) {
                    data->peer_snum = os_strdup(retval_char);
                }
                else if (0 == strcmp(key, NONCE_PEER)) {
                    data->kdf_nonce_data->nonce_peer_b64 = os_strdup(retval_char);
                    decode_length = \
                    eap_noob_Base64Decode((char *)data->kdf_nonce_data->nonce_peer_b64,
                        &data->kdf_nonce_data->nonce_peer);
                    if (0 == decode_length)
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode peer nonce");
                    else
                        data->rcvd_params |= NONCE_RCVD;
                }
                else if (0 == strcmp(key, MACp)) {
                    decode_length = eap_noob_Base64Decode((char *)retval_char, (u8**)&data->mac);
                    if (0 == decode_length)
                        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode MAC");
                    else
                        data->rcvd_params |= MAC_RCVD;
                }
                else if (0 == strcmp(key, X_COORDINATE)) {
                    data->ecdh_exchange_data->x_peer_b64 = os_strdup(json_string_value(value));
                    wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->x_peer_b64);
                }
                else if (0 == strcmp(key, Y_COORDINATE)) {
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
static void eap_noob_rsp_type_seven(struct eap_noob_serv_context * data,
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
        EAP_NOOB_SET_ERROR(data->peer_attr, E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    /* check error code after decoding */
    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerID(data)) {
        mac = eap_noob_gen_MAC(data, MACP, data->peer_attr->kdf_out->kmp,
              KMP_LEN, RECONNECT_EXCHANGE);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);

        if (0 != strcmp(data->peer_attr->mac, (char *)mac+16)) {
            EAP_NOOB_SET_ERROR(data->peer_attr,E4001);
            EAP_NOOB_SET_DONE(data, NOT_DONE);
            goto EXIT;
        }

        EAP_NOOB_CHANGE_STATE(data, REGISTERED);
        if (FAILURE == eap_noob_db_update(data, UPDATE_STATE)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed ");
            goto EXIT;
        }
        data->peer_attr->next_req = NONE;
        EAP_NOOB_SET_DONE(data, DONE);
        EAP_NOOB_SET_SUCCESS(data, SUCCESS);
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
static void eap_noob_rsp_type_six(struct eap_noob_serv_context * data,
                                  json_t * resp_obj)
{
    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-2");
    eap_noob_decode_obj(data->peer_attr, resp_obj);

    if (data->peer_attr->rcvd_params != TYPE_SIX_PARAMS) {
        EAP_NOOB_SET_ERROR(data->peer_attr, E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer",
            data->peer_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);
    if (eap_noob_verify_peerID(data)) {
        data->peer_attr->next_req = EAP_NOOB_TYPE_7;
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        data->peer_attr->rcvd_params = 0;
    }
}

/**
 * eap_oob_rsp_type_five - Process EAP-Response Type 5
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_five(struct eap_noob_serv_context * data,
                                   json_t * resp_obj)
{
    /* check for the supporting cryptosuites, PeerId, version, direction */
    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-1");

    /* TODO: Check for the current cryptosuite and the previous to
     * decide whether new key exchange has to be done */
    eap_noob_decode_obj(data->peer_attr, resp_obj);
    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (data->peer_attr->rcvd_params != TYPE_FIVE_PARAMS) {
        EAP_NOOB_SET_ERROR(data->peer_attr, E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerID(data)) {
        data->peer_attr->next_req = EAP_NOOB_TYPE_6;
    }
    EAP_NOOB_SET_DONE(data, NOT_DONE);
    data->peer_attr->rcvd_params = 0;
}

/**
 * eap_oob_rsp_type_four - Process EAP-Response Type 4
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_four(struct eap_noob_serv_context * data,
                                   json_t * resp_obj)
{
    u8 * mac = NULL; char * mac_b64 = NULL;
    int dir = 0;

    dir = (data->server_attr->dir & data->peer_attr->dir);

    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-CE-4");
    eap_noob_decode_obj(data->peer_attr, resp_obj);
    /* TODO :  validate MAC address along with peerID */
    if (data->peer_attr->rcvd_params != TYPE_FOUR_PARAMS) {
        EAP_NOOB_SET_ERROR(data->peer_attr,E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerID(data)) {
        mac = eap_noob_gen_MAC(data,MACP,data->peer_attr->kdf_out->kmp, KMP_LEN, COMPLETION_EXCHANGE);
        eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);

        if (0 != strcmp(data->peer_attr->mac, (char *)mac+16)) {
            EAP_NOOB_SET_ERROR(data->peer_attr,E4001);
            EAP_NOOB_SET_DONE(data, NOT_DONE);
            goto EXIT;
        }

        EAP_NOOB_CHANGE_STATE(data,REGISTERED);
        if (FAILURE == eap_noob_db_update(data,UPDATE_PERSISTENT_KEYS_SECRET)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Updating server state failed ");
            goto EXIT;
        }

        if (dir == SERV_TO_PEER) {
            eap_noob_del_temp_tuples(data);
        }

        data->peer_attr->next_req = NONE;
        EAP_NOOB_SET_DONE(data, DONE);
        EAP_NOOB_SET_SUCCESS(data,SUCCESS);
    }
EXIT:
    EAP_NOOB_FREE(mac_b64);
}

/**
 * eap_oob_rsp_type_three - Process EAP-Response Type 3
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_three(struct eap_noob_serv_context * data,
                                    json_t * resp_obj)
{
    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-WE-3");

    eap_noob_decode_obj(data->peer_attr,resp_obj);
    if (data->peer_attr->rcvd_params != TYPE_THREE_PARAMS) {
        EAP_NOOB_SET_ERROR(data->peer_attr,E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }
    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerID(data)) {
        EAP_NOOB_CHANGE_STATE(data, WAITING);
        data->peer_attr->next_req = NONE;
        EAP_NOOB_SET_DONE(data, DONE);
        EAP_NOOB_SET_SUCCESS(data, FAILURE);
    }
}

/**
 * eap_oob_rsp_type_two - Process EAP-Response/Initial Exchange 2
 * @data: Pointer to private EAP-NOOB data
 * @resp_obj: json object of the response received
 **/
static void eap_noob_rsp_type_two(struct eap_noob_serv_context * data,
                                  json_t * resp_obj)
{
    size_t secret_len = EAP_SHARED_SECRET_LEN;

    if (NULL == resp_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-2");
    eap_noob_decode_obj(data->peer_attr,resp_obj);

    if (data->peer_attr->rcvd_params != TYPE_TWO_PARAMS) {
        EAP_NOOB_SET_ERROR(data->peer_attr,E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer",
       data->peer_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);

    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerID(data)) {
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer",
          data->peer_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);
        if (eap_noob_derive_session_secret(data,&secret_len) != SUCCESS) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in deriving shared key");
            return;
        }
        eap_noob_Base64Encode(data->peer_attr->ecdh_exchange_data->shared_key,
          EAP_SHARED_SECRET_LEN, &data->peer_attr->ecdh_exchange_data->shared_key_b64);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Shared secret %s",
                data->peer_attr->ecdh_exchange_data->shared_key_b64);
        EAP_NOOB_CHANGE_STATE(data,WAITING);

        if (FAILURE == eap_noob_db_entry(data)) {
            EAP_NOOB_SET_DONE(data, DONE);
            EAP_NOOB_SET_SUCCESS(data,FAILURE);
            return;
        }

        data->peer_attr->next_req = NONE;
        EAP_NOOB_SET_DONE(data, DONE);
        EAP_NOOB_SET_SUCCESS(data,FAILURE);
    }
}


/**
 * eap_oob_rsp_type_one - Process EAP-Response/Initial Exchange 1
 * @data: Pointer to private EAP-NOOB data
 * @payload: EAP data received from the peer
 * @payloadlen: Length of the payload
 **/
static void eap_noob_rsp_type_one(struct eap_sm * sm, struct eap_noob_serv_context * data,
                                  json_t * resp_obj)
{
    /* Check for the supporting cryptosuites, PeerId, version, direction*/
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-1");

    if (NULL == resp_obj || NULL == data || NULL == sm) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }

    eap_noob_decode_obj(data->peer_attr, resp_obj);
    


    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (data->peer_attr->rcvd_params != TYPE_ONE_PARAMS) {
        EAP_NOOB_SET_ERROR(data->peer_attr,E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (eap_noob_verify_peerID(data)) {
        data->peer_attr->next_req = EAP_NOOB_TYPE_2;
    }

    eap_noob_get_sid(sm, data);
    EAP_NOOB_SET_DONE(data, NOT_DONE);
    data->peer_attr->rcvd_params = 0;
}


static int eap_noob_exec_hint_queries(struct eap_noob_serv_context * data)
{
    char * query = os_malloc(MAX_LINE_SIZE);
    //To-Do: send error if NoodID not found

    if (query) {
        snprintf(query, MAX_LINE_SIZE, "SELECT Noob, Hoob from %s where PeerId='%s' and  Hint='%s'", DEVICE_TABLE,
                data->peer_attr->PeerId,data->peer_attr->oob_data->hint_b64);
        printf("Query = %s\n",query);
        if (eap_noob_exec_query(query, eap_noob_callback, data) && data->peer_attr->oob_data->noob != NULL) {
            return eap_noob_db_update(data, UPDATE_OOB);
        }
        os_free(query);
    }
    printf("No NoobId found========================\n");
    return FAILURE;
}

static void eap_noob_rsp_hint(struct eap_noob_serv_context * data,
                              json_t * resp_obj)
{
    eap_noob_decode_obj(data->peer_attr,resp_obj);
    //check error code after decoding
    if ((data->peer_attr->err_code != NO_ERROR)) {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (data->peer_attr->rcvd_params != TYPE_HINT_PARAMS) {
        EAP_NOOB_SET_ERROR(data->peer_attr,E1002);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (!eap_noob_verify_peerID(data)) {
        EAP_NOOB_SET_ERROR(data->peer_attr,E1005);
        EAP_NOOB_SET_DONE(data, NOT_DONE);
        return;
    }

    if (!eap_noob_exec_hint_queries(data) ||
        NULL == data->peer_attr->oob_data->hint_b64) {
        EAP_NOOB_SET_ERROR(data->peer_attr,E1006);
        EAP_NOOB_SET_DONE(data,NOT_DONE);
    } else {
        EAP_NOOB_SET_DONE(data, NOT_DONE);
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
    struct eap_noob_serv_context * data = NULL;
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

    EAP_NOOB_JSON_FREE(resp_obj);
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
        case EAP_NOOB_TYPE_HINT:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE HINT");
            eap_noob_rsp_hint(data, resp_obj);
            break;

        case NONE:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: ERROR received");
            eap_noob_decode_obj(data->peer_attr, resp_obj);
            if (FAILURE == eap_noob_db_update(data,UPDATE_STATE_ERROR)) {
                wpa_printf(MSG_DEBUG,"Fail to Write Error to DB");
            }

            EAP_NOOB_SET_DONE(data, DONE);
            EAP_NOOB_SET_SUCCESS(data, FAILURE);
            break;
    }
    data->peer_attr->recv_msg = 0;
    EAP_NOOB_JSON_FREE(resp_obj);
}


static Boolean eap_noob_isDone(struct eap_sm *sm, void *priv)
{

    struct eap_noob_serv_context *data = priv;
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
    struct eap_noob_serv_context *data = priv;
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
    wpa_printf(MSG_DEBUG, "EAP-NOOB: GET  KEY");
    struct eap_noob_serv_context *data = NULL;
    u8 *key = NULL;

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->peer_attr->serv_state != REGISTERED) || (!data->peer_attr->kdf_out->msk))
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
 * eap_noob_get_emsk : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns EMSK or NULL
**/
static u8 * eap_noob_get_emsk(struct eap_sm * sm, void * priv, size_t * len)
{
    struct eap_noob_serv_context * data = NULL;
    u8 * emsk = NULL;
    wpa_printf(MSG_DEBUG, "EAP-NOOB:Get EMSK called");

    if (!priv || !sm || !len) return NULL;
    data = priv;

    if ((data->peer_attr->serv_state != REGISTERED) || (!data->peer_attr->kdf_out->emsk))
        return NULL;

    if (NULL == (emsk = os_malloc(EAP_EMSK_LEN)))
        return NULL;
    os_memcpy(emsk, data->peer_attr->kdf_out->emsk, EAP_EMSK_LEN);

    if (emsk) {
        *len = EAP_EMSK_LEN;
        wpa_hexdump(MSG_DEBUG, "EAP-NOOB: Copied EMSK",
                emsk, EAP_EMSK_LEN);
    }
    else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to fetch EMSK");
    }

    return emsk;
}


static int eap_noob_getTimeout(struct eap_sm *sm, void *priv)
{
    //struct eap_oob_serv_context *data = priv;

    printf("In function %s\n",__func__);
    /* Recommended retransmit times: retransmit timeout 5 seconds,
     * per-message timeout 15 seconds, i.e., 3 tries. */
    sm->MaxRetrans = 0; /* total 3 attempts */
    return 1;
}

/**
 * eap_noob_serv_ctxt_alloc : Allocates the subcontexts inside the peer context
 * @sm : eap method context
 * @peer : server context
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_serv_ctxt_alloc(struct eap_sm * sm, struct eap_noob_serv_context * data)
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
 * eap_noob_serv_ctxt_init -Supporting Initializer for EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @data: Pointer to EAP-NOOB data
 * @sm : eap method context
 **/
static int eap_noob_serv_ctxt_init(struct eap_noob_serv_context * data, struct eap_sm * sm)
{
    char * NAI = NULL;
    int retval = FAILURE;

    if (FAILURE != eap_noob_serv_ctxt_alloc(sm, data)) {
        data->peer_attr->serv_state = UNREG;
        data->peer_attr->peer_state = UNREG;
        data->peer_attr->err_code = NO_ERROR;
        data->peer_attr->rcvd_params = 0;
        data->peer_attr->minslp_count = 0;

        /* Setup DB */
        /* DB file name for the server */
        data->db_name = (char *) os_strdup(DB_NAME);
        /* DB Table name */
        data->db_table_name = (char *) os_strdup(PEER_TABLE);

        if (server_conf.read_conf == 0 &&
            FAILURE == eap_noob_read_config(data)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
            return FAILURE;
        }

        if (sm->identity) {
            NAI = os_zalloc(sm->identity_len+1);
            if (NULL == NAI) {
                EAP_NOOB_SET_ERROR(data->peer_attr, E1001);
                return FAILURE;
            }
            os_memcpy(NAI, sm->identity, sm->identity_len);
            strcat(NAI, "\0");
        }

        if (SUCCESS == (retval = eap_noob_parse_NAI(data, NAI))) {
            EAP_NOOB_FREE(NAI);
            if (!(retval = eap_noob_create_db(data)))
                return retval;

            if (data->peer_attr->err_code == NO_ERROR) {
                data->peer_attr->next_req = eap_noob_get_next_req(data);
            }

            if (data->peer_attr->serv_state == UNREG ||
               data->peer_attr->serv_state == RECONNECT) {

                if (FAILURE == eap_noob_read_config(data)) {
                    wpa_printf(MSG_DEBUG, \
                            "EAP-NOOB: Failed to initialize context");
                    return FAILURE;
                }
            }
        } else {
            printf("ID compare returned false\n");
        }
    }
    EAP_NOOB_FREE(NAI);
    return retval;
}

/**
 * eap_noob_free_ctx : Free up all memory in server context
 * @data: Pointer to EAP-NOOB data
 **/
static void eap_noob_free_ctx(struct eap_noob_serv_context * data)
{
    if (NULL == data)
        return;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    struct eap_noob_peer_data * peer = data->peer_attr;
    struct eap_noob_server_data * serv = data->server_attr;

    if (serv) {
        EAP_NOOB_FREE(serv->serv_info);
        if (serv->serv_config_params) {
            EAP_NOOB_FREE(serv->serv_config_params->Serv_name);
            EAP_NOOB_FREE(serv->serv_config_params->Serv_URL);
            os_free(serv->serv_config_params);
            serv->serv_config_params = NULL;
        }
        os_free(serv); serv = NULL;
    }
    if (peer) {
        EAP_NOOB_FREE(peer->PeerId);
        EAP_NOOB_FREE(peer->peerID_rcvd);
        EAP_NOOB_FREE(peer->peer_info);
        EAP_NOOB_FREE(peer->peer_snum);
        EAP_NOOB_FREE(peer->mac);
        EAP_NOOB_FREE(peer->user_info);
        if (peer->kdf_nonce_data) {
            EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_peer);
            EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_peer_b64);
            EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_serv);
            EAP_NOOB_FREE(peer->kdf_nonce_data->nonce_serv_b64);
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
            EAP_NOOB_FREE(peer->ecdh_exchange_data->y_b64);
            EAP_NOOB_JSON_FREE(peer->ecdh_exchange_data->jwk_serv);
            EAP_NOOB_JSON_FREE(peer->ecdh_exchange_data->jwk_peer);
            os_free(peer->ecdh_exchange_data);
            peer->ecdh_exchange_data = NULL;
        }
        if (peer->oob_data) {
            EAP_NOOB_FREE(peer->oob_data->noob_b64);
            EAP_NOOB_FREE(peer->oob_data->noob);
            EAP_NOOB_FREE(peer->oob_data->hoob_b64);
            EAP_NOOB_FREE(peer->oob_data->hoob);
            EAP_NOOB_FREE(peer->oob_data->hint_b64);
            EAP_NOOB_FREE(peer->oob_data->hint);
            os_free(peer->oob_data); peer->oob_data = NULL;
        }
        if (peer->kdf_out) {
            EAP_NOOB_FREE(peer->kdf_out->msk);
            EAP_NOOB_FREE(peer->kdf_out->msk_b64);
            EAP_NOOB_FREE(peer->kdf_out->emsk);
            EAP_NOOB_FREE(peer->kdf_out->emsk_b64);
            EAP_NOOB_FREE(peer->kdf_out->amsk);
            EAP_NOOB_FREE(peer->kdf_out->amsk_b64);
            EAP_NOOB_FREE(peer->kdf_out->kms);
            EAP_NOOB_FREE(peer->kdf_out->kms_b64);
            EAP_NOOB_FREE(peer->kdf_out->kmp);
            EAP_NOOB_FREE(peer->kdf_out->kmp_b64);
            EAP_NOOB_FREE(peer->kdf_out->kz);
            EAP_NOOB_FREE(peer->kdf_out->kz_b64);
            os_free(peer->kdf_out); peer->kdf_out = NULL;
        }
        os_free(peer); peer = NULL;
    }
    /* TODO  db_name, db_table_name, servDB */
    EAP_NOOB_FREE(data->db_name); EAP_NOOB_FREE(data->db_table_name);
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
    struct eap_noob_serv_context *data = priv;

    eap_noob_free_ctx(data);
}


/**
 * eap_noob_init - Initialize the EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @sm: Pointer to EAP State Machine data
 **/
static void * eap_noob_init(struct eap_sm *sm)
{
    struct eap_noob_serv_context * data = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER");

    if (NULL == (data = os_zalloc( sizeof (struct eap_noob_serv_context)))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER Fail to Allocate Memory");
        return NULL;
    }

    //TODO: check if hard coded initialization can be avoided
    if (FAILURE == eap_noob_serv_ctxt_init(data,sm) && data->peer_attr->err_code == NO_ERROR) {
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
    eap->getTimeout = eap_noob_getTimeout;

    return eap_server_method_register(eap);
}


