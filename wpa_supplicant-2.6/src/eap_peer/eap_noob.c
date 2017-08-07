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

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <signal.h>

#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <jansson.h>
#include "common.h"
#include "eap_i.h"
#include "eap_noob.h"
#include "../../wpa_supplicant/config.h"
#include "../../wpa_supplicant/wpa_supplicant_i.h"
#include "../../wpa_supplicant/blacklist.h"

static struct eap_noob_globle_conf eap_noob_globle_conf = {0};


#if 0
/**
 * eap_noob_sendUpdateSignal : Send user defined signal to auto runscript
   to display the new oob message
 * Returns: SUCCESS/FAILURE
**/
static int eap_noob_sendUpdateSignal()
{

	FILE *fp;
	char pid[10];
	int p = 0;
	fp = popen("pidof /usr/bin/python3 wpa_auto_run.py", "r");
	if (fp == NULL)
		return FAILURE;
	if ( fgets (pid, 10, fp)!=NULL )
	{
		/* writing content to stdout */
		i* writing content to stdout */
		wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",pid);
		p = atoi(pid);
		wpa_printf(MSG_DEBUG, "EAP-NOOB: %d",p);
	}
	pclose(fp);
	if (p) {
		kill(p,SIGUSR1);
		return SUCCESS;
	}
	else{
		wpa_printf(MSG_DEBUG,"EAP-NOOB: Process is not Running Try Later");
		return FAILURE;
	}
}
#endif
/**
 *eap_noob_ECDH_KDF_X9_63: generates KDF
 *@out:
 *@outlen:
 * Z:
 * Zlen:
 * alorithm_id:
 * alorithm_id_len:
 * partyUinfo:
 * partyUinfo_len:
 * partyVinfo:
 * partyVinfo_len
 * suppPrivinfo:
 * suppPrivinfo_len:
 * EVP_MD:
 * Returns:
**/
static int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
        const unsigned char * Z, size_t Zlen,
        const unsigned char * algorithm_id, size_t algorithm_id_len,
        const unsigned char * partyUinfo, size_t partyUinfo_len,
        const unsigned char * partyVinfo, size_t partyVinfo_len,
        const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
        const EVP_MD * md)
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


/**
 * eap_noob_gen_KDF : generates and updates the KDF inside the peer context.
 * @data  : peer context.
 * @state : EAP_NOOB state
 * Returns:
**/
static void eap_noob_gen_KDF(struct eap_noob_peer_context * data, int state)
{

    const EVP_MD * md = EVP_sha256();
    unsigned char * out = os_zalloc(KDF_LEN);
    int counter = 0;

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Algorith ID:", ALGORITHM_ID,ALGORITHM_ID_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce_Peer", data->server_attr->kdf_nonce_data->nonce_peer,
                      EAP_NOOB_NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce_Serv", data->server_attr->kdf_nonce_data->nonce_serv,
                      EAP_NOOB_NONCE_LEN);
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce_Serv", data->server_attr->ecdh_exchange_data->shared_key,
                      EAP_SHARED_SECRET_LEN);
    if (state == COMPLETION_EXCHANGE) {
        wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Noob",data->server_attr->oob_data->noob,EAP_NOOB_NOOB_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->server_attr->ecdh_exchange_data->shared_key, EAP_SHARED_SECRET_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN,
                data->server_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN,
                data->server_attr->oob_data->noob, EAP_NOOB_NOOB_LEN, md);
    } else {

        wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: kz", data->server_attr->kdf_out->Kz,KZ_LEN);
        eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                data->server_attr->kdf_out->Kz, KZ_LEN,
                (unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN,
                data->server_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN,
                NULL, 0, md);
    }
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: KDF",out,KDF_LEN);

    if (out != NULL) {
        data->server_attr->kdf_out->msk = os_zalloc(MSK_LEN);
        data->server_attr->kdf_out->emsk = os_zalloc(EMSK_LEN);
        data->server_attr->kdf_out->amsk = os_zalloc(AMSK_LEN);
        data->server_attr->kdf_out->Kms = os_zalloc(KMS_LEN);
        data->server_attr->kdf_out->Kmp = os_zalloc(KMP_LEN);
        data->server_attr->kdf_out->Kz = os_zalloc(KZ_LEN);

        memcpy(data->server_attr->kdf_out->msk,out,MSK_LEN);
        counter += MSK_LEN;
        memcpy(data->server_attr->kdf_out->emsk, out + counter, EMSK_LEN);
        counter += EMSK_LEN;
        memcpy(data->server_attr->kdf_out->amsk, out + counter, AMSK_LEN);
        counter += AMSK_LEN;
        memcpy(data->server_attr->kdf_out->Kms, out + counter, KMS_LEN);
        counter += KMS_LEN;
        memcpy(data->server_attr->kdf_out->Kmp, out + counter, KMP_LEN);
        counter += KMP_LEN;
        memcpy(data->server_attr->kdf_out->Kz, out + counter, KZ_LEN);
        counter += KZ_LEN;
    } else {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating memory, %s",
                   __func__);
    }
}


/**
 * eap_noob_prepare_peer_info_json : Create a Json object for peer information.
 * @data : peer context.
 * returns : reference to a new object or NULL.
**/
static json_t * eap_noob_prepare_peer_info_json(struct eap_sm * sm, struct eap_noob_peer_config_params * data)
{
    json_t * info_obj = NULL;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
    char bssid[18] = {0};

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (NULL != (info_obj = json_object())) {
        json_object_set_new(info_obj, PEER_MAKE,json_string(data->Peer_name));
        json_object_set_new(info_obj, PEER_TYPE,json_string(eap_noob_globle_conf.peer_type));
        json_object_set_new(info_obj, PEER_SERIAL_NUM,json_string(data->Peer_ID_Num));
        json_object_set_new(info_obj, PEER_SSID,json_string((char *)wpa_s->current_ssid->ssid));
        sprintf(bssid,"%x:%x:%x:%x:%x:%x",wpa_s->current_ssid->bssid[0],wpa_s->current_ssid->bssid[1],
                wpa_s->current_ssid->bssid[2],wpa_s->current_ssid->bssid[3],wpa_s->current_ssid->bssid[4],
                wpa_s->current_ssid->bssid[5]);
        json_object_set_new(info_obj,PEER_BSSID,json_string(bssid));
    }
    return info_obj;
}

/**
 * eap_noob_prepare_vers_arr : prepares a JSON array for Vers
 * @data: peer context
 * return : Json array/NULL
**/
static json_t * eap_noob_prepare_vers_arr(const struct eap_noob_peer_context * data)
{
    json_t * ver_arr = NULL;
    u32 count  = 0;

    if (!data || NULL == (ver_arr = json_array())) {
        return NULL;
    }

    for(count = 0; count < MAX_SUP_VER ; count++) {
        json_array_append_new(ver_arr,json_integer(data->server_attr->version[count]));
    }

    return ver_arr;
}

/**
 * eap_noob_prepare_csuites_arr : prepares a JSON array for Csuites
 * @data: peer context
 * return : Json array/NULL
**/
static json_t * eap_noob_prepare_csuites_arr(const struct eap_noob_peer_context * data)
{
    json_t * csuite_arr = NULL;
    u32 count  = 0;

    if (!data || NULL == (csuite_arr = json_array())) {
        return NULL;
    }

    for(count = 0; count < MAX_SUP_CSUITES ; count++) {
        json_array_append_new(csuite_arr,json_integer(data->server_attr->cryptosuite[count]));
    }

    return csuite_arr;
}

/**
 * eap_noob_prepare_mac_arr : Prepare a JSON array to generate MAC.
 * @data : peer context
 * @type : MAC type
 * state : EAP_NOOB state
 **/
static char * eap_noob_prepare_mac_arr(const struct eap_noob_peer_context * data, int type, int state)
{

    json_t * mac_arr = NULL;
    json_t * ver_arr = NULL;
    json_t * csuite_arr = NULL;
    char * mac_str = NULL;
    json_error_t error;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
    if (NULL != (mac_arr = json_array())) {

        if (type == MACP_TYPE) {
            json_array_append(mac_arr,json_integer(1));
        }

        if (type == MACS_TYPE) {
            json_array_append(mac_arr,json_integer(2));
        }

        if ((ver_arr = eap_noob_prepare_vers_arr(data)) == NULL)
            return NULL;

        json_array_append(mac_arr,ver_arr);
        json_array_append(mac_arr,json_integer(data->peer_attr->version));
        json_array_append(mac_arr,json_string(data->server_attr->peerId));


        if ((csuite_arr = eap_noob_prepare_csuites_arr(data)) == NULL)
            return NULL;

        json_array_append(mac_arr,csuite_arr);

        if (state == COMPLETION_EXCHANGE) {
            json_array_append(mac_arr,json_integer(data->server_attr->dir));

        }else{
            json_array_append(mac_arr,json_string(""));
        }
        json_array_append(mac_arr,json_string(data->server_attr->serv_info));
        json_array_append(mac_arr,json_integer(data->peer_attr->cryptosuite));
        if (state == COMPLETION_EXCHANGE) {
            json_array_append(mac_arr,json_integer(data->peer_attr->dir));
        }else{
            json_array_append(mac_arr,json_string(""));
        }
        if (strcmp(DEFAULT_REALM,data->peer_attr->realm) != 0) {
            json_array_append(mac_arr,json_string(data->peer_attr->realm));
        }
        json_array_append(mac_arr,json_string(data->peer_attr->peer_info));
        if (state == RECONNECT_EXCHANGE) {
            json_array_append(mac_arr,json_string(""));

        }else{
            json_array_append(mac_arr,json_loads(json_dumps(data->server_attr->ecdh_exchange_data->jwk_serv,
                              JSON_COMPACT|JSON_PRESERVE_ORDER), JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
        }
        json_array_append(mac_arr,json_string(data->server_attr->kdf_nonce_data->nonce_serv_b64));
        if (state == RECONNECT_EXCHANGE) {
            json_array_append(mac_arr,json_string(""));

        }else{
            json_array_append(mac_arr,json_loads(json_dumps(data->server_attr->ecdh_exchange_data->jwk_peer,
                            JSON_COMPACT|JSON_PRESERVE_ORDER), JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
        }
        json_array_append(mac_arr,json_string(data->server_attr->kdf_nonce_data->nonce_peer_b64));
        json_array_append(mac_arr,json_string(data->server_attr->oob_data->noob_b64));


        wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
        mac_str = json_dumps(mac_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
    }

    free(ver_arr);
    free(csuite_arr);
    return mac_str;
}

/**
 * eap_noob_gen_MAC : generate a HMAC for user authentication.
 * @data : peer context
 * type  : MAC type
 * @key  : key to generate MAC
 * @keylen: key length
 * Returns : MAC on success or NULL on error.
 **/
static u8 * eap_noob_gen_MAC(const struct eap_noob_peer_context * data,int type, u8 * key, int keylen, int state)
{
    u8 * mac = NULL;
    char * mac_str = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);

    if (NULL != (mac_str = eap_noob_prepare_mac_arr(data, type,state))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: MAC_STR = %s", mac_str);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: LENGTH = %d", (int)strlen(mac_str));
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KEY:",key,keylen);
        mac = HMAC(EVP_sha256(), key, keylen, (u8 *)mac_str, strlen(mac_str), NULL, NULL);
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MAC",mac,32);
        os_free(mac_str);
    }

    return mac;
}

#if 0
/**
 * eap_noob_get_noob : get nonce for OOB message
 * @data : peer context.
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_get_noob(struct eap_noob_peer_context *data) {

    int rc = 0;
    unsigned long err = 0;
    if (NULL == (data->server_attr->oob_data->noob = os_zalloc(EAP_NOOB_NONCE_LEN)))
        return FAILURE;

    if (1 != (rc = RAND_bytes(data->server_attr->oob_data->noob, EAP_NOOB_NONCE_LEN))) {
        err = ERR_get_error();
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);
        return FAILURE;
    }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Noob",data->server_attr->oob_data->noob,16);
    eap_noob_Base64Encode(data->server_attr->oob_data->noob, 16, &data->server_attr->oob_data->noob_b64);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Noob Base64 %s", data->server_attr->oob_data->noob_b64);

    return SUCCESS;
}


/**
 * eap_noob_send_oob : create noob and hood to send an oob message.
 * @data : peer context
 * Returns : SUCCESS/FAILURE
 **/
static int eap_noob_send_oob(struct eap_noob_peer_context *data) {

    unsigned char * hoob_out = os_zalloc(HASH_LEN);

    //char hint[HASH_LEN+8] = {0};
    char * hint_b64 = NULL;

    /*generate NOOB*/
    if (!eap_noob_get_noob(data))
        return FAILURE;

    /*generate HOOB*/
    if (!eap_noob_get_hoob(data,hoob_out, HASH_LEN)) {
        wpa_printf(MSG_DEBUG,"EAP-NOOB: ERROR in HOOB");
    }
    else{
        data->server_attr->oob_data->hoob = hoob_out;
        wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: HOOB",data->server_attr->oob_data->hoob,HASH_LEN);
        eap_noob_Base64Encode(data->server_attr->oob_data->hoob, HASH_LEN, &data->server_attr->oob_data->hoob_b64);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Hoob Base64 %s", data->server_attr->oob_data->hoob_b64);
        data->server_attr->oob_data->hint = os_zalloc(HASH_LEN+8);
        memset(data->server_attr->oob_data->hint,0,HASH_LEN+8);
        eap_noob_prepare_hint(data, (u8 *)data->server_attr->oob_data->hint);
        eap_noob_Base64Encode((u8 *)data->server_attr->oob_data->hint,HASH_LEN+8, &hint_b64);
        data->server_attr->oob_data->hint_b64 = os_strdup(hint_b64);
    }
    return SUCCESS;
}
#endif

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
    int i;

    if (NULL == b64message || NULL == buffer) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return 0;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    len = os_strlen(b64message);

    /* Convert base64url to base64 encoding. */
    int b64pad = 4*((len+3)/4)-len;
    temp = os_zalloc(len + b64pad);
    os_memcpy(temp, b64message, len);
    if (b64pad == 3) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB Input to %s is incorrect", __func__);
            return 0;
    }
    for (i=0; i < len; i++) {
        if (temp[i] == '-')
            temp[i] = '+';
        else if (temp[i] == '_')
            temp[i] = '/';
    }
    for (i=0; i<b64pad; i++)
        temp[len+i] = '=';

    decodeLen = (len * 3)/4;
    *buffer = (unsigned char*)os_zalloc(decodeLen);

    bio = BIO_new_mem_buf(temp, len+b64pad);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    len = BIO_read(bio, *buffer, os_strlen(b64message));

    wpa_printf(MSG_DEBUG, "EAP NOOB: Dumping BIO errors, if any");
    ERR_print_errors_fp(stdout);

    /* Length should equal decodeLen, else something goes horribly wrong */
    if (len != decodeLen) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB Unexpected error decoding message. Decoded len (%d),"
                   " expected (%d), input b64message len (%d)", len, decodeLen, (int)os_strlen(b64message));
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



#if 0
/**
 * eap_noob_prepare_hoob_arr : generate JSON array to calculate Hoob
 * @data: peer context
 * Returns : Json dump of hoob array on success or NULL on failure
**/
static char * eap_noob_prepare_hoob_arr(const struct eap_noob_peer_context * data) {

	json_t * hoob_arr = NULL;
	json_t * ver_arr = NULL;
	char * hoob_str = NULL;
	noob_json_error_t error;
	json_t * csuite_arr = NULL;
	int dir = (data->server_attr->dir & data->peer_attr->dir);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
	if (NULL != (hoob_arr = json_array())) {

		json_array_append(hoob_arr,json_integer(dir));

		if ((ver_arr = eap_noob_prepare_vers_arr(data)) == NULL)
			return NULL;

		json_array_append(hoob_arr,ver_arr);

		json_array_append(hoob_arr,json_integer(data->peer_attr->version));

		json_array_append(hoob_arr,json_string(data->server_attr->peerId));

		if ((csuite_arr = eap_noob_prepare_csuites_arr(data)) == NULL)
			return NULL;

		json_array_append(hoob_arr,csuite_arr);

		json_array_append(hoob_arr,json_integer(data->server_attr->dir));

		json_array_append(hoob_arr,json_string(data->server_attr->serv_info));

		json_array_append(hoob_arr,json_integer(data->peer_attr->cryptosuite));

		json_array_append(hoob_arr,json_integer(data->peer_attr->dir));

		json_array_append(hoob_arr,json_string(data->peer_attr->peer_info));

		json_array_append(hoob_arr,json_loads(json_dumps(data->server_attr->ecdh_exchange_data->jwk_serv,
			JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));

		json_array_append(hoob_arr,json_string(data->server_attr->kdf_nonce_data->nonce_serv_b64));

		json_array_append(hoob_arr,json_loads(json_dumps(data->server_attr->ecdh_exchange_data->jwk_peer,
			JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));

		json_array_append(hoob_arr,json_string(data->server_attr->kdf_nonce_data->nonce_peer_b64));

		json_array_append(hoob_arr,json_string(data->server_attr->oob_data->noob_b64));

		hoob_str = json_dumps(hoob_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
	}

	free(ver_arr);
	free(csuite_arr);
	return hoob_str;
}
#endif
/*
static int eap_noob_prepare_hash(u8 *out, size_t outlen,
	char * hash_string, int hash_str_len)
{
	const EVP_MD *md = EVP_sha256();
	EVP_MD_CTX *mctx = NULL;
	int rv = 0;
	size_t mdlen;


	if (outlen > ECDH_KDF_MAX || hash_str_len > ECDH_KDF_MAX)
		return 0;
	mctx = EVP_MD_CTX_create();
	if (mctx == NULL)
		return 0;
	mdlen = EVP_MD_size(md);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: HASH begin %d",(int)mdlen);

	unsigned char mtmp[EVP_MAX_MD_SIZE];
	EVP_DigestInit_ex(mctx, md, NULL);

	if (!EVP_DigestUpdate(mctx, hash_string, hash_str_len))
		goto err;
	if (!EVP_DigestFinal(mctx, mtmp, NULL))
		goto err;

	memcpy(out, mtmp, outlen);
	OPENSSL_cleanse(mtmp, mdlen);
	rv = 1;
err:
	wpa_printf(MSG_DEBUG,"EAP-NOOB:HASH finished %d",rv);
	EVP_MD_CTX_destroy(mctx);
	return rv;

}
*/
#if 0
/**
 * eap_noob_get_hoob : generate hoob
 * @data : peer context
 * @out  : output array
 * @outlen : output length
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_get_hoob(struct eap_noob_peer_context *data,unsigned char *out, size_t outlen)
{
	char * hoob_string = NULL;
	int hoob_str_len= 0;


	if (NULL != (hoob_string = eap_noob_prepare_hoob_arr(data))) {
		hoob_str_len = os_strlen(hoob_string);

		wpa_printf(MSG_DEBUG, "EAP-NOOB: HOOB string  = %s\n length = %d\n",hoob_string,hoob_str_len);
		wpa_printf(MSG_DEBUG,"EAP-NOOB: HOOB start ");
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-OOB: Value:",hoob_string, hoob_str_len);


		return eap_noob_prepare_hash(out, outlen,hoob_string,hoob_str_len);
	}

	return FAILURE;
}

#endif


static int eap_noob_derive_secret(struct eap_noob_peer_context * data, size_t * secret_len)
{
    EVP_PKEY_CTX * ctx = NULL;
    EVP_PKEY * peerkey = NULL;
    BIO * mem_pub_server = NULL;
    unsigned char * server_pub_key  = NULL;
    size_t skeylen = 0, len = 0;
    int ret = SUCCESS;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering function %s", __func__);
    if (NULL == data || NULL == secret_len) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
        return FAILURE;
    }
    mem_pub_server = BIO_new(BIO_s_mem());
    if (NULL == mem_pub_server) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error allocating memory in BIO");
        return FAILURE;
    }
    EAP_NOOB_FREE(data->server_attr->ecdh_exchange_data->shared_key);
    len = eap_noob_Base64Decode(data->server_attr->ecdh_exchange_data->x_serv_b64, &server_pub_key);
    if (len == 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to decode");
        ret = FAILURE; goto EXIT;
    }

    BIO_write(mem_pub_server, server_pub_key, len);
    if (NULL == d2i_PUBKEY_bio(mem_pub_server, &peerkey)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get peer public key");
        ret = FAILURE; goto EXIT;
    }

    ctx = EVP_PKEY_CTX_new(data->server_attr->ecdh_exchange_data->dh_key, NULL);
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

    data->server_attr->ecdh_exchange_data->shared_key  = OPENSSL_malloc(skeylen);

    if (!data->server_attr->ecdh_exchange_data->shared_key) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to allocate memory for secret");
        ret = FAILURE; goto EXIT;
    }

    if (EVP_PKEY_derive(ctx, data->server_attr->ecdh_exchange_data->shared_key, &skeylen) <= 0) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to derive secret key");
        ret = FAILURE; goto EXIT;
    }

    (*secret_len) = skeylen;

    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",
            data->server_attr->ecdh_exchange_data->shared_key, *secret_len);

EXIT:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    EAP_NOOB_FREE(server_pub_key);

    if (NULL != mem_pub_server)
        BIO_free_all(mem_pub_server);

    if (ret != SUCCESS)
        EAP_NOOB_FREE(data->server_attr->ecdh_exchange_data->shared_key);

    return ret;
}

#if 0
/**
 * eap_noob_derive_secret : Generates secret using public keys ogf both the entities
 * @data : peer context
 * @secret_len : Secret length
 * returns FAILURE/SUCCESS
**/
static int eap_noob_derive_secret(struct eap_noob_peer_context *data, size_t *secret_len)
{

	EC_KEY *ec_pub_server; // public key of peer
	EC_POINT *ecpoint_pub_server; // public key points of peer
	const EC_GROUP *ec_group; // group
	EVP_PKEY *evp_server = NULL ;

	EVP_PKEY_CTX *ctx;//context for derivation
	EVP_PKEY_CTX *pctx;//context for peer key

	unsigned char * x;
	unsigned char * y;
	size_t x_len;
	size_t y_len;
	size_t len;
	BIGNUM * x_big;
	BIGNUM * y_big;
	x_len = eap_noob_Base64Decode(data->server_attr->ecdh_exchange_data->x_serv_b64, &x, &len);
	y_len = eap_noob_Base64Decode(data->server_attr->ecdh_exchange_data->y_serv_b64, &y, &len);


	wpa_printf(MSG_DEBUG, "EAP-NOOB: deriving NID_secp256k1.");
	ec_pub_server = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (ec_pub_server == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create EC_KEYs");
		return 1;
	}

	/* Get the group used */
	ec_group = EC_KEY_get0_group(ec_pub_server);
	if (ec_group == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get GROUP");
		return 1;
	}


	x_big = BN_bin2bn(x,x_len,NULL);
	y_big = BN_bin2bn(y,y_len,NULL);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_POINT_bn2point");
	ecpoint_pub_server = EC_POINT_new(ec_group);
	if (EC_POINT_set_affine_coordinates_GFp(ec_group, ecpoint_pub_server, x_big, y_big,NULL) ==0)
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in affine coordinate setting");


	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key");

	if (!EC_KEY_set_public_key(ec_pub_server, ecpoint_pub_server)) {
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
	if (!EVP_PKEY_paramgen(pctx, &evp_server)) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create parameter object params.");
		return 1;
	}
	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key done");


	if (!EVP_PKEY_set1_EC_KEY(evp_server, ec_pub_server)) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to CONVERT EC_KEY to EVP_PKEY.");
		return 1;
	}
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret!.");


	/* Derive the secret */
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 1.");

	/* Create the context for the shared secret derivation */
	if (NULL == (ctx = EVP_PKEY_CTX_new(data->server_attr->ecdh_exchange_data->dh_key, NULL))) {
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
	/* Provide the server public key */
	if (1 != EVP_PKEY_derive_set_peer(ctx, evp_server)) {
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
	if (NULL == (data->server_attr->ecdh_exchange_data->shared_key = OPENSSL_malloc(*secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to create buffer OPENSSL_malloc.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 6.");

	/* Derive the shared secret */
	if (1 != (EVP_PKEY_derive(ctx, data->server_attr->ecdh_exchange_data->shared_key, secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to derive key EVP_PKEY_derive.");
		return 1;
	}
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",data->server_attr->ecdh_exchange_data->shared_key,*secret_len);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(evp_server);

	return 0;
}
#endif

static int eap_noob_get_key(struct eap_noob_server_data * data)
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
    EVP_PKEY_keygen(pctx, &data->ecdh_exchange_data->dh_key);
    PEM_write_PrivateKey(stdout, data->ecdh_exchange_data->dh_key,
                         NULL, NULL, 0, NULL, NULL);
    PEM_write_PUBKEY(stdout, data->ecdh_exchange_data->dh_key);

    /* Get public key */
    if (1 != i2d_PUBKEY_bio(mem_pub, data->ecdh_exchange_data->dh_key)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to copy public key to bio.");
        ret = FAILURE; goto EXIT;
    }

    pub_key_char = os_zalloc(MAX_X25519_LEN);
    pub_key_len = BIO_read(mem_pub, pub_key_char, MAX_X25519_LEN);

    EAP_NOOB_FREE(data->ecdh_exchange_data->x_b64);
    eap_noob_Base64Encode(pub_key_char, pub_key_len, &data->ecdh_exchange_data->x_b64);

EXIT:
    if (pctx)
        EVP_PKEY_CTX_free(pctx);
    EAP_NOOB_FREE(pub_key_char);
    BIO_free_all(mem_pub);
    return ret;
}

#if 0
/**
 * get_key - Generate Priv/Pub key pair based on the Csuite selected.
 * @data: Pointer to EAP-NOOB data
 * Returns: 1 if keys generated and stored successfully, or 0 if not
 **/
static int eap_noob_get_key(struct eap_noob_server_data *data)
{

	const EC_POINT *pub;
	const EC_GROUP *group;

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	size_t x_len;
	size_t y_len;
	unsigned char * x_val;
	unsigned char * y_val;

	/* Set up EC_KEY object and associated with the curve according to the specifier */


	wpa_printf(MSG_DEBUG, "EAP-NOOB: secp256k1 cryptosuite selected.");

	EVP_PKEY_CTX *pctx, *kctx;
	EVP_PKEY *params = NULL;
	EC_KEY * key;

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
	if (1 != EVP_PKEY_keygen(kctx, &data->ecdh_exchange_data->dh_key)) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to generate keys.");
		return 0;
	}

	key = EVP_PKEY_get1_EC_KEY(data->ecdh_exchange_data->dh_key);

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
	if (EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, NULL) != 1)
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

	eap_noob_Base64Encode(x_val,x_len, &data->ecdh_exchange_data->x_b64);
	eap_noob_Base64Encode(y_val,y_len, &data->ecdh_exchange_data->y_b64);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: X and Y %s,%s",data->ecdh_exchange_data->x_b64, data->ecdh_exchange_data->y_b64);

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", x_val, x_len);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Y coordinate", y_val, y_len);

	return 1;
}
#endif

/**
 * eap_noob_verify_param_len : verify lengths of string type parameters
 * @data : peer context
**/
static void eap_noob_verify_param_len(struct eap_noob_server_data * data)
{
    u32 count  = 0;
    u32 pos = 0x01;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return ;
    }

    for(count  = 0; count < 32; count++) {

        if (data->rcvd_params & pos) {
            switch(pos) {

                case PEERID_RCVD:
                    if (strlen(data->peerId) > MAX_PEER_ID_LEN) {
                        data->err_code = E1003;
                    }
                    break;
                case NONCE_RCVD:
                    if (strlen((char *)data->kdf_nonce_data->nonce_serv) > EAP_NOOB_NONCE_LEN) {
                        data->err_code = E1003;
                    }
                    break;
                case MAC_RCVD:
                    if (strlen(data->MAC) > MAC_LEN) {
                        data->err_code = E1003;
                    }
                    break;
                case INFO_RCVD:
                    if (strlen(data->serv_info) > MAX_INFO_LEN) {
                        data->err_code = E5002;
                    }
                    break;
            }
        }
        pos = pos<<1;
    }
}


/**
 * eap_noob_decode_obj : Decode parameters from incoming messages
 * @data : peer context
 * @req_obj : incoming json object with message parameters
**/
static void  eap_noob_decode_obj(struct eap_noob_server_data * data, json_t * req_obj)
{
    const char * key = NULL;
    char * retval_char = NULL, * dump_str = NULL;
    size_t arr_index, decode_length;
    json_t * arr_value, * value;
    json_error_t  error;
    int retval_int = 0;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s", __func__);
        return;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

    json_object_foreach(req_obj, key, value) {
        switch(json_typeof(value)) {
            case JSON_OBJECT:
                if (0 == strcmp(key, PKS)) {
                    dump_str = json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER);
                    data->ecdh_exchange_data->jwk_serv = json_loads(dump_str, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB:Copy Verify %s", dump_str);
                    os_free(dump_str);

                    if (NULL == data->ecdh_exchange_data->jwk_serv) {
                        data->err_code = E1003;
                        return;
                    }
                    data->rcvd_params |= PKEY_RCVD;
                } else if (0 == strcmp(key, SERVERINFO)) {
                    data->serv_info = json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER);
                    if (NULL == data->serv_info) {
                        data->err_code = E5002;
                        return;
                    }
                    data->rcvd_params |= INFO_RCVD;
                    wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv Info %s",data->serv_info);
                }
                eap_noob_decode_obj(data,value);
                break;

            case JSON_INTEGER:
                if ((0 == (retval_int = json_integer_value(value))) && (0 != strcmp(key, TYPE)) &&
                    (0 != strcmp(key, SLEEPTIME))) {
                    data->err_code = E1003;
                    return;
                } else if (0 == strcmp(key, DIRS)) {
                    data->dir = retval_int;
                    data->rcvd_params |= DIRS_RCVD;
                } else if (0 == strcmp(key, SLEEPTIME)) {
                    data->minsleep = retval_int;
                    //data->rcvd_params |= MINSLP_RCVD;
                } else if (0 == strcmp(key, ERRORCODE)) {
                    data->err_code = retval_int;
                }
                break;

            case JSON_STRING:
                if (NULL == (retval_char = (char *)json_string_value(value))) {
                    data->err_code = E1003;
                    return;
                }
                if (0 == strcmp(key, PEERID)) {
                    data->peerId = os_strdup(retval_char);
                    data->rcvd_params |= PEERID_RCVD;

                }
                if (0 == strcmp(key, REALM)) {
                    EAP_NOOB_FREE(data->realm);
                    data->realm = os_strdup(retval_char);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB:Realm %s",data->realm);
                } else if (0 == strcmp(key, NS)) {
                    data->kdf_nonce_data->nonce_serv_b64 = os_strdup(retval_char);
                    decode_length = eap_noob_Base64Decode(data->kdf_nonce_data->nonce_serv_b64,
                                          &data->kdf_nonce_data->nonce_serv);
                    data->rcvd_params |= NONCE_RCVD;
                } else if (0 == strcmp(key, HINT_SERV)) {
                    EAP_NOOB_FREE(data->oob_data->hint_b64);
                    EAP_NOOB_FREE(data->oob_data->hint);

                    data->oob_data->hint_b64 = os_strdup(retval_char);
                    data->oob_data->hint_len = eap_noob_Base64Decode(data->oob_data->hint_b64, &data->oob_data->hint);
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Received hint = %s", data->oob_data->hint_b64);
                    data->rcvd_params |= HINT_RCVD;
                } else if (0 == strcmp(key, MACS)) {
                    decode_length = eap_noob_Base64Decode((char *)retval_char, (u8**)&data->MAC);
                    data->rcvd_params |= MAC_RCVD;
                } else if (0 == strcmp(key, X_COORDINATE)) {
                    data->ecdh_exchange_data->x_serv_b64 = os_strdup(json_string_value(value));
                    wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->x_serv_b64);
                } else if (0 == strcmp(key, Y_COORDINATE)) {
                    data->ecdh_exchange_data->y_serv_b64 = os_strdup(json_string_value(value));
                    wpa_printf(MSG_DEBUG, "Y coordinate %s", data->ecdh_exchange_data->y_serv_b64);
                }
                break;

            case JSON_ARRAY:
                if (0 == strcmp(key, VERS)) {
                    json_array_foreach(value, arr_index, arr_value) {
                        if (json_is_integer(arr_value)) {
                            data->version[arr_index] = json_integer_value(arr_value);
                            wpa_printf(MSG_DEBUG, "EAP-NOOB: Version array value = %d", data->version[arr_index]);
                        } else {
                            data->err_code = E1003;
                            return;
                        }
                    }
                    data->rcvd_params |= VERSION_RCVD;
                } else if (0 == strcmp(key,CRYPTOSUITES)) {
                    json_array_foreach(value, arr_index, arr_value) {
                        if (json_is_integer(arr_value)) {
                            data->cryptosuite[arr_index] = json_integer_value(arr_value);
                            wpa_printf(MSG_DEBUG, "EAP-NOOB: Cryptosuites array value = %d", data->version[arr_index]);
                        } else {
                            data->err_code = E1003;
                            return;
                        }
                    }
                    data->rcvd_params |= CRYPTOSUITES_RCVD;
                }
                break;

            case JSON_REAL:
            case JSON_TRUE:
            case JSON_FALSE:
            case JSON_NULL:
                break;
        }
    }
    eap_noob_verify_param_len(data);
}


/**
 * eap_noob_assign_waittime : assign time fow which the SSID should be disabled.
 * @sm : eap state machine context
 * data: peer context
**/
static void eap_noob_assign_waittime(struct eap_sm *sm,struct eap_noob_peer_context *data)
{
    struct timespec tv;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB ASSIGN WAIT TIME");
    clock_gettime(CLOCK_BOOTTIME, &tv);

    if (0 == data->server_attr->minsleep && 0 != eap_noob_globle_conf.default_minsleep)
        data->server_attr->minsleep = eap_noob_globle_conf.default_minsleep;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Wait time  = %d", data->server_attr->minsleep);

    if (0 == strcmp(wpa_s->driver->name,"wired")) {
        sm->disabled_wired = tv.tv_sec + data->server_attr->minsleep;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: disabled untill = %ld", sm->disabled_wired);
        data->wired = 1;
        return;
    }

    sm->disabled_wired = 0;
    wpa_s->current_ssid->disabled_until.sec = tv.tv_sec + data->server_attr->minsleep;
    wpa_blacklist_add(wpa_s, wpa_s->current_ssid->bssid);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: SSID %s, time now : %ld  disabled untill = %ld", wpa_s->current_ssid->ssid, tv.tv_sec,
               wpa_s->current_ssid->disabled_until.sec);

}

/**
 * eap_noob_check_compatibility : check peer's compatibility with server.
 * The type 1 message params are used for making any dicision
 * @data : peer context
 * Returns : SUCCESS/FAILURE
 **/
int eap_noob_check_compatibility(struct eap_noob_peer_context *data)
{
    u32 count = 0;
    u8 vers_supported = 0;
    u8 csuite_supp = 0;

    if (0 == (data->peer_attr->dir & data->server_attr->dir)) {
        data->server_attr->err_code = E3003;
        return FAILURE;
    }

    for(count = 0; count < MAX_SUP_CSUITES ; count ++) {
        if (0 != (data->peer_attr->cryptosuite & data->server_attr->cryptosuite[count])) {
            csuite_supp = 1; break;
        }
    }

    if (csuite_supp == 0) {
        data->server_attr->err_code = E3002;
        return FAILURE;
    }

    for(count = 0; count < MAX_SUP_VER ; count ++) {
        if (0 != (data->peer_attr->version & data->server_attr->version[count])) {
            vers_supported = 1; break;
        }
    }

    if (vers_supported == 0) {
        data->server_attr->err_code = E3001;
        return FAILURE;
    }
    return SUCCESS;
}

/**
 * eap_noob_config_change : write back the content of identity into .conf file
 * @data : peer context
 * @sm : eap state machine context.
**/
static void eap_noob_config_change(struct eap_sm *sm , struct eap_noob_peer_context *data)
{
    char buff[120] = {0};
    size_t len = 0;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *)sm->msg_ctx;

    if (wpa_s) {
        snprintf(buff,120,"%s+s%d@%s", data->peer_attr->peerId, data->server_attr->state, data->peer_attr->realm);
        len = os_strlen(buff);

        os_free(wpa_s->current_ssid->eap.identity);
        wpa_s->current_ssid->eap.identity = os_malloc(os_strlen(buff));

        os_memcpy(wpa_s->current_ssid->eap.identity, buff, len);
        wpa_s->current_ssid->eap.identity_len = len;

        wpa_config_write(wpa_s->confname,wpa_s->conf);
    }
}

#if 0
int eap_noob_ascii_check(char * str, int len)
{
	int count = 0;

	for(;count <len; count++) {
		if (1 == (str[count] & 0x08))
		return FAILURE;
	}

	return SUCCESS;
}

#endif
/**
 * eap_noob_db_entry_check : check for an peerId entry inside the DB
 * @priv : server context
 * @argc : argument count
 * @argv : argument 2d array
 * @azColName : colomn name 2d array
**/
int eap_noob_db_entry_check(void * priv , int argc, char **argv, char **azColName)
{
    struct eap_noob_server_data * data = priv;

    if (strtol(argv[0],NULL,10) == 1) {
        data->record_present = TRUE;
    }

    return 0;
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
 * eap_noob_decode_csuites_array : assigns the values of Csuites JSON array to csuite array
 * @data: Server context
 * @array: Csuites JSON array
 * Returns: SUCCESS/FAILURE
**/
static int eap_noob_decode_csuites_array(char * array, struct eap_noob_server_data * data)
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
 * @priv : server context
 * @argc : argument count
 * @argv : argument 2d array
 * @azColName : colomn name 2d arra
**/
int eap_noob_callback(void * priv , int argc, char **argv, char **azColName)
{
    struct eap_noob_peer_context * peer = priv;
    struct eap_noob_server_data * data = peer->server_attr;
    int count  = 0;
    size_t len;
    json_error_t error;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB CALLBACK");

    for (count =0; count <argc; count++) {
        if (argv[count] && azColName[count]) {
            if (os_strcmp(azColName[count], "ssid") == 0) {
                if (NULL != data->ssid)
                    os_free(data->ssid);
                data->ssid = os_malloc(os_strlen(argv[count])+1);
                strcpy(data->ssid, argv[count]);
            }
            else if (os_strcmp(azColName[count], "PeerID") == 0) {
                if (NULL != data->peerId)
                    os_free(data->peerId);

                data->peerId = os_malloc(os_strlen(argv[count]));
                strcpy(data->peerId, argv[count]);
            }
            else if (os_strcmp(azColName[count], "Vers") == 0) {
                //data->version[0] = (int) strtol(argv[count], NULL, 10);
                eap_noob_decode_vers_array(argv[count], data);
            }
            else if (os_strcmp(azColName[count], "Verp") == 0) {
                peer->peer_attr->version = (int) strtol(argv[count], NULL, 10);
            }
            else if (os_strcmp(azColName[count], "state") == 0) {
                data->state = (int) strtol(argv[count], NULL, 10);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: ****************state = %d\n",data->state);
            }
            else if (os_strcmp(azColName[count], "Csuites") == 0) {
                //data->cryptosuite[0] = (int) strtol(argv[count], NULL, 10);
                eap_noob_decode_csuites_array(argv[count], data);
            }
            else if (os_strcmp(azColName[count], "Csuitep") == 0) {
                peer->peer_attr->cryptosuite = (int) strtol(argv[count], NULL, 10);
            }
            else if (os_strcmp(azColName[count], "Dirs") == 0) {
                data->dir = (int) strtol(argv[count], NULL, 10);
            }
            else if (os_strcmp(azColName[count], "Dirp") == 0) {
                peer->peer_attr->dir = (int) strtol(argv[count], NULL, 10);
            }
            else if (os_strcmp(azColName[count], "Np") == 0) {
                if (NULL != data->kdf_nonce_data->nonce_peer_b64)
                    os_free(data->kdf_nonce_data->nonce_peer_b64);

                data->kdf_nonce_data->nonce_peer_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->kdf_nonce_data->nonce_peer_b64, argv[count]);

                len = eap_noob_Base64Decode(data->kdf_nonce_data->nonce_peer_b64, &data->kdf_nonce_data->nonce_peer); //To-Do check for length

            }
            else if (os_strcmp(azColName[count], "Ns") == 0) {
                if (NULL != data->kdf_nonce_data->nonce_serv_b64)
                    os_free(data->kdf_nonce_data->nonce_serv_b64);

                data->kdf_nonce_data->nonce_serv_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->kdf_nonce_data->nonce_serv_b64, argv[count]);

                len = eap_noob_Base64Decode(data->kdf_nonce_data->nonce_serv_b64, &data->kdf_nonce_data->nonce_serv); //To-Do check for length

            }
            else if (os_strcmp(azColName[count], "minsleep") == 0) {
                data->minsleep = (int) strtol(argv[count], NULL, 10);
            }
            else if (os_strcmp(azColName[count], "ServInfo") == 0) {
                if (NULL != data->serv_info)
                    os_free(data->serv_info);

                data->serv_info = os_malloc(os_strlen(argv[count]));
                strcpy(data->serv_info, argv[count]);
            }
            else if (os_strcmp(azColName[count], "PeerInfo") == 0) {
                if (NULL != peer->peer_attr->peer_info)
                    os_free(peer->peer_attr->peer_info);

                peer->peer_attr->peer_info = os_malloc(os_strlen(argv[count]));
                strcpy(peer->peer_attr->peer_info, argv[count]);
            }
            else if (os_strcmp(azColName[count], "Realm") == 0) {
                if (NULL != data->realm)
                    os_free(data->realm);
                if (NULL != peer->peer_attr->realm)
                    os_free(peer->peer_attr->realm);

                data->realm = os_malloc(os_strlen(argv[count]));
                strcpy(data->realm, argv[count]);

                peer->peer_attr->realm = os_malloc(os_strlen(argv[count]));
                strcpy(peer->peer_attr->realm, argv[count]);

                len = eap_noob_Base64Decode(data->kdf_nonce_data->nonce_peer_b64, &data->kdf_nonce_data->nonce_peer); //To-Do check for length

            }
            else if (os_strcmp(azColName[count], "SharedSecret") == 0 && os_strlen(argv[count]) > 0) {
                if (NULL != data->ecdh_exchange_data->shared_key_b64)
                    os_free(data->ecdh_exchange_data->shared_key_b64);

                data->ecdh_exchange_data->shared_key_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->ecdh_exchange_data->shared_key_b64, argv[count]);
                len = eap_noob_Base64Decode(data->ecdh_exchange_data->shared_key_b64, &data->ecdh_exchange_data->shared_key);
            }
            else if (os_strcmp(azColName[count], "Noob") == 0 && os_strlen(argv[count]) > 0) {
                if (NULL != data->oob_data->noob_b64)
                    os_free(data->oob_data->noob_b64);

                data->oob_data->noob_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->oob_data->noob_b64, argv[count]);

                len = eap_noob_Base64Decode(data->oob_data->noob_b64, &data->oob_data->noob);
            }
            else if (os_strcmp(azColName[count], "hint_server") == 0 && os_strlen(argv[count]) > 0) {
                if (NULL != data->oob_data->hint_b64)
                    os_free(data->oob_data->hint_b64);

                data->oob_data->hint_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->oob_data->hint_b64, argv[count]);

                eap_noob_Base64Decode(data->oob_data->hint_b64, &data->oob_data->hint);
            }

            else if (os_strcmp(azColName[count], "Hoob") == 0 && os_strlen(argv[count]) > 0) {
                if (NULL != data->oob_data->hoob_b64)
                    os_free(data->oob_data->hoob_b64);

                data->oob_data->hoob_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->oob_data->hoob_b64, argv[count]);
                wpa_printf(MSG_DEBUG,"EAP-NOOB: HOOB: %s",argv[count]);

                len = eap_noob_Base64Decode(data->oob_data->hoob_b64, &data->oob_data->hoob);
            }else if (os_strcmp(azColName[count], "pub_key_serv") == 0) {
                data->ecdh_exchange_data->jwk_serv = json_loads(argv[count], JSON_COMPACT|JSON_PRESERVE_ORDER, &error); //ToDo: check and free this before assigning if required

                wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv_KEY: %s",argv[count]);

            }else if (os_strcmp(azColName[count], "pub_key_peer") == 0) {
                data->ecdh_exchange_data->jwk_peer = json_loads(argv[count], JSON_COMPACT|JSON_PRESERVE_ORDER, &error); //ToDo: check and free this before assigning if required
                wpa_printf(MSG_DEBUG,"EAP-NOOB:Peer_KEY: %s",argv[count]);
            }
            else if (os_strcmp(azColName[count], "kms") == 0 && os_strlen(argv[count]) > 0) {
                if (NULL != data->kdf_out->kms_b64)
                    os_free(data->kdf_out->kms_b64);

                data->kdf_out->kms_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->kdf_out->kms_b64, argv[count]);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kms");
                len = eap_noob_Base64Decode(data->kdf_out->kms_b64, &data->kdf_out->Kms);
            }
            else if (os_strcmp(azColName[count], "kmp") == 0 && os_strlen(argv[count]) > 0) {
                if (NULL != data->kdf_out->kmp_b64)
                    os_free(data->kdf_out->kmp_b64);

                data->kdf_out->kmp_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->kdf_out->kmp_b64, argv[count]);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kmp");
                len = eap_noob_Base64Decode(data->kdf_out->kmp_b64, &data->kdf_out->Kmp);
            }
            else if (os_strcmp(azColName[count], "kz") == 0 && os_strlen(argv[count]) > 0) {
                if (NULL != data->kdf_out->kz_b64)
                    os_free(data->kdf_out->kz_b64);

                data->kdf_out->kz_b64 = os_malloc(os_strlen(argv[count]));
                strcpy(data->kdf_out->kz_b64, argv[count]);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kz");
                len = eap_noob_Base64Decode(data->kdf_out->kz_b64, &data->kdf_out->Kz);
            }
        }
    }

    return 0;
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
static int eap_noob_exec_query(struct eap_noob_peer_context * data, const char * query,
                               int (*callback)(void *, int, char **, char **),
                               int num_args, ...)
{
    sqlite3_stmt * stmt = NULL;
    va_list args;
    int ret, i, indx = 0, ival, bval_len;
    char * sval = NULL;
    u8 * bval = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s, query - (%s), Number of arguments (%d)", __func__, query, num_args);

    if (SQLITE_OK != (ret = sqlite3_prepare_v2(data->peer_db, query, strlen(query)+1, &stmt, NULL))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error preparing statement, ret (%d)", ret);
        return FAILURE;
    }

    va_start(args, num_args);
    for (i = 0; i < num_args; i+=2, ++indx) {
        enum sql_datatypes type = va_arg(args, enum sql_datatypes);
        switch(type) {
            case INT:
                ival = va_arg(args, int);
                if (SQLITE_OK != sqlite3_bind_int(stmt, (indx+1), ival)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %d at index %d", ival, indx+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case UNSIGNED_BIG_INT:
                break;
            case TEXT:
                sval = va_arg(args, char *);
                if (SQLITE_OK != sqlite3_bind_text(stmt, (indx+1), sval, strlen(sval), NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB:Error binding %s at index %d", sval, indx+1);
                    ret = FAILURE; goto EXIT;
                }
                break;
            case BLOB:
                bval_len = va_arg(args, int);
                bval = va_arg(args, u8 *);
                if (SQLITE_OK != sqlite3_bind_blob(stmt, (indx+1), bval, bval_len, NULL)) {
                    wpa_printf(MSG_DEBUG, "EAP-NOOB: Error binding %.*s at index %d", bval_len, bval, indx+1);
                    ret = FAILURE; goto EXIT;
                } i++;
                break;
            default:
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Wrong data type");
                ret = FAILURE; goto EXIT;
        }
    }
#define MAX_FIELDS 32

    int fieldCount = sqlite3_column_count(stmt);
    while(1) {
        ret = sqlite3_step(stmt);
        if (ret != SQLITE_DONE && ret != SQLITE_ROW) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in step, ret (%d)", ret);
            ret = FAILURE; goto EXIT;
        }

        if (ret == SQLITE_DONE) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Done executing the query, ret (%d)\n", ret);
            ret = SUCCESS; break;
        }

        if (NULL == callback)
            continue;

        char * fieldNames[MAX_FIELDS];
        char * fieldVals[MAX_FIELDS];
        /* char * fieldTypes[MAX_FIELDS]; */
        for (i = 0; i < fieldCount; ++i) {
            fieldNames[i] = (char *)sqlite3_column_name(stmt, i);
            fieldVals[i] = (char *)sqlite3_column_text(stmt, i);
            /* fieldTypes[i] = (char *)sqlite3_column_decltype(stmt, i); */
        }

        if (SUCCESS != callback(data, fieldCount, fieldVals, fieldNames)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unexpected error in DB callback. Exiting query");
            ret = FAILURE; break;
        }
    }

EXIT:
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s, ret %d", __func__, ret);
    va_end(args);
    sqlite3_finalize(stmt);
    return ret;
}

/**
 * eap_noob_db_update : prepare a DB update query
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_db_update (struct eap_noob_peer_context * data, u8 type)
{
    char * query = os_zalloc(MAX_QUERY_LEN);
    int ret = FAILURE;

    switch(type) {
        case UPDATE_STATE:
            snprintf(query, MAX_QUERY_LEN, "UPDATE '%s' SET state=? where PeerID=?", data->db_table_name);
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->server_attr->state, TEXT, data->server_attr->peerId);
            break;
        case UPDATE_PERSISTENT_KEYS_SECRET:
            snprintf(query, MAX_QUERY_LEN, "UPDATE '%s' SET Kms=?, Kmp=?, Kz=?, state=? where PeerID=?", data->db_table_name);
            ret = eap_noob_exec_query(data, query, NULL, 10, TEXT, data->server_attr->kdf_out->kms_b64, TEXT,
                    data->server_attr->kdf_out->kmp_b64, TEXT, data->server_attr->kdf_out->kz_b64, INT,
                    data->server_attr->state, TEXT, data->server_attr->peerId);
            break;
        case UPDATE_OOB:
            snprintf(query,MAX_QUERY_LEN,"UPDATE '%s' SET gen_OOB=? where PeerID=?", data->db_table_name);
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, 1, TEXT, data->server_attr->peerId);
            break;
        case UPDATE_STATE_ERROR:
            snprintf(query, MAX_QUERY_LEN, "UPDATE '%s' SET err_code=? where PeerID=?", data->db_table_name);
            ret = eap_noob_exec_query(data, query, NULL, 4, INT, data->server_attr->err_code, TEXT, data->server_attr->peerId);
            break;

        case DELETE_EXPIRED_NOOB:
            snprintf(query, MAX_QUERY_LEN, "DELETE FROM oobs where expired=?");
            ret = eap_noob_exec_query(data, query, NULL, 2, INT, 1);
            break;
        case DELETE_SSID:
            snprintf(query, MAX_QUERY_LEN, "DELETE FROM %s where PeerID=?", data->db_table_name);
            ret = eap_noob_exec_query(data, query, NULL, 2, TEXT, data->server_attr->peerId);
            break;

        default:
            wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
            return FAILURE;
    }
    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB update failed");
    }

    os_free(query);
    return ret;
}

/**
 * eap_noob_db_entry : Make an entery of the current SSID context inside the DB
 * @sm : eap statemachine context
 * @data : peer context
 * Returns : FAILURE/SUCCESS
**/
static int eap_noob_db_entry(struct eap_sm * sm, struct eap_noob_peer_context * data)
{
    struct wpa_supplicant * wpa_s = NULL;
    char query[MAX_QUERY_LEN] = {0};
    json_t * vers_arr = NULL, * csuites_arr = NULL;
    int ret = 0;
    char * dump_str1, * dump_str2, * dump_str3, * dump_str4;

    if (NULL == data || NULL == sm) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
    wpa_s = (struct wpa_supplicant *)sm->msg_ctx;

    if (NULL == (vers_arr = eap_noob_prepare_vers_arr(data)))
        return FAILURE;

    if (NULL == (csuites_arr = eap_noob_prepare_csuites_arr(data))) {
        json_decref(vers_arr);
        return FAILURE;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Ver = %s\tcsuite = %s\t", json_dumps(vers_arr,JSON_COMPACT),
                json_dumps(csuites_arr,JSON_COMPACT));
    dump_str1 = json_dumps(vers_arr,JSON_COMPACT);
    dump_str2 = json_dumps(csuites_arr,JSON_COMPACT);
    dump_str3 = json_dumps(data->server_attr->ecdh_exchange_data->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER);
    dump_str4 = json_dumps(data->server_attr->ecdh_exchange_data->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER);
    snprintf(query,MAX_QUERY_LEN,"INSERT INTO %s (ssid, PeerID, Vers, Verp, state, Csuites, Csuitep, Dirs, Dirp, "
            "Np, Ns, minsleep, ServInfo, PeerInfo,SharedSecret, Noob, Hoob, OOB_RECEIVED_FLAG, "
            "pub_key_serv, pub_key_peer, err_code, Realm) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", data->db_table_name);
    ret = eap_noob_exec_query(data, query, NULL, 46, TEXT, wpa_s->current_ssid->ssid, TEXT, data->server_attr->peerId,
            TEXT,  dump_str1, INT, data->peer_attr->version, INT, data->server_attr->state,
            TEXT, dump_str2 , INT, data->peer_attr->cryptosuite, INT, data->server_attr->dir,
            INT, data->peer_attr->dir, BLOB, EAP_NOOB_NONCE_LEN, data->server_attr->kdf_nonce_data->nonce_peer_b64, BLOB,
            EAP_NOOB_NONCE_LEN, data->server_attr->kdf_nonce_data->nonce_serv_b64, INT, data->server_attr->minsleep, TEXT,
            data->server_attr->serv_info, TEXT, data->peer_attr->peer_info, TEXT,
            data->server_attr->ecdh_exchange_data->shared_key_b64, TEXT, "", TEXT, "", INT, 0, TEXT,
            dump_str3, TEXT, dump_str4? dump_str4:"", INT, data->server_attr->err_code, TEXT, data->peer_attr->realm);

    if (FAILURE == ret) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
    os_free(dump_str1); os_free(dump_str2); os_free(dump_str3); os_free(dump_str4);
    json_decref(vers_arr); json_decref(csuites_arr);
    return ret;
}

/**
 * eap_noob_err_msg : prepares error message
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_peer_context * data, u8 id)
{
    json_t * req_obj = NULL;
    struct wpabuf *req = NULL;
    char * req_json = NULL;
    size_t len = 0 ;
    int code = 0;

    if (NULL == data || NULL == data->peer_attr || 0 == (code = data->server_attr->err_code)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return NULL;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error request");

    if (NULL == (req_obj = json_object()))
        goto EXIT;

    if (data->peer_attr->peerId) {
        json_object_set_new(req_obj,PEERID,json_string(data->peer_attr->peerId));
    }
    json_object_set_new(req_obj, TYPE, json_integer(NONE));
    json_object_set_new(req_obj, ERRORCODE, json_integer(error_code[code]));
    json_object_set_new(req_obj, ERRORINFO, json_string(error_info[code]));

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

    wpabuf_put_data(req, req_json, len);
    data->server_attr->err_code = NO_ERROR;
EXIT:
    json_decref(req_obj);
    EAP_NOOB_FREE(req_json);
    return req;
}

/**
 * eap_noob_verify_peerId : compares recived PeerID with the assigned one
 * @data : peer context
 * @id : response message ID
**/
static struct wpabuf * eap_noob_verify_peerId(struct eap_noob_peer_context * data, u8  id)
{
    struct wpabuf * resp = NULL;

    if ((data->server_attr->peerId) && (data->peer_attr->peerId) &&
        (0 != strcmp(data->peer_attr->peerId, data->server_attr->peerId))) {
        data->server_attr->err_code = E1005;
        resp = eap_noob_err_msg(data,id);
    }

    return resp;
}

/**
 * eap_noob_rsp_type_four : prepares message type four
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_four(const struct eap_noob_peer_context * data, u8 id)
{
    json_t * rsp_obj = NULL;
    struct wpabuf * resp = NULL;
    char * resp_json = NULL, * mac_b64 = NULL;
    size_t len = 0 ;
    u8 * mac = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 4");
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (NULL == (rsp_obj = json_object()))
        return NULL;

    mac = eap_noob_gen_MAC(data, MACP_TYPE, data->server_attr->kdf_out->Kmp, KMP_LEN, COMPLETION_EXCHANGE);
    if (NULL == mac) goto EXIT;
    eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

    json_object_set_new(rsp_obj, TYPE, json_integer(EAP_NOOB_TYPE_4));
    json_object_set_new(rsp_obj, PEERID, json_string(data->peer_attr->peerId));
    json_object_set_new(rsp_obj, MACP, json_string(mac_b64));

    resp_json = json_dumps(rsp_obj,JSON_COMPACT);
    if (NULL == resp_json) goto EXIT;

    len = strlen(resp_json)+1;
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        goto EXIT;
    }
    wpabuf_put_data(resp,resp_json,len);
EXIT:
    EAP_NOOB_FREE(resp_json);
    EAP_NOOB_FREE(mac_b64);
    json_decref(rsp_obj);
    return resp;
}

/**
 * eap_noob_rsp_type_three : prepares message type three
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_three(const struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf * resp = NULL;
    char * resp_json = NULL;
    json_t * rsp_obj = NULL;
    size_t len = 0 ;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 3");
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (NULL == (rsp_obj = json_object()))
        return NULL;

    json_object_set_new(rsp_obj, TYPE, json_integer(EAP_NOOB_TYPE_3));
    json_object_set_new(rsp_obj, PEERID, json_string(data->peer_attr->peerId));

    resp_json = json_dumps(rsp_obj, JSON_COMPACT);
    if (NULL == resp_json) goto EXIT;
    len = strlen(resp_json)+1;
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        return NULL;
    }
    wpabuf_put_data(resp,resp_json,len);
EXIT:
    EAP_NOOB_FREE(resp_json);
    json_decref(rsp_obj);
    return resp;
}

/**
 *  eap_noob_build_JWK : Builds a JWK object to send in the inband message
 *  @jwk : output json object
 *  @x_64 : x co-ordinate in base64url format
 *  @y_64 : y co-ordinate in base64url format
 *  Returns : FAILURE/SUCCESS
**/
static int eap_noob_build_JWK( json_t ** jwk, const char * x_b64)
{
    if (NULL == x_b64) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: CO-ORDINATES are NULL!!");
        return FAILURE;
    }

    if (NULL == ((*jwk) = json_object())) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in JWK");
        return FAILURE;
    }
    json_object_set_new((*jwk), KEY_TYPE, json_string("EC"));
    json_object_set_new((*jwk), CURVE, json_string("Curve25519"));
    json_object_set_new((*jwk), X_COORDINATE, json_string(x_b64));
    wpa_printf(MSG_DEBUG, "JWK Key %s",json_dumps((*jwk),JSON_COMPACT));
    return SUCCESS;
}

/**
 * eap_noob_rsp_type_two : prepares message type two
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/

static struct wpabuf * eap_noob_rsp_type_two(struct eap_noob_peer_context * data, u8 id)
{
    json_t * rsp_obj = NULL;
    struct wpabuf *resp = NULL;
    char * resp_json = NULL;
    size_t len = 0 ;
    char * base64_nonce;
    size_t secret_len = EAP_SHARED_SECRET_LEN;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2");
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    data->server_attr->kdf_nonce_data->nonce_peer = os_zalloc(EAP_NOOB_NONCE_LEN);
    int rc = RAND_bytes(data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);
    unsigned long err = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);
        os_free(data->server_attr->kdf_nonce_data->nonce_peer);
        return NULL;
    }
    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce",
            data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);

    /* Generate Key material */
    if (eap_noob_get_key(data->server_attr) == 0)  {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
        goto EXIT;
    }

    if (FAILURE == eap_noob_build_JWK(&data->server_attr->ecdh_exchange_data->jwk_peer,
                data->server_attr->ecdh_exchange_data->x_b64)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to build JWK");
        goto EXIT;
    }
    eap_noob_Base64Encode(data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN, &base64_nonce);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Nonce %s", base64_nonce);

    data->server_attr->kdf_nonce_data->nonce_peer_b64 = base64_nonce;
    if (NULL == (rsp_obj = json_object()))
        goto EXIT;
    json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_2));
    json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerId));
    json_object_set_new(rsp_obj,NP,json_string(base64_nonce));
    json_object_set_new(rsp_obj,PKP,data->server_attr->ecdh_exchange_data->jwk_peer);

    resp_json = json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
    if (NULL == resp_json) goto EXIT;
    len = strlen(resp_json)+1;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Response %s = %d",resp_json,(int)strlen(resp_json));
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        goto EXIT;
    }

    wpabuf_put_data(resp,resp_json,len);

    eap_noob_derive_secret(data,&secret_len);
    data->server_attr->ecdh_exchange_data->shared_key_b64_len = \
        eap_noob_Base64Encode(data->server_attr->ecdh_exchange_data->shared_key, EAP_SHARED_SECRET_LEN,
        &data->server_attr->ecdh_exchange_data->shared_key_b64);

EXIT:
    if (rsp_obj)
        json_decref(rsp_obj);
    EAP_NOOB_FREE(resp_json);
    return resp;
}


/**
 * eap_noob_rsp_type_one : prepares message type one
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_one(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id)
{
    json_t * rsp_obj = NULL;
    struct wpabuf *resp = NULL;
    char * resp_json = NULL;
    size_t len = 0 ;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (NULL == (rsp_obj = json_object()))
        return NULL;

    json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_1));
    json_object_set_new(rsp_obj,VERP,json_integer(data->peer_attr->version));
    json_object_set_new(rsp_obj,PEERID,json_string(data->server_attr->peerId));
    json_object_set_new(rsp_obj,CRYPTOSUITEP,json_integer(data->peer_attr->cryptosuite));
    json_object_set_new(rsp_obj,DIRP,json_integer(data->peer_attr->dir));
    json_object_set_new(rsp_obj,PEERINFO,eap_noob_prepare_peer_info_json(sm,data->peer_attr->peer_config_params));

    resp_json = json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
    if (NULL == resp_json) goto EXIT;

    len = strlen(resp_json)+1;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: RESPONSE = %s = %d", resp_json, (int)strlen(resp_json));
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        return NULL;
    }
    wpabuf_put_data(resp,resp_json,len);
EXIT:
    json_decref(rsp_obj);
    EAP_NOOB_FREE(resp_json);
    return resp;

}

/*
static int eap_noob_prepare_hint(const struct eap_noob_peer_context *data,u8 * hint)
{
	char * hint_str = NULL;
	int hint_str_len = 0;
	int noob_len = strlen(data->server_attr->oob_data->noob_b64);
	int salt_len = strlen(HINT_SALT);

	hint_str = malloc(noob_len+salt_len);

	if (hint_str) {
		memset(hint_str,0,noob_len+salt_len);
		wpa_printf(MSG_DEBUG, "EAP-NOOB: noob= %s len = %d\n",data->server_attr->oob_data->noob_b64,noob_len);
		strcat(hint_str,data->server_attr->oob_data->noob_b64);
		strcat(hint_str,HINT_SALT);
		wpa_printf(MSG_DEBUG, "EAP-NOOB: HINT string = %s\n",hint_str);
		hint_str_len = strlen(hint_str);
		eap_noob_prepare_hash(hint, HASH_LEN, hint_str,hint_str_len);
		os_free(hint_str);
		return SUCCESS;
	}

	return FAILURE;
}
*/

static struct wpabuf * eap_noob_rsp_hint(const struct eap_noob_peer_context * data, u8 id)
{
    json_t * rsp_obj = NULL;
    struct wpabuf *resp = NULL;
    char * resp_json = NULL;
    size_t len = 0 ;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (NULL == (rsp_obj = json_object()))
        return NULL;

    json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_HINT));
    json_object_set_new(rsp_obj,PEERID,json_string(data->server_attr->peerId));
    json_object_set_new(rsp_obj,HINT_PEER,json_string(data->server_attr->oob_data->hint_b64));
    /* TODO : hash noob before sending
     * if (data->server_attr->oob_data->hint != NULL)
     * os_free(data->server_attr->oob_data->hint);
     * data->server_attr->oob_data->hint = os_zalloc(HASH_LEN);
     * memset(data->server_attr->oob_data->hint,0,HASH_LEN);
     * eap_noob_prepare_hint(data, (u8 *)data->server_attr->oob_data->hint);
     * eap_noob_Base64Encode((u8 *)data->server_attr->oob_data->hint,HASH_LEN, &hint_b64);
     * wpa_printf(MSG_DEBUG, "EAP-NOOB: Hint is %s\n",hint_b64);;
     * if (data->server_attr->oob_data->hint_b64 != NULL)
     * os_free(data->server_attr->oob_data->hint_b64);
     * data->server_attr->oob_data->hint_b64 = os_strdup(hint_b64);
     * wpa_printf(MSG_DEBUG, "EAP-NOOB: Hint is %s\n",data->server_attr->oob_data->hint_b64);
     * */
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Hint is %s", data->server_attr->oob_data->hint_b64);

    resp_json = json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
    if (NULL == resp_json) goto EXIT;

    len = strlen(resp_json)+1;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: RESPONSE = %s", resp_json);
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        return NULL;
    }
    wpabuf_put_data(resp,resp_json,len);
EXIT:
    json_decref(rsp_obj);
    EAP_NOOB_FREE(resp_json);
    return resp;
}

/**
 * eap_noob_rsp_type_five : prepares message type file
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_five(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id)
{
    json_t * rsp_obj = NULL;
    struct wpabuf *resp = NULL;
    char * resp_json = NULL;
    size_t len = 0 ;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    if (NULL == (rsp_obj = json_object()))
        goto EXIT;
    json_object_set_new(rsp_obj, TYPE, json_integer(EAP_NOOB_TYPE_5));
    json_object_set_new(rsp_obj, PEERID, json_string(data->server_attr->peerId));
    json_object_set_new(rsp_obj, CRYPTOSUITEP, json_integer(data->peer_attr->cryptosuite));
    json_object_set_new(rsp_obj, PEERINFO, eap_noob_prepare_peer_info_json(sm, data->peer_attr->peer_config_params));

    resp_json = json_dumps(rsp_obj, JSON_COMPACT);
    if (NULL == resp_json) goto EXIT;
    len = strlen(resp_json)+1;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: RESPONSE = %s", resp_json);
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB, len, EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        return NULL;
    }
    wpabuf_put_data(resp,resp_json,len);
EXIT:
    json_decref(rsp_obj);
    EAP_NOOB_FREE(resp_json);
    return resp;
}

/**
 * To-Do Based on the cryptosuite and server request decide whether new key has to be derived or not
 * eap_noob_rsp_type_six : prepares message type six
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_six(struct eap_noob_peer_context * data, u8 id)
{
    json_t * rsp_obj = NULL;
    struct wpabuf *resp = NULL;
    char * resp_json = NULL;
    size_t len = 0 ;
    char* base64_nonce;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 6");

    data->server_attr->kdf_nonce_data->nonce_peer = os_zalloc(EAP_NOOB_NONCE_LEN);
    int rc = RAND_bytes(data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);
    unsigned long err = ERR_get_error();
    if (rc != 1) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);
        os_free(data->server_attr->kdf_nonce_data->nonce_peer);
        return NULL;
    }

    wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);
    eap_noob_Base64Encode(data->server_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN, &base64_nonce);

    data->server_attr->kdf_nonce_data->nonce_peer_b64 = base64_nonce;

    if (NULL == (rsp_obj = json_object()))
        goto EXIT;

    json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_6));
    json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerId));
    json_object_set_new(rsp_obj,NP,json_string(base64_nonce));

    resp_json = json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
    if (NULL == resp_json) goto EXIT;
    len = strlen(resp_json)+1;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Json %s",resp_json);
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        return NULL;
    }
    wpabuf_put_data(resp,resp_json,len);
EXIT:
    json_decref(rsp_obj);
    EAP_NOOB_FREE(resp_json);
    return resp;
}

/**
 * eap_noob_rsp_type_seven : prepares message type seven
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_rsp_type_seven(const struct eap_noob_peer_context * data, u8 id)
{
    json_t * rsp_obj = NULL;
    struct wpabuf *resp = NULL;
    char * resp_json = NULL;
    size_t len = 0 ;
    u8 * mac = NULL;
    char * mac_b64 = NULL;

    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 7");

    if (NULL == (rsp_obj = json_object()))
        goto EXIT;

    mac = eap_noob_gen_MAC(data,MACP_TYPE,data->server_attr->kdf_out->Kmp, KMP_LEN,RECONNECT_EXCHANGE);
    if (NULL == mac) goto EXIT;
    eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);
    json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_7));
    json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerId));
    json_object_set_new(rsp_obj,MACP,json_string(mac_b64));

    resp_json = json_dumps(rsp_obj,JSON_COMPACT);
    if (NULL == resp_json) goto EXIT;
    len = strlen(resp_json)+1;
    resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
    if (resp == NULL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
                "for Response/NOOB-IE");
        return NULL;
    }

    wpabuf_put_data(resp,resp_json,len);
EXIT:
    json_decref(rsp_obj);
    EAP_NOOB_FREE(resp_json);
    return resp;
}

/**
 * eap_noob_req_type_seven :  Decodes request type seven
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_seven(struct eap_sm * sm, json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;
    u8 * mac = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 7");
    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    eap_noob_decode_obj(data->server_attr, req_obj);

    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_SEVEN_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }
    /* generate KDF */
    eap_noob_gen_KDF(data,RECONNECT_EXCHANGE);

    if (NULL != (resp = eap_noob_verify_peerId(data,id)))
        return resp;

    /* generate MAC */
    mac = eap_noob_gen_MAC(data,MACS_TYPE,data->server_attr->kdf_out->Kms, KMS_LEN,RECONNECT_EXCHANGE);
    if (NULL == mac)
        return NULL;

    if (0 != strcmp((char *)mac+16,data->server_attr->MAC)) {
        data->server_attr->err_code = E4001;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    resp = eap_noob_rsp_type_seven(data,id);
    data->server_attr->state = REGISTERED_STATE;
    eap_noob_config_change(sm, data);

    if (FAILURE == eap_noob_db_update(data,UPDATE_STATE)) {
        os_free(resp);
        return NULL;
    }

    return resp;
}

/**
 * eap_noob_req_type_six :  Decodes request type six
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_six(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf * resp = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 6");

    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_SIX_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_peerId(data,id))) {
        resp = eap_noob_rsp_type_six(data,id);
    }

    data->server_attr->rcvd_params = 0;
    return resp;
}

/**
 * eap_noob_req_type_five :  Decodes request type five
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_five(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 5");

    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_FIVE_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    data->peer_attr->peerId = os_strdup(data->server_attr->peerId);

    //TODO: handle eap_noob failure scenario
    if (SUCCESS == eap_noob_check_compatibility(data))
        resp = eap_noob_rsp_type_five(sm,data, id);
    else
        resp = eap_noob_err_msg(data,id);

    data->server_attr->rcvd_params = 0;
    return resp;
}

static int eap_noob_exec_hint_queries(struct eap_noob_peer_context * data)
{
    char * query = os_malloc(MAX_LINE_SIZE);
    int ret = FAILURE;
    //To-Do: send error if NoodID not found
    if (query) {
        snprintf(query, MAX_LINE_SIZE, "SELECT Noob, Hoob from oobs where PeerID=? and  noobId=?");
        ret = eap_noob_exec_query(data, query, eap_noob_callback, 4, TEXT, data->peer_attr->peerId,
                TEXT, data->server_attr->oob_data->hint_b64);
        os_free(query);
    }
    return ret;
}

#if 0
static int eap_noob_exec_hint_queries(struct eap_noob_peer_context * data)
{
        char * query = os_malloc(MAX_LINE_SIZE);
        //To-Do: send error if NoodID not found

        if (query) {
                snprintf(query,MAX_LINE_SIZE,"SELECT Noob, Hoob from %s where PeerID='%s' and  hint_server='%s'",TABLE_NAME,
                        data->peer_attr->peerId,data->server_attr->oob_data->hint_b64);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Query = %s\n",query);
                if (eap_noob_exec_query(query, eap_noob_callback,data,data)) {
                        return SUCCESS;

                }
                os_free(query);
        }
        return FAILURE;
}

#endif


/**
 * eap_noob_req_type_four :  Decodes request type four
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_four(struct eap_sm * sm, json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;
    char * mac_b64 = NULL;
    u8 * mac = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 4");

    eap_noob_decode_obj(data->server_attr, req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_FOUR_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }
    /* Execute Hint query in peer to server direction */
    if (data->peer_attr->dir == PEER_TO_SERV &&
       (FAILURE == eap_noob_exec_hint_queries(data) || data->server_attr->oob_data->noob_b64 == NULL)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Unrecognized NoobId");
        data->server_attr->err_code = E1006;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }
    /* generate Keys */
    eap_noob_gen_KDF(data, COMPLETION_EXCHANGE);

    if (NULL == (resp = eap_noob_verify_peerId(data, id))) {
        mac = eap_noob_gen_MAC(data, MACS_TYPE, data->server_attr->kdf_out->Kms, KMS_LEN,COMPLETION_EXCHANGE);

        if (NULL == mac) {
            os_free(resp); return NULL;
        }

        eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);
        wpa_printf(MSG_DEBUG, "EAP-NOOB:MAC = %s", mac_b64);

        if (0 != strcmp((char *)mac+16,data->server_attr->MAC)) {
            data->server_attr->err_code = E4001;
            resp = eap_noob_err_msg(data,id);
            return resp;
        }

        resp = eap_noob_rsp_type_four(data,id);
        data->server_attr->state = REGISTERED_STATE;
        eap_noob_config_change(sm,data);

        eap_noob_Base64Encode(data->server_attr->kdf_out->Kmp, KMP_LEN, &data->server_attr->kdf_out->kmp_b64);
        eap_noob_Base64Encode(data->server_attr->kdf_out->Kms, KMS_LEN, &data->server_attr->kdf_out->kms_b64);
        eap_noob_Base64Encode(data->server_attr->kdf_out->Kz, KZ_LEN, &data->server_attr->kdf_out->kz_b64);

        if (FAILURE == eap_noob_db_update(data,UPDATE_PERSISTENT_KEYS_SECRET)) {
            os_free(resp);
            return NULL;
        }
    }
    return resp;
}

/**
 * eap_noob_req_type_three :  Decodes request type three
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_three(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf * resp = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 3");

    if (FAILURE == eap_noob_db_update(data,DELETE_EXPIRED_NOOB)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error deleting Expired Noobs");
        return NULL;
    }

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }

    eap_noob_decode_obj(data->server_attr,req_obj);

    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_THREE_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_peerId(data,id))) {
        resp = eap_noob_rsp_type_three(data,id);
        if (0 != data->server_attr->minsleep)
            eap_noob_assign_waittime(sm,data);
    }

    return resp;
}

/**
 * eap_noob_req_type_two :  Decodes request type two
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id : pointer to response message buffer or null
**/
static struct wpabuf * eap_noob_req_type_two(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id)
{
    struct wpabuf *resp = NULL;

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 2");

    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_TWO_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_peerId(data,id))) {
        resp = eap_noob_rsp_type_two(data,id);
        data->server_attr->state = WAITING_FOR_OOB_STATE;
        if (eap_noob_db_entry(sm,data)) {
            eap_noob_config_change(sm,data);
            //TODO : handle when direction is BOTH_DIR
            /*if ((PEER_TO_SERV == (data->server_attr->dir & data->peer_attr->dir)) &&
              FAILURE == eap_noob_send_oob(data)) {
            //TODO: Reset supplicant in this case
            wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB generation FAILED");
            return NULL;
            }*/
            if ((PEER_TO_SERV == (data->server_attr->dir & data->peer_attr->dir)) && (FAILURE == eap_noob_db_update(data,UPDATE_OOB))) {
                os_free(resp);
                return NULL;
            }
            /*To-Do: If an error is received for the response then set the show_OOB flag to zero and send update signal*/
            /*if (FAILURE == eap_noob_sendUpdateSignal()) {
              wpa_printf(MSG_DEBUG,"EAP-NOOB: Failed to Notify the Script");
              }*/
        }
    }
    if (0!= data->server_attr->minsleep)
        eap_noob_assign_waittime(sm,data);

    return resp;
}


/**
 * eap_noob_req_type_one :  Decodes request type one
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_one(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf * resp = NULL;
    char * url = NULL;
    char url_cpy[2 * MAX_URL_LEN] = {0};

    if (NULL == req_obj || NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
        return NULL;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 1");

    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_ONE_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    /* checks on the received URL */
    if ( NULL == (url = os_strstr(data->server_attr->serv_info, "https://"))) {
        data->server_attr->err_code = E5003;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }
    strcpy(url_cpy,url);
    url_cpy[strlen(url_cpy)-2] = '\0';

    if (NULL == url || strlen(url_cpy) > MAX_URL_LEN ) {
        //FAILURE == eap_noob_ascii_check(url_cpy,strlen(url_cpy))) {
        data->server_attr->err_code = E5003;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    data->peer_attr->peerId = os_strdup(data->server_attr->peerId);

    if (NULL != data->server_attr->realm && strlen(data->server_attr->realm) > 0) {
        data->peer_attr->realm = os_strdup(data->server_attr->realm);
    } else {
        data->peer_attr->realm = os_strdup(DEFAULT_REALM);
        data->server_attr->realm = os_strdup(DEFAULT_REALM);
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB:Realm %s", data->server_attr->realm);

    //TODO: handle eap_noob failure scenario
    if (SUCCESS == eap_noob_check_compatibility(data))
        resp = eap_noob_rsp_type_one(sm,data, id);
    else
        resp = eap_noob_err_msg(data,id);

    data->server_attr->rcvd_params = 0;
    return resp;
}


static struct wpabuf * eap_noob_req_hint(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    struct wpabuf *resp = NULL;

    eap_noob_decode_obj(data->server_attr,req_obj);
    if (data->server_attr->err_code != NO_ERROR) {
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (data->server_attr->rcvd_params != TYPE_HINT_PARAMS) {
        data->server_attr->err_code = E1002;
        resp = eap_noob_err_msg(data,id);
        return resp;
    }

    if (NULL == (resp = eap_noob_verify_peerId(data,id))) {
        resp = eap_noob_rsp_hint(data,id);
    }
    return resp;
}

/**
 * eap_noob_req_err_handling :  handle received error message
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static void eap_noob_req_err_handling(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context * data, u8 id)
{
    if (!data->server_attr->err_code) {
        eap_noob_db_update(data, UPDATE_STATE_ERROR);
    }
}

/**
 * eap_noob_process :  Process recieved message
 * @eap_sm : eap statemachine context
 * @priv : peer context
 * @ret : eap method data
 * @reqData : received request message objecti
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_process (struct eap_sm * sm, void * priv, struct eap_method_ret *ret,
                                         const struct wpabuf * reqData)
{
    struct eap_noob_peer_context * data = priv;
    struct wpabuf * resp = NULL;
    const u8 * pos;
    size_t len;
    json_t * req_obj = NULL;
    json_t * req_type = NULL;
    json_error_t error;
    int msgtype;
    u8 id =0;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS CLIENT");

    pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, reqData, &len);
    if (pos == NULL || len < 1) {
        ret->ignore = TRUE;
        return NULL;
    }
    ret->ignore = FALSE;
    ret->methodState = METHOD_MAY_CONT;
    ret->decision = DECISION_FAIL;
    ret->allowNotifications = FALSE;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: RECIEVED REQUEST = %s", pos);
    req_obj = json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
    id = eap_get_id(reqData);

    if ((NULL != req_obj) && (json_is_object(req_obj) > 0)) {
        req_type = json_object_get(req_obj,TYPE);

        if ((NULL != req_type) && (json_is_integer(req_type) > 0)) {
            msgtype = json_integer_value(req_type);
        }
        else {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown type received");
            data->server_attr->err_code = E1003;
            resp = eap_noob_err_msg(data,id);
            goto EXIT;
        }
    }
    else {
        data->server_attr->err_code = E1003;
        resp = eap_noob_err_msg(data,id);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
        goto EXIT;
    }

    wpa_printf(MSG_DEBUG, "EAP-NOOB: State :%d, mtype = %d",data->server_attr->state,msgtype);
    if (VALID != state_message_check[data->server_attr->state][msgtype]) {
        data->server_attr->err_code = E2002;
        resp = eap_noob_err_msg(data,id);
        wpa_printf(MSG_DEBUG, "EAP-NOOB: State mismatch");
        goto EXIT;
    } else if ((data->server_attr->state == WAITING_FOR_OOB_STATE || data->server_attr->state == OOB_RECEIVED_STATE) &&
                msgtype == EAP_NOOB_TYPE_1) {
        if (FAILURE == eap_noob_db_update(data, DELETE_SSID)) {
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to delete SSID");
            goto EXIT;
        }
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Deleted SSID");
    }

    switch(msgtype) {

        case NONE:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Error message received");
            eap_noob_req_err_handling(sm,req_obj,data, id);
            break;
        case EAP_NOOB_TYPE_1:
            resp = eap_noob_req_type_one(sm,req_obj ,data,id);
            break;
        case EAP_NOOB_TYPE_2:
            resp = eap_noob_req_type_two(sm,req_obj ,data, id);
            break;
        case EAP_NOOB_TYPE_3:
            resp = eap_noob_req_type_three(sm,req_obj ,data, id);
            break;
        case EAP_NOOB_TYPE_4:
            resp = eap_noob_req_type_four(sm,req_obj ,data, id);

            ret->decision = DECISION_COND_SUCC;
            break;
        case EAP_NOOB_TYPE_5:
            resp = eap_noob_req_type_five(sm, req_obj, data, id);
            break;
        case EAP_NOOB_TYPE_6:
            resp = eap_noob_req_type_six(sm, req_obj, data, id);
            break;
        case EAP_NOOB_TYPE_7:
            resp = eap_noob_req_type_seven(sm, req_obj, data, id);
            ret->decision = DECISION_COND_SUCC;
            break;
        case EAP_NOOB_HINT:
            resp = eap_noob_req_hint(sm, req_obj, data, id);
            break;
        default:
            wpa_printf(MSG_DEBUG, "EAP-NOOB: Unknown EAP-NOOB request received");
            break;
    }

EXIT:
    if (req_type)
        json_decref(req_type); // Borrowed reference
    else if (req_obj)
        json_decref(req_obj);
    return resp;
}

/**
 * eap_noob_free_ctx : free all the allocations from peer context
 * @data : peer context
 *
**/
static void eap_noob_free_ctx(struct eap_noob_peer_context * data)
{
    if (NULL == data) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Input to %s is null", __func__);
        return;
    }
    struct eap_noob_peer_data * peer = data->peer_attr;
    struct eap_noob_server_data * serv = data->server_attr;
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s", __func__);

#if 0
    if (serv) {
        wpa_printf(MSG_DEBUG, "EAP_NOOB: Clearing server data");
        EAP_NOOB_FREE(serv->serv_info);
        EAP_NOOB_FREE(serv->MAC);
        EAP_NOOB_FREE(serv->ssid);
        EAP_NOOB_FREE(serv->peerId);
        EAP_NOOB_FREE(serv->realm);
        if (serv->ecdh_exchange_data) {
            EVP_PKEY_free(serv->ecdh_exchange_data->dh_key);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->x_serv_b64);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->y_serv_b64);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->x_b64);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->y_b64);
            json_decref(serv->ecdh_exchange_data->jwk_serv);
            json_decref(serv->ecdh_exchange_data->jwk_peer);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->shared_key);
            EAP_NOOB_FREE(serv->ecdh_exchange_data->shared_key_b64);
            os_free(serv->ecdh_exchange_data);
        }
        if (serv->oob_data) {
            EAP_NOOB_FREE(serv->oob_data->noob_b64);
            EAP_NOOB_FREE(serv->oob_data->noob);
            EAP_NOOB_FREE(serv->oob_data->hoob_b64);
            EAP_NOOB_FREE(serv->oob_data->noob);
            EAP_NOOB_FREE(serv->oob_data->hint_b64);
            EAP_NOOB_FREE(serv->oob_data->hint);
            os_free(serv->oob_data);
        }
        if (serv->kdf_nonce_data) {
            EAP_NOOB_FREE(serv->kdf_nonce_data->nonce_serv);
            EAP_NOOB_FREE(serv->kdf_nonce_data->nonce_serv_b64);
            EAP_NOOB_FREE(serv->kdf_nonce_data->nonce_peer);
            EAP_NOOB_FREE(serv->kdf_nonce_data->nonce_peer_b64);
            os_free(serv->kdf_nonce_data);
        }
        if (serv->kdf_out) {
            EAP_NOOB_FREE(serv->kdf_out->msk);
            EAP_NOOB_FREE(serv->kdf_out->msk_b64);
            EAP_NOOB_FREE(serv->kdf_out->emsk);
            EAP_NOOB_FREE(serv->kdf_out->emsk_b64);
            EAP_NOOB_FREE(serv->kdf_out->amsk);
            EAP_NOOB_FREE(serv->kdf_out->amsk_b64);
            EAP_NOOB_FREE(serv->kdf_out->Kms);
            EAP_NOOB_FREE(serv->kdf_out->kms_b64);
            EAP_NOOB_FREE(serv->kdf_out->Kmp);
            EAP_NOOB_FREE(serv->kdf_out->kmp_b64);
            EAP_NOOB_FREE(serv->kdf_out->Kz);
            EAP_NOOB_FREE(serv->kdf_out->kz_b64);
            os_free(serv->kdf_out);
        }
        os_free(serv);
    }

    if (peer) {
        wpa_printf(MSG_DEBUG, "EAP_NOOB: Clearing peer data");
        EAP_NOOB_FREE(peer->peerId);
        EAP_NOOB_FREE(peer->peer_info);
        EAP_NOOB_FREE(peer->MAC);
        EAP_NOOB_FREE(peer->realm);
        if (peer->peer_config_params) {
            EAP_NOOB_FREE(peer->peer_config_params->Peer_name);
            EAP_NOOB_FREE(peer->peer_config_params->Peer_ID_Num);
            os_free(peer->peer_config_params);
        }
        os_free(peer);
    }

    /* Close DB */
    wpa_printf(MSG_DEBUG, "EAP_NOOB: Closing DB");
    /* TODO check again */
    if (data->peer_db)
    if (SQLITE_OK != sqlite3_close(data->peer_db)) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
    }
    EAP_NOOB_FREE(data->db_name);
    EAP_NOOB_FREE(data->db_table_name);
    os_free(data); data = NULL;
    wpa_printf(MSG_DEBUG, "EAP_NOOB: Exit %s", __func__);
#endif
}

/**
 * eap_noob_deinit : de initialises the eap method context
 * @sm : eap statemachine context
 * @priv : method context
**/
static void eap_noob_deinit(struct eap_sm * sm, void * priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB DEINIT");
    struct eap_noob_peer_context * data = priv;

    eap_noob_free_ctx(data);
}

/**
 * eap_noob_create_db : Creates a new DB or opens the existing DB and populates the context
 * @sm : eap statemachine context
 * @data : peer context
 * returns : SUCCESS/FAILURE
**/
static int eap_noob_create_db(struct eap_sm *sm, struct eap_noob_peer_context * data)
{
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
    char buff[100] = {0};

    if (SQLITE_OK != sqlite3_open_v2(data->db_name, &data->peer_db,
                SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE, NULL)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: No DB found,new DB willbe created");
        return FAILURE;
    }

    if (FAILURE == eap_noob_exec_query(data, CREATE_CONNECTION_TABLE, NULL, 0)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: connections Table creation failed");
        return FAILURE;
    }

    if ((wpa_s->current_ssid->ssid) || (0 == strcmp(wpa_s->driver->name,"wired"))) {
        os_snprintf(buff, 100, "SELECT COUNT(*) from %s where ssid =?", data->db_table_name);
        if (FAILURE != eap_noob_exec_query(data, buff, eap_noob_db_entry_check, 2, TEXT, wpa_s->current_ssid->ssid) &&
           (data->server_attr->record_present)) {
            memset(buff, 0, sizeof(buff));
            os_snprintf(buff, 100, "SELECT * from %s where ssid =?",data->db_table_name);
            if (FAILURE !=  eap_noob_exec_query(data, buff, eap_noob_callback, 2, TEXT, wpa_s->current_ssid->ssid)) {
                data->peer_attr->peerId = os_strdup(data->server_attr->peerId);
            }
        }
    }
    return SUCCESS;
}

/**
 * eap_noob_assign_config : identify each config item and store the read value
 * @confname : name of the conf item
 * @conf_value : value of the conf item
 * @data : peer context
**/
static void eap_noob_assign_config(char * conf_name,char * conf_value,struct eap_noob_peer_data * data)
{
    //TODO : version and csuite are directly converted to integer.This needs to be changed if
    //more than one csuite or version is supported.

    wpa_printf(MSG_DEBUG, "EAP-NOOB:CONF Name = %s %d", conf_name, (int)strlen(conf_name));
    if (0 == strcmp("Version",conf_name)) {
        data->version = (int) strtol(conf_value, NULL, 10);
        data->config_params |= VERSION_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->version);
    }
    else if (0 == strcmp("Csuite",conf_name)) {
        data->cryptosuite = (int) strtol(conf_value, NULL, 10);
        data->config_params |= CRYPTOSUITES_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->cryptosuite);
    }
    else if (0 == strcmp("OobDirs",conf_name)) {
        data->dir = (int) strtol(conf_value, NULL, 10);
        data->config_params |= DIRS_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",data->dir);
    }
    else if (0 == strcmp("PeerMake", conf_name)) {
        data->peer_config_params->Peer_name = os_strdup(conf_value);
        data->config_params |= PEER_MAKE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",data->peer_config_params->Peer_name);
    }
    else if (0 == strcmp("PeerType", conf_name)) {
        eap_noob_globle_conf.peer_type = os_strdup(conf_value);
        data->config_params |= PEER_TYPE_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",eap_noob_globle_conf.peer_type);
    }
    else if (0 == strcmp("PeerSNum", conf_name)) {
        data->peer_config_params->Peer_ID_Num = os_strdup(conf_value);
        data->config_params |= PEER_ID_NUM_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %s",data->peer_config_params->Peer_ID_Num);
    }
    else if (0 == strcmp("MinSleepDefault", conf_name)) {
        eap_noob_globle_conf.default_minsleep = (int) strtol(conf_value, NULL, 10);
        data->config_params |= DEF_MIN_SLEEP_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",eap_noob_globle_conf.default_minsleep);
    }
    else if (0 == strcmp("OobMessageEncoding", conf_name)) {
        eap_noob_globle_conf.oob_enc_fmt = (int) strtol(conf_value, NULL, 10);
        data->config_params |= MSG_ENC_FMT_RCVD;
        wpa_printf(MSG_DEBUG, "EAP-NOOB: FILE  READ= %d",eap_noob_globle_conf.oob_enc_fmt);
    }

}

/**
 * eap_noob_parse_config : parse eacj line from the config file
 * @buff : read line
 * data : peer_context
**/
static void eap_noob_parse_config(char * buff,struct eap_noob_peer_data * data)
{
    char * pos = buff;
    char * conf_name = NULL;
    char * conf_value = NULL;
    char * token = NULL;

    for(; *pos == ' ' || *pos == '\t' ; pos++);

    if (*pos == '#')
        return;

    if (os_strstr(pos, "=")) {
        conf_name = strsep(&pos,"=");
        /*handle if there are any space after the conf item name*/
        token = conf_name;
        for(; (*token != ' ' && *token != 0 && *token != '\t'); token++);
        *token = '\0';

        token = strsep(&pos,"=");
        /*handle if there are any space before the conf item value*/
        for(; (*token == ' ' || *token == '\t' ); token++);

        /*handle if there are any comments after the conf item value*/
        //conf_value = strsep(&token,"#");
        conf_value = token;

        for(; (*token != '\n' && *token != '\t'); token++);
        *token = '\0';
        //wpa_printf(MSG_DEBUG, "EAP-NOOB: conf_value = %s token = %s\n",conf_value,token);
        eap_noob_assign_config(conf_name,conf_value, data);
    }
}

/**
 * eap_noob_handle_incomplete_conf :  assigns defult value of the configuration is incomplete
 * @data : peer config
 * Returs : FAILURE/SUCCESS
**/
static int eap_noob_handle_incomplete_conf(struct eap_noob_peer_context * data)
{
    if (!(data->peer_attr->config_params & PEER_MAKE_RCVD) ||
        !(data->peer_attr->config_params & PEER_ID_NUM_RCVD) ||
        !(data->peer_attr->config_params&PEER_TYPE_RCVD)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Peer Make or Peer Type or Peer Serial number missing");
        return FAILURE;
    }
    if (! (data->peer_attr->config_params & VERSION_RCVD))
        data->peer_attr->version = VERSION_ONE;
    if (! (data->peer_attr->config_params & CRYPTOSUITES_RCVD))
        data->peer_attr->cryptosuite = SUITE_ONE;
    if (! (data->peer_attr->config_params & DIRS_RCVD))
        data->peer_attr->dir = PEER_TO_SERV;
    if (! (data->peer_attr->config_params & DEF_MIN_SLEEP_RCVD))
        eap_noob_globle_conf.default_minsleep = 0;
    if (! (data->peer_attr->config_params & MSG_ENC_FMT_RCVD))
        eap_noob_globle_conf.oob_enc_fmt = FORMAT_BASE64URL;

    return SUCCESS;
}

/**
 * eap_noob_prepare_peer_info_obj : from the read configuration make a peer info JSON object
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/
/*
static int eap_noob_prepare_peer_info_obj(struct eap_noob_peer_data * data)
{
	//To-Do: Send Peer Info and Server Info during fast reconnect only if they have changed

	json_t * info_obj = NULL;

        if (NULL == data) {
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return FAILURE;
        }

        if (NULL != (info_obj = json_object())) {

                json_object_set_new(info_obj,PEER_NAME,json_string(data->peer_config_params->Peer_name));
                json_object_set_new(info_obj,PEER_SERIAL_NUM,json_string(data->peer_config_params->Peer_ID_Num));

                if (NULL == (data->peer_info = json_dumps(info_obj,JSON_COMPACT|JSON_PRESERVE_ORDER)) ||
			(strlen(data->peer_info) > MAX_INFO_LEN)) {
				wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no server info");
 	                       	return FAILURE;
			}
		wpa_printf(MSG_DEBUG, "EAP-NOOB: PEER INFO = %s\n",data->peer_info);
        }

	return SUCCESS;
}
*/
/**
 * eap_noob_read_config : read configuraions from config file
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/

static int eap_noob_read_config(struct eap_sm *sm,struct eap_noob_peer_context * data)
{
    FILE * conf_file = NULL;
    char * buff = NULL;

    if (NULL == (conf_file = fopen(CONF_FILE,"r"))) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Configuration file not found");
        return FAILURE;
    }

    if ((NULL == (buff = malloc(MAX_CONF_LEN))) ||
        (NULL == (data->peer_attr->peer_config_params =
         malloc(sizeof(struct eap_noob_peer_config_params)))))
        return FAILURE;

    data->peer_attr->config_params = 0;
    while(!feof(conf_file)) {
        if (fgets(buff,MAX_CONF_LEN, conf_file)) {
            eap_noob_parse_config(buff,data->peer_attr);
            memset(buff,0,MAX_CONF_LEN);
        }
    }
    free(buff);

    if ((data->peer_attr->version >MAX_SUP_VER) ||
        (data->peer_attr->cryptosuite > MAX_SUP_CSUITES) ||
        (data->peer_attr->dir > BOTH_DIR)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");
        return FAILURE;
    }

    if (eap_noob_globle_conf.oob_enc_fmt != FORMAT_BASE64URL) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Unsupported OOB message encoding format");
        return FAILURE;
    }
    if (data->peer_attr->config_params != CONF_PARAMS &&
        FAILURE == eap_noob_handle_incomplete_conf(data))
        return FAILURE;

    //return eap_noob_prepare_peer_info_obj(data->peer_attr);
    if ((NULL == (data->peer_attr->peer_info = json_dumps(eap_noob_prepare_peer_info_json(sm,
                  data->peer_attr->peer_config_params),JSON_COMPACT|JSON_PRESERVE_ORDER))) ||
        (strlen(data->peer_attr->peer_info) > MAX_INFO_LEN)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no peer info");
        return FAILURE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: PEER INFO = %s",data->peer_attr->peer_info);
    return SUCCESS;
}

/**
 * eap_noob_peer_ctxt_alloc : Allocates the subcontexts inside the peer context
 * @sm : eap method context
 * @peer : peer context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_peer_ctxt_alloc(struct eap_sm *sm,  struct eap_noob_peer_context * data)
{
    if (NULL == (data->peer_attr = os_zalloc( sizeof (struct eap_noob_peer_data)))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr = os_zalloc( sizeof (struct eap_noob_server_data))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->ecdh_exchange_data = os_zalloc( sizeof (struct eap_noob_ecdh_key_exchange))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->oob_data = os_zalloc( sizeof (struct eap_noob_oob_data))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->kdf_out = os_zalloc( sizeof (struct eap_noob_ecdh_kdf_out))))) {
        return FAILURE;
    }
    if ((NULL == (data->server_attr->kdf_nonce_data = os_zalloc( sizeof (struct eap_noob_ecdh_kdf_nonce))))) {
        return FAILURE;
    }

    return SUCCESS;
}

/**
 * eap_noob_peer_ctxt_init : initialises peer context
 * @sm : eap statemachine data
 * @data : peer context
 * Returns: SUCCESS/FAILURE
**/
static int eap_noob_peer_ctxt_init(struct eap_sm * sm,  struct eap_noob_peer_context * data)
{
    int retval = FAILURE;
    if (FAILURE == (retval = eap_noob_peer_ctxt_alloc(sm,data))) {
        wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in allocating peer context");
        goto EXIT;
    }

    data->server_attr->state = UNREGISTERED_STATE;
    data->server_attr->rcvd_params = 0;
    data->server_attr->err_code = 0;
    data->db_name = os_strdup(DB_NAME);
    data->db_table_name = os_strdup(TABLE_NAME);

    if (FAILURE == (retval = eap_noob_create_db(sm , data)))
        goto EXIT;

    wpa_printf(MSG_DEBUG, "EAP-NOOB:State = %d", data->server_attr->state);
    if (FAILURE == eap_noob_read_config(sm,data)) {
        wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to initialize context");
        goto EXIT;
    }

EXIT:
    if (FAILURE == retval)
        eap_noob_free_ctx(data);
    return retval;
}

/**
 * eap_noob_init : initialise the eap noob method
 *  @sm : eap statemachine context
 * Returns : eap  noob peer context
**/
static void * eap_noob_init(struct eap_sm * sm)
{
    struct eap_noob_peer_context * data;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB INIT");
    if (NULL == (data = os_zalloc( sizeof(struct eap_noob_peer_context))))
        return NULL;

    if (FAILURE == eap_noob_peer_ctxt_init(sm,data))
        return NULL;

    return data;
}

/**
 * eap_noob_isKeyAvailable : Checks if the shared key is presesnt
 * @sm : eap statemachine context
 * @priv : eap noob data
 * Returns : TRUE/FALSE
*/
static Boolean eap_noob_isKeyAvailable(struct eap_sm *sm, void *priv)
{
    struct eap_noob_peer_context * data = priv;
    Boolean retval = ((data->server_attr->state == REGISTERED_STATE) && \
                      (data->server_attr->ecdh_exchange_data->shared_key_b64 != NULL));
    wpa_printf(MSG_DEBUG, "EAP-NOOB: STATE = %d\n", data->server_attr->state);
    wpa_printf(MSG_DEBUG, "EAP-NOOB: KEY AVAILABLE? %d", retval);
    return retval;
}

/**
 * eap_noob_getKey : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns MSK or NULL
**/
static u8 * eap_noob_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_noob_peer_context * data = priv;
    u8 * key;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: GET  KEY");
    if ((data->server_attr->state != REGISTERED_STATE) || (!data->server_attr->kdf_out->msk))
        return NULL;

    if (NULL == (key = os_malloc(MSK_LEN)))
        return NULL;
    *len = MSK_LEN;
    os_memcpy(key, data->server_attr->kdf_out->msk, MSK_LEN);
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: MSK Derived",key,MSK_LEN);

    return key;
}

/**
 * eap_noob_get_emsk : gets the msk if available
 * @sm : eap statemachine context
 * @priv : eap noob data
 * @len : msk len
 * Returns EMSK or NULL
**/
static u8 * eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
    struct eap_noob_peer_context *data = priv;
    u8 *key;
    wpa_printf(MSG_DEBUG,"EAP-NOOB:Get EMSK Called");
    if ((data->server_attr->state != REGISTERED_STATE) || (!data->server_attr->kdf_out->emsk))
        return NULL;

    if (NULL == (key = os_malloc(MSK_LEN)))
        return NULL;

    *len = EAP_EMSK_LEN;
    os_memcpy(key, data->server_attr->kdf_out->emsk, EAP_EMSK_LEN);
    wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: EMSK",key,EAP_EMSK_LEN);
    return key;
}

/**
 * eap_noob_deinit_for_reauth : deinitialise the reauth context
 * @sm : eap statemachine context
 * @priv : eap noob data
 */

static void eap_noob_deinit_for_reauth(struct eap_sm *sm, void *priv)
{
    wpa_printf(MSG_DEBUG, "EAP-NOOB: DE-INIT reauth called");
}

/**
 * eap_noob_init_for_reauth : initialise the reauth context
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static void * eap_noob_init_for_reauth(struct eap_sm *sm, void *priv)
{
    struct eap_noob_peer_context * data = priv;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT reauth called\n");
    data->server_attr->state = RECONNECTING_STATE;

    return data;
}

/**
 * eap_noob_has_reauth_data : Changes the state to RECONNECT ,
 * if the current state is REGISTERED_STATE
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static Boolean eap_noob_has_reauth_data(struct eap_sm *sm, void *priv)
{
    struct eap_noob_peer_context * data = priv;
    struct wpa_supplicant * wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: Has reauth function called\n");
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Current SSID = %s, Stored SSID = %s\n",
            wpa_s->current_ssid->ssid,data->server_attr->ssid);
    if (data->server_attr->state == REGISTERED_STATE &&
        0 == strcmp((char *)wpa_s->current_ssid->ssid,data->server_attr->ssid)) {
        data->server_attr->state = RECONNECTING_STATE;
        eap_noob_config_change(sm,data);
        eap_noob_db_update(data,UPDATE_STATE);
        return TRUE;
    }
    wpa_printf(MSG_DEBUG, "EAP-NOOB: Returning False\n");
    return FALSE;
}

/**
 * eap_peer_noob_register : register eap noob method
**/
int eap_peer_noob_register(void)
{
    struct eap_method * eap = NULL;

    wpa_printf(MSG_DEBUG, "EAP-NOOB: NOOB REGISTER");
    eap = eap_peer_method_alloc(EAP_PEER_METHOD_INTERFACE_VERSION,
            EAP_VENDOR_IETF, EAP_TYPE_NOOB, "NOOB");

    if (eap == NULL)
        return -1;

    eap->init = eap_noob_init;
    eap->deinit = eap_noob_deinit;
    eap->process = eap_noob_process;
    eap->isKeyAvailable = eap_noob_isKeyAvailable;
    eap->getKey = eap_noob_getKey;
    eap->get_emsk = eap_noob_get_emsk;
    eap->has_reauth_data = eap_noob_has_reauth_data;
    eap->init_for_reauth = eap_noob_init_for_reauth;
    eap->deinit_for_reauth = eap_noob_deinit_for_reauth;

    return eap_peer_method_register(eap);
}
