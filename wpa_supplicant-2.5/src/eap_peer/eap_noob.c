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

#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/buffer.h>
#include <openssl/bio.h>
#include <openssl/hmac.h>
#include <signal.h>


/**
 * eap_noob_json_array - Wrapper function for creating JSON array.
 * Returns: reference to new array if successful or NULL otherwise.
 **/

static noob_json_t * eap_noob_json_array()
{
	return json_array();
}

/**
 * eap_noob_json_array_append - Wrapper function for appending elements to JSON array.
 * @arr  : input json array.
 * @value : Value to be appended.
 * Returns: Zero on success or -1 on failure.
 **/

static u32  eap_noob_json_array_append(noob_json_t * arr, noob_json_t * value)
{
	return json_array_append(arr, value);
}

/**
 * eap_noob_json_integer - Wrapper function for creating JSON_Integer value.
 * @value : Value to be converted.
 * Returns: reference to new value if successful or NULL otherwise.
 **/

static noob_json_t * eap_noob_json_integer(noob_json_int_t value)
{
	return json_integer(value);
}

/**
 * eap_noob_json_integer_value - Wrapper function for converting JSON_Integer 
   value to integer value.
 * @value : Value to be converted.
 * Returns: reference to new value if successful or NULL otherwise.
 **/
static noob_json_int_t eap_noob_json_integer_value(noob_json_t * value)
{
	return json_integer_value(value);
}

/**
 * eap_noob_json_integer - Wrapper function for creating JSON_Integer value.
 * @value : Value to be converted.
 * Returns: integer value or Zero otherwise.
 **/
static u32 eap_noob_json_is_integer(const noob_json_t * value)
{
	return json_is_integer(value);
}

/**
 * eap_noob_json_string - Wrapper function for creating JSON_String value.
 * @value : Value to be converted.
 * Returns: reference to new value if successful or NULL otherwise.
 **/
static noob_json_t * eap_noob_json_string(const noob_json_str_t * value)
{
	return json_string(value);
}

/**
 * eap_noob_json_string_value - Wrapper function for converting JSON_String to char * value.
 * @value : Value to be converted.
 * Returns: reference to new value if successful or NULL otherwise.
 **/
static noob_json_str_t * eap_noob_json_string_value(noob_json_t * value)
{
	return (char *)json_string_value(value);
}

/**
 * eap_noob_json_object : wrapper function for creating json object
**/
static noob_json_t * eap_noob_json_object()
{
	return json_object();
}

/**
 * eap_noob_json_object_set_new :  adds a new key value pair to the JSON object
 * @obj :  input JSON object
 * @key :  key for parameter
 * @value :  value for parameter
 * Returns : 0/-1
**/

static u32 eap_noob_json_object_set_new (noob_json_t * obj, const char* key, noob_json_t * value)
{
	return json_object_set_new(obj,key,value);
}

/** 
 *eap_noob_json_dumps : wrapper function to convert object type to string 
 * @root : object to be decoded
 * @flags : JSON flags for the calls
 * returns : converted buffer or NULL
 **/

static char * eap_noob_json_dumps(noob_json_t * root, size_t flags)
{
	return json_dumps(root, flags);
}


/** 
 *eap_noob_json_loads : wrapper function  to convert sting to JSON object type 
 * @input : input string
 * @flags : JSON flags for the calls
 * @error : object to collect error message
 * Returns  : reference to JSON obj 
 **/
static noob_json_t * eap_noob_json_loads(const char * input, size_t flags, noob_json_error_t * error)
{
	return json_loads(input,flags, error);
}

/** 
 *eap_noob_json_is_object : checks for JSON object type
 *@obj : input object
 Returns : TRUE/FALSE
**/
static u32 eap_noob_json_is_object(noob_json_t * obj)
{
	return json_is_object(obj);
}

/**
 *eap_noob_json_object_get : fetches the requested value from the JSON object
 *@obj : input JSON object
 *@key : key for the parameter inside the object
 *Returns :  refrence to the value inside the object 
**/
static noob_json_t * eap_noob_json_object_get(noob_json_t * obj, const char * key)
{
	return json_object_get(obj,key);
}
/**
 * eap_noob_json_typeof : Gives the JSON data type of the input argument
 @value : unknown json type param
 Returns : JSON datatype enum value 
**/
static u32 eap_noob_json_typeof(const noob_json_t * value)
{
	return json_typeof(value);
}


/**
 * eap_noob_sendUpdateSignal : Send user defined signal to auto runscript 
                      to display the new oob message
 * Returns: SUCCESS/FAILURE
**/
#if 0
static int eap_noob_sendUpdateSignal()
{

	FILE *fp;
	char pid[10];
	int p = 0;
	fp = popen("pidof /usr/bin/python3 wpa_auto_run.py", "r");
	if (fp == NULL)
		return FAILURE;
	if( fgets (pid, 10, fp)!=NULL ) 
	{
		/* writing content to stdout */
		printf("%s",pid);
		p = atoi(pid);
		printf("%d",p);
	}
	pclose(fp);
	if(p){
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
 * eap_noob_gen_KDF : generates and updates the KDF inside the peer context.
 * @data  : peer context.
 * @state : EAP_NOOB state 
 * Returns:
**/
static void eap_noob_gen_KDF(struct eap_noob_peer_context * data, int state){

	const EVP_MD *md = EVP_sha256();
	int counter = 0;
	unsigned char * out = os_zalloc(192);

	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Algorith ID:",ALGORITHM_ID,ALGORITHM_ID_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Nonce_Peer",data->serv_attr->kdf_nonce_data->nonce_peer,EAP_NOOB_NONCE_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Nonce_Serv",data->serv_attr->kdf_nonce_data->nonce_serv,EAP_NOOB_NONCE_LEN);
	if(state == COMPLETION_EXCHANGE){
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Noob",data->serv_attr->oob_data->noob,EAP_NOOB_NONCE_LEN);
		eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
				data->serv_attr->ecdh_exchange_data->shared_key, EAP_SHARED_SECRET_LEN,
				(unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
				data->serv_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN,
				data->serv_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN,
				data->serv_attr->oob_data->noob, EAP_NOOB_NONCE_LEN, md);
	}else{
		
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: kz",data->serv_attr->kdf_out->kz,KZ_LEN);
		eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
				data->serv_attr->kdf_out->kz, KZ_LEN,
				(unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
				data->serv_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN,
				data->serv_attr->kdf_nonce_data->nonce_serv, EAP_NOOB_NONCE_LEN,
				NULL, 0, md);
	}	
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: KDF",out,KDF_LEN);

	if(out != NULL){
		data->serv_attr->kdf_out->msk = os_zalloc(MSK_LEN);
		data->serv_attr->kdf_out->emsk = os_zalloc(EMSK_LEN);
		data->serv_attr->kdf_out->kms = os_zalloc(KMS_LEN);
		data->serv_attr->kdf_out->kmp = os_zalloc(KMP_LEN);
		data->serv_attr->kdf_out->kz = os_zalloc(KZ_LEN);

		memcpy(data->serv_attr->kdf_out->msk,out,MSK_LEN);
		counter += MSK_LEN;
		memcpy(data->serv_attr->kdf_out->emsk, out + counter, EMSK_LEN);
		counter += EMSK_LEN;
		memcpy(data->serv_attr->kdf_out->kms, out + counter, KMS_LEN);
		counter += KMS_LEN;
		memcpy(data->serv_attr->kdf_out->kmp, out + counter, KMP_LEN);
		counter += KMP_LEN;
		memcpy(data->serv_attr->kdf_out->kz, out + counter, KZ_LEN);
		counter += KZ_LEN;
	}
}

/**
 * eap_noob_prepare_peer_info_json : Create a Json object for peer information.
 * @data : peer context. 
 * returns : reference to a new object or NULL.
**/
static noob_json_t * eap_noob_prepare_peer_info_json(struct eap_sm *sm,struct eap_noob_peer_config_params * data)
{

	noob_json_t * info_obj = NULL;
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
	char bssid[18] = {0};

        if(NULL == data){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return NULL;
        }

        if(NULL != (info_obj = eap_noob_json_object())){

                eap_noob_json_object_set_new(info_obj,PEER_NAME,eap_noob_json_string(data->Peer_name));
                eap_noob_json_object_set_new(info_obj,PEER_SERIAL_NUM,eap_noob_json_string(data->Peer_ID_Num));
               	eap_noob_json_object_set_new(info_obj,PEER_SSID,eap_noob_json_string((char *)wpa_s->current_ssid->ssid));
		sprintf(bssid,"%x:%x:%x:%x:%x:%x",wpa_s->current_ssid->bssid[0],wpa_s->current_ssid->bssid[1],
			wpa_s->current_ssid->bssid[2],wpa_s->current_ssid->bssid[3],wpa_s->current_ssid->bssid[4],
			wpa_s->current_ssid->bssid[5]);
                eap_noob_json_object_set_new(info_obj,PEER_BSSID,eap_noob_json_string(bssid));
	}
	return info_obj;
}
/**
 * eap_noob_prepare_vers_arr : prepares a JSON array for Vers
 * @data: peer context
 * return : Json array/NULL
**/
static noob_json_t * eap_noob_prepare_vers_arr(const struct eap_noob_peer_context * data)
{
	noob_json_t * ver_arr = NULL;
	u32 count  = 0;

	if(!data || NULL == (ver_arr = eap_noob_json_array())){
		return NULL;
	}

	for(count = 0; count < MAX_SUP_VER ; count++){
		eap_noob_json_array_append(ver_arr,eap_noob_json_integer(data->serv_attr->version[count]));
	}

	return ver_arr;	
}

/**
 * eap_noob_prepare_csuites_arr : prepares a JSON array for Csuites
 * @data: peer context
 * return : Json array/NULL
**/

static noob_json_t * eap_noob_prepare_csuites_arr(const struct eap_noob_peer_context * data)
{
	noob_json_t * csuite_arr = NULL;
	u32 count  = 0;

	if(!data || NULL == (csuite_arr = eap_noob_json_array())){
                return NULL;
          }

          for(count = 0; count < MAX_SUP_CSUITES ; count++){
                  eap_noob_json_array_append(csuite_arr,eap_noob_json_integer(data->serv_attr->cryptosuite[count]));
          }
	
	return csuite_arr;
}
/**
 * eap_noob_prepare_mac_arr : Prepare a JSON array to generate MAC.
 * @data : peer context
 * @type : MAC type
 * state : EAP_NOOB state 
**/
static char * eap_noob_prepare_mac_arr(const struct eap_noob_peer_context * data, int type, int state){

	noob_json_t * mac_arr = NULL;
	noob_json_t * ver_arr = NULL;
	noob_json_t * csuite_arr = NULL;
	char * mac_str = NULL;
	noob_json_error_t error;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
	if(NULL != (mac_arr = eap_noob_json_array())){
		
		if(type == MACP){
			eap_noob_json_array_append(mac_arr,eap_noob_json_integer(1));
		}

		if(type == MACS){
			eap_noob_json_array_append(mac_arr,eap_noob_json_integer(2));
		}

		if((ver_arr = eap_noob_prepare_vers_arr(data)) == NULL)
			return NULL;

		eap_noob_json_array_append(mac_arr,ver_arr);
		eap_noob_json_array_append(mac_arr,eap_noob_json_integer(data->peer_attr->version));
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->serv_attr->peerID));

		
		if((csuite_arr = eap_noob_prepare_csuites_arr(data)) == NULL)
			return NULL;

		eap_noob_json_array_append(mac_arr,csuite_arr);

		if(state == COMPLETION_EXCHANGE){
			eap_noob_json_array_append(mac_arr,eap_noob_json_integer(data->serv_attr->dir));

		}else{
			eap_noob_json_array_append(mac_arr,eap_noob_json_string(""));
		}
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->serv_attr->serv_info));
		eap_noob_json_array_append(mac_arr,eap_noob_json_integer(data->peer_attr->cryptosuite));
		if(state == COMPLETION_EXCHANGE){
			eap_noob_json_array_append(mac_arr,eap_noob_json_integer(data->peer_attr->dir));
		}else{
			eap_noob_json_array_append(mac_arr,eap_noob_json_string(""));
		}
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->peer_attr->peer_info));
		if(state == RECONNECT_EXCHANGE){
			eap_noob_json_array_append(mac_arr,eap_noob_json_string(""));

		}else{
			eap_noob_json_array_append(mac_arr,eap_noob_json_loads(eap_noob_json_dumps(data->serv_attr->ecdh_exchange_data->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER),
					JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		}
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->serv_attr->kdf_nonce_data->nonce_serv_b64));
		if(state == RECONNECT_EXCHANGE){
			eap_noob_json_array_append(mac_arr,eap_noob_json_string(""));

		}else{
			eap_noob_json_array_append(mac_arr,eap_noob_json_loads(eap_noob_json_dumps(data->serv_attr->ecdh_exchange_data->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER),
						JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		}
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->serv_attr->kdf_nonce_data->nonce_peer_b64));
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->serv_attr->oob_data->noob_b64));


		wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
		mac_str = eap_noob_json_dumps(mac_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
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
static u8 * eap_noob_gen_MAC(const struct eap_noob_peer_context * data,int type, u8 * key, int keylen, int state){

	u8 * mac = NULL;
	char * mac_str = NULL;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);


	if(NULL != (mac_str = eap_noob_prepare_mac_arr(data, type,state))){
		printf("MAC_STR = %s\n", mac_str);
		printf("LENGTH = %d\n",(int)strlen(mac_str));
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KEY:",key,keylen);
		mac = HMAC(EVP_sha256(), key, keylen, (u8 *)mac_str, strlen(mac_str), NULL, NULL);
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MAC",mac,32);
	}

	return mac;

}

/**
 * eap_noob_get_noob : get nonce for OOB message
 * @data : peer context.
 * Returns : SUCCESS/FAILURE
**/ 
static int eap_noob_get_noob(struct eap_noob_peer_context *data){

	int rc = 0;
	unsigned long err = 0;
	if(NULL == (data->serv_attr->oob_data->noob = os_zalloc(EAP_NOOB_NONCE_LEN)))
		return FAILURE;

	if(1 != (rc = RAND_bytes(data->serv_attr->oob_data->noob, EAP_NOOB_NONCE_LEN))){
		err = ERR_get_error();
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);
		return FAILURE;
	}	

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Noob",data->serv_attr->oob_data->noob,16);
	eap_noob_Base64Encode(data->serv_attr->oob_data->noob, 16, &data->serv_attr->oob_data->noob_b64);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Noob Base64 %s", data->serv_attr->oob_data->noob_b64);

	return SUCCESS;
}

/**
 * eap_noob_send_oob : create noob and hood to send an oob message.
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_send_oob(struct eap_noob_peer_context *data){

	unsigned char * hoob_out = os_zalloc(HASH_LEN);
	/*generate NOOB*/
	if(!eap_noob_get_noob(data))
		return FAILURE;

	/*generate HOOB*/
	if(!eap_noob_get_hoob(data,hoob_out, HASH_LEN)){
		wpa_printf(MSG_DEBUG,"EAP-NOOB: ERROR in HOOB");
	}
	else{
		data->serv_attr->oob_data->hoob = hoob_out;
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: HOOB",data->serv_attr->oob_data->hoob,HASH_LEN);
		eap_noob_Base64Encode(data->serv_attr->oob_data->hoob, HASH_LEN, &data->serv_attr->oob_data->hoob_b64);
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Hoob Base64 %s", data->serv_attr->oob_data->hoob_b64);
	}
	return SUCCESS;
}


/**
 * eap_noob_calcDecodeLength : calculate length from base64url to ascii
 * @b64input : input base64url string
 * returns : length of input in ascii
**/

size_t eap_noob_calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
	       padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}


/**
 * eap_noob_Base64Decode :Decodes a base64url string.
 * @b64message : input base64url string
 * @buffer : output
 * @length : Converted string length.
 * Returns :  Converted string length.
**/

int eap_noob_Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen,i;
	
	int len = strlen(b64message);
	char * temp =NULL;

	switch (len % 4) // Pad with trailing '='s
	{
		case 0: temp = os_zalloc(len + 1);temp = strcpy(temp,b64message);break; // No pad chars in this case
		case 2: temp = os_zalloc(len + 3);strcpy(temp,b64message); strcat(temp,"==");break; // Two pad chars
		case 3: temp = os_zalloc(len +2);strcpy(temp,b64message); strcat(temp,"=");break; // One pad char
		default: return 0;
	}
	for(i=0;i< len;i++){
		if(temp[i] == '-'){
			temp[i] = '+';
		}else if(temp[i] == '_'){
			temp[i] = '/';
		}

	}

	decodeLen = eap_noob_calcDecodeLength(temp);
	*buffer = (unsigned char*)os_zalloc(decodeLen + 1);
	(*buffer)[decodeLen] = '\0';

	bio = BIO_new_mem_buf(temp, -1);
	b64 = BIO_new(BIO_f_base64());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
	*length = BIO_read(bio, *buffer, os_strlen(b64message));
	if(*length != decodeLen) return 0 ; //length should equal decodeLen, else something went horribly wrong

	os_free(temp);
	BIO_free_all(bio);

	return decodeLen; //success
}

/**
 * eap_noob_Base64Encode : Encode an ascii string to base64url
 * @buffer : input buffer
 * @length : input buffer length
 * @b64text : converted base64url text
 * Returns : SUCCESS/FAILURE
**/

int eap_noob_Base64Encode(const unsigned char* buffer, size_t length, char** b64text) { //Encodes a binary safe base 64 string
	BIO *bio, *b64;
	BUF_MEM *bufferPtr;
	char * temp;
	char * temp1;
	int len,i;

	b64 = BIO_new(BIO_f_base64());
	bio = BIO_new(BIO_s_mem());
	bio = BIO_push(b64, bio);

	BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Ignore newlines - write everything in one line
	BIO_write(bio, buffer, length);
	BIO_flush(bio);
	BIO_get_mem_ptr(bio, &bufferPtr);
	BIO_set_close(bio, BIO_NOCLOSE);

	temp = (char*) os_zalloc((bufferPtr->length + 1) * sizeof(char));
	os_memcpy(temp, bufferPtr->data, bufferPtr->length);
	temp[bufferPtr->length] = '\0';
	temp1 = strsep(&temp,"=");
	len = strlen(temp1);

	for(i=0;i<=len;i++){
		if(temp1[i] == '+'){
			temp1[i] = '-';
		}else if(temp1[i] == '/'){
			temp1[i] = '_';
		}

	}

	*b64text = (char*) os_zalloc((len + 1) * sizeof(char));
	strcpy(*b64text, temp1);
	(*b64text)[len] = '\0';

	//os_free(temp);
	BIO_free_all(bio);
	return (0); //success
}

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

int eap_noob_ECDH_KDF_X9_63(unsigned char *out, size_t outlen,
		const unsigned char *Z, size_t Zlen,
		const unsigned char *algorithm_id, size_t algorithm_id_len,
		const unsigned char * partyUinfo, size_t partyUinfo_len,
		const unsigned char * partyVinfo, size_t partyVinfo_len,
		const unsigned char * suppPrivinfo, size_t suppPrivinfo_len,
		const EVP_MD *md)
{
	EVP_MD_CTX *mctx = NULL;
	int rv = 0;
	unsigned int i;
	size_t mdlen;
	unsigned char ctr[4];
	wpa_printf(MSG_DEBUG,"EAP-NOOB: KDF start ");
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-OOB: Value:",Z,Zlen);	

	if (algorithm_id_len > ECDH_KDF_MAX || outlen > ECDH_KDF_MAX
			|| Zlen > ECDH_KDF_MAX || partyUinfo_len > ECDH_KDF_MAX 
			|| partyVinfo_len > ECDH_KDF_MAX || suppPrivinfo_len > ECDH_KDF_MAX)
		return 0;
	mctx = EVP_MD_CTX_create();
	if (mctx == NULL)
		return 0;
	mdlen = EVP_MD_size(md);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: KDF begin %d",(int)mdlen);
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
			if(!EVP_DigestUpdate(mctx, suppPrivinfo, suppPrivinfo_len))
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
 * eap_noob_prepare_hoob_arr : generate JSON array to calculate Hoob
 * @data: peer context
 * Returns : Json dump of hoob array on success or NULL on failure
**/
static char * eap_noob_prepare_hoob_arr(const struct eap_noob_peer_context * data){

	noob_json_t * hoob_arr = NULL;
	noob_json_t * ver_arr = NULL;
	char * hoob_str = NULL;
	noob_json_error_t error;
	noob_json_t * csuite_arr = NULL;
	int dir = (data->serv_attr->dir & data->peer_attr->dir);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
	if(NULL != (hoob_arr = eap_noob_json_array())){
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(dir));

		if((ver_arr = eap_noob_prepare_vers_arr(data)) == NULL)
			return NULL;

		eap_noob_json_array_append(hoob_arr,ver_arr);
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->peer_attr->version));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->serv_attr->peerID));

		if((csuite_arr = eap_noob_prepare_csuites_arr(data)) == NULL)
			return NULL;

		eap_noob_json_array_append(hoob_arr,csuite_arr);

		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->serv_attr->dir));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->serv_attr->serv_info));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->peer_attr->cryptosuite));
			
		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->peer_attr->dir));
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->peer_attr->peer_info));
			
		eap_noob_json_array_append(hoob_arr,eap_noob_json_loads(eap_noob_json_dumps(data->serv_attr->ecdh_exchange_data->jwk_serv,
			JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->serv_attr->kdf_nonce_data->nonce_serv_b64));
			
		eap_noob_json_array_append(hoob_arr,eap_noob_json_loads(eap_noob_json_dumps(data->serv_attr->ecdh_exchange_data->jwk_peer,
			JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->serv_attr->kdf_nonce_data->nonce_peer_b64));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->serv_attr->oob_data->noob_b64));

		hoob_str = eap_noob_json_dumps(hoob_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
	}

	free(ver_arr);
	free(csuite_arr);
	return hoob_str;
}

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


	if(NULL != (hoob_string = eap_noob_prepare_hoob_arr(data))){
		hoob_str_len = os_strlen(hoob_string);
	
		printf("HOOB string  = %s\n length = %d\n",hoob_string,hoob_str_len);
		wpa_printf(MSG_DEBUG,"EAP-NOOB: HOOB start ");
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-OOB: Value:",hoob_string, hoob_str_len);	


		return eap_noob_prepare_hash(out, outlen,hoob_string,hoob_str_len);
	}

	return FAILURE;
}


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
	x_len = eap_noob_Base64Decode(data->serv_attr->ecdh_exchange_data->x_serv_b64, &x, &len);
	y_len = eap_noob_Base64Decode(data->serv_attr->ecdh_exchange_data->y_serv_b64, &y, &len);

	
	wpa_printf(MSG_DEBUG, "EAP-NOOB: deriving NID_secp256k1.");
	ec_pub_server = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (ec_pub_server == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create EC_KEYs");
		return 1;
	}

	/* Get the group used */
	ec_group = EC_KEY_get0_group(ec_pub_server);
	if(ec_group == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get GROUP");
		return 1;
	}


	x_big = BN_bin2bn(x,x_len,NULL);
	y_big = BN_bin2bn(y,y_len,NULL);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_POINT_bn2point");
	ecpoint_pub_server = EC_POINT_new(ec_group);
	if(EC_POINT_set_affine_coordinates_GFp(ec_group, ecpoint_pub_server, x_big, y_big,NULL) ==0)
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in affine coordinate setting");


	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key");

	if (!EC_KEY_set_public_key(ec_pub_server, ecpoint_pub_server)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to SET Peer PUB KEY EC_POINT to EC_KEY.");
		return 1;
	}
	wpa_printf(MSG_DEBUG, "EAP-NOOB: EVP_PKEY_set1_EC_KEY");

	/* Create the context for parameter generation */
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
		return 1;
	}

	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(pctx)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to initialize parameter generation.");
		return 1;
	}

	/* We're going to use the ANSI X9.62 Prime 256k1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_secp256k1)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to select the curve.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key done before");

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(pctx, &evp_server)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create parameter object params.");
		return 1;
	}
	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key done");


	if (!EVP_PKEY_set1_EC_KEY(evp_server, ec_pub_server)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to CONVERT EC_KEY to EVP_PKEY.");
		return 1;
	}
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret!.");


	/* Derive the secret */
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 1.");

	/* Create the context for the shared secret derivation */
	if(NULL == (ctx = EVP_PKEY_CTX_new(data->serv_attr->ecdh_exchange_data->dh_key, NULL))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to create EVP_PKEY_CTX_new.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 2.");
	/* Initialise */
	if(1 != EVP_PKEY_derive_init(ctx)) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to EVP_PKEY_derive_init.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 3.");
	/* Provide the server public key */
	if(1 != EVP_PKEY_derive_set_peer(ctx, evp_server)) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to EVP_PKEY_derive_set_peer.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 4.");
	/* Determine buffer length for shared secret */
	if(1 != EVP_PKEY_derive(ctx, NULL, secret_len)) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to determine buffer length EVP_PKEY_derive.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 5.");

	/* Create the buffer */
	if(NULL == (data->serv_attr->ecdh_exchange_data->shared_key = OPENSSL_malloc(*secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to create buffer OPENSSL_malloc.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 6.");

	/* Derive the shared secret */
	if(1 != (EVP_PKEY_derive(ctx, data->serv_attr->ecdh_exchange_data->shared_key, secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to derive key EVP_PKEY_derive.");
		return 1;
	}
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",data->serv_attr->ecdh_exchange_data->shared_key,*secret_len);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(evp_server);

	return 0;
}


/**
 * get_key - Generate Priv/Pub key pair based on the Csuite selected.
 * @data: Pointer to EAP-NOOB data
 * Returns: 1 if keys generated and stored successfully, or 0 if not
 **/
static int eap_noob_get_key(struct eap_noob_serv_data *data)
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
	if(NULL == (pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL))){	
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for parameter generation.");
		return 0;
	}

	/* Initialise the parameter generation */
	if(1 != EVP_PKEY_paramgen_init(pctx)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to initialize parameter generation.");
		return 0;
	}

	/* We're going to use the ANSI X9.62 Prime 256k1 curve */
	if(1 != EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx,NID_secp256k1)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to select the curve.");
		return 0;
	}

	/* Create the parameter object params */
	if (!EVP_PKEY_paramgen(pctx, &params)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create parameter object params.");
		return 0;
	}

	/* Create the context for the key generation */
	if(NULL == (kctx = EVP_PKEY_CTX_new(params, NULL))){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create context for key generation.");
		return 0;
	}

	/* Generate the key */
	if(1 != EVP_PKEY_keygen_init(kctx)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to initialize to generate keys.");
		return 0;
	}
	if (1 != EVP_PKEY_keygen(kctx, &data->ecdh_exchange_data->dh_key)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to generate keys.");
		return 0;
	}

	key = EVP_PKEY_get1_EC_KEY(data->ecdh_exchange_data->dh_key);

	if(key == NULL)
	{		
		wpa_printf(MSG_DEBUG, "EAP-NOOB: No Key Returned from EVP.");
		return 0;
	}

	/* Get the group used */
	group = EC_KEY_get0_group(key);
	if(group == NULL) {
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
	if(EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, NULL) != 1)
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in coordinates"); 

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", x, 32);

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", y, 32);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Before mem alloc");
	x_len = BN_num_bytes(x);
	y_len = BN_num_bytes(y);
	x_val = os_zalloc(x_len);
	y_val = os_zalloc(y_len);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Before bin conversion");
	if(BN_bn2bin(x,x_val) == 0 || BN_bn2bin(y,y_val) == 0)
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Error converting to Bin");

	eap_noob_Base64Encode(x_val,x_len, &data->ecdh_exchange_data->x_b64);
	eap_noob_Base64Encode(y_val,y_len, &data->ecdh_exchange_data->y_b64);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: X and Y %s,%s",data->ecdh_exchange_data->x_b64, data->ecdh_exchange_data->y_b64);

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", x_val, x_len);	
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Y coordinate", y_val, y_len);

	return 1;
}


/**
 * eap_noob_verify_param_len : verify lengths of string type parameters 
 * @data : peer context
**/
static void eap_noob_verify_param_len(struct eap_noob_serv_data * data)
{

        u32 count  = 0;
        u32 pos = 0x01;

        if(NULL == data){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return ;
        }

        for(count  = 0; count < 32; count++){

                if(data->rcvd_params & pos){
                        switch(pos){

                                case PEERID_RCVD:
                                        if(strlen(data->peerID) > MAX_PEER_ID_LEN){
						data->err_code = E1003;
                                        }
                                        break;
                                case NONCE_RCVD:
                                        if(strlen((char *)data->kdf_nonce_data->nonce_serv) > EAP_NOOB_NONCE_LEN){
						data->err_code = E1003;
                                        }
                                        break;
                                case MAC_RCVD:
                                        if(strlen(data->MAC) > MAC_LEN){
						data->err_code = E1003;
                                        }
                                        break;
                                case INFO_RCVD:
                                        if(strlen(data->serv_info) > MAX_INFO_LEN){
						data->err_code = E1003;
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

static void  eap_noob_decode_obj(struct eap_noob_serv_data * data ,noob_json_t * req_obj){

	const char * key;
	noob_json_t * value;
	size_t arr_index;
	noob_json_t *arr_value;

	size_t decode_length;
	size_t decode_length_nonce;

	int retval_int = 0;
	const char* retval_char = NULL;
	noob_json_error_t  error;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB DECODE OBJECT");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return;		
	}
	json_object_foreach(req_obj, key, value) {

		switch(eap_noob_json_typeof(value)){
			case JSON_OBJECT:
				if(0 == strcmp(key,JSON_WEB_KEY)){
					data->rcvd_params |= PKEY_RCVD;
					wpa_printf(MSG_DEBUG,"EAP-NOOB:Copy Verify %s",eap_noob_json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER));
					data->ecdh_exchange_data->jwk_serv = eap_noob_json_loads(eap_noob_json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER),
								JSON_COMPACT|JSON_PRESERVE_ORDER,&error);
					wpa_printf(MSG_DEBUG,"EAP-NOOB:Copy Verify %s",eap_noob_json_dumps(data->ecdh_exchange_data->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER));
				}else if(0 == strcmp(key, SERV_INFO)){
					data->rcvd_params |= INFO_RCVD;
					data->serv_info = eap_noob_json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER);
					wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv Info %s",data->serv_info);

				}
				eap_noob_decode_obj(data,value);
				break;

			case JSON_INTEGER:

				if(0 == (retval_int = eap_noob_json_integer_value(value)) && 0 != strcmp(key,TYPE)){
					data->err_code = E1003;
					return;
				}
				else if(0 == strcmp(key, DIRECTION_SERV)){
					data->dir = retval_int;
					data->rcvd_params |= DIRECTION_RCVD;
				}
				else if(0 == strcmp(key, MINSLEEP)){
					data->minsleep = retval_int;
					data->rcvd_params |= MINSLP_RCVD;
				}
				else if(0 == strcmp(key, ERR_CODE)){
					data->err_code = retval_int;
				}
				break;

			case JSON_STRING:

				if(NULL == (retval_char = eap_noob_json_string_value(value))){
					data->err_code = E1003;
					return;
				}

				if(0 == strcmp(key, PEERID)){
					data->peerID = os_strdup(retval_char);
					data->rcvd_params |= PEERID_RCVD;

				}

				else if(0 == strcmp(key, NONCE_SERV)){ 
					data->kdf_nonce_data->nonce_serv_b64 = os_strdup(retval_char);
					eap_noob_Base64Decode(data->kdf_nonce_data->nonce_serv_b64, &data->kdf_nonce_data->nonce_serv, &decode_length_nonce);
					data->rcvd_params |= NONCE_RCVD;

				}

				else if(0 == strcmp(key, MAC_SERVER)){
					eap_noob_Base64Decode((char *)retval_char, (u8**)&data->MAC,&decode_length);	
					data->rcvd_params |= MAC_RCVD;
				}
				else if(0 == strcmp(key, X_COORDINATE)){
					data->ecdh_exchange_data->x_serv_b64 = os_strdup(eap_noob_json_string_value(value));
					wpa_printf(MSG_DEBUG, "X coordinate %s", data->ecdh_exchange_data->x_serv_b64);
				}else if(0 == strcmp(key, Y_COORDINATE)){
					data->ecdh_exchange_data->y_serv_b64 = os_strdup(eap_noob_json_string_value(value));
					wpa_printf(MSG_DEBUG, "Y coordinate %s", data->ecdh_exchange_data->y_serv_b64);
				}
				break;

			case JSON_ARRAY:
				if(0 == strcmp(key,VERSION_SERV)){
					json_array_foreach(value, arr_index, arr_value) {
						if(eap_noob_json_is_integer(arr_value)){
							data->version[arr_index] = eap_noob_json_integer_value(arr_value);
							printf("ARRAY value = %d\n",data->version[arr_index]);
						}else{
							data->err_code = E1003;
							return;		
						}
					}
					data->rcvd_params |= VERSION_RCVD;
				}
				else if(0 == strcmp(key,CSUITES_SERV)){
					json_array_foreach(value, arr_index, arr_value) {
						if(eap_noob_json_is_integer(arr_value)){
							data->cryptosuite[arr_index] = eap_noob_json_integer_value(arr_value);
							printf("ARRAY value = %d\n",data->cryptosuite[arr_index]);
						}else{
							data->err_code = E1003;
							return;		
						}
					}
					data->rcvd_params |= CSUITE_RCVD;
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
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB ASSIGN WAIT TIME");
	clock_gettime(CLOCK_BOOTTIME, &tv);
	wpa_s->current_ssid->disabled_until.sec = tv.tv_sec + data->serv_attr->minsleep;
	wpa_blacklist_add(wpa_s, wpa_s->current_ssid->bssid);
	printf("\n %s  *******************************************EAP-NOOB: now : %ld  disabled untill = %ld\n",wpa_s->current_ssid->ssid,tv.tv_sec ,wpa_s->current_ssid->disabled_until.sec);

}

/**
 * eap_noob_check_compatibility : check peer's compatibility with server. 
     The type 1 message params are used for making any dicision
 *@data : peer context
 * Returns : SUCCESS/FAILURE
**/
int eap_noob_check_compatibility(struct eap_noob_peer_context *data)
{

	u32 count = 0;
	u8 vers_supported = 0;
	u8 csuite_supp = 0;

	if(0 == (data->peer_attr->dir & data->serv_attr->dir)){
		data->serv_attr->err_code = E3003;		
		return FAILURE;
	}

	for(count = 0; count < MAX_SUP_CSUITES ; count ++){
		if(0 != (data->peer_attr->cryptosuite & data->serv_attr->cryptosuite[count])){
			csuite_supp = 1;
		}
	}

	if(csuite_supp == 0){
		data->serv_attr->err_code = E3002;
		return FAILURE;
	}

	for(count = 0; count < MAX_SUP_VER ; count ++){
		if(0 != (data->peer_attr->version & data->serv_attr->version[count])){
			vers_supported = 1;
		}
	}

	if(vers_supported == 0){
		data->serv_attr->err_code = E3001;		
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
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

	if(wpa_s){
		snprintf(buff,120,"%s+s%d@eap-noob.net",data->peer_attr->peerID, data->serv_attr->state);
		len = os_strlen(buff);

		os_free(wpa_s->current_ssid->eap.identity);

		wpa_s->current_ssid->eap.identity = os_malloc(os_strlen(buff));

		os_memcpy(wpa_s->current_ssid->eap.identity, buff, len);
		wpa_s->current_ssid->eap.identity_len = len;

		wpa_config_write(wpa_s->confname,wpa_s->conf);			
	}		

}

/**
 * eap_noob_db_entry_check : check for an peerID entry inside the DB
 * @priv : server context
 * @argc : argument count
 * @argv : argument 2d array
 * @azColName : colomn name 2d array 
**/
int eap_noob_db_entry_check(void * priv , int argc, char **argv, char **azColName){

	struct eap_noob_serv_data *data = priv;

	if(strtol(argv[0],NULL,10) == 1){
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
static int eap_noob_decode_vers_array(char * array, struct eap_noob_serv_data *data)
{
	noob_json_t * ver_arr = NULL;
	size_t index;
	noob_json_t *value;

	if(array == NULL || NULL == (ver_arr = eap_noob_json_loads(array, JSON_COMPACT,NULL)))
		return FAILURE;

	JSON_ARRAY_FOREACH(ver_arr, index, value){
		data->version[index] = json_integer_value(value);
	}
	return SUCCESS;	
}
/**
 * eap_noob_decode_csuites_array : assigns the values of Csuites JSON array to csuite array
 * @data: Server context
 * @array: Csuites JSON array
 * Returns: SUCCESS/FAILURE 
**/

static int eap_noob_decode_csuites_array(char * array, struct eap_noob_serv_data *data)
{
	noob_json_t * csuites_arr = NULL;
	size_t index;
	noob_json_t *value;

	if(array == NULL || NULL == (csuites_arr = eap_noob_json_loads(array, JSON_COMPACT,NULL)))
		return FAILURE;

	JSON_ARRAY_FOREACH(csuites_arr, index, value){
		data->cryptosuite[index] =  json_integer_value(value);
	}
	
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
	struct eap_noob_serv_data *data = peer->serv_attr;
	int count  = 0;

	size_t len;
	noob_json_error_t error;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB CALLBACK");

	for (count =0; count <argc; count++) {

		if (argv[count] && azColName[count]) {
			//printf("TOKEN = %s COLUMN = %s\n ", argv[count], azColName[count]);
			if (os_strcmp(azColName[count], "ssid") == 0) {
				if(NULL != data->ssid)
					os_free(data->ssid);
				data->ssid = os_malloc(os_strlen(argv[count])+1);
				strcpy(data->ssid, argv[count]);
			}
			else if (os_strcmp(azColName[count], "PeerID") == 0) {
				if(NULL != data->peerID)
					os_free(data->peerID);

				data->peerID = os_malloc(os_strlen(argv[count]));
				strcpy(data->peerID, argv[count]);
			}
			else if (os_strcmp(azColName[count], "Vers") == 0) {
				//data->version[0] = (int) strtol(argv[count], NULL, 10);
				eap_noob_decode_vers_array(argv[count], data);
				printf("***************VERSION = %d\n", data->version[0]);
			}
			else if (os_strcmp(azColName[count], "Verp") == 0) {
				peer->peer_attr->version = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "state") == 0) {
				data->state = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "Csuites") == 0) {
				//data->cryptosuite[0] = (int) strtol(argv[count], NULL, 10);
				eap_noob_decode_csuites_array(argv[count], data);
				printf("****************CSUITE = %d\n",data->version[0]);
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
			else if (os_strcmp(azColName[count], "nonce_peer") == 0) {
				if(NULL != data->kdf_nonce_data->nonce_peer_b64)
					os_free(data->kdf_nonce_data->nonce_peer_b64);

				data->kdf_nonce_data->nonce_peer_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kdf_nonce_data->nonce_peer_b64, argv[count]);

				eap_noob_Base64Decode(data->kdf_nonce_data->nonce_peer_b64, &data->kdf_nonce_data->nonce_peer, &len); //To-Do check for length

			}	
			else if (os_strcmp(azColName[count], "nonce_serv") == 0) {
				if(NULL != data->kdf_nonce_data->nonce_serv_b64)
					os_free(data->kdf_nonce_data->nonce_serv_b64);

				data->kdf_nonce_data->nonce_serv_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kdf_nonce_data->nonce_serv_b64, argv[count]);

				eap_noob_Base64Decode(data->kdf_nonce_data->nonce_serv_b64, &data->kdf_nonce_data->nonce_serv, &len); //To-Do check for length

			}
			else if (os_strcmp(azColName[count], "minsleep") == 0) {
				data->minsleep = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "ServInfo") == 0) {
				if(NULL != data->serv_info)
					os_free(data->serv_info);

				data->serv_info = os_malloc(os_strlen(argv[count]));
				strcpy(data->serv_info, argv[count]);
			}
			else if (os_strcmp(azColName[count], "PeerInfo") == 0) {
				if(NULL != peer->peer_attr->peer_info)
					os_free(peer->peer_attr->peer_info);

				peer->peer_attr->peer_info = os_malloc(os_strlen(argv[count]));
				strcpy(peer->peer_attr->peer_info, argv[count]);
			}
			else if (os_strcmp(azColName[count], "SharedSecret") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->ecdh_exchange_data->shared_key_b64)
					os_free(data->ecdh_exchange_data->shared_key_b64);

				data->ecdh_exchange_data->shared_key_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->ecdh_exchange_data->shared_key_b64, argv[count]);
				eap_noob_Base64Decode(data->ecdh_exchange_data->shared_key_b64, &data->ecdh_exchange_data->shared_key, &len);
			}
			else if (os_strcmp(azColName[count], "Noob") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->oob_data->noob_b64)
					os_free(data->oob_data->noob_b64);

				data->oob_data->noob_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->oob_data->noob_b64, argv[count]);

				eap_noob_Base64Decode(data->oob_data->noob_b64, &data->oob_data->noob, &len);
			}	
			else if (os_strcmp(azColName[count], "Hoob") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->oob_data->hoob_b64)
					os_free(data->oob_data->hoob_b64);

				data->oob_data->hoob_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->oob_data->hoob_b64, argv[count]);
				wpa_printf(MSG_DEBUG,"EAP-NOOB: HOOB: %s",argv[count]);

				eap_noob_Base64Decode(data->oob_data->hoob_b64, &data->oob_data->hoob, &len);
			}else if (os_strcmp(azColName[count], "pub_key_serv") == 0){
				data->ecdh_exchange_data->jwk_serv = eap_noob_json_loads(argv[count], JSON_COMPACT|JSON_PRESERVE_ORDER, &error); //ToDo: check and free this before assigning if required
				wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv_KEY: %s",argv[count]);

			}else if (os_strcmp(azColName[count], "pub_key_peer") == 0){
				data->ecdh_exchange_data->jwk_peer = eap_noob_json_loads(argv[count], JSON_COMPACT|JSON_PRESERVE_ORDER, &error); //ToDo: check and free this before assigning if required
				wpa_printf(MSG_DEBUG,"EAP-NOOB:Peer_KEY: %s",argv[count]);
			}
			else if (os_strcmp(azColName[count], "kms") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->kdf_out->kms_b64)
					os_free(data->kdf_out->kms_b64);

				data->kdf_out->kms_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kdf_out->kms_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kms");
				eap_noob_Base64Decode(data->kdf_out->kms_b64, &data->kdf_out->kms, &len);
			}	
			else if (os_strcmp(azColName[count], "kmp") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->kdf_out->kmp_b64)
					os_free(data->kdf_out->kmp_b64);

				data->kdf_out->kmp_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kdf_out->kmp_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kmp");
				eap_noob_Base64Decode(data->kdf_out->kmp_b64, &data->kdf_out->kmp, &len);
			}	
			else if (os_strcmp(azColName[count], "kz") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->kdf_out->kz_b64)
					os_free(data->kdf_out->kz_b64);

				data->kdf_out->kz_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kdf_out->kz_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kz");
				eap_noob_Base64Decode(data->kdf_out->kz_b64, &data->kdf_out->kz, &len);
			}		
		}
	}

	return 0;
}


/**
 * eap_noob_exec_query : wrapper function to execute a sql query
 * @query : query to be executed
 * @callback : pointer to callback function 
 * @argv : parmeter to callback function
 * @data : peer context
 * Returns  :  SUCCESS/FAILURE
**/

static int eap_noob_exec_query(const char * query, int(*callback)(void*, int ,char **, char ** ), 
		void * argv, struct eap_noob_peer_context *data){

	char * sql_error = NULL;
	
	if(NULL == data){
		wpa_printf(MSG_ERROR, "EAP-NOOB: Peer context null");
		return FAILURE;	
	}
	
	if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
        		wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
                	return FAILURE;
        	}

	if(SQLITE_OK != sqlite3_exec(data->peerDB, query,callback, argv, &sql_error)){
		if (sql_error!=NULL) {
			wpa_printf(MSG_DEBUG,"EAP_NOOB: sql error : %s\n",sql_error);
			sqlite3_free(sql_error);
		}
		if(SQLITE_OK != sqlite3_close(data->peerDB)){
                        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
                }

		wpa_printf(MSG_ERROR,"Failed to Query DB");
		return FAILURE;
	}

	if(SQLITE_OK != sqlite3_close(data->peerDB)){
                        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
        }
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);

	return SUCCESS;

}

/**
 * eap_noob_db_update : prepare a DB update query
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_db_update (struct eap_noob_peer_context *data, u8 type)
{

	char * query = os_zalloc(MAX_QUERY_LEN);

	switch(type){

		case UPDATE_STATE: 
			snprintf(query,MAX_QUERY_LEN,"UPDATE '%s' SET state=%d WHERE PeerID='%s'", 
					data->db_table_name, data->serv_attr->state, data->serv_attr->peerID);
			break;
		case UPDATE_PERSISTENT_KEYS_SECRET:
			snprintf(query,MAX_QUERY_LEN,"UPDATE '%s' SET kms='%s', kmp='%s', kz='%s', state=%d WHERE PeerID='%s'", 
				data->db_table_name, data->serv_attr->kdf_out->kms_b64,data->serv_attr->kdf_out->kmp_b64,data->serv_attr->kdf_out->kz_b64,
				data->serv_attr->state, data->serv_attr->peerID);
			break;
		case UPDATE_OOB:
			snprintf(query,MAX_QUERY_LEN,"UPDATE '%s' SET Noob='%s', Hoob='%s', show_OOB=%d WHERE PeerID='%s'", 
				data->db_table_name, data->serv_attr->oob_data->noob_b64,
				data->serv_attr->oob_data->hoob_b64, 1, data->serv_attr->peerID);
			break;

		case UPDATE_STATE_ERROR:
			snprintf(query,MAX_QUERY_LEN,"UPDATE '%s' SET err_code=%d WHERE PeerID='%s'", 
				data->db_table_name, data->serv_attr->err_code, data->serv_attr->peerID);
			break;

		default:
               		wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
               		return FAILURE;
	}
	
	printf("QUERY = %s\n",query);	
	if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data)){
			wpa_printf(MSG_ERROR, "EAP-NOOB: DB update failed");
			os_free(query);
			return FAILURE;
		}

	os_free(query);
	return SUCCESS;
}

/**
 * eap_noob_db_entry : Make an entery of the current SSID context inside the DB
 * @sm : eap statemachine context
 * @data : peer context
 * Returns : FAILURE/SUCCESS
**/
static int eap_noob_db_entry(struct eap_sm *sm,struct eap_noob_peer_context *data)
{
	char * query = os_zalloc(MAX_QUERY_LEN);
	noob_json_t * vers_arr = NULL;
	noob_json_t * csuites_arr = NULL;
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

	if((vers_arr = eap_noob_prepare_vers_arr(data)) == NULL)
		return FAILURE;
	if((csuites_arr = eap_noob_prepare_csuites_arr(data)) == NULL){
		os_free(vers_arr);
		return FAILURE;
	}

	printf(" Ver = %s\n csuite = %s\n",eap_noob_json_dumps(vers_arr,JSON_COMPACT),eap_noob_json_dumps(csuites_arr,JSON_COMPACT));

	snprintf(query,MAX_QUERY_LEN,"INSERT INTO %s (ssid, PeerID, Vers,Verp, state, Csuites,Csuitep,Dirs,Dirp, "
			"nonce_peer, nonce_serv, minsleep,ServInfo, PeerInfo,SharedSecret, Noob, Hoob," 
			" OOB_RECEIVED_FLAG,pub_key_serv,pub_key_peer,err_code)"
			"VALUES ('%s','%s','%s', %d, %d, '%s', %d, %d ,%d,'%s','%s', %d, '%s', '%s','%s',"
			" '%s', '%s', %d, '%s', '%s',%d)", data->db_table_name,
			wpa_s->current_ssid->ssid,data->serv_attr->peerID, eap_noob_json_dumps(vers_arr,JSON_COMPACT),
			data->peer_attr->version,data->serv_attr->state,  
			eap_noob_json_dumps(csuites_arr,JSON_COMPACT), data->peer_attr->cryptosuite,
			data->serv_attr->dir,data->peer_attr->dir,
			data->serv_attr->kdf_nonce_data->nonce_peer_b64, data->serv_attr->kdf_nonce_data->nonce_serv_b64,
			data->serv_attr->minsleep, data->serv_attr->serv_info, 
			data->peer_attr->peer_info,data->serv_attr->ecdh_exchange_data->shared_key_b64,
			"","",0,(eap_noob_json_dumps(data->serv_attr->ecdh_exchange_data->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER)),
			(eap_noob_json_dumps(data->serv_attr->ecdh_exchange_data->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER)),data->serv_attr->err_code);

	printf("QUERY = %s\n",query);

	if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data)){
		//sqlite3_close(data->peerDB);
		wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
		//TODO: free data here.
		os_free(query);	
		return FAILURE;
	}
	os_free(query);	
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
	return SUCCESS;
}

/**
 * eap_noob_err_msg : prepares error message 
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null 
**/
static struct wpabuf * eap_noob_err_msg(struct eap_noob_peer_context *data, u8 id)
{
	noob_json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;
	int code = data->serv_attr->err_code;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error request");
	if (!code)
		return NULL;

	if(NULL != (req_obj = eap_noob_json_object())){

		if(data->peer_attr->peerID){
			eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID));
		}
		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(NONE));
		eap_noob_json_object_set_new(req_obj,ERR_CODE,eap_noob_json_integer(error_code[code]));
		eap_noob_json_object_set_new(req_obj,ERR_INFO,eap_noob_json_string((char *)error_info[code]));

		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT);
		printf("ERROR message = %s\n",req_json);
		len = strlen(req_json)+1;

		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);

		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for NOOB ERROR message");
			os_free(req_json);
			return NULL;
		}

		wpabuf_put_data(req,req_json,len);
		os_free(req_json);
		data->serv_attr->err_code = NO_ERROR;
	}
	return req;
}

/**
 * eap_noob_verify_peerID : compares recived PeerID with the assigned one
 * @data : peer context
 * @id : response message ID
**/
static struct wpabuf * eap_noob_verify_peerID(struct eap_noob_peer_context * data, u8  id)
{

	struct wpabuf *resp = NULL;

	if((data->serv_attr->peerID) && (data->peer_attr->peerID) && 
			(0 != strcmp(data->peer_attr->peerID,data->serv_attr->peerID))){	
		data->serv_attr->err_code = E1005;
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

static struct wpabuf * eap_noob_rsp_type_four(const struct eap_noob_peer_context *data, u8 id){

	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;
	u8 * mac = NULL;
	char * mac_b64 = NULL;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 4");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	if(NULL != (rsp_obj = eap_noob_json_object())){

		mac = eap_noob_gen_MAC(data,MACP,data->serv_attr->kdf_out->kmp, KMP_LEN,COMPLETION_EXCHANGE);
		//TODO: handle NULL return value
		eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_4));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID));
		eap_noob_json_object_set_new(rsp_obj,MAC_PEER,eap_noob_json_string(mac_b64));

		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT);
		len = strlen(resp_json)+1;

		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}

		wpabuf_put_data(resp,resp_json,len);	
	}

	return resp;

}

/**
 * eap_noob_rsp_type_three : prepares message type three
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null 
**/
static struct wpabuf * eap_noob_rsp_type_three(const struct eap_noob_peer_context *data, u8 id){

	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 3");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	if(NULL != (rsp_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_3));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID));

		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT);
		len = strlen(resp_json)+1;

		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}

		wpabuf_put_data(resp,resp_json,len);	
	}

	return resp;

}

/**
 *  eap_noob_build_JWK : Builds a JWK object to send in the inband message
 *  @jwk : output json object
 *  @x_64 : x co-ordinate in base64url format
 *  @y_64 : y co-ordinate in base64url format
 *  Returns : FAILURE/SUCCESS
**/
static int eap_noob_build_JWK( noob_json_t ** jwk, const char * x_b64, const char * y_b64) {

	if(NULL != ((*jwk) = eap_noob_json_object())){
		eap_noob_json_object_set_new((*jwk), KEY_TYPE, eap_noob_json_string("EC"));
		eap_noob_json_object_set_new((*jwk), CURVE, eap_noob_json_string("P-256"));
	}else{
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in JWK");
		return FAILURE;
	}

	if(NULL == x_b64 || NULL == y_b64){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: CO-ORDINATES are NULL!!");
		return FAILURE;
	
	}
	eap_noob_json_object_set_new((*jwk), X_COORDINATE, eap_noob_json_string(x_b64));
	eap_noob_json_object_set_new((*jwk), Y_COORDINATE, eap_noob_json_string(y_b64));
	wpa_printf(MSG_DEBUG, "JWK Key %s",eap_noob_json_dumps((*jwk),JSON_COMPACT));
	return SUCCESS;
}

/**
 * eap_noob_rsp_type_two : prepares message type two
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null 
**/

static struct wpabuf * eap_noob_rsp_type_two(struct eap_noob_peer_context *data, u8 id){

	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	//char* base64_pubkey;
	char* base64_nonce;
	size_t secret_len = EAP_SHARED_SECRET_LEN;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	data->serv_attr->kdf_nonce_data->nonce_peer = os_zalloc(EAP_NOOB_NONCE_LEN);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 1");
	int rc = RAND_bytes(data->serv_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);
	unsigned long err = ERR_get_error();	

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 2");
	if(rc != 1) {

		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);	
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 3");
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->serv_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 4");
	/* Generate Key material */
	if (eap_noob_get_key(data->serv_attr) == 0)  {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
		return NULL;
	}

	if(FAILURE == eap_noob_build_JWK(&data->serv_attr->ecdh_exchange_data->jwk_peer, 
                             data->serv_attr->ecdh_exchange_data->x_b64, data->serv_attr->ecdh_exchange_data->y_b64)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to build JWK");
		return NULL;
	}
	eap_noob_Base64Encode(data->serv_attr->kdf_nonce_data->nonce_peer,EAP_NOOB_NONCE_LEN, &base64_nonce);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s",base64_nonce);

	data->serv_attr->kdf_nonce_data->nonce_peer_b64 = base64_nonce;

	if(NULL != (rsp_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_2));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID));
		eap_noob_json_object_set_new(rsp_obj,NONCE_PEER,eap_noob_json_string(base64_nonce));
		eap_noob_json_object_set_new(rsp_obj,JSON_WEB_KEY,data->serv_attr->ecdh_exchange_data->jwk_peer);

		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
		len = strlen(resp_json)+1;
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Json %s",resp_json);
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}

		wpabuf_put_data(resp,resp_json,len);			
	}

	eap_noob_derive_secret(data,&secret_len);
	data->serv_attr->ecdh_exchange_data->shared_key_b64_len = eap_noob_Base64Encode(data->serv_attr->ecdh_exchange_data->shared_key, 
		EAP_SHARED_SECRET_LEN, &data->serv_attr->ecdh_exchange_data->shared_key_b64);

	return resp;

}


/**
 * eap_noob_rsp_type_one : prepares message type one
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null 
**/
static struct wpabuf * eap_noob_rsp_type_one(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id){

	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	//TODO: generate a fresh nonce here
	if(NULL != (rsp_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_1));
		eap_noob_json_object_set_new(rsp_obj,VERSION_PEER,eap_noob_json_integer(data->peer_attr->version));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->serv_attr->peerID));
		eap_noob_json_object_set_new(rsp_obj,CSUITES_PEER,eap_noob_json_integer(data->peer_attr->cryptosuite));
		eap_noob_json_object_set_new(rsp_obj,DIRECTION_PEER,eap_noob_json_integer(data->peer_attr->dir));
		eap_noob_json_object_set_new(rsp_obj,PEERINFO,eap_noob_prepare_peer_info_json(sm,data->peer_attr->peer_config_params));

		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
		len = strlen(resp_json)+1;
		printf("RESPONSE = %s\n", resp_json);	
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}	
		wpabuf_put_data(resp,resp_json,len);	

	}

	return resp;

}

static int eap_noob_prepare_hint(const struct eap_noob_peer_context *data,u8 * hint)
{
	char * hint_str = NULL;
	int hint_str_len = 0;
	int noob_len = strlen(data->serv_attr->oob_data->noob_b64);
	int salt_len = strlen(HINT_SALT);
	
	hint_str = malloc(noob_len+salt_len);

	if(hint_str){
		memset(hint_str,0,noob_len+salt_len);
		printf("noob= %s len = %d\n",data->serv_attr->oob_data->noob_b64,noob_len);
		strcat(hint_str,data->serv_attr->oob_data->noob_b64);
		strcat(hint_str,HINT_SALT);
		printf("HINT string = %s\n",hint_str);
		hint_str_len = strlen(hint_str);
		eap_noob_prepare_hash(hint, HASH_LEN+8, hint_str,hint_str_len);	
		os_free(hint_str);
		return SUCCESS;	
	}

	return FAILURE;
}	


static struct wpabuf * eap_noob_rsp_hint(const struct eap_noob_peer_context *data, u8 id)
{
	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;
	char hint[HASH_LEN+8] = {0};
	char * hint_b64 = NULL;

	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}
	
	if(NULL != (rsp_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_HINT));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->serv_attr->peerID));
		//TODO : hash noob before sending
		eap_noob_prepare_hint(data, (u8 *)hint);
		eap_noob_Base64Encode((u8 *)hint,HASH_LEN+8, &hint_b64);
		eap_noob_json_object_set_new(rsp_obj,HINT,eap_noob_json_string(hint_b64));
		
		if(hint_b64) os_free(hint_b64);
	
		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
		len = strlen(resp_json)+1;
		printf("RESPONSE = %s\n", resp_json);	
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}	
		wpabuf_put_data(resp,resp_json,len);	

	}

	return resp;
}

/**
 * eap_noob_rsp_type_five : prepares message type file
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null 
**/
static struct wpabuf * eap_noob_rsp_type_five(struct eap_sm *sm,const struct eap_noob_peer_context *data, u8 id){

	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	//TODO: generate a fresh nonce here
	if(NULL != (rsp_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_5));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->serv_attr->peerID));
		eap_noob_json_object_set_new(rsp_obj,CSUITES_PEER,eap_noob_json_integer(data->peer_attr->cryptosuite));
		eap_noob_json_object_set_new(rsp_obj,PEERINFO,eap_noob_prepare_peer_info_json(sm,data->peer_attr->peer_config_params)); //Send this only if previous info has changed

		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT);
		len = strlen(resp_json)+1;
		printf("RESPONSE = %s\n", resp_json);	
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}	
		wpabuf_put_data(resp,resp_json,len);	

	}

	return resp;

}

/**
 * eap_noob_rsp_type_six : prepares message type six
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null 
**/

static struct wpabuf * eap_noob_rsp_type_six(struct eap_noob_peer_context *data, u8 id){

	//To-Do Based on the cryptosuite and server request decide whether new key has to be derived or not
	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;
	char* base64_nonce;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 6");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	data->serv_attr->kdf_nonce_data->nonce_peer = os_zalloc(EAP_NOOB_NONCE_LEN);
	int rc = RAND_bytes(data->serv_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);
	unsigned long err = ERR_get_error();	

	if(rc != 1) {

		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);	
	}

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->serv_attr->kdf_nonce_data->nonce_peer, EAP_NOOB_NONCE_LEN);

	eap_noob_Base64Encode(data->serv_attr->kdf_nonce_data->nonce_peer,EAP_NOOB_NONCE_LEN, &base64_nonce);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s",base64_nonce);

	data->serv_attr->kdf_nonce_data->nonce_peer_b64 = base64_nonce;

	if(NULL != (rsp_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_6));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID));
		eap_noob_json_object_set_new(rsp_obj,NONCE_PEER,eap_noob_json_string(base64_nonce));

		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
		len = strlen(resp_json)+1;
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Json %s",resp_json);
		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}

		wpabuf_put_data(resp,resp_json,len);			
	}

	return resp;
}

/**
 * eap_noob_rsp_type_seven : prepares message type seven
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null 
**/

static struct wpabuf * eap_noob_rsp_type_seven(const struct eap_noob_peer_context *data, u8 id){

	noob_json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;
	u8 * mac = NULL;
	char * mac_b64 = NULL;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 7");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	if(NULL != (rsp_obj = eap_noob_json_object())){

		mac = eap_noob_gen_MAC(data,MACP,data->serv_attr->kdf_out->kmp, KMP_LEN,RECONNECT_EXCHANGE);
		//TODO: handle NULL return value
		eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

		eap_noob_json_object_set_new(rsp_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_7));
		eap_noob_json_object_set_new(rsp_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID));
		eap_noob_json_object_set_new(rsp_obj,MAC_PEER,eap_noob_json_string(mac_b64));

		resp_json = eap_noob_json_dumps(rsp_obj,JSON_COMPACT);
		len = strlen(resp_json)+1;

		resp = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_RESPONSE, id);
		if (resp == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Response/NOOB-IE");
			return NULL;
		}

		wpabuf_put_data(resp,resp_json,len);	
	}

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

static struct wpabuf * eap_noob_req_type_seven(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;
	u8 * mac = NULL;
	char * mac_b64 = NULL;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 7");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	eap_noob_decode_obj(data->serv_attr,req_obj);

	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_SEVEN_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}
	// TODO : verify received MAC here.
	/*generate KDF*/	
	eap_noob_gen_KDF(data,RECONNECT_EXCHANGE);

	if(NULL == (resp = eap_noob_verify_peerID(data,id))){

		/*generate MAC*/
		mac = eap_noob_gen_MAC(data,MACS,data->serv_attr->kdf_out->kms, KMS_LEN,RECONNECT_EXCHANGE);
		eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

		//if(0 != strcmp(mac_b64,data->serv_attr->MAC)){
		if(0 != strcmp((char *)mac+16,data->serv_attr->MAC)){
			data->serv_attr->err_code = E4001;
			resp = eap_noob_err_msg(data,id);
			return resp;	
		}

		resp = eap_noob_rsp_type_seven(data,id);
		data->serv_attr->state = REGISTERED;
		eap_noob_config_change(sm,data);

		 if(FAILURE == eap_noob_db_update(data,UPDATE_STATE)){
			os_free(resp);
                        return NULL;
                }

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

static struct wpabuf * eap_noob_req_type_six(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;



	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 6");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	eap_noob_decode_obj(data->serv_attr,req_obj);


	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_SIX_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}

	if(NULL == (resp = eap_noob_verify_peerID(data,id))){
		resp = eap_noob_rsp_type_six(data,id);
	}

	data->serv_attr->rcvd_params = 0;
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

static struct wpabuf * eap_noob_req_type_five(struct eap_sm *sm,noob_json_t * req_obj , struct eap_noob_peer_context *data,
		u8 id){

	struct wpabuf *resp = NULL;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 5");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	eap_noob_decode_obj(data->serv_attr,req_obj);

	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_FIVE_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}

	data->peer_attr->peerID = os_malloc(strlen(data->serv_attr->peerID)+1);
	os_memcpy(data->peer_attr->peerID,data->serv_attr->peerID,strlen(data->serv_attr->peerID)+1);

	//TODO: handle eap_noob failure scenario
	if(SUCCESS == eap_noob_check_compatibility(data)){
		resp = eap_noob_rsp_type_five(sm,data, id);		
	}else{
		resp = eap_noob_err_msg(data,id);
	}


	data->serv_attr->rcvd_params = 0;	
	return resp;	

}


/**
 * eap_noob_req_type_four :  Decodes request type four
 * @eap_sm : eap statemachine context
 * @req_obj : received request message object
 * @data : peer context
 * @id   : response message id
 * Returns : pointer to message buffer or null
**/
static struct wpabuf * eap_noob_req_type_four(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;
	u8 * mac = NULL;
	char * mac_b64 = NULL;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 4");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	eap_noob_decode_obj(data->serv_attr,req_obj);

	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_FOUR_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}
	// TODO : verify received MAC here.
	/*generate KDF*/	
	eap_noob_gen_KDF(data,COMPLETION_EXCHANGE);

	if(NULL == (resp = eap_noob_verify_peerID(data,id))){

		/*generate MAC*/
		mac = eap_noob_gen_MAC(data,MACS,data->serv_attr->kdf_out->kms, KMS_LEN,COMPLETION_EXCHANGE);
		eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

		//if(0 != strcmp(mac_b64,data->serv_attr->MAC)){
		if(0 != strcmp((char *)mac+16,data->serv_attr->MAC)){
			data->serv_attr->err_code = E4001;
			resp = eap_noob_err_msg(data,id);
			return resp;	
		}

		resp = eap_noob_rsp_type_four(data,id);
		data->serv_attr->state = REGISTERED;
		eap_noob_config_change(sm,data);

		eap_noob_Base64Encode(data->serv_attr->kdf_out->kmp, KMP_LEN, &data->serv_attr->kdf_out->kmp_b64);
		eap_noob_Base64Encode(data->serv_attr->kdf_out->kms, KMS_LEN, &data->serv_attr->kdf_out->kms_b64);
		eap_noob_Base64Encode(data->serv_attr->kdf_out->kz, KZ_LEN, &data->serv_attr->kdf_out->kz_b64);

 		if(FAILURE == eap_noob_db_update(data,UPDATE_PERSISTENT_KEYS_SECRET)){
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
static struct wpabuf * eap_noob_req_type_three(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;



	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 3");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}
		
	eap_noob_decode_obj(data->serv_attr,req_obj);

	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_THREE_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}

	if(NULL == (resp = eap_noob_verify_peerID(data,id))){
		resp = eap_noob_rsp_type_three(data,id);
		//data->serv_attr->state = OOB;
		//eap_noob_config_change(sm,data);
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
static struct wpabuf * eap_noob_req_type_two(struct eap_sm *sm, noob_json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 2");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	eap_noob_decode_obj(data->serv_attr,req_obj);


	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_TWO_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}

	if(NULL == (resp = eap_noob_verify_peerID(data,id))){
		resp = eap_noob_rsp_type_two(data,id);
		data->serv_attr->state = WAITING;
		if(eap_noob_db_entry(sm,data)){
			eap_noob_config_change(sm,data);
			//TODO : handle when direction is BOTH_DIR
			if((PEER_TO_SERV == (data->serv_attr->dir & data->peer_attr->dir)) && 
					FAILURE == eap_noob_send_oob(data)){
				//TODO: Reset supplicant in this case
				wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB generation FAILED");
				return NULL;
			}
	
			if(FAILURE == eap_noob_db_update(data,UPDATE_OOB)){
                        	os_free(resp);
                        	return NULL;
               	 	}
			/*To-Do: If an error is received for the response then set the show_OOB flag to zero and send update signal*/
			/*if(FAILURE == eap_noob_sendUpdateSignal()){
				wpa_printf(MSG_DEBUG,"EAP-NOOB: Failed to Notify the Script");
			}*/

		}


	}

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

static struct wpabuf * eap_noob_req_type_one(struct eap_sm *sm,noob_json_t * req_obj , struct eap_noob_peer_context *data,
		u8 id){

	struct wpabuf *resp = NULL;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 1");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	eap_noob_decode_obj(data->serv_attr,req_obj);

	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_ONE_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}

	if(NULL == os_strstr(data->serv_attr->serv_info, "https://")){
		data->serv_attr->err_code = E1003;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}

	data->peer_attr->peerID = os_malloc(strlen(data->serv_attr->peerID)+1);
	os_memcpy(data->peer_attr->peerID,data->serv_attr->peerID,strlen(data->serv_attr->peerID)+1);

	//TODO: handle eap_noob failure scenario
	if(SUCCESS == eap_noob_check_compatibility(data)){
		resp = eap_noob_rsp_type_one(sm,data, id);		
	}else{
		resp = eap_noob_err_msg(data,id);
	}


	data->serv_attr->rcvd_params = 0;	
	return resp;	

}


static struct wpabuf * eap_noob_req_hint(struct eap_sm *sm,noob_json_t * req_obj , struct eap_noob_peer_context *data,
                u8 id)
{
	struct wpabuf *resp = NULL;

	eap_noob_decode_obj(data->serv_attr,req_obj);

	if(data->serv_attr->err_code != NO_ERROR){
		resp = eap_noob_err_msg(data,id);
		return resp;		
	}

	if(data->serv_attr->rcvd_params != TYPE_HINT_PARAMS){
		data->serv_attr->err_code = E1002;
		resp = eap_noob_err_msg(data,id);
		return resp;
	}

	if(NULL == (resp = eap_noob_verify_peerID(data,id))){
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
static void eap_noob_req_err_handling(struct eap_sm *sm,noob_json_t * req_obj , struct eap_noob_peer_context *data,
		u8 id){
	

	if(!data->serv_attr->err_code){
		eap_noob_db_update(data,UPDATE_STATE_ERROR);
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
static struct wpabuf * eap_noob_process (struct eap_sm *sm, void *priv,
		struct eap_method_ret *ret,
		const struct wpabuf *reqData)
{
	struct eap_noob_peer_context *data = priv;
	struct wpabuf *resp = NULL; //TODO:free
	const u8 *pos; //TODO: free
	size_t len;
	noob_json_t * req_obj = NULL;  //TODO: free
	noob_json_t * req_type = NULL; //TODO: free
	noob_json_error_t error;
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

	printf("RECIEVED REQUEST = %s\n", pos);	
	req_obj = eap_noob_json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
	id = eap_get_id(reqData);

	if((NULL != req_obj) && (eap_noob_json_is_object(req_obj) > 0)){

		req_type = eap_noob_json_object_get(req_obj,TYPE);

		if((NULL != req_type) && (eap_noob_json_is_integer(req_type) > 0)){
			msgtype = eap_noob_json_integer_value(req_type);
		}
		else{
			wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown type received");
			data->serv_attr->err_code = E1003;
			resp = eap_noob_err_msg(data,id);
			os_free(req_obj);
			os_free(req_type);
			return resp;

		}
	}
	else{
		data->serv_attr->err_code = E1003;
		resp = eap_noob_err_msg(data,id);
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
		os_free(req_obj);
		return resp;
	}


	printf("State :%d, mtype = %d\n",data->serv_attr->state,msgtype);
	if(VALID != state_message_check[data->serv_attr->state][msgtype]){
		data->serv_attr->err_code = E2002;
		resp = eap_noob_err_msg(data,id);
		wpa_printf(MSG_DEBUG, "EAP-NOOB: State mismatch");
		os_free(req_obj);
		return resp;
	}

	switch(msgtype){
	
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
			return NULL;
	}

	return resp;
}
/**
 * eap_noob_free_ctx : free all the allocations from peer context
 * @data : peer context
 *
**/
static void eap_noob_free_ctx(struct eap_noob_peer_context * data)
{

	struct eap_noob_peer_data * peer = data->peer_attr;
	struct eap_noob_serv_data * serv = data->serv_attr;

	if(NULL == data)
		return;	

	if(serv){
		if(serv->peerID)
			os_free(serv->peerID);
		if(serv->MAC)
			os_free(serv->MAC);
		if(serv->serv_info)
			os_free(serv->serv_info);
		if(serv->ssid)
			os_free(serv->ssid);

		os_free(serv);
	}

	if(peer){
		if(peer->peerID)
			os_free(peer->peerID);
		if(peer->peer_config_params)
			os_free(peer->peer_config_params);
		if(peer->peer_info)
			os_free(peer->peer_info);
		if(peer->MAC)
			os_free(peer->MAC);
		os_free(peer);
	}

	os_free(data);	
}

/**
 * eap_noob_deinit : de initialises the eap method context
 * @sm : eap statemachine context
 * @priv : method context
**/

static void eap_noob_deinit(struct eap_sm *sm, void *priv)
{
	//TODO:free every allocated memory to avoid leaks

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
static int eap_noob_create_db(struct eap_sm *sm,struct eap_noob_peer_context * data)
{


	char buff[100] = {0};//TODO : dynamic allocation of memory
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

	if(SQLITE_OK != sqlite3_open_v2(data->db_name, &data->peerDB,SQLITE_OPEN_READWRITE,NULL)){

		wpa_printf(MSG_ERROR, "EAP-NOOB: No DB found,new DB willbe created");

		if(SQLITE_OK != sqlite3_close(data->peerDB)){
                        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
        	}

		if(SQLITE_OK != sqlite3_open(data->db_name, &data->peerDB)){
			wpa_printf(MSG_ERROR, "EAP-NOOB: NEW DB creation failed");
			//TODO: free data here.
			return FAILURE;
		}

		if(FAILURE == eap_noob_exec_query(CREATE_CONNECTION_TABLE, NULL,NULL,data)){
			//sqlite3_close(data->peerDB);	
			wpa_printf(MSG_ERROR, "EAP-NOOB: connections Table creation failed");
			//TODO: free data here.
			return FAILURE;
		}

	}else{

		if(wpa_s->current_ssid->ssid){

			//TODO: add row check condition here	
			os_snprintf(buff,100,"SELECT COUNT(*) from %s WHERE ssid ='%s'",data->db_table_name,
					wpa_s->current_ssid->ssid);
			if(FAILURE !=  eap_noob_exec_query(buff, eap_noob_db_entry_check,data->serv_attr,data)
					&& (data->serv_attr->record_present)){

				memset(buff, 0, sizeof(buff));
				os_snprintf(buff,100,"SELECT * from %s WHERE ssid ='%s'",data->db_table_name,
						wpa_s->current_ssid->ssid);


			if(SQLITE_OK != sqlite3_open_v2(data->db_name, &data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
				wpa_printf(MSG_DEBUG,"EAP-NOOB: Failed to open db here");
				return FAILURE;
			}


			if(FAILURE !=  eap_noob_exec_query(buff, eap_noob_callback,data,data)){
				data->peer_attr->peerID = os_malloc(strlen(data->serv_attr->peerID)+1);
				os_memcpy(data->peer_attr->peerID,data->serv_attr->peerID,
						strlen(data->serv_attr->peerID)+1);
			}
			}
			//TODO handle noob client reset	
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
	//	more than one csuite or version is supported.

	printf("CONF Name = %s %d\n",conf_name,(int)strlen(conf_name));
	if(0 == strcmp("Version",conf_name)){
		data->version = (int) strtol(conf_value, NULL, 10);
		data->config_params |= VERSION_RCVD; 
		printf("FILE  READ= %d\n",data->version);
	}		
	else if(0 == strcmp("Csuite",conf_name)){
		data->cryptosuite = (int) strtol(conf_value, NULL, 10);
		data->config_params |= CSUITE_RCVD;
		printf("FILE  READ= %d\n",data->cryptosuite);
	}		
	else if(0 == strcmp("Direction",conf_name)){
		data->dir = (int) strtol(conf_value, NULL, 10);
		data->config_params |= DIRECTION_RCVD;
		printf("FILE  READ= %d\n",data->dir);
	}		
	else if(0 == strcmp("PeerName", conf_name)){
		data->peer_config_params->Peer_name = os_strdup(conf_value);
		data->config_params |= PEER_NAME_RCVD;
		printf("FILE  READ= %s\n",data->peer_config_params->Peer_name);
	}		
	else if(0 == strcmp("PeerSNum", conf_name)){
		data->peer_config_params->Peer_ID_Num = os_strdup(conf_value);
		data->config_params |= PEER_ID_NUM_RCVD;
		printf("FILE  READ= %s\n",data->peer_config_params->Peer_ID_Num);
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
	
	if(*pos == '#')
		return;
	
	if(os_strstr(pos, "=")){
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
		//printf("conf_value = %s token = %s\n",conf_value,token);
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

	if(!(data->peer_attr->config_params&PEER_NAME_RCVD) || 
		!(data->peer_attr->config_params&PEER_ID_NUM_RCVD)){
		wpa_printf(MSG_ERROR, "EAP-NOOB: Peer name or Peer ID number missing");
		return FAILURE;
	}
	
	//set default values
	data->peer_attr->version = VERSION_ONE;
	data->peer_attr->cryptosuite = SUITE_ONE;
	data->peer_attr->dir = PEER_TO_SERV;
	
	return SUCCESS;
}

/** 
 * eap_noob_prepare_peer_info_obj : from the read configuration make a peer info JSON object
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/
static int eap_noob_prepare_peer_info_obj(struct eap_noob_peer_data * data)
{
	//To-Do: Send Peer Info and Server Info during fast reconnect only if they have changed

	noob_json_t * info_obj = NULL;

        if(NULL == data){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return FAILURE;
        }

        if(NULL != (info_obj = eap_noob_json_object())){

                eap_noob_json_object_set_new(info_obj,PEER_NAME,eap_noob_json_string(data->peer_config_params->Peer_name));
                eap_noob_json_object_set_new(info_obj,PEER_SERIAL_NUM,eap_noob_json_string(data->peer_config_params->Peer_ID_Num));

                if(NULL == (data->peer_info = eap_noob_json_dumps(info_obj,JSON_COMPACT|JSON_PRESERVE_ORDER)) || 
			(strlen(data->peer_info) > MAX_INFO_LEN)){
				wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no server info");
 	                       	return FAILURE;
			}       
		printf("PEER INFO = %s\n",data->peer_info);
        }

	return SUCCESS;
}

/**
 * eap_noob_read_config : read configuraions from config file
 * @data : peer context
 * Returns : SUCCESS/FAILURE
**/

static int eap_noob_read_config(struct eap_sm *sm,struct eap_noob_peer_context * data)
{
	FILE * conf_file = NULL;
	char * buff = NULL; 

	if(NULL == (conf_file = fopen(CONF_FILE,"r"))){
		wpa_printf(MSG_ERROR, "EAP-NOOB: Configuration file not found");
		return FAILURE;
	}
	
	if((NULL == (buff = malloc(MAX_CONF_LEN))) || 
	(NULL == (data->peer_attr->peer_config_params = 
		malloc(sizeof(struct eap_noob_peer_config_params)))))
		return FAILURE;

	data->peer_attr->config_params = 0;	
	while(!feof(conf_file)){
		if(fgets(buff,MAX_CONF_LEN, conf_file)){
			eap_noob_parse_config(buff,data->peer_attr);
			memset(buff,0,MAX_CONF_LEN);
		}
	}
	
	free(buff);


	if((data->peer_attr->version >MAX_SUP_VER) || 
		(data->peer_attr->cryptosuite > MAX_SUP_CSUITES) || 
		(data->peer_attr->dir > BOTH_DIR)){
		wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");    
                return FAILURE;

	}

	if(data->peer_attr->config_params != CONF_PARAMS &&
		FAILURE == eap_noob_handle_incomplete_conf(data))
		return FAILURE;

	//return eap_noob_prepare_peer_info_obj(data->peer_attr);
	if((NULL == (data->peer_attr->peer_info = eap_noob_json_dumps(eap_noob_prepare_peer_info_json(sm,data->peer_attr->peer_config_params),
		JSON_COMPACT|JSON_PRESERVE_ORDER))) || (strlen(data->peer_attr->peer_info) > MAX_INFO_LEN)){
				wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no peer info");
 	                       	return FAILURE;
		}       
	printf("PEER INFO = %s\n",data->peer_attr->peer_info);

	return SUCCESS;
}

/**
 * eap_noob_peer_ctxt_alloc : Allocates the subcontexts inside the peer context
 * @sm : eap method context
 * @peer : peer context
 * Returns : SUCCESS/FAILURE 
**/

static int eap_noob_peer_ctxt_alloc(struct eap_sm *sm,  struct eap_noob_peer_context * data){

	if(NULL == (data->peer_attr = os_zalloc( sizeof (struct eap_noob_peer_data)))){
		return FAILURE;
	}
	if((NULL == (data->serv_attr = os_zalloc( sizeof (struct eap_noob_serv_data))))){
		return FAILURE;
	}
	if((NULL == (data->serv_attr->ecdh_exchange_data = os_zalloc( sizeof (struct eap_noob_ecdh_key_exchange))))){
		return FAILURE;
	}
	if((NULL == (data->serv_attr->oob_data = os_zalloc( sizeof (struct eap_noob_oob_data))))){
		return FAILURE;
	}
	if((NULL == (data->serv_attr->kdf_out = os_zalloc( sizeof (struct eap_noob_ecdh_kdf_out))))){
		return FAILURE;
	}
	if((NULL == (data->serv_attr->kdf_nonce_data = os_zalloc( sizeof (struct eap_noob_ecdh_kdf_nonce))))){
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

static int eap_noob_peer_ctxt_init(struct eap_sm *sm,  struct eap_noob_peer_context * data)
{

	/*TODO: remove hard codings and initialize preferably through a 
	  config file*/
	int retval = FAILURE;

	if(FAILURE != eap_noob_peer_ctxt_alloc(sm,data)){

	
		data->serv_attr->state = UNREG;
		data->serv_attr->rcvd_params = 0;
		data->serv_attr->err_code = 0;	
		/* Setup DB */
		/* DB file name for the client */
		data->db_name = os_strdup(DB_NAME);

		/* DB Table name */
		data->db_table_name = os_strdup(TABLE_NAME);

		if(FAILURE == (retval = eap_noob_create_db(sm , data)))
			return retval;		
	
		printf("************* STATE = %d\n",data->serv_attr->state);
	
		if(data->serv_attr->state == UNREG || 
			data->serv_attr->state == RECONNECT){	

			if(FAILURE == eap_noob_read_config(sm,data)){
				wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to initialize context");
				return FAILURE;
			}
		}
	}


	return retval;

}

/**
 * eap_noob_init : initialise the eap noob method
 *  @sm : eap statemachine context
 * Returns : eap  noob peer context
**/

static void * eap_noob_init(struct eap_sm *sm)
{
	struct eap_noob_peer_context * data;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB INIT");


	if(NULL == (data = os_zalloc( sizeof (struct eap_noob_peer_context))))
		return NULL;
	
	//TODO: check if hard coded initialization can be avoided
	if(FAILURE == eap_noob_peer_ctxt_init(sm,data))
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
	struct eap_noob_peer_context *data = priv;
	Boolean retval = ((data->serv_attr->state == REGISTERED) && (data->serv_attr->ecdh_exchange_data->shared_key_b64 != NULL));
	printf("STATE = %d\n", data->serv_attr->state);
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
	wpa_printf(MSG_DEBUG, "EAP-NOOB: GET  KEY");

	struct eap_noob_peer_context *data = priv;
	u8 *key;


	if ((data->serv_attr->state != REGISTERED) || (!data->serv_attr->kdf_out->msk))
		return NULL;

	if(NULL == (key = os_malloc(MSK_LEN)))
		return NULL;
	*len = MSK_LEN;
	os_memcpy(key, data->serv_attr->kdf_out->msk, MSK_LEN);
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
	if ((data->serv_attr->state != REGISTERED) || (!data->serv_attr->kdf_out->emsk))
                return NULL;

	if(NULL == (key = os_malloc(MSK_LEN)))
                return NULL;


        *len = EAP_EMSK_LEN;
        os_memcpy(key, data->serv_attr->kdf_out->emsk, EAP_EMSK_LEN);
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

        printf("############################# DE-INIT reauth called\n");
}

/**
 * eap_noob_init_for_reauth : initialise the reauth context
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static void * eap_noob_init_for_reauth(struct eap_sm *sm, void *priv)
{
        struct eap_noob_peer_context *data = priv;
	
	printf("############################# INIT reauth called\n");
	data->serv_attr->state = RECONNECT;

        return data;
}


/**
 * eap_noob_has_reauth_data : Changes the state to RECONNECT ,
    if the current state is REGISTERED
 * @sm : eap statemachine context
 * @priv : eap noob data
 */
static Boolean eap_noob_has_reauth_data(struct eap_sm *sm, void *priv)
{
	struct eap_noob_peer_context *data = priv;
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
	
        printf("######################### Has reauth function called\n");
	printf("Current SSID = %s, Stored SSID = %s\n",
		wpa_s->current_ssid->ssid,data->serv_attr->ssid);	
	if(data->serv_attr->state == REGISTERED && 
		0 == strcmp((char *)wpa_s->current_ssid->ssid,data->serv_attr->ssid)){

		data->serv_attr->state = RECONNECT;

		eap_noob_config_change(sm,data);

		eap_noob_db_update(data,UPDATE_STATE);
	
		return TRUE;
	}
	printf("############################Returning False\n");
	return FALSE;
}

/**
 * eap_peer_noob_register : register eap noob method
**/

int eap_peer_noob_register(void)
{
	int ret;
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
	 
	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret; 	
}
