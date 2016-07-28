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

#include <stdint.h>
#include <unistd.h>
#include <sqlite3.h>
#include <jansson.h>
#include <time.h>

#include "includes.h"
#include "common.h"
#include "eap_i.h"
#include "eap_server_oob.h"

static noob_json_t * eap_noob_json_array()
{
	return json_array();
}

static u32  eap_noob_json_array_append(noob_json_t * arr, noob_json_t * value)
{
	return json_array_append(arr, value);
}


static noob_json_t * eap_noob_json_integer(noob_json_int_t value)
{
	return json_integer(value);
}

static noob_json_int_t eap_noob_json_integer_value(noob_json_t * value)
{
	return json_integer_value(value);
}

static u32 eap_noob_json_is_integer(const noob_json_t * value)
{
	return json_is_integer(value);
}

static noob_json_t * eap_noob_json_string(const noob_json_str_t * value)
{
	return json_string(value);
}

static noob_json_str_t * eap_noob_json_string_value(noob_json_t * value)
{
	return (char *)json_string_value(value);
}

static noob_json_t * eap_noob_json_object()
{
	return json_object();
}

static u32 eap_noob_json_object_set_new (noob_json_t * obj, const char* key, noob_json_t * value)
{
	return json_object_set_new(obj,key,value);
}

static char * eap_noob_json_dumps(noob_json_t * root, size_t flags)
{
	return json_dumps(root, flags);
}


static noob_json_t * eap_noob_json_loads(const char * input, size_t flags, noob_json_error_t * error)
{
	return json_loads(input,flags, error);
}

static u32 eap_noob_json_is_object(noob_json_t * obj)
{
	return json_is_object(obj);
}

static noob_json_t * eap_noob_json_object_get(noob_json_t * obj, const char * key)
{
	return json_object_get(obj,key);
}

static u32 eap_noob_json_typeof(const noob_json_t * value)
{
	return json_typeof(value);
}


static void eap_noob_set_error(struct eap_noob_peer_data *data, 
		int err_code)
{
	printf("ERROR CODE = %d\n", err_code);
	data->next_req = NONE;
	data->err_code = err_code;
}


static int eap_noob_verify_peerID(struct eap_noob_serv_context * data)
{
	if(0 != strcmp(data->peer_attr->peerID_gen,
			data->peer_attr->peerID_rcvd)){
		eap_noob_set_error(data->peer_attr,E1005);

		return FAILURE;
	}
	return SUCCESS;
}


static int eap_noob_verify_state(struct eap_noob_serv_context * data)
{
	printf("VERIFY STATE SERV = %d PEER = %d\n", data->peer_attr->serv_state,
				data->peer_attr->peer_state);

	if((NUM_OF_STATES < data->peer_attr->serv_state ) || 
	(NUM_OF_STATES < data->peer_attr->peer_state ) || 
	(INVALID == state_machine[data->peer_attr->serv_state]
			[data->peer_attr->peer_state])){
		eap_noob_set_error(data->peer_attr,E2002);
		eap_noob_set_done(data, NOT_DONE);
		return FAILURE;
	}
	return SUCCESS; 
}

static void eap_noob_set_done(struct eap_noob_serv_context *data, 
		u8 outcome)
{
	data->peer_attr->is_done = outcome;
}


static void eap_noob_set_success(struct eap_noob_serv_context *data, 
		u8 outcome)
{
	data->peer_attr->is_success = outcome;
}

size_t eap_noob_calcDecodeLength(const char* b64input) { //Calculates the length of a decoded string
	size_t len = strlen(b64input),
	padding = 0;

	if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
		padding = 2;
	else if (b64input[len-1] == '=') //last char is =
		padding = 1;

	return (len*3)/4 - padding;
}

int eap_noob_Base64Decode(char* b64message, unsigned char** buffer, size_t* length) { //Decodes a base64 encoded string
	BIO *bio, *b64;

	int decodeLen,i;

	int len = strlen(b64message);
	char * temp = NULL;
	
	switch (len % 4) // Pad with trailing '='s
	{
		case 0: temp = os_zalloc(len + 1);strcpy(temp,b64message); break; // No pad chars in this case
		case 2: temp = os_zalloc(len + 3);strcpy(temp,b64message); strcat(temp,"==");break; // Two pad chars
		case 3: temp = os_zalloc(len +2);strcpy(temp,b64message); strcat(temp,"=");break; // One pad char
		default: return 0;
	}

	for(i=0;i<len;i++){
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


static int eap_noob_get_next_req(struct eap_noob_peer_data * data){

	int retval = 0;
	if(state_machine[data->serv_state][data->peer_state]){
	retval = next_request_type [(data->serv_state * NUM_OF_STATES) + data->peer_state];
	}
	wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv state = %d, Peer state = %d, Next req =%d",data->serv_state, data->peer_state, retval);
	if( retval == EAP_NOOB_TYPE_5) data->serv_state = RECONNECT;

	return retval;
}


int eap_noob_db_entry_check(void * priv , int argc, char **argv, char **azColName){

	int res = 0;
	struct eap_noob_serv_context *data = priv;

	if((res = strtol(argv[0],NULL,10)) == 1){
		data->peer_attr->record_present = TRUE;		
	}

	return 0;
}

int eap_noob_verify_oob_msg_len(struct eap_noob_peer_data *data)
{


	if(data){
		if(data->noob){
			if(data->noob_len > EAP_NOOB_NONCE_LEN){
				eap_noob_set_error(data,E1003);
				return FAILURE;	
			}
		}
		
		if(data->hoob){
			if(data->hoob_len > HASH_LEN){
				eap_noob_set_error(data,E1003);
				return FAILURE;		
			}
		}

	}

	return SUCCESS;	
}

int eap_noob_callback(void * priv , int argc, char **argv, char **azColName)
{

	struct eap_noob_serv_context * serv = priv;
	struct eap_noob_peer_data *data = serv->peer_attr;

	int count  = 0;
	
	size_t len;
	noob_json_error_t error;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB CALLBACK");

	for (count =0; count <argc; count++) {

		if (argv[count]) {
			if (os_strcmp(azColName[count], "PeerID") == 0) {
				if(NULL != data->peerID_rcvd)
					os_free(data->peerID_gen);

				data->peerID_gen = os_malloc(os_strlen(argv[count]));
				strcpy(data->peerID_gen, argv[count]);
			}
			else if (os_strcmp(azColName[count], "Verp") == 0) {
				data->version = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "Vers") == 0) {
				serv->server_attr->version[0] = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "serv_state") == 0) {
				data->serv_state = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "PKp") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->peer_public_key_b64)
					os_free(data->peer_public_key_b64);

				data->peer_public_key_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->peer_public_key_b64, argv[count]);
			}			
			else if (os_strcmp(azColName[count], "Csuitep") == 0) {
				data->cryptosuite = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "Csuites") == 0) {
				serv->server_attr->cryptosuite[0] = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "Dirp") == 0) {
				data->dir = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "Dirs") == 0) {
				serv->server_attr->dir = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "nonce_peer") == 0  && os_strlen(argv[count]) > 0) {
				if(NULL != data->nonce_peer_b64)
					os_free(data->nonce_peer_b64);

				data->nonce_peer_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->nonce_peer_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB nonce_peer");
				eap_noob_Base64Decode(data->nonce_peer_b64, &data->nonce_peer, &len); //To-Do check for length

			}	
			else if (os_strcmp(azColName[count], "nonce_serv") == 0  && os_strlen(argv[count]) > 0) {
				if(NULL != data->nonce_serv_b64)
					os_free(data->nonce_serv_b64);

				data->nonce_serv_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->nonce_serv_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB nonce_serv");
				eap_noob_Base64Decode(data->nonce_serv_b64, &data->nonce_serv, &len); //To-Do check for length

			}

			else if (os_strcmp(azColName[count], "PeerInfo") == 0) {
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB PeerInfo");
				if(NULL != data->peer_info)
					os_free(data->peer_info);

				data->peer_info = os_malloc(os_strlen(argv[count]));
				strcpy(data->peer_info, argv[count]);
			}

			else if (os_strcmp(azColName[count], "ServInfo") == 0) {
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB ServInfo");
				if(NULL != serv->server_attr->serv_info)
					os_free(serv->server_attr->serv_info);

				serv->server_attr->serv_info = os_malloc(os_strlen(argv[count]));
				strcpy(serv->server_attr->serv_info, argv[count]);
			}
			else if (os_strcmp(azColName[count], "SharedSecret") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->shared_key_b64)
					os_free(data->shared_key_b64);

				data->shared_key_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->shared_key_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB shared_key");
				eap_noob_Base64Decode(data->shared_key_b64, &data->shared_key, &len);
			}	
			else if (os_strcmp(azColName[count], "Noob") == 0  && os_strlen(argv[count]) > 0) {
				if(NULL != data->noob_b64)
					os_free(data->noob_b64);

				data->noob_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->noob_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB noob %d",(int)os_strlen(argv[count]));
				data->noob_len = eap_noob_Base64Decode(data->noob_b64, &data->noob, &len);
			}	
			else if (os_strcmp(azColName[count], "Hoob") == 0  && os_strlen(argv[count]) > 0) {
				if(NULL != data->hoob_b64)
					os_free(data->hoob_b64);

				data->hoob_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->hoob_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB hoob %s",data->hoob_b64);
				data->hoob_len = eap_noob_Base64Decode(data->hoob_b64, &data->hoob, &len);
			}
			else if (os_strcmp(azColName[count], "OOB_RECEIVED_FLAG") == 0 && (data->peer_state != RECONNECT && data->serv_state != RECONNECT )) { 
				//TODO: This has to be properly checked and not only oob received flag
				data->oob_recv = (int) strtol(argv[count],NULL,10);
				
				 if(data->oob_recv == 1234){				
					wpa_printf(MSG_DEBUG,"EAP-NOOB: Received oob!!");
					data->serv_state = OOB;
					data->peer_state = OOB;
				}else if (data->serv_state == WAITING){
					wpa_printf(MSG_DEBUG,"EAP-NOOB: Still waiting stage");
					data->peer_state = WAITING;
				}
			

			}
			else if (os_strcmp(azColName[count], "MINSLP_count") == 0) {
				data->minslp_count = (int )strtol(argv[count],NULL,10);
			}else if (os_strcmp(azColName[count], "pub_key_serv") == 0){
				data->jwk_serv = eap_noob_json_loads(argv[count], JSON_COMPACT, &error); //ToDo: check and free this before assigning if required
				wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv_Key: %s",eap_noob_json_dumps(data->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER));
			
			}else if (os_strcmp(azColName[count], "pub_key_peer") == 0){
				data->jwk_peer = eap_noob_json_loads(argv[count], JSON_COMPACT|JSON_PRESERVE_ORDER, &error); //ToDo: check and free this before assigning if required	
				wpa_printf(MSG_DEBUG,"EAP-NOOB:Peer_Key: %s",eap_noob_json_dumps(data->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER));
			}
			else if (os_strcmp(azColName[count], "kms") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->kms_b64)
					os_free(data->kms_b64);

				data->kms_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kms_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kms");
				eap_noob_Base64Decode(data->kms_b64, &data->kms, &len);
			}	
			else if (os_strcmp(azColName[count], "kmp") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->kmp_b64)
					os_free(data->kmp_b64);

				data->kmp_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kmp_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kmp");
				eap_noob_Base64Decode(data->kmp_b64, &data->kmp, &len);
			}	
			else if (os_strcmp(azColName[count], "kz") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->kz_b64)
					os_free(data->kz_b64);

				data->kz_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->kz_b64, argv[count]);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB kz");
				eap_noob_Base64Decode(data->kz_b64, &data->kz, &len);
			}	
			else if (os_strcmp(azColName[count], "errorCode") == 0 && os_strlen(argv[count]) > 0) {

				data->err_code = (int) strtol(argv[count],NULL,10);
				eap_noob_set_error(data,data->err_code);
				wpa_printf(MSG_DEBUG, "EAP-NOOB: EAP OOB Error during OOB");
			}	
				

		}
	}

	return 0;
}



static int eap_noob_exec_query(const char * query, int(*callback)(void*, int ,char **, char ** ), void * argv,
		struct eap_noob_serv_context * data){

	char * sql_error = NULL;
	//struct eap_oob_serv_context * value = data;
	
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
	
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Server context is NULL");
		return FAILURE;
	}

	if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->servDB,SQLITE_OPEN_READWRITE,NULL)){
		wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
		return FAILURE;
	}	
	
	if(SQLITE_OK != sqlite3_exec(data->servDB, query,callback, argv, &sql_error)){
		if (sql_error!=NULL) {
			wpa_printf(MSG_DEBUG,"EAP-NOOB: sql error : %s\n",sql_error);
			sqlite3_free(sql_error);
		}
		if(SQLITE_OK != sqlite3_close(data->servDB)){
			wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
		}
		return FAILURE;
	}

	if(SQLITE_OK != sqlite3_close(data->servDB)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
	return SUCCESS;
}

static int eap_noob_db_entry(struct eap_noob_serv_context *data)
{
	char query[1500] = {0}; //TODO : replace it with dynamic allocation
	struct eap_noob_peer_data * peer_attr = data->peer_attr;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

	snprintf(query,1500,"INSERT INTO %s ( PeerID, Verp,Vers, serv_state, Csuitep, Csuites,Dirp, Dirs,nonce_serv,nonce_peer, PeerInfo,ServInfo," 
			"SharedSecret, Noob, Hoob, OOB_RECEIVED_FLAG,MINSLP_count, pub_key_serv, pub_key_peer, kms, kmp, kz)"
			"VALUES ( '%s',%d ,%d, %d, %d, %d, %d, %d, '%s','%s', '%s','%s','%s','%s','%s', %d, %d, '%s', '%s', '%s', '%s', '%s')",
			data->db_table_name, peer_attr->peerID_gen, peer_attr->version,data->server_attr->version[0],
			peer_attr->serv_state, peer_attr->cryptosuite,data->server_attr->cryptosuite[0],
			peer_attr->dir,data->server_attr->dir,
			peer_attr->nonce_serv_b64,peer_attr->nonce_peer_b64, peer_attr->peer_info,
			data->server_attr->serv_info, 
			peer_attr->shared_key_b64,"","",0,peer_attr->minslp_count,
			(eap_noob_json_dumps(peer_attr->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER)), 
			(eap_noob_json_dumps(peer_attr->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER)),"","","");

	printf("QUERY = %s\n",query);
/*	
	if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->servDB,SQLITE_OPEN_READWRITE,NULL)){
		wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
		return FAILURE;
	}	
*/	
	if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data)){
		//sqlite3_close(data->servDB);
		wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
		//TODO: free data here.
		return FAILURE;
	}	

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
	return SUCCESS;
}

static int eap_noob_change_state(struct eap_noob_serv_context *data, int state)
{
	data->peer_attr->serv_state = state;

	return SUCCESS;
}

static int eap_noob_db_update(struct eap_noob_serv_context *data, u8 type)
{

	char query[1000] = {0}; //TODO: remove this static allocation and allocate dynamically with actual length
	int len = 1000;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);
	switch(type){

		case UPDATE_ALL:
			snprintf(query,len,"UPDATE '%s' SET Verp=%d , serv_state=%d, Csuite=%d," 
					"Dirp=%d, nonce='%s', PeerInfo='%s' WHERE PeerID='%s'", data->db_table_name, data->peer_attr->version,
					data->peer_attr->serv_state, data->peer_attr->cryptosuite, data->peer_attr->dir,data->peer_attr->nonce_peer,
					data->peer_attr->peer_info, data->peer_attr->peerID_gen);
			break;

		case UPDATE_STATE:
			snprintf(query,len,"UPDATE '%s' SET serv_state=%d WHERE PeerID='%s'",data->db_table_name,data->peer_attr->serv_state,
					data->peer_attr->peerID_gen);
			break;

		case UPDATE_STATE_ERROR:
			snprintf(query,len,"UPDATE '%s' SET serv_state=%d, errorCode=%d  WHERE PeerID='%s'",data->db_table_name,data->peer_attr->serv_state,
					data->peer_attr->err_code,data->peer_attr->peerID_gen);
			break;

		case UPDATE_STATE_MINSLP:
			snprintf(query,len,"UPDATE '%s' SET serv_state=%d, MINSLP_count =%d,sleepTime = %ld  WHERE PeerID='%s'",data->db_table_name,data->peer_attr->serv_state,
					data->peer_attr->minslp_count,data->peer_attr->sleep_time.tv_sec,data->peer_attr->peerID_gen);
			break;
		case UPDATE_PERSISTENT_KEYS_SECRET:
			snprintf(query,len,"UPDATE '%s' SET kms='%s', kmp='%s', kz='%s', serv_state=%d  WHERE PeerID='%s'",data->db_table_name,data->peer_attr->kms_b64,
					data->peer_attr->kmp_b64,data->peer_attr->kz_b64,data->peer_attr->serv_state,data->peer_attr->peerID_gen);
			break;
			
	
		default:
			wpa_printf(MSG_ERROR, "EAP-NOOB: Wrong DB update type");
			return FAILURE;

	}
	
		
/*
	if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->servDB,SQLITE_OPEN_READWRITE,NULL)){
		wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
		return FAILURE;
	}	
*/
	if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data)){
		//sqlite3_close(data->servDB);
		wpa_printf(MSG_ERROR, "EAP-NOOB: DB value update failed");
		//TODO: free data here.
		return FAILURE;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
	return SUCCESS;		

}


static int eap_noob_parse_NAI(struct eap_noob_serv_context * data, int len)
{

	char * token = NULL;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

	if(os_strstr(data->peer_attr->NAI, DOMAIN)){

		token = strsep(&data->peer_attr->NAI, "@"); /*TODO : check for leak*/
		data->peer_attr->user_name_peer = token;
		/*Peer State*/			
		if(os_strstr(data->peer_attr->user_name_peer, "+")){
		
			token = strsep(&data->peer_attr->user_name_peer, "+");
			data->peer_attr->peerID_rcvd = token;
			token = strsep(&data->peer_attr->user_name_peer, "+");
			if(*token != 's'){
				eap_noob_set_error(data->peer_attr,E1001);
				return FAILURE;	
			}
			data->peer_attr->peer_state = (int) strtol(token+1, NULL, 10);	
		}
		else {
			if(0 != strcmp("noob",data->peer_attr->user_name_peer)){
				eap_noob_set_error(data->peer_attr,E1001);
				return FAILURE;	
			}
		}
		/* REALM */
		token = strsep(&data->peer_attr->NAI, "@");
		data->peer_attr->realm = token;

		if(0 != strcmp(data->peer_attr->realm,DOMAIN)){
			eap_noob_set_error(data->peer_attr,E1001);
			return FAILURE;	
		}
	}else{
		eap_noob_set_error(data->peer_attr,E1001);
		return FAILURE;	
	}

	return SUCCESS;
}

static int eap_noob_create_db(struct eap_noob_serv_context * data)
{

	char buff[200] = {0}; //TODO : replace this with dynamic allocation

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);

	if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->servDB,SQLITE_OPEN_READWRITE,NULL)){

		wpa_printf(MSG_ERROR, "EAP-NOOB: No DB found,new DB will be created");
		
		if(SQLITE_OK != sqlite3_close(data->servDB)){
                        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB before creating table");
                }

		if(SQLITE_OK != sqlite3_open(data->db_name, &data->servDB)){
			wpa_printf(MSG_ERROR, "EAP-NOOB: NEW DB creation failed");
			//TODO: free data here.
			return FAILURE;
		}

		if(FAILURE == eap_noob_exec_query(CREATE_CONNECTION_TABLE, NULL,NULL,data)){
			//sqlite3_close(data->servDB);
			wpa_printf(MSG_ERROR, "EAP-NOOB: connections Table creation failed");
			//TODO: free data here.
			return FAILURE;
		}

	}else{

		/*check for the peer ID inside the DB*/	
		/*TODO: handle condition where there are two tuples for same peer id*/
		if(SQLITE_OK != sqlite3_open_v2(data->db_name, &data->servDB, SQLITE_OPEN_READWRITE,NULL)){
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to open and Create Table");
			//TODO: free data here.
			return FAILURE;
		}

		if(FAILURE == eap_noob_exec_query(CREATE_CONNECTION_TABLE, NULL,NULL,data)){
			//sqlite3_close(data->servDB);
			wpa_printf(MSG_ERROR, "EAP-NOOB: connections Table creation failed");
			//TODO: free data here.
			return FAILURE;
		}

		if(data->peer_attr->peerID_rcvd){

			os_snprintf(buff,200,"SELECT COUNT(*) from %s WHERE  PeerID = '%s'",
					data->db_table_name,data->peer_attr->peerID_rcvd);

			if(SQLITE_OK != sqlite3_open_v2(data->db_name, &data->servDB, SQLITE_OPEN_READWRITE,NULL)){
				wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to open and Create Table");
				//TODO: free data here.
				return FAILURE;
			}

			if(FAILURE != eap_noob_exec_query(buff, eap_noob_db_entry_check,
						data,data) && (data->peer_attr->record_present)){

				memset(buff, 0, sizeof(buff));
				os_snprintf(buff,200,"SELECT * from %s WHERE  PeerID = '%s'",
						data->db_table_name,data->peer_attr->peerID_rcvd);
				
				if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->servDB,SQLITE_OPEN_READWRITE,NULL)){
					wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
					return FAILURE;
				}	
				eap_noob_exec_query(buff, eap_noob_callback,data,data);
				
			}else{

				wpa_printf(MSG_ERROR, "EAP-NOOB: No record found ");
				//TODO :  send peer ID mismatch error code.
				return FAILURE;
			}
		}

	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
	return SUCCESS;
}

static void eap_noob_assign_config(char * conf_name,char * conf_value,struct eap_noob_server_data * data)
{
        //TODO : version and csuite are directly converted to integer.This needs to be changed if
        //      more than one csuite or version is supported.

        printf("CONF Name = %s %d\n",conf_name,(int)strlen(conf_name));
        if(0 == strcmp("Version",conf_name)){
                data->version[0] = (int) strtol(conf_value, NULL, 10);
                data->config_params |= VERSION_RCVD;
                printf("FILE  READ= %d\n",data->version[0]);
        }
        else if(0 == strcmp("Csuite",conf_name)){
                data->cryptosuite[0] = (int) strtol(conf_value, NULL, 10);
                data->config_params |= CSUITE_RCVD;
                printf("FILE  READ= %d\n",data->cryptosuite[0]);
        }
        else if(0 == strcmp("Direction",conf_name)){
                data->dir = (int) strtol(conf_value, NULL, 10);
                data->config_params |= DIRECTION_RCVD;
                printf("FILE  READ= %d\n",data->dir);
        }
        else if(0 == strcmp("ServName", conf_name)){
                data->serv_config_params->Serv_name = os_strdup(conf_value);
                data->config_params |= SERV_NAME_RCVD;
                printf("FILE  READ= %s\n",data->serv_config_params->Serv_name);
        }
        else if(0 == strcmp("ServUrl", conf_name)){
                data->serv_config_params->Serv_URL = os_strdup(conf_value);
                data->config_params |= SERV_URL_RCVD;
                printf("FILE  READ= %s\n",data->serv_config_params->Serv_URL);
        }

}


static void eap_noob_parse_config(char * buff,struct eap_noob_server_data * data)
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



static int eap_noob_handle_incomplete_conf(struct eap_noob_serv_context * data)
{

        if(!(data->server_attr->config_params & SERV_URL_RCVD) ||
                !(data->server_attr->config_params & SERV_NAME_RCVD)){
                wpa_printf(MSG_ERROR, "EAP-NOOB: Server name or Server URL  missing");
                return FAILURE;
        }

        //set default values
	data->server_attr->version[0] = VERSION_ONE;
	data->server_attr->cryptosuite[0] = SUITE_ONE;
	data->server_attr->dir = BOTH_DIR;

        return SUCCESS;
}

static noob_json_t * eap_noob_prepare_serv_json_obj(struct eap_noob_serv_config_params * data){

        noob_json_t * info_obj = NULL;

        if(NULL == data){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return NULL;
        }

        if(NULL != (info_obj = eap_noob_json_object())){

                eap_noob_json_object_set_new(info_obj,SERV_NAME,eap_noob_json_string(data->Serv_name));
                eap_noob_json_object_set_new(info_obj,SERV_URL,eap_noob_json_string(data->Serv_URL));
	}
	return info_obj;
}

static int eap_noob_prepare_serv_info_obj(struct eap_noob_server_data * data)
{

        noob_json_t * info_obj = NULL;

        if(NULL == data){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return FAILURE;
        }

        if(NULL != (info_obj = eap_noob_json_object())){

                eap_noob_json_object_set_new(info_obj,SERV_NAME,eap_noob_json_string(data->serv_config_params->Serv_name));
                eap_noob_json_object_set_new(info_obj,SERV_URL,eap_noob_json_string(data->serv_config_params->Serv_URL));

                if(NULL == (data->serv_info = eap_noob_json_dumps(info_obj,JSON_COMPACT|JSON_PRESERVE_ORDER)) || 
						(strlen(data->serv_info) > MAX_INFO_LEN)){
                	wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no server info");
                        return FAILURE;
		}
                printf("PEER INFO = %s\n",data->serv_info);
        }

        return SUCCESS;
}

static int eap_noob_read_config(struct eap_noob_serv_context * data)
{
        FILE * conf_file = NULL;
        char * buff = NULL;

        if(NULL == (conf_file = fopen(CONF_FILE,"r"))){
                wpa_printf(MSG_ERROR, "EAP-NOOB: Configuration file not found");
                return FAILURE;
        }

        if((NULL == (buff = malloc(MAX_CONF_LEN))) ||
        (NULL == (data->server_attr->serv_config_params =
                malloc(sizeof(struct eap_noob_serv_config_params)))))
                return FAILURE;

        data->server_attr->config_params = 0;
        while(!feof(conf_file)){
                if(fgets(buff,MAX_CONF_LEN, conf_file)){
                        eap_noob_parse_config(buff,data->server_attr);
                        memset(buff,0,MAX_CONF_LEN);
                }
        }

        free(buff);

	//TODO: version and csuites are compared for the first value inside the 
	//respective array. This needs to changed when there is more than one value.
	
	if((data->server_attr->version[0] > MAX_SUP_VER) || 
		(data->server_attr->cryptosuite[0] > MAX_SUP_CSUITES) || 
		(data->server_attr->dir > BOTH_DIR)){

                wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect confing value");	
		return FAILURE;
	}
		 
 
        if(data->server_attr->config_params != CONF_PARAMS && 
                FAILURE == eap_noob_handle_incomplete_conf(data))
                return FAILURE;

        return eap_noob_prepare_serv_info_obj(data->server_attr);

}
/**
 * eap_oob_serv_ctxt_init -Supporting Initializer for EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @data: Pointer to EAP-NOOB data
 **/
static int eap_noob_serv_ctxt_init( struct eap_noob_serv_context * data, struct eap_sm *sm)
{
	/*TODO: remove hard codings and initialize preferably through a
	  config file*/
	int retval = FAILURE;
	size_t len = 0;

	if((NULL != (data->peer_attr = os_zalloc( sizeof (struct eap_noob_peer_data)))) && 
			(NULL != (data->server_attr = os_zalloc( sizeof (struct eap_noob_server_data))))){

		data->peer_attr->serv_state = UNREG;
		data->peer_attr->peer_state = UNREG;
		data->peer_attr->err_code = NO_ERROR;
		data->peer_attr->rcvd_params = 0;	
		data->peer_attr->minslp_count = 0;

		/* Setup DB */
		/* DB file name for the server */
		data->db_name = (char *) os_strdup("peer_connection_db");
		/* DB Table name */
		data->db_table_name = (char *) os_strdup("peers_connected");

		
		if (sm->identity) {
			data->peer_attr->NAI = os_zalloc(sm->identity_len);
			if (data->peer_attr->NAI == NULL) {
				eap_noob_set_error(data->peer_attr,E1001);
				return FAILURE;
			}
			os_memcpy(data->peer_attr->NAI, sm->identity, sm->identity_len);
			len = sm->identity_len;
		}

		if(SUCCESS == (retval = eap_noob_parse_NAI(data,len))){			
			if(!(retval = eap_noob_create_db(data))) return retval;
			
			if(data->peer_attr->peerID_gen){
				if(eap_noob_verify_peerID(data) && 
				   eap_noob_verify_state(data));

				if((data->peer_attr->serv_state == WAITING || 
					data->peer_attr->serv_state == OOB) && 
					eap_noob_verify_oob_msg_len(data->peer_attr));		
			}

			if(data->peer_attr->err_code == NO_ERROR){
				data->peer_attr->next_req = 
				eap_noob_get_next_req(data->peer_attr);		
			}

			if(data->peer_attr->serv_state == UNREG ||
                        data->peer_attr->serv_state == RECONNECT){

                        if(FAILURE == eap_noob_read_config(data)){
                                wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to initialize context");
                                return FAILURE;
                        }
                }

		}
	}
	return retval;

}

/**
 * eap_oob_init - Initialize the EAP-NOOB Peer Method
 * Allocates memory for the EAP-NOOB data
 * @sm: Pointer to EAP State Machine data
 **/
static void * eap_noob_init(struct eap_sm *sm)
{

	struct eap_noob_serv_context * data;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER");
	if(NULL == (data = os_zalloc( sizeof (struct eap_noob_serv_context))))
	{
		wpa_printf(MSG_DEBUG, "EAP-NOOB: INIT SERVER Fail to Allocate Memory");

		return NULL;
	}
	//TODO: check if hard coded initialization can be avoided
	if(FAILURE == eap_noob_serv_ctxt_init(data,sm)){
		wpa_printf(MSG_DEBUG,"EAP-NOOB: INIT SERVER Fail to initialize context");
		return NULL;
	}
	return data;

}


/**

 * this method is to generate peer id

 **/

int eap_noob_get_id_peer(char *str, size_t size)
{
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Generating PeerID");

	const u8 charset[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";//!#$%&'*+-/=?^_`{|}~";
	time_t t = 0;
	srand((unsigned)time(&t));
	//To-Do: Check whether the generated Peer ID is already in db
	if (size) {
		size_t n;
		for (n = 0; n < size; n++) {
			int key = rand() % (int) (sizeof charset - 1);
			str[n] = charset[key];
		}
		str[n] = '\0';
	}

	if (str != NULL)
		return 0;

	return 1;
}

#if 1

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

#endif

#if 1

static int eap_noob_derive_session_secret(struct eap_noob_serv_context *data, size_t *secret_len) //ToDo: Rename this function as secret_key
{

	BIGNUM *big_pub_peer;//public key of peer 
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
	x_len = eap_noob_Base64Decode(data->peer_attr->x_peer_b64, &x, &len);	
	y_len = eap_noob_Base64Decode(data->peer_attr->y_peer_b64, &y, &len);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: deriving NID_secp256k1.");
	ec_pub_peer = EC_KEY_new_by_curve_name(NID_secp256k1);

	if (ec_pub_peer == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to create EC_KEYs");
		return 1;
	}

	/* Get the group used */
	ec_group = EC_KEY_get0_group(ec_pub_peer);
	if(ec_group == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get GROUP");
		return 1;
	}

	/* Peer u8 PUB Key to EC_KEY */
	big_pub_peer = BN_bin2bn(data->peer_attr->peer_public_key, data->peer_attr->pub_key_peer_len, NULL);
	x_big = BN_bin2bn(x,x_len,NULL);
	y_big = BN_bin2bn(y,y_len,NULL);
	
	if (big_pub_peer == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to convert Peer PUB KEY BIN to BIGNUM.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_POINT_bn2point");
	ecpoint_pub_peer = EC_POINT_new(ec_group);
	
	if(EC_POINT_set_affine_coordinates_GFp(ec_group, ecpoint_pub_peer, x_big, y_big,NULL) ==0)
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in affine coordinate setting");


	//ecpoint_pub_peer = EC_POINT_bn2point(ec_group, big_pub_peer, ecpoint_pub_peer, NULL);
	/*if (EC_POINT_bn2point(ec_group, big_pub_peer, ecpoint_pub_peer, NULL) == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to convert Peer PUB KEY BIGNUM to EC_POINT.");
		return 1;
	}*/

	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key");

	if (!EC_KEY_set_public_key(ec_pub_peer, ecpoint_pub_peer)){
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
	if (!EVP_PKEY_paramgen(pctx, &evp_peer)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to create parameter object params.");
		return 1;
	}
	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_KEY_set_public_key done");


	if (!EVP_PKEY_set1_EC_KEY(evp_peer, ec_pub_peer)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to CONVERT EC_KEY to EVP_PKEY.");
		return 1;
	}
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret!.");


	/* Derive the secret */
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 1.");

	/* Create the context for the shared secret derivation */
	if(NULL == (ctx = EVP_PKEY_CTX_new(data->peer_attr->dh_key, NULL))) {
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
	/* Provide the peer public key */
	if(1 != EVP_PKEY_derive_set_peer(ctx, evp_peer)) {
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
	if(NULL == (data->peer_attr->shared_key = OPENSSL_malloc(*secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to create buffer OPENSSL_malloc.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 6.");

	/* Derive the shared secret */
	if(1 != (EVP_PKEY_derive(ctx, data->peer_attr->shared_key, secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to derive key EVP_PKEY_derive.");
		return 1;
	}
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",data->peer_attr->shared_key,*secret_len);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(evp_peer);
	//EVP_PKEY_free(evp_keypair); //this can be discarded once the shared secret is derived

	return 0;
}

#endif

/**
 *  * get_key - Generate Priv/Pub key pair based on the Csuite selected.
 *   * @data: Pointer to EAP-NOOB data
 *    * Returns: 1 if keys generated and stored successfully, or 0 if not
 *     **/
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
 	if(!ctx) 
 	wpa_printf(MSG_DEBUG, "EAP-NOOB: BN_CTX Error");


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
	if (1 != EVP_PKEY_keygen(kctx, &data->peer_attr->dh_key)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to generate keys.");
		return 0;
	}

	key = EVP_PKEY_get1_EC_KEY(data->peer_attr->dh_key);

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
	if(EC_POINT_get_affine_coordinates_GFp(group, pub, x, y, ctx) != 1)
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

	eap_noob_Base64Encode(x_val,x_len, &data->peer_attr->x_b64);	
	eap_noob_Base64Encode(y_val,y_len, &data->peer_attr->y_b64);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: X and Y %s,%s",data->peer_attr->x_b64, data->peer_attr->y_b64);	

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

static int eap_noob_get_minsleep(struct eap_noob_serv_context *data)
{
	//TODO:  Include actual implementation for calculating the waiting time.
	return (int)((eap_noob_cal_pow(2,data->peer_attr->minslp_count))* (rand()%8) + 1) % 3600 ;
}

static struct wpabuf * eap_noob_err_msg(struct eap_noob_serv_context *data, u8 id)
{
	noob_json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;
	int code = data->peer_attr->err_code;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error request");
	if (!code)
		return NULL;

	if(NULL != (req_obj = eap_noob_json_object())){

		if(data->peer_attr->peerID_gen){
			eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));	
		}
		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(NONE));
		eap_noob_json_object_set_new(req_obj,ERR_CODE,eap_noob_json_integer(error_code[code]));
		eap_noob_json_object_set_new(req_obj,ERR_INFO,eap_noob_json_string(error_info[code]));

		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT);
		printf("ERROR message = %s\n",req_json);
		len = strlen(req_json)+1; 

		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);

		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for NOOB ERROR message");
			os_free(req_json);
			return NULL;
		}
		
		if(FAILURE == eap_noob_db_update(data,UPDATE_STATE_ERROR)){
			//eap_oob_set_error(); //Internal error
			//set_done(data, NOT_DONE);
			wpa_printf(MSG_DEBUG,"Fail to Write Error to DB");
		}

		wpabuf_put_data(req,req_json,len);  
		os_free(req_json);
		eap_noob_set_done(data,DONE);
		eap_noob_set_success(data,FAILURE);
		data->peer_attr->err_code = NO_ERROR;
	}
	return req;
}


static void eap_noob_gen_KDF(struct eap_noob_serv_context * data, int state){

        const EVP_MD *md = EVP_sha256();
        int counter = 0;
        unsigned char * out = os_zalloc(192);

	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: ALGORITH ID:",ALGORITHM_ID,ALGORITHM_ID_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Peer_NONCE:",data->peer_attr->nonce_peer,EAP_NOOB_NONCE_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Serv_NONCE:",data->peer_attr->nonce_serv,EAP_NOOB_NONCE_LEN);

	if(state == COMPLETION_EXCHANGE){
		
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: NOOB:",data->peer_attr->noob,EAP_NOOB_NONCE_LEN);
        	eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                	data->peer_attr->shared_key, EAP_SHARED_SECRET_LEN,
                	(unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                	data->peer_attr->nonce_peer, EAP_NOOB_NONCE_LEN,
                	data->peer_attr->nonce_serv, EAP_NOOB_NONCE_LEN,
                	data->peer_attr->noob, EAP_NOOB_NONCE_LEN, md);
	}else{
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: kz:",data->peer_attr->kz,KZ_LEN);
        	eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
                	data->peer_attr->kz, KZ_LEN,
                	(unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
                	data->peer_attr->nonce_peer, EAP_NOOB_NONCE_LEN,
                	data->peer_attr->nonce_serv, EAP_NOOB_NONCE_LEN,
                	NULL, 0, md);
	}	
        wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: KDF",out,KDF_LEN);

        if(out != NULL){
                data->peer_attr->msk = os_zalloc(MSK_LEN);
                data->peer_attr->emsk = os_zalloc(EMSK_LEN);
                data->peer_attr->kms = os_zalloc(KMS_LEN);
                data->peer_attr->kmp = os_zalloc(KMP_LEN);
                data->peer_attr->kz = os_zalloc(KZ_LEN);

                memcpy(data->peer_attr->msk,out,MSK_LEN);
                counter += MSK_LEN;
                memcpy(data->peer_attr->emsk, out + counter, EMSK_LEN);
                counter += EMSK_LEN;
                memcpy(data->peer_attr->kms, out + counter, KMS_LEN);
                counter += KMS_LEN;
                memcpy(data->peer_attr->kmp, out + counter, KMP_LEN);
                counter += KMP_LEN;
                memcpy(data->peer_attr->kz, out + counter, KZ_LEN);
                counter += KZ_LEN;
        }
}

static char * eap_noob_prepare_hoob_arr(struct eap_noob_serv_context * data){

	noob_json_t * hoob_arr = NULL;
	noob_json_t * ver_arr = NULL;
	noob_json_t * csuite_arr = NULL;
	char * hoob_str = NULL;
	noob_json_error_t error;
	u32 count  = 0;
        int dir = (data->server_attr->dir & data->peer_attr->dir);

        wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
	if(NULL != (hoob_arr = eap_noob_json_array())){
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(dir));
		
		if(NULL == (ver_arr = eap_noob_json_array())){
			free(hoob_arr);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_VER ; count++){
			eap_noob_json_array_append(ver_arr,eap_noob_json_integer(data->server_attr->version[count]));
		}

		eap_noob_json_array_append(hoob_arr,ver_arr);

		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->peer_attr->version));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->peer_attr->peerID_gen));
	
		if(NULL == (csuite_arr = eap_noob_json_array())){
			free(hoob_arr);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_CSUITES ; count++){
			eap_noob_json_array_append(csuite_arr,eap_noob_json_integer(data->server_attr->cryptosuite[count]));
		}

		eap_noob_json_array_append(hoob_arr,csuite_arr);
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->server_attr->dir));
			
		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->server_attr->serv_info));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->peer_attr->cryptosuite));
			
		eap_noob_json_array_append(hoob_arr,eap_noob_json_integer(data->peer_attr->dir));
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->peer_attr->peer_info));
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_loads(eap_noob_json_dumps(data->peer_attr->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->peer_attr->nonce_serv_b64));
			
		eap_noob_json_array_append(hoob_arr,eap_noob_json_loads(eap_noob_json_dumps(data->peer_attr->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		
		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->peer_attr->nonce_peer_b64));

		eap_noob_json_array_append(hoob_arr,eap_noob_json_string(data->peer_attr->noob_b64));

		hoob_str = eap_noob_json_dumps(hoob_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
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

static char * eap_noob_prepare_mac_arr(struct eap_noob_serv_context * data,int type,int state){

	noob_json_t * mac_arr = NULL;
	noob_json_t * ver_arr = NULL;
	noob_json_t * csuite_arr = NULL;
	char * mac_str = NULL;
	noob_json_error_t error;
	u32 count  = 0;

        wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
	if(NULL != (mac_arr = eap_noob_json_array())){
	
		if(type == MACP){
			eap_noob_json_array_append(mac_arr,eap_noob_json_integer(1));
		}

		if(type == MACS){
			eap_noob_json_array_append(mac_arr,eap_noob_json_integer(2));
		}
		
		if(NULL == (ver_arr = eap_noob_json_array())){
			free(mac_arr);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_VER ; count++){
			eap_noob_json_array_append(ver_arr,eap_noob_json_integer(data->server_attr->version[count]));
		}

		eap_noob_json_array_append(mac_arr,ver_arr);
		eap_noob_json_array_append(mac_arr,eap_noob_json_integer(data->peer_attr->version));
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->peer_attr->peerID_gen));
	
		if(NULL == (csuite_arr = eap_noob_json_array())){
			free(mac_arr);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_CSUITES ; count++){
			eap_noob_json_array_append(csuite_arr,eap_noob_json_integer(data->server_attr->cryptosuite[count]));
		}

		eap_noob_json_array_append(mac_arr,csuite_arr);
		if(state == COMPLETION_EXCHANGE){
			eap_noob_json_array_append(mac_arr,eap_noob_json_integer(data->server_attr->dir));
			
		}else{
			eap_noob_json_array_append(mac_arr,eap_noob_json_string(""));
		}
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->server_attr->serv_info));
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
			eap_noob_json_array_append(mac_arr,eap_noob_json_loads(eap_noob_json_dumps(data->peer_attr->jwk_serv,
					JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		}
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->peer_attr->nonce_serv_b64));
		if(state == RECONNECT_EXCHANGE){
			eap_noob_json_array_append(mac_arr,eap_noob_json_string(""));
		
		}else{
			eap_noob_json_array_append(mac_arr,eap_noob_json_loads(eap_noob_json_dumps(data->peer_attr->jwk_peer,
				JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		}
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->peer_attr->nonce_peer_b64));
		eap_noob_json_array_append(mac_arr,eap_noob_json_string(data->peer_attr->noob_b64));

		mac_str = eap_noob_json_dumps(mac_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
	}

	free(ver_arr);
	free(csuite_arr);
	return mac_str;
}


static u8 * eap_noob_gen_MAC(struct eap_noob_serv_context * data, int type, u8 * key, int keylen, int state){

        u8 * mac = NULL;
	char * mac_str = NULL;

        wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);

        	
	if(NULL != (mac_str = eap_noob_prepare_mac_arr(data, type, state))){
		printf("MAC_STR = %s\n", mac_str);
		printf("LENGTH = %d\n",(int)strlen(mac_str));
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: KEY:",key,keylen);
		mac = HMAC(EVP_sha256(), key, keylen, (u8 *)mac_str, strlen(mac_str), NULL, NULL);
        	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: MACp",mac,32);
	}

        return mac;
}


static struct wpabuf * eap_noob_req_type_seven(struct eap_noob_serv_context *data, u8 id){

	noob_json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;
	
	u8 * mac = NULL;
	char * mac_b64 = NULL;


	/*generate KDF*/
        eap_noob_gen_KDF(data,RECONNECT_EXCHANGE);

        /*generate MAC*/
        mac = eap_noob_gen_MAC(data,MACS,data->peer_attr->kms, KMS_LEN, RECONNECT_EXCHANGE);
	eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);
	
	//TODO : calculate MAC for encoding 
	if(NULL != (req_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_7));
		eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));	
		eap_noob_json_object_set_new(req_obj,MACs,eap_noob_json_string(mac_b64));	

		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT);
		len = strlen(req_json)+1; 

		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);

		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Request/NOOB-FR");
			os_free(req_json);
			return NULL;
		}

		wpabuf_put_data(req,req_json,len);  
		os_free(req_json);
	}
	return req;
}

/**
 * eap_oob_req_type_six - Build the EAP-Request/Fast Reconnect 2.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/

static struct wpabuf * eap_noob_req_type_six(struct eap_noob_serv_context *data, u8 id){

	noob_json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;
	char * base64_nonce;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 2/Fast Reconnect");

	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;
	}
	data->peer_attr->nonce_serv = os_zalloc(EAP_NOOB_NONCE_LEN);

	int rc = RAND_bytes(data->peer_attr->nonce_serv, EAP_NOOB_NONCE_LEN);// To-Do base64 encoding
	unsigned long err = ERR_get_error();

	if(rc != 1) {

		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);	
	}

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->peer_attr->nonce_serv, EAP_NOOB_NONCE_LEN);

	
	//ToDo: Based on the previous and the current versions of cryptosuites of peers, decide whether new public key has to be generated 	

	//TODO: change get key params and finally store only base 64 encoded public key	
	eap_noob_Base64Encode(data->peer_attr->nonce_serv,EAP_NOOB_NONCE_LEN, &base64_nonce);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s",base64_nonce);
	
	data->peer_attr->nonce_serv_b64 = base64_nonce;

	if(NULL != (req_obj = eap_noob_json_object())){ 

		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_6));
		eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));
		eap_noob_json_object_set_new(req_obj,NONCE_SERV,eap_noob_json_string(base64_nonce));
	

		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT);

		wpa_printf(MSG_DEBUG, "EAP-NOOB: request %s",req_json);	
		len = strlen(req_json)+1; //check here

		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);// len +1 for null termination

		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Request/NOOB-FR");
			os_free(base64_nonce);
			os_free(req_json);
			return NULL;
		}

		wpabuf_put_data(req,req_json,len);	
		os_free(req_json);

	}
	return req;
}

/**
 * eap_oob_req_type_five - Build the EAP-Request/Fast Reconnect 1.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_five(struct eap_noob_serv_context *data, u8 id)
{
	/* (Type=1,PeerId,CryptoSuites,Dirs,ServerInfo) */

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 1/Fast Reconnect");

	size_t len;
	struct wpabuf *req = NULL;
	char * req_json= NULL;
	u32 count  = 0;
	noob_json_t * req_obj = NULL;
	noob_json_t * csuite_arr = NULL;


	//if((NULL != (req_obj = eap_noob_json_object())) && eap_oob_db_entry(data)){
	if(NULL != (req_obj = eap_noob_json_object())){
		
		if(NULL == (csuite_arr = eap_noob_json_array())){
			free(req_obj);
			return NULL;
		}
		for(count = 0; count < MAX_SUP_CSUITES ; count++){
			eap_noob_json_array_append(csuite_arr,eap_noob_json_integer(data->server_attr->cryptosuite[count]));
		}
	

		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_5));
		eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));
		eap_noob_json_object_set_new(req_obj,CSUITES_SERV,csuite_arr);
		eap_noob_json_object_set_new(req_obj,SERV_INFO,eap_noob_prepare_serv_json_obj(data->server_attr->serv_config_params));//To-Do send this only if changed (check even at peer side)

		//free(csuite_arr);
		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT);
		len = strlen(req_json);//check here	
		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len+1 , EAP_CODE_REQUEST, id);
		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Request/NOOB-FR");
			return NULL;
		}

		wpabuf_put_data(req,req_json,len+1);	
		os_free(req_json);
	}	
	return req;		

}

static struct wpabuf * eap_noob_req_type_four(struct eap_noob_serv_context *data, u8 id){

	noob_json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;
	
	u8 * mac = NULL;
	char * mac_b64 = NULL;
	u8 * hoob = os_zalloc(HASH_LEN);
	char * hoob_b64 = NULL;

	     /*generate HOOB*/
        if(!eap_noob_get_hoob(data,hoob, HASH_LEN)){
                wpa_printf(MSG_DEBUG,"EAP-NOOB: ERROR in HOOB");
		//TODO : send internal error
        }
        else{
                //data->peer_attr->hoob = hoob_out;
                wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: HOOB",hoob,HASH_LEN);
                eap_noob_Base64Encode(hoob, HASH_LEN, &hoob_b64);
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Hoob Base64 %s", hoob_b64);
        }

	 	
	if(0 != strcmp((char *)hoob, (char *)data->peer_attr->hoob)){
		eap_noob_set_error(data->peer_attr,E4001);
		return eap_noob_err_msg(data,id);
	}
	
	 /*generate KDF*/
        eap_noob_gen_KDF(data,COMPLETION_EXCHANGE);
        /*generate MAC*/
        mac = eap_noob_gen_MAC(data,MACS,data->peer_attr->kms, KMS_LEN,COMPLETION_EXCHANGE);
	eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

	eap_noob_Base64Encode(data->peer_attr->kms, KMS_LEN, &data->peer_attr->kms_b64);
	eap_noob_Base64Encode(data->peer_attr->kmp, KMP_LEN, &data->peer_attr->kmp_b64);
	eap_noob_Base64Encode(data->peer_attr->kz, KZ_LEN, &data->peer_attr->kz_b64);
	
	//TODO : calculate MAC for encoding 
	if(NULL != (req_obj = eap_noob_json_object())){

		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_4));
		eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));	
		eap_noob_json_object_set_new(req_obj,MACs,eap_noob_json_string(mac_b64));	

		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT);
		len = strlen(req_json)+1; 

		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);

		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Request/NOOB-CE");
			os_free(req_json);
			return NULL;
		}

		wpabuf_put_data(req,req_json,len);  
		os_free(req_json);
	}
	return req;
}



static struct wpabuf * eap_noob_req_type_three(struct eap_noob_serv_context *data, u8 id){

	noob_json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 3/Waiting Exchange");
	if(NULL != (req_obj = eap_noob_json_object())){

		data->peer_attr->minsleep = eap_noob_get_minsleep(data);
		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_3));
		eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));	
		eap_noob_json_object_set_new(req_obj,MINSLEEP,eap_noob_json_integer(data->peer_attr->minsleep));
		clock_gettime(CLOCK_REALTIME, &data->peer_attr->sleep_time);
		wpa_printf(MSG_DEBUG,"Current Time is %ld",data->peer_attr->sleep_time.tv_sec);
		data->peer_attr->sleep_time.tv_sec = data->peer_attr->sleep_time.tv_sec + data->peer_attr->minsleep;

		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT);
		len = strlen(req_json)+1; 

		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);

		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Request/NOOB-WE");
			os_free(req_json);
			return NULL;
		}

		wpabuf_put_data(req,req_json,len);  
		os_free(req_json);
	}
	return req;
}
/**
 * eap_oob_req_type_two - Build the EAP-Request/Initial Exchange 2.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/

static struct wpabuf * eap_noob_req_type_two(struct eap_noob_serv_context *data, u8 id){

	noob_json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;
	//char* base64_pubkey;
	char* base64_nonce;

	//char * check;
	//char * check1; 
	//noob_json_t * test = NULL;
	//noob_json_t * jwk = NULL;
	
	if(NULL != (data->peer_attr->jwk_serv = eap_noob_json_object())){ 
		eap_noob_json_object_set_new(data->peer_attr->jwk_serv,KEY_TYPE,eap_noob_json_string("EC"));	
		eap_noob_json_object_set_new(data->peer_attr->jwk_serv,CURVE,eap_noob_json_string("P-256"));	
		//eap_noob_json_object_set_new(jwk,"kid",eap_noob_json_string("1234"));
	}else{
		wpa_printf(MSG_DEBUG,"EAP-NOOB: Error in JWK");
	}	
	
	//check1 = eap_noob_json_dumps(jwk,JSON_COMPACT);	
	//wpa_printf(MSG_DEBUG, "EAP-NOOB: request- check1 %s",check1);	

	//unsigned char *decode_nonce;
	//unsigned char *decode_key;
	//size_t decode_length;
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 2/Initial Exchange");

	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;
	}
	data->peer_attr->nonce_serv = os_zalloc(EAP_NOOB_NONCE_LEN);
	/*if (os_get_random(data->peer_attr->nonce_serv, EAP_NOOB_NONCE_LEN)) {
	  wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to generate the nonce");
	  set_done(data,DONE);
	  set_success(data,FAIL);
	  return NULL;
	  }*/

	int rc = RAND_bytes(data->peer_attr->nonce_serv, EAP_NOOB_NONCE_LEN);// To-Do base64 encoding
	unsigned long err = ERR_get_error();

	if(rc != 1) {

		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);	
	}

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->peer_attr->nonce_serv, EAP_NOOB_NONCE_LEN);
	//data->server_attr->nonce = 1234;

	/* Generate Key material */
	if (eap_noob_get_key(data) == 0)  {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");	
		eap_noob_set_done(data,DONE);
		eap_noob_set_success(data,FAILURE);
		return NULL;
	}
	
	
	eap_noob_json_object_set_new(data->peer_attr->jwk_serv,X_COORDINATE,eap_noob_json_string(data->peer_attr->x_b64));
	eap_noob_json_object_set_new(data->peer_attr->jwk_serv,Y_COORDINATE,eap_noob_json_string(data->peer_attr->y_b64));

	//TODO: change get key params and finally store only base 64 encoded public key	
	//eap_noob_Base64Encode(data->peer_attr->serv_public_key, data->peer_attr->pub_key_server_len, &base64_pubkey);
	//wpa_printf(MSG_DEBUG,"EAP-NOOB: Public Key %s",base64_pubkey);
	eap_noob_Base64Encode(data->peer_attr->nonce_serv,EAP_NOOB_NONCE_LEN, &base64_nonce);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s",base64_nonce);
	
	data->peer_attr->nonce_serv_b64 = base64_nonce;
	//data->peer_attr->serv_public_key_b64 = base64_pubkey;

	if(NULL != (req_obj = eap_noob_json_object())){ 

		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_2));
		eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));
		eap_noob_json_object_set_new(req_obj,NONCE_SERV,eap_noob_json_string(base64_nonce));
		//eap_noob_json_object_set_new(req_obj,PUBLICKEY_SERV,eap_noob_json_string(base64_pubkey));
		eap_noob_json_object_set_new(req_obj,JSON_WEB_KEY,data->peer_attr->jwk_serv);
		

		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);

		wpa_printf(MSG_DEBUG, "EAP-NOOB: request %s",req_json);	
		len = strlen(req_json)+1; //check here

		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len , EAP_CODE_REQUEST, id);// len +1 for null termination

		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Request/NOOB-IE");
			os_free(base64_nonce);
			//os_free(base64_pubkey);
			os_free(req_json);
			return NULL;
		}

		wpabuf_put_data(req,req_json,len);	
		os_free(req_json);

	}
	//eap_noob_Base64Decode(base64_pubkey, &decode_key, &decode_length);
	//wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Key Verify", decode_key, decode_length);
	//os_free(base64_nonce);
	//os_free(base64_pubkey);
	return req;
}

/**
 * eap_oob_req_type_one - Build the EAP-Request/Initial Exchange 1.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to EAP-NOOB data
 * @id: EAP packet ID
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_req_type_one(struct eap_noob_serv_context *data, u8 id)
{
	/* (Type=1,PeerId,CryptoSuites,Dirs,ServerInfo) */

	u32 count  = 0;
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Request 1/Initial Exchange");

	size_t len;
	struct wpabuf *req = NULL;
	char * req_json= NULL;

	// Temp variables
	char id_peer[MAX_PEER_ID_LEN + 1] = {0}; // +1 for null termination

	noob_json_t * req_obj = NULL;
	noob_json_t * ver_arr = NULL;
	noob_json_t * csuite_arr = NULL;


	/* build PeerID */
	if (eap_noob_get_id_peer(id_peer, MAX_PEER_ID_LEN)) {
		wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to generate PeerID");
		return NULL;
	}

	data->peer_attr->peerID_gen = os_zalloc(MAX_PEER_ID_LEN);
	strcat(data->peer_attr->peerID_gen, id_peer);

	if(NULL != (req_obj = eap_noob_json_object())){
		
		if(NULL == (ver_arr = eap_noob_json_array())){
			free(req_obj);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_VER ; count++){
			eap_noob_json_array_append(ver_arr,eap_noob_json_integer(data->server_attr->version[count]));
		}

		
		if(NULL == (csuite_arr = eap_noob_json_array())){
			free(req_obj);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_CSUITES ; count++){
			eap_noob_json_array_append(csuite_arr,eap_noob_json_integer(data->server_attr->cryptosuite[count]));
		}
		eap_noob_json_object_set_new(req_obj,TYPE,eap_noob_json_integer(EAP_NOOB_TYPE_1));
		eap_noob_json_object_set_new(req_obj,VERSION_SERV,ver_arr);
		eap_noob_json_object_set_new(req_obj,PEERID,eap_noob_json_string(data->peer_attr->peerID_gen));
		eap_noob_json_object_set_new(req_obj,CSUITES_SERV,csuite_arr);
		eap_noob_json_object_set_new(req_obj,DIRECTION_SERV,eap_noob_json_integer(data->server_attr->dir));
		eap_noob_json_object_set_new(req_obj,SERV_INFO,eap_noob_prepare_serv_json_obj(data->server_attr->serv_config_params));
		
		req_json = eap_noob_json_dumps(req_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
		printf("REQ Received = %s\n", req_json);
		len = strlen(req_json);//check here
		req = eap_msg_alloc(EAP_VENDOR_IETF, EAP_TYPE_NOOB,len+1 , EAP_CODE_REQUEST, id);
		if (req == NULL) {
			wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to allocate memory "
					"for Request/NOOB-IE");
			return NULL;
		}

		wpabuf_put_data(req,req_json,len+1);	
		os_free(req_json);
	}	
	return req;		

}



/**
 * eap_oob_buildReq - Build the EAP-Request packets.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @id: EAP response to be processed (eapRespData)
 * Returns: Pointer to allocated EAP-Request packet, or NULL if not.
 **/
static struct wpabuf * eap_noob_buildReq(struct eap_sm *sm, void *priv, u8 id)
{
	wpa_printf(MSG_DEBUG, "EAP-NOOB: BUILDREQ SERVER");


	struct eap_noob_serv_context *data = priv;

	printf("next req = %d\n", data->peer_attr->next_req);
	//TODO : replce switch case with function pointers.
	switch (data->peer_attr->next_req) {

		case NONE:
			return eap_noob_err_msg(data,id);

		case EAP_NOOB_TYPE_1:
			return eap_noob_req_type_one(data, id); // 1st IE Request

		case EAP_NOOB_TYPE_2:
			return eap_noob_req_type_two(data, id); // 2nd IE Request

		case EAP_NOOB_TYPE_3:
			return eap_noob_req_type_three(data,id);

		case EAP_NOOB_TYPE_4:
			return eap_noob_req_type_four(data,id);
		case EAP_NOOB_TYPE_5:
			return eap_noob_req_type_five(data,id);
		case EAP_NOOB_TYPE_6:
			return eap_noob_req_type_six(data,id);
		case EAP_NOOB_TYPE_7:
			return eap_noob_req_type_seven(data,id);

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
static Boolean eap_noob_check(struct eap_sm *sm, void *priv,
		struct wpabuf *respData)
{
	wpa_printf(MSG_INFO, "EAP-NOOB: Checking EAP-Response packet.");

	struct eap_noob_serv_context *data = priv;
	const u8 *pos;
	size_t len;

	noob_json_t * resp_obj = NULL;  //TODO: free
	noob_json_t * resp_type = NULL; //TODO: free
	noob_json_error_t error;
	u32 state = data->peer_attr->serv_state; 

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);


	resp_obj = eap_noob_json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);

	if((NULL != resp_obj) && (eap_noob_json_is_object(resp_obj) > 0)){

		resp_type = eap_noob_json_object_get(resp_obj,TYPE);

		if((NULL != resp_type) && (eap_noob_json_is_integer(resp_type) > 0)){
			data->peer_attr->recv_msg = eap_noob_json_integer_value(resp_type);
		}else{
			wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown message type");
			os_free(resp_obj);
			os_free(resp_type);
			eap_noob_set_error(data->peer_attr,E1002);
			return FALSE;		
		}
	}
	else{
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Request with unknown format received");
		os_free(resp_obj);
		eap_noob_set_error(data->peer_attr,E1002);
		return FALSE;		
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Received frame: opcode=%d", data->peer_attr->recv_msg);
	printf("STATE = %d\n",data->peer_attr->serv_state);

	printf("VERIFY STATE SERV = %d PEER = %d\n", data->peer_attr->serv_state,
				data->peer_attr->peer_state);
	if((NONE != data->peer_attr->recv_msg) && ((state >= NUM_OF_STATES) || 
			(data->peer_attr->recv_msg > MAX_MSG_TYPES) || 
			(VALID != state_message_check[state][data->peer_attr->recv_msg]))){
		eap_noob_set_error(data->peer_attr,E1004);	
		return FALSE;
	}		
	return FALSE;

}

static void eap_noob_verify_param_len(struct eap_noob_peer_data * data)
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
					if(strlen(data->peerID_rcvd) > MAX_PEER_ID_LEN){	
						eap_noob_set_error(data,E1003);
					}
					break;
				case NONCE_RCVD:
					if(strlen((char *)data->nonce_peer) > EAP_NOOB_NONCE_LEN){
						eap_noob_set_error(data,E1003);
					}
					break;
				case MAC_RCVD:
					if(strlen(data->mac) > MAC_LEN){
						eap_noob_set_error(data,E1003);	
					}					
					break;
				case INFO_RCVD:
					if(strlen(data->peer_info) > MAX_INFO_LEN){
						eap_noob_set_error(data,E1003);
					}
					break;					
			}
		}
		pos = pos<<1;
	}
}

int eap_noob_FindIndex( int value )
{
    int index = 0;  

    while ( index < 13 && error_code[index] != value ) ++index;

    return index;
}

static void  eap_noob_decode_obj(struct eap_noob_peer_data * data ,noob_json_t * resp_obj)
{

	const char * key;
	noob_json_t * value;

	size_t decode_length;
	size_t decode_length_key;
	size_t decode_length_nonce;
	int retval_int = 0;
	const char* retval_char = NULL;
	noob_json_error_t error;

	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return;
	}


	json_object_foreach(resp_obj, key, value) {
		switch(eap_noob_json_typeof(value)){

			case JSON_OBJECT:
				if(0 == strcmp(key,JSON_WEB_KEY)){
					wpa_printf(MSG_DEBUG,"EAP-NOOB: Copy verify: %s",eap_noob_json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER));
					data->jwk_peer = eap_noob_json_loads(eap_noob_json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER),
								JSON_COMPACT|JSON_PRESERVE_ORDER,&error);	
					wpa_printf(MSG_DEBUG,"EAP-NOOB: Copy verify1: %s",eap_noob_json_dumps(data->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER));
					data->rcvd_params |= PKEY_RCVD;
				}else if(0 == strcmp(key,PEER_INFO)){
					data->peer_info = eap_noob_json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER);	
					wpa_printf(MSG_DEBUG,"EAP-NOOB: Peer Info: %s",data->peer_info);
					data->rcvd_params |= INFO_RCVD;	
				}
				eap_noob_decode_obj(data,value);
				break;

			case JSON_INTEGER:
					
				if(0 == (retval_int = eap_noob_json_integer_value(value)) && 0 != strcmp(key,TYPE) ){
					eap_noob_set_error(data,E1003);
					return;
				}
						
				if(0 == strcmp(key,VERSION_PEER)){
					data->version = retval_int;
					data->rcvd_params |= VERSION_RCVD;
				}
				else if(0 == strcmp(key, CSUITES_PEER)){
					data->cryptosuite = retval_int;
					data->rcvd_params |= CSUITE_RCVD;
				}
				else if(0 == strcmp(key, DIRECTION_PEER)){
					data->dir = retval_int;
					data->rcvd_params |= DIRECTION_RCVD;
				}else if(0 == strcmp(key, ERR_CODE)){
					eap_noob_set_error(data,eap_noob_FindIndex(retval_int));
				}
				break;

			case JSON_STRING:

				if(NULL == (retval_char = eap_noob_json_string_value(value))){
					eap_noob_set_error(data,E1003);
					return;
				}

				if(0 == strcmp(key, PEERID)){
					data->peerID_rcvd = os_strdup(retval_char);
					data->rcvd_params |= PEERID_RCVD;
				}
				else if(0 == strcmp(key, PUBLICKEY_PEER)){
					data->peer_public_key_b64 = os_strdup(retval_char);
					data->pub_key_peer_len = eap_noob_Base64Decode((char *)data->peer_public_key_b64, &data->peer_public_key, &decode_length_key);
				}
				else if(0 == strcmp(key, PEER_SERIAL_NUM)){
					data->peer_snum = os_strdup(retval_char);
				}
				else if(0 == strcmp(key, NONCE_PEER)){
					data->nonce_peer_b64 = os_strdup(retval_char);
					eap_noob_Base64Decode((char *)data->nonce_peer_b64, &data->nonce_peer, &decode_length_nonce);
					data->rcvd_params |= NONCE_RCVD;
				}
				else if(0 == strcmp(key, MACp)){
					//data->mac = os_strdup(retval_char);
					eap_noob_Base64Decode((char *)retval_char, (u8**)&data->mac,&decode_length);
					data->rcvd_params |= MAC_RCVD;
				}
			    else if(0 == strcmp(key, X_COORDINATE)){
					data->x_peer_b64 = os_strdup(eap_noob_json_string_value(value));
					wpa_printf(MSG_DEBUG, "X coordinate %s", data->x_peer_b64);
				}else if(0 == strcmp(key, Y_COORDINATE)){
					data->y_peer_b64 = os_strdup(eap_noob_json_string_value(value));
					wpa_printf(MSG_DEBUG, "Y coordinate %s", data->y_peer_b64);
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

static void eap_noob_rsp_type_seven(struct eap_sm *sm,
	struct eap_noob_serv_context *data,
	noob_json_t *resp_obj)
{
	u8 * mac = NULL;
	char * mac_b64 = NULL;

	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return ;		
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-3");	
	eap_noob_decode_obj(data->peer_attr,resp_obj);
	// TODO :  validate MAC address along with peerID


	if(data->peer_attr->rcvd_params != TYPE_SEVEN_PARAMS){
		eap_noob_set_error(data->peer_attr,E1002);
		eap_noob_set_done(data, NOT_DONE);
		return;
	}
	//check error code after decoding	
	if((data->peer_attr->err_code != NO_ERROR)){
		 eap_noob_set_done(data, NOT_DONE);
		 return;
	}

	if(eap_noob_verify_peerID(data) ){

        	mac = eap_noob_gen_MAC(data,MACP,data->peer_attr->kmp, KMP_LEN, RECONNECT_EXCHANGE);
		eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);

		//if(0 != strcmp(data->peer_attr->mac,mac_b64)){
		if(0 != strcmp(data->peer_attr->mac,(char *)mac+16)){
			eap_noob_set_error(data->peer_attr,E4001);
			eap_noob_set_done(data, NOT_DONE);
                 	return;
		}
		
		eap_noob_change_state(data,REGISTERED);		
		if(FAILURE == eap_noob_db_update(data,UPDATE_STATE)){
			return;
		}			
		data->peer_attr->next_req = NONE;
		eap_noob_set_done(data, DONE);
		eap_noob_set_success(data,SUCCESS);
	}
}


/**
 * eap_oob_rsp_type_six - Process EAP-Response/Fast Reconnect 2
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to private EAP-NOOB data
 * @payload: EAP data received from the peer
 * @payloadlen: Length of the payload
 **/
static void eap_noob_rsp_type_six(struct eap_sm *sm,
		struct eap_noob_serv_context *data,
		noob_json_t *resp_obj)
{
	
	
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-2");	
	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return ;		
	}


	eap_noob_decode_obj(data->peer_attr,resp_obj);

	if(data->peer_attr->rcvd_params != TYPE_SIX_PARAMS){
		eap_noob_set_error(data->peer_attr,E1002);
		eap_noob_set_done(data, NOT_DONE);
		return;
	}
	

	//check error code after decoding	
	if((data->peer_attr->err_code != NO_ERROR)){
		 eap_noob_set_done(data, NOT_DONE);
		 return;
	}

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->nonce_peer, EAP_NOOB_NONCE_LEN);

	if(eap_noob_verify_peerID(data))
	{
		data->peer_attr->next_req = EAP_NOOB_TYPE_7;
		eap_noob_set_done(data, NOT_DONE);
		data->peer_attr->rcvd_params = 0;
	}
}

/**
 * eap_oob_rsp_type_five - Process EAP-Response/Fast reconnect 1
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to private EAP-NOOB data
 * @payload: EAP data received from the peer
 * @payloadlen: Length of the payload
 **/
static void eap_noob_rsp_type_five(struct eap_sm *sm,
		struct eap_noob_serv_context *data,
		noob_json_t *resp_obj)
{
	/*check for the supporting cryptosuites, peerID_gen, version, direction*/
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-FR-1");	

	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return ;		
	}

	//ToDo: Check for the current cryptosuite and the previous to decide whether new key exchange has to be done
	eap_noob_decode_obj(data->peer_attr,resp_obj);
	//check error code after decoding	
	if((data->peer_attr->err_code != NO_ERROR)){
		 eap_noob_set_done(data, NOT_DONE);
		 return;
	}

	if(data->peer_attr->rcvd_params != TYPE_FIVE_PARAMS){
		eap_noob_set_error(data->peer_attr,E1002);
		eap_noob_set_done(data, NOT_DONE);
		return;
	}
	
	
	if(eap_noob_verify_peerID(data)){ 
		data->peer_attr->next_req = EAP_NOOB_TYPE_6;
	}
	eap_noob_set_done(data, NOT_DONE);
	data->peer_attr->rcvd_params = 0;	
}

static void eap_noob_rsp_type_four(struct eap_sm *sm,
	struct eap_noob_serv_context *data,
	noob_json_t *resp_obj)
{
	u8 * mac = NULL;
	char * mac_b64 = NULL;

	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return ;		
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-CE-4");	
	eap_noob_decode_obj(data->peer_attr,resp_obj);
	// TODO :  validate MAC address along with peerID


	if(data->peer_attr->rcvd_params != TYPE_FOUR_PARAMS){
		eap_noob_set_error(data->peer_attr,E1002);
		eap_noob_set_done(data, NOT_DONE);
		return;
	}
	//check error code after decoding	
	if((data->peer_attr->err_code != NO_ERROR)){
		 eap_noob_set_done(data, NOT_DONE);
		 return;
	}

	if(eap_noob_verify_peerID(data) ){

        	mac = eap_noob_gen_MAC(data,MACP,data->peer_attr->kmp, KMP_LEN, COMPLETION_EXCHANGE);
		eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);

		//if(0 != strcmp(data->peer_attr->mac,mac_b64)){
		if(0 != strcmp(data->peer_attr->mac,(char *)mac+16)){
			eap_noob_set_error(data->peer_attr,E4001);
			eap_noob_set_done(data, NOT_DONE);
                 	return;
		}
		
		eap_noob_change_state(data,REGISTERED);		
		if(FAILURE == eap_noob_db_update(data,UPDATE_PERSISTENT_KEYS_SECRET)){
			return;
		}			
		data->peer_attr->next_req = NONE;
		eap_noob_set_done(data, DONE);
		eap_noob_set_success(data,SUCCESS);
	}
}

static void eap_noob_rsp_type_three(struct eap_sm *sm,
		struct eap_noob_serv_context *data,
		noob_json_t *resp_obj)
{
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-WE-3");	
	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return ;		
	}

	eap_noob_decode_obj(data->peer_attr,resp_obj);


	if(data->peer_attr->rcvd_params != TYPE_THREE_PARAMS){
		eap_noob_set_error(data->peer_attr,E1002);
		eap_noob_set_done(data, NOT_DONE);
		return;
	}
	//check error code after decoding	
	if((data->peer_attr->err_code != NO_ERROR)){
		 eap_noob_set_done(data, NOT_DONE);
		 return;
	}

	if((eap_noob_verify_peerID(data)) && (SUCCESS == eap_noob_change_state(data,WAITING))){

		data->peer_attr->minslp_count++;

		if(MAX_WAIT_EXCHNG_TRIES == data->peer_attr->minslp_count){
			eap_noob_set_error(data->peer_attr,E2001);
                	eap_noob_set_done(data, NOT_DONE);
                	return;
		}
	
		if(FAILURE == eap_noob_db_update(data,UPDATE_STATE_MINSLP)){
			//eap_oob_set_error(); //Internal error
			//set_done(data, NOT_DONE);
			return;
		}
		data->peer_attr->next_req = NONE;
		eap_noob_set_done(data, DONE);
		eap_noob_set_success(data,FAILURE);
	}
}
/**
 * eap_oob_rsp_type_two - Process EAP-Response/Initial Exchange 2
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to private EAP-NOOB data
 * @payload: EAP data received from the peer
 * @payloadlen: Length of the payload
 **/
static void eap_noob_rsp_type_two(struct eap_sm *sm,
		struct eap_noob_serv_context *data,
		noob_json_t *resp_obj)
{
	size_t secret_len = EAP_SHARED_SECRET_LEN;
	
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-2");	
	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return ;		
	}


	eap_noob_decode_obj(data->peer_attr,resp_obj);

	if(data->peer_attr->rcvd_params != TYPE_TWO_PARAMS){
		eap_noob_set_error(data->peer_attr,E1002);
		eap_noob_set_done(data, NOT_DONE);
		return;
	}
	
	
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->nonce_peer, EAP_NOOB_NONCE_LEN);
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Public Key Peer", data->peer_attr->peer_public_key, data->peer_attr->pub_key_peer_len);

	//check error code after decoding	
	if((data->peer_attr->err_code != NO_ERROR)){
		 eap_noob_set_done(data, NOT_DONE);
		 return;
	}

	if(eap_noob_verify_peerID(data))
	{
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce Peer", data->peer_attr->nonce_peer, EAP_NOOB_NONCE_LEN);
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Public Key Peer", data->peer_attr->peer_public_key, data->peer_attr->pub_key_peer_len);
		eap_noob_derive_session_secret(data,&secret_len);
		eap_noob_Base64Encode(data->peer_attr->shared_key, EAP_SHARED_SECRET_LEN, &data->peer_attr->shared_key_b64);

		eap_noob_change_state(data,WAITING);

		if(FAILURE == eap_noob_db_entry(data)){
			eap_noob_set_done(data, DONE);
			eap_noob_set_success(data,FAILURE);
			return;
		}

		data->peer_attr->next_req = NONE;
		eap_noob_set_done(data, DONE);
		eap_noob_set_success(data,FAILURE);
	}
}


/**
 * eap_oob_rsp_type_one - Process EAP-Response/Initial Exchange 1
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @data: Pointer to private EAP-NOOB data
 * @payload: EAP data received from the peer
 * @payloadlen: Length of the payload
 **/
static void eap_noob_rsp_type_one(struct eap_sm *sm,
		struct eap_noob_serv_context *data,
		noob_json_t *resp_obj)
{
	/*check for the supporting cryptosuites, peerID_gen, version, direction*/
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Response Processed/NOOB-IE-1");	

	if(NULL == resp_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return ;		
	}


	eap_noob_decode_obj(data->peer_attr,resp_obj);
	//check error code after decoding	
	if((data->peer_attr->err_code != NO_ERROR)){
		 eap_noob_set_done(data, NOT_DONE);
		 return;
	}

	if(data->peer_attr->rcvd_params != TYPE_ONE_PARAMS){
		eap_noob_set_error(data->peer_attr,E1002);
		eap_noob_set_done(data, NOT_DONE);
		return;
	}
	
	
	if(eap_noob_verify_peerID(data)){ 
		data->peer_attr->next_req = EAP_NOOB_TYPE_2;
	}
	eap_noob_set_done(data, NOT_DONE);
	data->peer_attr->rcvd_params = 0;	
}





/**
 * eap_oob_process - Control Process EAP-Response.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 * @respData: EAP response to be processed (eapRespData)
 **/
static void eap_noob_process(struct eap_sm *sm, void *priv, struct wpabuf *respData)
{

	wpa_printf(MSG_DEBUG, "EAP-NOOB: PROCESS SERVER");


	struct eap_noob_serv_context *data = priv;
	const u8 *pos;
	size_t len;

	noob_json_t * resp_obj = NULL;  //TODO: free
	noob_json_error_t error;

	pos = eap_hdr_validate(EAP_VENDOR_IETF, EAP_TYPE_NOOB, respData, &len);
	if (pos == NULL || len < 1)
		return;

	if(data->peer_attr->err_code != NO_ERROR)
		return;	
	if(NULL == (resp_obj = eap_noob_json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error)))
		return;

	printf("RECEIVED RESPONSE = %s\n",pos);
	//TODO : replce switch case with function pointers.
	switch (data->peer_attr->recv_msg) {
		case EAP_NOOB_TYPE_1:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 1");
			eap_noob_rsp_type_one(sm, data, resp_obj);
			break;

		case EAP_NOOB_TYPE_2:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 2 %s", eap_noob_json_dumps(resp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER));			
			eap_noob_rsp_type_two(sm, data, resp_obj);
			break;

		case EAP_NOOB_TYPE_3:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 3");			
			eap_noob_rsp_type_three(sm, data, resp_obj);
			break;

		case EAP_NOOB_TYPE_4:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 4");			
			eap_noob_rsp_type_four(sm, data, resp_obj);
			break;

		case EAP_NOOB_TYPE_5:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 5");
			eap_noob_rsp_type_five(sm, data, resp_obj);
			break;

		case EAP_NOOB_TYPE_6:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 6");
			eap_noob_rsp_type_six(sm, data, resp_obj);
			break;

		case EAP_NOOB_TYPE_7:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ENTERING NOOB PROCESS TYPE 7");
			eap_noob_rsp_type_seven(sm, data, resp_obj);
			break;

		case NONE: 
			wpa_printf(MSG_DEBUG, "EAP-NOOB: ERROR received");
			eap_noob_decode_obj(data->peer_attr,resp_obj);
			if(FAILURE == eap_noob_db_update(data,UPDATE_STATE_ERROR)){
				wpa_printf(MSG_DEBUG,"Fail to Write Error to DB");
			}
				
			eap_noob_set_done(data,DONE);
			eap_noob_set_success(data,FAILURE);
			break;
	
	}
	data->peer_attr->recv_msg = 0;
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

static void eap_noob_free_ctx(struct eap_noob_serv_context * data)
{

	struct eap_noob_peer_data * peer = data->peer_attr;
	struct eap_noob_server_data * serv = data->server_attr;

	if(NULL == data)
		return;

	if(serv){
		if(serv->serv_config_params)
			os_free(serv->serv_config_params);
		if(serv->serv_info)
			os_free(serv->serv_info);

		os_free(serv);
	}

	if(peer){
		if(peer->peerID_gen)
			os_free(peer->peerID_gen);
		if(peer->peerID_rcvd)
			os_free(peer->peerID_rcvd);
		if(peer->peer_info)
			os_free(peer->peer_info);
		if(peer->NAI)
			os_free(peer->NAI);
		
		if(peer->nonce_peer)
			os_free(peer->nonce_peer);
		if(peer->nonce_peer_b64)
			os_free(peer->nonce_peer_b64);
		if(peer->nonce_serv)
			os_free(peer->nonce_serv);
		if(peer->dh_key)
			os_free(peer->dh_key);

		if(peer->shared_key)
			os_free(peer->shared_key);
		if(peer->shared_key_b64)
			os_free(peer->shared_key_b64);
		if(peer->jwk_serv)
			os_free(peer->jwk_serv);
		if(peer->jwk_peer)
			os_free(peer->jwk_peer);
		os_free(peer);
	}

	os_free(data);
}

/**
 * eap_oob_reset - Release/Reset EAP-NOOB data that is not needed.
 * @sm: Pointer to EAP state machine allocated with eap_peer_sm_init()
 * @priv: Pointer to private EAP-NOOB data
 **/
static void eap_noob_reset(struct eap_sm *sm, void *priv)
{
	wpa_printf(MSG_DEBUG, "EAP-NOOB: RESET SERVER");
	struct eap_noob_serv_context *data = priv;

	eap_noob_free_ctx(data);
}


static u8 * eap_noob_getKey(struct eap_sm *sm, void *priv, size_t *len)
{
	wpa_printf(MSG_DEBUG, "EAP-NOOB: GET  KEY");

        struct eap_noob_serv_context *data = priv;
        u8 *key;

        if ((data->peer_attr->serv_state != REGISTERED) || (!data->peer_attr->msk))
               return NULL;

        //Base64Decode((char *)data->peer_attr->msk_b64, &data->peer_attr->msk, len);

        if(NULL == (key = os_malloc(MSK_LEN)))
        //if(NULL == (key = os_malloc(64)))
                return NULL;
	*len = MSK_LEN;
        os_memcpy(key, data->peer_attr->msk, MSK_LEN);
	//memset(key,1,64);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: MSK Derived",key,MSK_LEN);
        return key;

}

static u8 * eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{

	struct eap_noob_serv_context *data = priv;
        u8 *emsk;
	wpa_printf(MSG_DEBUG, "EAP-NOOB:Get EMSK called");

       if ((data->peer_attr->serv_state != REGISTERED) || (!data->peer_attr->emsk))
               return NULL;
 
        if(NULL == (emsk = os_malloc(EAP_EMSK_LEN)))
		return NULL;
        os_memcpy(emsk, data->peer_attr->emsk, EAP_EMSK_LEN);
        
        if (emsk) {
                *len = EAP_EMSK_LEN;
                wpa_hexdump(MSG_DEBUG, "EAP-NOOB: Copied EMSK",
                            emsk, EAP_EMSK_LEN);
        } else{ 
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
 * eap_server_oob_register - Register EAP-NOOB as a supported EAP peer method.
 * Returns: 0 on success, -1 on invalid method, or -2 if a matching EAP
 * method has already been registered
 **/
int eap_server_noob_register(void) {
	struct eap_method *eap;
	int ret;

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
	ret = eap_server_method_register(eap);
	if (ret)
		eap_server_method_free(eap);
		return ret;
}
