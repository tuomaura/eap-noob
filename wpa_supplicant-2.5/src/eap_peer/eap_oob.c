#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <string.h>
#include <sqlite3.h>
#include <jansson.h>
#include "common.h"
#include "eap_i.h"
#include "eap_oob.h"
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
//extern char * global_conf_file;
//extern struct wpa_config * global_conf;

static int eap_noob_sendUpdateSignal()
{

	FILE *fp;
	char pid[10];
	int p = 0;
	fp = popen("pidof /usr/bin/python ./signal.py", "r");
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
#if 0
static int startBrowser(const char* path, const char* url)
{
	int pid;
	int len = 14 + os_strlen(path) + os_strlen(url);
	char *command=os_zalloc(len);

	memset(command,0,len);
	//TODO: check if the packeg is installed	
	snprintf(command, len , "qrencode --size=10 -o %s %s",path, url);

	wpa_printf(MSG_DEBUG,"EAP-NOOB: Here is the command %s",command);
	if(system(command) == -1){
		wpa_printf(MSG_DEBUG,"EAP-NOOB: System returned fail");
		os_free(command);
		return FAILURE;
	}

	pid=fork();	

	if(pid==0)
	{
		//TODO : Check for availability of other browsers if firefox is not present
		wpa_printf(MSG_DEBUG,"EAP-NOOB:I am the child Process");
		execlp("/usr/bin/firefox", "firefox", path, NULL);
		//wpa_printf(MSG_DEBUG,"EAP-NOOB:Still I am the child Process");
		os_free(command);
		return SUCCESS;

	}
	//wpa_printf(MSG_DEBUG,"EAP-NOOB: I am the parent");
	os_free(command);
	return SUCCESS; 
}
#endif
#if 0
static int eap_oob_gen_QRcode(struct eap_noob_peer_context *data){

	char * link = "https://130.233.193.139:8080/api/QRcode/";
	char * url ;
	char * path = "/tmp/qrcode.png";
	int url_len = 0;

	url_len = os_strlen(link) + os_strlen(data->serv_attr->peerID) + 
		os_strlen(data->serv_attr->hoob_b64) + os_strlen(data->serv_attr->noob_b64) + 3;
	url = os_zalloc(url_len);

	memset(url,0,url_len);
	snprintf(url,url_len,"%s%s/%s/%s",link,data->serv_attr->peerID,data->serv_attr->noob_b64,data->serv_attr->hoob_b64 );

	return startBrowser(path,url);

}
#endif

static void eap_noob_gen_KDF(struct eap_noob_peer_context * data, int state){

	const EVP_MD *md = EVP_sha256();
	int counter = 0;
	unsigned char * out = os_zalloc(192);

	//	data->peer_attr->noob = (u8 *)"1234";
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Algorith ID:",ALGORITHM_ID,ALGORITHM_ID_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Nonce_Peer",data->serv_attr->nonce_peer,EAP_NOOB_NONCE_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Nonce_Serv",data->serv_attr->nonce_serv,EAP_NOOB_NONCE_LEN);
	if(state == COMPLETION_EXCHANGE){
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Noob",data->serv_attr->noob,EAP_NOOB_NONCE_LEN);
		eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
				data->serv_attr->shared_key, EAP_SHARED_SECRET_LEN,
				(unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
				data->serv_attr->nonce_peer, EAP_NOOB_NONCE_LEN,
				data->serv_attr->nonce_serv, EAP_NOOB_NONCE_LEN,
				data->serv_attr->noob, EAP_NOOB_NONCE_LEN, md);
	}else{
		
		wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: kz",data->serv_attr->kz,KZ_LEN);
		eap_noob_ECDH_KDF_X9_63(out, KDF_LEN,
				data->serv_attr->kz, KZ_LEN,
				(unsigned char *)ALGORITHM_ID, ALGORITHM_ID_LEN,
				data->serv_attr->nonce_peer, EAP_NOOB_NONCE_LEN,
				data->serv_attr->nonce_serv, EAP_NOOB_NONCE_LEN,
				NULL, 0, md);
	}	
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: KDF",out,KDF_LEN);

	if(out != NULL){
		data->serv_attr->msk = os_zalloc(MSK_LEN);
		data->serv_attr->emsk = os_zalloc(EMSK_LEN);
		data->serv_attr->kms = os_zalloc(KMS_LEN);
		data->serv_attr->kmp = os_zalloc(KMP_LEN);
		data->serv_attr->kz = os_zalloc(KZ_LEN);

		memcpy(data->serv_attr->msk,out,MSK_LEN);
		counter += MSK_LEN;
		memcpy(data->serv_attr->emsk, out + counter, EMSK_LEN);
		counter += EMSK_LEN;
		memcpy(data->serv_attr->kms, out + counter, KMS_LEN);
		counter += KMS_LEN;
		memcpy(data->serv_attr->kmp, out + counter, KMP_LEN);
		counter += KMP_LEN;
		memcpy(data->serv_attr->kz, out + counter, KZ_LEN);
		counter += KZ_LEN;
	}
}


static json_t * eap_noob_prepare_peer_info_json(struct eap_noob_peer_config_params * data){

	json_t * info_obj = NULL;

        if(NULL == data){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return NULL;
        }

        if(NULL != (info_obj = json_object())){

                json_object_set_new(info_obj,PEER_NAME,json_string(data->Peer_name));
                json_object_set_new(info_obj,PEER_SERIAL_NUM,json_string(data->Peer_ID_Num));
	}
	return info_obj;
}

static char * eap_noob_prepare_mac_arr(const struct eap_noob_peer_context * data, int type, int state){

	json_t * mac_arr = NULL;
	json_t * ver_arr = NULL;
	char * mac_str = NULL;
	json_error_t error;
	json_t * csuite_arr = NULL;
	u32 count  = 0;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
	if(NULL != (mac_arr = json_array())){
		//json_array_append(mac_arr,json_integer(1));
		if(type == MACP){
			json_array_append(mac_arr,json_integer(1));
		}

		if(type == MACS){
			json_array_append(mac_arr,json_integer(2));
		}

		if(NULL == (ver_arr = json_array())){
			free(mac_arr);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_VER ; count++){
			json_array_append(ver_arr,json_integer(data->serv_attr->version[count]));
		}

		json_array_append(mac_arr,ver_arr);
		//json_array_append(mac_arr,json_integer(data->serv_attr->version));
		json_array_append(mac_arr,json_integer(data->peer_attr->version));
		json_array_append(mac_arr,json_string(data->serv_attr->peerID));

	        if(NULL == (csuite_arr = json_array())){
                        free(mac_arr);
                        return NULL;
                }

                for(count = 0; count < MAX_SUP_CSUITES ; count++){
                        json_array_append(csuite_arr,json_integer(data->serv_attr->cryptosuite[count]));
                }

		json_array_append(mac_arr,csuite_arr);

		if(state == COMPLETION_EXCHANGE){
			json_array_append(mac_arr,json_integer(data->serv_attr->dir));

		}else{
			json_array_append(mac_arr,json_string(""));
		}
		json_array_append(mac_arr,json_string(data->serv_attr->serv_info));
		json_array_append(mac_arr,json_integer(data->peer_attr->cryptosuite));
		if(state == COMPLETION_EXCHANGE){
			json_array_append(mac_arr,json_integer(data->peer_attr->dir));
		}else{
			json_array_append(mac_arr,json_string(""));
		}
		json_array_append(mac_arr,json_string(data->peer_attr->peer_info));
		//json_array_append(mac_arr,json_string(data->serv_attr->serv_public_key_b64));
		if(state == RECONNECT_EXCHANGE){
			json_array_append(mac_arr,json_string(""));

		}else{
			json_array_append(mac_arr,json_loads(json_dumps(data->serv_attr->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		}
		json_array_append(mac_arr,json_string(data->serv_attr->nonce_serv_b64));
		//json_array_append(mac_arr,json_string(data->serv_attr->peer_public_key_b64));
		if(state == RECONNECT_EXCHANGE){
			json_array_append(mac_arr,json_string(""));

		}else{
			json_array_append(mac_arr,json_loads(json_dumps(data->serv_attr->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		}
		json_array_append(mac_arr,json_string(data->serv_attr->nonce_peer_b64));
		json_array_append(mac_arr,json_string(data->serv_attr->noob_b64));


		wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
		mac_str = json_dumps(mac_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
	}

	free(ver_arr);
	free(csuite_arr);
	return mac_str;
}

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

static int eap_noob_get_noob(struct eap_noob_peer_context *data){

	int rc = 0;
	unsigned long err = 0;
	if(NULL == (data->serv_attr->noob = os_zalloc(EAP_NOOB_NONCE_LEN)))
		return FAILURE;

	if(1 != (rc = RAND_bytes(data->serv_attr->noob, EAP_NOOB_NONCE_LEN))){
		err = ERR_get_error();
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);
		return FAILURE;
	}	

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Noob",data->serv_attr->noob,16);
	eap_noob_Base64Encode(data->serv_attr->noob, 16, &data->serv_attr->noob_b64);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Noob Base64 %s", data->serv_attr->noob_b64);	

	return SUCCESS;
}

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
		data->serv_attr->hoob = hoob_out;
		wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: HOOB",data->serv_attr->hoob,HASH_LEN);
		eap_noob_Base64Encode(data->serv_attr->hoob, HASH_LEN, &data->serv_attr->hoob_b64);
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Hoob Base64 %s", data->serv_attr->hoob_b64);
	}
#if 0
	/*generate QR code*/
	if(!eap_oob_gen_QRcode(data))
		return FAILURE;
#endif
	return SUCCESS;
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

static char * eap_noob_prepare_hoob_arr(const struct eap_noob_peer_context * data){

	json_t * hoob_arr = NULL;
	json_t * ver_arr = NULL;
	char * hoob_str = NULL;
	json_error_t error;
	json_t * csuite_arr = NULL;
	u32 count  = 0;
	int dir = (data->serv_attr->dir & data->peer_attr->dir);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: %s",__func__);
	if(NULL != (hoob_arr = json_array())){
		
		json_array_append(hoob_arr,json_integer(dir));

		if(NULL == (ver_arr = json_array())){
			free(hoob_arr);
			return NULL;
		}

		for(count = 0; count < MAX_SUP_VER ; count++){
			json_array_append(ver_arr,json_integer(data->serv_attr->version[count]));
		}

		json_array_append(hoob_arr,ver_arr);
		
		json_array_append(hoob_arr,json_integer(data->peer_attr->version));

		json_array_append(hoob_arr,json_string(data->serv_attr->peerID));

	        if(NULL == (csuite_arr = json_array())){
                        free(hoob_arr);
                        return NULL;
                }

                for(count = 0; count < MAX_SUP_CSUITES ; count++){
                        json_array_append(csuite_arr,json_integer(data->serv_attr->cryptosuite[count]));
                }

		json_array_append(hoob_arr,csuite_arr);

		json_array_append(hoob_arr,json_integer(data->serv_attr->dir));

		json_array_append(hoob_arr,json_string(data->serv_attr->serv_info));

		json_array_append(hoob_arr,json_integer(data->peer_attr->cryptosuite));
			
		json_array_append(hoob_arr,json_integer(data->peer_attr->dir));
		
		json_array_append(hoob_arr,json_string(data->peer_attr->peer_info));
			
		json_array_append(hoob_arr,json_loads(json_dumps(data->serv_attr->jwk_serv,
			JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		
		json_array_append(hoob_arr,json_string(data->serv_attr->nonce_serv_b64));
			
		json_array_append(hoob_arr,json_loads(json_dumps(data->serv_attr->jwk_peer,
			JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error));
		
		json_array_append(hoob_arr,json_string(data->serv_attr->nonce_peer_b64));

		json_array_append(hoob_arr,json_string(data->serv_attr->noob_b64));

		hoob_str = json_dumps(hoob_arr,JSON_COMPACT|JSON_PRESERVE_ORDER);
	}

	free(ver_arr);
	free(csuite_arr);
	return hoob_str;
}

static int eap_noob_get_hoob(struct eap_noob_peer_context *data,unsigned char *out, size_t outlen)
{
	const EVP_MD *md = EVP_sha256();
	EVP_MD_CTX *mctx = NULL;
	int rv = 0;
	size_t mdlen;
	char * mac_string = NULL; //TODO : allocate memory dynamically
	int mac_str_len= 0;
#if 0
	char mac_string[1000] = {0}; //TODO : allocate memory dynamically
	int mac_str_len= 0;

	char * ver_arr = malloc(sizeof(u32) * MAX_SUP_VER * 3);
	char * csuite_arr = malloc(sizeof(u32) * MAX_SUP_CSUITES * 3);
	char buff[4] = {0};
	u32 count = 0;

	memset(ver_arr,0 , sizeof(sizeof(u32) * MAX_SUP_VER * 3));	
	memset(csuite_arr,0 , sizeof(sizeof(u32) * MAX_SUP_CSUITES * 3));	

	for(count = 0; count < MAX_SUP_VER; count ++){
                snprintf(buff,4,"%d",data->serv_attr->version[count]);
                strcat(ver_arr,buff);
        }
	
	for(count = 0; count < MAX_SUP_CSUITES; count ++){
                snprintf(buff,4,"%d",data->serv_attr->cryptosuite[count]);
                strcat(csuite_arr,buff);
        }

	int dir = (data->serv_attr->dir & data->peer_attr->dir);

	snprintf(mac_string,1000,"%d%s%d%s%s%d%s%d%d%s%s%s%s%s%s",dir,ver_arr,
			data->peer_attr->version,data->serv_attr->peerID,
			csuite_arr,data->serv_attr->dir,
			data->serv_attr->serv_info,data->peer_attr->cryptosuite,
			data->peer_attr->dir,data->peer_attr->peer_info,
			data->serv_attr->serv_public_key_b64,
			data->serv_attr->nonce_serv_b64,data->serv_attr->peer_public_key_b64,
			data->serv_attr->nonce_peer_b64,data->serv_attr->noob_b64);	
	free(ver_arr);
	free(csuite_arr);
#endif
	mac_string = eap_noob_prepare_hoob_arr(data);
	mac_str_len = os_strlen(mac_string);
	
	printf("HOOB string  = %s\n length = %d\n",mac_string,mac_str_len);
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


static int eap_noob_derive_session_key(struct eap_noob_peer_context *data, size_t *secret_len)
{

	//BIGNUM *big_pub_server;//public key of peer 
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
	x_len = eap_noob_Base64Decode(data->serv_attr->x_serv_b64, &x, &len);	
	y_len = eap_noob_Base64Decode(data->serv_attr->y_serv_b64, &y, &len);

	/*switch (data->specifier) {
	  case EAP_NOOB_CIPHER_P256_SHA256:
	  wpa_printf(MSG_DEBUG, "EAP-NOOB: deriving NID_secp256k1.");
	  ec_pub_peer = EC_KEY_new_by_curve_name(NID_secp256k1);
	  ec_keypair = EC_KEY_new_by_curve_name(NID_secp256k1);
	  break;
	  case EAP_NOOB_CIPHER_P521_SHA256:
	  wpa_printf(MSG_DEBUG, "EAP-NOOB: deriving NID_secp521r1.");
	  ec_pub_peer = EC_KEY_new_by_curve_name(NID_secp521r1);
	  ec_keypair = EC_KEY_new_by_curve_name(NID_secp521r1);
	  break;
	  default:
	  wpa_printf(MSG_DEBUG, "EAP-NOOB: Unsupported cryptosuite.");
	  return 1;
	  }*/

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

	/* Peer u8 PUB Key to EC_KEY */
//	big_pub_server = BN_bin2bn(data->serv_attr->serv_public_key, data->serv_attr->pub_key_serv_len, NULL);

	x_big = BN_bin2bn(x,x_len,NULL);
	y_big = BN_bin2bn(y,y_len,NULL);
/*
	if (big_pub_server == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to convert Peer PUB KEY BIN to BIGNUM.");
		return 1;
	}
*/
	wpa_printf(MSG_DEBUG, "EAP-NOOB: EC_POINT_bn2point");
	ecpoint_pub_server = EC_POINT_new(ec_group);
	if(EC_POINT_set_affine_coordinates_GFp(ec_group, ecpoint_pub_server, x_big, y_big,NULL) ==0)
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Error in affine coordinate setting");

	//ecpoint_pub_peer = EC_POINT_bn2point(ec_group, big_pub_peer, ecpoint_pub_peer, NULL);
	/*if (EC_POINT_bn2point(ec_group, big_pub_server, ecpoint_pub_server, NULL) == NULL) {
	  wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to convert Peer PUB KEY BIGNUM to EC_POINT.");
	  return 1;
	  }*/

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
	if(NULL == (ctx = EVP_PKEY_CTX_new(data->serv_attr->dh_key, NULL))) {
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
	if(NULL == (data->serv_attr->shared_key = OPENSSL_malloc(*secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to create buffer OPENSSL_malloc.");
		return 1;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Deriving the secret! 6.");

	/* Derive the shared secret */
	if(1 != (EVP_PKEY_derive(ctx, data->serv_attr->shared_key, secret_len))) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB:Fail to derive key EVP_PKEY_derive.");
		return 1;
	}
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: Secret Derived",data->serv_attr->shared_key,*secret_len);
	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(evp_server);
	//EVP_PKEY_free(evp_keypair); //this can be discarded once the shared secret is derived

	return 0;
}


/**
 *  * get_key - Generate Priv/Pub key pair based on the Csuite selected.
 *   * @data: Pointer to EAP-NOOB data
 *    * Returns: 1 if keys generated and stored successfully, or 0 if not
 *     **/
static int eap_noob_get_key(struct eap_noob_serv_data *data)
{
	//BIGNUM *big_pub = NULL;
	//size_t big_pub_len;

	//const BIGNUM *big_priv;
	//size_t big_priv_len;

	const EC_POINT *pub;
	const EC_GROUP *group;
	//point_conversion_form_t form;

	BIGNUM *x = BN_new();
	BIGNUM *y = BN_new();
	size_t x_len;
	size_t y_len;
	unsigned char * x_val;
	unsigned char * y_val;

	/* Set up EC_KEY object and associated with the curve according to the specifier */
#if 0
	switch (data->specifier) {
		case EAP_NOOB_CIPHER_P256_SHA256:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: secp256k1 cryptosuite selected.");
			data->dh_key = EC_KEY_new_by_curve_name(NID_secp256k1);
			break;
		case EAP_NOOB_CIPHER_P521_SHA256:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: NID_secp521r1 cryptosuite selected.");
			data->dh_kstruct eap_oob_serv_dataey = EC_KEY_new_by_curve_name(NID_secp521r1);
			break;
		default:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: Unsupported cryptosuite.");
			return 0;

	}
#endif


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
	if (1 != EVP_PKEY_keygen(kctx, &data->dh_key)){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Fail to generate keys.");
		return 0;
	}

	key = EVP_PKEY_get1_EC_KEY(data->dh_key);

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
#if 0
	/* Get private key in prv */
	big_priv = EC_KEY_get0_private_key(key);
	if (big_priv == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get PRIV KEY");
		return 0;
	}
#endif
	/* Get public key in pub */
	pub = EC_KEY_get0_public_key(key);
	if (pub == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get PUB KEY");
		return 0;
	}
	/* Get conversion form */
//	form = EC_KEY_get_conv_form(key); // no validation required for returned value because key is validated for NULL


	/*	if (form == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to get EC_POINT conversion form.");
		return 0;
		}*/

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

	eap_noob_Base64Encode(x_val,x_len, &data->x_b64);	
	eap_noob_Base64Encode(y_val,y_len, &data->y_b64);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: X and Y %s,%s",data->x_b64, data->y_b64);	

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: X coordinate", x_val, x_len);	
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Y coordinate", y_val, y_len);
#if 0
	/* Convert Pub-Key to BIGNUM */
	big_pub = EC_POINT_point2bn(group, pub, form, big_pub, NULL);
	if (big_pub == NULL) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to convert PUB KEY to BIGNUM.");
		return 0;
	}
	big_pub_len = BN_num_bytes(big_pub);
	data->peer_public_key = os_zalloc(big_pub_len);
	data->pub_key_peer_len = big_pub_len;
	/* Convert Pub-Key BIGNUM to BIN */
	if (BN_bn2bin(big_pub, data->peer_public_key) == 0) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to convert PUB KEY BIGNUM to BIN.");
		return 0;
	}
	big_priv_len = BN_num_bytes(big_priv);
	data->priv_key = os_zalloc(big_priv_len);
	data->priv_key_len = big_priv_len;
	/* Convert Priv-Key BIGNUM to BIN */
	if (BN_bn2bin(big_priv, data->priv_key) == 0) {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to convert PRIV KEY BIGNUM to BIN.");
		return 0;
	}


	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Public Key", data->peer_public_key, data->pub_key_peer_len);
#endif
	return 1;
}


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
                                        if(strlen((char *)data->nonce_serv) > EAP_NOOB_NONCE_LEN){
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



static void  eap_noob_decode_obj(struct eap_noob_serv_data * data ,json_t * req_obj){

	const char * key;
	json_t * value;
	size_t arr_index;
	json_t *arr_value;

	size_t decode_length;
	//size_t decode_length_key;
	size_t decode_length_nonce;

	int retval_int = 0;
	const char* retval_char = NULL;
	json_error_t  error;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB DECODE OBJECT");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return;		
	}
	json_object_foreach(req_obj, key, value) {

		switch(json_typeof(value)){
			case JSON_OBJECT:
				if(0 == strcmp(key,JSON_WEB_KEY)){
					data->rcvd_params |= PKEY_RCVD;
					wpa_printf(MSG_DEBUG,"EAP-NOOB:Copy Verify %s",json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER));
					data->jwk_serv = json_loads(json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER),JSON_COMPACT|JSON_PRESERVE_ORDER,&error);
					wpa_printf(MSG_DEBUG,"EAP-NOOB:Copy Verify %s",json_dumps(data->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER));
				}else if(0 == strcmp(key, SERV_INFO)){
					data->rcvd_params |= INFO_RCVD;
					data->serv_info = json_dumps(value,JSON_COMPACT|JSON_PRESERVE_ORDER);
					wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv Info %s",data->serv_info);

				}
				eap_noob_decode_obj(data,value);
				break;

			case JSON_INTEGER:

				if(0 == (retval_int = json_integer_value(value)) && 0 != strcmp(key,TYPE)){
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

				if(NULL == (retval_char = json_string_value(value))){
					data->err_code = E1003;
					return;
				}

				if(0 == strcmp(key, PEERID)){
					data->peerID = os_strdup(retval_char);
					data->rcvd_params |= PEERID_RCVD;

				}
/*
				else if(0 == strcmp(key, PUBLICKEY_SERV)){
					data->serv_public_key_b64 = os_strdup(retval_char);
					data->pub_key_serv_len = eap_noob_Base64Decode((char *)data->serv_public_key_b64, 
							&data->serv_public_key, &decode_length_key);
					data->rcvd_params |= PKEY_RCVD;
				}
*/
				else if(0 == strcmp(key, NONCE_SERV)){ 
					data->nonce_serv_b64 = os_strdup(retval_char);
					eap_noob_Base64Decode(data->nonce_serv_b64, &data->nonce_serv, &decode_length_nonce);
					data->rcvd_params |= NONCE_RCVD;

				}

				else if(0 == strcmp(key, MAC_SERVER)){
					//data->MAC = os_strdup(retval_char);
					eap_noob_Base64Decode((char *)retval_char, (u8**)&data->MAC,&decode_length);	
					data->rcvd_params |= MAC_RCVD;
				}
				else if(0 == strcmp(key, X_COORDINATE)){
					data->x_serv_b64 = os_strdup(json_string_value(value));
					wpa_printf(MSG_DEBUG, "X coordinate %s", data->x_serv_b64);
				}else if(0 == strcmp(key, Y_COORDINATE)){
					data->y_serv_b64 = os_strdup(json_string_value(value));
					wpa_printf(MSG_DEBUG, "Y coordinate %s", data->y_serv_b64);
				}
				break;

			case JSON_ARRAY:
				if(0 == strcmp(key,VERSION_SERV)){
					json_array_foreach(value, arr_index, arr_value) {
						if(json_is_integer(arr_value)){
							data->version[arr_index] = json_integer_value(arr_value);
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
						if(json_is_integer(arr_value)){
							data->cryptosuite[arr_index] = json_integer_value(arr_value);
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

static void eap_noob_config_change(struct eap_sm *sm , struct eap_noob_peer_context *data)
{

	char buff[120] = {0};
	size_t len = 0;
	//struct eapol_ctx *ctx = ( struct eapol_ctx *) sm->eapol_ctx;
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

int eap_noob_db_entry_check(void * priv , int argc, char **argv, char **azColName){

	struct eap_noob_serv_data *data = priv;

	if(strtol(argv[0],NULL,10) == 1){
		data->record_present = TRUE;
	}

	return 0;

}

int eap_noob_callback(void * priv , int argc, char **argv, char **azColName){

	struct eap_noob_peer_context * peer = priv;
	struct eap_noob_serv_data *data = peer->serv_attr;
	int count  = 0;

	size_t len;
	json_error_t error;

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
				data->version[0] = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "Verp") == 0) {
				peer->peer_attr->version = (int) strtol(argv[count], NULL, 10);
			}
			else if (os_strcmp(azColName[count], "state") == 0) {
				data->state = (int) strtol(argv[count], NULL, 10);
			}
/*
			else if (os_strcmp(azColName[count], "PKs") == 0) {
				if(NULL != data->serv_public_key_b64)
					os_free(data->serv_public_key_b64);

				data->serv_public_key_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->serv_public_key_b64, argv[count]);
			}

			else if (os_strcmp(azColName[count], "PKp") == 0) {
				if(NULL != data->peer_public_key_b64)
					os_free(data->peer_public_key_b64);

				data->peer_public_key_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->peer_public_key_b64, argv[count]);
			}
*/
			else if (os_strcmp(azColName[count], "Csuites") == 0) {
				data->cryptosuite[0] = (int) strtol(argv[count], NULL, 10);
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
				if(NULL != data->nonce_peer_b64)
					os_free(data->nonce_peer_b64);

				data->nonce_peer_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->nonce_peer_b64, argv[count]);

				eap_noob_Base64Decode(data->nonce_peer_b64, &data->nonce_peer, &len); //To-Do check for length

			}	
			else if (os_strcmp(azColName[count], "nonce_serv") == 0) {
				if(NULL != data->nonce_serv_b64)
					os_free(data->nonce_serv_b64);

				data->nonce_serv_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->nonce_serv_b64, argv[count]);

				eap_noob_Base64Decode(data->nonce_serv_b64, &data->nonce_serv, &len); //To-Do check for length

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
				if(NULL != data->shared_key_b64)
					os_free(data->shared_key_b64);

				data->shared_key_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->shared_key_b64, argv[count]);
				eap_noob_Base64Decode(data->shared_key_b64, &data->shared_key, &len);
			}
			else if (os_strcmp(azColName[count], "Noob") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->noob_b64)
					os_free(data->noob_b64);

				data->noob_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->noob_b64, argv[count]);

				eap_noob_Base64Decode(data->noob_b64, &data->noob, &len);
			}	
			else if (os_strcmp(azColName[count], "Hoob") == 0 && os_strlen(argv[count]) > 0) {
				if(NULL != data->hoob_b64)
					os_free(data->hoob_b64);

				data->hoob_b64 = os_malloc(os_strlen(argv[count]));
				strcpy(data->hoob_b64, argv[count]);
				wpa_printf(MSG_DEBUG,"EAP-NOOB: HOOB: %s",argv[count]);

				eap_noob_Base64Decode(data->hoob_b64, &data->hoob, &len);
			}else if (os_strcmp(azColName[count], "pub_key_serv") == 0){
				data->jwk_serv = json_loads(argv[count], JSON_COMPACT|JSON_PRESERVE_ORDER, &error); //ToDo: check and free this before assigning if required
				wpa_printf(MSG_DEBUG,"EAP-NOOB:Serv_KEY: %s",argv[count]);

			}else if (os_strcmp(azColName[count], "pub_key_peer") == 0){
				data->jwk_peer = json_loads(argv[count], JSON_COMPACT|JSON_PRESERVE_ORDER, &error); //ToDo: check and free this before assigning if required	
				wpa_printf(MSG_DEBUG,"EAP-NOOB:Peer_KEY: %s",argv[count]);
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
			}/*else if(os_strcmp(azColName[count], "show_OOB") == 0){
				printf("SHOW OOB RECEIVED\n");
			}*/
		
		}
	}

	return 0;
}

static int eap_noob_exec_query(const char * query, int(*callback)(void*, int ,char **, char ** ), void * data,sqlite3 * dbname){

	char * sql_error = NULL;

	if(SQLITE_OK != sqlite3_exec(dbname, query,callback, data, &sql_error)){
		if (sql_error!=NULL) {
			wpa_printf(MSG_DEBUG,"EAP_NOOB: sql error : %s\n",sql_error);
			sqlite3_free(sql_error);
		}
		if(SQLITE_OK != sqlite3_close(dbname)){
                        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
                }

		wpa_printf(MSG_DEBUG,"FAILED QUERY");
		return FAILURE;
	}
	if(SQLITE_OK != sqlite3_close(dbname)){
                        wpa_printf(MSG_DEBUG, "EAP-NOOB:Error closing DB");
        }
	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);

	return SUCCESS;


}

static int eap_noob_db_entry(struct eap_sm *sm,struct eap_noob_peer_context *data)
{
	char query[1500] = {0}; //TODO : replace it with dynamic allocation
	struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Entering %s",__func__);


	snprintf(query,1500,"INSERT INTO %s (ssid, PeerID, Vers,Verp, state, Csuites,Csuitep,Dirs,Dirp, "
			"nonce_peer, nonce_serv, minsleep,ServInfo, PeerInfo,SharedSecret, Noob, Hoob," 
			" OOB_RECEIVED_FLAG,pub_key_serv,pub_key_peer,err_code)"
			"VALUES ('%s','%s', %d, %d, %d, %d, %d, %d ,%d,'%s','%s', %d, '%s', '%s','%s',"
			" '%s', '%s', %d, '%s', '%s',%d)", data->db_table_name,
			wpa_s->current_ssid->ssid,data->serv_attr->peerID, data->serv_attr->version[0],
			data->peer_attr->version,data->serv_attr->state,  
			data->serv_attr->cryptosuite[0] , data->peer_attr->cryptosuite,
			data->serv_attr->dir,data->peer_attr->dir,
			data->serv_attr->nonce_peer_b64, data->serv_attr->nonce_serv_b64, 
			data->serv_attr->minsleep, data->serv_attr->serv_info, 
			data->peer_attr->peer_info,data->serv_attr->shared_key_b64,
			"","",0,(json_dumps(data->serv_attr->jwk_serv,JSON_COMPACT|JSON_PRESERVE_ORDER)),
			(json_dumps(data->serv_attr->jwk_peer,JSON_COMPACT|JSON_PRESERVE_ORDER)),data->serv_attr->err_code);


	printf("QUERY = %s\n",query);
	if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
                wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
                return FAILURE;
        }
	if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
		//sqlite3_close(data->peerDB);
		wpa_printf(MSG_ERROR, "EAP-NOOB: DB value insertion failed");
		//TODO: free data here.
		return FAILURE;
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: Exiting %s",__func__);
	return SUCCESS;
}

static struct wpabuf * eap_noob_err_msg(struct eap_noob_peer_context *data, u8 id)
{
	json_t * req_obj = NULL;
	struct wpabuf *req = NULL;
	char * req_json = NULL;
	size_t len = 0 ;
	int code = data->serv_attr->err_code;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: Build error request");
	if (!code)
		return NULL;

	if(NULL != (req_obj = json_object())){

		if(data->peer_attr->peerID){
			json_object_set_new(req_obj,PEERID,json_string(data->peer_attr->peerID));
		}
		json_object_set_new(req_obj,TYPE,json_integer(NONE));
		json_object_set_new(req_obj,ERR_CODE,json_integer(error_code[code]));
		json_object_set_new(req_obj,ERR_INFO,json_string(error_info[code]));

		req_json = json_dumps(req_obj,JSON_COMPACT);
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


static struct wpabuf * eap_noob_rsp_type_four(const struct eap_noob_peer_context *data, u8 id){

	json_t * rsp_obj = NULL;
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

	if(NULL != (rsp_obj = json_object())){

		mac = eap_noob_gen_MAC(data,MACP,data->serv_attr->kmp, KMP_LEN,COMPLETION_EXCHANGE);
		//TODO: handle NULL return value
		eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

		json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_4));
		json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerID));
		json_object_set_new(rsp_obj,MAC_PEER,json_string(mac_b64));

		resp_json = json_dumps(rsp_obj,JSON_COMPACT);
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

static struct wpabuf * eap_noob_rsp_type_three(const struct eap_noob_peer_context *data, u8 id){

	json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 3");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	if(NULL != (rsp_obj = json_object())){

		json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_3));
		json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerID));

		resp_json = json_dumps(rsp_obj,JSON_COMPACT);
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

static struct wpabuf * eap_noob_rsp_type_two(struct eap_noob_peer_context *data, u8 id){

	json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	//char* base64_pubkey;
	char* base64_nonce;
	size_t secret_len = EAP_SHARED_SECRET_LEN;

	/*unsigned char * out = os_zalloc(192);
	  const EVP_MD *md;
	  md = EVP_sha256();*/

	//struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;

	//json_t * jwk = NULL;

	if(NULL != (data->serv_attr->jwk_peer = json_object())){ 
		json_object_set_new(data->serv_attr->jwk_peer,KEY_TYPE,json_string("EC"));	
		json_object_set_new(data->serv_attr->jwk_peer,CURVE,json_string("P-256"));	
		//json_object_set_new(jwk,"kid",json_string("1234"));
	}else{
		wpa_printf(MSG_DEBUG,"EAP-NOOB: Error in JWK");
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	data->serv_attr->nonce_peer = os_zalloc(EAP_NOOB_NONCE_LEN);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 1");
	int rc = RAND_bytes(data->serv_attr->nonce_peer, EAP_NOOB_NONCE_LEN);
	unsigned long err = ERR_get_error();	

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 2");
	if(rc != 1) {

		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);	
	}

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 3");
	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->serv_attr->nonce_peer, EAP_NOOB_NONCE_LEN);

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 2 here 4");
	/* Generate Key material */
	if (eap_noob_get_key(data->serv_attr) == 0)  {
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate keys");
		return NULL;
	}

	json_object_set_new(data->serv_attr->jwk_peer,X_COORDINATE,json_string(data->serv_attr->x_b64));
	json_object_set_new(data->serv_attr->jwk_peer,Y_COORDINATE,json_string(data->serv_attr->y_b64));

	//eap_noob_Base64Encode(data->serv_attr->peer_public_key, data->serv_attr->pub_key_peer_len, &base64_pubkey);
	//wpa_printf(MSG_DEBUG,"EAP-NOOB: Public Key %s",base64_pubkey);
	eap_noob_Base64Encode(data->serv_attr->nonce_peer,EAP_NOOB_NONCE_LEN, &base64_nonce);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s",base64_nonce);

	//data->serv_attr->peer_public_key_b64 = base64_pubkey;
	data->serv_attr->nonce_peer_b64 = base64_nonce;

	//TODO: generate a fresh nonce here
	if(NULL != (rsp_obj = json_object())){

		json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_2));
		json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerID));
		json_object_set_new(rsp_obj,NONCE_PEER,json_string(base64_nonce));
		//json_object_set_new(rsp_obj,PUBLICKEY_PEER,json_string(base64_pubkey));
		json_object_set_new(rsp_obj,JSON_WEB_KEY,data->serv_attr->jwk_peer);

		resp_json = json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
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

	eap_noob_derive_session_key(data,&secret_len);
	data->serv_attr->shared_key_b64_len = eap_noob_Base64Encode(data->serv_attr->shared_key, EAP_SHARED_SECRET_LEN, &data->serv_attr->shared_key_b64);

	/*ECDH_KDF_X9_63(out, 192,data->serv_attr->shared_key,
	  EAP_SHARED_SECRET_LEN,(const u8 *)"EAP-NOOB",8,md);
	  wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: KDF",out,192);
	  data->serv_attr->kdf = out;*/

	//os_free(base64_nonce);
	//os_free(base64_pubkey);

	/*sprintf(query,"INSERT INTO connections (ssid, PeerID, Vers, state, PKs, PKp, Csuite,Dirs, nonce_peer, nonce_serv, minsleep, ServInfo, SharedSecret, Noob, Hoob, OOB_RECEIVED_FLAG)"
	  "VALUES ('%s','%s', %d, %d, '%s', '%s',%d ,%d, '%s' , '%s', %d, '%s', '%s', '%s', '%s', %d)",wpa_s->conf->ssid->ssid,data->serv_attr->peerID, data->serv_attr->version,
	  data->serv_attr->state, data->serv_attr->serv_public_key_b64, data->serv_attr->peer_public_key_b64, data->serv_attr->cryptosuite , data->serv_attr->dir,
	  data->serv_attr->nonce_peer_b64, data->serv_attr->nonce_serv_b64, data->serv_attr->minsleep, data->serv_attr->serv_info, data->serv_attr->shared_key_b64,"ab","ab",0);

	  eap_oob_exec_query(query, NULL,NULL,data->peerDB);*/
	//eap_oob_db_entry(sm,data);

	return resp;

}
static struct wpabuf * eap_noob_rsp_type_one(const struct eap_noob_peer_context *data, u8 id){

	json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	//TODO: generate a fresh nonce here
	if(NULL != (rsp_obj = json_object())){

		json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_1));
		json_object_set_new(rsp_obj,VERSION_PEER,json_integer(data->peer_attr->version));
		json_object_set_new(rsp_obj,PEERID,json_string(data->serv_attr->peerID));
		json_object_set_new(rsp_obj,CSUITES_PEER,json_integer(data->peer_attr->cryptosuite));
		json_object_set_new(rsp_obj,DIRECTION_PEER,json_integer(data->peer_attr->dir));
		json_object_set_new(rsp_obj,PEERINFO,eap_noob_prepare_peer_info_json(data->peer_attr->peer_config_params));

		resp_json = json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
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


static struct wpabuf * eap_noob_rsp_type_five(const struct eap_noob_peer_context *data, u8 id){

	json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;

	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	//TODO: generate a fresh nonce here
	if(NULL != (rsp_obj = json_object())){

		json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_5));
		json_object_set_new(rsp_obj,PEERID,json_string(data->serv_attr->peerID));
		json_object_set_new(rsp_obj,CSUITES_PEER,json_integer(data->peer_attr->cryptosuite));
		json_object_set_new(rsp_obj,PEERINFO,eap_noob_prepare_peer_info_json(data->peer_attr->peer_config_params)); //Send this only if previous info has changed

		resp_json = json_dumps(rsp_obj,JSON_COMPACT);
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


static struct wpabuf * eap_noob_rsp_type_six(struct eap_noob_peer_context *data, u8 id){

	//To-Do Based on the cryptosuite and server request decide whether new key has to be derived or not
	json_t * rsp_obj = NULL;
	struct wpabuf *resp = NULL;
	char * resp_json = NULL;
	size_t len = 0 ;
	char* base64_nonce;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB BUILD RESP TYPE 6");
	if(NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}

	data->serv_attr->nonce_peer = os_zalloc(EAP_NOOB_NONCE_LEN);
	int rc = RAND_bytes(data->serv_attr->nonce_peer, EAP_NOOB_NONCE_LEN);
	unsigned long err = ERR_get_error();	

	if(rc != 1) {

		wpa_printf(MSG_DEBUG, "EAP-NOOB: Failed to generate nonce Error Code = %lu",err);	
	}

	wpa_hexdump_ascii(MSG_DEBUG, "EAP-NOOB: Nonce", data->serv_attr->nonce_peer, EAP_NOOB_NONCE_LEN);

	eap_noob_Base64Encode(data->serv_attr->nonce_peer,EAP_NOOB_NONCE_LEN, &base64_nonce);
	wpa_printf(MSG_DEBUG,"EAP-NOOB: Nonce %s",base64_nonce);

	data->serv_attr->nonce_peer_b64 = base64_nonce;

	if(NULL != (rsp_obj = json_object())){

		json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_6));
		json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerID));
		json_object_set_new(rsp_obj,NONCE_PEER,json_string(base64_nonce));

		resp_json = json_dumps(rsp_obj,JSON_COMPACT|JSON_PRESERVE_ORDER);
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


static struct wpabuf * eap_noob_rsp_type_seven(const struct eap_noob_peer_context *data, u8 id){

	json_t * rsp_obj = NULL;
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

	if(NULL != (rsp_obj = json_object())){

		mac = eap_noob_gen_MAC(data,MACP,data->serv_attr->kmp, KMP_LEN,RECONNECT_EXCHANGE);
		//TODO: handle NULL return value
		eap_noob_Base64Encode(mac+16, MAC_LEN, &mac_b64);

		json_object_set_new(rsp_obj,TYPE,json_integer(EAP_NOOB_TYPE_7));
		json_object_set_new(rsp_obj,PEERID,json_string(data->peer_attr->peerID));
		json_object_set_new(rsp_obj,MAC_PEER,json_string(mac_b64));

		resp_json = json_dumps(rsp_obj,JSON_COMPACT);
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
static struct wpabuf * eap_noob_req_type_seven(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;
	u8 * mac = NULL;
	char * mac_b64 = NULL;

	char query[1000] = {0}; //TODO: remove this static allocation and allocate dynamically with actual length
	int len = 1000;

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
		mac = eap_noob_gen_MAC(data,MACS,data->serv_attr->kms, KMS_LEN,RECONNECT_EXCHANGE);
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


		snprintf(query,len,"UPDATE '%s' SET state=%d WHERE PeerID='%s'", data->db_table_name, data->serv_attr->state, data->serv_attr->peerID);

		if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
                        wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
                        return FAILURE;
                }

		if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
			//sqlite3_close(data->peerDB);	
			wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
			//TODO: free data here.
			//	return FAILURE;
		}
	}
	return resp;	
}


static struct wpabuf * eap_noob_req_type_six(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

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
		/*generate KDF*/	
		//eap_oob_gen_KDF(data,RECONNECT_EXCHANGE);
	}

#if 0

	if(NULL == (resp = eap_noob_verify_peerID(data,id))){

		/*generate MAC*/
		mac = eap_noob_gen_MAC(data,MACS,data->serv_attr->kms, KMS_LEN,COMPLETION_EXCHANGE);
		eap_noob_Base64Encode(mac, MAC_LEN, &mac_b64);

		if(0 != strcmp(mac_b64,data->serv_attr->MAC)){
			data->serv_attr->err_code = E4001;
			resp = eap_noob_err_msg(data,id);
			return resp;	
		}

		resp = eap_noob_rsp_type_four(data,id);
		data->serv_attr->state = REGISTERED;
		eap_noob_config_change(sm,data);


		snprintf(query,len,"UPDATE '%s' SET kms='%s', kmp='%s', kz='%s', state=%d WHERE PeerID='%s'", data->db_table_name, data->serv_attr->kms_b64,data->serv_attr->kmp_b64,data->serv_attr->kz_b64, data->serv_attr->state, data->serv_attr->peerID);

		if(SQLITE_OK != sqlite3_open(data->db_name, &data->peerDB)){
			wpa_printf(MSG_ERROR, "EAP-NOOB: NEW DB creation failed");
			//TODO: free data here.
			//	return FAILURE;
		}

		if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
			sqlite3_close(data->peerDB);	
			wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
			//TODO: free data here.
			//	return FAILURE;
		}
	}

#endif
	data->serv_attr->rcvd_params = 0;
	return resp;	
}



static struct wpabuf * eap_noob_req_type_five(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context *data,
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
		resp = eap_noob_rsp_type_five(data, id);		
	}else{
		resp = eap_noob_err_msg(data,id);
	}


	data->serv_attr->rcvd_params = 0;	
	return resp;	

}


static struct wpabuf * eap_noob_req_type_four(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;
	u8 * mac = NULL;
	char * mac_b64 = NULL;

	char query[1000] = {0}; //TODO: remove this static allocation and allocate dynamically with actual length
	int len = 1000;


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
		mac = eap_noob_gen_MAC(data,MACS,data->serv_attr->kms, KMS_LEN,COMPLETION_EXCHANGE);
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

		eap_noob_Base64Encode(data->serv_attr->kmp, KMP_LEN, &data->serv_attr->kmp_b64);
		eap_noob_Base64Encode(data->serv_attr->kms, KMS_LEN, &data->serv_attr->kms_b64);
		eap_noob_Base64Encode(data->serv_attr->kz, KZ_LEN, &data->serv_attr->kz_b64);
		

		snprintf(query,len,"UPDATE '%s' SET kms='%s', kmp='%s', kz='%s', state=%d WHERE PeerID='%s'", data->db_table_name, data->serv_attr->kms_b64,data->serv_attr->kmp_b64,data->serv_attr->kz_b64, data->serv_attr->state, data->serv_attr->peerID);


		if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
                        wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
                        return FAILURE;
                }
		if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
			//sqlite3_close(data->peerDB);	
			wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
			//TODO: free data here.
			//	return FAILURE;
		}
	}
	return resp;	
}

static struct wpabuf * eap_noob_req_type_three(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;



	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB PROCESS REQ TYPE 3");
	if(NULL == req_obj || NULL == data){
		wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
		return NULL;		
	}
# if 0
	if((PEER_TO_SERV == (data->serv_attr->dir & data->peer_attr->dir)) && 
			FAILURE == eap_noob_send_oob(data)){
		//TODO: Reset supplicant in this case
		wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB generation FAILED");
		return NULL;
	}

#endif		
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

	//if(0 == strcmp(data->peer_attr->peerID , data->serv_attr->peerID)){
	if(NULL == (resp = eap_noob_verify_peerID(data,id))){
		resp = eap_noob_rsp_type_three(data,id);
		data->serv_attr->state = OOB;
		eap_noob_config_change(sm,data);
		eap_noob_assign_waittime(sm,data);
#if 0		
		snprintf(query,len,"UPDATE '%s' SET Noob='%s'  WHERE PeerID='%s'", data->db_table_name, data->serv_attr->noob_b64, data->serv_attr->peerID);

		if(SQLITE_OK != sqlite3_open(data->db_name, &data->peerDB)){
			wpa_printf(MSG_ERROR, "EAP-NOOB: NEW DB creation failed");
			//TODO: free data here.
			//	return FAILURE;
		}

		if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
			sqlite3_close(data->peerDB);	
			wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
			//TODO: free data here.
			//	return FAILURE;
		}
		struct wpa_supplicant *wpa_s = (struct wpa_supplicant *) sm->msg_ctx;
		struct timespec tv;
		clock_gettime(CLOCK_BOOTTIME, &tv);
		wpa_s->conf->ssid->disabled_until.sec = tv.tv_sec + 1;
#endif
	}

	return resp;	

}

static struct wpabuf * eap_noob_req_type_two(struct eap_sm *sm, json_t * req_obj , struct eap_noob_peer_context *data, u8 id){

	struct wpabuf *resp = NULL;
	char query[1000] = {0}; //TODO : replace it with dynamic allocation
	int len = 1000;

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

			snprintf(query,len,"UPDATE '%s' SET Noob='%s', Hoob='%s', show_OOB=%d WHERE PeerID='%s'", 
			data->db_table_name, data->serv_attr->noob_b64, 
			data->serv_attr->hoob_b64, 1, data->serv_attr->peerID);
			printf("EAP-NOOB: QUERY = %s\n",query);
			
			if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
                                        wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
                                        return FAILURE;
                        }
			

			if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
				//sqlite3_close(data->peerDB);	
				wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
				//TODO: free data here.
				//	return FAILURE;
			}
			/*To-Do: If an error is received for the response then set the show_OOB flag to zero and send update signal*/
			if(FAILURE == eap_noob_sendUpdateSignal()){
				wpa_printf(MSG_DEBUG,"EAP-NOOB: Failed to Notify the Script");
			}

		}


	}

	return resp;	
}



static struct wpabuf * eap_noob_req_type_one(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context *data,
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
		resp = eap_noob_rsp_type_one(data, id);		
	}else{
		resp = eap_noob_err_msg(data,id);
	}


	data->serv_attr->rcvd_params = 0;	
	return resp;	

}


static void eap_noob_req_err_handling(struct eap_sm *sm,json_t * req_obj , struct eap_noob_peer_context *data,
		u8 id){
	

	char query[200] = {0}; //TODO : replace it with dynamic allocation
	int len = 200;

	if(!data->serv_attr->err_code){
		
		snprintf(query,len,"UPDATE '%s' SET err_code=%d WHERE PeerID='%s'", 
			data->db_table_name, data->serv_attr->err_code, data->serv_attr->peerID);

			if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
				wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
		}
	}	
}

static struct wpabuf * eap_noob_process (struct eap_sm *sm, void *priv,
		struct eap_method_ret *ret,
		const struct wpabuf *reqData)
{
	struct eap_noob_peer_context *data = priv;
	struct wpabuf *resp = NULL; //TODO:free
	const u8 *pos; //TODO: free
	size_t len;
	json_t * req_obj = NULL;  //TODO: free
	json_t * req_type = NULL; //TODO: free
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

	printf("RECIEVED REQUEST = %s\n", pos);	
	req_obj = json_loads((char *)pos, JSON_COMPACT|JSON_PRESERVE_ORDER, &error);
	id = eap_get_id(reqData);

	if((NULL != req_obj) && (json_is_object(req_obj) > 0)){

		req_type = json_object_get(req_obj,TYPE);

		if((NULL != req_type) && (json_is_integer(req_type) > 0)){
			msgtype = json_integer_value(req_type);
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
		default:
			wpa_printf(MSG_DEBUG, "EAP-NOOB: Unknown EAP-NOOB request received");
			return NULL;
	}

	return resp;
}

static void eap_noob_free_ctx(struct eap_noob_peer_context * data)
{

	struct eap_noob_data * peer = data->peer_attr;
	struct eap_noob_serv_data * serv = data->serv_attr;

	if(NULL == data)
		return;	

	if(serv){
		if(serv->peerID)
			os_free(serv->peerID);
/*
		if(serv->serv_public_key)
			os_free(serv->serv_public_key);
		if(serv->serv_public_key_b64)
			os_free(serv->serv_public_key_b64);
		if(serv->peer_public_key)
			os_free(serv->peer_public_key);
*/
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


static void eap_noob_deinit(struct eap_sm *sm, void *priv)
{
	//TODO:free every allocated memory to avoid leaks

	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB DEINIT");
	struct eap_noob_peer_context * data = priv;

	eap_noob_free_ctx(data);
}

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

		if(FAILURE == eap_noob_exec_query(CREATE_CONNECTION_TABLE, NULL,NULL,data->peerDB)){
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
			if(FAILURE !=  eap_noob_exec_query(buff, eap_noob_db_entry_check,data->serv_attr,data->peerDB)
					&& (data->serv_attr->record_present)){

				memset(buff, 0, sizeof(buff));
				os_snprintf(buff,100,"SELECT * from %s WHERE ssid ='%s'",data->db_table_name,
						wpa_s->current_ssid->ssid);


			if(SQLITE_OK != sqlite3_open_v2(data->db_name, &data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
				wpa_printf(MSG_DEBUG,"EAP-NOOB: Failed to open db here");
				return FAILURE;
			}


			if(FAILURE !=  eap_noob_exec_query(buff, eap_noob_callback,data,
						data->peerDB)){
				//printf("AFTER DB CALLBACK \n");
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

static void eap_noob_assign_config(char * conf_name,char * conf_value,struct eap_noob_data * data)
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


static void eap_noob_parse_config(char * buff,struct eap_noob_data * data)
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


static int eap_noob_prepare_peer_info_obj(struct eap_noob_data * data)
{
	//To-Do: Send Peer Info and Server Info during fast reconnect only if they have changed

	json_t * info_obj = NULL;

        if(NULL == data){
                wpa_printf(MSG_DEBUG, "EAP-NOOB: Input arguments NULL for function %s",__func__);
                return FAILURE;
        }

        if(NULL != (info_obj = json_object())){

                json_object_set_new(info_obj,PEER_NAME,json_string(data->peer_config_params->Peer_name));
                json_object_set_new(info_obj,PEER_SERIAL_NUM,json_string(data->peer_config_params->Peer_ID_Num));

                if(NULL == (data->peer_info = json_dumps(info_obj,JSON_COMPACT|JSON_PRESERVE_ORDER)) || 
			(strlen(data->peer_info) > MAX_INFO_LEN)){
				wpa_printf(MSG_ERROR, "EAP-NOOB: Incorrect or no server info");
 	                       	return FAILURE;
			}       
		printf("PEER INFO = %s\n",data->peer_info);
        }

	return SUCCESS;
}

static int eap_noob_read_config(struct eap_noob_peer_context * data)
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
	
	return eap_noob_prepare_peer_info_obj(data->peer_attr);

}


static int eap_noob_peer_ctxt_init(struct eap_sm *sm,  struct eap_noob_peer_context * data)
{

	/*TODO: remove hard codings and initialize preferably through a 
	  config file*/
	int retval = FAILURE;

	if(NULL != (data->peer_attr = os_zalloc( sizeof (struct eap_noob_data))) && 
			(NULL != (data->serv_attr = os_zalloc( sizeof (struct eap_noob_serv_data))))){

	
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
		
		if(data->serv_attr->state == UNREG || 
			data->serv_attr->state == RECONNECT){	

			if(FAILURE == eap_noob_read_config(data)){
				wpa_printf(MSG_ERROR, "EAP-NOOB: Failed to initialize context");
				return FAILURE;
			}
		}
	}


	return retval;

}

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

static Boolean eap_noob_isKeyAvailable(struct eap_sm *sm, void *priv)
{
	struct eap_noob_peer_context *data = priv;
	Boolean retval = ((data->serv_attr->state == REGISTERED) && (data->serv_attr->shared_key_b64 != NULL));
	printf("STATE = %d\n", data->serv_attr->state);
	wpa_printf(MSG_DEBUG, "EAP-NOOB: KEY AVAILABLE? %d", retval);
	return retval;
}


static u8 * eap_noob_getKey(struct eap_sm *sm, void *priv, size_t *len)
{   
	wpa_printf(MSG_DEBUG, "EAP-NOOB: GET  KEY");

	struct eap_noob_peer_context *data = priv;
	u8 *key;


	if ((data->serv_attr->state != REGISTERED) || (!data->serv_attr->msk))
		return NULL;

	//Base64Decode((char *)data->serv_attr->shared_key_b64, &data->serv_attr->shared_key, len);

	if(NULL == (key = os_malloc(MSK_LEN)))
		return NULL;
	*len = MSK_LEN;
	os_memcpy(key, data->serv_attr->msk, MSK_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: MSK Derived",key,MSK_LEN);

	return key;
}

static u8 * eap_noob_get_emsk(struct eap_sm *sm, void *priv, size_t *len)
{
        struct eap_noob_peer_context *data = priv;
        u8 *key;
	wpa_printf(MSG_DEBUG,"EAP-NOOB:Get EMSK Called");
	if ((data->serv_attr->state != REGISTERED) || (!data->serv_attr->emsk))
                return NULL;

	if(NULL == (key = os_malloc(MSK_LEN)))
                return NULL;


        *len = EAP_EMSK_LEN;
        os_memcpy(key, data->serv_attr->emsk, EAP_EMSK_LEN);
	wpa_hexdump_ascii(MSG_DEBUG,"EAP-NOOB: EMSK",key,EAP_EMSK_LEN);
        return key;
}
static void eap_noob_deinit_for_reauth(struct eap_sm *sm, void *priv)
{

        printf("############################# DE-INIT reauth called\n");
}

static void * eap_noob_init_for_reauth(struct eap_sm *sm, void *priv)
{
        struct eap_noob_peer_context *data = priv;
	
	printf("############################# INIT reauth called\n");
	data->serv_attr->state = RECONNECT;
/*	
	char query[1000] = {0}; //TODO: remove this static allocation and allocate dynamically with actual length
	int len = 1000;

	printf("############################# INIT reauth called\n");
	data->serv_attr->state = RECONNECT;

	eap_oob_config_change(sm,data);
	
	snprintf(query,len,"UPDATE '%s' SET state=%d WHERE PeerID='%s'", data->db_table_name, data->serv_attr->state, data->serv_attr->peerID);
			
	if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
        	wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
                return NULL;
        }
			

	if(FAILURE == eap_oob_exec_query(query, NULL,NULL,data->peerDB)){
		wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
		return NULL;
	}
*/
        return data;
}


static Boolean eap_noob_has_reauth_data(struct eap_sm *sm, void *priv)
{
	struct eap_noob_peer_context *data = priv;
	char query[1000] = {0}; //TODO: remove this static allocation and allocate dynamically with actual length
	int len = 1000;

        printf("######################### Has reauth function called\n");
	
	if(data->serv_attr->state == REGISTERED){

		data->serv_attr->state = RECONNECT;

		eap_noob_config_change(sm,data);
	
		snprintf(query,len,"UPDATE '%s' SET state=%d WHERE PeerID='%s'", data->db_table_name, data->serv_attr->state, data->serv_attr->peerID);
			
		if(SQLITE_OK != sqlite3_open_v2(data->db_name,&data->peerDB,SQLITE_OPEN_READWRITE,NULL)){
        		wpa_printf(MSG_ERROR, "EAP-NOOB: Error opening DB");
                	return FALSE;
        	}
			

		if(FAILURE == eap_noob_exec_query(query, NULL,NULL,data->peerDB)){
			wpa_printf(MSG_ERROR, "EAP-NOOB: updating Noob failed");
			return FALSE;
		}
		
		return TRUE;

	}
	printf("############################Returning False\n");
	return FALSE;
}


int eap_peer_noob_register(void)
{
	int ret;
	struct eap_method * eap = NULL;


	wpa_printf(MSG_DEBUG, "EAP-NOOB: OOB REGISTER");
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
	/*
	   eap->get_identity = eap_oob_get_identity;
	*/
	   eap->has_reauth_data = eap_noob_has_reauth_data;
	   eap->init_for_reauth = eap_noob_init_for_reauth;
	   eap->deinit_for_reauth = eap_noob_deinit_for_reauth;
	 
	ret = eap_peer_method_register(eap);
	if (ret)
		eap_peer_method_free(eap);
	return ret; 	
}
