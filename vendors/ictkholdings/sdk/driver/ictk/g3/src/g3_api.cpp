#include <g3_api.h>
#include "inter_def.h"
#include <stdlib.h>
//#include <memory.h>
#include <stdio.h>
#include <string>
using namespace std;



//#pragma comment(lib,"libBASE.lib")
VAR_BYTES * convert_data_ieb100(void *pure_data, int data_size, int max_res_size);
//int do_normal_process(char inst, char p1, short p2, const void * data, int data_size, void * recv_data, int *real_recv_size);
G3_API_RESULT do_normal_process(char inst, char p1, short p2, const void * data, int data_size, VAR_BYTES ** recv_buff);
void SwapBytes(void* value, int size);
void SetBevalue(void* outvalue, int size, int value);
void api_view(const char *title);
G3_API_RESULT do_normal_process_return_ok(char inst, char p1, short p2, const void * data, int data_size);
int check_sign_struct(EN_SIGN_OPTION sign_option, int structure_size);
int check_vefify_struct(EN_VERIFY_OPTION verify_option, int structure_size);
int check_dynamic_auth_struct(EN_DYNAMIC_AUTH verify_etc, int structure_size);
int return_from_recv(VAR_BYTES *precvbuff);
bool append_var_bytes(VAR_BYTES**dist, const void*buffer, int size);
void view_hexstr(const char *title, const void *pbuff, int size);
void test();
VAR_BYTES* alloc_var_bytes(int size);

VAR_BYTES* create_var_bytes(const void*init, int size);
int CALLTYPE def_send_n_recv(const unsigned char*snd, int snd_size, unsigned char*recv, int* recv_size, void*etcparam);


PFSENDRECV _psend = def_send_n_recv;
//PF_CONVERT _pconvert_data = convert_data_ieb100;
//PFSENDRECV _precv = NULL;
void * _etcparam = NULL;
bool is_use_ieb_100 = true;
FILE * _fp = stderr;

//
//void g3api_set_user_send_recv_pf(const PFSENDRECV psend, const PFSENDRECV precv){
//	_psend = psend;
//	_precv = precv;
//
//
//}



int CALLTYPE def_send_n_recv(const unsigned char*snd, int snd_size, unsigned char*recv, int* recv_size, void*etcparam)
{
	api_view("def_send_n_recv");

	return 0;
}
const char * CALLTYPE g3api_get_lib_version(){
	api_view("g3api_get_lib_version");
	static char szVersion[32] = LIB_VERSION;
	return szVersion;
}

void CALLTYPE g3api_set_user_send_recv_pf(PFSENDRECV psendrecv, void * etcparam){
	api_view("g3api_set_user_send_recv_pf");
	_psend = psendrecv;
	_etcparam = etcparam;
	fprintf(_fp, "0x%x\n", etcparam);
	//_psend(NULL, 0, NULL, NULL, NULL);

}

int send_receiv_packet(LPWRITE_PACKET write_packet,int delay){
	
	_psend((unsigned char *)write_packet, write_packet->header.length, NULL, 0, _etcparam);


	//_precv()


	return 0;

}



G3_API_RESULT CALLTYPE g3api_raw_snd_recv(const unsigned char * snd, int snd_size, unsigned char * recv, int* recv_size){
	int ret = _psend(snd, snd_size, recv, recv_size, _etcparam);
	return ret;
}


void g3api_set_etc_param(void * etcparam){
	_etcparam = etcparam;

}

void g3api_set_fp(void *fp)
{
	_fp = (FILE*)fp;
	
}


VAR_BYTES* g3api_alloc_var_bytes(int size){
	VAR_BYTES*ret = (VAR_BYTES*)malloc(4 + size);
	return ret;
}

void g3api_free_var_bytes(const VAR_BYTES* var_bytes){
	free((void*)var_bytes);
}

G3_API_RESULT CALLTYPE g3api_snd_recv_with_puredata(const unsigned char * puresnd, int snd_size, unsigned char * recv, int* recv_size){
	api_view("g3api_snd_recv_with_puredata");


	VAR_BYTES *precvbuff = NULL;
	int ret;

	LPWRITE_PURE_PACKET lpwrite_pure_packet = (LPWRITE_PURE_PACKET)puresnd;

	//puresnd

	ret = do_normal_process(lpwrite_pure_packet->header.ins, 
		lpwrite_pure_packet->header.p1, 
		lpwrite_pure_packet->header.p2, lpwrite_pure_packet->data ,
		snd_size - sizeof(HEADER_WRITE_PURE_PACKET)
		, &precvbuff);

	if (ret < 0) return ret;

	if (*recv_size < precvbuff->size){
	
		ret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}
	*recv_size = precvbuff->size;

	memcpy(recv, precvbuff->buffer, precvbuff->size);

	//*key_value_size = precvbuff->size;

END:
	if (precvbuff) free(precvbuff);
	return ret;

}



G3_API_RESULT CALLTYPE g3api_read_key_value(const int key_index, EN_AREA_TYPE area_type, EN_RW_INST_OPTION rw_type,const void* data,int data_size,void* data_structure, int structure_size)
//G3_API_RESULT g3api_read_key_value(const int key_index, EN_AREA_TYPE area_type, EN_RW_INST_OPTION rw_type, ST_KEY_VALUE* key_value, ST_IV* iv, ST_MAC* mac)
{


	api_view("g3api_read_key_value");


	VAR_BYTES *precvbuff = NULL;
	int ret;

	//if (*key_value_size < KEY_VALUE_SIZE){
	//	return ERR_KEY_BUFF_SIZE;
	//}
	if (data)
	{
		if (data_size != 32)
		{
			ret = RET_ERR_DIFF_STRUCT_SIZE;
			goto END;
		}
	}

	ret = do_normal_process(READ, key_index, MAKEWORD(area_type, rw_type), data, data_size, &precvbuff);

	if (ret < 0) return ret;

	if (KEY_VALUE_SIZE > precvbuff->size){
		/*int err_ret = 0;
		memcpy(&err_ret, precvbuff->buffer, 4);
		SwapBytes(&err_ret, 4);*/
		ret = return_from_recv(precvbuff);// ERR_INTERCHIP | err_ret;
		goto END;
	}

	memcpy(data_structure, precvbuff->buffer, precvbuff->size);
	//*key_value_size = precvbuff->size;

END:
	if (precvbuff) free(precvbuff);
	return ret;
}


G3_API_RESULT CALLTYPE g3api_write_key_value(const int key_index, EN_AREA_TYPE area_type, EN_RW_INST_OPTION rw_type, const void* data_structure, int structure_size)
//G3_API_RESULT g3api_write_key_value(const int key_index, EN_AREA_TYPE area_type, EN_RW_INST_OPTION rw_type, const ST_KEY_VALUE* key_value, const ST_IV* iv, const ST_MAC* mac)
//int g3api_write_key_value(const int key_index, AREA_TYPE area_type, EN_RW_INST_OPTION rw_type, const unsigned char * key_value, int key_value_size)
{
	api_view("g3api_write_key_value");

	return do_normal_process_return_ok(WRITE, key_index, MAKEWORD(area_type, rw_type), data_structure, structure_size);

}


int CALLTYPE g3api_get_challenge(int chall_size, unsigned char * challenge, int* res_chall_size){
	
	api_view("g3api_get_challenge");
	VAR_BYTES *precvbuff = NULL;
	if (!res_chall_size) return RET_ERR_RECV_ALLOC_ERROR;
	//if (res_chall_size) *res_chall_size =0;

	int nret = do_normal_process(GET_CHAL, chall_size, 0, NULL, 0, &precvbuff);
	if (nret < 0) {
		*res_chall_size = 0;
		goto END;;
	}
	if (!precvbuff){

		goto END;;

	}
	if ( precvbuff->size > *res_chall_size){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}

	if(challenge) memcpy(challenge, precvbuff->buffer, precvbuff->size);
	if (res_chall_size) *res_chall_size = precvbuff->size;

END:
	if (precvbuff) free(precvbuff);

	return nret;



	
}

int CALLTYPE g3api_verify_passwd(const int key_index, const unsigned char * passwd, int passwd_size){
	api_view("g3api_verify_passwd");
	return  do_normal_process_return_ok(VERIFY_PWD, key_index, 0, passwd, passwd_size);
#if 0
	VAR_BYTES *precvbuff = NULL;
	int nret = do_normal_process(VERIFY_PWD, key_index, 0, passwd, passwd_size, &precvbuff);

	if (nret < 0) {
		goto END;
	}

	if (!precvbuff){
		nret = RET_ERR_RECV_ALLOC_ERROR;
		goto END;
	}

	nret = return_from_recv(precvbuff);// RET_ERR_INTERCHIP | err_ret;
	if (nret < 0) {
		goto END;;
	}

	/*if (precvbuff->size != structure_size) {
		nret = RET_ERR_DIFF_STRUCT_SIZE;
		goto END;
	}*/
END:
	if (precvbuff) free(precvbuff);


	return nret;

#endif
}

int CALLTYPE g3api_change_password(const int key_index, const unsigned char * passwd, int passwd_size){
	api_view("g3api_change_password");
	int recv_ret = 0;
	int recv_ret_size = 4;
	return  do_normal_process_return_ok(CHANGE_PWD, key_index, 0, passwd, passwd_size);

}

int CALLTYPE g3api_init_puf(const int key_index, unsigned int initial){
	api_view("g3api_init_puf");
	SwapBytes(&initial,4);

	int nret = do_normal_process_return_ok(INIT_PRIV_KEY, key_index, 0, &initial, 4);
	return nret;
}
G3_API_RESULT CALLTYPE g3api_sign(const int key_index, EN_SIGN_OPTION sign_option, const unsigned char * msg, int msg_size, void * sign_structure, int structure_size)
//int g3api_sign(const int key_index, SIGN_OPTION ecdsa_option, const unsigned char * msg, int msg_size, void * sign_structure, int structure_size)
{
	api_view("g3api_sign");

	int nret = check_sign_struct(sign_option, structure_size);
	if (nret<0) return nret;

	
	//int recv_size = structure_size;
	VAR_BYTES *precvbuff = NULL;
	nret = do_normal_process(SIGN, key_index, sign_option, msg, msg_size, &precvbuff);

	if (nret < 0) {
		goto END;;
	}

	if (!precvbuff){
		nret = RET_ERR_RECV_ALLOC_ERROR;
		goto END;
	}

	nret = return_from_recv(precvbuff);// RET_ERR_INTERCHIP | err_ret;
	if (nret < 0) {
		goto END;;
	}

	if (precvbuff->size != structure_size) {
		nret =  RET_ERR_DIFF_STRUCT_SIZE;
		goto END;
	}

	

	memcpy(sign_structure, precvbuff->buffer, precvbuff->size);
END:

	if (precvbuff) free(precvbuff);


	return nret;

}
G3_API_RESULT CALLTYPE g3api_verify(const int key_index, EN_VERIFY_OPTION verify_option, const unsigned char * msg, int msg_size, const void * sign_structure, int structure_size)
//int g3api_verify(const int key_index, VERIFY_OPTION verify_option, const unsigned char * msg, int msg_size, const void * sign_structure, int structure_size)
{
	api_view("g3api_verify");
	int nret = check_vefify_struct(verify_option, structure_size);
	if (nret<0) return nret;
	
	unsigned char * pbuff = (unsigned char *)malloc(msg_size + structure_size);
	memcpy(pbuff, msg, msg_size);
	memcpy(pbuff + msg_size, sign_structure, structure_size);



	


	nret = do_normal_process_return_ok(VERIFY, key_index, verify_option, pbuff, msg_size + structure_size);
	free(pbuff);

	return nret;
}

G3_API_RESULT CALLTYPE g3api_dynamic_auth(int key_index, EN_DYNAMIC_AUTH dauth_option, int pos_pub_dynamic, const unsigned char * msg, int msg_size, const void * sign_structure, int structure_size)
//int g3api_dynamic_auth(int key_index, DYNAMIC_AUTH dauth_option, int pos_pub_dynamic, const unsigned char * msg, int msg_size, const void * sign_structure, int structure_size)
{
	api_view("g3api_verify_dynamic");
	int nret = check_dynamic_auth_struct(dauth_option, structure_size);
	if (nret<0) return nret;
	
	unsigned char * pbuff = (unsigned char *)malloc(msg_size + structure_size);
	memcpy(pbuff, msg, msg_size);
	memcpy(pbuff + msg_size, sign_structure, structure_size);

	
	
	nret = do_normal_process_return_ok(VERIFY, key_index, MAKEWORD(dauth_option, pos_pub_dynamic), pbuff, msg_size + structure_size);
	free(pbuff);

	return nret;


}


G3_API_RESULT CALLTYPE g3api_encryption(IN int key_index, IN EN_KEY_TYPE key_type, IN EN_BLOCK_MODE block_mode, IN const ST_IV * iv, IN const unsigned char* data, IN int data_size, OUT unsigned char* cipher, INOUT int* cipher_size)
{

	

	api_view("g3api_encryption");
	VAR_BYTES *precvbuff = NULL;
	VAR_BYTES * buff = create_var_bytes(iv, sizeof(ST_IV));
	append_var_bytes(&buff, data, data_size);

	view_hexstr("g3api_encryption test", buff->buffer, buff->size);

	int nret = do_normal_process(ENCRYPT, key_index, MAKEWORD(block_mode, key_type), buff->buffer, buff->size, &precvbuff);
	if (nret < 0) goto END;
//if(iv) memcpy(iv, precvbuff->buffer, sizeof(ST_IV));
	//if (cipher) memcpy(cipher, precvbuff->buffer + sizeof(ST_IV), precvbuff->size - sizeof(ST_IV));


	if (cipher_size && (precvbuff->size > *cipher_size)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}
	if (cipher){
		memcpy(cipher, precvbuff->buffer, precvbuff->size);
		*cipher_size = precvbuff->size;
	}




	if (cipher) memcpy(cipher, precvbuff->buffer, precvbuff->size);
	//if (cipher_size) *cipher_size = precvbuff->size - sizeof(ST_IV);



END:
	if (precvbuff) free(precvbuff);

	return nret;



}

G3_API_RESULT CALLTYPE g3api_decryption(IN int key_index, IN EN_KEY_TYPE key_type, IN EN_BLOCK_MODE block_mode, IN const ST_IV* iv, IN const unsigned char* cipher, IN int cipher_size, OUT unsigned char* data, INOUT int* data_size)
{

	
	api_view("g3api_decryption");
	VAR_BYTES *precvbuff = NULL;

	VAR_BYTES * buff = create_var_bytes(iv, sizeof(ST_IV));
	append_var_bytes(&buff, cipher, cipher_size);
	
	view_hexstr("g3api_decryption test", buff->buffer, buff->size);

	int nret = do_normal_process(DECRYPT, key_index, MAKEWORD(block_mode,key_type), buff->buffer, buff->size, &precvbuff);
	
	if (nret < 0) goto END;

	if (data) memcpy(data, precvbuff->buffer, precvbuff->size);
	if (data_size) *data_size = precvbuff->size;




END:
	if (buff) free(buff);
	if (precvbuff) free(precvbuff);

	return nret;
}

G3_API_RESULT CALLTYPE g3api_encryption_ecies(IN int key_index, IN EN_KEY_TYPE key_type, OUT ST_ECIES* rs)
{

	api_view("g3api_encryption_ecies");
	VAR_BYTES *precvbuff = NULL;
	int nret = do_normal_process(ENCRYPT, key_index, MAKEWORD(0x10,key_type) , NULL, 0, &precvbuff);
	if (nret < 0) goto END;

	if (precvbuff->size != sizeof(ST_ECIES)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}
	if (rs) memcpy(rs, precvbuff->buffer, precvbuff->size);


END:
	if (precvbuff) free(precvbuff);

	return nret;
}

G3_API_RESULT CALLTYPE g3api_decryption_ecies(IN int key_index, INOUT ST_ECIES* rs)
{

	api_view("g3api_decryption_ecies");
	VAR_BYTES *precvbuff = NULL;
	if (!rs){
		return RET_ERR_RECV_ALLOC_ERROR;


	}
	int nret = do_normal_process(DECRYPT, key_index, 0x10, rs->r, sizeof(rs->r), &precvbuff);
	if (nret < 0) goto END;
	
	if (precvbuff->size != sizeof( ((ST_ECIES*)0)->s)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}

	if (rs) memcpy(rs->s, precvbuff->buffer, precvbuff->size);


END:
	if (precvbuff) free(precvbuff);

	return nret;
}


G3_API_RESULT CALLTYPE g3api_encryption_ecies_xy(IN int key_index, IN EN_KEY_TYPE key_type, OUT ST_ECIES_XY* rp)
{

	api_view("g3api_encryption_ecies_xy");
	VAR_BYTES *precvbuff = NULL;
	int nret = do_normal_process(ENCRYPT, key_index, MAKEWORD(0x11, key_type), NULL, 0, &precvbuff);
	if (nret < 0) goto END;

	if (precvbuff->size != sizeof(ST_ECIES_XY)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}
	if (rp) memcpy(rp, precvbuff->buffer, precvbuff->size);


END:
	if (precvbuff) free(precvbuff);

	return nret;
}

G3_API_RESULT CALLTYPE g3api_decryption_ecies_xy(IN int key_index, INOUT ST_ECIES_XY* rp)
{

	api_view("g3api_decryption_ecies_xy");
	VAR_BYTES *precvbuff = NULL;
	if (!rp){
		return RET_ERR_RECV_ALLOC_ERROR;


	}
	int nret = do_normal_process(DECRYPT, key_index, 0x11, rp->r, sizeof(rp->r), &precvbuff);
	if (nret < 0) goto END;

	if (precvbuff->size != sizeof(((ST_ECIES_XY*)0)->p)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}

	if (rp) memcpy(rp->p, precvbuff->buffer, precvbuff->size);


END:
	if (precvbuff) free(precvbuff);

	return nret;
}

G3_API G3_API_RESULT CALLTYPE g3api_encryption_sm2(IN int key_index, IN EN_KEY_TYPE key_type, OUT ST_SM2_C1 * c1, IN const byte* data, IN int data_size, OUT ST_SM2_C3 * c3, OUT byte* cipher, INOUT int* cipher_size)
{
	VAR_BYTES *precvbuff = NULL;

	int nret;
	int unit_size = 240;
	int remain_size = 0;

	int index = 0;

	if (!c1 || !data || !c3 || !cipher){
		return RET_ERR_RECV_ALLOC_ERROR;
	}

	/* sm2 encryption initialize */

	api_view("g3api_encryption_sm2_initialize");

	nret = do_normal_process(ENCRYPT, key_index, 0x0020, NULL, 0, &precvbuff);
	if (nret < 0 || nret == 0x03 || nret == 0x0f) goto END;

	if (precvbuff->size != sizeof(ST_SM2_C1)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}
	if (c1) memcpy(c1, precvbuff->buffer, precvbuff->size);
	

	api_view("g3api_encryption_sm2_update");

	if (!data_size)
	{
		nret = RET_ERR_RECV_ALLOC_ERROR;
		goto END;
	}

	remain_size = data_size;

	while (remain_size)
	{
		int realsize = g3min(remain_size, unit_size);

		nret = do_normal_process(ENCRYPT, key_index, 0x0021, data + index, realsize, &precvbuff);
		
		if (nret < 0) goto END;
		
		if (precvbuff->size != (sizeof(ST_SM2_C1) + index + realsize)){
			nret = RET_ERR_RECV_BUFF_SIZE;
			goto END;
		}
		
		remain_size -= realsize;
		index += realsize;
	}
	if (cipher_size) memcpy(cipher, (precvbuff->buffer) + sizeof(ST_SM2_C1), *cipher_size);
	
	api_view("g3api_encryption_sm2_final");

	nret = do_normal_process(ENCRYPT, key_index, 0x0022, NULL, 0, &precvbuff);
	if (nret < 0 || nret == 0x03 || nret == 0x0f) goto END;
	
	if (precvbuff->size != (sizeof(ST_SM2_C1) + index + sizeof(ST_SM2_C3))){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}

	if (c3) memcpy(c3, ((precvbuff->buffer) + sizeof(ST_SM2_C1) + *cipher_size), sizeof(ST_SM2_C3));
	
	

END:
	if (precvbuff) free(precvbuff);

	return nret;
}

G3_API G3_API_RESULT CALLTYPE g3api_decryption_sm2(IN int key_index, IN EN_KEY_TYPE key_type, IN ST_SM2_C1 * c1, IN const byte* cipher, IN int cipher_size, IN ST_SM2_C3 * c3, OUT byte* data, INOUT int* data_size)
{
	VAR_BYTES *precvbuff = NULL;

	int nret;
	int unit_size = 240;
	int remain_size = 0;
	int send_size = 0;

	int index = 0;

	if (!c1 || !data || !c3 || !cipher){
		return RET_ERR_RECV_ALLOC_ERROR;
	}

	/* sm2 decryption initialize */

	api_view("g3api_decryption_sm2_initialize");

	nret = do_normal_process_return_ok(DECRYPT, key_index, 0x0020, c1, sizeof(ST_SM2_C1));
	if (nret < 0 || nret == 0x03 || nret == 0x0f) goto END;

	api_view("g3api_decryption_sm2_update");

	if (!cipher_size)
	{
		nret = RET_ERR_RECV_ALLOC_ERROR;
		goto END;
	}

	remain_size = cipher_size;

	while (remain_size)
	{
		int realsize = g3min(remain_size, unit_size);

		nret = do_normal_process(DECRYPT, key_index, 0x0021, cipher + index, realsize, &precvbuff);

		if (nret < 0) goto END;

		if (precvbuff->size != (index + realsize)){
			nret = RET_ERR_RECV_BUFF_SIZE;
			goto END;
		}

		remain_size -= realsize;
		index += realsize;
	}
	if (data_size) memcpy(data, precvbuff->buffer, *data_size);

	api_view("g3api_decryption_sm2_final");

	nret = do_normal_process_return_ok(DECRYPT, key_index, 0x0022, c3, sizeof(ST_SM2_C3));
	if (nret < 0 || nret == 0x03 || nret == 0x0f) goto END;
	
END:
	if (precvbuff) free(precvbuff);

	return nret;
}

G3_API_RESULT CALLTYPE g3api_get_public_key(int key_index, EN_PUB_TYPE pub_type, void* pub_key, int structure_size)

{

	api_view("g3api_get_public_key");
	VAR_BYTES *precvbuff = NULL;
	short lowerbyte = 0;
	switch (structure_size){
	case sizeof(ST_ECC_PUBLIC) :
		lowerbyte = 1;
		break;
	case sizeof(ST_ECC_PUBLIC_COMPRESS) :
		lowerbyte = 0;
		break;
									

	default:
		return RET_ERR_DIFF_STRUCT_SIZE;

	}


	
	int nret = do_normal_process(GET_PUB_KEY, key_index, MAKEWORD(lowerbyte, pub_type), NULL, 0, &precvbuff);
	
	if (nret < 0) goto END;

	if (pub_key) memcpy(pub_key, precvbuff->buffer, precvbuff->size);




END:
	if (precvbuff) free(precvbuff);

	return nret;



}

G3_API_RESULT CALLTYPE g3api_session(IN int key_index, IN EN_SESSION_MODE en_session_mode, IN const byte* indata, IN int indata_size, OUT byte* outdata, INOUT int* outdata_size)
{

	api_view("g3api_session");
	VAR_BYTES *precvbuff = NULL;
	

	int nret = do_normal_process(SESSION, key_index, en_session_mode, indata, indata_size, &precvbuff);


	if (nret < 0) goto END;

	if (outdata_size){
		if (precvbuff->size > *outdata_size){
			nret = RET_ERR_RECV_BUFF_SIZE;
			goto END;
		}
		else
		{
			*outdata_size = precvbuff->size;
 			memcpy(outdata, precvbuff->buffer, precvbuff->size);
		}
	}


END:
	if (precvbuff) free(precvbuff);

	return nret;



}


G3_API_RESULT CALLTYPE g3api_set_extern_public_key(IN const void* pub_key, IN int structure_size, OUT ST_DATA_32* puk_hash)
{

	api_view("g3api_set_extern_public_key");
	
	VAR_BYTES *precvbuff = NULL;
	int nret = do_normal_process(SESSION, 1, EXT_PUB_KEY, pub_key, structure_size, &precvbuff);

	
	if (nret < 0) goto END;

	if (!precvbuff || precvbuff->size != sizeof(ST_DATA_32)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}
	memcpy(puk_hash, precvbuff->buffer, precvbuff->size);




END:
	if (precvbuff) free(precvbuff);

	return nret;



}

G3_API_RESULT CALLTYPE g3api_certification(int key_index, EN_CERTIFICATION_WRITE_MODE certification_write_mode, const unsigned char * cert, int cert_size)
//G3_API_RESULT g3api_certification(int key_index, CERTIFICATION_WRITE_MODE certification_write_mode, const unsigned char * cert, int cert_size)
{
	
	api_view("g3api_certification");
	int nret = 0;
	int unit_size = 240;

	const unsigned char * psubcert = cert;

	int remain_size = cert_size;
	int index = 0;
	while (remain_size>0)
	{
		int realsize = g3min(remain_size, unit_size);
		if (remain_size <= unit_size)//마지막루프 
		{
			index = 0xff;
		}
		VAR_BYTES *precvbuff = NULL;
		nret = do_normal_process_return_ok(CERT, key_index, MAKEWORD(index, certification_write_mode), psubcert, realsize);
		if (nret < 0) return nret;
		if (precvbuff) {
			free(precvbuff);
			precvbuff = NULL;
		}

		
		psubcert += unit_size;
		remain_size -= unit_size;
		


		index++;
	} ;


	return nret;



}

G3_API_RESULT CALLTYPE g3api_issue_certification(int key_index, int public_key_pos, EN_ISSUE_CERT_AREA_TYPE issue_cert_area_type, int sector_num_to_store, int key_id, IN const ST_DATA_32* encrypted_key, const unsigned char * cert, int cert_size)

//int g3api_issue_certification(int key_index, const unsigned char * cert, int cert_size)
{

	api_view("g3api_issue_certification");
	int nret = 0;
	int unit_size = 240;
	unsigned char buff[64];

	const unsigned char * psubcert = cert;

	int remain_size = cert_size;
	int index = 0;
	while (remain_size>0)
	{
		int realsize = g3min(remain_size, unit_size);
		
		VAR_BYTES *precvbuff = NULL;
		int unit_pub_pos = -1;
		if (public_key_pos < unit_size && public_key_pos>=0) unit_pub_pos = public_key_pos;
		nret = do_normal_process_return_ok(ISSUE_CERT, key_index, MAKEWORD(index, unit_pub_pos), psubcert, realsize);
		if (nret < 0) return nret;
		if (precvbuff) {
			free(precvbuff);
			precvbuff = NULL;
		}


		psubcert += unit_size;
		remain_size -= unit_size;
		public_key_pos -= unit_size;



		index++;
	};

	index = 0xff;
	buff[0] = issue_cert_area_type;
	buff[1] = sector_num_to_store;
	SwapBytes(&key_id, 2);
	memcpy(&buff[2], &key_id, 2);

	if (encrypted_key)
	{
		memcpy(&buff[4], encrypted_key, 32);
		nret = do_normal_process_return_ok(ISSUE_CERT, key_index, 0XFFFF, buff, 4+32);
	}
	else
	{
		nret = do_normal_process_return_ok(ISSUE_CERT, key_index, 0XFFFF, buff, 4);
	}

	return nret;


	api_view("g3api_issue_certification");
	VAR_BYTES *precvbuff = NULL;
	nret = do_normal_process(ISSUE_CERT, 0, 0, NULL, 0, &precvbuff);
	if (nret < 0) goto END;


END:
	if (precvbuff) free(precvbuff);

	return nret;



}


G3_API_RESULT CALLTYPE g3api_ecdh(IN EN_ECDH_MODE en_ecdh_mode, IN const void* Q_b, IN int Q_b_struct_size, IN const ST_ECDH_RANDOM* st_ecdh_random, OUT ST_ECC_PUBLIC* Q_chip, OUT void* ecdh_value, OUT int ecdh_value_struct_size)
{


	api_view("g3api_ecdh");
	VAR_BYTES *precvbuff = NULL;
	int p2 = 0x0000;
	
	VAR_BYTES * buff = create_var_bytes(Q_b, Q_b_struct_size);
	
	switch (en_ecdh_mode)
	{
	case NORMAL_ECDH:
		break;
	case GEN_TLS_BLOCK:
	case SET_TLS_SESSION_KEY:
		append_var_bytes(&buff, st_ecdh_random, sizeof(ST_ECDH_RANDOM));

		break;
	}
	
	if (ecdh_value_struct_size == sizeof(ST_ECDH_PRE_MASTER_SECRET)){

	}
	int nret = do_normal_process(ECDH, 0, en_ecdh_mode, buff->buffer, buff->size, &precvbuff);
	if (nret < 0) goto END;
	if (precvbuff->size != sizeof(ST_ECC_PUBLIC) + ecdh_value_struct_size){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}

	memcpy(Q_chip, precvbuff->buffer, sizeof(ST_ECC_PUBLIC));
	memcpy(ecdh_value, precvbuff->buffer + sizeof(ST_ECC_PUBLIC), ecdh_value_struct_size);


END:
	if (precvbuff) free(precvbuff);

	return nret;



}


G3_API_RESULT CALLTYPE g3api_make_tls_inter_header_without_size(IN int seq_num, IN EN_CONTENT_TYPE content_type, IN EN_TLS_VERSION tls_version, OUT ST_TLS_INTER_HEADER_WITHOUT_SIZE* tls_inter_header_without_size)
{
	api_view("g3api_make_tls_inter_header_without_size");

	//TLS_INTER_HEADER tls_inter_header = { 0, };
	//ST_TLS_INTER_HEADER_WITHOUT_SIZE *tls_inter_header_without_size = &tls_inter_header->tls_inter_header_without_size;
	tls_inter_header_without_size->hi_be_sequence = 0;
	SetBevalue(&tls_inter_header_without_size->lo_be_sequence ,4, seq_num);
	SetBevalue(&tls_inter_header_without_size->tls_be_ver,2,tls_version);

	tls_inter_header_without_size->content_type = content_type;


	/*SwapBytes(&tls_inter_header_without_size->lo_be_sequence, 4);
	SwapBytes(&tls_inter_header_without_size->tls_be_ver, 2);
	SwapBytes(&tls_inter_header->msg_be_size, 2);
*/

	return 0;
}
G3_API_RESULT CALLTYPE tls_crypto_temp(int cmd, IN const ST_TLS_INTER_HEADER* tls_inter_header,
	IN const ST_IV* iv, 
	IN const byte* init_buff, IN int init_buff_size,
	IN const byte* in, IN int in_size, 
	int tail_size,
	VAR_BYTES **pprecvbuff)
{
	int last_index = 0;
	int remain_size =0;
	int unit_size = 240;

	int index = 0;
	byte* pubb = NULL;

	if (!iv || !in || !pprecvbuff){
		return RET_ERR_RECV_ALLOC_ERROR;
	}

	
	VAR_BYTES *pplastrecvbuff = NULL;
	//VAR_BYTES *precvbuff = NULL;




	VAR_BYTES * buff = create_var_bytes(tls_inter_header, sizeof(TLS_INTER_HEADER));

	view_hexstr("TLS_INTER_HEADER", tls_inter_header, sizeof(TLS_INTER_HEADER));

	
	append_var_bytes(&buff, iv, sizeof(ST_IV));
	if(init_buff) append_var_bytes(&buff, init_buff, init_buff_size);


	int nret = do_normal_process_return_ok(cmd, 0, 0, buff->buffer, buff->size);
	if (nret < 0) goto END;
	//if (buff)  free(buff);



	pubb = (byte*)in;
	//byte* pubb = (byte*) msg;
	view_hexstr("in", in, in_size);

	//int tail_size = in_size % 16;
	remain_size = in_size - tail_size;
	unit_size = 240;

	index = 0;
	while (remain_size>0)
	{
		int realsize = g3min(remain_size, unit_size);
		#if 0 //deleted by ICTK
		fprintf(_fp, "remain_size:%d realsize : %d\n", remain_size, realsize);
		#endif
		//VAR_BYTES *precvbuff = NULL;
		int unit_pub_pos = -1;

		view_hexstr("pubb:", pubb, realsize);
		nret = do_normal_process(cmd, 0, 1, pubb, realsize, pprecvbuff);
		if (nret < 0) return nret;
		//if (precvbuff) {
		//	free(precvbuff);
		//	precvbuff = NULL;
		//}

		pubb += realsize;
		remain_size -= realsize;

		index++;
	};
	#if 0 //deleted by ICTK
	fprintf(_fp, "remain_size:%d tail_size : %d\n", remain_size, tail_size);
	#endif
	view_hexstr("pubb:", pubb, tail_size);

	

	
	nret = do_normal_process(cmd, 0, 0xff, pubb, tail_size, &pplastrecvbuff);
	if (nret < 0) goto END;

	if (nret == 1){
		goto END;
	}

	
	if (cmd == TLS_DEC_VERIFY){
		last_index = 1;

		if (pplastrecvbuff) nret = pplastrecvbuff->buffer[0];

	}
	if (pplastrecvbuff) append_var_bytes(pprecvbuff, pplastrecvbuff->buffer + last_index, pplastrecvbuff->size - last_index);


	


	//if (out_size && (precvbuff->size > *out_size)){
	//	nret = RET_ERR_RECV_BUFF_SIZE;
	//	goto END;
	//}
	//if (out){
	//	memcpy(out, precvbuff->buffer, precvbuff->size);
	//	*out_size = precvbuff->size;
	//}


END:
	if (buff) free(buff);
	if (pplastrecvbuff) free(pplastrecvbuff);

	return nret;



}



G3_API_RESULT CALLTYPE g3api_tls_mac_encrypt(
	IN const ST_TLS_INTER_HEADER_WITHOUT_SIZE* tls_inter_header_without_size, 
	IN const ST_IV* client_iv, IN const ST_DATA_16* header_random, 
	IN const byte* msg, IN int msg_size, 
	OUT byte* crypto, INOUT int * crypto_size)
{


	api_view("g3api_tls_mac_encrypt");
	VAR_BYTES *precvbuff = NULL;

	if (!header_random){
		return RET_ERR_RECV_ALLOC_ERROR;
	}
	
	VAR_BYTES * buff = alloc_var_bytes( 0);
	
	append_var_bytes(&buff, header_random, sizeof(ST_DATA_16));
	append_var_bytes(&buff, msg, msg_size);
	ST_TLS_INTER_HEADER tls_inter_header;
	memcpy(&tls_inter_header.tls_inter_header_without_size, tls_inter_header_without_size, sizeof(ST_TLS_INTER_HEADER_WITHOUT_SIZE));
	SetBevalue(&tls_inter_header.msg_be_size, 2, msg_size);
	
	
	int nret = tls_crypto_temp(TLS_MAC_ENC, &tls_inter_header, client_iv,
		NULL,0,
		buff->buffer, buff->size, buff->size % 16, &precvbuff);




	if (crypto_size && (precvbuff->size > *crypto_size)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}
	if (crypto){
		memcpy(crypto, precvbuff->buffer, precvbuff->size);
		*crypto_size = precvbuff->size;
	}
	

END:
	if (buff) free(buff);
	//if (precvbuff) free(precvbuff);

	return nret;



}
G3_API_RESULT CALLTYPE g3api_tls_decrypt_verify(
	IN const ST_TLS_INTER_HEADER_WITHOUT_SIZE* tls_inter_header_without_size, 
	IN const ST_IV* server_iv, 
	IN const byte* crypto, IN int crypto_size, 
	OUT ST_DATA_16* header_random, 
	OUT byte* msg, INOUT int* msg_size)
{


	api_view("g3api_tls_decrypt_verify");
	VAR_BYTES *precvbuff = NULL;

	VAR_BYTES * buff = create_var_bytes(msg, *msg_size);
	append_var_bytes(&buff, header_random, sizeof(ST_DATA_16));

	ST_TLS_INTER_HEADER tls_inter_header;
	memcpy(&tls_inter_header.tls_inter_header_without_size, tls_inter_header_without_size, sizeof(ST_TLS_INTER_HEADER_WITHOUT_SIZE));
	SetBevalue(&tls_inter_header.msg_be_size, 2, crypto_size);



	int nret = tls_crypto_temp(TLS_DEC_VERIFY, &tls_inter_header,  server_iv,
		crypto + crypto_size-32, 32,
		//NULL,0,
		crypto, crypto_size,48,
		&precvbuff);
	
	if (nret != 0) goto END;
	
	//nret = precvbuff->buffer[0];

	if (msg_size && (precvbuff->size > *msg_size + sizeof(ST_DATA_16)+1)){
		nret = RET_ERR_RECV_BUFF_SIZE;
		goto END;
	}

	if (precvbuff->size <= sizeof(ST_DATA_16) + 1){
		nret = RET_ERR_RET_SIZE;
		goto END;
	}

	memcpy(header_random, &precvbuff->buffer[0], sizeof(ST_DATA_16));
	memcpy(msg, &precvbuff->buffer[sizeof(ST_DATA_16)], precvbuff->size - sizeof(ST_DATA_16));

	if (msg_size) *msg_size = precvbuff->size  - sizeof(ST_DATA_16);


END:
	if (precvbuff) free(precvbuff);

	return nret;



}


G3_API_RESULT CALLTYPE g3api_tls_get_handshake_digest(IN EN_HANDSHAKE_MODE handshake_mode, IN const ST_DATA_32* hash_handshake_msg, OUT ST_TLS_HAND_HANDSHAKE_DIGEST* handshake_digest)
{

	api_view("g3api_tls_get_handshake_digest");
	VAR_BYTES *precvbuff = NULL;
	int nret = do_normal_process(TLS_GET_HANDSHAKE_DIGEST, 0, handshake_mode, hash_handshake_msg, sizeof(ST_DATA_32), &precvbuff);
	
	if (nret < 0) goto END;

	
	if (precvbuff->size != sizeof(ST_TLS_HAND_HANDSHAKE_DIGEST) ){
		nret = RET_ERR_RET_SIZE;
		goto END;
	}
	memcpy(handshake_digest, precvbuff->buffer, precvbuff->size);


END:
	if (precvbuff) free(precvbuff);

	return nret;



}
VAR_BYTES * _testbuff = NULL;
int CALLTYPE deffunction(int param){
	fprintf(_fp, "\n %d \n", param);
	return param;
}
PFTEST _in = deffunction;

int _test_value = -1;
int * _ptest_value = &_test_value;
G3_API_RESULT CALLTYPE g3api_test(IN PFTEST in, IN int in_size)
{
	api_view("g3api_test");
	_in = in;
	_in(in_size);
	_test_value = in_size;
	fprintf(_fp, "\n0x%x\n", _in);
	return 0;
}



G3_API_RESULT CALLTYPE g3api_test2(IN char* test, IN int* out_size)
{
	api_view("g3api_test2");
	//const unsigned char tempbuff[] = { 0xE2, 0xC4, 0x26, 0xE7, 0xF1, 0x77, 0x8C, 0x6F, 0xC5, 0x95, 0xF5, 0x4E, 0x9F, 0xEF, 0xDA, 0x71, 0x14, 0x00, 0x00, 0x0C, 0x92, 0x28, 0xE3, 0xFD, 0x2E, 0xB4, 0x11, 0xAE, 0x47, 0xF1, 0x0F, 0x1E, };
	const unsigned char tempbuff[] = { 0xE2, 0xC4, 0x26, 0xE7, 0xF1, 0x77, 0, 0x6F, 0xC5, 0x95, 0xF5, 0x4E, 0x9F, 0xEF, 0xDA, 0x71, 0x14, 0x00, 0x00, 0x0C, 0x92, 0x28, 0xE3, 0xFD, 0x2E, 0xB4, 0x11, 0xAE, 0x47, 0xF1, 0x0F, 0x1E, };
	memcpy(test, tempbuff, 32);
	*out_size = 32;

	return 0;
}
G3_API_RESULT CALLTYPE g3api_test3(IN int* in_size)
{
	api_view("g3api_test3");
	_ptest_value = in_size;
	fprintf(_fp, "\n%d\n", *in_size);
	*in_size = 123132;
	return 0;
}
//START API

G3_API_RESULT CALLTYPE g3api_get_device_version()
{
	api_view("g3api_get_device_version");
	return 0;
}	
	
char* CALLTYPE g3api_get_sn()
{
	api_view("g3api_get_sn");
	return 0;
}	

G3_API_RESULT CALLTYPE g3api_diversify(IN int key_index,IN EN_DIVERSIFY_MODE diversify_mode,IN const byte* data,IN int data_size)
{

	api_view("g3api_diversify");
	
	return do_normal_process_return_ok(DIVERSIFY, key_index, diversify_mode, data, data_size);	
}	
	
	
G3_API_RESULT CALLTYPE g3api_hash_sha256(IN EN_SHA256_MODE sha256_mode,IN const byte* data,IN int data_size,OUT ST_DATA_32* outdata)
{
	//G3_API_RESULT do_normal_process_return_ok(char inst, char p1, short p2, const void * data, int data_size)
	api_view("g3api_hash_sha256");	
	int nret;
	int unit_size = 240;
	int remain_size = 0;

	int index = 0;

	VAR_BYTES *precvbuff = NULL;
	
	if( sha256_mode == 0x0000 )
	{
		return do_normal_process_return_ok(SHA256, 0, sha256_mode, NULL, 0);	
	}
	else if( sha256_mode == 0x0001 )
	{
		remain_size = data_size;

		while (remain_size)
		{
			int realsize = g3min(remain_size, unit_size);
			return do_normal_process_return_ok(SHA256, 0, sha256_mode, data, realsize);
			if (nret < 0) goto END;

			remain_size -= realsize;
			index += realsize;
		}
	}
	else
	{
		nret = do_normal_process(SHA256, 0, sha256_mode, NULL, 0, &precvbuff);	
	}
	
	if (nret < 0) goto END;
	
	if(outdata)
	{
		memcpy(outdata, precvbuff->buffer, precvbuff->size);
	}

	
END:
	if (precvbuff) free(precvbuff);

	return nret;
}	


G3_API_RESULT CALLTYPE g3api_hash_sm3(IN EN_SM3_MODE sm3_mode, IN const byte* data, IN int data_size, OUT ST_DATA_32* outdata)
{
	api_view("g3api_hash_sm3");
	int nret;
	int unit_size = 240;
	int remain_size = 0;

	int index = 0;

	VAR_BYTES *precvbuff = NULL;

	if (sm3_mode == 0x0000)
	{
		return do_normal_process_return_ok(SM3, 0x01, sm3_mode, NULL, 0);
	}
	else if (sm3_mode == 0x0001)
	{
		remain_size = data_size;

		while (remain_size)
		{
			int realsize = g3min(remain_size, unit_size);

			nret = do_normal_process_return_ok(SM3, 0x01, sm3_mode, data + index, realsize);
			if (nret < 0) goto END;

			remain_size -= realsize;
			index += realsize;
		}
	}
	else
	{
		nret = do_normal_process(SM3, 0x01, sm3_mode, NULL, 0, &precvbuff);
	}

	if (nret < 0) goto END;

	if (outdata)
	{
		memcpy(outdata, precvbuff->buffer, precvbuff->size);
	}


END:
	if (precvbuff) free(precvbuff);

	return nret;
}

	
G3_API_RESULT CALLTYPE g3api_reset()
{
	
	api_view("g3api_reset");

	return do_normal_process_return_ok(RESET, 0, 0, NULL, 0);
	/*
	VAR_BYTES *precvbuff = NULL;
	
	int nret = do_normal_process_return_ok(RESET, 0, 0, NULL, 0, &precvbuff);
	
	if (nret < 0) goto END;


END:
	if (precvbuff) free(precvbuff);
	
	return nret;
	*/
}	

	//END API
#if 0

G3_API_RESULT CALLTYPE g3api_test(const unsigned char * in, int in_size)
{
	api_view("g3api_test");
	//_testbuff = create_var_bytes(in, in_size);
	//int ret = _psend(_testbuff->buffer, _testbuff->size, NULL, NULL, NULL);

	VAR_BYTES * pvsnd = create_var_bytes("0123456789", 30);
	VAR_BYTES * precv = alloc_var_bytes(32);
	int size = 32;


	/*printf("pvsnd->buffer:0x%x\n", pvsnd);
	printf("pvsnd->buffer:0x%x\n", pvsnd);
	printf("pvsnd->buffer:0x%x\n", precv);
	printf("pvsnd->buffer:0x%x\n", _psend);*/

	int ret = _psend(pvsnd->buffer, pvsnd->size, precv->buffer, &precv->size, NULL);
	printf("%d %d\n", precv->size, ret);
	view_hexstr("precv", precv->buffer, precv->size);

	return 0;
}
void asfdaafdasf(){

	VAR_BYTES * pvsnd = create_var_bytes("0123456789", 10);
	VAR_BYTES * precv = alloc_var_bytes(32);
	int size = 32;



	int ret = _psend(pvsnd->buffer, pvsnd->size, precv->buffer, &precv->size, NULL);
	printf("%d %d\n", precv->size, ret);
	view_hexstr("precv", precv->buffer, precv->size);
}

G3_API_RESULT g3api_test7(const unsigned char * in, int in_size)
{
	api_view("g3api_test7");

	//VAR_BYTES * pvsnd = create_var_bytes("0123456789", 30);
	//VAR_BYTES * precv = alloc_var_bytes(32);
	//int size = 32;
	//int ret = 0;

	/*printf("pvsnd->buffer:0x%x\n", pvsnd);
	printf("pvsnd->buffer:0x%x\n", pvsnd);
	printf("pvsnd->buffer:0x%x\n", precv);
	printf("pvsnd->buffer:0x%x\n", _psend);*/
	asfdaafdasf();


	return 0;
}

G3_API_RESULT g3api_test6(const unsigned char * in, int in_size, PFSENDRECV pfsend)
{
	api_view("g3api_test6");

	_testbuff = create_var_bytes(in, in_size);

	VAR_BYTES * pvsnd = create_var_bytes("0123456789", 10);
	VAR_BYTES * precv = alloc_var_bytes(32);
	int size = 32;



	int ret = _psend(pvsnd->buffer, pvsnd->size, precv->buffer, &precv->size, NULL);
	printf("%d %d\n", precv->size, ret);
	view_hexstr("precv", precv->buffer, precv->size);

	return 0;
}

G3_API_RESULT g3api_test2(unsigned char * out, int* out_size)
{
	api_view("g3api_test2");
	printf("assign size :%d", *out_size);
	_testbuff = alloc_var_bytes(32);;
	if (_testbuff->size > *out_size){
		printf("assinge size is not enough\n");
		return -1;
	}

	memcpy(out, _testbuff->buffer, _testbuff->size);
	memcpy(out + _testbuff->size, _testbuff->buffer, _testbuff->size);
	*out_size = _testbuff->size * 2;




	return 0;
}

G3_API_RESULT g3api_test3(ST_ECC_PUBLIC* param)
{
	api_view("g3api_test3");
	printf("0x%x", param);
	unsigned char * pchar = (unsigned char *)param;
	for (int i = 0; i < sizeof(ST_ECC_PUBLIC); i++){
		*pchar = i % 255;
		pchar++;
	}
	return 0;
}


G3_API_RESULT g3api_test4(PFTEST pfsend)
{
	api_view("g3api_test4");




	//pfsend(23, 42);


	return 0;
}
G3_API_RESULT g3api_test5(PFSENDRECV pfsend)
{
	api_view("g3api_test5");


	VAR_BYTES * pvsnd = create_var_bytes("0123456789", 10);
	VAR_BYTES * precv = alloc_var_bytes(32);
	int size = 32;



	int ret = _psend(pvsnd->buffer, pvsnd->size, precv->buffer, &precv->size, NULL);
	printf("%d %d\n", precv->size, ret);
	view_hexstr("precv", precv->buffer, precv->size);
	return 0;
}
G3_API_RESULT GetSoftwareVersion(
	char* LCP_Version,
	char* FCP_Version
	)
{
	int return_status = 0;
	string LCP_V("test");
	string FCP_V("test");
	strcpy(LCP_Version, LCP_V.c_str());
	strcpy(FCP_Version, FCP_V.c_str());

	return return_status;
}



G3_API_RESULT g3api_test8(PFSENDRECV pfsend, const unsigned char * in, int in_size)
{
	api_view("g3api_test8");
	asfdaafdasf();
	return 0;
}

#endif // 0
