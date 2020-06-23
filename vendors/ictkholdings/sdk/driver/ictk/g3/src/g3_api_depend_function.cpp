#include <g3_api.h>
#include "inter_def.h"
#include <stdlib.h>
//#include <memory.h>
#include <stdio.h>
#include <map>
//#include "neoCoLib.h"
using namespace std;


unsigned long calcCRC(unsigned char* data, int iLength);
void SwapBytes(void* value, int size);
//VAR_BYTES * convert_data_ieb100(void *pure_data, int data_size);
VAR_BYTES * convert_data(void *pure_data, int data_size);
//extern PF_CONVERT _pconvert_data;
extern PFSENDRECV _psend;
extern void * _etcparam;
extern FILE * _fp;
void test()
{
	/*VECBYTE vecbyte = NCL::HexStr2Byte("2323");
	fprintf(_fp,"vecbyte :%d ",vecbyte.size() );*/

}

VAR_BYTES* alloc_var_bytes(int size)
{
	VAR_BYTES*ret = (VAR_BYTES*)malloc(8 + size);
	ret->allocsize = size;
	ret->size = size;
	memset(ret->buffer,0, size);
	return ret;
}

VAR_BYTES* create_var_bytes(const void*init,int size)
{
	VAR_BYTES*ret = alloc_var_bytes(size);
	if (init) memcpy(ret->buffer, init, size);
	return ret;
}

bool append_var_bytes(VAR_BYTES**dist ,const void*buffer, int size)
{
	if (!dist || !buffer) return false;
	VAR_BYTES*ret = *dist;
	int oldsize = ret->size;
	VAR_BYTES* newret = (VAR_BYTES*)realloc(ret, 8+oldsize + size);
	
	//free(ret);
	newret->size = oldsize+size;
	memcpy(newret->buffer + oldsize, buffer, size);
	*dist = newret;

	return true;
	
}



void api_view(const char *title)
{
#if 0
	fprintf(_fp,"\n#######################\n%s\n#######################\n", title);
#endif
}
void view_hexstr(const char *title,const void *pbuff, int size)
{
#if 0
	fprintf(_fp,"%s:\n", title);
	unsigned char *pbyte = (unsigned char *)pbuff;
	for (int i = 0; i < size; i++){
		fprintf(_fp,"%.2X", *pbyte);
		pbyte++;
	}
	fprintf(_fp,"\n");
#endif
}
LPWRITE_PACKET make_write_packet(char inst, char p1, short p2, const void * data, int data_size, int *packet_size)
{
	//sizeof(WRITE_PACKET) is included crc
	int total_write_packet_size = sizeof(WRITE_PACKET) + data_size;//included crc
	int total_write_packet_size_without_crc = sizeof(HEADER_WRITE_PACKET)-1 + data_size;//included crc

	LPWRITE_PACKET lp_write_packet = (LPWRITE_PACKET)malloc(total_write_packet_size);
	memset(lp_write_packet, 0x00, total_write_packet_size);
	lp_write_packet->header.ins = inst;
	lp_write_packet->header.p1 = p1;
	SwapBytes(&p2, 2);
	lp_write_packet->header.p2 = p2;
	lp_write_packet->header.length = total_write_packet_size_without_crc+2;
	lp_write_packet->header.inst_flag = 0x03;
	if (data_size > 0) memcpy(lp_write_packet->data, data, data_size);

	unsigned long crc = calcCRC((unsigned char*)lp_write_packet+1, total_write_packet_size_without_crc);
	memcpy(&lp_write_packet->data[data_size], &crc, 2);

	//fprintf(_fp,"0x%x 0x%x 0x%x \n", crc, lp_write_packet->data[total_write_packet_size_without_crc], lp_write_packet->data[total_write_packet_size_without_crc + 1]);
	//fprintf(_fp,"total_write_packet_size:%d \ntotal_write_packet_size_without_crc:%d\n", total_write_packet_size, total_write_packet_size_without_crc);
	if (packet_size) *packet_size = total_write_packet_size;
	return lp_write_packet;
}

#if 0
VAR_BYTES * convert_data(void *pure_data, int data_size,  int max_res_size){
	VAR_BYTES * pret = alloc_var_bytes(data_size);

	memcpy(pret->buffer, pure_data, data_size);
	return pret;
}

LPWRITE_IEB100_PACKET make_write_ieb100_packet(char rom_inst, char res_size, const void * data, int data_size, int *packet_size){

	//sizeof(WRITE_PACKET) is included crc
int total_write_packet_size = sizeof(HEADER_WRITE_IEB100_PACKET) + data_size + 1;//included crc
int body_size_big_end = 4 + 1 + 1 + data_size;//dummy+res_size+rom_type+data


LPWRITE_IEB100_PACKET lp_write_packet = (LPWRITE_IEB100_PACKET)malloc(total_write_packet_size);
memset(lp_write_packet, 0x00, total_write_packet_size);
lp_write_packet->header.rom_inst = rom_inst;
lp_write_packet->header.body_size_big_end = body_size_big_end;
//	lp_write_packet->header.rom_type = rom_type;
SwapBytes(&lp_write_packet->header.body_size_big_end, 4);
lp_write_packet->header.res_size = res_size;

if (data_size > 0) memcpy(lp_write_packet->data, data, data_size);
if (packet_size) *packet_size = total_write_packet_size;

//fprintf(_fp,"total_write_packet_size:%d \body_size_big_end:%d\n", total_write_packet_size, body_size_big_end);

return lp_write_packet;
}


VAR_BYTES * convert_data_ieb100(void *pure_data, int data_size, int max_res_size)
{
	int packet_ieb100_size = 0;
	//map<int, int> map_size_per_inst = get_map_size();
	LPHEADER_WRITE_PACKET lpheader = (LPHEADER_WRITE_PACKET)pure_data;

	int size = max_res_size;
	if (size == 0){
		size = 0xf0;
	}

	LPWRITE_IEB100_PACKET lpwrite_ieb100_packet = make_write_ieb100_packet(0x7, size, pure_data, data_size, &packet_ieb100_size);
	VAR_BYTES * pret = alloc_var_bytes(packet_ieb100_size);
	memcpy(pret->buffer, lpwrite_ieb100_packet, packet_ieb100_size);
	free(lpwrite_ieb100_packet);
	return pret;
}
#endif

map<int, int> & get_map_size(){
	static map<int, int> _map_size_per_inst;
	static bool is_load = false;
	if (!is_load){
		_map_size_per_inst[READ] = 67;
		_map_size_per_inst[WRITE] = 4;
		_map_size_per_inst[VERIFY_PWD] = 5;
		_map_size_per_inst[CHANGE_PWD] = 4;
		_map_size_per_inst[GET_CHAL] = 35;
		_map_size_per_inst[INIT_PRIV_KEY] = 4;
		_map_size_per_inst[SIGN] = 67;
		_map_size_per_inst[VERIFY] = 4;
		_map_size_per_inst[ENCRYPT] = 0xf3;
		_map_size_per_inst[DECRYPT] = 0xf3;
		_map_size_per_inst[SESSION] = 0x90;
		_map_size_per_inst[DIVERSIFY] = 4;
		_map_size_per_inst[GET_PUB_KEY] = 67;
		_map_size_per_inst[CERT] = 4;
		_map_size_per_inst[ISSUE_CERT] = 4;
		_map_size_per_inst[RESET] = 4;
		is_load = true;
	}



	return _map_size_per_inst;
}


int return_from_recv(VAR_BYTES *precvbuff)
{
	int nret = precvbuff->buffer[0];
	//if (precvbuff->size == 4){
	//	int err_ret = 0;
	//	memcpy(&err_ret, precvbuff->buffer, 4);
	//	SwapBytes(&err_ret, 4);
	//	return  ERR_INTERCHIP | err_ret;

	//}
	if (precvbuff->size == 1){
		return precvbuff->buffer[0];
	}
	return 0;

}

G3_API_RESULT do_normal_process(char inst, char p1, short p2, const void * data, int data_size, VAR_BYTES ** recv_buff)
{
	int packet_size = 0;
	int packet_ieb100_size = 0;
	G3_API_RESULT nRet = 0;
	unsigned short crc = 0;
	unsigned long calc_crc = 0;
	//if (recv_buff) {
	//	*recv_buff = NULL;

	//	//memcpy(precvbuff->buffer, &buff[1], recv_size - 3);
	//}

	map<int, int> map_size_per_inst = get_map_size();

	int max_res_size = map_size_per_inst[(unsigned char)inst];
	if (max_res_size == 0){
		max_res_size = 243;
	}

	LPWRITE_PACKET lp_write_packet = make_write_packet(inst, p1, p2, data, data_size, &packet_size);
	//VAR_BYTES *psend_buff = _pconvert_data(lp_write_packet, packet_size, max_res_size);
	view_hexstr("pure packet", lp_write_packet, packet_size);
	
	unsigned char buff[255] = { 0, };
	int recv_size = max_res_size;
#if 0	//deleted by hupark
	fprintf(_fp,"_psend: 0x%x\n", _psend);
#endif
	nRet = _psend((unsigned char *)lp_write_packet, packet_size, buff, &recv_size, _etcparam);

	view_hexstr("recv data", buff, recv_size);
	if (nRet != RET_SUCCESS)
	{
		nRet = RET_ERR_INTERCHIP_COMMUNICATIONS_ERROR;
		goto END;
	}

	view_hexstr("recv data", buff, recv_size);

	recv_size = buff[0];

	//if (*real_recv_size +3< recv_size) {
	//	nRet = ERR_RECV_BUFF_SIZE;
	//	goto END;
	//}

	calc_crc = calcCRC(buff, recv_size - 2);
	
	memcpy(&crc, buff + recv_size - 2, 2);
	
	//view_hexstr("precvbuff", buff, recv_size);
	//view_hexstr("realbuff", buff, recv_size - 2);

	//fprintf(_fp,"crc:0x%.4x calc_crc:0x%.4x\n", crc, calc_crc);
	if (crc != calc_crc){
		nRet = RET_ERR_RECV_CRC_ERROR;
		//free(precvbuff);
		//if (real_recv_size) *real_recv_size = 0;
		goto END;

	}


	if (recv_size-3 == 1 || recv_size-3 == 2){
		nRet =  buff[1];
		nRet |= (nRet == 0 || nRet == 1) ? 0 : ERR_INTERCHIP;
		goto END;
	}


	

	if (recv_buff) {
		if (*recv_buff == NULL){
			*recv_buff = alloc_var_bytes( 0);
		}
		append_var_bytes(recv_buff, &buff[1], recv_size - 3);

		//VAR_BYTES *precvbuff = alloc_var_bytes(recv_size - 3);
		//*recv_buff = precvbuff;
		//
		//memcpy(precvbuff->buffer, &buff[1], recv_size - 3);
	}
	//if (real_recv_size) *real_recv_size = recv_size - 3;


END:
	//send_receiv_packet(lpwrite_ieb100_packet, packet_ieb100_size);
	//if (psend_buff) free(psend_buff);
	if (lp_write_packet) free(lp_write_packet);


	return nRet;



}

G3_API_RESULT do_normal_process_return_ok(char inst, char p1, short p2, const void * data, int data_size)
{	
	G3_API_RESULT recv_ret = 0;
	int recv_ret_size = 4;
	VAR_BYTES *precvbuff = NULL;
	return do_normal_process(inst, p1, p2, data, data_size, NULL);
#if 0
	int nret = do_normal_process(inst, p1, p2, data, data_size, NULL);
	if (nret < 0) return nret;

	nret = return_from_recv(precvbuff);
	nret = precvbuff->buffer[0];
	if (precvbuff->size == 4){
		int err_ret = 0;
		memcpy(&err_ret , precvbuff->buffer, 4);
		SwapBytes(&err_ret, 4);
		recv_ret = ERR_INTERCHIP | err_ret;
		goto END;
		
	}
		
END:

	if (precvbuff) free(precvbuff);

	return recv_ret;
#endif

}
int check_sign_struct(EN_SIGN_OPTION sign_option, int structure_size)
{
	switch (sign_option)
	{
	case SIGN_ECDSA_EXT_SHA256:
	case SIGN_ECDSA_WITH_SHA256:
		if (structure_size != sizeof(ST_SIGN_ECDSA)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;
	case SIGN_HMAC:
		if (structure_size != sizeof(ST_SIGN_HMAC)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;
	case SIGN_SYMM:
	case SIGN_SESSION_SYMM:
		if (structure_size != sizeof(ST_SIGN_SYMM)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;
	default:
		return RET_ERR_SIGN_MODE_PARSE_ERR;
		break;
	}

	return 0;
}

int check_vefify_struct(EN_VERIFY_OPTION verify_option, int structure_size)
{
	switch (verify_option)
	{
	case VERIFY_ECDSA_EXT_SHA256:
	case VERIFY_ECDSA_WITH_SHA256:
	case VERIFY_EXT_PUB_ECDSA_EXT_SHA256:
	case VERIFY_EXT_PUB_ECDSA_WITH_SHA256:
		if (structure_size != sizeof(ST_SIGN_ECDSA)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}

		break;
	case VERIFY_HMAC:
		if (structure_size != sizeof(ST_SIGN_HMAC)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;
	case VERIFY_SYMM:
	case VERIFY_SESSION_SYMM:
		if (structure_size != sizeof(ST_SIGN_SYMM)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;
		break;
	default:
		return RET_ERR_SIGN_MODE_PARSE_ERR;
		break;
	}

	return 0;
}


int check_dynamic_auth_struct(EN_DYNAMIC_AUTH verify_etc, int structure_size)
{
	switch (verify_etc)
	{
	case DYN_AUTH_ECDSA_SHA256:
	case DYN_AUTH_CERT_PUB_ECDSA_SHA256:
		if (structure_size != sizeof(ST_SIGN_ECDSA)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;
		break;
	case DYN_AUTH_HMAC:
		if (structure_size != sizeof(ST_SIGN_HMAC)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;
	case DYN_AUTH_SYMM:
		if (structure_size != sizeof(ST_SIGN_SYMM)){
			return RET_ERR_SIGN_MODE_PARSE_ERR;
		}
		break;

	default:
		return RET_ERR_SIGN_MODE_PARSE_ERR;
	}


	
	
	return 0;
}
