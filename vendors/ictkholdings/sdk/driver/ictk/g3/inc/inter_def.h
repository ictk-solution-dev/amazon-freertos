#ifndef __INTER_DEFINE_HEADER__
#define __INTER_DEFINE_HEADER__

#include "g3_define.h"


//typedef byte byte 


//START STRUCTURE
//END STRUCTURE
#pragma pack(push, 1)   
typedef struct _tagSECTOR{
	byte first_byte;
	byte second_byte;
	byte ac[6];
}SECTOR, *LPSECTOR;



typedef struct _tagHEADER_WRITE_PACKET{
	byte  inst_flag;
	byte  length;
	byte  ins;
	byte  p1;
	word  p2;
}HEADER_WRITE_PACKET, *LPHEADER_WRITE_PACKET;

typedef struct _tagWRITE_PACKET{
	HEADER_WRITE_PACKET header;
	byte data[2];//CRC 를 위해 2바이트 할
}WRITE_PACKET, *LPWRITE_PACKET;


// 신원석(neo1seok) 2018-05-10
typedef struct _tagHEADER_WRITE_PURE_PACKET{
	byte  ins;
	byte  p1;
	word  p2;
}HEADER_WRITE_PURE_PACKET, *LPHEADER_WRITE_PURE_PACKET;


typedef struct _tagWRITE_PURE_PACKET{
	HEADER_WRITE_PURE_PACKET header;
	byte data[2];//CRC 를 위해 2바이트 할
}WRITE_PURE_PACKET, *LPWRITE_PURE_PACKET;
// 신원석(neo1seok) 2018-05-10 : HEADER_WRITE_PURE_PACKET 추가


typedef struct _tagHEADER_WRITE_IEB100_PACKET{
	byte  rom_inst;
	dword  body_size_big_end;//dummy+res_size+rom_type+data_size
	dword  dummy;
	byte  res_size;
	//byte  rom_type;
}HEADER_WRITE_IEB100_PACKET, *LPHEADER_WRITE_IEB100_PACKET;

typedef struct _tagWRITE_IEB100_PACKET{
	HEADER_WRITE_IEB100_PACKET header;
	byte data[1];
}WRITE_IEB100_PACKET, *LPWRITE_IEB100_PACKET;

typedef struct _tagTLS_INTER_HEADER{
	dword  hi_be_sequence;
	dword  lo_be_sequence;
	byte content_type;
	word tls_be_ver;
	word msg_be_size;

}TLS_INTER_HEADER, *LPTLS_INTER_HEADER;


#pragma pack(pop)  







typedef LPVAR_BYTES(*PF_CONVERT)(void *pure_data, int data_size, int max_res_size);


#define	READ	0x80
#define	WRITE	0x81
#define	VERIFY_PWD	0x82
#define	CHANGE_PWD	0x83
#define	GET_CHAL	0x84
#define	INIT_PRIV_KEY	0x85
#define	SIGN	0x86
#define	VERIFY	0x87
#define	ENCRYPT	0x88
#define	DECRYPT	0x89
#define	SESSION	0x8A
#define	DIVERSIFY	0x8B
#define	GET_PUB_KEY	0x8C
#define	CERT	0x8D
#define	ISSUE_CERT	0x8E

#define	ECDH 0x90
#define	TLS_MAC_ENC	0x91
#define	TLS_DEC_VERIFY	0x92
#define	TLS_GET_HANDSHAKE_DIGEST 0x93
#define SHA256 0x94
#define SM3	   0x94

#define	RESET	0x9F


#define MAKEWORD(l_,h_)   ((word)(((byte)(l_))|(((word)((byte)(h_)))<<8)))
//#define MAKEWORD_BIG(l_,h_)   ((word)(((byte)(h_))|(((word)((byte)(l_)))<<8)))
#define KEY_VALUE_SIZE 32

#ifndef g3min
#define g3min(a,b)    (((a) < (b)) ? (a) : (b))
#endif

















































































































#endif //__INTER_DEFINE_HEADER__