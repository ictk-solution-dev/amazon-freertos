
#ifndef __G3_API_HEADER__
#define __G3_API_HEADER__

#include "g3_define.h"


//#define LIB_VERSION "1.0.0"
G3_API void g3api_set_fp(void *fp);
//START API

//###################################################	
/**
*   @brief  
*
*
*   @return const char *
*/
//###################################################
G3_API const char * CALLTYPE g3api_get_lib_version
(
);

	
//###################################################	
/**
*   @brief  Sets user send and receive function
*
*   @param psendrecv	: Pointer to send and receive function  
*   @param etcparam		: etcparam
*
*   @return void
*/
//###################################################
G3_API void CALLTYPE g3api_set_user_send_recv_pf
(
		IN PFSENDRECV psendrecv,
		IN void* etcparam
);

	
//###################################################	
/**
*   @brief  
*
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_get_device_version
(
);

	
//###################################################	
/**
*   @brief  
*
*
*   @return char*
*/
//###################################################
G3_API char* CALLTYPE g3api_get_sn
(
);

	
//###################################################	
/**
*   @brief Transmits raw data and receive response
*
*   @param snd			: Pointer to send data buffer
*   @param snd_size		: Size of send data
*   @param recv			: Pointer to receive data buffer
*   @param recv_size	: Size of receive data
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_raw_snd_recv
(
		IN const byte* snd ,
		IN int snd_size,
		OUT byte* recv,
		OUT int* recv_size
);



// 신원석(neo1seok) 2018-05-10
//###################################################	
/**
*   @brief	Transmits pure data and receive response
*
*   @param snd			: Pointer to send data buffer
*   @param snd_size		: Size of send data
*   @param recv			: Pointer to receive data buffer
*   @param recv_size	: Size of receive data
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_snd_recv_with_puredata
(
IN const byte* pure_snd,
IN int snd_size,
OUT byte* recv,
OUT int* recv_size
);

// 신원석(neo1seok) 2018-05-10 : HEADER_WRITE_PURE_PACKET 추가


	
//###################################################
/**
*   @brief  Read value from the setup area, key area and user data area
*
*   @param	key_index		: Key sector index ( p1 )
*   @param	area_type		: The type of area to read ( p2_lower )
*							  It can be one of the following values : 
*								@arg SETUP_AREA
*								@arg KEY_AREA
*								@arg DATA_AREA_0
*								@arg DATA_AREA_1
*   @param	rw_type			: Read operation mode(p2_upper) 
*							  It can be one of the following values : 
*								@arg PLAIN_TEXT																		- plain read
*								@arg CBC, CTR, SESSION_KEY_CBC, SESSION_KEY_CTR									    - encrypted read
*								@arg CBC_with_MAC, CTR_with_MAC, SESSION_KEY_CBC_with_MAC, SESSION_KEY_CTR_with_MAC - encrypted read with MAC
*								@arg MASKED																			- masked read
*   @param	data			: Input data only for masked operation(rw_type -> MASKED)
*   @param	data_size		: The size of the mask
*   @param	data_structure	: Read data.
*							  it can be one of the following structures : 
*								@arg ST_RW_DATA				: Data[32]						 - plain read, masked read
*								@arg ST_RW_DATA_WITH_IV		: Data[32] || IV[16]			 - encrypted read
*								@arg ST_RW_DATA_WITH_IV_MAC	: Data[32] || IV[16] || MAC[16]	 - encrypted read with MAC
*   @param	structure_size  : The size of data_structure
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_read_key_value
(
		IN int key_index,
		IN EN_AREA_TYPE area_type,
		IN EN_RW_INST_OPTION rw_type,
		IN const void* data,
		IN int data_size,
		OUT void* data_structure,
		OUT int structure_size
);

	
//###################################################	
/**
*   @brief  Writes value in setup area, key area and user data area. 
*
*   @param	key_index		: Key sector index. (p1)
*   @param	area_type		: The type of area to write. (p2_lower)
*						      It can be one of the following values : 
*								@arg SETUP_AREA
*								@arg KEY_AREA
*								@arg DATA_AREA_0
*								@arg DATA_AREA_1
*   @param	rw_type			: Write operation mode. (p2_upper) 
*							  It can be one of the following values :
*								@arg PLAIN_TEXT																		 - plain write
*								@arg CBC, CTR, SESSION_KEY_CBC, SESSION_KEY_CTR										 - encrypted write
*								@arg CBC_with_MAC, CTR_with_MAC, SESSION_KEY_CBC_with_MAC, SESSION_KEY_CTR_with_MAC  - encrypted write with MAC
*								@arg MASKED																			 - masked write
*   @param	data_structure	: Data to write.
*							  it can be one of the following structures :
*							    @arg ST_RW_DATA				: Data[32]						- plain write
*								@arg ST_RW_DATA_WITH_IV		: Data[32] || IV[16]			- encrypted write without MAC
*								@arg ST_RW_dATA_wITH_MASK	: Data[32] || MASK[32]		    - masked write
*								@arg ST_RW_DATA_WITH_IV_MAC	: Data[32] || IV[16] || MAC[16] - encrypted write with MAC
*   @param	structure_size	: The size of data_structure
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_write_key_value
(
		IN int key_index,
		IN EN_AREA_TYPE area_type,
		IN EN_RW_INST_OPTION rw_type,
		IN const void* data_structure,
		IN int structure_size
);

	
//###################################################	
/**
*   @brief  Generates challenge and loads it to temporary memory
*	@note	Whenever the generated challenge is used once for an authentication, the callenge becomes invalidated,
*			regardless of whether the authentication has been passed or not.
*
*   @param	chall_size		: The size of challenge to get
*   @param	challenge		: The buffer to put challenge 
*   @param	res_chall_size	: The size of challnge
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_get_challenge
(
		IN int chall_size,
		OUT byte* challenge,
		INOUT int* res_chall_size
);

	
//###################################################	
/**
*   @brief	Verifies the password of the target sector using input password key and obtain AC
*
*   @param key_index		: Key sector index(p1)
*   @param passwd			: Input password key
*   @param passwd_size		: The size of password key
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_verify_passwd
(
		IN int key_index,
		IN const byte* passwd,
		IN int passwd_size
);

	
//###################################################	
/**
*   @brief	Changes the password of the target sector to input password key
*
*   @param key_index		: Key sector index(p1)
*   @param passwd			: Input password key
*   @param passwd_size		: The size of password key
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_change_password
(
		IN int key_index,
		IN const byte* passwd,
		IN int passwd_size
);

	
//###################################################	
/**
*   @brief  Writes the revision value to the target sector, the target sector should be an ECC PUF
*
*   @param key_index		: Key sector index(p1)
*   @param initial			: The revision value (4 bytes)
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_init_puf
(
		IN int key_index,
		IN unsigned int initial
);

	
//###################################################	
/**
*   @brief  Generates a signature using input data and target key.
*	@note	The signature algorithm is determined as the target key type.
*
*   @param key_index		: Key sector index. (p1)
*   @param sign_option		: Signature algorithm.(p2)
*							  It can be one of the following values :
*								@arg SIGN_ECDSA_EXT_SHA256,SIGN_ECDSA_WITH_SHA256 - The target key type must be ECC_PUF or ECC_PRV
*								@arg SIGN_HMAC									  - The target key type must be SHA256
*								@arg SIGN_SYMM, SIGN_SESSION_SYMM				  - The target key type must be AES128 or SM4
*   @param msg				: Input data to be used for generating a signature
*   @param msg_size			: The size of msg
*   @param sign_structure	: Command outputs.
*							  It can be one of the following structures :
*								@arg ST_SIGN_ECDSA	: r[32] || s[32]
*								@arg ST_SIGN_SYMM	: sign[16]
*								@arg ST_SIGN_HMAC	: sign[32]
*   @param structure_size	: The size of sign_structure

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_sign
(
		IN int key_index,
		IN EN_SIGN_OPTION sign_option,
		IN const byte* msg,
		IN int msg_size,
		OUT void * sign_structure,
		IN int structure_size
);

	
//###################################################	
/**
*   @brief  Verifies the signature. 
*	@note	The target sector should be a public key or symmetric key
*			To obtain AC, use the dynamic_auth.
*
*   @param key_index		: Key sector index(p1)
*   @param verify_option	: The option of command(p2)
*							  It can be one of the following values : 
*								@arg VERYFY_ECDSA_EXT_SHA256,VERYFY_ECDSA_WITH_SHA256,VERYFY_HMAC,VERYFY_SYMM,VERIFY_SESSION_SYMM,
*									 VERYFY_EXT_PUB_ECDSA_EXT_SHA256,VERYFY_EXT_PUB_ECDSA_WITH_SHA256
*   @param msg				: Input data, it contains data and signature
*   @param msg_size			: The size of input data
*   @param sign_structure	: Command outputs.
*							  It can be one of the following structures :
*								@arg ST_SIGN_ECDSA : r[32] || s[32]
*								@arg ST_SIGN_SYMM  : sign[16]
*								@arg ST_SIGN_HMAC  : sign[32]
*   @param structure_size	: The size of sign_structure
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_verify
(
		IN int key_index,
		IN EN_VERIFY_OPTION verify_option,
		IN const byte* msg,
		IN int msg_size,
		IN const void* sign_structure,
		IN int structure_size
);

	
//###################################################	
/**
*   @brief  Verifies the signature and obtain AC. 
*	@note	Input signature must be generated using challenge that generated in G3
*		
*   @param key_index		: Key sector index(p1)
*   @param dauth_option		: The mode of the command(p2_lower)
*							  It can be one of the following values :
*								@arg DYN_AUTH_ECDSA_SHA256, DYN_AUTH_HMAC, DYN_AUTH_SYMM, DYN_AUTH_CERT_PUB_ECDSA_SHA256
*   @param pos_pub_dynamic	: A random position(p2_upper)
*   @param msg				: Input data, it contains data and signature
*   @param msg_size			: The size of input data 
*   @param sign_structure	: Command outputs.
*							  It can be one of the following structures :
*								@arg ST_SIGN_ECDSA : r[32] || s[32]
*								@arg ST_SIGN_SYMM  : sign[16]
*								@arg ST_SIGN_HMAC  : sign[32]
*   @param structure_size	: The size of sign_sturucture
*
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_dynamic_auth
(
		IN int key_index,
		IN EN_DYNAMIC_AUTH dauth_option,
		IN int pos_pub_dynamic,
		IN const byte* msg,
		IN int msg_size,
		IN const void* sign_structure,
		IN int structure_size
);

	
//###################################################	
/**
*   @brief  Encrypts a given plain data using target key.
*
*   @param key_index		: Key sector index(p1)
*   @param key_type			: The key type of the target key(p2_upper)
*								@arg SECTOR_KEY
*								@arg SESSION_KEY
*   @param block_mode		: The block cipher operation mode(p2_lower)
*								@arg BL_CBC
*								@arg BL_CTR
*   @param iv				: Initial vector 
*   @param data				: The plain data to be encrypted
*   @param data_size		: The size of plain data
*   @param cipher			: Output from the command, cipher data
*   @param cipher_size		: The size of cipher data

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_encryption
(
		IN int key_index,
		IN EN_KEY_TYPE key_type,
		IN EN_BLOCK_MODE block_mode,
		IN const ST_IV * iv,
		IN const byte* data,
		IN int data_size,
		OUT byte* cipher,
		INOUT int* cipher_size
);

	
//###################################################	
/**
*   @brief  Decrypts a given cipher data using target key
*
*   @param key_index		: Key sector index(p1)
*   @param key_type			: The key type of the target key(p2_upper)
*								@arg SECTOR_KEY
*								@arg SESSION_KEY
*   @param block_mode		: The block cipher operation mode(p2_lower)
*								@arg BL_CBC
*								@arg BL_CTR
*   @param iv				: Initial vector
*   @param cipher			: The cipher data to be decrypted
*   @param cipher_size		: The size of cipher data
*   @param data				: Output from the command, plain data
*   @param data_size		: The size of plain data

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_decryption
(
		IN int key_index,
		IN EN_KEY_TYPE key_type,
		IN EN_BLOCK_MODE block_mode,
		IN const ST_IV* iv,
		IN const byte* cipher,
		IN int cipher_size,
		OUT byte* data,
		INOUT int* data_size
);

	
//###################################################	
/**
*   @brief  Encrypts a given plain data with ECIES. The target key must be a public key
*
*   @param key_index		: Key sector index(p1)
*   @param rs				: R (R=rG, r:random) - ECC private key, S=x of (rKB=kBR), r: random, KB : public key of B, kB : private key of B)

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_encryption_ecies
(
		IN int key_index,
		OUT ST_ECIES* rs
);

	
//###################################################	
/**
*   @brief  Decrypt a given cipher data with ECIES. The target key must be a private key
*
*   @param key_index		: Key sector index(p1)
*   @param rs				: R (R=rG, r:random) - ECC private key, S=x of (rKB=kBR), r: random, KB : public key of B, kB : private key of B)

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_decryption_ecies
(
		IN int key_index,
		INOUT ST_ECIES* rs
);

	
//###################################################	
/**
*   @brief  Generates sessions and loads the session key to temporary memory.
*
*   @param key_index		: Key sector index(p1)
*   @param en_session_mode	: Session operation mode(p2)
*							  It can be one of the following values :
*								@arg SYMM_KEY, FACTORY_AES, FACTORY_SM4, EXT_SESSION_KEY_AES, EXT_SESSION_KEY_SM4, EXT_PUB_KEY
*   @param indata			: The parameter to be used for making a session key
*								@arg SYMM_KEY					:	Sesssion_b[16]
*								@arg FACTORY_AES/SM4			:	Index[2] || Session_b[16]
*								@arg EXT_SESSION_KEY_AES/SM4	:	Session_key[16]
*								@arg EXT_PUB_KEY				:	ECC public key[64or33]
*   @param indata_size		: The size of input data
*   @param outdata			: Output from the command
*								@arg SYMM_KEY					:	Session_chip[16] || encrypt(0(zero),session_key)[16]
*								@arg FACTORY_AES/SM4			:	Encrypt(0(zero),session_key)[16]
*								@arg EXT_SESSION_KEY_AES/SM4	:	Encrypt(0(zero),session_key)[16]
*								@arg EXT_PUB_KEY				:	SHA256(Input_data)
*   @param outdata_size		: The size of output

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_session
(
		IN int key_index,
		IN EN_SESSION_MODE en_session_mode,
		IN const byte* indata,
		IN int indata_size,
		OUT byte* outdata,
		INOUT int* outdata_size
);

	
//###################################################	
/**
*   @brief  Loads input public key to temporary memory
*
*   @param pub_key			: Public key to load, enable 2 follow structure ST_ECC_PUBLIC and ST_ECC_PUBLIC_COMPRESS
*   @param structure_size	: The size of the public key
*   @param puk_hash			: Output from the command, hashed data

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_set_extern_public_key
(
		IN const void* pub_key,
		IN int structure_size,
		OUT ST_DATA_32* puk_hash
);

	
//###################################################	
/**
*   @brief  Diversifies a symmetric key by using diversify AC. 
*	@note	It can be executed in two mode : self mode and inherit mode
*			If rw_operation bits of the target key setting is 11, diversify command requires a MAC
*
*   @param key_index		: Key sector index(p1)
*   @param diversify_mode	: The mode of diversify(p2)
*							  It can be one of the following values :
*								@arg INHERIT_MODE
*								@arg SELF_MODE
*   @param data				: The parameter to be used for diversifying
*   @param data_size		: The size of data

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_diversify
(
		IN int key_index,
		IN EN_DIVERSIFY_MODE diversify_mode,
		IN const byte* data,
		IN int data_size
);

	
//###################################################	
/**
*   @brief  Outputs a public key in a compress form(33bytes) or X,Y coordinate form(64 bytes)
*
*   @param key_index		: Key sector index(p1)
*   @param pub_type			: The type of public key
*							  It can be one of the following values :
*								@arg KEY_SECTOR
*								@arg TEMP_PUBLIC_KEY
*   @param pub_key			: The buffer to put the public key.
*							  It can be one of the following values :
*								@arg ST_ECC_PUBLIC			:	puk[64]
*								@arg ST_ECC_PUBLIC_COMPRESS	:	puk[33]
*   @param structure_size	: The size of buffer

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_get_public_key
(
		IN int key_index,
		IN EN_PUB_TYPE pub_type,
		OUT void* pub_key,
		IN int structure_size
);

	
//###################################################	
/**
*   @brief  Verifies a certificate, and then update a public key or store it in public key of temporary memory
*			The session can be generated by the public key of temporary memory
*
*   @param key_index				: Key sector index(p1)
*   @param certification_write_mode : The mode of certificate write
*									  It can be one of the following values :
*										@arg TO_TEMP
*										@arg TO_KEY_SECTOR
*   @param cert						: Input a certificate to verify
*   @param cert_size				: The size of certificate

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_certification
(
		IN int key_index,
		IN EN_CERTIFICATION_WRITE_MODE certification_write_mode,
		IN const byte* cert,
		IN int cert_size
);

	
//###################################################	
/**
*   @brief  Issues a certificate and store it. Add the pair public key of private key in target sector to certificate
*			The length of the certificate cannot exceed 1024 bytes.
*
*   @param key_index			: Key sector index(p1)
*   @param public_key_pos		: The public key position
*   @param issue_cert_area_type	: The area type of the sector to store the issued certificate
*								  It can be one of the following values :
*									@arg ISCRT_KEY_AREA
*									@arg ISCRT_DATA_AREA_0
*									@arg ISCRT_DATA_AREA_1
*   @param sector_num_to_store  : The sector number to store the issued certificate
*   @param key_id				: Factory key ID or the sector number of private key
*   @param encrypted_key		: When using key_id as a factory key id, encrypted_key must be given
*   @param cert					: Input TBS certificate
*   @param cert_size			: The size of tbs certificate

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_issue_certification
(
		IN int key_index,
		IN int public_key_pos,
		IN EN_ISSUE_CERT_AREA_TYPE issue_cert_area_type,
		IN int sector_num_to_store,
		IN int key_id,
		IN const ST_DATA_32* encrypted_key,
		IN const byte* cert,
		IN int cert_size
);

	
//###################################################	
/**
*   @brief  Used for session key agreement. 
*
*   @param en_ecdh_mode				: The mode of ECDH instruction
*									  It can be one of the following values :
*										@arg NORMAL_ECDH, GEN_TLS_BLOCK, SET_TLS_SESSION_KEY
*   @param Q_b						: The type of public key
*									  It can be one of the following values :
*										@arg ST_ECC_PUBLIC			:	puk[64]
*										@arg ST_ECC_PUBLIC_COMPRESS	:	puk[33]
*   @param Q_b_struct_size			: The size of public key
*   @param st_ecdh_random			: ServerHello.random[32] || ClientHello.random[32] 
*   @param Q_chip					: Command outputs, public key chip(dchipG)[64]
*   @param ecdh_value				: Command outputs.
*									  It depends on the ECDH mode and can be one of the following values :
*										@arg NORMAL_ECDH			: pre_master_secret[32]
*										@arg GEN_TLS_BLOCK			: TLS_key_block[128]
*										@arg SET_TLS_SESSION_KEY	: client_write_IV[16] || server_write_IV[16] 
*   @param ecdh_value_struct_size	: The size of ecdh_value 

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_ecdh
(
		IN EN_ECDH_MODE en_ecdh_mode,
		IN const void* Q_b,
		IN int Q_b_struct_size,
		IN const ST_ECDH_RANDOM* st_ecdh_random,
		OUT ST_ECC_PUBLIC* Q_chip,
		OUT void* ecdh_value,
		OUT int ecdh_value_struct_size
);

	
//###################################################	
/**
*   @brief  Generate tls header without size
*
*   @param seq_num							: The TLS sequence low 4 byte
*   @param content_type						: The content type[1]
*   @param tls_version						: The TLS version[2]
*   @param tls_inter_header_without_size	: The structure to contain the TLS header without size
*												@arg ST_TLS_INTER_HEADER_WITHOUT_SIZE : TLS Sequence Num[8] || TLS type[1] || TLS Version[2]
*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_make_tls_inter_header_without_size
(
		IN int seq_num,
		IN EN_CONTENT_TYPE content_type,
		IN EN_TLS_VERSION tls_version,
		OUT ST_TLS_INTER_HEADER_WITHOUT_SIZE* tls_inter_header_without_size
);

	
//###################################################	
/**
*   @brief  Generates an encrypted TLS record using the TLS session key block stored in temporary memory
*
*   @param tls_inter_header_without_size	: TLS_HEADER : TLS Sequence Num[8] || TLS type[1] || TLS Version[2] 
*   @param client_iv						: Client_Write_IV[16]
*   @param header_random					: The first input data must contain 16 bytes of random IV to prevent attacks
*   @param msg								: The plain text
*   @param msg_size							: The size of the plain text
*   @param crypto							: The cipher text
*   @param crypto_size						: The size of the cipher text

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_tls_mac_encrypt
(
		IN const ST_TLS_INTER_HEADER_WITHOUT_SIZE* tls_inter_header_without_size,
		IN const ST_IV* client_iv,
		IN const ST_DATA_16* header_random,
		IN const byte* msg,
		IN int msg_size,
		OUT byte* crypto,
		INOUT int * crypto_size
);

	
//###################################################	
/**
*   @brief  Generate a decrypted TLS fragment from an input encrypted TLS record using the TLS session key block stored in temporary memory
*
*   @param tls_inter_header_without_size	: TLS_HEADER : TLS Sequence Num[8] || TLS type[1] || TLS Version[2] 
*   @param server_iv						: Server_Write_IV[16]
*   @param crypto							: The cipher text
*   @param crypto_size						: The size of the cipher text
*   @param header_random					: The first output data must contain 16 bytes of random IV to prevent attacks
*   @param msg								: The plain text
*   @param msg_size							: The size of the plain text

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_tls_decrypt_verify
(
		IN const ST_TLS_INTER_HEADER_WITHOUT_SIZE* tls_inter_header_without_size,
		IN const ST_IV* server_iv,
		IN const byte* crypto,
		IN int crypto_size,
		OUT ST_DATA_16* header_random,
		OUT byte* msg,
		INOUT int* msg_size
);

	
//###################################################	
/**
*   @brief  Used for finishing the TLS session key agreement
*
*   @param handshake_mode		: The mode of handshake instruction
*   @param hash_handshake_msg	: The data to be used for handshaking
*   @param handshake_digest		: The handshake digest

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_tls_get_handshake_digest
(
		IN EN_HANDSHAKE_MODE handshake_mode,
		IN const ST_DATA_32* hash_handshake_msg,
		OUT ST_TLS_HAND_HANDSHAKE_DIGEST* handshake_digest
);


//###################################################	
/**
*   @brief  For SHA256 calculation. Sha256 command is executed in three steps : initialization, update and finalization
*	
*	@param sha256_mode	: The step of SHA256 command
*   @param data			: The data to be subjected to the sha256 operation
*   @param data_size	: The size of input data
*   @param outdata		: Outputs from the command, hashed data

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_sha256
(
		IN EN_SHA256_MODE sha256_mode,
		IN const byte* data,
		IN int data_size,
		OUT ST_DATA_32* outdata
);


//###################################################	
/**
*   @brief  Reset the G3, and then initialize authentication results and a session
*

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_reset
(
);

	
//###################################################	
/**
*   @brief  
*
*   @param in 
*   @param in_size 

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_test
(
		IN PFTEST in,
		IN int in_size
);

	
//###################################################	
/**
*   @brief  
*
*   @param test 
*   @param out_size 

*   @return G3_API_RESULT
*/
//###################################################
G3_API G3_API_RESULT CALLTYPE g3api_test2
(
		IN char* test,
		IN int* out_size
);

	//END API

/**
*   @brief  Swaps the values of two integer parameters.
*
*   @param  a is an initialized integer variable
*   @param  b is an initialized integer variable
*   @return void
*/
G3_API int GetSoftwareVersion(
	char* LCP_Version,
	char* FCP_Version
	);





#endif //__G3_API_HEADER__






