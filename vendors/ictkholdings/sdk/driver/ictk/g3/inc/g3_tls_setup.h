/* Copyright Statement:
 *  2019 -09-10 
 *  ZN tehnologies 
 *  G3 related parameters will be stored 
 *  amazon info added to amazon group 
 * 
 * @file g3_tls_setup.h
 *
 */

#ifndef __G3_TLS_SETUP_H__
#define __G3_TLS_SETUP_H__

#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


#ifdef __cplusplus
}
#endif

#ifdef ICTK_TLS
void g3_cert_init();

#define G3_CLIENT_CERT_PRIVKEY_KEYSECTOR           114           //privkey sector (1), public key sector(2)
//#define G3_CLIENT_CERT_PRIVKEY_TYPE                0x02         //ec param secp256r1

#if G3_CLIENT_CERT_PRIVKEY_KEYSECTOR != 114
#error "G3_CLIENT_CERT_PRIVKEY_KEYSECTOR" must be 114
#endif


#endif

#endif

