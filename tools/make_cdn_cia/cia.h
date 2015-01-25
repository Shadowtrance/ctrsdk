/*
 * Copyright 2013 3DSGuy
 * Copyright 2015 173210
 *
 * This file is part of make_cdn_cia.
 *
 * make_cdn_cia is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * make_cdn_cia is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with make_cdn_cia.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>

#if __BYTE_ORDER__ ==  __ORDER_BIG_ENDIAN__ || BYTE_ORDER == BIG_ENDIAN
#define htoctr16
#define ctr16toh
#define htoctr32
#define ctr32toh
#define htoctr64
#define ctr64toh
#elif __GNUC__ >= 4 && __GNUC_MINOR__ >= 4
#if __GNUC_MINOR__ >= 8 || (defined(__powerpc__) && __GNUC_MINOR__ >= 6)
#define htoctr16 __builtin_bswap16
#define ctr16toh __builtin_bswap16
#endif
#define htoctr32 __builtin_bswap32
#define ctr32toh __builtin_bswap32
#define htoctr64 __builtin_bswap64
#define ctr64toh __builtin_bswap64
#elif __GNUC__ >= 5
#define htoctr16 __builtin_bswap16
#define ctr16toh __builtin_bswap16
#define htoctr32 __builtin_bswap32
#define ctr32toh __builtin_bswap32
#define htoctr64 __builtin_bswap64
#define ctr64toh __builtin_bswap64
#elif defined(__INTEL_COMPILER)
#define htoctr16(v) ((uint16_t)_bswap16((__int16)(v)))
#define ctr16toh(v) ((uint16_t)_bswap16((__int16)(v)))
#define htoctr32(v) ((uint32_t)_bswap((int)(v)))
#define ctr32toh(v) ((uint32_t)_bswap((int)(v)))
#define htoctr64(v) ((uint64_t)_bswap64((__int64)(v)))
#define ctr64toh(v) ((uint64_t)_bswap64((__int64)(v)))
#elif _MSC_VER >= 1400
#define htoctr16(v) ((uint16_t)_byteswap_ushort((unsigned short)(v)))
#define ctr16toh(v) ((uint16_t)_byteswap_ushort((unsigned short)(v)))
#define htoctr32(v) ((uint32_t)_byteswap_ulong((unsigned long)(v)))
#define ctr32toh(v) ((uint32_t)_byteswap_ulong((unsigned long)(v)))
#define htoctr64(v) ((uint64_t)_byteswap_uint64((unsigned __int64)(v)))
#define ctr64toh(v) ((uint64_t)_byteswap_uint64((unsigned __int64)(v)))
#endif

enum {
	SIGTYPE_RSA4096_SHA1 = 0x10000,
	SIGTYPE_RSA2048_SHA1 = 0x10001,
	SIGTYPE_ECDSA_SHA1 = 0x10002,
	SIGTYPE_RSA4096_SHA256 = 0x10003,
	SIGTYPE_RSA2048_SHA256 = 0x10004,
	SIGTYPE_ECDSA_SHA256 = 0x10005
};

typedef struct
{
	uint32_t offset;
	uint32_t size;
} cert_t;

typedef struct
{
	uint8_t padding_0[60];
	uint8_t issuer[64];
	uint8_t version;
	uint8_t ca_crl_version;
	uint8_t signer_crl_version;
	uint8_t padding_1;
} TMD_SIG_STRUCT;

typedef struct
{
	uint32_t content_id;
	uint16_t content_index;
	uint16_t content_type;
	uint64_t size;
	uint8_t sha_256_hash[0x20];
} TMD_CONTENT;

typedef struct
{
	TMD_SIG_STRUCT tmd_sig;
	uint64_t system_version;
	uint64_t title_id;
	uint32_t title_type;
	uint8_t reserved[64];
	uint32_t access_rights;
	uint16_t title_version;
	uint16_t content_count;
	uint16_t boot_content;
	uint8_t padding[2];
	uint8_t sha_256_hash[32];
	uint8_t content_info_records[2304];
} TMD_STRUCT;

typedef struct
{
	uint8_t padding_0[60];
	uint8_t issuer[64];
	uint8_t ECDH[60];
	uint8_t unknown[3];
} TIK_SIG_STRUCT;

typedef struct
{
	TIK_SIG_STRUCT tik_sig;
	uint8_t encrypted_title_key[16];
	uint8_t unknown_0;
	uint64_t ticket_id;
	uint32_t ticket_consoleID;
	uint64_t title_id;
	uint8_t unknown_1[2];
	uint16_t title_version;
	uint8_t unused_0[8];
	uint8_t unused_1;
	uint8_t common_key_index;
	uint8_t unknown_2[350];
} TIK_STRUCT;

typedef struct
{
	FILE *fp;
	uint32_t sig_ize;
	uint64_t title_id;
	uint16_t title_version;
	cert_t cert[2];
} __attribute__((__packed__)) 
TIK_CONTEXT;

typedef struct
{
	FILE *fp;
	uint32_t sig_size;
	uint64_t title_id;
	uint16_t title_version;
	cert_t cert[2];
	uint16_t content_count;
	TMD_CONTENT *content;
	
	uint16_t *title_index;
} __attribute__((__packed__)) 
TMD_CONTEXT;

typedef struct
{
	uint32_t header_size;
	uint16_t type;
	uint16_t version;
	uint32_t cert_size;
	uint32_t tik_size;
	uint32_t tmd_size;
	uint32_t meta_size;
	uint64_t content_size;
	uint8_t content_index[8192];
} CIA_HEADER;

int generate_cia(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp);

int process_tik(TIK_CONTEXT *tik_context);
int process_tmd(TMD_CONTEXT *tmd_context);
