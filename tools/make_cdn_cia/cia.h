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

#define ALIGN_CIA(v) ((v) & 0x3F ? (v) & ~0x3F + 0x40 : (v))

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
	uint8_t padding_0[0x3c];
	uint8_t issuer[0x40];
	uint8_t version;
	uint8_t ca_crl_version;
	uint8_t signer_crl_version;
	uint8_t padding_1;
} TMD_SIG_STRUCT;

typedef struct
{
	uint32_t content_id;
	uint16_t content_index;
	uint8_t content_type[2];
	uint64_t size;
	uint8_t sha_256_hash[0x20];
} TMD_CONTENT;

typedef struct
{
	TMD_SIG_STRUCT tmd_sig;
	uint8_t system_version[8];
	uint64_t title_id;
	uint8_t title_type[4];
	uint8_t reserved[0x40];
	uint8_t access_rights[4];
	uint16_t title_version;
	uint16_t content_count;
	uint8_t boot_content[2];
	uint8_t padding[2];
	uint8_t sha_256_hash[0x20];
	uint8_t content_info_records[0x900];
} TMD_STRUCT;

typedef struct
{
	uint8_t padding_0[0x3c];
	uint8_t issuer[0x40];
	uint8_t ECDH[0x3c];
	uint8_t unknown[3];
} TIK_SIG_STRUCT;

typedef struct
{
	TIK_SIG_STRUCT tik_sig;
	uint8_t encrypted_title_key[0x10];
	uint8_t unknown_0;
	uint8_t ticket_id[8];
	uint8_t ticket_consoleID[4];
	uint64_t title_id;
	uint8_t unknown_1[2];
	uint16_t title_version;
	uint8_t unused_0[8];
	uint8_t unused_1;
	uint8_t common_key_index;
	uint8_t unknown_2[0x15e];
} TIK_STRUCT;

typedef struct
{
	FILE *fp;
	uint64_t title_id;
	uint16_t title_version;
	uint32_t size;
	cert_t cert[2];
	uint16_t content_count;
	TMD_CONTENT *content;
	
	uint16_t *title_index;
} __attribute__((__packed__)) 
TMD_CONTEXT;

typedef struct
{
	FILE *fp;
	uint64_t title_id;
	uint16_t title_version;
	uint32_t size;
	cert_t cert[2];
} __attribute__((__packed__)) 
TIK_CONTEXT;

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
