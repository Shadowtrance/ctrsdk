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

#include <stdint.h>
#include <stdio.h>

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
	uint8_t ECDH[60];
	uint8_t unknown[3];
	uint8_t encrypted_title_key[16];
	uint8_t unknown_0;
	uint64_t ticket_id;
	uint32_t ticket_consoleID;
	uint64_t titleId;
	uint8_t unknown_1[2];
	uint16_t titleVer;
	uint8_t unused_0[8];
	uint8_t unused_1;
	uint8_t common_key_index;
	uint8_t unknown_2[350];
} TIKHdr;

typedef struct
{
	FILE *fp;
	size_t size;
	uint64_t titleId;
	uint16_t titleVer;
	cert_t xsCert;
	cert_t caCert;
} TIKCtx;

typedef struct
{
	uint8_t padding_0[60];
	uint8_t issuer[64];
	uint8_t version;
	uint8_t ca_crl_version;
	uint8_t signer_crl_version;
	uint8_t padding_1;
	uint64_t system_version;
	uint64_t title_id;
	uint32_t title_type;
	uint8_t reserved[64];
	uint32_t access_rights;
	uint16_t title_version;
	uint16_t contentCnt;
	uint16_t boot_content;
	uint8_t padding[2];
	uint8_t sha_256_hash[32];
	uint8_t content_info_records[2304];
} TMDHdr;

typedef struct
{
	uint32_t content_id;
	uint16_t content_index;
	uint16_t content_type;
	uint64_t size;
	uint8_t sha_256_hash[0x20];
} TMDContent;

typedef struct
{
	FILE *fp;
	size_t size;
	uint64_t titleId;
	uint16_t titleVer;
	cert_t cpCert;
	cert_t caCert;
	uint16_t contentCnt;
	TMDContent *content;

	uint16_t *title_index;
} TMDCtx;

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
} CIAHdr;

int writeCIA(const TMDCtx *tmd, const TIKCtx *tik, FILE *fp);

int processTIK(TIKCtx *tik_context);
int processTMD(TMDCtx *tmd_context);
