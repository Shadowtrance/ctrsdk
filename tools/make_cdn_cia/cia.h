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
	uint8_t pad[60];
	uint8_t issuer[64];
	uint8_t ECDH[60];
	uint8_t unk0[3];
	uint8_t titleKey[16];
	uint8_t unk1;
	uint64_t ticketId;
	uint32_t consoleID;
	uint64_t titleId;
	uint8_t unk2[2];
	uint16_t titleVer;
	uint8_t unk3[9];
	uint8_t keyIndex;
	uint8_t unk4[350];
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
	uint8_t pad0[60];
	uint8_t issuer[64];
	uint8_t ver;
	uint8_t caCrlVer;
	uint8_t signerCrlVer;
	uint8_t pad1;
	uint64_t sysVer;
	uint64_t titleId;
	uint32_t titleType;
	uint8_t reserve[64];
	uint32_t access;
	uint16_t titleVer;
	uint16_t contentCnt;
	uint16_t bootContent;
	uint8_t pad2[2];
	uint8_t sha256[32];
	uint8_t contentInfo[2304];
} TMDHdr;

typedef struct
{
	uint32_t id;
	uint16_t index;
	uint16_t type;
	uint64_t size;
	uint8_t sha256[32];
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
	uint32_t hdrSize;
	uint16_t type;
	uint16_t ver;
	uint32_t certSize;
	uint32_t tikSize;
	uint32_t tmdSize;
	uint32_t metaSize;
	uint64_t contentSize;
	uint8_t contentIndex[8192];
} CIAHdr;

int writeCIA(const TMDCtx *tmd, const TIKCtx *tik, FILE *fp);

int processTIK(TIKCtx *tik_context);
int processTMD(TMDCtx *tmd_context);
