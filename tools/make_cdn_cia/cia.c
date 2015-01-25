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
 *
 * You should have received a copy of the GNU General Public License
 * along with make_cdn_cia.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "cia.h"
#include "endian.h"
#include <ctype.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t getSigSize(uint32_t sig_type)
{
	switch (sig_type) {
		case SIGTYPE_RSA4096_SHA1:
		case SIGTYPE_RSA4096_SHA256:
			return 516;

		case SIGTYPE_RSA2048_SHA1:
		case SIGTYPE_RSA2048_SHA256:
			return 260;

		case SIGTYPE_ECDSA_SHA1:
		case SIGTYPE_ECDSA_SHA256:
			return 64;

		default:
			errno = EILSEQ;
			return 0;
	}
}

static size_t getCertSize(uint32_t sig_type)
{
	switch (be32toh(sig_type)) {
		case SIGTYPE_RSA4096_SHA1:
		case SIGTYPE_RSA4096_SHA256:
			return 1220;

		case SIGTYPE_RSA2048_SHA1:
		case SIGTYPE_RSA2048_SHA256:
			return 708;

		case SIGTYPE_ECDSA_SHA1:
		case SIGTYPE_ECDSA_SHA256:
			return 140;

		default:
			errno = EILSEQ;
			return 0;
	}
}

static int buildCIAHdr(CIA_HEADER *cia, const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd)
{
	uint16_t index, i;

	if (cia == NULL || tik == NULL || tmd == NULL) {
		errno = EFAULT;
		return -1;
	}

	cia->header_size = htole32(sizeof(*cia));
	cia->type = htole16(0);
	cia->version = htole16(0);
	cia->cert_size = htole32(tik->caCert.size + tik->xsCert.size + tmd->cpCert.size);
	cia->tik_size = htole32(tik->size);
	cia->tmd_size = htole32(tmd->size);
	cia->meta_size = htole32(0);
	cia->content_size = 0;
	for (i = 0; i < tmd->contentCnt; i++)
		cia->content_size += be64toh(tmd->content[i].size);
	cia->content_size = htole64(cia->content_size);

	memset(cia->content_index, 0, sizeof(cia->content_index));
	for (i = 0; i < tmd->contentCnt; i++) {
		index = be16toh(tmd->content[i].content_index);
		cia->content_index[index >> 3] |= 0x80 >> (index & 7);
	}

	return 0;
}

int writeCIA(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp)
{
	CIA_HEADER cia;
	FILE *content;
	char buf[1220];
	uint16_t i;
	long align;
	size_t left;

	buildCIAHdr(&cia, tik, tmd);
	if (fseek(fp, 0, SEEK_SET)) {
		perror("CIA: error");
		return -1;
	}
	if (fwrite(&cia, sizeof(cia), 1, fp) <= 0) {
		perror("CIA: error");
		return -1;
	}

	align = sizeof(CIA_HEADER) & 0x3F;
	if (align)
		if (fseek(fp, 0x40 - align, SEEK_CUR)) {
			perror("CIA: error");
			return -1;
		}

	if (fseek(tik->fp, tik->caCert.offset, SEEK_SET)) {
		perror("TIK: errror");
		return -1;
	}
	if (fread(buf, tik->caCert.size, 1, tik->fp) <= 0) {
		perror("TIK: errror");
		return -1;
	}
	if (fwrite(buf, tik->caCert.size, 1, fp) <= 0) {
		perror("CIA: error");
		return -1;
	}

	if (fseek(tik->fp, tik->xsCert.offset, SEEK_SET)) {
		perror("TIK: errror");
		return -1;
	}
	if (fread(buf, tik->xsCert.size, 1, tik->fp) <= 0) {
		perror("TIK: errror");
		return -1;
	}
	if (fwrite(buf, tik->xsCert.size, 1, fp) <= 0) {
		perror("CIA: error");
		return -1;
	}

	if (fseek(tmd->fp, tmd->cpCert.offset, SEEK_SET)) {
		perror("TMD: errror");
		return -1;
	}
	if (fread(buf, tmd->cpCert.size, 1, tmd->fp) <= 0) {
		perror("TMD: errror");
		return -1;
	}
	if (fwrite(buf, tmd->cpCert.size, 1, fp) <= 0) {
		perror("CIA: error");
		return -1;
	}

	align = le32toh(cia.cert_size) & 0x3F;
	if (align)
		if (fseek(fp, 0x40 - align, SEEK_CUR)) {
			perror("CIA: error");
			return -1;
		}

	if (fseek(tik->fp, 0, SEEK_SET)) {
		perror("TIK: errror");
		return -1;
	}
	if (fread(buf, tik->size, 1, tik->fp) <= 0) {
		perror("TIK: errror");
		return -1;
	}
	if (fwrite(buf, tik->size, 1, fp) <= 0) {
		perror("CIA: error");
		return -1;
	}

	align = tik->size & 0x3F;
	if (align)
		if (fseek(fp, 0x40 - align, SEEK_CUR)) {
			perror("CIA: error");
			return -1;
		}

	if (fseek(tmd->fp, 0, SEEK_SET)) {
		perror("TMD: errror");
		return -1;
	}
	if (fread(buf, tmd->size, 1, tmd->fp) < 0) {
		perror("TMD: errror");
		return -1;
	}
	if (fwrite(buf, tmd->size, 1, fp) <= 0) {
		perror("CIA: error");
		return -1;
	}

	align = tmd->size & 0x3F;
	if (align)
		if (fseek(fp, 0x40 - align, SEEK_CUR)) {
			perror("CIA: error");
			return -1;
		}

	for (i = 0; i < tmd->contentCnt; i++) {
		sprintf(buf, "%08x", be32toh(tmd->content[i].content_id));

		content = fopen(buf, "rb");
		if (content == NULL) {
#ifdef _WIN32
			sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].content_id));
			perror(buf);
			return -1;
#else
			for (i = 0; i < 16; i++)
				if (islower(((unsigned char *)buf)[i]))
					((unsigned char *)buf)[i] = toupper(((unsigned char *)buf)[i]);

			content = fopen(buf, "rb");
			if (content == NULL) {
				sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].content_id));
				perror(buf);
				return -1;
			}
#endif
		}
		for (left = be64toh(tmd->content[i].size); left > sizeof(buf); left -= sizeof(buf)) {
			if (fread(buf, sizeof(buf), 1, content) <= 0) {
				sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].content_id));
				perror(buf);
				return -1;
			}
			if (fwrite(buf, sizeof(buf), 1, fp) <= 0) {
				perror("CIA: error");
				return -1;
			}
		}
		if (fread(buf, left, 1, content) <= 0) {
			sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].content_id));
			perror(buf);
			return -1;
		}
		if (fwrite(buf, left, 1, fp) <= 0) {
			perror("CIA: error");
			return -1;
		}
		fclose(content);
	}

	if (fclose(fp)) {
		perror("CIA: error");
		return -1;
	}

	return 0;
}

int processTIK(TIK_CONTEXT *tik_context)
{
	TIK_STRUCT tik_struct;
	uint32_t sigType;

	if (tik_context == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (fseek(tik_context->fp, 0, SEEK_SET))
		return -1;
	if (fread(&sigType, sizeof(sigType), 1, tik_context->fp) <= 0)
		return -1;
	tik_context->size = getSigSize(be32toh(sigType));
	if (!tik_context->size) {
		printf("CETK: error: The signature could not be recognized.\n");
		return -1;
	}

	if (fseek(tik_context->fp, tik_context->size, SEEK_SET))
		return -1;
	if (fread(&tik_struct, sizeof(tik_struct), 1, tik_context->fp) <= 0) {
		perror("CETK: error");
		return -1;
	}

	tik_context->size += sizeof(tik_struct);
	tik_context->titleId = tik_struct.titleId;
	tik_context->titleVer = be16toh(tik_struct.titleVer);

	tik_context->xsCert.offset = tik_context->size;
	if (fread(&sigType, sizeof(sigType), 1, tik_context->fp) <= 0) {
		perror("CETK: error");
		return -1;
	}
	tik_context->xsCert.size = getCertSize(be32toh(sigType));
	if (!tik_context->xsCert.size) {
		printf("CETK: error: xs certificate is unrecognized.\n");
		return -1;
	}

	tik_context->caCert.offset = tik_context->xsCert.offset + tik_context->xsCert.size;
	if (fseek(tik_context->fp, tik_context->caCert.offset, SEEK_SET))
		return -1;
	if (fread(&sigType, sizeof(sigType), 1, tik_context->fp) <= 0)
		return -1;
	tik_context->caCert.size = getCertSize(be32toh(sigType));
	if (!tik_context->caCert.size) {
		printf("CETK: error: ca certificate is unrecognized.\n");
		return -1;
	}

	return 0;
}

int processTMD(TMD_CONTEXT *tmd_context)
{
	TMD_STRUCT tmd_struct;
	uint32_t sigType;

	if (tmd_context == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (fseek(tmd_context->fp, 0, SEEK_SET)) {
		perror("TMD: error");
		return -1;
	}
	if (fread(&sigType, sizeof(sigType), 1, tmd_context->fp) <= 0) {
		perror("TMD: error");
		return -1;
	}
	tmd_context->size = getSigSize(be32toh(sigType));
	if (!tmd_context->size) {
		printf("TMD: error: The signature cannot be recognized.\n");
		return -1;
	}

	if (fseek(tmd_context->fp, tmd_context->size, SEEK_SET)) {
		perror("TMD: error");
		return -1;
	}
	if (fread(&tmd_struct, sizeof(tmd_struct), 1, tmd_context->fp)) {
		perror("TMD: error");
		return -1;
	}

	tmd_context->size += sizeof(tmd_struct);
	tmd_context->titleId = tmd_struct.title_id;
	tmd_context->titleVer = be16toh(tmd_struct.title_version);

	tmd_context->contentCnt = be16toh(tmd_struct.contentCnt);
	tmd_context->size += sizeof(TMD_CONTENT) * tmd_context->contentCnt;
	tmd_context->content = malloc(sizeof(TMD_CONTENT) * tmd_context->contentCnt);
	if (fread(tmd_context->content, sizeof(TMD_CONTENT), tmd_context->contentCnt, tmd_context->fp)
		< tmd_context->contentCnt) {
		perror("content: error");
		return -1;
	}

	tmd_context->cpCert.offset = tmd_context->size;
	if (fread(&sigType, sizeof(sigType), 1, tmd_context->fp) <= 0) {
		perror("TMD: error");
		return -1;
	}
	tmd_context->cpCert.size = getCertSize(be32toh(sigType));
	if (!tmd_context->cpCert.size) {
		printf("TMD: error: cp certificate is unrecognized.\n");
		return -1;
	}

	tmd_context->caCert.offset = tmd_context->cpCert.offset + tmd_context->cpCert.size;
	if (fseek(tmd_context->fp, tmd_context->caCert.offset, SEEK_SET))
		return -1;
	if (fread(&sigType, sizeof(sigType), 1, tmd_context->fp) <= 0)
		return -1;
	tmd_context->caCert.size = getCertSize(be32toh(sigType));
	if (!tmd_context->caCert.size) {
		printf("TMD: error: ca certificate is unrecognized.\n");
		return -1;
	}

	return 0;
}
