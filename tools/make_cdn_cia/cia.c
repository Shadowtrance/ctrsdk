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

static size_t getSigSize(uint32_t sigType)
{
	switch (sigType) {
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

static size_t getCertSize(uint32_t sigType)
{
	switch (be32toh(sigType)) {
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

static int buildCIAHdr(CIAHdr *cia, const TIKCtx *tik, const TMDCtx *tmd)
{
	uint16_t index, i;

	if (cia == NULL || tik == NULL || tmd == NULL) {
		errno = EFAULT;
		return -1;
	}

	cia->hdrSize = htole32(sizeof(*cia));
	cia->type = htole16(0);
	cia->ver = htole16(0);
	cia->certSize = htole32(tik->caCert.size + tik->xsCert.size + tmd->cpCert.size);
	cia->tikSize = htole32(tik->size);
	cia->tmdSize = htole32(tmd->size);
	cia->metaSize = htole32(0);
	cia->contentSize = 0;
	for (i = 0; i < tmd->contentCnt; i++)
		cia->contentSize += be64toh(tmd->content[i].size);
	cia->contentSize = htole64(cia->contentSize);

	memset(cia->contentIndex, 0, sizeof(cia->contentIndex));
	for (i = 0; i < tmd->contentCnt; i++) {
		index = be16toh(tmd->content[i].index);
		cia->contentIndex[index >> 3] |= 0x80 >> (index & 7);
	}

	return 0;
}

int writeCIA(const TMDCtx *tmd, const TIKCtx *tik, FILE *fp)
{
	CIAHdr cia;
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

	align = sizeof(CIAHdr) & 0x3F;
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

	align = le32toh(cia.certSize) & 0x3F;
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
		sprintf(buf, "%08x", be32toh(tmd->content[i].id));

		content = fopen(buf, "rb");
		if (content == NULL) {
#ifdef _WIN32
			sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].id));
			perror(buf);
			return -1;
#else
			for (i = 0; i < 16; i++)
				if (islower(((unsigned char *)buf)[i]))
					((unsigned char *)buf)[i] = toupper(((unsigned char *)buf)[i]);

			content = fopen(buf, "rb");
			if (content == NULL) {
				sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].id));
				perror(buf);
				return -1;
			}
#endif
		}
		for (left = be64toh(tmd->content[i].size); left > sizeof(buf); left -= sizeof(buf)) {
			if (fread(buf, sizeof(buf), 1, content) <= 0) {
				sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].id));
				perror(buf);
				return -1;
			}
			if (fwrite(buf, sizeof(buf), 1, fp) <= 0) {
				perror("CIA: error");
				return -1;
			}
		}
		if (fread(buf, left, 1, content) <= 0) {
			sprintf(buf, "0x%08X: error", be32toh(tmd->content[i].id));
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

int processTIK(TIKCtx *tik)
{
	TIKHdr hdr;
	uint32_t sigType;

	if (tik == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (fseek(tik->fp, 0, SEEK_SET))
		return -1;
	if (fread(&sigType, sizeof(sigType), 1, tik->fp) <= 0)
		return -1;
	tik->size = getSigSize(be32toh(sigType));
	if (!tik->size) {
		printf("CETK: error: The signature could not be recognized.\n");
		return -1;
	}

	if (fseek(tik->fp, tik->size, SEEK_SET))
		return -1;
	if (fread(&hdr, sizeof(hdr), 1, tik->fp) <= 0) {
		perror("CETK: error");
		return -1;
	}

	tik->size += sizeof(hdr);
	tik->titleID = hdr.titleID;

	tik->xsCert.offset = tik->size;
	if (fread(&sigType, sizeof(sigType), 1, tik->fp) <= 0) {
		perror("CETK: error");
		return -1;
	}
	tik->xsCert.size = getCertSize(be32toh(sigType));
	if (!tik->xsCert.size) {
		printf("CETK: error: xs certificate is unrecognized.\n");
		return -1;
	}

	tik->caCert.offset = tik->xsCert.offset + tik->xsCert.size;
	if (fseek(tik->fp, tik->caCert.offset, SEEK_SET))
		return -1;
	if (fread(&sigType, sizeof(sigType), 1, tik->fp) <= 0)
		return -1;
	tik->caCert.size = getCertSize(be32toh(sigType));
	if (!tik->caCert.size) {
		printf("CETK: error: ca certificate is unrecognized.\n");
		return -1;
	}

	return 0;
}

int processTMD(TMDCtx *tmd)
{
	TMDHdr hdr;
	uint32_t sigType;

	if (tmd == NULL) {
		errno = EFAULT;
		return -1;
	}

	if (fseek(tmd->fp, 0, SEEK_SET)) {
		perror("TMD: error");
		return -1;
	}
	if (fread(&sigType, sizeof(sigType), 1, tmd->fp) <= 0) {
		perror("TMD: error");
		return -1;
	}
	tmd->size = getSigSize(be32toh(sigType));
	if (!tmd->size) {
		printf("TMD: error: The signature cannot be recognized.\n");
		return -1;
	}

	if (fseek(tmd->fp, tmd->size, SEEK_SET)) {
		perror("TMD: error");
		return -1;
	}
	if (fread(&hdr, sizeof(hdr), 1, tmd->fp)) {
		perror("TMD: error");
		return -1;
	}

	tmd->size += sizeof(hdr);
	tmd->titleID = hdr.titleID;

	tmd->contentCnt = be16toh(hdr.contentCnt);
	tmd->size += sizeof(TMDContent) * tmd->contentCnt;
	tmd->content = malloc(sizeof(TMDContent) * tmd->contentCnt);
	if (fread(tmd->content, sizeof(TMDContent), tmd->contentCnt, tmd->fp)
		< tmd->contentCnt) {
		perror("content: error");
		return -1;
	}

	tmd->cpCert.offset = tmd->size;
	if (fread(&sigType, sizeof(sigType), 1, tmd->fp) <= 0) {
		perror("TMD: error");
		return -1;
	}
	tmd->cpCert.size = getCertSize(be32toh(sigType));
	if (!tmd->cpCert.size) {
		printf("TMD: error: cp certificate is unrecognized.\n");
		return -1;
	}

	tmd->caCert.offset = tmd->cpCert.offset + tmd->cpCert.size;
	if (fseek(tmd->fp, tmd->caCert.offset, SEEK_SET))
		return -1;
	if (fread(&sigType, sizeof(sigType), 1, tmd->fp) <= 0)
		return -1;
	tmd->caCert.size = getCertSize(be32toh(sigType));
	if (!tmd->caCert.size) {
		printf("TMD: error: ca certificate is unrecognized.\n");
		return -1;
	}

	return 0;
}
