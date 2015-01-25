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
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t get_sig_size(uint32_t sig_type)
{
	switch (sig_type) {
		case SIGTYPE_RSA4096_SHA1:
		case SIGTYPE_RSA4096_SHA256:
			return 512;

		case SIGTYPE_RSA2048_SHA1:
		case SIGTYPE_RSA2048_SHA256:
			return 256;

		case SIGTYPE_ECDSA_SHA1:
		case SIGTYPE_ECDSA_SHA256:
			return 60;

		default:
			errno = EILSEQ;
			return 0;
	}
}

static size_t get_cert_size(uint32_t sig_type)
{
	switch (ctr32toh(sig_type)) {
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

static size_t get_total_cert_size(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd)
{
	if (tmd == NULL || tik == NULL)
		return EFAULT;

	return tik->cert[1].size + tik->cert[0].size + tmd->cert[0].size;
}

static int write_cia_header(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd, FILE *fp)
{
	CIA_HEADER hdr;
	uint16_t index, i;

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	hdr.header_size = sizeof(hdr);
	hdr.type = 0;
	hdr.version = 0;
	hdr.cert_size = get_total_cert_size(tik, tmd);
	hdr.tik_size = tik->size;
	hdr.tmd_size = tmd->size;
	hdr.meta_size = 0;
	hdr.content_size = 0;
	for (i = 0; i < tmd->content_count; i++)
		hdr.content_size += be64toh(tmd->content[i].size);

	memset(hdr.content_index, 0, sizeof(hdr.content_index));
	for (i = 0; i < tmd->content_count; i++) {
		index = ctr16toh(tmd->content[i].content_index);
		hdr.content_index[index >> 3] |= 0x80 >> (index & 7);
	}

	if (fseek(fp, 0, SEEK_SET))
		return errno;
	if (fwrite(&hdr, sizeof(hdr), 1, fp) <= 0)
		return errno;

	return 0;
}

static int write_cert_chain(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd, FILE *fp)
{
	uint8_t cert[4096];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp, ALIGN_CIA(sizeof(CIA_HEADER)), SEEK_SET))
		return -1;

	if (fseek(tik->fp, tik->cert[1].offset, SEEK_SET))
		return -1;
	if (fread(cert, tik->cert[1].size, 1, tik->fp) <= 0)
		return -1;
	if (fwrite(cert, tik->cert[1].size, 1, fp) <= 0)
		return -1;

	if (fseek(tik->fp, tik->cert[0].offset, SEEK_SET))
		return -1;
	if (fread(cert, tik->cert[0].size, 1, tik->fp) <= 0)
		return -1;
	if (fwrite(cert, tik->cert[0].size, 1, fp) <= 0)
		return -1;

	if (fseek(tmd->fp, tmd->cert[0].offset, SEEK_SET))
		return -1;
	if (fread(cert, tmd->cert[0].size, 1, tmd->fp) <= 0)
		return -1;
	if (fwrite(&cert, tmd->cert[0].size, 1, fp) <= 0)
		return -1;
	
	return 0;
}

static int write_tik(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd, FILE *fp)
{
	uint8_t buf[tik->size];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		ALIGN_CIA(get_total_cert_size(tik, tmd))
			+ ALIGN_CIA(sizeof(CIA_HEADER)),
		SEEK_SET))
		return -1;
	if (fseek(tik->fp, 0, SEEK_SET))
		return -1;
	if (fread(buf, tik->size, 1, tik->fp) <= 0)
		return -1;
	if (fwrite(buf, tik->size, 1, fp) <= 0)
		return -1;

	return 0;
}

static int write_tmd(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd, FILE *fp)
{
	uint8_t buf[tmd->size];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		ALIGN_CIA(tik->size)
			+ ALIGN_CIA(get_total_cert_size(tik, tmd))
			+ ALIGN_CIA(sizeof(CIA_HEADER)),
		SEEK_SET))
		return -1;
	if (fseek(tmd->fp, 0, SEEK_SET))
		return -1;
	if (fread(buf, tmd->size, 1, tmd->fp) < 0)
		return -1;
	if (fwrite(buf, tmd->size, 1, fp) <= 0)
		return -1;

	return 0;
}

static int write_content(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd, FILE *fp)
{
	FILE *content;
	uint16_t i;
	uint64_t left;
	char buf[1048576];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		ALIGN_CIA(tmd->size)
			+ ALIGN_CIA(tik->size)
			+ ALIGN_CIA(get_total_cert_size(tik, tmd))
			+ ALIGN_CIA(sizeof(CIA_HEADER)),
		SEEK_SET))
		return -1;

	for (i = 0; i < tmd->content_count; i++) {
		sprintf(buf, "%08x", ctr32toh(tmd->content[i].content_id));

		content = fopen(buf, "rb");
		if (content == NULL) {
#ifdef _WIN32
			sprintf(buf, "[!] Content %08x", ctr32toh(tmd->content[i].content_id));
			perror(buf);
			return -1;
#else
			for (i = 0; i < 16; i++)
				if (islower(((unsigned char *)buf)[i]))
					((unsigned char *)buf)[i] = toupper(((unsigned char *)buf)[i]);

			content = fopen(buf, "rb");
			if (content == NULL) {
				sprintf(buf, "[!] Content %08x", ctr32toh(tmd->content[i].content_id));
				perror(buf);
				return -1;
			}
#endif
		}
		for (left = be64toh(tmd->content[i].size); left > sizeof(buf); left -= sizeof(buf)) {
			if (fread(buf, sizeof(buf), 1, content) <= 0)
				return -1;
			if (fwrite(buf, sizeof(buf), 1, fp) <= 0)
				return -1;
		}
		if (fread(buf, left, 1, content) <= 0)
			return -1;
		if (fwrite(buf, left, 1, fp) <= 0)
			return -1;
		fclose(content);
	}

	return 0;
}

int generate_cia(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp)
{
	int ret;

	ret = write_cia_header(tik, tmd, fp);
	if (ret)
		return ret;
	ret = write_cert_chain(tik, tmd, fp);
	if (ret)
		return ret;
	ret = write_tik(tik, tmd, fp);
	if (ret)
		return ret;
	ret = write_tmd(tik, tmd, fp);
	if (ret)
		return ret;
	ret = write_content(tik, tmd, fp);
	if (ret)
		return ret;

	if (fclose(fp))
		return -1;

	return 0;
}

int process_tik(TIK_CONTEXT *tik_context)
{
	TIK_STRUCT tik_struct;
	uint32_t sig_type;
	size_t sig_size;

	if (tik_context == NULL)
		return EFAULT;

	if (fseek(tik_context->fp, 0, SEEK_SET))
		return errno;
	if (fread(&sig_type, sizeof(sig_type), 1, tik_context->fp) <= 0)
		return errno;
	sig_size = get_sig_size(ctr32toh(sig_type));
	if (!sig_size) {
		printf("[!] The CETK signature could not be recognised\n");
		return errno;
	}

	if (fseek(tik_context->fp, sig_size, SEEK_CUR))
		return errno;
	if (fread(&tik_struct, sizeof(tik_struct), 1, tik_context->fp) <= 0)
		return errno;

	tik_context->title_id = tik_struct.title_id;
	tik_context->title_version = ctr16toh(tik_struct.title_version);
	tik_context->size = 4 + sig_size + sizeof(TIK_STRUCT);

	tik_context->cert[0].offset = tik_context->size;
	if (fread(&sig_type, sizeof(sig_type), 1, tik_context->fp) <= 0)
		return errno;
	tik_context->cert[0].size = get_cert_size(ctr32toh(sig_type));
	if (!tik_context->cert[0].size) {
		printf("[!] The first signatures in the CETK 'Cert Chain' is unrecognised.\n");
		return errno;
	}

	tik_context->cert[1].offset = tik_context->cert[0].offset + tik_context->cert[0].size;
	if (fseek(tik_context->fp, tik_context->cert[0].size - 4, SEEK_SET))
		return errno;
	if (fread(&sig_type, sizeof(sig_type), 1, tik_context->fp) <= 0)
		return errno;
	tik_context->cert[1].size = get_cert_size(ctr32toh(sig_type));
	if (!tik_context->cert[1].size) {
		printf("[!] The second signatures in the CETK 'Cert Chain' is unrecognised.\n");
		return errno;
	}

	return 0;
}

int process_tmd(TMD_CONTEXT *tmd_context)
{
	TMD_STRUCT tmd_struct;
	uint32_t sig_type;
	size_t sig_size;

	if (tmd_context == NULL)
		return EFAULT;

	if (fseek(tmd_context->fp, 0, SEEK_SET))
		return errno;
	if (fread(&sig_type, sizeof(sig_type), 1, tmd_context->fp) <= 0)
		return errno;
	sig_size = get_sig_size(ctr32toh(sig_type));
	if (!sig_size) {
		printf("[!] The TMD signature could not be recognised\n");
		return errno;
	}

	if (fseek(tmd_context->fp, sig_size, SEEK_CUR))
		return errno;
	if (fread(&tmd_struct, sizeof(tmd_struct), 1, tmd_context->fp))
		return errno;

	tmd_context->title_id = tmd_struct.title_id;
	tmd_context->title_version = ctr16toh(tmd_struct.title_version);
	tmd_context->size = 4 + sig_size + sizeof(TMD_STRUCT) + sizeof(TMD_CONTENT) * tmd_context->content_count;

	tmd_context->content_count = ctr16toh(tmd_struct.content_count);
	tmd_context->content = malloc(sizeof(TMD_CONTENT) * tmd_context->content_count);
	if (fread(tmd_context->content, sizeof(TMD_CONTENT), tmd_context->content_count, tmd_context->fp)
		< tmd_context->content_count)
		return errno;

	tmd_context->cert[0].offset = tmd_context->size;
	if (fread(&sig_type, sizeof(sig_type), 1, tmd_context->fp) <= 0)
		return errno;
	tmd_context->cert[0].size = get_cert_size(ctr32toh(sig_type));
	if (!tmd_context->cert[0].size) {
		printf("[!] The first signatures in the TMD 'Cert Chain' is unrecognised.\n");
		return errno;
	}

	tmd_context->cert[1].offset = tmd_context->cert[0].offset + tmd_context->cert[0].size;
	if (fseek(tmd_context->fp, tmd_context->cert[0].size - 4, SEEK_SET))
		return errno;
	if (fread(&sig_type, sizeof(sig_type), 1, tmd_context->fp) <= 0)
		return errno;
	tmd_context->cert[1].size = get_cert_size(ctr32toh(sig_type));
	if (!tmd_context->cert[1].size) {
		printf("[!] One or both of the signatures in the TMD 'Cert Chain' are unrecognised\n");
		return errno;
	}

	return 0;
}
