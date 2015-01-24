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
#include <errno.h>
#include <stdio.h>

static size_t get_sig_size(long offset, FILE *fp)
{
	uint32_t sig_type;

	if (fseek(fp, offset, SEEK_SET))
		return errno;
	if (fread(&sig_type, sizeof(sig_type), 1, fp) <= 0)
		return errno;
	switch (be32toh(sig_type)) {
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
			return EILSEQ;
	}
}

static size_t get_cert_size(long offset, FILE *fp)
{
	size_t sig_size;

	sig_size = get_sig_size(offset, fp);
	return sig_size < SIGTYPE_MIN ? sig_size : 4 + sig_size + sizeof(CERT_2048KEY_DATA_STRUCT);
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
		index = be16toh(tmd->content[i].content_index);
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
	u8 cert[4096];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp, align_value(sizeof(CIA_HEADER), 64), SEEK_SET))
		return IO_FAIL;

	if (fseek(tik->fp, tik->cert[1].offset, SEEK_SET))
		return IO_FAIL;
	if (fread(cert, tik->cert[1].size, 1, tik->fp) <= 0)
		return IO_FAIL;
	if (fwrite(cert, tik->cert[1].size, 1, fp) <= 0)
		return IO_FAIL;

	if (fseek(tik->fp, tik->cert[0].offset, SEEK_SET))
		return IO_FAIL;
	if (fread(cert, tik->cert[0].size, 1, tik->fp) <= 0)
		return IO_FAIL;
	if (fwrite(cert, tik->cert[0].size, 1, fp) <= 0)
		return IO_FAIL;

	if (fseek(tmd->fp, tmd->cert[0].offset, SEEK_SET))
		return IO_FAIL;
	if (fread(cert, tmd->cert[0].size, 1, tmd->fp) <= 0)
		return IO_FAIL;
	if (fwrite(&cert, tmd->cert[0].size, 1, fp) <= 0)
		return IO_FAIL;
	
	return 0;
}

static int write_tik(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd, FILE *fp)
{
	u8 buf[tik->size];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		align_value(get_total_cert_size(tik, tmd), 64)
			+ align_value(sizeof(CIA_HEADER), 64),
		SEEK_SET))
		return IO_FAIL;
	if (fseek(tik->fp, 0, SEEK_SET))
		return IO_FAIL;
	if (fread(buf, tik->size, 1, tik->fp) <= 0)
		return IO_FAIL;
	if (fwrite(buf, tik->size, 1, fp) <= 0)
		return IO_FAIL;

	return 0;
}

static int write_tmd(const TIK_CONTEXT *tik, const TMD_CONTEXT *tmd, FILE *fp)
{
	u8 buf[tmd->size];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		align_value(tik->size, 64)
			+ align_value(get_total_cert_size(tik, tmd), 64)
			+ align_value(sizeof(CIA_HEADER), 64),
		SEEK_SET))
		return IO_FAIL;
	if (fseek(tmd->fp, 0, SEEK_SET))
		return IO_FAIL;
	if (fread(buf, tmd->size, 1, tmd->fp) < 0)
		return IO_FAIL;
	if (fwrite(buf, tmd->size, 1, fp) <= 0)
		return IO_FAIL;

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
		align_value(tmd->size, 64)
			+ align_value(tik->size, 64)
			+ align_value(get_total_cert_size(tik, tmd), 64)
			+ align_value(sizeof(CIA_HEADER), 64),
		SEEK_SET))
		return IO_FAIL;

	for (i = 0; i < tmd->content_count; i++) {
		sprintf(buf, "%08x", be32toh(tmd->content[i].content_id));

		content = fopen(buf, "rb");
		if (content == NULL) {
#ifdef _WIN32
			sprintf(buf, "[!] Content %08x", be32toh(tmd->content[i].content_id));
			perror(buf);
			return IO_FAIL;
#else
			for (i = 0; i < 16; i++)
				if (islower(((unsigned char *)buf)[i]))
					((unsigned char *)buf)[i] = toupper(((unsigned char *)buf)[i]);

			content = fopen(buf, "rb");
			if (content == NULL) {
				sprintf(buf, "[!] Content %08x", be32toh(tmd->content[i].content_id));
				perror(buf);
				return IO_FAIL;
			}
#endif
		}
		for (left = be64toh(tmd->content[i].size); left > sizeof(buf); left -= sizeof(buf)) {
			if (fread(buf, sizeof(buf), 1, content) <= 0)
				return IO_FAIL;
			if (fwrite(buf, sizeof(buf), 1, fp) <= 0)
				return IO_FAIL;
		}
		if (fread(buf, left, 1, content) <= 0)
			return IO_FAIL;
		if (fwrite(buf, left, 1, fp) <= 0)
			return IO_FAIL;
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
		return IO_FAIL;

	return 0;
}

int process_tik(TIK_CONTEXT *tik_context)
{
	TIK_STRUCT tik_struct;
	size_t sig_size;

	if (tik_context == NULL)
		return EFAULT;

	sig_size = get_sig_size(0, tik_context->fp);
	if (sig_size < SIGTYPE_MIN) {
		printf("[!] The CETK signature could not be recognised\n");
		return sig_size;
	}

	if (fseek(tik_context->fp, 4 + sig_size, SEEK_SET))
		return errno;
	if (fread(&tik_struct, sizeof(tik_struct), 1, tik_context->fp) <= 0)
		return errno;

	tik_context->title_version = be16toh(tik_struct.title_version);
	tik_context->size = 4 + sig_size + sizeof(TIK_STRUCT);

	tik_context->cert[0].offset = tik_context->size;
	tik_context->cert[0].size = get_cert_size(tik_context->cert[0].offset, tik_context->fp);
	if (tik_context->cert[0].size < SIGTYPE_MIN) {
		printf("[!] The first signatures in the CETK 'Cert Chain' is unrecognised.\n");
		return tik_context->cert[0].size;
	}

	tik_context->cert[1].offset = tik_context->cert[0].offset + tik_context->cert[0].size;
	tik_context->cert[1].size = get_cert_size(tik_context->cert[1].offset, tik_context->fp);
	if (tik_context->cert[1].size < SIGTYPE_MIN) {
		printf("[!] The second signatures in the CETK 'Cert Chain' is unrecognised.\n");
		return tik_context->cert[1].size;
	}
	tik_context->title_id = tik_struct.title_id;

	return 0;
}

int process_tmd(TMD_CONTEXT *tmd_context)
{
	TMD_STRUCT tmd_struct;
	size_t sig_size;
	int i;

	if (tmd_context == NULL)
		return EFAULT;

	sig_size = get_sig_size(0, tmd_context->fp);
	if (sig_size < SIGTYPE_MIN) {
		printf("[!] The TMD signature could not be recognised\n");
		return sig_size;
	}

	if (fseek(tmd_context->fp, 4 + sig_size, SEEK_SET))
		return errno;
	if (fread(&tmd_struct, sizeof(tmd_struct), 1, tmd_context->fp))
		return errno;

	tmd_context->content_count = be16toh(tmd_struct.content_count);
	tmd_context->title_version = be16toh(tmd_struct.title_version);
	tmd_context->size = 4 + sig_size + sizeof(TMD_STRUCT) + sizeof(TMD_CONTENT) * tmd_context->content_count;

	tmd_context->cert[0].offset = tmd_context->size;
	tmd_context->cert[0].size = get_cert_size(tmd_context->cert[0].offset, tmd_context->fp);
	if (tmd_context->cert[0].size < SIGTYPE_MIN) {
		printf("[!] The first signatures in the TMD 'Cert Chain' is unrecognised.\n");
		return tmd_context->cert[0].size;
	}

	tmd_context->cert[1].offset = tmd_context->cert[0].offset + tmd_context->cert[0].size;
	tmd_context->cert[1].size = get_cert_size(tmd_context->cert[1].offset, tmd_context->fp);
	if (tmd_context->cert[1].size < SIGTYPE_MIN) {
		printf("[!] One or both of the signatures in the TMD 'Cert Chain' are unrecognised\n");
		return tmd_context->cert[1].size;
	}
	tmd_context->title_id = tmd_struct.title_id;
	tmd_context->content = malloc(sizeof(TMD_CONTENT) * tmd_context->content_count);
	if (fseek(tmd_context->fp, 4 + sig_size + sizeof(TMD_STRUCT), SEEK_SET))
		return errno;
	if (fread(tmd_context->content, sizeof(TMD_CONTENT), tmd_context->content_count, tmd_context->fp) < tmd_context->content_count)
		return errno;


	return 0;
}
