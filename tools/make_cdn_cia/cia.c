/**
Copyright 2013 3DSGuy

This file is part of make_cdn_cia.

make_cdn_cia is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

make_cdn_cia is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with make_cdn_cia.  If not, see <http://www.gnu.org/licenses/>.
**/
#include "lib.h"
#include "cia.h"

static u32 get_sig_size(long offset, FILE *fp)
{
	u32 sig_type;

	fseek(fp, offset, SEEK_SET);
	fread(&sig_type,sizeof(sig_type), 1, fp);
	switch(sig_type) {
		/*
		case(RSA_4096_SHA1):
			return 0x200;
		case(RSA_2048_SHA1):
			return 0x100;
		case(Elliptic_Curve_0):
			return 0x3C;
		*/
		case(RSA_4096_SHA256):
			return 0x200;
		case(RSA_2048_SHA256):
			return 0x100;
		/*
		case(Elliptic_Curve_1):
			return 0x3C;
		*/
	}

	return ERR_UNRECOGNISED_SIG;
}

static u32 get_cert_size(long offset, FILE *fp)
{
	u32 sig_size;

	sig_size = get_sig_size(offset, fp);
	return sig_size == ERR_UNRECOGNISED_SIG ?
		ERR_UNRECOGNISED_SIG :
		(4 + sig_size + sizeof(CERT_2048KEY_DATA_STRUCT));
}

static u64 read_content_size(const TMD_CONTENT *content)
{
	return u8_to_u64(content->content_size, BE);
}

static u64 get_content_size(const TMD_CONTEXT *tmd)
{
	u64 content_size = 0;

	for(int i = 0; i < tmd->content_count; i++)
		content_size += read_content_size(&tmd->content[i]);

	return content_size;
}

static u32 get_content_id(TMD_CONTENT content_struct)
{
	return u8_to_u32(content_struct.content_id,BE);
}

static TIK_STRUCT get_tik_struct(u32 sig_size, FILE *tik)
{
	TIK_STRUCT tik_struct;
	fseek(tik,(0x4+sig_size),SEEK_SET);
	fread(&tik_struct,sizeof(tik_struct),1,tik);
	return tik_struct;
}

static TMD_STRUCT get_tmd_struct(u32 sig_size, FILE *tmd)
{
	TMD_STRUCT tmd_struct;
	fseek(tmd,(0x4+sig_size),SEEK_SET);
	fread(&tmd_struct,sizeof(tmd_struct),1,tmd);
	return tmd_struct;
}

static u32 get_total_cert_size(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik)
{
	if (tmd == NULL || tik == NULL)
		return 0;

	return tik->cert.size[1] + tik->cert.size[0] + tmd->cert.size[0];
}

static int write_cia_header(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp)
{
	CIA_HEADER hdr;
	u16 index, i;

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	hdr.header_size = sizeof(hdr);
	hdr.type = 0;
	hdr.version = 0;
	hdr.cert_size = get_total_cert_size(tmd, tik);
	hdr.tik_size = tik->size;
	hdr.tmd_size = tmd->size;
	hdr.meta_size = 0;
	hdr.content_size = get_content_size(tmd);

	memset(hdr.content_index, 0, sizeof(hdr.content_index));
	for (i = 0; i < tmd->content_count; i++) {
		index = u8_to_u16(tmd->content[i].content_index, BE);
		hdr.content_index[index >> 3] |= 0x80 >> (index & 7);
	}

	if (fseek(fp, 0, SEEK_SET))
		return IO_FAIL;
	if (fwrite(&hdr, sizeof(hdr), 1, fp) <= 0)
		return IO_FAIL;

	return 0;
}

static int write_cert_chain(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp)
{
	u8 cert[4096];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp, align_value(sizeof(CIA_HEADER), 64), SEEK_SET))
		return IO_FAIL;

	if (fseek(tik->fp, tik->cert.offset[1], SEEK_SET))
		return IO_FAIL;
	if (fread(cert, tik->cert.size[1], 1, tik->fp) <= 0)
		return IO_FAIL;
	if (fwrite(cert, tik->cert.size[1], 1, fp) <= 0)
		return IO_FAIL;

	if (fseek(tik->fp, tik->cert.offset[0], SEEK_SET))
		return IO_FAIL;
	if (fread(cert, tik->cert.size[0], 1, tik->fp) <= 0)
		return IO_FAIL;
	if (fwrite(cert, tik->cert.size[0], 1, fp) <= 0)
		return IO_FAIL;

	if (fseek(tmd->fp, tmd->cert.offset[0], SEEK_SET))
		return IO_FAIL;
	if (fread(cert, tmd->cert.size[0], 1, tmd->fp) <= 0)
		return IO_FAIL;
	if (fwrite(&cert, tmd->cert.size[0], 1, fp) <= 0)
		return IO_FAIL;
	
	return 0;
}

static int write_tik(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp)
{
	u8 buf[tik->size];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		align_value(get_total_cert_size(tmd, tik), 64)
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

static int write_tmd(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp)
{
	u8 buf[tmd->size];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		align_value(tik->size, 64)
			+ align_value(get_total_cert_size(tmd, tik), 64)
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

static int write_content(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp)
{
	FILE *content;
	u16 i;
	u64 left;
	char buf[1048576];

	if (tmd == NULL || tik == NULL || fp == NULL)
		return -1;

	if (fseek(fp,
		align_value(tmd->size, 64)
			+ align_value(tik->size, 64)
			+ align_value(get_total_cert_size(tmd, tik), 64)
			+ align_value(sizeof(CIA_HEADER), 64),
		SEEK_SET))
		return IO_FAIL;

	for (i = 0; i < tmd->content_count; i++) {
		sprintf(buf, "%08x", get_content_id(tmd->content[i]));

		content = fopen(buf, "rb");
		if (content == NULL) {
#ifdef _WIN32
			sprintf(buf, "[!] Content %08x", get_content_id(tmd->content[i]));
			perror(buf);
			return IO_FAIL;
#else
			for (i = 0; i < 16; i++)
				if (islower(((unsigned char *)buf)[i]))
					((unsigned char *)buf)[i] = toupper(((unsigned char *)buf)[i]);

			content = fopen(buf, "rb");
			if (content == NULL) {
				sprintf(buf, "[!] Content %08x", get_content_id(tmd->content[i]));
				perror(buf);
				return IO_FAIL;
			}
#endif
		}
		for (left = read_content_size(&tmd->content[i]); left > sizeof(buf); left -= sizeof(buf)) {
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

	ret = write_cia_header(tmd, tik, fp);
	if (ret)
		return ret;
	ret = write_cert_chain(tmd, tik, fp);
	if (ret)
		return ret;
	ret = write_tik(tmd, tik, fp);
	if (ret)
		return ret;
	ret = write_tmd(tmd, tik, fp);
	if (ret)
		return ret;
	ret = write_content(tmd, tik, fp);
	if (ret)
		return ret;

	if (fclose(fp))
		return IO_FAIL;

	return 0;
}

int process_tik(TIK_CONTEXT *tik_context)
{
	TIK_STRUCT tik_struct;
	u32 sig_size;

	sig_size = get_sig_size(0, tik_context->fp);
	if (sig_size == ERR_UNRECOGNISED_SIG) {
		printf("[!] The CETK signature could not be recognised\n");
		return ERR_UNRECOGNISED_SIG;
	}

	tik_struct = get_tik_struct(sig_size, tik_context->fp);
	tik_context->title_version = u8_to_u16(tik_struct.title_version, BE);
	tik_context->size = 4 + sig_size + sizeof(TIK_STRUCT);

	if (tik_context->size == ERR_UNRECOGNISED_SIG) {
		return ERR_UNRECOGNISED_SIG;
	}

	tik_context->cert.offset[0] = tik_context->size;
	tik_context->cert.size[0] = get_cert_size(tik_context->size, tik_context->fp);
	tik_context->cert.offset[1] = tik_context->size + tik_context->cert.size[0];
	tik_context->cert.size[1] = get_cert_size(tik_context->cert.offset[1], tik_context->fp);

	if (tik_context->cert.size[0] == ERR_UNRECOGNISED_SIG || tik_context->cert.size[1] == ERR_UNRECOGNISED_SIG) {
		printf("[!] One or both of the signatures in the CETK 'Cert Chain' are unrecognised\n");
		return ERR_UNRECOGNISED_SIG;
	}
	tik_context->title_id = tik_struct.title_id;

	return 0;
}

int process_tmd(TMD_CONTEXT *tmd_context)
{
	TMD_STRUCT tmd_struct;
	u32 sig_size;
	int i;

	sig_size = get_sig_size(0, tmd_context->fp);
	if (sig_size == ERR_UNRECOGNISED_SIG) {
		printf("[!] The TMD signature could not be recognised\n");
		return ERR_UNRECOGNISED_SIG;
	}

	tmd_struct = get_tmd_struct(sig_size, tmd_context->fp);
	tmd_context->content_count = u8_to_u16(tmd_struct.content_count, BE);
	tmd_context->title_version = u8_to_u16(tmd_struct.title_version, BE);
	tmd_context->size = 4 + sig_size + sizeof(TMD_STRUCT) + sizeof(TMD_CONTENT) * tmd_context->content_count;

	tmd_context->cert.offset[0] = tmd_context->size;
	tmd_context->cert.size[0] = get_cert_size(tmd_context->size, tmd_context->fp);
	tmd_context->cert.offset[1] = tmd_context->size + tmd_context->cert.size[0];
	tmd_context->cert.size[1] = get_cert_size(tmd_context->cert.offset[1], tmd_context->fp);

	if (tmd_context->cert.size[0] == ERR_UNRECOGNISED_SIG || tmd_context->cert.size[1] == ERR_UNRECOGNISED_SIG) {
		printf("[!] One or both of the signatures in the TMD 'Cert Chain' are unrecognised\n");
		return ERR_UNRECOGNISED_SIG;
	}
	tmd_context->title_id = tmd_struct.title_id;
	tmd_context->content = malloc(sizeof(TMD_CONTENT) * tmd_context->content_count);
	fseek(tmd_context->fp, 4 + sig_size + sizeof(TMD_STRUCT), SEEK_SET);
	fread(tmd_context->content, sizeof(TMD_CONTENT), tmd_context->content_count, tmd_context->fp);


	return 0;
}
