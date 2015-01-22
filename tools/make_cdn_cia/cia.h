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
//Sig Types
#define Elliptic_Curve_1 0x05000100
#define RSA_2048_SHA256 0x04000100
#define RSA_4096_SHA256 0x03000100
#define Elliptic_Curve_0 0x02000100
#define RSA_2048_SHA1 0x01000100
#define RSA_4096_SHA1 0x00000100
//Errors
#define ERR_UNRECOGNISED_SIG 2

typedef struct
{
	u32 offset[2];
	u32 size[2];
} cert_t;

typedef struct
{
	u8 modulus[0x100];
	u8 exponent[0x4];
} RSA_2048_PUB_KEY;

typedef struct
{
	u8 padding_0[0x3c];
	u8 issuer[0x40];
	u8 tag_0[4];
	u8 name[0x40];
	u8 tag_1[0x4];
	RSA_2048_PUB_KEY pubk;
	u8 padding_1[0x34];
} CERT_2048KEY_DATA_STRUCT;

typedef struct
{
	u8 padding_0[0x3c];
	u8 issuer[0x40];
	u8 version;
	u8 ca_crl_version;
	u8 signer_crl_version;
	u8 padding_1;
} TMD_SIG_STRUCT;

typedef struct
{
	u8 content_id[4];
	u8 content_index[2];
	u8 content_type[2];
	u8 content_size[8];
	u8 sha_256_hash[0x20];
} TMD_CONTENT;

typedef struct
{
	TMD_SIG_STRUCT tmd_sig;
	u8 system_version[8];
	u8 title_id[8];
	u8 title_type[4];
	u8 reserved[0x40];
	u8 access_rights[4];
	u8 title_version[2];
	u8 content_count[2];
	u8 boot_content[2];
	u8 padding[2];
	u8 sha_256_hash[0x20];
	u8 content_info_records[0x900];
} TMD_STRUCT;

typedef struct
{
	u8 padding_0[0x3c];
	u8 issuer[0x40];
	u8 ECDH[0x3c];
	u8 unknown[3];
} TIK_SIG_STRUCT;

typedef struct
{
	TIK_SIG_STRUCT tik_sig;
	u8 encrypted_title_key[0x10];
	u8 unknown_0;
	u8 ticket_id[8];
	u8 ticket_consoleID[4];
	u8 title_id[8];
	u8 unknown_1[2];
	u8 title_version[2];
	u8 unused_0[8];
	u8 unused_1;
	u8 common_key_index;
	u8 unknown_2[0x15e];
} TIK_STRUCT;

typedef struct
{
	u8 result;

	FILE *fp;
	u8 title_id[8];
	u16 title_version;
	u32 size;
	cert_t cert;
	u16 content_count;
	TMD_CONTENT *content;
	
	u16 *title_index;
} __attribute__((__packed__)) 
TMD_CONTEXT;

typedef struct
{
	u8 result;
	
	FILE *fp;
	u8 title_id[8];
	u16 title_version;
	u32 size;
	cert_t cert;
} __attribute__((__packed__)) 
TIK_CONTEXT;

typedef struct
{
	u32 header_size;
	u16 type;
	u16 version;
	u32 cert_size;
	u32 tik_size;
	u32 tmd_size;
	u32 meta_size;
	u64 content_size;
	u8 content_index[8192];
} CIA_HEADER;

int generate_cia(const TMD_CONTEXT *tmd, const TIK_CONTEXT *tik, FILE *fp);

TIK_CONTEXT process_tik(FILE *fp);
TMD_CONTEXT process_tmd(FILE *fp);

int check_tid(const u8 *tid0, const u8 *tid1);
