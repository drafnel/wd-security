/*
 * wd-security.c
 *
 *   A library for managing the password protection of external drives
 *   supported by the proprietary WD Security software.
 *
 * Copyright (C) 2025-2026  Brandon Casey
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <https://www.gnu.org/licenses/>.
 */
#include "config.h"

#include "wd-security.h"

#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <endian.h>
#include <inttypes.h>
#include <limits.h>

#include <fcntl.h>
#include <unistd.h>
#include <scsi/scsi.h>
#include <scsi/sg.h>
#include <sys/ioctl.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>

#define ARRAY_LEN(_ary) (sizeof(_ary)/sizeof(*(_ary)))

/* Prefix for logging messages */
#define WDS_LOG_PREFIX "wd-security"

/* Name of environment variable which may be set to an integer
 * 0, 1, 2 etc to control the logging level */
#define WDS_LOGLEVEL_ENV "WDS_DEBUG"

/* WD Security constants and limits */
#define WD_SECURITY_VSC_SIG 0x45
#define WD_SECURITY_MODE_PAGE_SIG 0x30
#define WD_SECURITY_MAX_CIPHERS 255

/* SCSI Mode Sense Page Codes */
#define WD_SECURITY_DEVICE_CONFIGURATION_PAGE_CODE 0x20
#define WD_SECURITY_OPERATIONS_PAGE_CODE 0x21

/* setpw flag bits */
#define WD_SECURITY_OLDDEF 0x01   /* current password is default */
#define WD_SECURITY_NEWDEF 0x10   /* set new password to default */

/* erase flag bits */
#define WD_SECURITY_COMBINE 0x01  /* combine key with on-device RNG bits */

/* SCSI Sense Buffer error_code_bits helper macros */
#define SCSI_SB_INFO_VALID_MASK 0x80
#define SCSI_SB_ERROR_CODE_MASK 0x7f
#define SCSI_SB_INFO_VALID(_ecb) ((_ecb) & SCSI_SB_INFO_VALID_MASK)
#define SCSI_SB_ERROR_CODE(_ecb) ((_ecb) & SCSI_SB_ERROR_CODE_MASK)
#define SCSI_SB_CURRENT_ERRORS  0x70
#define SCSI_SB_DEFERRED_ERRORS 0x71

/* SCSI Sense Buffer sense_key_bits helper macros */
#define SCSI_SB_FILEMARK_MASK   0x80
#define SCSI_SB_EOM_MASK        0x40   /* End Of Media */
#define SCSI_SB_ILI_MASK        0x20   /* Incorrect Length */
#define SCSI_SB_SDAT_OVFL_MASK  0x10
#define SCSI_SB_SENSE_KEY_MASK  0x0f

#define SCSI_SB_FILEMARK(_skb)   ((_skb) & SCSI_SB_FILEMARK_MASK)
#define SCSI_SB_EOM(_skb)        ((_skb) & SCSI_SB_EOM_MASK)
#define SCSI_SB_ILI(_skb)        ((_skb) & SCSI_SB_ILI_MASK)
#define SCSI_SB_SDAT_OVFL(_skb)  ((_skb) & SCSI_SB_SDAT_OVFL_MASK)
#define SCSI_SB_SENSE_KEY(_skb)  ((_skb) & SCSI_SB_SENSE_KEY_MASK)

/* SCSI Sense Buffer sense_key_specific helper macros */
#define SCSI_SB_SKSV_MASK       0x80    /* Sense Key Specific Valid? */
#define SCSI_SB_SKSV(_sksb)     ((_sksb) & SCSI_SB_SKSV_MASK)

/* SCSI sense buffer constants */

#define SCSI_ASC_INVALID_COMMAND_OPERATION 0x20
#define SCSI_ASC_INVALID_CDB_FIELD 0x24
#define SCSI_ASC_INVALID_PARAM_FIELD 0x26
#define SCSI_ASC_SECURITY_ERROR 0x74

/* SCSI Mode Sense/Select constants */

/* Page Control constants */
#define SCSI_MS_PC_CURRENT     0x00
#define SCSI_MS_PC_CHANGEABLE  0x01
#define SCSI_MS_PC_DEFAULT     0x02
#define SCSI_MS_PC_SAVED       0x03
#define SCSI_MS_PC_MASK        0xc0

/* Page Code bits */
#define SCSI_MS_PAGE_CODE_MASK 0x3f
#define SCSI_MS_SPF_BIT        0x40
#define SCSI_MS_PS_BIT         0x80

#define SCSI_MS_PAGE_CODE(_bits) ((_bits) & SCSI_MS_PAGE_CODE_MASK)

/* flag bits */
#define SCSI_MS_SP_BIT         0x01
#define SCSI_MS_DBD_BIT        0x08

/* SCSI Error helper macros */

/*
 * Make WD_SECURITY_ESCSI
 * (sg_io_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK &&
 * sg_io_hdr.masked_status != CHECK_CONDITION
 */
#define MAKE_SG_ERROR(_sghdr) \
	((((unsigned)(_sghdr).masked_status) << 8) | WD_SECURITY_ESCSI)

/*
 * Make WD_SECURITY_ESENSE
 * sg_io_hdr.masked_status == CHECK_CONDITION &&
 * SCSI_SB_ERROR_CODE(sense_data_packed.error_code_bits) is NOT
 *   SCSI_SB_CURRENT_ERRORS or SCSI_SB_DEFERRED_ERRORS
 */
#define MAKE_SENSE_ERROR(_sdp) ( \
	(((unsigned)SCSI_SB_ERROR_CODE((_sdp)->error_code_bits)) << 16) | \
	(((unsigned)SCSI_SB_SENSE_KEY((_sdp)->sense_key_bits))   <<  8) | \
	WD_SECURITY_ESENSE \
)

/*
 * Make WD_SECURITY_EKCQ
 * sg_io_hdr.masked_status == CHECK_CONDITION &&
 * SCSI_SB_ERROR_CODE(sense_data_packed.error_code_bits) is
 * SCSI_SB_CURRENT_ERRORS or SCSI_SB_DEFERRED_ERRORS
 */
#define MAKE_KCQ_ERROR(_sdp) ( \
	(((unsigned)(SCSI_SB_ERROR_CODE((_sdp)->error_code_bits) & 0x01)) << 28) | \
	(((unsigned)SCSI_SB_SENSE_KEY((_sdp)->sense_key_bits)) << 24) | \
	(((unsigned)((_sdp)->asc))                             << 16) | \
	(((unsigned)((_sdp)->ascq))                            <<  8) | \
	WD_SECURITY_EKCQ \
)

/* Logging levels */
enum log_level { DIE = 0, ERROR, WARNING, INFO, DEBUG, DEBUG2 };

static enum log_level log_level = DIE;

/* WD Security constants */
const uint8_t wd_security_default_salt[] = {
	'W', 0x00, 'D', 0x00, 'C', 0x00, '.', 0x00
};
static const uint8_t wd_security_handy_store_security_sig[] = {
	0x00, 0x01, 'D', 'W'
};
static const uint8_t wd_security_handy_store_user_sig[] = {
	0x00, 0x02, 'D', 'W'
};

/* Necessary ??? */
static int wds_log_level (int level)
{
	enum log_level old_level = log_level;
	log_level = level;
	return old_level;
}

static __attribute__((format (printf, 3, 0)))
void vmesg (enum log_level level, const char *suffix, const char *fmt,
		va_list ap)
{
	if (log_level >= level) {
		char msg[4096];
		int c = '!';

		switch (level) {
		case DEBUG2:
		case DEBUG:
			c = 'D';
			break;
		case ERROR:
			c = 'E';
			break;
		case WARNING:
			c = 'W';
			break;
		case INFO:
			c = 'I';
			break;
		case DIE:
			c = '*';
			break;
		}

		vsnprintf(msg, sizeof(msg), fmt, ap);

		if (suffix)
			fprintf(stderr, WDS_LOG_PREFIX " [%c]: %s: %s\n",
					c, msg, suffix);
		else
			fprintf(stderr, WDS_LOG_PREFIX " [%c]: %s\n", c, msg);
	}

	if (level == DIE)
		abort();
}

static __attribute__((format (printf, 2, 3)))
void mesg (enum log_level level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vmesg(level, NULL, fmt, ap);
	va_end(ap);
}

static __attribute__((format (printf, 2, 3)))
void mesg_errno (enum log_level level, const char *fmt, ...)
{
	va_list ap;
	va_start(ap, fmt);
	vmesg(level, strerror(errno), fmt, ap);
	va_end(ap);
}

#define die_errno(...) mesg_errno(DIE, __VA_ARGS__)

static void hexdump (enum log_level level, const char *label,
		const uint8_t* bytes, unsigned len)
{
	unsigned i;

	if (log_level < level)
		return;

	fputs(label, stderr);
	for (i = 0; i < len; i++)
		fprintf(stderr, " 0x%.2" PRIx8, bytes[i]);
	putc('\n', stderr);
}

static __attribute__((malloc, alloc_size(1)))
void* xmalloc (size_t sz)
{
	void *ptr = malloc(sz);
	if (!ptr)
		die_errno("memory allocation failed");
	return ptr;
}

static __attribute__((malloc, alloc_size(1, 2)))
void* xcalloc (size_t nm, size_t sz)
{
	void *ptr = calloc(nm, sz);
	if (!ptr)
		die_errno("memory allocation failed");
	return ptr;
}

struct wds_handle {
	int fd;
	unsigned int timeout;
	uint8_t salt[8];
	uint32_t iterations;
	unsigned status_loaded:1;          /* cipher, kek_size valid */
	unsigned security_block_loaded:1;  /* iterations, salt valid */
	uint16_t kek_size;
	uint8_t cipher;
};

#if 0
/* Are these useful at all ???  Maybe for non-FDE encryption when the
 * encrypted DEK is accessible ?? */
/* Default 32-byte Key Encryption Key (KEK) */
static const uint8_t default_kek_aes_256_ecb[] = {
	0x03, 0x14, 0x15, 0x92, 0x65, 0x35, 0x89, 0x79,
	0x32, 0x38, 0x46, 0x26, 0x43, 0x38, 0x32, 0x79,
	0xFC, 0xEB, 0xEA, 0x6D, 0x9A, 0xCA, 0x76, 0x86,
	0xCD, 0xC7, 0xB9, 0xD9, 0xBC, 0xC7, 0xCD, 0x86
};

/* Default 16-byte Key Encryption Key (KEK) */
static const uint8_t default_kek_aes_128_ecb[] = {
	0x03, 0x14, 0x15, 0x92, 0x65, 0x35, 0x89, 0x79,
	0x2B, 0x99, 0x2D, 0xDF, 0xA2, 0x32, 0x49, 0xD6
};
#endif

static const struct {
	uint8_t mode;
	const char *name;
} cipher_names[] = {
	{ WD_SECURITY_CIPHER_NONE,        "No Encryption" },
	{ WD_SECURITY_CIPHER_AES_128_ECB, "AES-128-ECB" },
	{ WD_SECURITY_CIPHER_AES_128_CBC, "AES-128-CBC" },
	{ WD_SECURITY_CIPHER_AES_128_XTS, "AES-128-XTS" },
	{ WD_SECURITY_CIPHER_AES_256_ECB, "AES-256-ECB" },
	{ WD_SECURITY_CIPHER_AES_256_CBC, "AES-256-CBC" },
	{ WD_SECURITY_CIPHER_AES_256_XTS, "AES-256-XTS" },
	{ WD_SECURITY_CIPHER_FDE,         "Full Disk Encryption" }
};

static const char* const status_names[] = {
	[WD_SECURITY_STATUS_NOPASSWD]  = "Not Protected",
	[WD_SECURITY_STATUS_LOCKED]    = "Locked",
	[WD_SECURITY_STATUS_UNLOCKED]  = "Unlocked",
	[WD_SECURITY_STATUS_LOCKEDOUT] = "Locked Out",
	[WD_SECURITY_STATUS_NOKEY]     = "No Encryption Key"
};

static const char* const error_names[] = {
	"Success",
	"System call failed",       /* ESYSCALL */
	"Bad signature",            /* ESIG */
	"Block size unsupported",   /* ESIZE */
	"Bad checksum",             /* ECHKSUM */
	"SHA256 hash failed",       /* ECRYPTO */
	"Not locked",               /* ENOTLOCKED */
	"Locked out",               /* ELOCKEDOUT */
	"Authentication failed",    /* EAUTH */
	"No KEK or bad size",       /* EKEK */
	"KEK too big",              /* E2BIG */
	"Invalid reset SYN",        /* EBADSYN */
	"Bad cipher or key length", /* ECIPHER */
	"Locked",                   /* ELOCKED */
	"Not supported",            /* ENOTSUP */
	"Bad SCSI response",        /* EBADRESP */
};

/* WD Vendor Specific SCSI Commands (VSC) Command Descriptor Block (CDB) */

struct __attribute__((packed)) wds_vsc_cdb {
	uint8_t code;
	uint8_t subcode;
	uint32_t address;
	uint8_t reserved;
	uint16_t length;
	uint8_t control;
};

/* Initialization constants for wds_vsc_cdb struct */

#define WD_SECURITY_VSC_CDB_STATUS_INIT \
	{ 0xc0, 0x45, 0x00000000, 0x00, 0x0000, 0x00 }
#define WD_SECURITY_VSC_CDB_UNLOCK_INIT \
	{ 0xc1, 0xe1, 0x00000000, 0x00, 0x0000, 0x00 }
#define WD_SECURITY_VSC_CDB_SETPW_INIT \
	{ 0xc1, 0xe2, 0x00000000, 0x00, 0x0000, 0x00 }
#define WD_SECURITY_VSC_CDB_ERASE_INIT \
	{ 0xc1, 0xe3, 0x00000000, 0x00, 0x0000, 0x00 }
#define WD_SECURITY_VSC_CDB_HANDY_CAPACITY_INIT \
	{ 0xd5, 0x00, 0x00000000, 0x00, 0x0000, 0x00 }
#define WD_SECURITY_VSC_CDB_HANDY_STORE_RD_INIT \
	{ 0xd8, 0x00, 0x00000000, 0x00, 0x0000, 0x00 }
#define WD_SECURITY_VSC_CDB_HANDY_STORE_WR_INIT \
	{ 0xda, 0x00, 0x00000000, 0x00, 0x0000, 0x00 }

/* SCSI Mode Sense/Select Command Descriptor Block (CDB) */

struct __attribute__((packed)) mode_sense_6_cdb {
	uint8_t code;            /* 0x1a */
	uint8_t flag_bits;       /* DBD:3 */
	uint8_t page_code_bits;  /* PC:6-7 PageCode:0-5 */
	uint8_t subpage_code;
	uint8_t length;
	uint8_t control;
};

struct __attribute__((packed)) mode_select_6_cdb {
	uint8_t code;            /* 0x15 */
	uint8_t flag_bits;       /* PF:4 RTD:1 SP:0 */
	uint8_t reserved[2];
	uint8_t length;
	uint8_t control;
};

struct __attribute__((packed)) mode_sense_10_cdb {
	uint8_t code;            /* 0x5a */
	uint8_t flag_bits;       /* LLBAA:4 DBD:3 */
	uint8_t page_code_bits;  /* PC:6-7 PageCode:0-5 */
	uint8_t subpage_code;
	uint8_t reserved[3];
	uint16_t length;
	uint8_t control;
};

struct __attribute__((packed)) mode_select_10_cdb {
	uint8_t code;           /* 0x55 */
	uint8_t flag_bits;      /* PF:4 SP:0 */
	uint8_t reserved[5];
	uint16_t length;
	uint8_t control;
};

/* WD Security Response Payloads */

struct __attribute__((packed)) wds_encryption_status_packed {
	uint8_t sig;
	uint8_t reserved1[2];
	uint8_t status;
	uint8_t cipher;
	uint8_t reserved2;
	uint16_t kek_size;
	uint8_t reset_syn[4];
	uint8_t reserved3[3];
	uint8_t num_ciphers;
	uint8_t ciphers[FLEXIBLE_ARRAY_MEMBER];
};

struct __attribute__((packed)) wds_encryption_unlock_packed {
	uint8_t sig;
	uint8_t reserved[5];
	uint16_t length;
	uint8_t kek[FLEXIBLE_ARRAY_MEMBER];
};

struct __attribute__((packed)) wds_encryption_setpw_packed {
	uint8_t sig;
	uint8_t reserved1[2];
	uint8_t flag_bits;
	uint8_t reserved2[2];
	uint16_t length;
	uint8_t kek[FLEXIBLE_ARRAY_MEMBER];
};

struct __attribute__((packed)) wds_encryption_erase_packed {
	uint8_t sig;
	uint8_t reserved1[2];
	uint8_t flag_bits;
	uint8_t cipher;
	uint8_t reserved2;
	uint16_t length;
	uint8_t key[FLEXIBLE_ARRAY_MEMBER];
};

struct __attribute__((packed)) wds_handy_capacity_packed {
	uint32_t last_block;
	uint32_t length;
	uint8_t reserved[2];
	uint16_t max_xfer_len;
};

struct __attribute__((packed)) wds_handy_store_security_block_packed {
	uint8_t sig[4];
	uint8_t reserved1[4];
	uint32_t iterations;
	uint8_t salt[8];
	uint8_t reserved2[4];
	uint8_t hint[202];
	uint8_t reserved3[285];
	uint8_t checksum;
};

struct __attribute__((packed)) wds_handy_store_user_block_packed {
	uint8_t sig[4];
	uint8_t reserved1[4];
	uint8_t label[64];
	uint8_t reserved2[439];
	uint8_t checksum;
};

/* WD Security Mode Sense/Select Payloads */

struct __attribute__((packed)) scsi_mode_param_header6 {
	uint8_t mode_data_length;
	uint8_t medium_type;
	uint8_t flag_bits;      /* WP:7 DPOFUA:4 */
	uint8_t block_desc_length;
};

struct __attribute__((packed)) scsi_mode_param_header10 {
	uint16_t mode_data_length;
	uint8_t medium_type;
	uint8_t flag1_bits;     /* WP:7 DPOFUA:4 */
	uint8_t flag2_bits;     /* LONGLBA:0 */
	uint8_t reserved;
	uint16_t block_descriptor_length;
};

struct __attribute__((packed)) wds_config_mode_page_packed {
	uint8_t page_code_bits; /* PS:7 SPF:6 PageCode:0-5 */
	uint8_t page_length;
	uint8_t sig;
	uint8_t reserved1;
	uint8_t flag1_bits;     /* DisAP:7 DisCD:1 DisSES:0 */
	uint8_t flag2_bits;     /* 2TBL:1 DisWL:0 */
	uint8_t reserved2[2];
};

struct __attribute__((packed)) wds_operations_mode_page_packed {
	uint8_t page_code_bits; /* PS:7 SPF:6 PageCode:0-5 */
	uint8_t page_length;
	uint8_t sig;
	uint8_t reserved1;
	uint8_t flag1_bits;     /* LOOSESB2:1 ESATA15:0 */
	uint8_t flag2_bits;     /* CDMVALID:1 ENCDEJ:0 */
	uint8_t reserved2[2];
	uint8_t power_led_brite;
	uint8_t backlight_brite;
	uint8_t flag3_bits;     /* INVLCD:0 */
	uint8_t reserved3;
};

/* SCSI Sense Buffer Data
 * ref. https://tldp.org/HOWTO/archived/SCSI-Programming-HOWTO/SCSI-Programming-HOWTO-10.html */
struct __attribute__((packed)) sense_data_packed {
	uint8_t error_code_bits;      /* MSb indicates .information is valid */
	uint8_t reserved;
	uint8_t sense_key_bits;  /* Filemark, EOM, ILI, SDAT_OVFL, Sense Key */
	uint32_t information;
	uint8_t additional_sense_length;  /* size of additional_sense_bytes */
	uint32_t command_specific_info;
	uint8_t asc;                      /* Additional Sense Code */
	uint8_t ascq;                     /* Additional Sense Code Qualifier */
	uint8_t field_replaceable_unit_code;
	uint8_t sense_key_specific[3];
	uint8_t additional_sense_bytes[FLEXIBLE_ARRAY_MEMBER];
};

static struct wds_encryption_status* unpack_encryption_status (
		const struct wds_encryption_status_packed *packed)
{
	struct wds_encryption_status *unpacked;
	unsigned i;

	unpacked = xmalloc(offsetof (struct wds_encryption_status, ciphers) +
			packed->num_ciphers);
	unpacked->status = packed->status;
	unpacked->cipher = packed->cipher;
	unpacked->kek_size = be16toh(packed->kek_size);
	for (i = 0; i < ARRAY_LEN(unpacked->reset_syn); i++)
		unpacked->reset_syn[i] = packed->reset_syn[i];
	unpacked->num_ciphers = packed->num_ciphers;
	for (i = 0; i < unpacked->num_ciphers; i++)
		unpacked->ciphers[i] = packed->ciphers[i];

	return unpacked;
}

static void unpack_handy_capacity (
		const struct wds_handy_capacity_packed *packed,
		struct wds_handy_capacity *unpacked)
{
	unpacked->last_block = be32toh(packed->last_block);
	unpacked->length = be32toh(packed->length);
	unpacked->max_xfer_len = be16toh(packed->max_xfer_len);
}

static void unpack_handy_store_security_block (
		const struct wds_handy_store_security_block_packed *packed,
		struct wds_handy_store_security_block *unpacked)
{
	/*
	 * WD Security probably stores iterations in *native* byte-order
	 * and not explicitly in little-endian byte order.  But since
	 * it's most likely that the security block will have been
	 * created on x86, let's assume LE so we do the right thing on
	 * BE platforms.
	 */
	unpacked->iterations = le32toh(packed->iterations);
	memcpy(unpacked->salt, packed->salt, sizeof(packed->salt));
	memcpy(unpacked->hint, packed->hint, sizeof(packed->hint));
}

static void unpack_handy_store_user_block (
		const struct wds_handy_store_user_block_packed *packed,
		struct wds_handy_store_user_block* unpacked)
{
	memcpy(unpacked->label, packed->label, sizeof(packed->label));
}

const char* wds_cipher_to_string (unsigned cipher) {
	unsigned i;
	for (i = 0; i < ARRAY_LEN(cipher_names); i++)
		if (cipher_names[i].mode == cipher)
			return cipher_names[i].name;
	return "unknown";
}

uint8_t wds_string_to_cipher (const char* name) {
	unsigned i;
	for (i = 0; i < ARRAY_LEN(cipher_names); i++)
		if (!strcmp(cipher_names[i].name, name))
			return cipher_names[i].mode;
	return (uint8_t)-1;
}

const char* wds_status_to_string (unsigned status) {
	if (status < ARRAY_LEN(status_names) && status_names[status])
		return status_names[status];
	return "unknown";
}

const char* wds_strerror (int err) {
	static char buf[128];

	if (err >= 0 && (size_t)err < ARRAY_LEN(error_names))
		return error_names[err];

	switch (WDS_STATUS(err)) {
	case WD_SECURITY_ESCSI:
		snprintf(buf, sizeof(buf),
				"SCSI operation failed with status (0x%hhx)",
				WDS_ESCSI_STATUS(err));
		return  buf;
	case WD_SECURITY_ESENSE:
		snprintf(buf, sizeof(buf), "SCSI operation failed with status "
				"CHECK_CONDITION ("
				"sense code 0x%hhx, "
				"sense key 0x%hhx)",
				WDS_ESENSE_ERROR_CODE(err),
				WDS_ESENSE_SENSE_KEY(err));
		return  buf;
	case WD_SECURITY_EKCQ:
		snprintf(buf, sizeof(buf), "SCSI operation failed with status "
				"CHECK_CONDITION (%s Errors, "
				"sense key 0x%hhx, "
				"ASC 0x%hhx, "
				"ASCQ 0x%hhx)",
				WDS_EKCQ_IS_DEFERRED(err) ?
				"Deferred" : "Current",
				WDS_EKCQ_SENSE_KEY(err),
				WDS_EKCQ_ASC(err),
				WDS_EKCQ_ASCQ(err));
		return  buf;
	}

	return "unknown";
}

static int decode_sense_data_generic (const struct sense_data_packed *sdp)
{
	switch (SCSI_SB_ERROR_CODE(sdp->error_code_bits)) {
	case SCSI_SB_CURRENT_ERRORS:
		mesg(DEBUG, "SCSI Sense Data Current Errors: "
			    "Sense Key (0x%.2" PRIx8 ") "
			    "ASC (0x%.2" PRIx8 ") "
			    "ASCQ (0x%.2" PRIx8 ")",
			    SCSI_SB_SENSE_KEY(sdp->sense_key_bits),
			    sdp->asc,
			    sdp->ascq);
		return MAKE_KCQ_ERROR(sdp);
	case SCSI_SB_DEFERRED_ERRORS:
		mesg(DEBUG, "SCSI Sense Data Deferred Errors: "
			    "Sense Key (0x%.2" PRIx8 ") "
			    "ASC (0x%.2" PRIx8 ") "
			    "ASCQ (0x%.2" PRIx8 ")",
			    SCSI_SB_SENSE_KEY(sdp->sense_key_bits),
			    sdp->asc,
			    sdp->ascq);
		return MAKE_KCQ_ERROR(sdp);
	}

	mesg(DEBUG, "SCSI Sense Data: "
		    "Error Code (0x%.2" PRIx8 ") "
		    "Sense Key (0x%.2" PRIx8 ")",
		    SCSI_SB_ERROR_CODE(sdp->error_code_bits),
		    SCSI_SB_SENSE_KEY(sdp->sense_key_bits));
	return MAKE_SENSE_ERROR(sdp);
}

static int scsi_cmd (int fd, unsigned int timeout, unsigned char *cmdp,
		unsigned char cmd_len, int dxfer_direction,
		unsigned short iovec_count, void *dxferp,
		unsigned int *dxfer_len,
		int (*decode_sense) (const struct sense_data_packed*))
{
	sg_io_hdr_t sg_hdr;
	unsigned char sensb[sizeof(struct sense_data_packed)];

	hexdump(DEBUG2, "SCSI CDB:", (uint8_t*)cmdp, cmd_len);

	memset(sensb, 0, sizeof(sensb));

	memset(&sg_hdr, 0, sizeof(sg_hdr));
	sg_hdr.interface_id = 'S';
	sg_hdr.dxfer_direction = dxfer_direction;
	sg_hdr.cmd_len = cmd_len;
	sg_hdr.mx_sb_len = sizeof(sensb);
	sg_hdr.iovec_count = iovec_count;
	sg_hdr.dxfer_len = *dxfer_len;
	sg_hdr.dxferp = dxferp;
	sg_hdr.cmdp = cmdp;
	sg_hdr.sbp = sensb;
	sg_hdr.timeout = timeout;

	if (ioctl(fd, SG_IO, &sg_hdr)) {
		mesg_errno(ERROR, "SCSI ioctl failed");
		return WD_SECURITY_ESYSCALL;
	}

	if ((sg_hdr.info & SG_INFO_OK_MASK) != SG_INFO_OK) {
		mesg(ERROR, "SCSI command failed");
		if (sg_hdr.masked_status == CHECK_CONDITION) {
			hexdump(DEBUG2, "Sense Buffer:", sensb, sg_hdr.sb_len_wr);
			if (!decode_sense)
				decode_sense = decode_sense_data_generic;
			return decode_sense((struct sense_data_packed*)sensb);
		}
		mesg(DEBUG, "SCSI error ("
			    "status: 0x%.2hhx, "
			    "masked_status: 0x%.2hhx, "
			    "msg_status: 0x%.2hhx, "
			    "host_status: 0x%.4hx, "
			    "driver_status: 0x%.4hx)",
			    sg_hdr.status,
			    sg_hdr.masked_status,
			    sg_hdr.msg_status,
			    sg_hdr.host_status,
			    sg_hdr.driver_status);
		return MAKE_SG_ERROR(sg_hdr);
	}

	*dxfer_len -= sg_hdr.resid;

	if (dxfer_direction == SG_DXFER_FROM_DEV ||
	    dxfer_direction == SG_DXFER_TO_FROM_DEV)
	{
		hexdump(DEBUG2, "SCSI Command Response:", dxferp, *dxfer_len);
	}

	return 0;
}

struct wds_handle* wds_open (const char *device, const struct wds_opts *opts,
		int *err)
{
	struct wds_handle *h;
	const char *loglevel_env;
	int fd;
	int ver;

	loglevel_env = getenv(WDS_LOGLEVEL_ENV);
	if (loglevel_env) {
		char *endptr;
		long level;
		errno = 0;
		level = strtol(loglevel_env, &endptr, 10);
		/* ensure no error, and *some* of the string was consumed */
		if (!errno && endptr != loglevel_env) {
			if (level > INT_MAX)
				level = INT_MAX;
			else if (level < INT_MIN)
				level = INT_MIN;
			wds_log_level(level);
		}
	}

	fd = open(device, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		mesg_errno(ERROR, "failed opening WD Security device \"%s\"",
				device);
		if (err)
			*err = WD_SECURITY_ESYSCALL;
		return NULL;
	}

	if (ioctl(fd, SG_GET_VERSION_NUM, &ver)) {
		mesg_errno(ERROR, "ioctl failed getting SCSI Generic Version Number");
		if (err)
			*err = WD_SECURITY_ESYSCALL;
		close(fd);
		return NULL;
	}

	mesg(INFO, "SCSI Generic Version %d", ver);

	if (ver < 30000) {
		mesg(ERROR, "not a SCSI Generic device, or driver too old");
		if (err)
			*err = WD_SECURITY_ENOTSUP;
		close(fd);
		return NULL;
	}

	h = xcalloc(1, sizeof(*h));
	h->fd = fd;
	if (opts) {
		if (opts->timeout_ms)
			h->timeout = opts->timeout_ms;
	}

	return h;
}

int wds_close (struct wds_handle *h) {
	int err = 0;

	if (close(h->fd)) {
		mesg_errno(ERROR, "failed closing WD Security device");
		err = WD_SECURITY_ESYSCALL;
	}

	free(h);

	return err;
}

struct wds_encryption_status* wds_get_status (struct wds_handle *wds, int *err)
{
	const struct wds_encryption_status_packed *esp;
	struct wds_encryption_status *es;
	struct wds_vsc_cdb cdb = WD_SECURITY_VSC_CDB_STATUS_INIT;
	unsigned char buf[sizeof(struct wds_encryption_status_packed) +
		WD_SECURITY_MAX_CIPHERS];
	unsigned int dxfer_len;
	int e;

	cdb.length = htobe16(sizeof(buf));

	dxfer_len = sizeof(buf);
	e = scsi_cmd(wds->fd, wds->timeout, (unsigned char*)&cdb, sizeof(cdb),
			SG_DXFER_FROM_DEV, 0, buf, &dxfer_len, NULL);
	if (e) {
		if (err)
			*err = e;
		return NULL;
	}

	esp = (const struct wds_encryption_status_packed*) &buf;

	if (esp->sig != WD_SECURITY_VSC_SIG) {
		mesg(ERROR, "bad signature in encryption status response, "
				"expected 0x%.2" PRIx8 ", got 0x%.2" PRIx8,
				WD_SECURITY_VSC_SIG, esp->sig);
		if (err)
			*err = WD_SECURITY_ESIG;
		return NULL;
	}

	es = unpack_encryption_status(esp);

	/* cache the cipher and kek size */
	wds->cipher = es->cipher;
	wds->kek_size = es->kek_size;
	wds->status_loaded = 1;

	return es;
}

static int scsi_set_mode_page6 (int fd, unsigned int timeout, int save_pages,
		void *mp, uint8_t mp_len)
{
	sg_iovec_t iov[2];
	struct scsi_mode_param_header6 mp_hdr;
	struct mode_select_6_cdb cdb;
	unsigned int dxfer_len;

	memset(&mp_hdr, 0, sizeof(mp_hdr));
	/* mp_hdr.mode_data_length =; reserved for mode select */
	mp_hdr.medium_type = TYPE_DISK; /* really necessary? */

	iov[0].iov_base = &mp_hdr;
	iov[0].iov_len = sizeof(mp_hdr);
	iov[1].iov_base = mp;
	iov[1].iov_len = mp_len;

	dxfer_len = iov[0].iov_len + iov[1].iov_len;

	memset(&cdb, 0, sizeof(cdb));

	cdb.code = MODE_SELECT;
	if (save_pages)
		cdb.flag_bits = SCSI_MS_SP_BIT;
	cdb.length = dxfer_len;

	return scsi_cmd(fd, timeout, (unsigned char*)&cdb, sizeof(cdb),
		SG_DXFER_TO_DEV, ARRAY_LEN(iov), iov, &dxfer_len, NULL);
}

static int scsi_set_mode_page10 (int fd, unsigned int timeout, int save_pages,
		void *mp, uint8_t mp_len)
{
	sg_iovec_t iov[2];
	struct scsi_mode_param_header10 mp_hdr;
	struct mode_select_10_cdb cdb;
	unsigned int dxfer_len;

	memset(&mp_hdr, 0, sizeof(mp_hdr));
	/* mp_hdr.mode_data_length =; reserved for mode select */
	mp_hdr.medium_type = TYPE_DISK; /* really necessary? */

	iov[0].iov_base = &mp_hdr;
	iov[0].iov_len = sizeof(mp_hdr);
	iov[1].iov_base = mp;
	iov[1].iov_len = mp_len;

	dxfer_len = iov[0].iov_len + iov[1].iov_len;

	memset(&cdb, 0, sizeof(cdb));

	cdb.code = MODE_SELECT_10;
	if (save_pages)
		cdb.flag_bits = SCSI_MS_SP_BIT;
	cdb.length = htobe16((uint16_t)dxfer_len);

	return scsi_cmd(fd, timeout, (unsigned char*)&cdb, sizeof(cdb),
		SG_DXFER_TO_DEV, ARRAY_LEN(iov), iov, &dxfer_len, NULL);
}

static int scsi_set_mode_page (int fd, unsigned int timeout, int save_pages,
		void *mp, uint8_t mp_len)
{
	int err;

	err = scsi_set_mode_page10(fd, timeout, save_pages, mp, mp_len);
	if (err) {
		if ((WDS_ESCSI_STATUS(err) == WD_SECURITY_EKCQ &&
		     WDS_EKCQ_SENSE_KEY(err) == ILLEGAL_REQUEST &&
		     WDS_EKCQ_ASC(err) == SCSI_ASC_INVALID_COMMAND_OPERATION) ||
		    (WDS_ESCSI_STATUS(err) == WD_SECURITY_ESENSE &&
		     WDS_ESENSE_SENSE_KEY(err) == ILLEGAL_REQUEST))
		{
			/* If the SCSI command fails with ILLEGAL_REQUEST, then
			 * maybe the device doesn't support 10-byte commands.
			 * Retry using the 6-byte command */
			return scsi_set_mode_page6(fd, timeout, save_pages, mp,
				mp_len);
		}
	}

	return err;
}

static int scsi_get_mode_page_6 (int fd, unsigned int timeout,
		uint8_t page_control, uint8_t page_code, void *mp,
		uint8_t *mp_len)
{
	sg_iovec_t iov[2];
	struct scsi_mode_param_header6 mp_hdr;
	struct mode_sense_6_cdb cdb;
	unsigned int dxfer_len;
	int err;

	iov[0].iov_base = &mp_hdr;
	iov[0].iov_len = sizeof(mp_hdr);
	iov[1].iov_base = mp;
	iov[1].iov_len = *mp_len;

	dxfer_len = iov[0].iov_len + iov[1].iov_len;

	memset(&cdb, 0, sizeof(cdb));

	cdb.code = MODE_SENSE;
	cdb.flag_bits = SCSI_MS_DBD_BIT;  /* disable block descriptors */
	cdb.page_code_bits = (page_control << 6 & SCSI_MS_PC_MASK) |
			     (page_code & SCSI_MS_PAGE_CODE_MASK);
	cdb.length = dxfer_len;

	err = scsi_cmd(fd, timeout, (unsigned char*)&cdb, sizeof(cdb),
		SG_DXFER_FROM_DEV, ARRAY_LEN(iov), iov, &dxfer_len, NULL);
	if (err)
		return err;

	if (dxfer_len < sizeof(mp_hdr)) {
		mesg(ERROR, "SCSI Mode Page(6) too small, expected %zu, got %u",
			sizeof(mp_hdr), dxfer_len);
		return WD_SECURITY_EBADRESP;
	}

	mesg(DEBUG2, "SCSI Mode Page(6) Header: "
		"mode data length (%" PRIu8 ") "
		"medium type (%" PRIu8 ") "
		"block descriptor length (%" PRIu8 ")",
		mp_hdr.mode_data_length,
		mp_hdr.medium_type,
		mp_hdr.block_desc_length);

	/* Should never happen since we set the DBD bit */
	if (mp_hdr.block_desc_length) {
		mesg(ERROR, "SCSI Mode Page(6) non-zero block descriptor "
			"length");
		return WD_SECURITY_EBADRESP;
	}

	if ((unsigned)mp_hdr.mode_data_length + 1 < dxfer_len) {
		mesg(WARNING, "SCSI Mode Page(6) data length (%" PRIu8 ") is "
			"smaller than dxfer_len(%u)",
			mp_hdr.mode_data_length + 1,
			dxfer_len);
		dxfer_len = mp_hdr.mode_data_length + 1;
	}

	if (dxfer_len > sizeof(mp_hdr))
		*mp_len = dxfer_len - sizeof(mp_hdr);
	else
		*mp_len = 0;

	return 0;
}

static int scsi_get_mode_page_10 (int fd, unsigned int timeout,
		uint8_t page_control, uint8_t page_code, void *mp,
		uint8_t *mp_len)
{
	sg_iovec_t iov[2];
	struct scsi_mode_param_header10 mp_hdr;
	struct mode_sense_10_cdb cdb;
	unsigned int dxfer_len;
	uint16_t mode_data_length;
	uint16_t block_desc_length;
	int err;

	iov[0].iov_base = &mp_hdr;
	iov[0].iov_len = sizeof(mp_hdr);
	iov[1].iov_base = mp;
	iov[1].iov_len = *mp_len;

	dxfer_len = iov[0].iov_len + iov[1].iov_len;

	memset(&cdb, 0, sizeof(cdb));

	cdb.code = MODE_SENSE_10;
	cdb.flag_bits = SCSI_MS_DBD_BIT; /* disable block descriptors */
	cdb.page_code_bits = (page_control << 6 & SCSI_MS_PC_MASK) |
			     (page_code & SCSI_MS_PAGE_CODE_MASK);
	cdb.length = htobe16((uint16_t)dxfer_len);

	err = scsi_cmd(fd, timeout, (unsigned char*)&cdb, sizeof(cdb),
		SG_DXFER_FROM_DEV, 2, iov, &dxfer_len, NULL);
	if (err)
		return err;

	if (dxfer_len < sizeof(mp_hdr)) {
		mesg(ERROR, "SCSI Mode Page(10) too small, expected %zu, got %u",
			sizeof(mp_hdr), dxfer_len);
		return WD_SECURITY_EBADRESP;
	}

	mode_data_length = be16toh(mp_hdr.mode_data_length);
	block_desc_length = be16toh(mp_hdr.block_descriptor_length);

	mesg(DEBUG2, "SCSI Mode Page(10) Header: "
		"mode data length (%" PRIu16 ") "
		"medium type (%" PRIu8 ") "
		"block descriptor length (%" PRIu16 ")",
		mode_data_length,
		mp_hdr.medium_type,
		block_desc_length);

	/* Should never happen since we set the DBD bit */
	if (block_desc_length) {
		mesg(ERROR, "SCSI Mode Page(10) non-zero block descriptor "
			"length");
		return WD_SECURITY_EBADRESP;
	}

	if ((unsigned)mode_data_length + sizeof(uint16_t) < dxfer_len) {
		mesg(WARNING, "SCSI Mode Page(10) data length (%zu) is "
			"smaller than dxfer_len(%u)",
			mode_data_length + sizeof(uint16_t),
			dxfer_len);
		dxfer_len = mode_data_length + sizeof(uint16_t);
	}

	if (dxfer_len > sizeof(mp_hdr))
		*mp_len = dxfer_len - sizeof(mp_hdr);
	else
		*mp_len = 0;

	return 0;
}

static int scsi_get_mode_page (int fd, unsigned int timeout,
		uint8_t page_control, uint8_t page_code, void *mp,
		uint8_t *mp_len)
{
	int err;

	err = scsi_get_mode_page_10(fd, timeout, page_control, page_code, mp,
		mp_len);
	if (err) {
		if ((WDS_ESCSI_STATUS(err) == WD_SECURITY_EKCQ &&
		     WDS_EKCQ_SENSE_KEY(err) == ILLEGAL_REQUEST &&
		     WDS_EKCQ_ASC(err) == SCSI_ASC_INVALID_COMMAND_OPERATION) ||
		    (WDS_ESCSI_STATUS(err) == WD_SECURITY_ESENSE &&
		     WDS_ESENSE_SENSE_KEY(err) == ILLEGAL_REQUEST))
		{
			/* If the SCSI command fails with ILLEGAL_REQUEST, then
			 * maybe the device doesn't support the 10-byte
			 * mode sense command.  Try the 6-byte version */
			return scsi_get_mode_page_6(fd, timeout, page_control,
				page_code, mp, mp_len);
		}
	}

	return err;
}

static void unpack_config_mode_page (
		const struct wds_config_mode_page_packed *packed,
		struct wds_config_mode_page* unpacked)
{
	unpacked->flags = packed->flag1_bits | packed->flag2_bits << 8;
}

static void pack_config_mode_page_masked (
		const struct wds_config_mode_page *unpacked,
		const struct wds_config_mode_page *unpacked_mask,
		struct wds_config_mode_page_packed *packed)
{
	uint8_t obits;
	uint8_t nbits;
	uint8_t mask;

	obits = packed->flag1_bits;
	nbits = unpacked->flags & 0xff;
	mask = unpacked_mask->flags & 0xff;
	packed->flag1_bits = (obits & ~mask) | (nbits & mask);

	obits = packed->flag2_bits;
	nbits = (unpacked->flags >> 8) & 0xff;
	mask = (unpacked_mask->flags >> 8) & 0xff;
	packed->flag2_bits = (obits & ~mask) | (nbits & mask);
}

static int read_config_mode_page (struct wds_handle *wds, uint8_t page_control,
		struct wds_config_mode_page_packed *mpp)
{
	int err;
	uint8_t len = sizeof(*mpp);

	err = scsi_get_mode_page(wds->fd, wds->timeout, page_control,
		WD_SECURITY_DEVICE_CONFIGURATION_PAGE_CODE, mpp, &len);
	if (err)
		return err;

	if (len < sizeof(*mpp)) {
		mesg(ERROR, "Device Configuration mode page too small, "
			"expected %zu, got %" PRIu8,
			sizeof(*mpp), len);
		return WD_SECURITY_EBADRESP;
	}

	if (WDS_IS_SET(mpp->page_code_bits, SCSI_MS_SPF_BIT)) {
		mesg(ERROR, "Device Configuration mode page has SPF set");
		return WD_SECURITY_EBADRESP;
	}

	mesg(DEBUG2, "Device Configuration mode page: "
		"parameters saveable (%d) "
		"page code (0x%.2" PRIx8 ") "
		"page length (%" PRIu8 ") "
		"signature (0x%.2" PRIx8 ")",
		WDS_IS_SET(mpp->page_code_bits, SCSI_MS_PS_BIT),
		SCSI_MS_PAGE_CODE(mpp->page_code_bits),
		mpp->page_length,
		mpp->sig);

	if (SCSI_MS_PAGE_CODE(mpp->page_code_bits) !=
	    WD_SECURITY_DEVICE_CONFIGURATION_PAGE_CODE)
	{
		mesg(ERROR, "Device Configuration mode page bad page code, "
				"expected 0x%.2" PRIx8 ", got 0x%.2" PRIx8,
				WD_SECURITY_DEVICE_CONFIGURATION_PAGE_CODE,
				SCSI_MS_PAGE_CODE(mpp->page_code_bits));
		return WD_SECURITY_EBADRESP;
	}

	if (page_control != SCSI_MS_PC_CHANGEABLE &&
	    mpp->sig != WD_SECURITY_MODE_PAGE_SIG)
	{
		mesg(ERROR, "Device Configuration mode page bad signature, "
				"expected 0x%.2" PRIx8 ", got 0x%.2" PRIx8,
				WD_SECURITY_MODE_PAGE_SIG, mpp->sig);
		return WD_SECURITY_ESIG;
	}

	if (offsetof(struct wds_config_mode_page_packed, page_length) +
		mpp->page_length + 1 < sizeof(*mpp))
	{
		mesg(ERROR, "Device Configuration mode page short page length "
			"(%" PRIu8 ")", mpp->page_length);
		return WD_SECURITY_EBADRESP;
	}

	return 0;
}

int wds_read_config_mode_page (struct wds_handle *wds,
		struct wds_config_mode_page *mode_page,
		struct wds_config_mode_page *changeable)
{
	struct wds_config_mode_page_packed mpp;
	int err;

	err = read_config_mode_page(wds, SCSI_MS_PC_CURRENT, &mpp);
	if (err)
		return err;

	unpack_config_mode_page(&mpp, mode_page);

	if (changeable) {
		if (read_config_mode_page(wds, SCSI_MS_PC_CHANGEABLE, &mpp)) {
			mesg(WARNING, "failed reading \"changeable\" Device "
				"Configuration mode page, mark unchangeable");
			memset(changeable, 0, sizeof(*changeable));
		} else
			unpack_config_mode_page(&mpp, changeable);
	}

	return 0;
}

int wds_write_config_mode_page (struct wds_handle *wds,
		const struct wds_config_mode_page *mode_page,
		const struct wds_config_mode_page *mode_page_mask)
{
	struct wds_config_mode_page_packed mpp;
	int save_pages;
	int err;

	err = read_config_mode_page(wds, SCSI_MS_PC_CURRENT, &mpp);
	if (err)
		return err;

	pack_config_mode_page_masked(mode_page, mode_page_mask, &mpp);

	save_pages = WDS_IS_SET(mpp.page_code_bits, SCSI_MS_PS_BIT);

	/* clear Parameters Saveable bit, it's reserved during mode-select */
	mpp.page_code_bits &= ~SCSI_MS_PS_BIT;

	return scsi_set_mode_page(wds->fd, wds->timeout, save_pages, &mpp,
		sizeof(mpp));
}

static void unpack_operations_mode_page (
		const struct wds_operations_mode_page_packed *packed,
		struct wds_operations_mode_page* unpacked)
{
	unpacked->flags = packed->flag1_bits |
			  ((uint32_t)packed->flag2_bits << 8) |
			  ((uint32_t)packed->flag3_bits << 16);

	unpacked->power_led_brite = packed->power_led_brite;
	unpacked->backlight_brite = packed->backlight_brite;
}

static void pack_operations_mode_page_masked (
		const struct wds_operations_mode_page* unpacked,
		const struct wds_operations_mode_page* unpacked_mask,
		struct wds_operations_mode_page_packed *packed)
{
	uint8_t obits;
	uint8_t nbits;
	uint8_t mask;

	obits = packed->flag1_bits;
	nbits = unpacked->flags & 0xff;
	mask = unpacked_mask->flags & 0xff;
	packed->flag1_bits = (obits & ~mask) | (nbits & mask);

	obits = packed->flag2_bits;
	nbits = (unpacked->flags >> 8) & 0xff;
	mask = (unpacked_mask->flags >> 8) & 0xff;
	packed->flag2_bits = (obits & ~mask) | (nbits & mask);

	obits = packed->flag3_bits;
	nbits = (unpacked->flags >> 16) & 0xff;
	mask = (unpacked_mask->flags >> 16) & 0xff;
	packed->flag3_bits = (obits & ~mask) | (nbits & mask);

	if (unpacked_mask->power_led_brite)
		packed->power_led_brite = unpacked->power_led_brite;
	if (unpacked_mask->backlight_brite)
		packed->backlight_brite = unpacked->backlight_brite;
}

static int read_operations_mode_page (int fd, unsigned timeout,
		uint8_t page_control,
		struct wds_operations_mode_page_packed *mpp)
{
	int err;
	uint8_t len = sizeof(*mpp);

	err = scsi_get_mode_page(fd, timeout, page_control,
		WD_SECURITY_OPERATIONS_PAGE_CODE, mpp, &len);
	if (err)
		return err;

	if (len < sizeof(*mpp)) {
		mesg(ERROR, "Device Operations mode page too small, "
			"expected %zu, got %" PRIu8,
			sizeof(*mpp), len);
		return WD_SECURITY_EBADRESP;
	}

	if (WDS_IS_SET(mpp->page_code_bits, SCSI_MS_SPF_BIT)) {
		mesg(ERROR, "Device Operations mode page has SPF set");
		return WD_SECURITY_EBADRESP;
	}

	mesg(DEBUG2, "Device Operations mode page: "
		"parameters saveable: (%d) "
		"page code (0x%.2" PRIx8 ") "
		"page length (%" PRIu8 ") "
		"signature (0x%.2" PRIx8 ")",
		WDS_IS_SET(mpp->page_code_bits, SCSI_MS_PS_BIT),
		SCSI_MS_PAGE_CODE(mpp->page_code_bits),
		mpp->page_length,
		mpp->sig);

	if (SCSI_MS_PAGE_CODE(mpp->page_code_bits) !=
	    WD_SECURITY_OPERATIONS_PAGE_CODE)
	{
		mesg(ERROR, "Device Operations mode page bad page code, "
				"expected 0x%.2" PRIx8 ", got 0x%.2" PRIx8,
				WD_SECURITY_OPERATIONS_PAGE_CODE,
				SCSI_MS_PAGE_CODE(mpp->page_code_bits));
		return WD_SECURITY_EBADRESP;
	}

	if (page_control != SCSI_MS_PC_CHANGEABLE &&
	    mpp->sig != WD_SECURITY_MODE_PAGE_SIG)
	{
		mesg(ERROR, "Device Operations mode page bad signature, "
				"expected 0x%.2" PRIx8 ", got 0x%.2" PRIx8,
				WD_SECURITY_MODE_PAGE_SIG, mpp->sig);
		return WD_SECURITY_ESIG;
	}

	if (offsetof(struct wds_operations_mode_page_packed, page_length) +
		mpp->page_length + 1 < sizeof(*mpp))
	{
		mesg(ERROR, "Device Operations mode page short page length (%"
			PRIu8 ")", mpp->page_length);
		return WD_SECURITY_EBADRESP;
	}

	return 0;
}

int wds_read_operations_mode_page (struct wds_handle *wds,
		struct wds_operations_mode_page *mode_page,
		struct wds_operations_mode_page *changeable)
{
	struct wds_operations_mode_page_packed mpp;
	int err;

	err = read_operations_mode_page(wds->fd, wds->timeout,
			SCSI_MS_PC_CURRENT, &mpp);
	if (err)
		return err;

	unpack_operations_mode_page(&mpp, mode_page);

	if (changeable) {
		if (read_operations_mode_page(wds->fd, wds->timeout,
			    SCSI_MS_PC_CHANGEABLE, &mpp))
		{
			mesg(WARNING, "failed reading \"changeable\" Device "
				"Operations mode page, mark unchangeable");
			memset(changeable, 0, sizeof(*changeable));
		} else
			unpack_operations_mode_page(&mpp, changeable);
	}

	return 0;
}

int wds_write_operations_mode_page (struct wds_handle *wds,
		const struct wds_operations_mode_page *mode_page,
		const struct wds_operations_mode_page *mode_page_mask)
{
	struct wds_operations_mode_page_packed mpp;
	int save_pages;
	int err;

	err = read_operations_mode_page(wds->fd, wds->timeout,
			SCSI_MS_PC_CURRENT, &mpp);
	if (err)
		return err;

	pack_operations_mode_page_masked(mode_page, mode_page_mask, &mpp);

	save_pages = WDS_IS_SET(mpp.page_code_bits, SCSI_MS_PS_BIT);

	/* clear Parameters Saveable bit, it's reserved during mode-select */
	mpp.page_code_bits &= ~SCSI_MS_PS_BIT;

	return scsi_set_mode_page(wds->fd, wds->timeout, save_pages, &mpp,
		sizeof(mpp));
}

int wds_read_handy_capacity (struct wds_handle *wds,
		struct wds_handy_capacity *hc)
{
	struct wds_handy_capacity_packed hcp;
	struct wds_vsc_cdb cdb = WD_SECURITY_VSC_CDB_HANDY_CAPACITY_INIT;
	unsigned int dxfer_len;
	int err;

	dxfer_len = sizeof(hcp);

	err = scsi_cmd(wds->fd, wds->timeout, (unsigned char*)&cdb, sizeof(cdb),
			SG_DXFER_FROM_DEV, 0, &hcp, &dxfer_len, NULL);
	if (err)
		return err;

	unpack_handy_capacity(&hcp, hc);

	return 0;
}

static uint8_t checksum (const uint8_t *buf, unsigned len) {
	uint8_t csum = 0;
	unsigned i;

	for (i = 0; i < len; i++)
		csum += buf[i];

	return csum;
}

int wds_encode_handy_store_security_block (
		const struct wds_handy_store_security_block *hs,
		void *buf, size_t len)
{
	struct wds_handy_store_security_block_packed *hsp;

	if (len < sizeof(*hsp)) {
		mesg(ERROR, "buffer too small for Handy Store Security Block, "
			    "expected %zu, got %zu", sizeof(*hsp), len);
		return WD_SECURITY_ESIZE;
	}

	hsp = (struct wds_handy_store_security_block_packed*)buf;

	memset(hsp, 0, sizeof(*hsp));

	if (hs) {
		memcpy(hsp->sig, wd_security_handy_store_security_sig,
			sizeof(hsp->sig));
		hsp->iterations = htole32(hs->iterations);
		memcpy(hsp->salt, hs->salt, sizeof(hsp->salt));
		memcpy(hsp->hint, hs->hint, sizeof(hsp->hint));
		hsp->checksum = ~checksum((uint8_t*)hsp, sizeof(*hsp)) + 1;

		assert(checksum((uint8_t*)hsp, sizeof(*hsp)) == 0);
	}

	return 0;
}

int wds_decode_handy_store_security_block (const void *buf, size_t len,
		struct wds_handy_store_security_block *hs)
{
	const struct wds_handy_store_security_block_packed *hsp;

	if (len != sizeof(*hsp)) {
		mesg(ERROR, "unexpected Handy Store Security Block size, "
			    "expected %zu, got %zu", sizeof(*hsp), len);
		return WD_SECURITY_ESIZE;
	}

	hsp = (const struct wds_handy_store_security_block_packed*)buf;

	if (memcmp(hsp->sig, wd_security_handy_store_security_sig,
				sizeof(hsp->sig)))
	{
		mesg(ERROR, "Handy Store Security Block bad signature");
		hexdump(DEBUG, "Expected: ",
				wd_security_handy_store_security_sig,
				sizeof(wd_security_handy_store_security_sig));
		hexdump(DEBUG, "Got: ", hsp->sig, sizeof(hsp->sig));
		return WD_SECURITY_ESIG;
	}

	if (checksum((uint8_t*)hsp, sizeof(*hsp))) {
		mesg(ERROR, "Handy Store Security Block bad checksum");
		return WD_SECURITY_ECHKSUM;
	}

	unpack_handy_store_security_block(hsp, hs);

	return 0;
}

static int wds_encode_handy_store_user_block (
		const struct wds_handy_store_user_block *hs,
		void *buf, size_t len)
{
	struct wds_handy_store_user_block_packed *hsp;

	assert(len == sizeof(*hsp));

	hsp = (struct wds_handy_store_user_block_packed*)buf;

	memset(hsp, 0, sizeof(*hsp));

	if (hs) {
		memcpy(hsp->sig, wd_security_handy_store_user_sig,
				sizeof(hsp->sig));
		memcpy(hsp->label, hs->label, sizeof(hsp->label));
		hsp->checksum = ~checksum((uint8_t*)hsp, sizeof(*hsp)) + 1;

		assert(checksum((uint8_t*)hsp, sizeof(*hsp)) == 0);
	}

	return 0;
}

static int wds_decode_handy_store_user_block (const void *buf, size_t len,
		struct wds_handy_store_user_block *hs)
{
	const struct wds_handy_store_user_block_packed *hsp;

	if (len != sizeof(*hsp)) {
		mesg(ERROR, "unexpected Handy Store User Block size, "
			    "expected %zu, got %zu", sizeof(*hsp), len);
		return WD_SECURITY_ESIZE;
	}

	hsp = (const struct wds_handy_store_user_block_packed*)buf;

	if (memcmp(hsp->sig, wd_security_handy_store_user_sig, sizeof(hsp->sig)))
	{
		mesg(ERROR, "Handy Store User Block bad signature");
		hexdump(DEBUG, "Expected: ", wd_security_handy_store_user_sig,
				sizeof(wd_security_handy_store_user_sig));
		hexdump(DEBUG, "Got: ", hsp->sig, sizeof(hsp->sig));
		return WD_SECURITY_ESIG;
	}

	if (checksum((uint8_t*)hsp, sizeof(*hsp))) {
		mesg(ERROR, "Handy Store User Block bad checksum");
		return WD_SECURITY_ECHKSUM;
	}

	unpack_handy_store_user_block(hsp, hs);

	return 0;
}

static int decode_sense_data_handy_store (const struct sense_data_packed *sdp)
{
	if (SCSI_SB_ERROR_CODE(sdp->error_code_bits) ==
			SCSI_SB_CURRENT_ERRORS &&
	    SCSI_SB_SENSE_KEY(sdp->sense_key_bits) == DATA_PROTECT &&
	    sdp->asc == SCSI_ASC_SECURITY_ERROR)
	{
		switch (sdp->ascq) {
		case 0x71:
			mesg(ERROR, "Not Authorized");
			return WD_SECURITY_EAUTH;
		}
	}

	return decode_sense_data_generic(sdp);
}

int wds_write_handy_store_blocks (struct wds_handle *wds, uint32_t block,
		uint16_t num_blocks, const void *buf, size_t *buf_len)
{
	struct wds_vsc_cdb cdb = WD_SECURITY_VSC_CDB_HANDY_STORE_WR_INIT;
	unsigned int dxfer_len;
	int err;

	cdb.address = htobe32(block);
	cdb.length = htobe16(num_blocks);

	if (*buf_len > UINT_MAX) {
		mesg(WARNING, "Handy Store blocks buffer too big, truncating");
		*buf_len = UINT_MAX;
	}

	dxfer_len = *buf_len;
	err = scsi_cmd(wds->fd, wds->timeout, (unsigned char*)&cdb, sizeof(cdb),
			SG_DXFER_TO_DEV, 0, (unsigned char*)buf, &dxfer_len,
			decode_sense_data_handy_store);

	/* Update buf_len to contain number of bytes actually transferred? */
	*buf_len = dxfer_len;

	return err;
}

int wds_write_handy_store_security_block (struct wds_handle *wds,
		const struct wds_handy_store_security_block *hs)
{
	struct wds_handy_store_security_block_packed hsp;
	size_t len = sizeof(hsp);
	int err;

	err = wds_encode_handy_store_security_block(hs, &hsp, len);
	if (err)
		return err;

	/* clear security_block_loaded bit */
	wds->security_block_loaded = 0;

	return wds_write_handy_store_blocks(wds,
			WD_SECURITY_HANDY_STORE_SECURITY_BLOCK, 1, &hsp, &len);
}

int wds_write_handy_store_user_block (struct wds_handle *wds,
		const struct wds_handy_store_user_block *hs)
{
	struct wds_handy_store_user_block_packed hsp;
	size_t len = sizeof(hsp);
	int err;

	err = wds_encode_handy_store_user_block(hs, &hsp, len);
	if (err)
		return err;

	return wds_write_handy_store_blocks(wds,
			WD_SECURITY_HANDY_STORE_USER_BLOCK, 1, &hsp, &len);
}

int wds_read_handy_store_blocks (struct wds_handle *wds, uint32_t block,
		uint16_t num_blocks, void *buf, size_t *buf_len)
{
	struct wds_vsc_cdb cdb = WD_SECURITY_VSC_CDB_HANDY_STORE_RD_INIT;
	unsigned int dxfer_len;
	int err;

	cdb.address = htobe32(block);
	cdb.length = htobe16(num_blocks);

	if (*buf_len > UINT_MAX) {
		mesg(WARNING, "Handy Store blocks buffer too big, clamping");
		*buf_len = UINT_MAX;
	}

	dxfer_len = *buf_len;
	err = scsi_cmd(wds->fd, wds->timeout, (unsigned char*)&cdb, sizeof(cdb),
			SG_DXFER_FROM_DEV, 0, (unsigned char*)buf, &dxfer_len, NULL);
	if (err)
		return err;

	*buf_len = dxfer_len;

	mesg(DEBUG2, "Handy Store Buffer Length: %zu", *buf_len);

	return 0;
}

int wds_read_handy_store_security_block (
		struct wds_handle *wds,
		struct wds_handy_store_security_block* hs)
{
	struct wds_handy_store_security_block_packed hsp;
	size_t len = sizeof(hsp);
	int err;

	err = wds_read_handy_store_blocks(wds,
			WD_SECURITY_HANDY_STORE_SECURITY_BLOCK, 1, &hsp, &len);
	if (err)
		return err;

	err = wds_decode_handy_store_security_block(&hsp, len, hs);
	if (err)
		return err;

	/* cache salt and iteration rounds  */
	wds->iterations = hs->iterations;
	memcpy(wds->salt, hsp.salt, sizeof(hsp.salt));

	wds->security_block_loaded = 1;

	return 0;
}

int wds_read_handy_store_user_block (struct wds_handle *wds,
		struct wds_handy_store_user_block* hs)
{
	struct wds_handy_store_user_block_packed hsp;
	size_t len = sizeof(hsp);
	int err;

	err = wds_read_handy_store_blocks(wds,
			WD_SECURITY_HANDY_STORE_USER_BLOCK, 1, &hsp, &len);
	if (err)
		return err;

	return wds_decode_handy_store_user_block(&hsp, len, hs);
}

/*
 * Generate Key Encryption Key (KEK)
 *
 * Password should be in UTF-16LE encoding and be 50-bytes or less in
 * order to maintain compatibility with the proprietary WD Security.
 *
 * salt
 * salt_bytes
 * pw        password string
 * pw_bytes  length of password string.
 * iterations
 *
 * Returns 0 on success.
 */
int wds_generate_kek (const uint8_t *salt, size_t salt_bytes,
		const uint8_t *pw, size_t pw_bytes, unsigned long iterations,
		uint8_t kek[WD_SECURITY_KEK_MAX_BYTES])
{
#ifdef HAVE_EVP_MD_FETCH
	EVP_MD *md;
#else
	const EVP_MD *md;
#endif
	EVP_MD_CTX *ctx;
	unsigned long i;
	unsigned len;

	if (!salt) {
		salt = wd_security_default_salt;
		salt_bytes = sizeof(wd_security_default_salt);
		mesg(INFO, "generate-KEK: using default salt \"%s\"",
				WD_SECURITY_DEFAULT_SALT_ASCII);
	}

	if (!iterations) {
		iterations = WD_SECURITY_DEFAULT_ITERATIONS;
		mesg(INFO, "generate-KEK: using default iteration rounds (%lu)",
				iterations);
	}

#ifdef HAVE_EVP_MD_FETCH
	md = EVP_MD_fetch(NULL, "SHA256", NULL);
#else
	md = EVP_sha256();
#endif
	if (!md) {
		mesg(ERROR, "can't find SHA256 implementation");
		goto failure;
	}

#ifdef HAVE_EVP_MD_FETCH
	ctx = EVP_MD_CTX_new();
#else
	ctx = EVP_MD_CTX_create();
#endif

	if (!EVP_DigestInit_ex(ctx, md, NULL)) {
		mesg(ERROR, "EVP_DigestInit failed");
		goto cleanup_failure;
	}

	if (!EVP_DigestUpdate(ctx, salt, salt_bytes) ||
	    !EVP_DigestUpdate(ctx, pw, pw_bytes)) {
		mesg(ERROR, "EVP_DigestUpdate1 failed");
		goto cleanup_failure;
	}

	if (!EVP_DigestFinal_ex(ctx, kek, &len)) {
		mesg(ERROR, "EVP_DigestFinal_ex1 failed");
		goto cleanup_failure;
	}

	assert(len == WD_SECURITY_KEK_MAX_BYTES);

	for (i = 1; i < iterations; i++) {
		if (!EVP_DigestInit_ex(ctx, md, NULL)) {
			mesg(ERROR, "EVP_DigestInit_ex failed");
			goto cleanup_failure;
		}

		if (!EVP_DigestUpdate(ctx, kek, len)) {
			mesg(ERROR, "EVP_DigestUpdate failed");
			goto cleanup_failure;
		}

		if (!EVP_DigestFinal_ex(ctx, kek, &len)) {
			mesg(ERROR, "EVP_DigestFinal_ex failed");
			goto cleanup_failure;
		}
	}

#ifdef HAVE_EVP_MD_FETCH
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);
#else
	EVP_MD_CTX_destroy(ctx);
#endif

	return 0;

cleanup_failure:
#ifdef HAVE_EVP_MD_FETCH
	EVP_MD_CTX_free(ctx);
	EVP_MD_free(md);
#else
	EVP_MD_CTX_destroy(ctx);
#endif
failure:
	return WD_SECURITY_ECRYPTO;
}

static int decode_sense_data_unlock (const struct sense_data_packed *sdp)
{
	if (SCSI_SB_ERROR_CODE(sdp->error_code_bits) ==
			SCSI_SB_CURRENT_ERRORS &&
	    SCSI_SB_SENSE_KEY(sdp->sense_key_bits) == ILLEGAL_REQUEST &&
	    sdp->asc == SCSI_ASC_SECURITY_ERROR)
	{
		switch (sdp->ascq) {
		case 0x40:
			mesg(ERROR, "Authentication Failed");
			return WD_SECURITY_EAUTH;
		case 0x80:
			mesg(ERROR, "Unlock Attempts Exhausted");
			return WD_SECURITY_ELOCKEDOUT;
		case 0x81:
			mesg(ERROR, "Already Unlocked, Not Protected, or No "
					"Encryption Key");
			return WD_SECURITY_ENOTLOCKED;
		}
	}

	return decode_sense_data_generic(sdp);
}

int wds_unlock_kek (struct wds_handle *wds, const uint8_t *kek,
		uint16_t kek_bytes)
{
	struct wds_vsc_cdb cdb = WD_SECURITY_VSC_CDB_UNLOCK_INIT;
	struct wds_encryption_unlock_packed *unlock_param;
	uint16_t unlock_param_len;
	unsigned int dxfer_len;
	int err;

	unlock_param_len = offsetof(struct wds_encryption_unlock_packed, kek) +
		kek_bytes;
	unlock_param = xcalloc(1, unlock_param_len);
	unlock_param->sig = WD_SECURITY_VSC_SIG;
	unlock_param->length = htobe16(kek_bytes);
	memcpy(unlock_param->kek, kek, kek_bytes);

	cdb.length = htobe16(unlock_param_len);

	dxfer_len = unlock_param_len;
	err = scsi_cmd(wds->fd, wds->timeout, (unsigned char*)&cdb, sizeof(cdb),
			SG_DXFER_TO_DEV, 0, (unsigned char*)unlock_param,
			&dxfer_len, decode_sense_data_unlock);

	free(unlock_param);

	if (err)
		return err;

	/* clear status bit */
	wds->status_loaded = 0;

	return 0;
}

int wds_unlock (struct wds_handle *wds, const uint8_t *pw, size_t pw_bytes)
{
	uint8_t kek[WD_SECURITY_KEK_MAX_BYTES];
	struct wds_handy_store_security_block sb;
	const uint8_t *salt;
	size_t salt_bytes;
	unsigned long iterations;
	int err;

	/* Get Encryption Status if necessary (to populate wds->kek_size) */
	if (!wds->status_loaded) {
		struct wds_encryption_status *es = wds_get_status(wds, &err);
		free(es);
		if (!es)
			return err;
	}

	if (wds->kek_size > WD_SECURITY_KEK_MAX_BYTES) {
		mesg(ERROR, "KEK size (%" PRIu16 ") is unsupported (max %u)",
				wds->kek_size, WD_SECURITY_KEK_MAX_BYTES);
		return WD_SECURITY_E2BIG;
	}

	/* Get Handy Store Security Block if necessary (to populate
	 * wds->salt and wds->iterations */
	if (wds->security_block_loaded ||
	    !wds_read_handy_store_security_block(wds, &sb)) {
		salt = wds->salt;
		salt_bytes = sizeof(wds->salt);
		iterations = wds->iterations;
	} else {
		/* if security block can't be loaded, have
		 * wds_generate_kek() use the fallback salt and
		 * iterations */
		salt = NULL;
		salt_bytes = 0;
		iterations = 0;
	}

	err = wds_generate_kek(salt, salt_bytes, pw, pw_bytes, iterations, kek);
	if (err)
		return err;

	return wds_unlock_kek(wds, kek, wds->kek_size);
}

static int decode_sense_data_changepw (const struct sense_data_packed *sdp)
{
	if (SCSI_SB_ERROR_CODE(sdp->error_code_bits) ==
			SCSI_SB_CURRENT_ERRORS &&
	    SCSI_SB_SENSE_KEY(sdp->sense_key_bits) == ILLEGAL_REQUEST)
	{
		switch (sdp->asc) {
		case SCSI_ASC_SECURITY_ERROR:
			switch (sdp->ascq) {
			case 0x40:
				mesg(ERROR, "Authentication Failed");
				return WD_SECURITY_EAUTH;
			case 0x81:
				/* device locked, supplied no password */
				/* device locked, supplied bad password */
				/* device locked, supplied correct password */
				mesg(ERROR, "Device Locked");
				return WD_SECURITY_ELOCKED;
			}
			break;
		case SCSI_ASC_INVALID_PARAM_FIELD:
			if (sdp->ascq == 0x00) {
				/* Both new and old KEKs were flagged as
				 * absent, or KEK length is wrong. */
				mesg(ERROR, "Invalid Field in Parameter List");
				return WD_SECURITY_EKEK;
			}
			break;
		}
	}

	return decode_sense_data_generic(sdp);
}

int wds_changepw_kek (struct wds_handle *wds, const uint8_t *oldkek,
		const uint8_t *newkek, uint16_t kek_bytes)
{
	struct wds_encryption_setpw_packed *param;
	struct wds_vsc_cdb cdb = WD_SECURITY_VSC_CDB_SETPW_INIT;
	uint16_t param_len;
	unsigned int dxfer_len;
	int err;

	param_len = offsetof(struct wds_encryption_setpw_packed, kek) +
		2 * kek_bytes;
	param = xcalloc(1, param_len);
	param->sig = WD_SECURITY_VSC_SIG;
	param->length = htobe16(kek_bytes);

	if (oldkek)
		memcpy(param->kek, oldkek, kek_bytes);
	else
		param->flag_bits |= WD_SECURITY_OLDDEF;

	if (newkek)
		memcpy(param->kek + kek_bytes, newkek, kek_bytes);
	else
		param->flag_bits |= WD_SECURITY_NEWDEF;

	cdb.length = htobe16(param_len);

	dxfer_len = param_len;
	err = scsi_cmd(wds->fd, wds->timeout, (unsigned char*)&cdb, sizeof(cdb),
		SG_DXFER_TO_DEV, 0, (unsigned char*)param, &dxfer_len,
		decode_sense_data_changepw);

	free(param);

	if (err)
		return err;

	/* clear status bit */
	wds->status_loaded = 0;

	return 0;
}

int wds_changepw (struct wds_handle *wds, const uint8_t *opw, size_t opw_bytes,
		const uint8_t *npw, size_t npw_bytes)
{
	struct wds_handy_store_security_block sb;
	uint8_t okekbuf[WD_SECURITY_KEK_MAX_BYTES];
	uint8_t nkekbuf[WD_SECURITY_KEK_MAX_BYTES];
	uint8_t *okek = okekbuf;
	uint8_t *nkek = nkekbuf;
	const uint8_t *salt;
	size_t salt_bytes;
	unsigned long iterations;
	int err;

	/* Get Encryption Status if necessary (to populate wds->kek_size) */
	if (!wds->status_loaded) {
		struct wds_encryption_status *es = wds_get_status(wds, &err);
		free(es);
		if (!es)
			return err;
	}

	if (wds->kek_size > WD_SECURITY_KEK_MAX_BYTES) {
		mesg(ERROR, "KEK size (%" PRIu16 ") is unsupported (max %u)",
				wds->kek_size, WD_SECURITY_KEK_MAX_BYTES);
		return WD_SECURITY_E2BIG;
	}

	/* Get Handy Store Security Block if necessary (to populate
	 * wds->salt and wds->iterations */
	if (wds->security_block_loaded ||
	    !wds_read_handy_store_security_block(wds, &sb)) {
		salt = wds->salt;
		salt_bytes = sizeof(wds->salt);
		iterations = wds->iterations;
	} else {
		/* if security block can't be loaded, have
		 * wds_generate_kek() use the fallback salt and
		 * iterations */
		salt = NULL;
		salt_bytes = 0;
		iterations = 0;
	}

	if (opw) {
		err = wds_generate_kek(salt, salt_bytes, opw, opw_bytes,
				iterations, okek);
		if (err) {
			mesg(ERROR, "failed to generate old KEK");
			return err;
		}
	} else
		okek = NULL;

	if (npw) {
		err = wds_generate_kek(salt, salt_bytes, npw, npw_bytes,
				iterations, nkek);
		if (err) {
			mesg(ERROR, "failed to generate new KEK");
			return err;
		}
	} else
		nkek = NULL;

	return wds_changepw_kek(wds, okek, nkek, wds->kek_size);
}

static int decode_sense_data_erase (const struct sense_data_packed *sdp)
{
	if (SCSI_SB_ERROR_CODE(sdp->error_code_bits) == SCSI_SB_CURRENT_ERRORS)
	{
		if (SCSI_SB_SENSE_KEY(sdp->sense_key_bits) == ILLEGAL_REQUEST)
		{
			if (sdp->asc == SCSI_ASC_INVALID_CDB_FIELD &&
			    sdp->ascq == 0x00)
			{
				/* Invalid key reset enabler or wrong
				 * parameter list length */
				mesg(ERROR, "Invalid Field in CDB");
				return WD_SECURITY_EBADSYN;
			} else if (sdp->asc == SCSI_ASC_INVALID_PARAM_FIELD &&
				   sdp->ascq == 0x00)
			{
				/* Mismatch between cipher and key length,
				 * probably also unsupported cipher */
				mesg(ERROR, "Invalid Field in Parameter List");
				return WD_SECURITY_ECIPHER;
			}
		}
	}

	return decode_sense_data_generic(sdp);
}

int wds_erase (struct wds_handle *wds, const uint8_t reset_syn[4],
		const uint8_t *key, uint16_t key_bytes, uint8_t cipher,
		unsigned combine)
{
	struct wds_encryption_erase_packed *param;
	struct wds_vsc_cdb cdb = WD_SECURITY_VSC_CDB_ERASE_INIT;
	uint16_t param_len;
	unsigned int dxfer_len;
	int err;

	param_len = offsetof(struct wds_encryption_erase_packed, key) +
		key_bytes;

	param = xcalloc(1, param_len);
	param->sig = WD_SECURITY_VSC_SIG;
	if (combine) /* or just turn `combine` into flag bits? */
		param->flag_bits |= WD_SECURITY_COMBINE;
	param->cipher = cipher;
	param->length = htobe16(key_bytes * 8);
	memcpy(param->key, key, key_bytes);

	memcpy(&cdb.address, reset_syn, sizeof(cdb.address));
	cdb.length = htobe16(param_len);

	dxfer_len = param_len;
	err = scsi_cmd(wds->fd, wds->timeout, (unsigned char*)&cdb, sizeof(cdb),
		SG_DXFER_TO_DEV, 0, (unsigned char*)param, &dxfer_len,
		decode_sense_data_erase);

	free(param);

	if (err)
		return err;

	/* clear status bit */
	wds->status_loaded = 0;

	return 0;
}
