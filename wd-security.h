/*
 * wd-security.h
 *
 *   A library for managing the password protection of external drives
 *   supported by the proprietary WD Security software.
 *
 * Copyright (C) 2025  Brandon Casey
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
#ifndef WD_SECURITY_H
#define WD_SECURITY_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum Size (Bytes) of Key Encryption Key (KEK) */
#define WD_SECURITY_KEK_MAX_BYTES 32

/* Security Status States */
#define WD_SECURITY_STATUS_NOPASSWD   0x00
#define WD_SECURITY_STATUS_LOCKED     0x01
#define WD_SECURITY_STATUS_UNLOCKED   0x02
#define WD_SECURITY_STATUS_LOCKEDOUT  0x06
#define WD_SECURITY_STATUS_NOKEY      0x07

/* Cipher Modes */
#define WD_SECURITY_CIPHER_NONE         0x00
#define WD_SECURITY_CIPHER_AES_128_ECB  0x10
#define WD_SECURITY_CIPHER_AES_128_CBC  0x12
#define WD_SECURITY_CIPHER_AES_128_XTS  0x18
#define WD_SECURITY_CIPHER_AES_256_ECB  0x20
#define WD_SECURITY_CIPHER_AES_256_CBC  0x22
#define WD_SECURITY_CIPHER_AES_256_XTS  0x28
#define WD_SECURITY_CIPHER_FDE          0x30

/* Error Constants */
#define WD_SECURITY_ESYSCALL    1  /* syscall failed, errno is set */
#define WD_SECURITY_ESIG        2  /* bad signature */
#define WD_SECURITY_ESIZE       3  /* handy store block size mismatch */
#define WD_SECURITY_ECHKSUM     4  /* bad checksum */
#define WD_SECURITY_ECRYPTO     5  /* sha256 hash crypto function failed */
#define WD_SECURITY_ENOTLOCKED  6  /* attempt to unlock when not locked */
#define WD_SECURITY_ELOCKEDOUT  7  /* attempt to unlock, attempts exhausted */
#define WD_SECURITY_EAUTH       8  /* authentication failed, bad password */
#define WD_SECURITY_EKEK        9  /* KEK length wrong, or both KEKs absent */
#define WD_SECURITY_E2BIG      10  /* KEK size too big */
#define WD_SECURITY_EBADSYN    11  /* invalid reset syn or wrong param length */
#define WD_SECURITY_ECIPHER    12  /* cipher/length mismatch (unknown cipher) */
#define WD_SECURITY_ELOCKED    13  /* attempt to change pw when device locked */

#define WD_SECURITY_ESCSI      32  /* info != SG_INFO_OK,  */
#define WD_SECURITY_ESENSE     33  /* SCSI status is CHECK_CONDITION */
#define WD_SECURITY_EKCQ       34  /* CHECK_CONDITION and Key Code Qualifier */

/* Error Helper macros */
#define WD_SECURITY_STATUS_MASK 0xff
#define WDS_STATUS(_e) ((_e) & WD_SECURITY_STATUS_MASK)

#define WDS_ESCSI_STATUS(_e)      (((_e) >>  8) & 0xff)
#define WDS_ESENSE_ERROR_CODE(_e) (((_e) >> 16) & 0xff)
#define WDS_ESENSE_SENSE_KEY(_e)  (((_e) >>  8) & 0xff)
#define WDS_EKCQ_KCQ(_e)          (((_e) >>  8) & 0x0fffff)
#define WDS_EKCQ_IS_CURRENT(_e)   (!((_e) & 0x10000000))
#define WDS_EKCQ_IS_DEFERRED(_e)  (  (_e) & 0x10000000)
#define WDS_EKCQ_SENSE_KEY(_e)    (((_e) >> 24) & 0x0f)
#define WDS_EKCQ_ASC(_e)          (((_e) >> 16) & 0xff)
#define WDS_EKCQ_ASCQ(_e)         (((_e) >>  8) & 0xff)

/* WD Security defaults */
#define WD_SECURITY_DEFAULT_ITERATIONS 1000
#define WD_SECURITY_DEFAULT_SALT_ASCII "WDC."
#define WD_SECURITY_DEFAULT_SALT wd_security_default_salt

extern const uint8_t wd_security_default_salt[8];

typedef struct wds_handle wds_handle;

struct wds_opts {
	unsigned timeout_ms;  /* timeout for SCSI operations */
	char reserved[16];
};

struct wds_encryption_status {
	uint8_t status;
	uint8_t cipher;
	uint16_t kek_size;
	uint8_t reset_syn[4];
	uint8_t num_ciphers;
	uint8_t ciphers[1];   /* flexible array of ciphers */
};

struct wds_handy_capacity {
	uint32_t last_block;
	uint32_t length;
	uint16_t max_xfer_len;
};

struct wds_handy_store_security_block {
	uint32_t iterations;
	uint8_t salt[8];      /* maybe UTF-16 */
	uint8_t hint[202];    /* password hint, UTF-16LE */
};

struct wds_handy_store_user_block {
	uint8_t label[64];    /* drive label, UTF-16LE */
};

extern const char* wds_cipher_to_string (unsigned cipher);
extern uint8_t wds_string_to_cipher (const char* name);
extern const char* wds_status_to_string (unsigned status);
extern const char* wds_strerror (int err);

extern wds_handle* wds_open (const char *device, const struct wds_opts*,
		int *err);
extern int wds_close (wds_handle*);
extern struct wds_encryption_status* wds_get_status (wds_handle*, int *err);
extern int wds_unlock (wds_handle *wds, const uint8_t *pw, size_t pw_bytes);
extern int wds_unlock_kek (struct wds_handle *wds, const uint8_t *kek,
			   uint16_t kek_bytes);
extern int wds_changepw (wds_handle *wds, const uint8_t *opw, size_t opw_bytes,
			 const uint8_t *npw, size_t npw_bytes);
extern int wds_changepw_kek (wds_handle *wds, const uint8_t *okek,
			     const uint8_t *nkek, uint16_t kek_bytes);
extern int wds_erase (wds_handle *wds, const uint8_t reset_syn[4],
		      const uint8_t *key, uint16_t key_bytes, uint8_t cipher,
		      unsigned combine);

extern int wds_read_handy_capacity (wds_handle*, struct wds_handy_capacity*);
extern int wds_read_handy_store_security_block (wds_handle*,
		struct wds_handy_store_security_block*);
extern int wds_read_handy_store_user_block (wds_handle*,
		struct wds_handy_store_user_block*);

extern int wds_write_handy_store_security_block (wds_handle *wds,
		const struct wds_handy_store_security_block *hs);
extern int wds_write_handy_store_user_block (wds_handle *wds,
		const struct wds_handy_store_user_block *hs);

extern int wds_generate_kek (const uint8_t *salt, size_t salt_bytes,
			     const uint8_t *pw, size_t pw_bytes,
			     unsigned long iterations,
			     uint8_t kek[WD_SECURITY_KEK_MAX_BYTES]);

#ifdef __cplusplus
}  /* extern "C" */
#endif

#endif /* WD_SECURITY_H */
