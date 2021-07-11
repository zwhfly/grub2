/* efiramdisk.c - load disk image to memory and emulate EFI Block IO device */
/*
 *  GRUB  --  GRand Unified Bootloader
 *  Copyright (C) 2021  Free Software Foundation, Inc.
 *  Copyright (C) 2021  zwhfly <zwhfly@163.com>
 *
 *  GRUB is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  GRUB is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with GRUB.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <grub/crypto.h>
#include <grub/dl.h>
#include <grub/efi/api.h>
#include <grub/efi/efi.h>
#include <grub/err.h>
#include <grub/extcmd.h>
#include <grub/file.h>
#include <grub/i18n.h>
#include <grub/misc.h>
#include <grub/mm.h>
#include <grub/env.h>
#include <grub/types.h>
#include <grub/loader.h>
#include <grub/charset.h>
#include <grub/term.h>


GRUB_MOD_LICENSE("GPLv3+");


/* EFIAPI definition for microsoft calling convention. */
#define EFIAPI __attribute__((ms_abi))

static grub_efi_boolean_t const efi_false = 0;
static grub_efi_boolean_t const efi_true = !0;


/* GUID for "Vendor-Defined Messaging Device Path" */
#define EFIRAMDISK_DP_GUID \
  { 0x928da54f, 0x7b56, 0x4f5b, \
      { 0x85, 0x8a, 0xa6, 0xfa, 0x92, 0x35, 0xcb, 0xc3 } \
  }

static grub_efi_guid_t efi_block_io_guid = GRUB_EFI_BLOCK_IO_GUID;
static grub_efi_guid_t efi_block_io2_guid = GRUB_EFI_BLOCK_IO2_GUID;
static grub_efi_guid_t efi_device_path_guid = GRUB_EFI_DEVICE_PATH_GUID;
static grub_efi_guid_t efi_simple_file_system_guid = GRUB_EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
static grub_efi_guid_t efiramdisk_dp_guid = EFIRAMDISK_DP_GUID;

#define EFIRAMDISK_CD_BLOCK_SIZE 2048
#define EFIRAMDISK_HD_BLOCK_SIZE 512

typedef struct efiramdisk_device_path {
    grub_efi_vendor_device_path_t vendor_msg_dp;
    unsigned char addr[sizeof(void *)];
    unsigned char size[sizeof(grub_efi_uintn_t)];
} GRUB_PACKED efiramdisk_device_path_t;
typedef struct efiramdisk_full_device_path {
    efiramdisk_device_path_t efiramdisk_node;
    grub_efi_device_path_t end_node;
} GRUB_PACKED efiramdisk_full_device_path_t;

typedef struct efiramdisk_data efiramdisk_data_t;
typedef struct efiramdisk_block_io
{
    grub_efi_block_io_t efi_block_io;
    efiramdisk_data_t *data;
} efiramdisk_block_io_t;
typedef struct efiramdisk_block_io2
{
    grub_efi_block_io2_t efi_block_io2;
    efiramdisk_data_t *data;
} efiramdisk_block_io2_t;
struct efiramdisk_data
{
    grub_efi_handle_t handle;
    grub_efi_block_io_media_t media;
    efiramdisk_block_io_t block_io;
    efiramdisk_block_io2_t block_io2;
    void *disk_content;
    grub_efi_uintn_t disk_size;
    efiramdisk_full_device_path_t device_path;
};


/*
 * grub_efi_block_io_t member function implementation
 */
static grub_efi_status_t EFIAPI block_io_reset(
    grub_efi_block_io_t *this __attribute__((unused)),
    grub_efi_boolean_t extended_verification __attribute__((unused)))
{
    return GRUB_EFI_SUCCESS;
}

static grub_efi_status_t EFIAPI block_io_read_blocks(
    grub_efi_block_io_t *this,
    grub_efi_uint32_t media_id,
    grub_efi_lba_t lba,
    grub_efi_uintn_t buffer_size,
    void *buffer)
{
    efiramdisk_data_t *data = ((efiramdisk_block_io_t *)(this))->data;

    if (media_id != data->media.media_id)
        return GRUB_EFI_MEDIA_CHANGED;

    if (buffer == NULL)
        return GRUB_EFI_INVALID_PARAMETER;

    if (buffer_size == 0)
        return GRUB_EFI_SUCCESS;

    if ((buffer_size % data->media.block_size) != 0)
        return GRUB_EFI_BAD_BUFFER_SIZE;

    if (lba > data->media.last_block)
        return GRUB_EFI_INVALID_PARAMETER;

    // Since lba is in range,
    //   we can safely assume that block_size*lba < disk_size < uintn_t_max
    grub_efi_uintn_t offset = data->media.block_size * (grub_efi_uintn_t)lba;
    if (buffer_size > data->disk_size - offset)
        return GRUB_EFI_INVALID_PARAMETER;

    grub_memcpy(buffer, (char *)(data->disk_content) + offset, buffer_size);

    return GRUB_EFI_SUCCESS;
}

static grub_efi_status_t EFIAPI block_io_write_blocks(
    grub_efi_block_io_t *this,
    grub_efi_uint32_t media_id,
    grub_efi_lba_t lba,
    grub_efi_uintn_t buffer_size,
    void *buffer)
{
    efiramdisk_data_t *data = ((efiramdisk_block_io_t *)(this))->data;

    if (media_id != data->media.media_id)
        return GRUB_EFI_MEDIA_CHANGED;

    if (data->media.read_only == efi_true)
        return GRUB_EFI_WRITE_PROTECTED;

    if (buffer == NULL)
        return GRUB_EFI_INVALID_PARAMETER;

    if (buffer_size == 0)
        return GRUB_EFI_SUCCESS;

    if ((buffer_size % data->media.block_size) != 0)
        return GRUB_EFI_BAD_BUFFER_SIZE;

    if (lba > data->media.last_block)
        return GRUB_EFI_INVALID_PARAMETER;

    // Since lba is in range,
    //   we can safely assume that block_size*lba < disk_size < uintn_t_max
    grub_efi_uintn_t offset = data->media.block_size * (grub_efi_uintn_t)lba;
    if (buffer_size > data->disk_size - offset)
        return GRUB_EFI_INVALID_PARAMETER;

    grub_memcpy((char *)(data->disk_content) + offset, buffer, buffer_size);

    return GRUB_EFI_SUCCESS;
}

static grub_efi_status_t EFIAPI block_io_flush_blocks(
    grub_efi_block_io_t *this __attribute__((unused)))
{
    return GRUB_EFI_SUCCESS;
}


/*
 * grub_efi_block_io2_t member function implementation
 */
static grub_efi_status_t EFIAPI block_io2_reset_ex(
    grub_efi_block_io2_t *this __attribute__((unused)),
    grub_efi_boolean_t extended_verification __attribute__((unused)))
{
    return GRUB_EFI_SUCCESS;
}

static grub_efi_status_t EFIAPI block_io2_read_blocks_ex(
    grub_efi_block_io2_t *this,
    grub_efi_uint32_t media_id,
    grub_efi_lba_t lba,
    grub_efi_block_io2_token_t *token,
    grub_efi_uintn_t buffer_size,
    void *buffer)
{
    efiramdisk_data_t *data = ((efiramdisk_block_io2_t *)(this))->data;
    grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;

    grub_efi_status_t status = block_io_read_blocks(
        &(data->block_io.efi_block_io), media_id, lba, buffer_size, buffer);

    if (status != GRUB_EFI_SUCCESS)
        return status;

    if (token != NULL && token->event != NULL)
    {
        token->transaction_status = GRUB_EFI_SUCCESS;
        efi_call_1(b->signal_event, token->event);
    }

    return GRUB_EFI_SUCCESS;
}

static grub_efi_status_t EFIAPI block_io2_write_blocks_ex(
    grub_efi_block_io2_t *this,
    grub_efi_uint32_t media_id,
    grub_efi_lba_t lba,
    grub_efi_block_io2_token_t *token,
    grub_efi_uintn_t buffer_size,
    void *buffer)
{
    efiramdisk_data_t *data = ((efiramdisk_block_io2_t *)(this))->data;
    grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;

    grub_efi_status_t status = block_io_write_blocks(
        &(data->block_io.efi_block_io), media_id, lba, buffer_size, buffer);

    if (status != GRUB_EFI_SUCCESS)
        return status;

    if (token != NULL && token->event != NULL)
    {
        token->transaction_status = GRUB_EFI_SUCCESS;
        efi_call_1(b->signal_event, token->event);
    }

    return GRUB_EFI_SUCCESS;
}

static grub_efi_status_t EFIAPI block_io2_flush_blocks_ex(
    grub_efi_block_io2_t *this,
    grub_efi_block_io2_token_t *token)
{
    efiramdisk_data_t *data = ((efiramdisk_block_io2_t *)(this))->data;
    grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;

    if (data->media.read_only == efi_true)
        return GRUB_EFI_WRITE_PROTECTED;

    if (token != NULL && token->event != NULL)
    {
        token->transaction_status = GRUB_EFI_SUCCESS;
        efi_call_1(b->signal_event, token->event);
    }

    return GRUB_EFI_SUCCESS;
}

#define EFIRAMDISK_BLOCK_IO_PROTOCOL_REVISION 0x00010000
static grub_efi_block_io_t efi_block_io_template = {
    .revision = EFIRAMDISK_BLOCK_IO_PROTOCOL_REVISION,
    .media = NULL,
    .reset = (grub_efi_block_io_reset_t *)block_io_reset,
    .read_blocks = (grub_efi_block_io_read_blocks_t *)block_io_read_blocks,
    .write_blocks = (grub_efi_block_io_write_blocks_t *)block_io_write_blocks,
    .flush_blocks = (grub_efi_block_io_flush_blocks_t *)block_io_flush_blocks};

static grub_efi_block_io2_t efi_block_io2_template = {
    .media = NULL,
    .reset_ex = (grub_efi_block_io2_reset_ex_t *)block_io2_reset_ex,
    .read_blocks_ex = (grub_efi_block_io2_read_blocks_ex_t *)block_io2_read_blocks_ex,
    .write_blocks_ex = (grub_efi_block_io2_write_blocks_ex_t *)block_io2_write_blocks_ex,
    .flush_blocks_ex = (grub_efi_block_io2_flush_blocks_ex_t *)block_io2_flush_blocks_ex};

static grub_efi_block_io_media_t efi_block_io_media_template = {
    .media_id = 0,
    .removable_media = efi_false,
    .media_present = efi_true,
    .logical_partition = efi_false,
    .read_only = efi_false,
    .write_caching = efi_false,
    .block_size = 0,
    .io_align = 0,
    .last_block = 0};

static void init_efiramdisk_data(
    efiramdisk_data_t *data,
    void *disk_content,
    grub_efi_uintn_t disk_size,
    grub_efi_uint32_t block_size,
    grub_efi_uintn_t block_count)
{
    data->handle = NULL;
    data->disk_content = disk_content;
    data->disk_size = disk_size;

    grub_efi_block_io_media_t *media = &data->media;
    grub_memcpy(media, &efi_block_io_media_template, sizeof(grub_efi_block_io_media_t));
    media->block_size = block_size;
    media->last_block = block_count - 1U;

    efiramdisk_block_io_t *block_io = &data->block_io;
    grub_memcpy(&(block_io->efi_block_io), &efi_block_io_template, sizeof(grub_efi_block_io_t));
    block_io->efi_block_io.media = media;
    block_io->data = data;

    efiramdisk_block_io2_t *block_io2 = &data->block_io2;
    grub_memcpy(&(block_io2->efi_block_io2), &efi_block_io2_template, sizeof(grub_efi_block_io2_t));
    block_io2->efi_block_io2.media = media;
    block_io2->data = data;

    /* fill device path */
    efiramdisk_device_path_t *device_path = &(data->device_path.efiramdisk_node);
    grub_efi_vendor_device_path_t *vendor_msg_dp = &(device_path->vendor_msg_dp);
    vendor_msg_dp->header.type = GRUB_EFI_MESSAGING_DEVICE_PATH_TYPE;
    vendor_msg_dp->header.subtype = GRUB_EFI_VENDOR_MESSAGING_DEVICE_PATH_SUBTYPE;
    vendor_msg_dp->header.length = (grub_efi_uint16_t)(sizeof(efiramdisk_device_path_t));
    grub_memcpy(&vendor_msg_dp->vendor_guid, &efiramdisk_dp_guid, sizeof(grub_efi_guid_t));
    grub_memcpy(&device_path->addr[0], &disk_content, sizeof(void *));
    grub_memcpy(&device_path->size[0], &disk_size, sizeof(grub_efi_uintn_t));
    grub_efi_device_path_t *end_node = GRUB_EFI_NEXT_DEVICE_PATH(((grub_efi_device_path_t *)device_path));
    end_node->type = GRUB_EFI_END_DEVICE_PATH_TYPE;
    end_node->subtype = GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
    end_node->length = 4;
}


static grub_dl_t this_module = NULL;
#define MAX_DISK_COUNT 256
static efiramdisk_data_t *loaded_disk_datas[MAX_DISK_COUNT] = { 0 };


static grub_err_t release_efiramdisk(efiramdisk_data_t *data)
{
    grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
    grub_efi_status_t efi_status = GRUB_EFI_SUCCESS;

    efi_status = efi_call_3(b->disconnect_controller,
        data->handle,
        NULL,
        NULL);
    if (efi_status != GRUB_EFI_SUCCESS)
    {
        grub_errno = GRUB_ERR_ACCESS_DENIED;
        return grub_error(grub_errno,
            "EFI disconnect_controller failed (error 0x%llx)",
            (unsigned long long)efi_status);
    }

    efi_status = efi_call_10(
        b->uninstall_multiple_protocol_interfaces,
        data->handle,
        &efi_block_io_guid,
        &(data->block_io.efi_block_io),
        &efi_block_io2_guid,
        &(data->block_io2.efi_block_io2),
        &efi_device_path_guid,
        (grub_efi_device_path_t *)(&(data->device_path)),
        NULL,
        NULL,
        NULL);
    if (efi_status != GRUB_EFI_SUCCESS)
    {
        grub_errno = GRUB_ERR_ACCESS_DENIED;
        return grub_error(grub_errno,
            "EFI uninstall_multiple_protocol_interfaces failed (error 0x%llx)",
            (unsigned long long)efi_status);
    }

    efi_status = efi_call_1(b->free_pool, data->disk_content);
    if (efi_status != GRUB_EFI_SUCCESS)
    {
        grub_printf("EFI free_pool failed (error 0x%llx)\n",
            (unsigned long long)efi_status);
    }

    grub_free(data);

    return GRUB_ERR_NONE;
}

static const struct grub_arg_option efiramdisk_unload_arg_options[] = {
    {"index", 'i', 0, N_("The index of efiramdisk to unload."), "INDEX", ARG_TYPE_INT},
    {0, 0, 0, 0, 0, 0}};

static grub_err_t grub_cmd_efiramdisk_unload(
    struct grub_extcmd_context *ctxt,
    int argc __attribute__((unused)),
    char **args __attribute__((unused)))
{
    struct grub_arg_list *state = ctxt->state;

    if (!(state[0].set))
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "index (-i|--index INDEX) expected");

    char const *index_end = NULL;
    unsigned long index = grub_strtoul(state[0].arg, &index_end, 10);
    if (GRUB_ERR_NONE != grub_errno || *index_end)
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "index unrecognized");

    if (index >= MAX_DISK_COUNT || loaded_disk_datas[index] == NULL)
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "no disk on the specified index");

    grub_err_t r = release_efiramdisk(loaded_disk_datas[index]);
    if (r == GRUB_ERR_NONE)
    {
        loaded_disk_datas[index] = NULL;
        grub_dl_unref(this_module);
    }
    return r;
}


static grub_err_t do_checksum(char const *hashname, void const *buf, grub_size_t nbytes, char const *env_name)
{
    const gcry_md_spec_t *hash = grub_crypto_lookup_md_by_name(hashname);
    if (!hash)
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "unknown hash: %s", hashname);

    grub_size_t len = hash->mdlen;
    void *context = grub_zalloc(hash->contextsize + len * 2 + 1);
    if (!context)
        return GRUB_ERR_OUT_OF_MEMORY;

    hash->init(context);
    hash->write(context, buf, nbytes);
    hash->final(context);
    unsigned char *pb = (unsigned char *)(hash->read(context));

    char *string = ((char *)context) + hash->contextsize;
    char *ps = string;
    char const *digits = "0123456789abcdef";
    for (grub_size_t i = 0; i < len; ++i)
    {
        unsigned char byte = pb[i];
        *ps++ = digits[(byte >> 4) & 0xF];
        *ps++ = digits[byte & 0xF];
    }
    *ps = 0;

    grub_printf("checksum (%s): %s\n", hashname, string);

    if (env_name)
        grub_env_set(env_name, string);

    grub_free(context);
    return GRUB_ERR_NONE;
}

static const struct grub_arg_option efiramdisk_load_arg_options[] = {
    {"expand", 'x', 0, N_("Expand the efiramdisk to the specified size."), "SIZE", ARG_TYPE_INT},
    {"type", 't', 0, N_("The type of efiramdisk to load. Defaults to hd."), "hd|cd", ARG_TYPE_STRING},
    {"checksum", 0, 0, N_("Hash algo used to checksum the disk image file."), "HASH", ARG_TYPE_STRING},
    {"checksumsetvar", 0, 0, N_("Name of env var to store checksum result."), "VAR", ARG_TYPE_STRING},
    {"indexsetvar", 0, 0, N_("Name of env var to store the loaded efiramdisk index."), "VAR", ARG_TYPE_STRING},
    {0, 0, 0, 0, 0, 0}};

static grub_err_t grub_cmd_efiramdisk_load(
    struct grub_extcmd_context *ctxt, int argc, char **args)
{
    grub_err_t ret = GRUB_ERR_NONE;
    grub_efi_status_t efi_status = GRUB_EFI_SUCCESS;

    struct grub_arg_list *state = ctxt->state;

    grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;

    if (argc < 1)
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "disk image file path expected");

    if (state[3].set && !state[2].set)
        return grub_error(GRUB_ERR_BAD_ARGUMENT,
            "`--checksumsetvar VAR` needs `--checksum HASH` specified.");

    grub_efi_uint32_t block_size = EFIRAMDISK_HD_BLOCK_SIZE; /* Defaults to hd. */
    if (state[1].set)
    {
        if (grub_strcmp(state[1].arg, "hd") == 0)
            block_size = EFIRAMDISK_HD_BLOCK_SIZE;
        else if (grub_strcmp(state[1].arg, "cd") == 0)
            block_size = EFIRAMDISK_CD_BLOCK_SIZE;
        else
            return grub_error(GRUB_ERR_BAD_ARGUMENT, "expected hd|cd for -t|--type");
    }

    /* find the first free disk data slot */
    unsigned index = 0;
    for (; index < MAX_DISK_COUNT; ++index)
        if (loaded_disk_datas[index] == NULL)
            break;
    if (index >= MAX_DISK_COUNT)
        return grub_error(GRUB_ERR_ACCESS_DENIED, "no free disk slot");

    grub_efi_uintn_t max_disk_size = 0;
    max_disk_size -= block_size;

    grub_efi_uintn_t expand_size = 0;
    if (state[0].set)
    {
        unsigned long long expand_arg = grub_strtoull(state[0].arg, 0, 10);
        if (expand_arg > max_disk_size)
            return grub_error(GRUB_ERR_OUT_OF_MEMORY, "expand size too large");
        expand_size = (grub_efi_uintn_t)expand_arg;
    }

    grub_file_t file = grub_file_open(args[0], 0);
    if (!file)
        return grub_errno;

    grub_off_t file_size_raw = grub_file_size(file);
    if (file_size_raw > max_disk_size)
    {
        ret = grub_error(GRUB_ERR_OUT_OF_MEMORY, "file size too large");
        goto close_file;
    }
    grub_efi_uintn_t const file_size = (grub_efi_uintn_t)file_size_raw;

    grub_efi_uintn_t disk_size =
        expand_size > file_size ? expand_size : file_size;
    grub_efi_uintn_t block_count = (disk_size - 1U + block_size) / block_size;
    disk_size = block_count * block_size;

    //It seems that EFI allocate function is more tolerant
    //  to large memory allocations than grub_malloc.
    void *disk_content_vptr = NULL;
    efi_status = efi_call_3(b->allocate_pool, GRUB_EFI_RUNTIME_SERVICES_DATA,
        disk_size, &disk_content_vptr);
    if (efi_status != GRUB_EFI_SUCCESS)
    {
        grub_error(efi_status == GRUB_EFI_OUT_OF_RESOURCES ?
                GRUB_ERR_OUT_OF_MEMORY : GRUB_ERR_ACCESS_DENIED,
            "EFI failed to allocate memory for disk content (error 0x%llx)",
            (unsigned long long)efi_status);
        goto close_file;
    }
    char *disk_content = (char *)disk_content_vptr;

    /* load file to memory and show progress */
    grub_efi_uintn_t const read_unit = 2 * 1024 * 1024;//2MiB
    unsigned long long const file_size_mb = file_size >> 20U;
    unsigned char progress_reduce_precision = 0;
    {
        grub_uint64_t max_u64_div100 = 0;
        --max_u64_div100;
        max_u64_div100 /= 100U;
        if (file_size > max_u64_div100)
            progress_reduce_precision = 7;//x>>7 == x/128
    }
    char progress_bar[51];
    progress_bar[50] = 0;
    for (unsigned i = 0; i < 50; ++i) progress_bar[i] = ' ';
    unsigned progress_bar_i = 0;
    grub_printf("0/%lluMB[%s]00%%", file_size_mb, progress_bar);
    grub_refresh();
    for (grub_efi_uintn_t loaded_size = 0; loaded_size < file_size;)
    {
        grub_efi_uintn_t remaining = file_size - loaded_size;
        grub_efi_uintn_t request = (remaining < read_unit) ? remaining : read_unit;
        grub_ssize_t actual_read = grub_file_read(file, disk_content + loaded_size, request);
        if (actual_read < 0 || ((grub_size_t)actual_read) != request)
        {
            grub_error(grub_errno, "premature end of file");
            goto release_disk_content;
        }
        loaded_size += request;

        /* progress */
        grub_uint64_t x = loaded_size;
        x >>= progress_reduce_precision;
        grub_uint64_t y = file_size;
        y >>= progress_reduce_precision;
        unsigned percentage = (unsigned)(x * 100U / y);
        for (; progress_bar_i < percentage / 2; ++progress_bar_i)
            progress_bar[progress_bar_i] = '#';
        unsigned long long loaded_size_mb = loaded_size >> 20U;
        grub_printf("\r");
        grub_printf("%llu/%lluMB[%s]%02u%%",
            loaded_size_mb, file_size_mb, progress_bar, percentage);
        grub_refresh();
    }
    grub_printf("\n");

    /* clear extra memory */
    grub_memset(disk_content + file_size, 0, disk_size - file_size);

    /* checksum */
    if (state[2].set)
    {
        ret = do_checksum(state[2].arg, disk_content, file_size,
            state[3].set ? state[3].arg : NULL);
        if (ret != GRUB_ERR_NONE)
            goto release_disk_content;
    }

    /* create efiramdisk instance and register it to the EFI machinery */
    efiramdisk_data_t *data = grub_malloc(sizeof(efiramdisk_data_t));
    if (!data)
    {
        ret = GRUB_ERR_OUT_OF_MEMORY;
        goto release_disk_content;
    }
    init_efiramdisk_data(data, disk_content, disk_size, block_size, block_count);
    efi_status = efi_call_10(
        b->install_multiple_protocol_interfaces,
        &data->handle,
        &efi_block_io_guid,
        &(data->block_io.efi_block_io),
        &efi_block_io2_guid,
        &(data->block_io2.efi_block_io2),
        &efi_device_path_guid,
        (grub_efi_device_path_t *)(&(data->device_path)),
        NULL,
        NULL,
        NULL);
    if (efi_status != GRUB_EFI_SUCCESS)
    {
        ret = grub_error(GRUB_ERR_ACCESS_DENIED,
            "EFI install_multiple_protocol_interfaces failed (error 0x%llx)",
            (unsigned long long)efi_status);
        goto release_efiramdisk_data;
    }
    loaded_disk_datas[index] = data;
    grub_dl_ref(this_module);
    grub_printf("Successfully loaded efiramdisk #%u. Disk size: %llu.\n",
        (unsigned)index, (unsigned long long)(disk_size));
    if (state[4].set)
    {
        char buf[32] = { 0 };
        grub_snprintf(buf, 30, "%u", (unsigned)index);
        grub_env_set(state[4].arg, buf);
    }

    efi_status = efi_call_4(b->connect_controller, data->handle, NULL, NULL, efi_true);
    if (efi_status != GRUB_EFI_SUCCESS)
    {
        //The rollback operation (uninstall_multiple_protocol_interfaces) may fail.
        //So do not rollback.
        //Issue `efiramdisk_unload` command to rollback.
        grub_printf("EFI connect_controller failed (error 0x%llx)\n",
            (unsigned long long)efi_status);
    }

    goto close_file;

release_efiramdisk_data:
    grub_free(data);
release_disk_content:
    efi_call_1(b->free_pool, disk_content);//TODO: fail?
close_file:
    grub_file_close(file);
    return ret;
}


static grub_efi_handle_t efiloader_boot_image = NULL;

static grub_err_t efiloader_boot(void)
{
    if (efiloader_boot_image == NULL)
        return grub_error(GRUB_ERR_ACCESS_DENIED, "No boot image loaded.");

    grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
    grub_efi_uintn_t exit_data_size = 0;
    grub_efi_char16_t *exit_data = NULL;

    grub_puts("efiramdisk efiloader: starting image...");
    grub_efi_status_t start_image_result = efi_call_3(b->start_image, efiloader_boot_image, &exit_data_size, &exit_data);
    grub_puts("efiramdisk efiloader: EFI start_image returned");

    if (exit_data)
    {
        char *buf = grub_malloc(exit_data_size * GRUB_MAX_UTF8_PER_UTF16 + 1);
        if (buf)
        {
            *grub_utf16_to_utf8((grub_uint8_t *)buf, exit_data, exit_data_size) = 0;
            grub_puts("exit data:");
            grub_puts(buf);
            grub_free(buf);
        }
        else
        {
            grub_puts("no enough memory to print exit data.");
        }
        efi_call_1(b->free_pool, exit_data);
    }

    grub_loader_unset();

    if (start_image_result != GRUB_EFI_SUCCESS)
        return grub_error(GRUB_ERR_BAD_OS,
                          "EFI start_image failed (error 0x%llx)",
                          (unsigned long long)start_image_result);

    return GRUB_ERR_NONE;
}

static void efiloader_unload_image(grub_efi_handle_t image_handle)
{
    grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
    grub_efi_status_t efi_status = efi_call_1(b->unload_image, image_handle);
    if (efi_status != GRUB_EFI_SUCCESS)
        grub_printf("EFI unload_image failed (error 0x%llx)\n", (unsigned long long)efi_status);
}

static grub_err_t efiloader_unload(void)
{
    if (efiloader_boot_image != NULL)
    {
        efiloader_unload_image(efiloader_boot_image);
        efiloader_boot_image = NULL;
    }
    return GRUB_ERR_NONE;
}

static unsigned long efiloader_get_sfs_dp_rank(grub_efi_device_path_t *sfs_dp_tail)
{
    if (!sfs_dp_tail)
        return GRUB_ULONG_MAX;

    if (sfs_dp_tail->type == GRUB_EFI_END_DEVICE_PATH_TYPE)
        return 0;

    if (sfs_dp_tail->type == GRUB_EFI_MEDIA_DEVICE_PATH_TYPE)
    {
        if (sfs_dp_tail->subtype == GRUB_EFI_CDROM_DEVICE_PATH_SUBTYPE)
        {
            grub_efi_cdrom_device_path_t *p =
                (grub_efi_cdrom_device_path_t *)sfs_dp_tail;
            unsigned long r = p->boot_entry;
            return r + 1U;
        }
        if (sfs_dp_tail->subtype == GRUB_EFI_HARD_DRIVE_DEVICE_PATH_SUBTYPE)
        {
            grub_efi_hard_drive_device_path_t *p =
                (grub_efi_hard_drive_device_path_t *)sfs_dp_tail;
            unsigned long r = p->partition_number;
            return r + 1U;
        }
    }

    return GRUB_ULONG_MAX - 1U;
}

static grub_err_t efiloader_load(efiramdisk_data_t *data, char const *file_path)
{
    grub_err_t ret = GRUB_ERR_NONE;

    /* enumerate simple file system handles */
    grub_efi_uintn_t num_sfs_handles = 0;
    grub_efi_handle_t *sfs_handles = grub_efi_locate_handle(
        GRUB_EFI_BY_PROTOCOL, &efi_simple_file_system_guid, NULL, &num_sfs_handles);
    if (!sfs_handles)
        return grub_error(GRUB_ERR_ACCESS_DENIED,
            "grub_efi_locate_handle for simple file system failed");

    grub_size_t file_path_len = grub_strlen(file_path);
    grub_size_t file_u16path_len = file_path_len * GRUB_MAX_UTF16_PER_UTF8;
    char *file_end_dp = grub_memalign(
        2,
        sizeof(grub_efi_file_path_device_path_t)//file path dp header
        + (file_u16path_len + 1U) * sizeof(grub_efi_char16_t)//file path
        + sizeof(grub_efi_device_path_t)//end dp
    );
    if (!file_end_dp)
    {
        ret = GRUB_ERR_OUT_OF_MEMORY;
        goto release_sfs_handles;
    }
    grub_efi_file_path_device_path_t *file_dp = (grub_efi_file_path_device_path_t *)file_end_dp;
#if __GNUC__ >= 9
#pragma GCC diagnostic ignored "-Waddress-of-packed-member"
#endif
    file_u16path_len = grub_utf8_to_utf16(
        &(file_dp->path_name[0]),//2-aligned
        file_u16path_len,
        (grub_uint8_t const *)file_path,
        file_path_len,
        NULL);
    file_dp->path_name[file_u16path_len] = 0;
    grub_size_t file_dp_length = sizeof(grub_efi_file_path_device_path_t) +
        (file_u16path_len + 1U) * sizeof(grub_efi_char16_t);
    if (file_dp_length > 65535)//`length` member is 2 bytes
    {
        ret = grub_error(GRUB_ERR_OUT_OF_RANGE,
            "file path is too long to fit in efi file path device path");
        goto release_file_end_dp;
    }
    file_dp->header.length = (grub_efi_uint16_t)file_dp_length;
    file_dp->header.type = GRUB_EFI_MEDIA_DEVICE_PATH_TYPE;
    file_dp->header.subtype = GRUB_EFI_FILE_PATH_DEVICE_PATH_SUBTYPE;
    grub_efi_device_path_t *end_dp = GRUB_EFI_NEXT_DEVICE_PATH(&(file_dp->header));
    end_dp->type = GRUB_EFI_END_DEVICE_PATH_TYPE;
    end_dp->subtype = GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE;
    end_dp->length = 4;
    grub_size_t file_end_dp_len = ((char *)end_dp) - file_end_dp + 4U;

    efiramdisk_device_path_t *efiramdisk_dp_node = &(data->device_path.efiramdisk_node);
    grub_size_t efiramdisk_dp_size = sizeof(*efiramdisk_dp_node);

    unsigned long selected_dp_rank = GRUB_ULONG_MAX;
    grub_efi_handle_t loaded_image_handle = NULL;
    grub_efi_device_path_t *loaded_image_dp = NULL;
    for (grub_efi_uintn_t i = 0; i < num_sfs_handles; ++i)
    {
        grub_efi_device_path_t *sfs_dp = grub_efi_get_device_path(sfs_handles[i]);
        if (!sfs_dp)
            continue;

        //If sfs_dp is shorter than efiramdisk_dp_node, the short part is different.
        //So there is no out-of-bound read?
        //No! Actually this is undefined behavior.
        //See https://trust-in-soft.com/blog/2015/12/21/memcmp-requires-pointers-to-fully-valid-buffers/
        //So, FIXME.
        if (0 != grub_memcmp(sfs_dp, efiramdisk_dp_node, efiramdisk_dp_size))
            continue;
        grub_efi_device_path_t *sfs_dp_tail =
            (grub_efi_device_path_t *)(((char *)sfs_dp) + efiramdisk_dp_size);

        //test if better
        unsigned long dp_rank = efiloader_get_sfs_dp_rank(sfs_dp_tail);
        if (dp_rank >= selected_dp_rank)
            continue;

        grub_efi_device_path_t *sfs_end_node = sfs_dp_tail;
        while (!(sfs_end_node->type == GRUB_EFI_END_DEVICE_PATH_TYPE
            && sfs_end_node->subtype == GRUB_EFI_END_ENTIRE_DEVICE_PATH_SUBTYPE))
            sfs_end_node = GRUB_EFI_NEXT_DEVICE_PATH(sfs_end_node);
        grub_size_t sfs_dp_len = (char *)(sfs_end_node) - (char *)(sfs_dp);

        grub_efi_device_path_t *dp =
            (grub_efi_device_path_t *)grub_malloc(sfs_dp_len + file_end_dp_len);
        if (!dp)
        {
            ret = GRUB_ERR_OUT_OF_MEMORY;
            goto release_loaded_image;
        }
        grub_memcpy(dp, sfs_dp, sfs_dp_len);
        grub_memcpy(((char *)dp) + sfs_dp_len, file_end_dp, file_end_dp_len);

        grub_efi_handle_t h = NULL;
        grub_efi_boot_services_t *b = grub_efi_system_table->boot_services;
        grub_efi_status_t efi_status = efi_call_6(
            b->load_image,
            efi_true,
            grub_efi_image_handle,
            (grub_efi_device_path_t *)dp,
            NULL,
            0,
            &h);
        if (efi_status != GRUB_EFI_SUCCESS || h == NULL)
        {
            grub_free(dp);
            continue;
        }
        else
        {
            if (loaded_image_handle != NULL)
                efiloader_unload_image(loaded_image_handle);
            if (loaded_image_dp != NULL)
                grub_free(loaded_image_dp);
            loaded_image_handle = h;
            loaded_image_dp = dp;
            selected_dp_rank = dp_rank;
        }
    }
    if (loaded_image_handle == NULL)
    {
        ret = grub_error(GRUB_ERR_FILE_NOT_FOUND,
            "the specified file can not be found or be loaded");
        goto release_loaded_image;
    }

    grub_efi_loaded_image_t *loaded_image = grub_efi_get_loaded_image(loaded_image_handle);
    if (!loaded_image)
    {
        ret = grub_error(GRUB_ERR_ACCESS_DENIED, "grub_efi_get_loaded_image failed");
        goto release_loaded_image;
    }

    grub_printf("Loaded image, base=0x%llX, size=%llu, device path:\n",
        (unsigned long long)(loaded_image->image_base),
        (unsigned long long)(loaded_image->image_size));
    grub_efi_print_device_path(loaded_image_dp);

    grub_loader_unset();
    grub_loader_set(efiloader_boot, efiloader_unload, 0);
    efiloader_boot_image = loaded_image_handle;
    loaded_image_handle = NULL;

release_loaded_image:
    if (loaded_image_handle != NULL)
        efiloader_unload_image(loaded_image_handle);
    if (loaded_image_dp != NULL)
        grub_free(loaded_image_dp);
release_file_end_dp:
    grub_free(file_end_dp);
release_sfs_handles:
    grub_free(sfs_handles);
    return ret;
}

static const struct grub_arg_option efiramdisk_efiloader_arg_options[] = {
    {"index", 'i', 0, N_("The index of efiramdisk to load image from."), "INDEX", ARG_TYPE_INT},
    {0, 0, 0, 0, 0, 0}};

static grub_err_t grub_cmd_efiramdisk_efiloader(
    struct grub_extcmd_context *ctxt, int argc, char **args)
{
    struct grub_arg_list *state = ctxt->state;

    if (!(state[0].set))
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "index (-i|--index INDEX) expected");

    char const *index_end = NULL;
    unsigned long index = grub_strtoul(state[0].arg, &index_end, 10);
    if (GRUB_ERR_NONE != grub_errno || *index_end)
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "index unrecognized");

    if (index >= MAX_DISK_COUNT || loaded_disk_datas[index] == NULL)
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "no disk on the specified index");

    if (argc != 1)
        return grub_error(GRUB_ERR_BAD_ARGUMENT, "expected one boot file path");
    char * image_path = args[0];

    return efiloader_load(loaded_disk_datas[index], image_path);
}


static grub_extcmd_t cmd_load, cmd_unload, cmd_efiloader;

GRUB_MOD_INIT(efiramdisk)
{
    this_module = mod;

    cmd_load = grub_register_extcmd(
        "efiramdisk_load",
        grub_cmd_efiramdisk_load,
        0,
        N_("[-x|--expand SIZE] [-t|--type hd|cd] [--checksum HASH] [--checksumsetvar VAR] [--indexsetvar VAR] filepath"),
        N_("Load efiramdisk."),
        efiramdisk_load_arg_options);

    cmd_unload = grub_register_extcmd(
        "efiramdisk_unload",
        grub_cmd_efiramdisk_unload,
        0,
        N_("-i|--index INDEX"),
        N_("Unload efiramdisk."),
        efiramdisk_unload_arg_options);

    cmd_efiloader = grub_register_extcmd(
        "efiramdisk_efiloader",
        grub_cmd_efiramdisk_efiloader,
        0,
        N_("-i|--index INDEX imagepath"),
        N_("Load image on the specified efiramdisk at the specified path to boot. DO NOT use backslash(/) or double-slash(\\\\) in imagepath."),
        efiramdisk_efiloader_arg_options);
}

GRUB_MOD_FINI(efiramdisk)
{
    efiloader_unload();
    for (unsigned i = 0; i < MAX_DISK_COUNT; ++i)
    {
        efiramdisk_data_t *data = loaded_disk_datas[i];
        if (data && GRUB_ERR_NONE == release_efiramdisk(data))
            loaded_disk_datas[i] = NULL;
    }
    grub_unregister_extcmd(cmd_load);
    grub_unregister_extcmd(cmd_unload);
    grub_unregister_extcmd(cmd_efiloader);
}
