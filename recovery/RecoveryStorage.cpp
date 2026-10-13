/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0 */
#include "DefaultCredential.h"
#include "FsCrypt.h"
#include "MetadataCrypt.h"
#include "Utils.h"
#include "VoldUtil.h"

#include <fcntl.h>
#include <linux/fscrypt.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>

#include <array>
#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/scopeguard.h>
#include <android-base/unique_fd.h>
#include <android/binder_manager.h>
#include <android/binder_auto_utils.h>
#include <cutils/fs.h>
#include <fstab/fstab.h>
#include <openssl/crypto.h>
#include <private/android_filesystem_config.h>
#include <selinux/android.h>

namespace {
using android::base::GetProperty;
using android::base::SetProperty;

bool IsStorageUnlocked() {
    android::base::unique_fd directory(open("/data/media/0", O_RDONLY | O_DIRECTORY | O_CLOEXEC));
    if (directory < 0) return false;
    fscrypt_get_policy_ex_arg policy {};
    policy.policy_size = sizeof(policy.policy);
    if (ioctl(directory.get(), FS_IOC_GET_ENCRYPTION_POLICY_EX, &policy) != 0 ||
        policy.policy.version != FSCRYPT_POLICY_V2) return false;
    fscrypt_get_key_status_arg status {};
    status.key_spec.type = FSCRYPT_KEY_SPEC_TYPE_IDENTIFIER;
    memcpy(status.key_spec.u.identifier, policy.policy.v2.master_key_identifier,
           FSCRYPT_KEY_IDENTIFIER_SIZE);
    return ioctl(directory.get(), FS_IOC_GET_ENCRYPTION_KEY_STATUS, &status) == 0 &&
           status.status == FSCRYPT_KEY_STATUS_PRESENT;
}

bool WaitKeystore(bool running) {
    for (int i = 0; i < 100; ++i) {
        ndk::SpAIBinder binder(AServiceManager_checkService(
            "android.system.keystore2.IKeystoreService/default"));
        if (static_cast<bool>(binder.get()) == running) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return false;
}

bool StartKeystore() {
    // Keystore defers irreversible hardware-key garbage collection until
    // Android boot completes. Never start the snapshot service after that phase.
    if (android::base::GetBoolProperty("sys.boot_completed", false)) return false;
    if (!SetProperty("ctl.start", "keystore2-recovery")) return false;
    if (WaitKeystore(true)) return true;
    SetProperty("ctl.stop", "keystore2-recovery");
    return false;
}

bool StopRecoveryCryptoServices() {
    bool success = true;
    for (const char* service : {"keystore2-recovery", "recovery-keymaster", "recovery-qseecomd"}) {
        const bool stopped = SetProperty("ctl.stop", service);
        const bool exited = stopped && android::base::WaitForProperty(
            std::string("init.svc.") + service, "stopped", std::chrono::seconds(5));
        success = exited && success;
    }
    return success;
}

bool SnapshotDatabase(const std::string& source, const std::string& directory, uid_t owner) {
    if (fs_prepare_dir(directory.c_str(), 0700, AID_ROOT, AID_ROOT) != 0) return false;
    const auto filename = source.substr(source.rfind('/') + 1);
    for (const std::string suffix : {"", "-wal", "-shm"}) {
        if (unlink((directory + "/" + filename + suffix).c_str()) != 0 && errno != ENOENT)
            return false;
    }
    for (const std::string suffix : {"", "-wal"}) {
        const auto path = source + suffix;
        android::base::unique_fd input(open(path.c_str(), O_RDONLY | O_CLOEXEC));
        if (input < 0) {
            if (!suffix.empty() && errno == ENOENT) continue;
            return false;
        }
        struct stat st {};
        if (fstat(input.get(), &st) != 0 || !S_ISREG(st.st_mode) ||
            st.st_size < 0 || st.st_size > 512 * 1024 * 1024) return false;
        const auto target = directory + "/" + source.substr(source.rfind('/') + 1) + suffix;
        android::base::unique_fd output(open(target.c_str(), O_WRONLY | O_CREAT | O_TRUNC |
                                             O_CLOEXEC | O_NOFOLLOW, 0600));
        if (output < 0) return false;
        std::array<char, 64 * 1024> buffer {};
        for (off_t offset = 0; offset < st.st_size; offset += buffer.size()) {
            const auto count = std::min<off_t>(buffer.size(), st.st_size - offset);
            if (!android::base::ReadFullyAtOffset(input.get(), buffer.data(), count, offset) ||
                !android::base::WriteFully(output.get(), buffer.data(), count)) return false;
        }
        if (fchown(output.get(), owner, owner) != 0 || fsync(output.get()) != 0) return false;
    }
    if (chown(directory.c_str(), owner, owner) != 0) return false;
    return owner != AID_KEYSTORE || selinux_android_restorecon(directory.c_str(),
                                                            SELINUX_ANDROID_RESTORECON_RECURSE) == 0;
}

bool InitializeExistingKeys() {
    return fscrypt_initialize_systemwide_keys() && fscrypt_init_user0();
}

bool LoadFstab() {
    if (!android::fs_mgr::ReadDefaultFstab(&fstab_default)) return false;
    for (auto& entry : fstab_default) {
        // Installation reads internal storage. Do not format, repair, or alter
        // its contents as a side effect of mounting for decryption.
        entry.fs_mgr_flags.formattable = false;
        entry.fs_mgr_flags.check = false;
        if (entry.mount_point == "/data") entry.flags |= MS_RDONLY;
    }
    if (GetProperty("ro.crypto.type", "").empty() && !SetProperty("ro.crypto.type", "file"))
        return false;
    return GetProperty("ro.crypto.type", "") == "file";
}

bool MountExistingData() {
    auto entry = android::fs_mgr::GetEntryForMountPoint(&fstab_default, "/data");
    if (!entry || entry->metadata_key_dir.empty() ||
        access((entry->metadata_key_dir + "/key").c_str(), R_OK) != 0) return false;
    return android::vold::fscrypt_mount_metadata_encrypted(entry->blk_device, "/data", false,
        false, entry->fs_type, false, {}, {}, 0) && InitializeExistingKeys();
}
}  // namespace

int main(int argc, char** argv) {
    android::base::InitLogging(argv, android::base::StderrLogger);
    // Only a recovery ramdisk has this fstab. Never operate from normal Android.
    if (access("/system/etc/recovery.fstab", R_OK) != 0 || !LoadFstab()) return 1;
    if (prctl(PR_SET_PDEATHSIG, SIGTERM) != 0 || getppid() == 1) return 1;
    alarm(90);
    if (argc == 2 && std::string(argv[1]) == "--cleanup")
        return StopRecoveryCryptoServices() ? 0 : 1;
    if (argc == 2 && std::string(argv[1]) == "--mount") return MountExistingData() ? 0 : 1;
    if (argc == 2 && std::string(argv[1]) == "--unlock") {
        if (!InitializeExistingKeys()) return 1;
        std::vector<uint8_t> secret;
        const bool derived = RecoveryDefaultCredentialSecret(&secret);
        const bool unlocked = derived && fscrypt_unlock_ce_storage(0, secret);
        OPENSSL_cleanse(secret.data(), secret.size());
        return unlocked && IsStorageUnlocked() ? 0 : 1;
    }
    if (argc != 1) return 1;
    if (IsStorageUnlocked()) return 0;
    auto cleanup = android::base::make_scope_guard([] { StopRecoveryCryptoServices(); });
    if (!SetProperty("ctl.start", "hwservicemanager-recovery") ||
        !android::base::WaitForProperty("hwservicemanager.ready", "true", std::chrono::seconds(10)))
        return 1;
    if (!SetProperty("ctl.start", "recovery-qseecomd") ||
        !android::base::WaitForProperty("vendor.sys.listeners.registered", "true",
                                       std::chrono::seconds(10)) ||
        !SetProperty("ctl.start", "recovery-keymaster")) return 1;
    if (fs_prepare_dir("/tmp/recovery-keystore", 0700, AID_KEYSTORE, AID_KEYSTORE) != 0 ||
        selinux_android_restorecon("/tmp/recovery-keystore", SELINUX_ANDROID_RESTORECON_RECURSE) != 0 ||
        !StartKeystore()) return 1;
    const auto mount_result = android::vold::ForkExecvp({argv[0], "--mount"});
    SetProperty("ctl.stop", "keystore2-recovery");
    if (!WaitKeystore(false) || mount_result != 0) return 1;
    // Work with ephemeral copies, including SQLite's WAL. No keystore schema
    // migration or locksettings database write touches the user's originals.
    if (!SnapshotDatabase("/data/misc/keystore/persistent.sqlite", "/tmp/recovery-keystore", AID_KEYSTORE) ||
        !SnapshotDatabase("/data/system/locksettings.db", "/tmp/recovery-locksettings", AID_ROOT) ||
        !StartKeystore()) return 1;
    const auto unlock_result = android::vold::ForkExecvp({argv[0], "--unlock"});
    SetProperty("ctl.stop", "keystore2-recovery");
    return unlock_result == 0 && IsStorageUnlocked() ? 0 : 1;
}
