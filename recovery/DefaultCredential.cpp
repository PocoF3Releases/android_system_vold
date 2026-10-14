/*
 * Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0
 *
 * Mirrors the LSKF protector and SP v2/v3 derivation in Android 17's
 * SyntheticPasswordManager, SyntheticPasswordCrypto and SP800Derive.
 */
#include "DefaultCredential.h"

#include <aidl/android/security/authorization/IKeystoreAuthorization.h>
#include <android/hardware/gatekeeper/1.0/IGatekeeper.h>
#include <endian.h>
#include <hardware/hw_auth_token.h>
#include <inttypes.h>
#include <sys/stat.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/stringprintf.h>
#include <android/binder_manager.h>
#include <aidl/android/system/keystore2/IKeystoreService.h>
#include <aidl/android/system/keystore2/IKeystoreSecurityLevel.h>
#include <aidl/android/system/keystore2/IKeystoreOperation.h>
#include <aidl/android/system/keystore2/Domain.h>
#include <aidl/android/hardware/security/keymint/KeyParameter.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <sqlite3.h>

namespace ks = aidl::android::system::keystore2;
namespace km = aidl::android::hardware::security::keymint;

namespace {
struct SensitiveBytes {
    std::vector<uint8_t> bytes;
    ~SensitiveBytes() { OPENSSL_cleanse(bytes.data(), bytes.size()); }
};

std::vector<uint8_t> PersonalizedHash(const std::string& label,
                                     const std::vector<uint8_t>& input) {
    if (label.size() > 128) return {};
    std::array<uint8_t, 128> prefix {};
    memcpy(prefix.data(), label.data(), label.size());
    SHA512_CTX ctx;
    SHA512_Init(&ctx);
    SHA512_Update(&ctx, prefix.data(), prefix.size());
    SHA512_Update(&ctx, input.data(), input.size());
    std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);
    SHA512_Final(hash.data(), &ctx);
    OPENSSL_cleanse(&ctx, sizeof(ctx));
    return hash;
}

bool ReadState(const std::string& path, std::vector<uint8_t>* output) {
    struct stat st {};
    if (stat(path.c_str(), &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < 0 || st.st_size > 128 * 1024) return false;
    std::string contents;
    if (!android::base::ReadFileToString(path, &contents)) return false;
    output->assign(contents.begin(), contents.end());
    OPENSSL_cleanse(contents.data(), contents.size());
    return true;
}

bool ReadProtector(uint64_t* protector) {
    sqlite3* database = nullptr;
    if (sqlite3_open_v2("/tmp/recovery-locksettings/locksettings.db", &database,
                        SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, nullptr) != SQLITE_OK) {
        if (database) sqlite3_close(database);
        return false;
    }
    sqlite3_stmt* statement = nullptr;
    bool result = false;
    if (sqlite3_prepare_v2(database,
        "SELECT value FROM locksettings WHERE name='sp-handle' AND user=0", -1,
        &statement, nullptr) == SQLITE_OK && sqlite3_step(statement) == SQLITE_ROW) {
        const auto value = sqlite3_column_text(statement, 0);
        int64_t signed_id;
        if (value && android::base::ParseInt(reinterpret_cast<const char*>(value), &signed_id)
            && signed_id != 0) {
            *protector = static_cast<uint64_t>(signed_id);
            result = true;
        }
    }
    sqlite3_finalize(statement);
    sqlite3_close(database);
    return result;
}

bool SoftwareDecrypt(const std::vector<uint8_t>& protector_secret,
                     const std::vector<uint8_t>& encrypted, std::vector<uint8_t>* plaintext) {
    if (encrypted.size() < 12 + 16) return false;
    SensitiveBytes key {PersonalizedHash("application-id", protector_secret)};
    if (key.bytes.size() < 32) return false;
    std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>
        ctx(EVP_CIPHER_CTX_new(), EVP_CIPHER_CTX_free);
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr,
                                  key.bytes.data(), encrypted.data()) != 1) return false;
    const auto length = encrypted.size() - 12 - 16;
    plaintext->resize(length + 16);
    int produced = 0, tail = 0;
    if (EVP_DecryptUpdate(ctx.get(), plaintext->data(), &produced,
                          encrypted.data() + 12, length) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, 16,
                            const_cast<uint8_t*>(encrypted.data() + 12 + length)) != 1 ||
        EVP_DecryptFinal_ex(ctx.get(), plaintext->data() + produced, &tail) != 1) return false;
    plaintext->resize(produced + tail);
    return true;
}

bool HardwareDecrypt(uint64_t protector, const std::vector<uint8_t>& encrypted,
                     std::vector<uint8_t>* plaintext) {
    if (encrypted.size() < 12 + 16) return false;
    ndk::SpAIBinder binder(AServiceManager_checkService(
        "android.system.keystore2.IKeystoreService/default"));
    auto service = ks::IKeystoreService::fromBinder(binder);
    if (!service) return false;
    ks::KeyDescriptor descriptor;
    descriptor.domain = ks::Domain::SELINUX;
    descriptor.nspace = 103;  // KeyProperties.NAMESPACE_LOCKSETTINGS
    descriptor.alias = android::base::StringPrintf("synthetic_password_%" PRIx64, protector);
    ks::KeyEntryResponse entry;
    if (!service->getKeyEntry(descriptor, &entry).isOk() || !entry.iSecurityLevel) return false;
    std::vector<km::KeyParameter> parameters;
    km::KeyParameter p;
    p.tag = km::Tag::PURPOSE;
    p.value = km::KeyParameterValue::make<km::KeyParameterValue::Tag::keyPurpose>(km::KeyPurpose::DECRYPT);
    parameters.push_back(p);
    p.tag = km::Tag::BLOCK_MODE;
    p.value = km::KeyParameterValue::make<km::KeyParameterValue::Tag::blockMode>(km::BlockMode::GCM);
    parameters.push_back(p);
    p.tag = km::Tag::PADDING;
    p.value = km::KeyParameterValue::make<km::KeyParameterValue::Tag::paddingMode>(km::PaddingMode::NONE);
    parameters.push_back(p);
    p.tag = km::Tag::MAC_LENGTH;
    p.value = km::KeyParameterValue::make<km::KeyParameterValue::Tag::integer>(128);
    parameters.push_back(p);
    p.tag = km::Tag::NONCE;
    p.value = km::KeyParameterValue::make<km::KeyParameterValue::Tag::blob>(
        std::vector<uint8_t>(encrypted.begin(), encrypted.begin() + 12));
    parameters.push_back(p);
    ks::CreateOperationResponse operation;
    if (!entry.iSecurityLevel->createOperation(entry.metadata.key, parameters, false, &operation).isOk()
        || !operation.iOperation || operation.operationChallenge) {
        if (operation.iOperation) operation.iOperation->abort();
        return false;
    }
    std::optional<std::vector<uint8_t>> result;
    const std::optional<std::vector<uint8_t>> input(
        std::vector<uint8_t>(encrypted.begin() + 12, encrypted.end()));
    if (!operation.iOperation->finish(input, std::nullopt, &result).isOk() || !result) {
        operation.iOperation->abort();
        return false;
    }
    *plaintext = std::move(*result);
    return true;
}

std::vector<uint8_t> DeriveStorageSecret(uint8_t version, const std::vector<uint8_t>& sp) {
    if (version == 2) return PersonalizedHash("fbe-key", sp);
    if (version != 3) return {};
    const std::string label = "fbe-key";
    const std::string context = "android-synthetic-password-personalization-context";
    std::vector<uint8_t> input {0, 0, 0, 1};
    input.insert(input.end(), label.begin(), label.end());
    input.push_back(0);
    input.insert(input.end(), context.begin(), context.end());
    const uint32_t context_bits = context.size() * 8;
    for (int shift = 24; shift >= 0; shift -= 8) input.push_back(context_bits >> shift);
    input.insert(input.end(), {0, 0, 1, 0});  // 256 output bits
    std::vector<uint8_t> result(SHA256_DIGEST_LENGTH);
    unsigned int length = result.size();
    if (!HMAC(EVP_sha256(), sp.data(), sp.size(), input.data(), input.size(),
               result.data(), &length) || length != result.size()) return {};
    return result;
}

struct PasswordData {
    int type = -2;
    uint8_t log_n = 0, log_r = 0, log_p = 0;
    std::vector<uint8_t> salt, handle;
};

bool ParsePasswordData(const std::vector<uint8_t>& data, PasswordData* pwd) {
    size_t offset = 0;
    auto integer = [&](uint32_t* value) {
        if (data.size() - offset < 4) return false;
        *value = 0;
        for (int i = 0; i < 4; ++i) *value = (*value << 8) | data[offset++];
        return true;
    };
    uint32_t type, size;
    if (!integer(&type) || data.size() - offset < 3) return false;
    pwd->type = static_cast<int16_t>(type);  // Android 14 beta compatibility.
    pwd->log_n = data[offset++];
    pwd->log_r = data[offset++];
    pwd->log_p = data[offset++];
    if (!integer(&size) || size == 0 || size > 64 || size > data.size() - offset) return false;
    pwd->salt.assign(data.begin() + offset, data.begin() + offset + size);
    offset += size;
    if (!integer(&size) || size == 0 || size > 4096 || size > data.size() - offset) return false;
    pwd->handle.assign(data.begin() + offset, data.begin() + offset + size);
    offset += size;
    return data.size() - offset == 0 || data.size() - offset == 4;
}

bool VerifyGatekeeper(const PasswordData& pwd, const std::vector<uint8_t>& stretched) {
    using android::hardware::gatekeeper::V1_0::GatekeeperStatusCode;
    using android::hardware::gatekeeper::V1_0::IGatekeeper;
    auto gatekeeper = IGatekeeper::tryGetService();
    for (int i = 0; !gatekeeper && i < 50; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        gatekeeper = IGatekeeper::tryGetService();
    }
    if (!gatekeeper) {
        LOG(ERROR) << "Recovery Gatekeeper is unavailable";
        return false;
    }
    SensitiveBytes password{PersonalizedHash("user-gk-authentication", stretched)}, token;
    bool verified = false;
    int response_code = -1;
    auto result =
            gatekeeper->verify(100000, 0, pwd.handle, password.bytes, [&](const auto& response) {
                response_code = static_cast<int>(response.code);
                if (response.code == GatekeeperStatusCode::ERROR_RETRY_TIMEOUT) {
                    LOG(ERROR) << "Credential verification throttled for " << response.timeout
                               << " ms";
                    return;
                }
                verified = response.code == GatekeeperStatusCode::STATUS_OK ||
                           response.code == GatekeeperStatusCode::STATUS_REENROLL;
                if (verified) token.bytes.assign(response.data.begin(), response.data.end());
            });
    // Do not reenroll, delete users, or persist credential state from recovery.
    if (!result.isOk() || !verified || token.bytes.size() != sizeof(hw_auth_token_t)) {
        LOG(ERROR) << "Gatekeeper verification failed (status " << response_code << ", transport "
                   << result.isOk() << ", token size " << token.bytes.size() << ")";
        return false;
    }
    hw_auth_token_t raw;
    memcpy(&raw, token.bytes.data(), sizeof(raw));
    km::HardwareAuthToken auth;
    auth.challenge = raw.challenge;
    auth.userId = raw.user_id;
    auth.authenticatorId = raw.authenticator_id;
    auth.authenticatorType =
            static_cast<km::HardwareAuthenticatorType>(be32toh(raw.authenticator_type));
    auth.timestamp.milliSeconds = be64toh(raw.timestamp);
    auth.mac.assign(raw.hmac, raw.hmac + sizeof(raw.hmac));
    OPENSSL_cleanse(&raw, sizeof(raw));
    auto service = aidl::android::security::authorization::IKeystoreAuthorization::fromBinder(
            ndk::SpAIBinder(AServiceManager_checkService("android.security.authorization")));
    bool accepted = false;
    if (service) {
        const auto status = service->addAuthToken(auth);
        accepted = status.isOk();
        if (!accepted)
            LOG(ERROR) << "Auth token delivery failed (exception " << status.getExceptionCode()
                       << ", service " << status.getServiceSpecificError() << ")";
    } else {
        LOG(ERROR) << "Recovery authorization service unavailable";
    }
    OPENSSL_cleanse(auth.mac.data(), auth.mac.size());
    return accepted;
}
}  // namespace

int RecoveryCredentialType() {
    uint64_t protector;
    if (!ReadProtector(&protector)) return -2;
    const auto prefix =
            android::base::StringPrintf("/data/system_de/0/spblob/%016" PRIx64, protector);
    struct stat st{};
    if (stat((prefix + ".weaver").c_str(), &st) == 0) return -2;
    if (stat((prefix + ".pwd").c_str(), &st) != 0) return errno == ENOENT ? -1 : -2;
    SensitiveBytes data;
    PasswordData pwd;
    return ReadState(prefix + ".pwd", &data.bytes) && ParsePasswordData(data.bytes, &pwd) ? pwd.type
                                                                                          : -2;
}

bool RecoveryCredentialSecret(const std::vector<uint8_t>& credential,
                              std::vector<uint8_t>* secret) {
    uint64_t protector = 0;
    if (!ReadProtector(&protector)) return false;
    const auto prefix = android::base::StringPrintf("/data/system_de/0/spblob/%016" PRIx64, protector);
    struct stat st {};
    if (stat((prefix + ".weaver").c_str(), &st) == 0) {
        LOG(ERROR) << "Weaver protectors are not supported by this recovery path";
        return false;
    }
    SensitiveBytes secdiscardable, blob, protector_secret, intermediate, sp;
    if (!ReadState(prefix + ".secdis", &secdiscardable.bytes) ||
        secdiscardable.bytes.size() != 16 * 1024 || !ReadState(prefix + ".spblob", &blob.bytes) ||
        blob.bytes.size() < 2 || (blob.bytes[0] != 2 && blob.bytes[0] != 3) || blob.bytes[1] != 0) {
        LOG(ERROR) << "Invalid synthetic password protector state";
        return false;
    }
    protector_secret.bytes.resize(32, 0);
    if (stat((prefix + ".pwd").c_str(), &st) == 0) {
        SensitiveBytes serialized;
        PasswordData pwd;
        if (!ReadState(prefix + ".pwd", &serialized.bytes) ||
            !ParsePasswordData(serialized.bytes, &pwd) || (pwd.type != 3 && pwd.type != 4) ||
            credential.empty() || credential.size() > 64 || pwd.log_n > 20 || pwd.log_r > 8 ||
            pwd.log_p > 8) {
            LOG(ERROR) << "Invalid password derivation parameters";
            return false;
        }
        const uint64_t n = 1ULL << pwd.log_n, r = 1ULL << pwd.log_r, p = 1ULL << pwd.log_p;
        if (128 * n * r > 64 * 1024 * 1024 ||
            EVP_PBE_scrypt(reinterpret_cast<const char*>(credential.data()), credential.size(),
                           pwd.salt.data(), pwd.salt.size(), n, r, p, 64 * 1024 * 1024,
                           protector_secret.bytes.data(), protector_secret.bytes.size()) != 1) {
            LOG(ERROR) << "Password stretching failed";
            return false;
        }
        if (!VerifyGatekeeper(pwd, protector_secret.bytes)) {
            LOG(ERROR) << "Credential authentication failed";
            return false;
        }
    } else {
        if (errno != ENOENT || !credential.empty()) return false;
        const std::string default_password = "default-password";
        memcpy(protector_secret.bytes.data(), default_password.data(), default_password.size());
    }
    SensitiveBytes sec_hash {PersonalizedHash("secdiscardable-transform", secdiscardable.bytes)};
    protector_secret.bytes.insert(protector_secret.bytes.end(), sec_hash.bytes.begin(), sec_hash.bytes.end());
    const std::vector<uint8_t> encrypted(blob.bytes.begin() + 2, blob.bytes.end());
    if (!HardwareDecrypt(protector, encrypted, &intermediate.bytes) ||
        !SoftwareDecrypt(protector_secret.bytes, intermediate.bytes, &sp.bytes) || sp.bytes.size() != 128)
        return false;
    *secret = DeriveStorageSecret(blob.bytes[0], sp.bytes);
    return !secret->empty();
}
