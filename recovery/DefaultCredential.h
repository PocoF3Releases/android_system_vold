/* Copyright (C) 2026 The Android Open Source Project
 * SPDX-License-Identifier: Apache-2.0 */
#pragma once
#include <cstdint>
#include <vector>
int RecoveryCredentialType();
bool RecoveryCredentialSecret(const std::vector<uint8_t>& credential, std::vector<uint8_t>* secret);
