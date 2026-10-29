# RootOfTrust is OPTIONAL in the pinned ASN.1 schema. Unknown SOFTWARE boot
# state is omitted; failures for hardware security levels remain failures.
file(READ "${KEYMASTER_DIR}/km_openssl/attestation_record.cpp" ATTESTATION_SOURCE)
set(ROOT_START_MARKER "    KM_ROOT_OF_TRUST* root_of_trust = nullptr;")
set(ROOT_END_MARKER "    if (!ASN1_INTEGER_set(key_desc->attestation_version,")
string(FIND "${ATTESTATION_SOURCE}" "${ROOT_START_MARKER}" ROOT_START)
string(FIND "${ATTESTATION_SOURCE}" "${ROOT_END_MARKER}" ROOT_END)
if(ROOT_START LESS 0 OR ROOT_END LESS ROOT_START)
  message(FATAL_ERROR "Pinned attestation RootOfTrust port markers changed")
endif()
string(SUBSTRING "${ATTESTATION_SOURCE}" 0 ${ROOT_START} ATTESTATION_PREFIX)
string(SUBSTRING "${ATTESTATION_SOURCE}" ${ROOT_END} -1 ATTESTATION_SUFFIX)
set(SOFTWARE_UNKNOWN_ROOT [=[
    keymaster_error_t error = KM_ERROR_UNKNOWN_ERROR;
    auto vb_params = context.GetVerifiedBootParams(&error);
    const bool omit_unknown_software_root =
        context.GetSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE &&
        error == KM_ERROR_UNIMPLEMENTED && vb_params == nullptr;
    if (error != KM_ERROR_OK && !omit_unknown_software_root) return error;
    if (!omit_unknown_software_root) {
        if (!vb_params) return KM_ERROR_UNKNOWN_ERROR;
        KM_ROOT_OF_TRUST* root_of_trust = KM_ROOT_OF_TRUST_new();
        if (!root_of_trust) return KM_ERROR_MEMORY_ALLOCATION_FAILED;
        if (context.GetSecurityLevel() == KM_SECURITY_LEVEL_SOFTWARE) {
            key_desc->software_enforced->root_of_trust = root_of_trust;
        } else {
            key_desc->tee_enforced->root_of_trust = root_of_trust;
        }
        if (vb_params->verified_boot_key.data_length &&
            !ASN1_OCTET_STRING_set(root_of_trust->verified_boot_key, vb_params->verified_boot_key.data,
                                  vb_params->verified_boot_key.data_length)) {
            return TranslateLastOpenSslError();
        }
        if (vb_params->verified_boot_hash.data_length &&
            !ASN1_OCTET_STRING_set(root_of_trust->verified_boot_hash, vb_params->verified_boot_hash.data,
                                  vb_params->verified_boot_hash.data_length)) {
            return TranslateLastOpenSslError();
        }
        root_of_trust->device_locked = vb_params->device_locked ? 0xFF : 0x00;
        if (!ASN1_ENUMERATED_set(root_of_trust->verified_boot_state, vb_params->verified_boot_state)) {
            return TranslateLastOpenSslError();
        }
    }
    error = KM_ERROR_OK;

]=])
file(WRITE "${CMAKE_CURRENT_BINARY_DIR}/attestation_record.cpp"
  "${ATTESTATION_PREFIX}${SOFTWARE_UNKNOWN_ROOT}${ATTESTATION_SUFFIX}")
