#include "cng_keymint_context.h"
#include "hybrid_keymint_context.h"
#include <keymaster/android_keymaster.h>
#include <keymaster/android_keymaster_messages.h>
#include <keymaster/keymaster_context.h>
#include <openssl/sha.h>

#include <windows.h>
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <set>
#include <stdexcept>
#include <string>
#include <thread>
#include <type_traits>
#include <vector>

namespace {
using namespace keymaster;
constexpr uint32_t kResponse = 0x80000000;
constexpr size_t kMaximumFrame = 1024 * 1024;
constexpr int kVersion = 4;
size_t cng_generations = 0, software_generations = 0, protected_signatures = 0;
std::set<keymaster_operation_handle_t> protected_operations;
void Require(bool value, const char* code) { if (!value) throw std::runtime_error(code); }
std::string Sha256Hex(const std::vector<uint8_t>& bytes) {
    uint8_t digest[SHA256_DIGEST_LENGTH]{};
    Require(!bytes.empty() && SHA256(bytes.data(), bytes.size(), digest), "PUBLIC_ROOT_HASH_FAILED");
    constexpr char hex[] = "0123456789abcdef";
    std::string result;
    result.reserve(sizeof(digest) * 2);
    for (const auto value : digest) { result += hex[value >> 4]; result += hex[value & 15]; }
    return result;
}
class Handle {
 public:
    explicit Handle(HANDLE value) : value_(value) {}
    ~Handle() { if (value_ != INVALID_HANDLE_VALUE && value_ != nullptr) CloseHandle(value_); }
    HANDLE get() const { return value_; }
    Handle(const Handle&) = delete;
    Handle& operator=(const Handle&) = delete;
 private:
    HANDLE value_;
};
uint32_t Read32(const uint8_t* bytes) {
    return uint32_t(bytes[0]) | (uint32_t(bytes[1]) << 8) | (uint32_t(bytes[2]) << 16) | (uint32_t(bytes[3]) << 24);
}
void Write32(uint8_t* bytes, uint32_t value) {
    for (unsigned index = 0; index < 4; ++index) bytes[index] = static_cast<uint8_t>(value >> (index * 8));
}
bool Transfer(HANDLE pipe, uint8_t* data, size_t size, bool write, bool allow_eof = false) {
    Handle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
    Require(event.get() != nullptr, "PIPE_EVENT_FAILED");
    size_t offset = 0;
    while (offset < size) {
        ResetEvent(event.get());
        OVERLAPPED operation{};
        operation.hEvent = event.get();
        DWORD count = 0;
        const DWORD length = static_cast<DWORD>(std::min(size - offset, size_t{65536}));
        const BOOL started = write ? WriteFile(pipe, data + offset, length, nullptr, &operation)
                                   : ReadFile(pipe, data + offset, length, nullptr, &operation);
        if (!started) {
            const DWORD error = GetLastError();
            if (!write && allow_eof && offset == 0 && (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED)) return false;
            Require(error == ERROR_IO_PENDING, "PIPE_IO_FAILED");
            const DWORD waited = WaitForSingleObject(event.get(), allow_eof && offset == 0 ? INFINITE : 120000);
            if (waited != WAIT_OBJECT_0) {
                CancelIoEx(pipe, &operation);
                GetOverlappedResult(pipe, &operation, &count, TRUE);
                throw std::runtime_error("PIPE_IO_TIMEOUT");
            }
        }
        if (!GetOverlappedResult(pipe, &operation, &count, FALSE)) {
            const DWORD error = GetLastError();
            if (!write && allow_eof && offset == 0 && (error == ERROR_BROKEN_PIPE || error == ERROR_PIPE_NOT_CONNECTED)) return false;
            throw std::runtime_error("PIPE_COMPLETION_FAILED");
        }
        if (!count && !write && allow_eof && offset == 0) return false;
        Require(count > 0 && count <= length, "PIPE_TRANSFER_SIZE");
        offset += count;
    }
    return true;
}
template <typename Response> std::vector<uint8_t> Encode(const Response& response) {
    const size_t size = response.SerializedSize();
    Require(size > 0 && size <= kMaximumFrame, "RESPONSE_SIZE");
    std::vector<uint8_t> output(size);
    Require(response.Serialize(output.data(), output.data() + output.size()) == output.data() + output.size(), "RESPONSE_SERIALIZATION");
    return output;
}
template <typename Request> void Decode(const std::vector<uint8_t>& payload, Request* request) {
    const uint8_t empty = 0;
    const uint8_t* begin = payload.empty() ? &empty : payload.data();
    const uint8_t* cursor = begin;
    Require(request->Deserialize(&cursor, begin + payload.size()) && cursor == begin + payload.size(), "REQUEST_DESERIALIZATION");
}

void DecodeEmptyCommandPayload(const std::vector<uint8_t>& payload) {
    // Cuttlefish sends a serialized Buffer, including its four-byte zero length.
    Buffer request;
    Decode(payload, &request);
    Require(request.available_read() == 0, "UNEXPECTED_COMMAND_PAYLOAD");
}

void WireSelfTest() {
    static_assert(GET_HMAC_SHARING_PARAMETERS == 19 && EARLY_BOOT_ENDED == 26);
    Buffer request;
    const auto canonical = Encode(request);
    Require(canonical == std::vector<uint8_t>({0, 0, 0, 0}), "EMPTY_BUFFER_WIRE_FORMAT");
    size_t accepted = 0, rejected = 0;
    const std::vector<std::vector<uint8_t>> invalid = {
        {}, {0}, {0, 0}, {0, 0, 0}, {0, 0, 0, 0, 0},
        {1, 0, 0, 0}, {1, 0, 0, 0, 42}, {255, 255, 255, 255}
    };
    for (const auto command : {GET_HMAC_SHARING_PARAMETERS, EARLY_BOOT_ENDED}) {
        uint8_t header[8]{};
        Write32(header, command);
        Write32(header + 4, static_cast<uint32_t>(canonical.size()));
        Require(Read32(header) == static_cast<uint32_t>(command) && Read32(header + 4) == 4,
                "EMPTY_COMMAND_FRAME");
        DecodeEmptyCommandPayload(canonical);
        ++accepted;
        for (const auto& payload : invalid) {
            bool failed = false;
            try { DecodeEmptyCommandPayload(payload); }
            catch (const std::runtime_error&) { failed = true; }
            Require(failed, "MALFORMED_EMPTY_COMMAND_ACCEPTED");
            ++rejected;
        }
    }
    std::cout << "{\"state\":\"wire_self_test_passed\",\"accepted\":" << accepted
              << ",\"rejected\":" << rejected << ",\"empty_buffer_payload_bytes\":4}\n";
}
template <typename Request, typename Response>
std::vector<uint8_t> Invoke(AndroidKeymaster& device, const std::vector<uint8_t>& payload,
        void (AndroidKeymaster::*method)(const Request&, Response*)) {
    Request request(kVersion);
    Decode(payload,&request);
    Response response(kVersion);
    (device.*method)(request, &response);
    if constexpr (std::is_same_v<Response,GenerateKeyResponse>) {
        if (response.error == KM_ERROR_OK) {
            const auto& blob = response.key_blob;
            const bool protected_key = blob.size() == 36 && Read32(blob.begin()) == 1;
            if (protected_key) ++cng_generations; else ++software_generations;
            std::cout << "{\"event\":\"generated_key\",\"storage\":\"" << (protected_key?"cng_reference":"software_blob") << "\"}\n" << std::flush;
        } else {
            std::cout << "{\"event\":\"generation_failed\",\"code\":" << response.error << ",\"tags\":[";
            bool first = true;
            for (const auto& parameter : request.key_description) { if (!first) std::cout << ','; first=false; std::cout << static_cast<uint32_t>(parameter.tag); }
            std::cout << "]}\n" << std::flush;
        }
    }
    if constexpr (std::is_same_v<Response,BeginOperationResponse>) {
        if (response.error == KM_ERROR_OK && request.key_blob.key_material_size == 36
                && Read32(request.key_blob.key_material) == 1) protected_operations.insert(response.op_handle);
        if (response.error != KM_ERROR_OK) {
            std::cout << "{\"event\":\"begin_failed\",\"code\":" << response.error << ",\"tags\":[";
            bool first = true;
            for (const auto& parameter : request.additional_params) {
                if (!first) std::cout << ',';
                first = false;
                std::cout << static_cast<uint32_t>(parameter.tag);
            }
            std::cout << "]}\n" << std::flush;
        }
    }
    if constexpr (std::is_same_v<Response,FinishOperationResponse>) {
        if (protected_operations.erase(request.op_handle) && response.error == KM_ERROR_OK) {
            ++protected_signatures;
            std::cout << "{\"event\":\"protected_signature\",\"bytes\":" << response.output.available_read() << "}\n" << std::flush;
        }
    }
    if constexpr (std::is_same_v<Request,AbortOperationRequest>) protected_operations.erase(request.op_handle);
    return Encode(response);
}
template <typename Request, typename Response>
std::vector<uint8_t> Returned(AndroidKeymaster& device, const std::vector<uint8_t>& payload,
        Response (AndroidKeymaster::*method)(const Request&)) {
    Request request(kVersion);
    Decode(payload,&request);
    return Encode((device.*method)(request));
}
std::vector<uint8_t> Dispatch(AndroidKeymaster& device, uint32_t command, const std::vector<uint8_t>& payload) {
    switch (command) {
#define POINTER_CASE(command_name, request, response, method) case command_name: return Invoke<request,response>(device,payload,&AndroidKeymaster::method)
        POINTER_CASE(GENERATE_KEY, GenerateKeyRequest, GenerateKeyResponse, GenerateKey);
        POINTER_CASE(BEGIN_OPERATION, BeginOperationRequest, BeginOperationResponse, BeginOperation);
        POINTER_CASE(UPDATE_OPERATION, UpdateOperationRequest, UpdateOperationResponse, UpdateOperation);
        POINTER_CASE(FINISH_OPERATION, FinishOperationRequest, FinishOperationResponse, FinishOperation);
        POINTER_CASE(ABORT_OPERATION, AbortOperationRequest, AbortOperationResponse, AbortOperation);
        POINTER_CASE(IMPORT_KEY, ImportKeyRequest, ImportKeyResponse, ImportKey);
        POINTER_CASE(EXPORT_KEY, ExportKeyRequest, ExportKeyResponse, ExportKey);
        POINTER_CASE(ADD_RNG_ENTROPY, AddEntropyRequest, AddEntropyResponse, AddRngEntropy);
        POINTER_CASE(GET_KEY_CHARACTERISTICS, GetKeyCharacteristicsRequest, GetKeyCharacteristicsResponse, GetKeyCharacteristics);
        POINTER_CASE(UPGRADE_KEY, UpgradeKeyRequest, UpgradeKeyResponse, UpgradeKey);
        POINTER_CASE(CONFIGURE, ConfigureRequest, ConfigureResponse, Configure);
        POINTER_CASE(DELETE_KEY, DeleteKeyRequest, DeleteKeyResponse, DeleteKey);
        POINTER_CASE(DELETE_ALL_KEYS, DeleteAllKeysRequest, DeleteAllKeysResponse, DeleteAllKeys);
        POINTER_CASE(IMPORT_WRAPPED_KEY, ImportWrappedKeyRequest, ImportWrappedKeyResponse, ImportWrappedKey);
#undef POINTER_CASE
        case GET_VERSION_2: return Returned(device,payload,&AndroidKeymaster::GetVersion2);
        case COMPUTE_SHARED_HMAC: return Returned(device,payload,&AndroidKeymaster::ComputeSharedHmac);
        case DEVICE_LOCKED: return Returned(device,payload,&AndroidKeymaster::DeviceLocked);
        case EARLY_BOOT_ENDED:
            DecodeEmptyCommandPayload(payload);
            return Encode(device.EarlyBootEnded());
        case GET_HMAC_SHARING_PARAMETERS:
            DecodeEmptyCommandPayload(payload);
            return Encode(device.GetHmacSharingParameters());
        case GENERATE_TIMESTAMP_TOKEN: {
            GenerateTimestampTokenRequest request(kVersion);
            Decode(payload,&request);
            GenerateTimestampTokenResponse response(kVersion);
            device.GenerateTimestampToken(request,&response);
            return Encode(response);
        }
        default: {
            EmptyKeymasterResponse response(kVersion);
            response.error = KM_ERROR_UNIMPLEMENTED;
            return Encode(response);
        }
    }
}
}  // namespace

int main(int argc, char** argv) {
    size_t frames = 0, bytes_in = 0, bytes_out = 0;
    bool connected = false;
    try {
        if (argc == 2 && std::string(argv[1]) == "--wire-self-test") {
            WireSelfTest();
            return 0;
        }
        const bool lab_attestation = argc == 3 && std::string(argv[2]) == "--lab-software-attestation";
        Require(argc == 2 || lab_attestation, "PIPE_ARGUMENTS_INVALID");
        std::string name(argv[1]);
        Require(name.size() >= 8 && name.size() <= 80 && name.rfind("adl-keymint-",0) == 0
                && name.find_first_not_of("abcdefghijklmnopqrstuvwxyz0123456789-") == std::string::npos, "PIPE_NAME_FORMAT");
        const std::wstring pipe_name = L"\\\\.\\pipe\\" + std::wstring(name.begin(),name.end());
        HANDLE raw = INVALID_HANDLE_VALUE;
        const auto start = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start < std::chrono::seconds(30)) {
            raw = CreateFileW(pipe_name.c_str(),GENERIC_READ|GENERIC_WRITE,0,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
            if (raw != INVALID_HANDLE_VALUE) break;
            const DWORD error = GetLastError();
            Require(error == ERROR_PIPE_BUSY || error == ERROR_FILE_NOT_FOUND, "PIPE_CONNECT_FAILED");
            WaitNamedPipeW(pipe_name.c_str(),100);
            std::this_thread::sleep_for(std::chrono::milliseconds(25));
        }
        Require(raw != INVALID_HANDLE_VALUE, "PIPE_CONNECT_TIMEOUT");
        Handle pipe(raw);
        connected = true;
        std::vector<uint8_t> public_lab_root;
        auto context = androidlab::CreateHybridKeymintContext(lab_attestation, &public_lab_root);
        const std::string root_hash_json = lab_attestation ? "\"" + Sha256Hex(public_lab_root) + "\"" : "null";
        Require(context->SetSystemVersion(140000,202309) == KM_ERROR_OK, "SOFTWARE_CONFIGURATION_FAILED");
        Require(context->SetVendorPatchlevel(20230905) == KM_ERROR_OK, "SOFTWARE_VENDOR_CONFIGURATION_FAILED");
        AndroidKeymaster device(context.release(),16,kVersion);
        std::cout << "{\"state\":\"connected\",\"message_version\":4,\"security_level\":\"SOFTWARE\",\"lab_software_attestation\":"
                  << (lab_attestation ? "true" : "false") << ",\"attestation_root_trust\":\""
                  << (lab_attestation ? "lab_owned_untrusted" : "unavailable") << "\",\"lab_root_sha256\":"
                  << root_hash_json << "}\n" << std::flush;
        for (;;) {
            uint8_t header[8]{};
            if (!Transfer(pipe.get(),header,sizeof(header),false,true)) break;
            const uint32_t command = Read32(header), size = Read32(header+4);
            Require((command & kResponse) == 0 && size <= kMaximumFrame, "REQUEST_FRAME_INVALID");
            std::vector<uint8_t> payload(size);
            if (size) Transfer(pipe.get(),payload.data(),payload.size(),false);
            std::cout << "{\"event\":\"request\",\"command\":" << command
                      << ",\"payload_bytes\":" << size << "}\n" << std::flush;
            auto response = Dispatch(device,command,payload);
            Require(device.message_version() == kVersion, "MESSAGE_VERSION_CHANGED");
            Write32(header,command|kResponse);
            Write32(header+4,static_cast<uint32_t>(response.size()));
            Transfer(pipe.get(),header,sizeof(header),true);
            Transfer(pipe.get(),response.data(),response.size(),true);
            ++frames; bytes_in += size; bytes_out += response.size();
            if (frames == 1) {
                std::cout << "{\"state\":\"serving\",\"completed_frames\":1,\"security_level\":\"SOFTWARE\"}\n" << std::flush;
            }
        }
        std::cout << "{\"state\":\"closed\",\"frames\":" << frames << ",\"payload_bytes_in\":" << bytes_in
                  << ",\"payload_bytes_out\":" << bytes_out << ",\"cng_generations\":" << cng_generations
                  << ",\"software_generations\":" << software_generations << ",\"protected_signatures\":" << protected_signatures
                  << ",\"android_tee_verified\":false}\n";
        return 0;
    } catch (const std::exception& error) {
        std::cerr << error.what() << '\n';
        std::cout << "{\"state\":\"failed\",\"connected\":" << (connected?"true":"false")
                  << ",\"frames\":" << frames << ",\"android_tee_verified\":false}\n";
        return 1;
    }
}
