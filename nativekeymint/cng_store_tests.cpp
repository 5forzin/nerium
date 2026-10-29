#include "cng_key_store.h"
#include <windows.h>
#include <bcrypt.h>
#include <array>
#include <atomic>
#include <iostream>
#include <stdexcept>
#include <thread>
#include <vector>
static bool Verify(const std::vector<uint8_t>& blob,const std::array<uint8_t,32>& digest,const std::vector<uint8_t>& sig){
 BCRYPT_ALG_HANDLE alg=0; BCRYPT_KEY_HANDLE key=0;
 if(BCryptOpenAlgorithmProvider(&alg,BCRYPT_RSA_ALGORITHM,nullptr,0)<0)throw std::runtime_error("VERIFY_PROVIDER");
 auto imported=BCryptImportKeyPair(alg,nullptr,BCRYPT_RSAPUBLIC_BLOB,&key,const_cast<PUCHAR>(blob.data()),static_cast<ULONG>(blob.size()),0);
 if(imported<0){BCryptCloseAlgorithmProvider(alg,0);throw std::runtime_error("VERIFY_IMPORT");}
 BCRYPT_PSS_PADDING_INFO padding{BCRYPT_SHA256_ALGORITHM,32};
 auto status=BCryptVerifySignature(key,&padding,const_cast<PUCHAR>(digest.data()),32,const_cast<PUCHAR>(sig.data()),static_cast<ULONG>(sig.size()),BCRYPT_PAD_PSS);
 BCryptDestroyKey(key);BCryptCloseAlgorithmProvider(alg,0);return status>=0;
}
static void Require(bool value,const char* code){if(!value)throw std::runtime_error(code);}
int main(){try{
 androidlab::CngKeyStore store;auto id=store.GenerateRsaPss2048();Require(store.Contains(id),"CONTAINS");auto pub=store.PublicBlob(id);
 std::array<uint8_t,32> digest{};for(size_t i=0;i<digest.size();i++)digest[i]=static_cast<uint8_t>(i);
 auto sig=store.SignSha256(id,digest);Require(Verify(pub,digest,sig),"VALID_SIGNATURE");std::cout<<"PASS generated key and independent BCrypt PSS verification\n";
 digest[0]^=1;Require(!Verify(pub,digest,sig),"ALTERED_DIGEST");digest[0]^=1;std::cout<<"PASS altered digest rejected\n";
 auto second=store.GenerateRsaPss2048();Require(!Verify(store.PublicBlob(second),digest,sig),"WRONG_KEY");Require(store.Delete(second),"DELETE_SECOND");std::cout<<"PASS wrong public key rejected\n";
 std::atomic<int> succeeded{0},missing{0};std::thread signer([&]{for(int i=0;i<20;i++){try{store.SignSha256(id,digest);succeeded++;}catch(const std::runtime_error& error){if(std::string(error.what())!="CNG_KEY_NOT_FOUND")throw;missing++;}}});
 Require(store.Delete(id),"DELETE");signer.join();Require(!store.Contains(id),"STILL_CONTAINS");Require(!store.Delete(id),"SECOND_DELETE");Require(succeeded+missing==20,"RACE_COUNT");std::cout<<"PASS concurrent sign/delete and repeated delete\n";
 bool refused=false;try{store.SignSha256(id,digest);}catch(const std::runtime_error& error){refused=std::string(error.what())=="CNG_KEY_NOT_FOUND";}Require(refused,"SIGN_AFTER_DELETE");std::cout<<"PASS sign after delete rejected\n";
 refused=false;try{store.PublicBlob(id);}catch(const std::runtime_error& error){refused=std::string(error.what())=="CNG_KEY_NOT_FOUND";}Require(refused,"PUBLIC_AFTER_DELETE");std::cout<<"PASS public lookup after delete rejected\n";
 std::cout<<"6 store controls passed\n";return 0;
}catch(const std::exception& error){std::cerr<<error.what()<<"\n";return 1;}}