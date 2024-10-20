#
# Copyright (C) 2011-2021 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1
NUM_PAD_PAGES ?= 1
PADDING_TOOL ?= ./generate_large_array.py
HIBE_ENCRYPTOR ?= hibe_encryptor
HIBE_DEPTH ?= 5

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef -Wshadow \
                    -Wcast-align -Wcast-qual -Wconversion -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11

######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

App_Cpp_Files := App/App.cpp App/UntrustedEnclaveMessageExchange.cpp
App_Include_Paths := -IApp -I$(SGX_SDK)/include -IInclude

App_C_Flags := -fPIC -Wno-attributes $(App_Include_Paths)

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -L$(SGX_LIBRARY_PATH) -l$(Urts_Library_Name) -lpthread

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)

App_Name := app

######## Enclave Settings ########

Enclave_Version_Script := Enclave/Enclave_debug.lds
ifeq ($(SGX_MODE), HW)
ifneq ($(SGX_DEBUG), 1)
ifneq ($(SGX_PRERELEASE), 1)
	# Choose to use 'Enclave.lds' for HW release mode
	Enclave_Version_Script = Enclave/Enclave.lds 
endif
endif
endif

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := Enclave/Enclave.cpp Enclave/bellerophon/bellerophon.cpp Enclave/bellerophon/EnclaveMessageExchange.cpp Enclave/bellerophon/Utility_E1.cpp
Enclave_Include_Paths := -IEnclave -I$(SGX_SDK)/include -I$(SGX_SDK)/include/libcxx -I$(SGX_SDK)/include/tlibc -IInclude

Enclave_C_Flags := -nostdinc -fvisibility=hidden -fpie -fstack-protector $(Enclave_Include_Paths) -DPB_ENABLE_SGX
Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(Enclave_Security_Link_Flags) \
		      -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_mbedcrypto -lsgx_pthread -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic -Wl,--print-gc-sections  \
	-Wl,--defsym,__ImageBase=0 \
	-Wl,--version-script=$(Enclave_Version_Script)

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Decrypt_Enclave_Name := decrypt_enclave.signed.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := Enclave/Enclave.config.xml
Enclave_Test_Key := Enclave/Enclave_private_test.pem

# Bellerophon Settings
Pcl_Encryption_Tool := $(SGX_SDK)/bin/x64/sgx_encrypt
PCL_KEY := key.bin
Encryption_Tool_Flags := -d -bellerophon
Encrypted_Enclave_Name  := $(Enclave_Name).enc

# PCL source files
PCL_ASM_FILES       := Enclave/bellerophon/crypto/pcl_vpaes-x86_64.s \
                       Enclave/bellerophon/crypto/pcl_ghash-x86_64.s

PCL_CPP_FILES       := Enclave/bellerophon/crypto/pcl_crypto.cpp \
		       Enclave/bellerophon/crypto/pcl_mem.cpp

PCL_C_FILES        := Enclave/bellerophon/crypto/pcl_sha256.c    \
                      Enclave/bellerophon/crypto/pcl_gcm128.c

# object files
PCL_CPP_OBJECTS                 := $(PCL_CPP_FILES:%.cpp=%.o)
PCL_C_OBJECTS                   := $(PCL_C_FILES:%.c=%.o)
PCL_ASM_OBJECTS                 := $(PCL_ASM_FILES:%.s=%.o)
PCL_INCLUDE_PATH		:= -I/usr/include \
				   -I/usr/include/x86_64-linux-gnu \
				   -I./Enclave/bellerophon \
				   -I./Enclave/bellerophon/crypto


Enclave_Cpp_Objects := $(Enclave_Cpp_Objects) $(PCL_CPP_OBJECTS) $(PCL_C_OBJECTS) $(PCL_ASM_OBJECTS)

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


.PHONY: all run target
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target: $(App_Name) $(Enclave_Name)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."
else
target: $(App_Name) $(Signed_Enclave_Name)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif
endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* $(Enclave_Cpp_Objects) Enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)

######## App Objects ########

App/Enclave_u.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

App/Enclave_u.c: App/Enclave_u.h

#App/DhSessionEnclave_u.h: $(SGX_EDGER8R) Enclave/bellerophon/DhSessionEnclave.edl
#	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/bellerophon/DhSessionEnclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include --search-path ../Include
#	@echo "GEN  =>  $@"

#App/DhSessionEnclave_u.c: App/DhSessionEnclave_u.h

#App/DhSessionEnclave_u.o: App/DhSessionEnclave_u.c
#	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
#	@echo "CC   <=  $<"

App/DecryptEnclave_u.h: $(SGX_EDGER8R) Enclave/bellerophon/decryption_enclave/DecryptEnclave.edl
	@cd App && $(SGX_EDGER8R) --untrusted ../Enclave/bellerophon/decryption_enclave/DecryptEnclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include --search-path ../Include
	@echo "GEN  =>  $@"

App/DecryptEnclave_u.c: App/DecryptEnclave_u.h

App/DecryptEnclave_u.o: App/DecryptEnclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/Enclave_u.o: App/Enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

App/%.o: App/%.cpp App/Enclave_u.h App/DecryptEnclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) -DHIBE_DEPTH=$(HIBE_DEPTH) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): App/Enclave_u.o App/DecryptEnclave_u.o $(App_Cpp_Objects)
	@$(CXX) $^ -o $@ $(App_Link_Flags)
	@echo "LINK =>  $@"

######## Enclave Objects ########

Enclave/Enclave_t.h: $(SGX_EDGER8R) Enclave/Enclave.edl
	@cd Enclave && $(SGX_EDGER8R) --trusted ../Enclave/Enclave.edl --search-path ../Enclave --search-path $(SGX_SDK)/include
	@echo "GEN  =>  $@"

Enclave/Enclave_t.c: Enclave/Enclave_t.h

Enclave/Enclave_t.o: Enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/Enclave.o: Enclave/Enclave.cpp
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	objcopy $@ --rename-section .text=.encrypt.text
	objcopy $@ --rename-section .data=.encrypt.data
	objcopy $@ --rename-section .rodata=.encrypt.rodata

	@echo "CXX  <=  $<"

Enclave/bellerophon/bellerophon.o: Enclave/bellerophon/bellerophon.cpp Enclave/Enclave_t.h
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	
	@echo "CXX <= $<"

Enclave/bellerophon/EnclaveMessageExchange.o: Enclave/bellerophon/EnclaveMessageExchange.cpp Enclave/Enclave_t.h
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX <= $<"

Enclave/bellerophon/Utility_E1.o: Enclave/bellerophon/Utility_E1.cpp
	$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	
	@echo "CXX <= $<"

#Enclave/bellerophon/DhSessionEnclave_t.o: Enclave/bellerophon/DhSessionEnclave_t.c
#	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
#	@echo "CC   <=  $<"

#Enclave/bellerophon/DhSessionEnclave_t.c: Enclave/bellerophon/DhSessionEnclave_t.h

#Enclave/bellerophon/DhSessionEnclave_t.h: $(SGX_EDGER8R) Enclave/bellerophon/DhSessionEnclave.edl
#	@cd Enclave/bellerophon && $(SGX_EDGER8R) --trusted ../bellerophon/DhSessionEnclave.edl --search-path ../../Enclave --search-path $(SGX_SDK)/include --search-path ../../Include
#	@echo "GEN => $<"

#Enclave/bellerophon/DhSessionEnclave_t.c: Enclave/bellerophon/DhSessionEnclave_t.h

#Enclave/bellerophon/DhSessionEnclave_t.o: Enclave/bellerophon/DhSessionEnclave_t.c
#	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"


Enclave/bellerophon/crypto/%.o: Enclave/bellerophon/crypto/%.s
	@$(CC) $(SGX_COMMON_CFLAGS) $(PCL_INCLUDE_PATH) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/bellerophon/crypto/%.o: Enclave/bellerophon/crypto/%.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(PCL_INCLUDE_PATH) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/bellerophon/crypto/%.o: Enclave/bellerophon/crypto/%.cpp
	@$(CC) $(SGX_COMMON_CXXFLAGS) $(PCL_INCLUDE_PATH) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Enclave/%.o: Enclave/%.cpp #Enclave/DhSessionEnclave_t.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Enclave/%.o: Enclave/%.cc
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Pad_Enclave: $(PADDING_TOOL)
	@echo "Padding Enclave with" $(NUM_PAD_PAGES)
	@$(PADDING_TOOL) $(NUM_PAD_PAGES) > ./Enclave/EnclaveData.cpp

Insert_Ciphertext: $(HIBE_ENCRYPTOR) Enclave/bellerophon/bellerophon.cpp
	$(HIBE_ENCRYPTOR) --hibe-depth $(HIBE_DEPTH) > ciphertext
	sed -e '60{r ciphertext' -e 'd}' ./Enclave/bellerophon/bellerophon.cpp -i

$(Enclave_Cpp_Objects): Pad_Enclave Insert_Ciphertext Enclave/Enclave_t.h #Enclave/bellerophon/DhSessionEnclave_t.h

$(Enclave_Name): Enclave/Enclave_t.o  $(Enclave_Cpp_Objects) 
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(PCL_KEY):
	@python3 -c "print ('\x0a'*16, end='')" > $@
	@echo "GEN => $@"

$(Encrypted_Enclave_Name): $(Enclave_Name) $(Pcl_Encryption_Tool) $(PCL_KEY)
	$(Pcl_Encryption_Tool) -i $< -o $@ -k $(PCL_KEY) $(Encryption_Tool_Flags)
	@echo "Encrypted => $@"

$(Decrypt_Enclave_Name): Enclave/bellerophon/decryption_enclave/Makefile
	$(MAKE) -C Enclave/bellerophon/decryption_enclave
	cp Enclave/bellerophon/decryption_enclave/$@ .
	@echo "LINK => $@"

$(Signed_Enclave_Name): $(Encrypted_Enclave_Name) $(Decrypt_Enclave_Name)
ifeq ($(wildcard $(Enclave_Test_Key)),)
	@echo "There is no enclave test key<Enclave_private_test.pem>."
	@echo "The project will generate a key<Enclave_private_test.pem> for test."
	@openssl genrsa -out $(Enclave_Test_Key) -3 3072
endif
	
	@$(SGX_ENCLAVE_SIGNER) sign -key $(Enclave_Test_Key) -enclave $(Encrypted_Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"

.PHONY: clean clean_results

clean_results:
	rm -rf csv* out* result* ciphertext

clean:
	@rm -f .config_* $(PCL_KEY) $(App_Name) $(Enclave_Name) $(Encrypted_Enclave_Name) $(Decrypt_Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) App/Enclave_u.* App/*.o App/*_u.c App/*_u.h $(Enclave_Cpp_Objects) Enclave/Enclave_t.* Enclave/bellerophon/*_t.* Enclave/bellerophon/*.o $(Enclave_Test_Key) *.enc
	make clean -C Enclave/bellerophon/decryption_enclave
