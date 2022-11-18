CC = gcc

SOURCE_1 = generateIndexes.c
SOURCE_2 = ${WAM_DIR}/WAM/WAM.c 
SOURCE_3 = ${WAM_DIR}/WAM/wam-wrapper.c


LDFLAGS+=\
-I${WAM_DIR}/iota.c/build/include/ \
-I${WAM_DIR}/iota.c/build/include/cjson/ \
-I${WAM_DIR}/iota.c/build/include/client/ \
-I${WAM_DIR}/iota.c/build/include/crypto/ \
-I${WAM_DIR}/iota.c/build/include/core/ \

LDFLAGS += \
-L${WAM_DIR}/iota.c/build/lib/ \
-liota_crypto -lcrypto -liota_core -liota_client -lcjson -lcurl -lsodium 

APP = WAM_generateIndexes

.PHONY: all
all:
	$(CC) $(SOURCE_1) $(SOURCE_2) $(SOURCE_3) -o $(APP) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(APP) *.o
