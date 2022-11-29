CC = gcc
CFLAGS = -g

ifndef $(WAM_DIR)
WAM_DIR = .
endif

SOURCE_1 = sampleHeartBeat.c
SOURCE_2 = ${WAM_DIR}/WAM/WAM.c 
SOURCE_3 = ${WAM_DIR}/WAM/wam-wrapper.c
SOURCE_3 = ../../Consensous/consensous.c


LDFLAGS+=\
-I${WAM_DIR} \
-I${WAM_DIR}/iota.c/build/include/ \
-I${WAM_DIR}/iota.c/build/include/cjson/ \
-I${WAM_DIR}/iota.c/build/include/client/ \
-I${WAM_DIR}/iota.c/build/include/crypto/ \
-I${WAM_DIR}/iota.c/build/include/core/ \

LDFLAGS += \
-L${WAM_DIR}/iota.c/build/lib/ \
-liota_crypto -lcrypto -liota_core -liota_client -lcjson -lcurl -lsodium -lpthread

APP = WAM_heartbeat

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SOURCE_1) $(SOURCE_2) $(SOURCE_3) -o $(APP) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(APP) *.o
