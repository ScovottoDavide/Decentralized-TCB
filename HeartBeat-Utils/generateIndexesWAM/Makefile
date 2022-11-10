CC = gcc

SOURCE_1 = generateIndexes.c
SOURCE_2 = /home/privateadm/WAM/WAM.c 
SOURCE_3 = /home/privateadm/WAM/wam-wrapper.c


LDFLAGS+=\
-I/home/privateadm/iota.c/build/include/ \
-I/home/privateadm/iota.c/build/include/cjson/ \
-I/home/privateadm/iota.c/build/include/client/ \
-I/home/privateadm/iota.c/build/include/crypto/ \
-I/home/privateadm/iota.c/build/include/core/ \

LDFLAGS += \
-L/home/privateadm/iota.c/build/lib/ \
-liota_crypto -lcrypto -liota_core -liota_client -lcjson -lcurl -lsodium 

APP = WAM_generateIndexes

.PHONY: all
all:
	$(CC) $(SOURCE_1) $(SOURCE_2) $(SOURCE_3) -o $(APP) $(LDFLAGS)

.PHONY: clean
clean:
	rm -f $(APP) *.o
