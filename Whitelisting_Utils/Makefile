#define the C compiler to use
CC = gcc -g

# define the C source files
SRCS = whitelistUpload.c /home/pi/WAM/WAM.c

# define any library to link into executable:
# if I want to link libraries (libx.so or libx.a) I use the -llibname option
FLAGS =\
 -lssl #-lcrypto

LDFLAGS+=\
-I/home/pi/iota.c/build/include/ \
-I/home/pi/iota.c/build/include/cjson/ \
-I/home/pi/iota.c/build/include/client/ \
-I/home/pi/iota.c/build/include/crypto/ \
-I/home/pi/iota.c/build/include/core/ \

LDFLAGS += \
-L/home/pi/iota.c/build/lib/ \
-liota_crypto -lcrypto -liota_core -liota_client -lcjson -lcurl -lsodium

# define the executable file
MAIN = uploadWhitelist

.PHONY: all
all:
	$(CC) $(CFLAGS) $(SRCS) -o $(MAIN) $(LDFLAGS) $(FLAGS)

.PHONY: clean
clean:
	$(RM) $(MAIN)
