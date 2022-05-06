#define the C compiler to use
CC = gcc

# define any library to link into executable:
#  if I want to link libraries (libx.so or libx.a) I use the -llibname option
LIBS = -ltss2-esys -ltss2-tctildr -ltss2-mu -lssl -lcrypto

# define the C source files
SRCS = PoC-Verifier.c tpm2_checkquote.c

# define rule for gcc
TARGET = PoC-Verifier.c

# define the executable file
MAIN = Verifier

all: $(TARGET)
	 $(CC) -o $(MAIN) $(SRCS) $(LIBS)

clean:
	$(RM) $(MAIN)
