INCS= -I/usr/local/include/luajit-2.0
LIBS= -lluajit-5.1 -lcrypto

CC= gcc
WARN= -Wall 
CFLAGS= $(INCS) $(LIBS) $(WARN) -O2 $G 

all:
	$(CC) -shared -o codec.so $(CFLAGS) codec.c

clean:
	rm -f codec.so
