
#-finstrument-functions -lSaturn -pg 
# -O3 

S3LIB = ../libs3-1.4/build/lib/libs3.a

all: cpor-misc.o cpor.h cpor-core.o cpor-app.c cpor-file.o cpor-keys.o cpor-app.c
	gcc -g -Wall -lcrypto -o cpor cpor-app.c cpor-core.o cpor-misc.o cpor-file.o cpor-keys.o

cpor-s3: cpor-misc.o cpor.h cpor-core.o cpor-app.c cpor-file.o cpor-keys.o cpor-s3.o cpor-app.c 
	gcc -DUSE_S3 -g -Wall -O3 -lpthread -lcurl -lxml2 -lz -lcrypto -o cpor-s3 cpor-app.c cpor-misc.o cpor-core.o cpor-file.o cpor-keys.o cpor-s3.o $(S3LIB)

cpor-core.o: cpor-core.c cpor.h
	gcc -g -Wall -c cpor-core.c

cpor-misc.o: cpor-misc.c cpor.h
	gcc -g -Wall -c cpor-misc.c

cpor-file.o: cpor-file.c cpor.h
	gcc -g -Wall -c cpor-file.c

cpor-keys.o: cpor-keys.c cpor.h
	gcc -g -Wall -c cpor-keys.c

cpor-s3.o: cpor-s3.c cpor.h ../libs3-1.4/build/include/libs3.h
	gcc -DUSE_S3 -g -Wall -O3 -I../libs3-1.4/build/include/ -c cpor-s3.c

cporlib: cpor-core.o cpor-misc.o
	ar -rv cporlib.a cpor-core.o cpor-misc.o

clean:
	rm -rf *.o *.tag *.t cpor.dSYM cpor cpor-s3
