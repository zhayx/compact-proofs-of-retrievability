
#-finstrument-functions -lSaturn -pg 

all: cpor-misc.o cpor.h cpor-core.o cpor-app.o
	gcc -g -Wall -O3 -lcrypto -o cpor cpor-app.c cpor-core.o cpor-misc.o 

cpor-core.o: cpor-core.c cpor.h
	gcc -g -Wall -O3 -c cpor-core.c

cpor-misc.o: cpor-misc.c cpor.h
	gcc -g -Wall -O3 -c cpor-misc.c
	

cporlib: cpor-core.o cpor-misc.o
	ar -rv cporlib.a cpor-core.o cpor-misc.o

clean:
	rm -rf *.o *.tag cpor.dSYM cpor
