http_inject: http_inject.o
	gcc -o http_inject http_inject.o -lpcap

http_inject.o: http_inject.c
	gcc -o http_inject.o -c http_inject.c

clean:
	rm -f ./*.o 
