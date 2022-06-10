all: logger acmonitor test_aclog;
	if [ ! -d "~/test" ]; then sudo mkdir test; sudo chmod a+rwx test; fi

logger: logger.c
	gcc -Wall -fPIC -shared -o logger.so logger.c -lcrypto -ldl 

acmonitor: acmonitor.c 
	gcc acmonitor.c -o acmonitor -D_FILE_OFFSET_BITS=64

test_aclog: test_aclog.c 
	gcc test_aclog.c -o test_aclog 

clean:
	rm -rf file_* 
	rm -rf logger.so
	rm -rf test_aclog
	rm -rf acmonitor
	sudo rm -rf test

