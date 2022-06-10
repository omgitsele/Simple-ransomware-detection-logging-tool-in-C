#define _GNU_SOURCE

#include <time.h>
#include <stdio.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <openssl/md5.h>

// Print the MD5 sum as hex-digits.
void print_md5_sum(unsigned char* md) {
    int i;
    for(i=0; i <MD5_DIGEST_LENGTH; i++) {
            printf("%02x",md[i]);
    }
	printf("\n");
}

FILE *
fopen(const char *path, const char *mode) 
{

	FILE *original_fopen_ret;
	FILE *(*original_fopen)(const char*, const char*);
	int accessType = -1;
	// F_OK tests for the existence of the file
	// if the file doesn't exist we set the access type to 0
	// otherwise we know that we read a file so we set access type to 1
	if(access(path, F_OK) == -1)
	{
		accessType = 0;
	}
	else
	{
		accessType = 1;
	}
	/* call the original fopen function */
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	original_fopen_ret = (*original_fopen)(path, mode);


	
	//Getting file descriptor
	int fileDescriptor = fileno(original_fopen_ret);
	char fileName[10000];
	char buf[10000];
	//Retrieve filename from file descriptor 
	
	sprintf(buf, "/proc/self/fd/%d", fileDescriptor);
	readlink(buf, fileName, sizeof(fileName));

	int actionDeniedFlag = 0;
	if(access(path, R_OK) == -1)
		actionDeniedFlag = 1;

	//Get timestamp
	struct tm *tm;
	time_t t;
	char str_time[9];
	char str_date[11];

	t = time(NULL);
	tm = localtime(&t);

	strftime(str_time, sizeof(str_time), "%H:%M:%S", tm);
	strftime(str_date, sizeof(str_date), "%d-%m-%Y", tm);



	unsigned char result[MD5_DIGEST_LENGTH];
	unsigned long file_size;
    char* file_buffer;

	fseek(original_fopen_ret, 0L, SEEK_END);
  	file_size = ftell(original_fopen_ret);
  	fseek(original_fopen_ret, 0L, SEEK_SET);
	file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, fileDescriptor, 0);
	MD5((unsigned char*) file_buffer, file_size, result);
	munmap(file_buffer, file_size); 



	int uid = getuid();


	char *logFilePath = "./file_logging.log";
	FILE *logFile;

	if(access(logFilePath, F_OK) == -1)
	{
		printf("Creating the logging file!\n");
		logFile = (*original_fopen)(logFilePath,"w");
		fclose(logFile);
	}

	logFile = (*original_fopen)(logFilePath,"r+");
	fseek(logFile, 0, SEEK_END);

	char temp[MD5_DIGEST_LENGTH];
	sprintf(temp, "%x", *(uint32_t *)result);

	//write to the file
	fprintf(logFile, "%d,%s,%s,%s,%d,%d,%s\n", uid, basename(fileName), str_date, str_time, accessType, actionDeniedFlag, temp);

	fclose(logFile);

	


	return original_fopen_ret;
}


size_t 
fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) 
{

	size_t original_fwrite_ret;
	size_t (*original_fwrite)(const void*, size_t, size_t, FILE*);

	/* call the original fwrite function */
	original_fwrite = dlsym(RTLD_NEXT, "fwrite");
	original_fwrite_ret = (*original_fwrite)(ptr, size, nmemb, stream);

	FILE *(*original_fopen)(const char*, const char*);
	original_fopen = dlsym(RTLD_NEXT, "fopen");
	
	char fileName[128];
	char buf[128];

	//Getting file descriptor
	int fileDescriptor = fileno(stream);
	//Retrieve filename from file descriptor 
	sprintf(buf, "/proc/self/fd/%d", fileDescriptor);
	memset(fileName, 0, sizeof(fileName));
	readlink(buf, fileName, sizeof(fileName));

	int actionDeniedFlag = 0;
	if(access(fileName, W_OK) == -1)
		actionDeniedFlag = 1;

	//Get timestamp
	struct tm *tm;
	time_t t;
	char str_time[9];
	char str_date[11];

	t = time(NULL);
	tm = localtime(&t);

	strftime(str_time, sizeof(str_time), "%H:%M:%S", tm);
	strftime(str_date, sizeof(str_date), "%d-%m-%Y", tm);


	unsigned char result[MD5_DIGEST_LENGTH];
	unsigned long file_size;
    char* file_buffer;

	fseek(stream, 0L, SEEK_END);
  	file_size = ftell(stream);
  	fseek(stream, 0L, SEEK_SET);

	file_buffer = mmap(0, file_size, PROT_READ, MAP_SHARED, fileDescriptor, 0);
	MD5((unsigned char*) file_buffer, file_size, result);
	munmap(file_buffer, file_size); 



	int uid = getuid();


	char *logFilePath = "./file_logging.log";
	FILE *logFile;

	if(access(logFilePath, F_OK) == -1)
	{
		logFile = (*original_fopen)(logFilePath,"w");
		fclose(logFile);
	}
	logFile = (*original_fopen)(logFilePath,"r+");
	fseek(logFile, 0, SEEK_END);

	char temp[MD5_DIGEST_LENGTH];
	sprintf(temp, "%x", *(uint32_t *)result);
	
	//write to the file
	fprintf(logFile, "%d,%s,%s,%s,%d,%d,%s\n", uid, basename(fileName), str_date, str_time, 2, actionDeniedFlag, temp);

	fclose(logFile);

	return original_fwrite_ret;
}


