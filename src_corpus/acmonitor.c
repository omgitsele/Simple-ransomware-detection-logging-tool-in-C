#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <stdbool.h>

struct entry {

	int uid; /* user id (positive integer) */
	int access_type; /* access type values [0-2] */
	int action_denied; /* is action denied values [0-1] */

	time_t date; /* file access date */
	time_t time; /* file access time */

	char *file; /* filename (string) */
	char *fingerprint; /* file fingerprint */

	int inv_accesses;
	
	/* add here other fields if necessary */
	/* ... */
	/* ... */

};

char** str_split(char* a_str, const char a_delim)
{
    char** result    = 0;
    size_t count     = 0;
    char* tmp        = a_str;
    char* last_comma = 0;
    char delim[2];
    delim[0] = a_delim;
    delim[1] = 0;

    /* Count how many elements will be extracted. */
    while (*tmp)
    {
        if (a_delim == *tmp)
        {
            count++;
            last_comma = tmp;
        }
        tmp++;
    }

    /* Add space for trailing token. */
    count += last_comma < (a_str + strlen(a_str) - 1);

    /* Add space for terminating null string so caller
       knows where the list of returned strings ends. */
    count++;

    result = malloc(sizeof(char*) * count);

    if (result)
    {
        size_t idx  = 0;
        char* token = strtok(a_str, delim);

        while (token)
        {
            assert(idx < count);
            *(result + idx++) = strdup(token);
            token = strtok(0, delim);
        }
        assert(idx == count - 1);
        *(result + idx) = 0;
    }

    return result;
}


void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./monitor \n"
		   "Options:\n"
		   "-m Prints malicious users\n"
		   "-i <filename>, Prints table of users that modified "
		   "the file <filename> and the number of modifications\n"
		   "-h Help message\n"
		   "-v Given a number it will check for malicious intentions. Prints the total number of files created in the last 20 minutes.\n"
		   "-e list all encrypted files\n"
		   
		   "\n\n"
		   );

	exit(1);
}


void 
list_unauthorized_accesses(FILE *log)
{
	char *line = NULL;
	size_t len = 0;
    ssize_t read;
	int line_no = 0;
	int action_denied_flag = 0;
	char subbuff[5];

	int count = 0; //number of unique users in the table
    char *uid;
	int number1;
    int **users;
	int lineNo = 0;
	

	users = (int **)malloc(sizeof*users);
	users[count] = (int *)malloc(2*sizeof(int));
	

	while ((read = getline(&line, &len, log)) != -1) {

		char** tokens;
		tokens = str_split(line, ',');
		if (lineNo == 0)
		{
			lineNo++;
			if (tokens)
			{
				for (int i = 0; i<7; i++)
				{
					if (i == 0)
					{
						int uid1 = atoi(*(tokens+i));
						users = (int **) realloc(users, (count + 1) * sizeof(*users));
						users[0] = (int *)malloc(2*sizeof(int));
						users[0][0] = uid1;
						users[0][1] = 0;
					}
					if (i == 4)
					{
						if (**(tokens + i) == '1')
						{
							users[0][1] = 1;
						}
					}
					free(*(tokens + i));
					
				}
				free(tokens);			
			}
		}
		else
		{
			if (tokens)
			{
				int flag = -1;
				//iterate through all the fields
				for (int i = 0; i<7; i++)
				{
					
					//field 0 -> id
					if (i == 0)
					{
						char* uid1 = *(tokens+i);
						int intUid = atoi(uid1);

						//Search if user already exists in our table
						for (int j = 0; j < count+1; j++)
						{
							
							if (users[j][0] == intUid)
							{
								flag = j;
								
							}							
						}
						if (flag == -1)
						 //initialization of user
						{
								users = (int **) realloc(users, (count + 1) * sizeof(*users));
								users[count+1] = (int *)malloc((count+1)*sizeof(int));

								users[count+1][0] = intUid;
								users[count+1][1] = 0;
								count++;
						}
						//end of search
						
					}
					
					if (i == 4)
					{
						if (**(tokens + i) == '1')
						{
							if (flag !=-1)
							{
								users[flag][1] = users[flag][1] + 1;

							}
							else
							{
								users[count][1] = 1;

							}
						}
						
					}
					
					free(*(tokens + i));
				}
				free(tokens);
			}
		}

	}

	for (int i = 0; i < count+1; i++)
	{
		if (users[i][1] >=7)
		{
			printf("User with id: %d has malicious intents. (%d invalid accesses)\n", users[i][0], users[i][1]);
		}
		free(users[i]);
		
	}
	free(users);
	
	return;

}


void
list_file_modifications(FILE *log, char *file_to_scan)
{

	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */
	char *line = NULL;
	size_t len = 0;
    ssize_t read;
	int line_no = 0;

	int count = 0; //number of unique users in the table
	int number1;
	int lineNo = 0;
	char* thisFile;


	int **users;

	users = (int **)malloc(sizeof*users);
	users[count] = (int *)malloc(2*sizeof(int));
	int userNo = 0;
	char lastFinger[16];
	int timesFound = 0;
	

	while ((read = getline(&line, &len, log)) != -1) {
		char** tokens;
		tokens = str_split(line, ',');
		if (tokens)
		{
			int uid = atoi(*(tokens+0));
			thisFile = *(tokens+1);
			int accessType = atoi(*(tokens+4));
			int actionDeniedFlag = atoi(*(tokens+5));
			char* fingerPrint = *(tokens+6);
			int flag = -1;
			
			//if we found the file
			if (strcmp(file_to_scan, thisFile) == 0) 
			{
				//keep the last fingerprint
				if (timesFound == 0)
				{
					strcpy(lastFinger,fingerPrint);
					timesFound++;
				}
				//first user in table
				if (userNo == 0)
				{
					if(strcmp(lastFinger,fingerPrint)!=0 && accessType==2 && actionDeniedFlag != 1){
						
						users = (int **) realloc(users, (count + 1) * sizeof(*users));
						users[0] = (int *)malloc(2*sizeof(int));
						users[0][0] = uid;
						users[0][1] = 0;
						users[0][1] = 1;
						
						for (int i = 0; i < 7; i++)
						{
							free(*(tokens + i));
						}
						strcpy(lastFinger,fingerPrint);
						free(tokens);	
						userNo++;	
					}	
				}
				else
				{
					
					if(strcmp(lastFinger,fingerPrint)!=0 && accessType==2 && actionDeniedFlag != 1){
						strcpy(lastFinger,fingerPrint);
						//Search if user already exists in our table
						for (int j = 0; j < userNo; j++)
						{
							if (users[j][0] == uid)
							{
								flag = j;
								users[j][1] = users[j][1] + 1;
							}							
						}
						if (flag == -1)
						 //initialization of user
						{
							users = (int **) realloc(users, (userNo + 1) * sizeof(*users));
							users[userNo] = (int *)malloc((userNo+1)*sizeof(int));
							users[userNo][0] = uid;
							users[userNo][1] = 1;
							userNo++;
						}	
				
					
					}
					for (int i = 0; i < 7; i++)
					{
						free(*(tokens + i));
					}
					free(tokens);
				}
			}	
		}		
		
	}

	for (int i = 0; i < userNo; i++)
	{
		printf("User %d modified the file %d times\n", users[i][0], users[i][1]);
	}

	return;

}

void list_created_last_20_mins(FILE *log, int min){
	char *line = NULL;
	int created;
	size_t len = 0;
    ssize_t read;
	char* thisFile;
	int uid;
	int accessType;
	int actionDeniedFlag;
	char* fingerPrint;
	char* str_date;
	char *str_time;

	struct tm *tm;
	time_t t;
	char time_now[9];
	char time_now2[9];
	char date_now[11];

	t = time(NULL);
	tm = localtime(&t);

	strftime(time_now, sizeof(time_now), "%H:%M:%S", tm);
	strftime(time_now2, sizeof(time_now2), "%H:%M:%S", tm);
	printf("Time: %s\n", time_now);
	strftime(date_now, sizeof(date_now), "%d-%m-%Y", tm);
	int records = 0;

	while ((read = getline(&line, &len, log)) != -1) {

		for (size_t i = 0; i < strlen(time_now2); i++)
		{
			time_now[i] = time_now2[i];
		}
		
		char** tokens;
		tokens = str_split(line, ',');
		if (tokens)
		{
			uid = atoi(*(tokens+0));
			thisFile = *(tokens+1);
			accessType = atoi(*(tokens+4));
			actionDeniedFlag = atoi(*(tokens+5));
			fingerPrint = *(tokens+6);
			char* str_date = *(tokens+2);
			char* str_time = *(tokens+3);
			//printf("Time of log: %s\n",str_time);
			//printf("Access type: %d\n",accessType);

			if (strcmp(str_date, date_now) == 0 && accessType == 0)
			{
				
				
				char** tokens2;
				char** tokens3;
				tokens2 = str_split(str_time, ':');
				tokens3 = str_split(time_now, ':');
				int hours_file;
				int minutes_file;
				int hours_now;
				int minutes_now;
				if (tokens2 && tokens3)
				{
					hours_file = atoi(*(tokens2+0));
					minutes_file = atoi(*(tokens2+1));
					//printf("Hours file: %d Minutes file: %d Seconds: %d\n",hours_file, minutes_file, atoi(*(tokens2+2)));
					hours_now = atoi(*(tokens3+0));
					minutes_now = atoi(*(tokens3+1));
					//printf("Hours now: %d Minutes now: %d\n",hours_now, minutes_now);
					if (hours_now == hours_file)
					{
						if (hours_now - hours_file <=20)
						{
							records++;
							printf("Time file: %d:%d\n",hours_file, minutes_file);
							printf("Time now:  %d:%d\n",hours_now, minutes_now);
						}
					}
					else if (hours_now - hours_file == 1)
					{
						if (60 - minutes_file + minutes_now <=20)
						{
							records++;
							printf("Time file: %d:%d\n",hours_file, minutes_file);
							printf("Time now:  %d:%d\n",hours_now, minutes_now);
						}
						
					}
					
					


				}
				else
				{
					printf("Problem with tokens!\n");
				}
				for (int i = 0; i < 2; i++)
				{
					free(*(tokens2 + i));
				}
				free(tokens2);
				for (int i = 0; i < 2; i++)
				{
					free(*(tokens3 + i));
				}
				free(tokens3);	
			}
			else
			{
				//printf("Date now: %s Date file: %s\n",date_now, str_date);
			}
			for (int i = 0; i < 7; i++)
			{
				free(*(tokens + i));
			}
			free(tokens);
			
		}
		
		
	}
	
	if (records>=min)
	{
		printf("Malicious action detected! %d Files were created in the last 20 minutes\n",records);	
	}
	else
	{
		printf("Nothing suspicious. Total number of files created in the last 20 minutes: %d\n",records);	
	}
	

}

void list_encrypted(FILE *log){

	char *line = NULL;
	int uid;
	int accessType;
	int actionDeniedFlag;
	char* fingerPrint;
	char* str_date;
	char *str_time;
	char temp[1024];
	int created;
	size_t len = 0;
    ssize_t read;
	char* thisFile;
	char *ext;
	char *enc = ".encrypt";
	


	while ((read = getline(&line, &len, log)) != -1) {
		char** tokens;
		tokens = str_split(line, ',');
		if (tokens)
		{
			uid = atoi(*(tokens+0));
			thisFile = *(tokens+1);
			accessType = atoi(*(tokens+4));
			actionDeniedFlag = atoi(*(tokens+5));
			fingerPrint = *(tokens+6);
			char* str_date = *(tokens+2);
			char *str_time = *(tokens+3);
			strcpy(temp, thisFile);
			ext = strrchr(temp, '.');
			if (ext){
				if (strcmp(ext,enc)==0 && accessType == 2) {
					printf("Found encrypted file: %s Created at: %s %s\n", temp, str_date, str_time);
				}
			}
			for (int i = 0; i < 7; i++)
			{
				free(*(tokens + i));
			}
			free(tokens);
		}

	}

	return;
}



int 
main(int argc, char *argv[])
{

	int ch;
	FILE *log;
	int min;
	bool flag = true;

	if (argc < 2)
		usage();

	log = fopen("./file_logging.log", "r");
	if (log == NULL) {
		flag = false;
	}

	while ((ch = getopt(argc, argv, "h:i:v:em")) != -1) {
		switch (ch) {		
		case 'i':
			if (!flag)
			{
				printf("Error opening log file \"%s\"\n", "./log");
				return -1;
			}
			
			list_file_modifications(log, optarg);
			break;
		case 'm':
			if (!flag)
			{
				printf("Error opening log file \"%s\"\n", "./log");
				return -1;
			}
			list_unauthorized_accesses(log);
			break;
		case 'e':
			if (!flag)
			{
				printf("Error opening log file \"%s\"\n", "./log");
				return -1;
			}
			list_encrypted(log);
			break;
		case 'v':	
			if (!flag)
			{
				printf("Error opening log file \"%s\"\n", "./log");
				return -1;
			}		
			min = atoi(optarg);
			printf("MIN: %d",min);
			list_created_last_20_mins(log, min);
			break;
			
		default:
			usage();
		}

	}


	/* add your code here */
	/* ... */
	/* ... */
	/* ... */
	/* ... */


	fclose(log);
	argc -= optind;
	argv += optind;	
	
	return 0;
}
