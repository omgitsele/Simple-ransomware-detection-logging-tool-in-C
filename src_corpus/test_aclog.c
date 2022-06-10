#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>
#include <ctype.h>
#include <stdbool.h>

int main(int argc, char **argv) 
{
	int i;
	size_t bytes;
	FILE *file;
	char *filename;
	int c;
	int no_of_copies;
	char *directory;
	opterr = 0;
	bool createdFlag = false;
	
	
 	while ((c = getopt (argc, argv, ":d:n:b:")) != -1)
		switch (c)
		{
		case 'd':
			directory = (char*)malloc(strlen(optarg)+2);
			strcpy(directory, optarg);
		case 'n':
			if (!createdFlag)
			{
				createdFlag = true;
				no_of_copies = atoi(optarg);
				if (no_of_copies > 0)
				{
				printf("Starting: Creating %d files\n",no_of_copies);
				for (size_t i = 0; i < no_of_copies; i++)
				{
					char *name = "test/copyFile.txt";
					filename = (char*)malloc(strlen(name)+2);
					sprintf(filename, "test/copyFile%ld.txt", i);
					
					file = fopen(filename, "w+");
					if (file == NULL)
						printf("fopen error\n");
					else {
						bytes = fwrite(filename, strlen(filename), 1, file);
						printf("File %s has been created!\n",filename);
						fclose(file);
					}
				}
				}
				
			}
			break;
		case 'b':
			
			printf("creating file: %s\n",optarg);
			char *name = "/test/copyFile.txt";
			filename = (char*)malloc(strlen(name)+2);
			sprintf(filename, "test/copyFile.txt");
			
			file = fopen(optarg, "w+");
			if (file == NULL)
				printf("fopen error\n");
			else {
				bytes = fwrite(filename, strlen(filename), 1, file);
				fclose(file);
			}
			break;
		case '?':
			if (optopt == 'c')
				fprintf (stderr, "Option -%c requires an argument.\n", optopt);
			else if (isprint (optopt))
				fprintf (stderr, "Unknown option `-%c'.\n", optopt);
			else
				fprintf (stderr,"Unknown option character `\\x%x'.\n",optopt);
			return 1;
		default:
			abort ();
      }


}
