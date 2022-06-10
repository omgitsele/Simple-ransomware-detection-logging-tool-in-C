Dimitris Eleftheriadis 2015030067

gcc --version -> gcc (Ubuntu 9.3.0-17ubuntu1~20.04) 9.3.0
run "make all" to build the project. It will also create a folder name "test" (if not exists) in which all the files will be created/encrypted/decrypted.

I DID NOT USE "fopen64". Instead I compile the program with the flag -D_FILE_OFFSET_BITS=64.
According to this post https://stackoverflow.com/questions/730709/2gb-limit-on-file-size-when-using-fwrite-in-c
"the *64 functions are not portable, and not well-defined in any standards",
"Most systems expect fopen (and off_t) to be based on 2^31 file size limit. Replacing them with off64_t and fopen64 makes this explicit, 
but is not recommended in general as they are non-standard."

The code has comments and is pretty self explanatory.
All the files have a help message that explains how they are used.

The algorithm used for encryption/decryption is the same as given in the assignment.


Folder contains:
    -logger.c
        "logger.c" contains the custom fopen() and fwrite() functions.
        The code has comments and is pretty self explanatory.

    -acmonitor.c
        Use "./acmonitor -h" for a help message on how to run it.
        "acmonitor.c" contains the code for the monitoring tool which is responsible for monitoring the
        logs created by the Access Control Logging tool.
        
        Exaple of use:
        ./acmonitor -m -> prints malicious users
        ./acmonitor -e -> prints all the files that were encrypted
        ./acmonitor -i <fileName> -> prints all the users that modified the file and the number of times they modified it
        ./acmonitor -v <number> -> Prints the total number of files created in the last 20 minutes and if they are suspicious or not

    -test_aclog.c
        contains the code is used to test and demonstrate the above
        tasks. 

    -ransomware.sh
        This is the implementation of the ranswomware that was asked. It has a very detailed help 
        message to see how to operate it. 
        Example of use:
        
        1) Generate files:
            ./ransomware.sh -d <FULL_DIRECTORY> -g -n <X> -> Generate X amount of .txt files under FULL_DIRECTORY
        
        2) Encrypt files:
            ./ransomware.sh -d <FULL_DIRECTORY> -e -> Encrypt all files in specified FULL_DIRECTORY
            ./ransomware.sh -d <FULL_DIRECTORY> -e -n <X> -> Encrypt X files in specified FULL_DIRECTORY
            
        3) Decrypt files:
            ./ransomware.sh -d <FULL_DIRECTORY> -z -> Decrypts all encrypted files under FULL_DIRECTORY

        In case an option is not given the program will print a message accordingly.
