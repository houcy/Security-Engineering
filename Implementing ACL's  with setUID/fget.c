#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <pwd.h>
#include <fcntl.h>


int check_access(char *path,char *name_file);

uid_t callerID,ownerID = 0;
void change_uid(char *path)
{
		
	printf("path : %s",path);
	FILE *user_file = fopen("/home/shagun/simple_slash/bin/users.txt","r"); 
	
    printf("setuid started\n");
    char buffer[100];
    if(strstr(path,"alice") != NULL)
    {    
        printf("Here");
	while(!feof(user_file))
        {
            fscanf(user_file,"%s",buffer);
            if(strcmp(buffer,"alice") == 0)
            {
                fscanf(user_file,"%s",buffer);
                ownerID = (uid_t) atoi(buffer);
                break;
            }   
        }
    }
    else if(strstr(path,"bob")!=NULL)
    {
        
	while(!feof(user_file))
        {
            fscanf(user_file,"%s",buffer);
            if(strcmp(buffer,"bob") == 0)
            {
                fscanf(user_file,"%s",buffer);
                ownerID = (uid_t) atoi(buffer);
                break;
            }   
        }
    }
    


    	printf("Euid to switch to is : %d\n",ownerID);
	int status;
	status = seteuid (ownerID);  
	if (status < 0) 
	{
    		fprintf (stderr, "Couldn't set uid.\n");
    		//exit(0);
    	}
    		printf("The user id was switched to: %d\n",ownerID);
    		printf("Uid before exiting switch is: %d\n",callerID);
	
}


void undo_switch(uid_t originalID)
{
    int status;
    status = seteuid (originalID);  

    if (status < 0) {
    fprintf (stderr, "Couldn't set uid.\n");
    exit(0);
    }
    printf("The user id was switched back to: %d\n",originalID);
}


int main(int argc, char const *argv[])
{
	
	char path[20],name_file[20];
	DIR *directory_ptr;	//pointer to directory
	if(argc != 3)
	{
		printf("Supply only 2 argument. Format : Path <space> filename\n");
		return 0;
	}
	else
	{
		//printf("Argument supplied is : %s\n", argv[1]);
		strcpy(path,argv[1]);
		strcpy(name_file,argv[2]);
		printf("Path is : %s\n",path);
		printf("File is : %s\n",name_file);
		
	}
	
	if(argv[1][0] == '/')
	{
		
		//change_uid(path);
		directory_ptr = opendir(path);
		if (!directory_ptr) 
		{
        		fprintf (stderr, "Cannot open directory '%s': %s\n",path, strerror (errno));
        		exit (EXIT_FAILURE);
		}
		
		//reading the contents of the directory.
		struct dirent *dir_read;	//for reading directory structure
		const char *d_name;		//file names, pre defined data member
		int flag = 0;			//ACL present = 1 , else = 0.
		const char f[8] = "ACL.txt";
		struct stat fileStat;		//stat buff for permissions
		char final_filename[50];
		strcpy(final_filename,name_file);
		//strcat(final_filename,f);
		//printf("ACL associated to this file is : %s\n",final_filename);
		
		while ((dir_read = readdir(directory_ptr)) != NULL)	//check directory for ACL.txt
		{
			if(dir_read->d_type == DT_REG)		//only check for files no sym links and directories.
			{
				//printf("File names : %s\n",dir_read->d_name);	//display all file names
				if(strcmp(dir_read->d_name,final_filename) == 0)	//check if file exists or not
				{
					printf("File found.\n");
					flag = 1;
				}
			}
		}
		
		if(flag==0)		// No file, return error to user.
		{
			printf("No file present. Can't access the file.\n");
				
		}
		else if(flag==1)	// Yes file present, check who is accessing.
		{
			check_access(path,final_filename);
		}
		else 
		{
			printf("Value of flag is : %d\n", flag);	// should only be 1 or 0
		}

	closedir(directory_ptr);
	}
	else if (argv[1][0] == '.')
	{
		printf("Address only using the full path no relative path.\n");
	}
	return 0;
}

int check_access(char *path,char *name_file)
{

			
			//new code
			FILE *fp, *fp1;
			//char acl[7]="ACL.txt"; 
			char temp_path[100];	//path to read the ACL file.  
			char temp_path_to_file[100];
			strcpy(temp_path,path);	// D S
			strcat(temp_path,name_file);
			strcpy(temp_path_to_file,temp_path);
			strcat(temp_path,"ACL.txt");
			fp = fopen(temp_path, "r+");			
			fp1 = fopen(temp_path_to_file, "r+");
			mode_t final_perm=0;
			char buff[50];
			char buffer[100];
			int k = 0;
			int id_in_int=0;	//for comparision to ruid
			int id_in_int1=0;	// '' '' '' '' guid
			int read_flag=0;	//read permissions in group rwx
			int read_flag_gid=0;	//person's group id matches the id of the group mentioned in the file.
			static uid_t ruid;	//checking the real uid.
			ruid = getuid();
			static gid_t guid;
			guid = getgid();
			//printf("ruid : %d\n",ruid);
			//printf("guid : %d\n",guid);
			printf("Checking owner rights . . .\n");
		while(!feof(fp))
			{
				
				fscanf(fp,"%s",buff);
    				if(strcmp(buff,"Owner:")==0)
				{
					fscanf(fp,"%s",buff);
					id_in_int = atoi(buff);
					if(id_in_int==ruid)
					{
						printf("Status : Owner!\n");
						printf("Displaying file contents . . .\n");
						while(!feof(fp1))
						{
							fscanf(fp1,"%s",buff);
							printf("%s",buff);
							printf(" ");
						}		
						k = 1;
						fclose(fp1);
					}
					else
					{
						printf("Owner rights don't match. Access denied.\n");
					}
				}
				else if(strcmp(buff,"G:")==0)
				{
					
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"r")==0)
					{
						read_flag = 1;	//user can read in the group. So ls allowed.
					}
					
				}
				else if(strcmp(buff,"Group:")==0)
				{
					//check gid and the id of the file.
					fscanf(fp,"%s",buff);
					id_in_int1 = atoi(buff);
					if(id_in_int1==guid)
					{
						read_flag_gid = 1;	//groups match. 
					} 

				}
			}
			if(k == 0)
			{
				printf("Checking group rights . . .\n");
				if(read_flag_gid && read_flag)	//read permissions as same grp && dir permissions.
				{
					printf("Displaying file contents . . .\n");
					while(!feof(fp1))
					{
						fscanf(fp1,"%s",buff);
						printf("%s",buff);
						printf(" ");
					}
					fclose(fp1);
				}
				else
				{
					printf("You don't have the apt permissions to view the directory.\n");
				}
			}


	return 0;
}
