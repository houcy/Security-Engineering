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

int acl(char *path, char *acl_name);
int make_file(char *path, char *name_file, char *data);

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
	setreuid(geteuid(), getuid());
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
	if(argc < 4)
	{
		printf("Supply 3 arguments. Format : Path <space> file_name <space> contents\n");
		return 0;
	}
	else
	{
		//printf("Argument supplied is : %s\n", argv[1]);
		strcpy(path,argv[1]);
		printf("Path is : %s\n",path);
		strcpy(name_file,argv[2]);
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
		strcat(final_filename,f);
		printf("ACL associated to this file is : %s\n",final_filename);
		
		while ((dir_read = readdir(directory_ptr)) != NULL)	//check directory for ACL.txt
		{
			if(dir_read->d_type == DT_REG)		//only check for files no sym links and directories.
			{
				//printf("File names : %s\n",dir_read->d_name);	//display all file names
				if(strcmp(dir_read->d_name,name_file) == 0)	//check if file exists or not
				{
					flag = 1;
				}
			}
		}
		
		if(flag==0)		// No file, do file create and store permissions.
		{
			//make_file(path,name_file,argv[3]);
			//acl(path);
			//make_dir(path,name_dir);	
			
			chdir(path);
			char buf1[256];
			strncpy(buf1, argv[3], sizeof(buf1));
			char cwd[1024];
			if (getcwd(cwd, sizeof(cwd)) != NULL)
			{
				//fprintf(stdout, "Current working dir: %s\n", cwd);
				printf("Entering directory to create file. . .\n");
      			} 			
			else
			{
       				perror("getcwd() error");
			}
			int count = strlen(argv[3]);
			int i = 4;
			int acl_noacl=0;	
			for (i = 4;i<argc;i++)
			{
				strcat(buf1, " ");
				count = count + strlen(argv[i]);
				strcat(buf1,argv[i]);
	
			}      

			if (count>sizeof(buf1))	
			{		
				printf("Length exceeded. Please limit your response to %lu words \n", sizeof(buf1));
				exit(0);
			}

			else
			{
				acl_noacl = acl(path,final_filename);
				if(acl_noacl == 0)	//ACL created = true
				{
					//make_file(path,name_file,buf1);		//now create file.
					/*umask(0);
					int fin = open(argv[2], O_RDWR|O_CREAT, 0666);
					if (fin == -1) 
					{
		 	        		printf("\nFailed to open file.\n");
		 	        		return 1;
	 	   			}*/
					//printf("File Created !\n");
			 		make_file(path,name_file,buf1);
					//write (fin, buf1, strlen(buf1));
			 		//close(fin);
				}
				else
				{
					printf("Can't create ACL. File creation stopped.\n");
				}
			}

			
		}		
		else if(flag==1)	// Yes file, throw an error.
		{
			printf("A file with this name already exists. Change the name.\n");
			
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



int acl(char *path, char *acl_name)
{

			int value_for_temp_path = 0;
			int len_of_path = strlen(path);
			int len_of_f = 7;
			struct stat fileStat;
			value_for_temp_path = len_of_path + len_of_f ;
			//printf("Total len : %d\n",value_for_temp_path);
			FILE *fp;
			char temp_path[value_for_temp_path];	//path to create the ACL.  
			strcpy(temp_path,path);			// D S
			strcat(temp_path,acl_name);
			//printf("Total path : %s\n",temp_path);
			printf("Creating an ACL @ %s . . . \n",temp_path);
			fp = fopen(temp_path, "w+");
			
			if (!stat(path, &fileStat))
	        	{
			    fprintf(fp,"U: ");
			    fprintf(fp,"%s ",(fileStat.st_mode & S_IRUSR) ? "r" : "-");
			    fprintf(fp,"%s ",(fileStat.st_mode & S_IWUSR) ? "w" : "-");
			    fprintf(fp,"%s \n",(fileStat.st_mode & S_IXUSR) ? "x" : "-");
			    
			    fprintf(fp,"G: ");
			    fprintf(fp,"%s ",(fileStat.st_mode & S_IRGRP) ? "r" : "-");
			    fprintf(fp,"%s ",(fileStat.st_mode & S_IWGRP) ? "w" : "-");
			    fprintf(fp,"%s \n",(fileStat.st_mode & S_IXGRP) ? "x" : "-");
			    
			    fprintf(fp,"O: ");
			    fprintf(fp,"%s ",(fileStat.st_mode & S_IROTH) ? "r" : "-");
			    fprintf(fp,"%s ",(fileStat.st_mode & S_IWOTH) ? "w" : "-");
			    fprintf(fp,"%s \n",(fileStat.st_mode & S_IXOTH) ? "x" : "-");

			    fprintf(fp,"Owner: ");
			    fprintf(fp,"%ld \n",(long)fileStat.st_uid);

			    fprintf(fp,"Group: ");
			    fprintf(fp,"%ld ",(long)fileStat.st_gid);	
			// not done the part where I create a dir in the existing dir having ACL.
			}
			
		/*if (!stat(path, &fileStat)){
		fprintf(fp,"U: ");
    		fprintf( fp,"%d ", (fileStat.st_mode & S_IRUSR) ? S_IRUSR : 0);
    		fprintf( fp,"%d ", (fileStat.st_mode & S_IWUSR) ? S_IWUSR : 0);
    		fprintf( fp,"%d \n", (fileStat.st_mode & S_IXUSR) ? S_IXUSR : 0);
    		fprintf(fp,"G: ");
    		fprintf( fp,"%d ", (fileStat.st_mode & S_IRGRP) ? S_IRGRP : 0);
    		fprintf( fp,"%d ", (fileStat.st_mode & S_IWGRP) ? S_IWGRP : 0);
    		fprintf( fp,"%d \n", (fileStat.st_mode & S_IXGRP) ? S_IXGRP : 0);
    		fprintf(fp,"O: ");
    		fprintf( fp,"%d ", (fileStat.st_mode & S_IROTH) ? S_IROTH : 0);
    		fprintf( fp,"%d ", (fileStat.st_mode & S_IWOTH) ? S_IWOTH : 0);
    		fprintf( fp,"%d \n", (fileStat.st_mode & S_IXOTH) ? S_IXOTH : 0);      		
			

		}*/

			else
			{
				perror("Error in stat\n");
			}
			printf("File Creation Done.\n");
			fclose(fp);

	return 0;
}


//migrating things to make_file function.

int make_file(char *path, char *name_file , char *data)
{

			

			/*
			umask(0);
			int fin = open(data, O_RDWR|O_CREAT, 0666);
			if (fin == -1) 
			{
		 	       printf("\nFailed to open file.\n");
		 	       return 1;
	 	   	}
			printf("File Created !\n");
			write (fin, buf1, strlen(buf1));
			close(fin);
			*/				
			
			//new code
			char buffer[50];
			FILE *fp;
			//char acl[7]="ACL.txt"; 
			char temp_path[100];	//path to read the ACL file.  
			char temp_path_file[100];	//path to read the file -> data file.
			strcpy(temp_path,path);	// D S
			strcat(temp_path,name_file);
			strcat(temp_path,"ACL.txt");
			//printf("Total path : %s\n",temp_path);
			//printf("Creating file @ %s . . . \n",temp_path);
			fp = fopen(temp_path, "r+");			
			mode_t final_perm=0;
			char buff[50];
		/*while(!feof(fp))
    		{
    			
			fscanf(fp,"%s",buffer);
    			if (strcmp(buffer,"U:")==0)
    			{    				
    				//printf("In user\n");		
				int permissions[3];
    				fscanf(fp,"%s",buffer);
    				permissions[0] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[0];
    				fscanf(fp,"%s",buffer);
    				permissions[1] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[1];    				
    				fscanf(fp,"%s",buffer);
    				permissions[2] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[2];    				
    			}
    			else if(strcmp(buffer,"G:")==0)     				
    			{
    				//printf("In G\n");
				fscanf(fp,"%s",buffer);
    				int permissions[3];    				
    				permissions[0] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[0];
    				fscanf(fp,"%s",buffer);
    				permissions[1] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[1];    				
    				fscanf(fp,"%s",buffer);
    				permissions[2] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[2];    				
    			}
    			else if (strcmp(buffer,"O:")==0)
    			{
    				//printf("In O\n");
				fscanf(fp,"%s",buffer);
    				int permissions[3];    				
    				permissions[0] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[0];
    				fscanf(fp,"%s",buffer);
    				permissions[1] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[1];    				
    				fscanf(fp,"%s",buffer);
    				permissions[2] = atoi(buffer);
    				inherited_permissions = inherited_permissions | permissions[2];    				
    				break;	
    			}
			
    		}*/

		/* not needed
		while(!feof(fp))
			{
				fscanf(fp,"%s",buff);
    				if (strcmp(buff,"U:")==0)
				{
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"r")==0)
					final_perm = final_perm | S_IRUSR;
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"w")==0)
					final_perm = final_perm | S_IWUSR;
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"x")==0)
					final_perm = final_perm | S_IXUSR;
				}
				else if (strcmp(buff,"G:")==0)
				{
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"r")==0)
					final_perm = final_perm | S_IRGRP;
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"w")==0)
					final_perm = final_perm | S_IWGRP;
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"x")==0)
					final_perm = final_perm | S_IXGRP;
				}
				else if (strcmp(buff,"O:")==0)
				{
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"r")==0)
					final_perm = final_perm | S_IROTH;
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"w")==0)
					final_perm = final_perm | S_IWOTH;
					fscanf(fp,"%s",buff);
					if(strcmp(buff,"x")==0)
					final_perm = final_perm | S_IXOTH;
				}					
			}
			*/


		//printf("Permissions : %d\n",final_perm);
		umask(0);
		chdir(path);
		int fin = open(name_file, O_RDWR|O_CREAT, 0777);
		if (fin == -1) 
		{
 		       printf("\nFailed to open or create file.\n");
 		       return 1;						//comes till here.
 	   	}
	
		 write (fin, data, strlen(data));
		 close(fin);	
		printf("File Created!\n");
		

	return 0;
}
