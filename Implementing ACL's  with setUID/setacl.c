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


int check_access_to_file(char *path,char *name_file);
int check_access_to_dir(char *path,char *name_file);

int main(int argc, char const *argv[])
{
	
	char path[20],name_file[20],temp[20];
	DIR *directory_ptr;	//pointer to directory
	int flag_dir = 0;
	int flag_file = 0;
	char a[7] = "ACL.txt";
	if(argc != 4)
	{
		printf("Supply only 3 argument. Format : Path <space> filename/direcroty <space> -d or -f(only one param)\n");
		return 0;
	}
	else
	{
		//printf("Argument supplied is : %s\n", argv[1]);
		strcpy(path,argv[1]);
		strcpy(name_file,argv[2]);
		strcpy(temp,name_file);
		printf("Path is : %s\n",path);
		printf("File is : %s\n",temp);
		if(strcmp(argv[3],"-f")==0)
		{
			printf("File ACL's running. . . \n");
			strcat(temp,a);
			printf("ACL associated with file is : %s\n",temp);
			flag_file = 1;
			
		}
		else if(strcmp(argv[3],"-d")==0)
		{
			printf("Directory ACL's running. . . \n");
			printf("ACL associated with directory is : %s\n",a);		
			flag_dir = 1;
		}
		
	}
	
	if(argv[1][0] == '/')
	{
		
		directory_ptr = opendir(path);
		if (!directory_ptr) 
		{
        		fprintf (stderr, "Cannot open directory '%s': %s\n",path, strerror (errno));
        		exit (EXIT_FAILURE);
		}
		
		//reading the contents of the directory.
		struct dirent *dir_read;	//for reading directory structure
		const char *d_name;		//file names, pre defined data member
		int flag_1 = 0;			//ACL present for file
		int flag_2 = 0;			//ACl present for dir
		const char f[8] = "ACL.txt";
		struct stat fileStat;		//stat buff for permissions
		
		while ((dir_read = readdir(directory_ptr)) != NULL)	//check directory for ACL.txt
		{
			if(dir_read->d_type == DT_REG)		//only check for files no sym links and directories.
			{
				//printf("File names : %s\n",dir_read->d_name);	//display all file names
				if(strcmp(dir_read->d_name,temp) == 0)	//check if file exists or not
				{
					flag_1 = 1;
				}
				else if(strcmp(dir_read->d_name,f) == 0)	//check if file exists or not
				{
					flag_2 = 1;
				}
			}
		}
		
		if(flag_1 && flag_file)		
		{
			//printf("File ACL.\n");
			write_file_acl(path,name_file);
				
		}
		else if(flag_2 && flag_dir)	
		{
			//printf("Directory ACL.\n");
			write_dir_acl(path,name_file);
		}
		else 
		{
			printf("Error : No ACL combinations match.\n");	
		}

	closedir(directory_ptr);
	}
	else if (argv[1][0] == '.')
	{
		printf("Address only using the full path no relative path.\n");
	}
	return 0;
}

int write_file_acl(char *path,char *name_file)
{

			
			
			FILE *fp;
			char temp_path[100];	//path to read the ACL file.  
			//char temp_path_to_file[100];
			strcpy(temp_path,path);	// D S
			strcat(temp_path,name_file);
			//strcpy(temp_path_to_file,temp_path);
			strcat(temp_path,"ACL.txt");
			printf("Path : %s\n",temp_path);
			fp = fopen(temp_path, "r+");			
			mode_t final_perm=0;
			char buff[50];
			//char buffer[100];
			int id_in_int=0;	//for comparision to ruid
			static uid_t ruid;	//checking the real uid.
			ruid = getuid();
			static gid_t guid;
			guid = getgid();
			int can_write = 0;
			//printf("ruid : %d\n",ruid);
			//printf("guid : %d\n",guid);
			printf("Only owner can re-write . . .\n");
			do
			{
				fscanf(fp,"%s",buff);
				if(strcmp(buff,"Owner:")==0)
				{
					fscanf(fp,"%s",buff);
					id_in_int = atoi(buff);
					if(id_in_int==ruid)
					{
						printf("This is the owner!\n");	
						can_write = 1;	
					}
					else
					{
						printf("Owner rights don't match. Access denied.\n");
						return 0;
					}
				}
				
			}while(!feof(fp));
			fclose(fp);
			char a[20];
			char b[20];
			char c[20];
			char d[1];
			if(can_write)
			{
				fp = fopen(temp_path, "w+");
				printf("Input new permissions. . .\n");
				printf("Format : U: r w x\n");
				
				printf("Input user permissions.\n");
				gets(a);
				fputs(a,fp);
				fputs("\n",fp);
				
				printf("Input group permissions.\n");
				gets(b);
				fputs(b,fp);
				fputs("\n",fp);

				printf("Input other permissions.\n");
				gets(c);
				fputs(c,fp);
				fputs("\n",fp);
				
				fprintf(fp,"Owner: ");
			    	fprintf(fp,"%d",ruid);
				fputs("\n",fp);

			    	fprintf(fp,"Group: ");
			    	fprintf(fp,"%d",guid);
					
			}
			fclose(fp);
	return 0;
}


int write_dir_acl(char *path,char *name_file)
{

			
			
			FILE *fp;
			char temp_path[100];	//path to read the ACL file.  
			//char temp_path_to_file[100];
			strcpy(temp_path,path);	// D S
			strcat(temp_path,"ACL.txt");
			//strcpy(temp_path_to_file,temp_path);
			//strcat(temp_path,"ACL.txt");
			printf("path : %s\n",temp_path);
			fp = fopen(temp_path, "r+");			
			mode_t final_perm=0;
			int id_in_int=0;	//for comparision to ruid
			char buff[50];
			//char buffer[100];
			static uid_t ruid;	//checking the real uid.
			ruid = getuid();
			static gid_t guid;
			guid = getgid();
			int can_write = 0;
			//printf("ruid : %d\n",ruid);
			//printf("guid : %d\n",guid);
			printf("Only owner can re-write . . .\n");
			do
			{
				fscanf(fp,"%s",buff);
				if(strcmp(buff,"Owner:")==0)
				{
					fscanf(fp,"%s",buff);
					id_in_int = atoi(buff);
					if(id_in_int==ruid)
					{
						printf("This is the owner!\n");	
						can_write = 1;	
					}
					else
					{
						printf("Owner rights don't match. Access denied.\n");
						return 0;
					}
				}
				
			}while(!feof(fp));
			
			fclose(fp);
			char a[20];
			char b[20];
			char c[20];
			char d[1];
			if(can_write)
			{
				fp = fopen(temp_path, "w+");
				printf("Input new permissions. . .\n");
				printf("Format : U: r w x\n");
				
				printf("Input user permissions.\n");
				gets(a);
				fputs(a,fp);
				fputs("\n",fp);
				
				printf("Input group permissions.\n");
				gets(b);
				fputs(b,fp);
				fputs("\n",fp);

				printf("Input other permissions.\n");
				gets(c);
				fputs(c,fp);
				fputs("\n",fp);
				
				fprintf(fp,"Owner: ");
			    	fprintf(fp,"%d",ruid);
				fputs("\n",fp);

			    	fprintf(fp,"Group: ");
			    	fprintf(fp,"%d",guid);
					
			}
			fclose(fp);
			
	return 0;
}
