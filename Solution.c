/*
 * Decrypt Ransom Crypren @huntingmalware - mlw.re 
 * MD5 File Infect: f6a8d7a4291c55020101d046371a8bda
 * Link Vt: https://www.virustotal.com/en/file/082060e3320870d1d576083e0ee65c06a1104913ae866137f8ca45891c059a76/analysis/1463052611/
 */

#include <stdio.h>
#include <string.h>

void fileReadKey(char *path,char *key){
	FILE *a = fopen(path,"rb");
	int leng=0;
	leng = fread(key,sizeof(char),64,a);
}

void decrypt(char *path,char *key){
	FILE *a = fopen(path,"rb");
	strcat(path,".decrypt");
	FILE *b=fopen(path,"ab");
	char buff[64];
	int leng=0;
	while(!feof(a)){
		leng = fread(buff,sizeof(char),64,a);
		int i =0;
		for(i=0;i<leng;i++)
			buff[i]=buff[i]-key[i];
		fwrite(buff,sizeof(char),64,b);
	}
	printf("%s\n",path);
}

int main(int arg,char *argv[]){
	char *key[64];
	if(arg<3){
		printf("Error Usage: %s <filekey.txt> <file.Encrypted>\n",argv[0]);
	}else{
		printf("File Key:%s\tFile encrypted:%s\n",argv[1],argv[2]);
		fileReadKey(argv[1],key);
		printf("key is:%s\n",key);
		printf("-------------------------------------------------\n");
		decrypt(argv[2],key);
	}
	printf("\n");
}