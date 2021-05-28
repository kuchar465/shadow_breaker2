#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>
#include <mqueue.h>
#include <fcntl.h>
#include <signal.h> 
#include <semaphore.h>
#include <time.h>

#include <crypt.h>

char * hash = "";
struct stat statbufPass;
struct stat statbufHash;
char * passwords = "";
char * salt = "";
mqd_t mq;
char *shmpath = "";
char *shmpath2 = "";
char *shmpath3 = "";
int memSize = 1024;
char *memBuff;
char *progBuff;
char *flagBuff;
sem_t sem;


struct Message
{
    char filename[256];
    char hash[512];
    char salt[128];
    char passMemPath[10];
    char progMemPath[10];
    char flagMemPath[10];
    sem_t sem; 
    int longestPass;
    int start;
    int stop;
};

void readHash(char * hashFile){
    char * smap1;
    int fd1 = open(hashFile, O_RDONLY);
    if(fd1 > 0){
        int res2 = fstat(fd1, &statbufHash);
    	if(res2 == 0){
            smap1 = mmap(NULL, statbufHash.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd1, 0);
            if(smap1 != NULL ){
                hash=smap1;
                for(int i=0;i<2;i++)
                    salt = strtok_r(hash, "$", &hash);
                munmap(hash, statbufHash.st_size);
                hash = mmap(NULL, statbufHash.st_size, PROT_READ|PROT_WRITE, MAP_PRIVATE, fd1, 0); 
                close(fd1);
            }
        }
    }
}

void clearQueue(void){
    int retVal;
    struct mq_attr attr;
    mqd_t mq2 = mq_open("/Queue",O_RDWR | O_CREAT | O_NONBLOCK, 0666, NULL);
    mq_getattr(mq2,&attr);
    int buffSize = attr.mq_msgsize,prior;
    char message[buffSize];
    while(1)
    {
        retVal = mq_receive(mq2,message,buffSize,&prior);
        mq_getattr(mq2,&attr);
        if(attr.mq_curmsgs==0){
            break;
        }
    }
    mq_close(mq2);
}

void handler(int sigNo) {
    clearQueue();
    mq_close(mq);
    munmap(hash, statbufHash.st_size);
    munmap(passwords, statbufHash.st_size);
    shm_unlink(shmpath);
    munmap(memBuff, memSize);
    shm_unlink(shmpath3);
    munmap(flagBuff, memSize);
    shm_unlink(shmpath2);
    munmap(progBuff, memSize);
    exit(0);
}

int string_compare(char* str1, char* str2)
    {
    int ctr=0;

    while(str1[ctr]==str2[ctr])
    {
        if(str1[ctr]=='\0'||str2[ctr]=='\0')
            break;
        ctr++;
    }
    if(str1[ctr]=='\0' && str2[ctr]=='\0')
        return 0;
    else
        return -1;
    }

int main(int argc, char **argv){
    int ret;
    char * hashFile, * dict;
    
    sem_init(&sem, 1, 1);

    int passMax = 0;
    int passwordAmount = 0;
    int longestPass=0;

    struct sigaction sa;

    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    int processAmount = 0;

    

    while ((ret = getopt (argc, argv, "f:s:p:")) != -1)
        switch (ret) {
            case 'f':
                hashFile = optarg;
                readHash(hashFile);
                break;
            case 's':
                dict = optarg;
                int fd2 = open(dict, O_RDONLY);
                if (fd2 > 0){
                    int res = fstat(fd2, &statbufPass);
                    if(res == 0){
                        char* smap2 = mmap(NULL, statbufPass.st_size, PROT_READ, MAP_SHARED, fd2, 0);
                        if(smap2 != NULL && close(fd2)==0){
                            passwords=smap2;
                            int tmp = 0;
                            for(int i=0; passwords[i]!='\0'; i++){
                                if(passwords[i]=='\n'){
                                    passwordAmount++;
                                    if(passwordAmount==1000){
                                        passMax = i;
                                    }
                                    if(tmp>longestPass){
                                        longestPass=tmp;
                                    }
                                    tmp=0;
                                }
                                tmp++;  
                            }
                        }
                    }
                }
                break;
            case 'p':
                processAmount = atoi(optarg);
                break;  
        }

        char processAmountCmp[1024];
        sprintf(processAmountCmp, "%d", processAmount);
    
        shmpath = "/pass";
        int fdMem = shm_open(shmpath, O_CREAT | O_RDWR, 0666);
        ftruncate(fdMem, memSize);
        memBuff = mmap(NULL, memSize, PROT_WRITE, MAP_SHARED, fdMem, 0);
        close(fdMem);
        strcpy(memBuff, "");

        shmpath2 = "/progress";
        int fdProg = shm_open(shmpath2, O_CREAT | O_RDWR, 0666);
        ftruncate(fdProg, memSize);
        progBuff = mmap(NULL, memSize, PROT_WRITE, MAP_SHARED, fdProg, 0);
        close(fdProg);
        strcpy(progBuff, "0");

        shmpath3 = "/flag";
        int fdFlag = shm_open(shmpath3, O_CREAT | O_RDWR, 0666);
        ftruncate(fdFlag, memSize);
        flagBuff = mmap(NULL, memSize, PROT_WRITE, MAP_SHARED, fdFlag, 0);
        close(fdFlag);
        strcpy(flagBuff, " ");

        int bitLoc = (int)((float)statbufPass.st_size/(float)processAmount);
        struct Message messages[processAmount];
        int stop = 0;
	    for(int i=0; i<processAmount; i++){
		    int start = stop;
            stop=(i+1)*bitLoc;
            while(passwords[stop]!='\n' && passwords[stop]!='\0')
                stop++;
            if(passwords[start]=='\n')
                start++;
            messages[i].start = start;
            messages[i].stop = stop+1;
            messages[i].longestPass = longestPass;
            strcpy(messages[i].filename,dict);
            strcpy(messages[i].hash, hash);
            strcpy(messages[i].salt, salt);
            strcpy(messages[i].passMemPath, shmpath);
            strcpy(messages[i].progMemPath, shmpath2);
            strcpy(messages[i].flagMemPath, shmpath3);
            messages[i].sem=sem;
            start = stop;
	    }

    struct mq_attr attr;
    char * que = "/Queue";
    mq = mq_open(que,O_RDWR | O_CREAT, 0666, NULL);
    printf("kolejka: %s\n", que);
    mq_getattr(mq,&attr);
    int retVal;
    int stoper = 0;
    int waitval = 0;
    int sum = 0;
    int stopt = 0;
    while(stoper!=processAmount){
        clock_gettime(CLOCK_MONOTONIC, &stoptp);
        retVal = mq_send(mq,(const char*)&messages[stoper],sizeof(struct Message),10);
        mq_getattr(mq,&attr);
        waitval++;
       
       
        stoper++;  
    }

    int logflag = 0;
    mq_getattr(mq,&attr);
    while(!strcmp(memBuff,"")){
        if(stopt%10000000==0){
            printf("tasks send: %d, task finished: %s\n", waitval, progBuff);
        }
        stopt++;
        if(string_compare(progBuff,processAmountCmp)==0){
            logflag = 1;
            break;
        }
        mq_getattr(mq,&attr);
    }
    strcpy(flagBuff, "0");
    
    printf("task send: %d, task finished: %s\n", waitval, progBuff);
    fflush(stdout);
    sleep(2);
   
    

    mq_close(mq);

    if(logflag==0)
    printf("\tfound password: %s\n", memBuff);
    else{
        printf("\tpassword not found \n");
    }
    
    printf("\ttasks done: %s\n", progBuff);
    clearQueue();
    shm_unlink(shmpath);
    munmap(memBuff, memSize);
    shm_unlink(shmpath2);
    munmap(progBuff, memSize);
    shm_unlink(shmpath3);
    munmap(flagBuff, memSize);
    munmap(hash, statbufHash.st_size);
    munmap(passwords, statbufHash.st_size);
    sem_destroy(&sem); 
    return 0;
}