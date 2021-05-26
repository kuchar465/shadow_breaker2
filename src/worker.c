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
#include <time.h>
#include <semaphore.h>


#include <crypt.h>

char * dict;
char * passwords = "";
int tasksDone = 0;
int maxTasks = 0;
char * gQueueName = "";
struct Message *messages;
mqd_t mq;
int flag = 1;
char *fdFlag;

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

void updateProgress(struct Message msg){
    sem_wait(&msg.sem);
    int size = 1024;
        char tmp[1024];
        int shm_dictionary = shm_open(msg.progMemPath, O_RDWR, 0666);
        char *fdPass;
        fdPass = mmap(0, size, PROT_WRITE, MAP_SHARED, shm_dictionary, 0);
        close(shm_dictionary);
        char str[1024];
        strcpy(tmp, fdPass);
        sprintf(str, "%d", atoi(tmp) + 1);
        strcpy(fdPass, "");
        strcpy(fdPass, str);
        printf("%s tasks done\n", fdPass);
        //munmap(fdPass, size);
    sem_post(&msg.sem);   
}

char* hash2(char* password, char* salt){
	char* tmp = malloc(sizeof(char)*(strlen(salt)+4));
    strcat(tmp, "$6$");
	strcat(tmp, salt);
    struct crypt_data data;
    data.initialized = 0;
	char* hashVal = crypt_r(password, tmp, &data);
	free(tmp);
	return hashVal;
}

void doWork(struct Message msg){
	char* password = malloc(sizeof(char)*(msg.longestPass));
	int z=0;
    int before = 0;
	for(int i=msg.start; i<msg.stop; i++){
		if(passwords[i] != '\n'){
			password[z]=passwords[i];
			z++;
		}
		else{
            //printf("\n%s - ",password);	
			char* check = hash2(password, msg.salt);
			if(strcmp(check, msg.hash)==0){
                int size = 1024;
                int shm_dictionary = shm_open(msg.passMemPath, O_RDWR, 0666);
                char *fdPass;
                ftruncate(shm_dictionary, size);
                fdPass = mmap(0, size, PROT_WRITE, MAP_SHARED, shm_dictionary, 0);
                updateProgress(msg);
                close(shm_dictionary);
				printf("\n%s - ",password);
                printf("found\n");
                strcpy(fdPass, password);
                munmap(fdPass, size);
                shm_unlink(msg.passMemPath);
                
				break;	
			}
			bzero(password, msg.longestPass);
			z=0;
            before=i;
		}
	}
    free(password);	
}

void handler(int sigNo) {
    mqd_t mq;
    struct mq_attr attr;
    int retVal;
    mq = mq_open(gQueueName, O_RDWR | O_CREAT, 0666, NULL);
    mq_getattr(mq,&attr);
    
    if(flag == 0){
    printf("sigint, returning %d tasks\n", maxTasks-tasksDone);
        for(int i=tasksDone;i<maxTasks; i++){
            retVal = mq_send(mq,(const char*)&messages[i],sizeof(struct Message),10);
        }
    printf("tasks returned\n");
    }
    
    free(messages);
    mq_close(mq);
    exit(0);
}



int main(int argc, char **argv){
    int ret;
    char * Queue;
    int tasks = 0;

    struct sigaction sa;

    sa.sa_handler = handler;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    while ((ret = getopt (argc, argv, "q:p:")) != -1)
        switch (ret) {
            case 'q':
                Queue = optarg;
                gQueueName = Queue;
                
                break;
            case 'p':
                tasks = atoi(optarg);
                maxTasks = tasks;
                break;  
        }

    int retVal;
    int prior;
    
    struct mq_attr attr;
    mq = mq_open(Queue,O_RDWR | O_CREAT, 0666, NULL);
    
    messages = malloc(tasks * sizeof(struct Message));
    
    mq_getattr(mq,&attr);
    char buff[attr.mq_msgsize];
    int buffSize = attr.mq_msgsize;

    struct timespec start;
    clock_gettime(CLOCK_REALTIME, &start);
    start.tv_sec += 5;  // Set for 20 seconds
    for(int i=0;i<tasks;i++){
        while(attr.mq_curmsgs==0){
            mq_getattr(mq,&attr);
        }
        clock_gettime(CLOCK_REALTIME, &start);
        start.tv_sec += 5;  
        mq_timedreceive(mq,(char *)&messages[i],buffSize,NULL, &start);
        int size = 1024;
        int shm = shm_open(messages[i].flagMemPath, O_RDWR, 0666);
        ftruncate(shm, size);
        fdFlag = mmap(0, size, PROT_WRITE, MAP_SHARED, shm, 0);
    }
                
    //munmap(fdPass, size);
    //shm_unlink(msg.passMemPath);

    struct stat statbufPass;
    int passwordAmount = 0;
    int longestPass=0;
    
    int passMax = 0;
    
    for(int i = 0; i<tasks; i++){
        flag = 0;
        dict = messages[i].filename;
        int fd2 = open(dict, O_RDONLY);
        if (fd2 > 0){
            int res = fstat(fd2, &statbufPass);
            if(res == 0){
                char* smap2 = mmap(NULL, statbufPass.st_size, PROT_READ, MAP_SHARED, fd2, 0);
                if(smap2 != NULL && close(fd2)==0){
                    passwords=smap2;
                }
            }
        }
        if(!strcmp("0",fdFlag)){
            munmap(dict, statbufPass.st_size);
            break;
        }
        doWork(messages[i]);
        
        munmap(dict, statbufPass.st_size);
        tasksDone++;

        updateProgress(messages[i]);
    }
    
    free(messages);
    return 0;
}