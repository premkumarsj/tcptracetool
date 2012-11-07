#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include<ctype.h>
#include<malloc.h>
char inputfile[20];
char input_arra[100][100];
//cmd that needs to b executed

char ip[20];
float delta;
int empty_check=0;
int cmd_flag=0;
int in_len=0;
char tempfile[200][200];
int node_count=-1;
int teststream=-1;
//int node_count_rev=0;
int size =0;
char temp_pak[100][400];
char user_input[100];
//no of packets in the stream
int no_pak=0;
int flag_h=0 , flag_d=0 , d_value=0 , flag_f=0;
//each stream comes in it
char arra[20000][500];
char temp[100];
char s[6];			
//for filters
char filter[10];
char filter_oper[5];	
char filter_data[10];
char runtimecmd[100];
char testname[20];

void dort(int stm, char* type[] , float delta);
void tc_rt(int stm ,int checkip);
void tc_fr(int stm ,int checkip);
void create_datastruct();
void delim_pak();
int get_data();
void time_stamp();
void printdata();
void execution(int argc,char* argv[]);

void printflags();
void testcase(int index , int size);
int check_s(int start , int size);
void dofr(int stm, char* type[]);

int file_read();
int check_f(int size);
int check_t(int size);
int check_h(int size);

int check_filename();
int check_ip(int size);
int check_delta(int size);
int check_d(int size);
struct ackfreq
{
		unsigned int seq_no;
		unsigned int ack_no;		
		int fre;
		char ack3t[20];
		char ack1t[20];
}af_array[20000];
struct packet
{
	char rx_num[20];
	char flags[20];
	char chksum[20];
	char expert_msg[100];
	char lpcb_no[20];
	char timestamp[20];

	unsigned int seq_no;
	unsigned int acq_no;
	unsigned int hdr_len;
	unsigned int win_size;
	unsigned int win_size_cal;	
	unsigned int win_scale;
	unsigned int dup_ack;
	unsigned int dup_ack_num;
	unsigned int nxt_seq;
	struct packet *next;
	struct packet *prev;

	
}*packet_head;
	
struct stream
{
	

	char src_ip[20];
	char dst_ip[20];
	char pcb_no[20];

	unsigned int st_no;
	unsigned int src_port;
	unsigned int dst_port;
	unsigned int ws_val_cl;		
	unsigned int mss_val_cl;
	unsigned int mss_val_svr;	
	unsigned int ws_val_svr;
	unsigned int ws_en;
	
	

	struct stream *snext;
	struct stream *sprev;

	struct packet *link;
	
}*stream_head;         



//main
int main( int argc , char *argv[])
{

//char hellp[10];
//stccpy();
execution(argc,argv);

return 0;
}


int get_data()
{
	char cmd[100][100];
	int i=-1,ic=0;	
	int o_output =0;
	int c_output =0;
	int flag=1;
	char rm_cmd[40];
	while(1)
	{	
		flag=1;		
		i=i+1;
		empty_check=0;
//		printf("command is foris = %d \n",i);			
			strcpy(cmd,"");
		if(cmd_flag == 0)
		{
		//printf("inside %d normal \n",cmd_flag);
			for(ic=0;ic<100;ic++)			
				strcpy(cmd, " " );			
				
			sprintf(cmd,"tshark -R \" tcp.stream ==  %d  \" -T fields -e tcp.stream -e tcp.srcport -e ip.dst  -e tcp.dstport  -e nstrace.pdevno -e nstrace.l_pdevno -e nstrace.dir -e tcp.seq -e tcp.ack -e tcp.hdr_len -e tcp.flags -e tcp.window_size_value -e tcp.window_size -e tcp.window_size_scalefactor -e tcp.checksum -e tcp.analysis.duplicate_ack -e tcp.analysis.duplicate_ack_num  -e tcp.options.wscale.shift  -e tcp.options.sack_perm -e ip.src -e tcp.options.mss_val -e frame.time_relative -e tcp.nxt.seq -e expert.message -r   ",i);
		}
		else
		{	
					//printf("\ninside else \n");
				for(ic=0;ic<100;ic++)			
				strcpy(cmd, " " );			
		
		
			sprintf(cmd,"tshark -R \" tcp.stream ==  %d && ",i);
			//for(ic=0;ic<(in_len-2);ic++)
			//{
			//	strcat(cmd," ");			
			//	strcat(cmd,runtimecmd[ic]);	
			//	strcat(cmd," ");			
			//}
				strcat(cmd," ");			
				strcat(cmd,runtimecmd);	
			
			strcat(cmd," \" -T fields -e tcp.stream -e tcp.srcport -e ip.dst  -e tcp.dstport  -e nstrace.pdevno -e nstrace.l_pdevno -e nstrace.dir -e tcp.seq -e tcp.ack -e tcp.hdr_len -e tcp.flags -e tcp.window_size_value -e tcp.window_size -e tcp.window_size_scalefactor -e tcp.checksum -e tcp.analysis.duplicate_ack -e tcp.analysis.duplicate_ack_num  -e tcp.options.wscale.shift  -e tcp.options.sack_perm -e ip.src -e tcp.options.mss_val -e frame.time_relative -e tcp.nxt.seq -e expert.message -r ");		

		
			
			
		}
		strcat(cmd,inputfile);

		strcat(cmd," > ");
		
		//to create the temp file name
		time_stamp();
		strcat(tempfile,".txt");		
		strcat(cmd,tempfile);
		strcat(cmd," 2>&1");
		//printf("%s \n",cmd);	
			
		//printf("\n");
				
		o_output = system(cmd);	
		if(o_output!=0)
		{
			printf("\n\ncommand entered is wrong\n");
			return 1;
		}
//		printf("hello");
		
		flag=file_read();
		
		strcpy(rm_cmd,"");
		strcpy(rm_cmd,"rm ");
		strcat(rm_cmd, tempfile); 
		//c_output=system(rm_cmd);
		if(flag==0)
		{
		//printf("\ninside flag 0 \n");
			for(ic=0;ic<100;ic++)			
				strcpy(cmd, " " );			
			sprintf(cmd,"tshark -R \" tcp.stream ==  %d  \" -T fields -e tcp.stream -e tcp.srcport -e ip.dst  -e tcp.dstport  -e nstrace.pdevno -e nstrace.l_pdevno -e nstrace.dir -e tcp.seq -e tcp.ack -e tcp.hdr_len -e tcp.flags -e tcp.window_size_value -e tcp.window_size -e tcp.window_size_scalefactor -e tcp.checksum -e tcp.analysis.duplicate_ack -e tcp.analysis.duplicate_ack_num  -e tcp.options.wscale.shift  -e tcp.options.sack_perm -e ip.src -e tcp.options.mss_val -e frame.time_relative -e tcp.nxt.seq -e expert.message -r   ",i);
			strcat(cmd,inputfile);
			empty_check=1;
			strcat(cmd," > ");
			time_stamp();
			strcat(tempfile,".txt");		
			strcat(cmd,tempfile);
			o_output = system(cmd);	
			flag=file_read();

			strcpy(rm_cmd,"");
			strcpy(rm_cmd,"rm ");
			strcat(rm_cmd, tempfile); 
			c_output=system(rm_cmd);
		
			if(flag==0)
			{
				//printf("going to break");
				break;
			}
			node_count++;
//			printf("skipping %d stream \n",i);	
		}
		
	}
  //   printf("going out to break");
	strcpy(cmd," clear");     
	o_output = system(cmd);		
	return 0;	
}

void time_stamp(){

    time_t ltime; /* calendar time */
    ltime=time(NULL); /* get current cal time */
    strcpy(tempfile,"");
     strcpy(tempfile,asctime( localtime(&ltime) ) );

    char *i=(char*)tempfile, *j=(char*)tempfile;  
  
    do {  
    if (*i != ' ')  
    *(j++) = *i;  
    } while (*(i++)); 

    char *s = tempfile;
    char *p2 =s;
    while(*s != '\0') 
    {
        if(*s != '\t' && *s != '\n') 
	{
                *p2++ = *s++;
        } else 
	{
                ++s;
        }
    }
    *p2 = '\0';


}
int file_read()
{

	struct stream *current;
	struct packet *current_pak;
	FILE *file = fopen ( tempfile, "r" );
	int i,j ,k=0;
	int pp=0;
	int count;
	int length;
	//int tempo=0;
	//char *token[100];
	char line[500]; /* or other suitable maximum line size */ 


	for(i=0; i<2000; i++)
	for(j=0; j<500; j++) 
	arra[i][j] = '\0';

	
	int no_check=0;

	for(i=0; i<300; i++)
	line[i] = '\0';
	int pass=3;
	if ( file != NULL )
	{ 

		count=0; 

		while ( fgets ( line, sizeof line, file ) != NULL ) /* read a line */
		{
			if(pass!=0)
				pass--;		
			else
			{
				//printf("Inside While %s\n\n", line);
				length = strlen(line);			
				//printf("String Length %d\n\n", length);
				for(pp=0; pp<length-1; pp++)
				{
					arra[count][pp] = line[pp];	
				}	
				
				for(j=0; j<500; j++)
				line[j] = '\0';
				//no_check=strlen(arra[i]);						
				//if(empty_check == 0)
					//printf("\n array ----> \n %s \n \n", arra[count]);
					count++;	
			}
		}
		fclose ( file );
		//printf("After File Close\n");
	}	
	else
	{
		perror (tempfile); /* why didn't the file open? */
	}
	
	no_pak=count;
	//printf("No of packets %d", no_pak); 
	if(!strcmp(arra,""))
		return 0;
	else if(empty_check == 1)
	{
		empty_check == 0;
		return 1;	
	}
	else
	{
		//--->break and create the db
		delim_pak();
			
	}		
	int no=0 , m=0 ,n=0 ,p=0 ;
	//printf("am going to print the output through an array \n");		
	//for (i=0;i<no_pak;i++)
	//	printf("array --> \n %s",arra[i]);	
	return 1;

}

    
void delim_pak()
{
	int i=0 , m=0 , n=0 , j=0 ,p =0 ,ii=0 ,jj=0;
	int pak_len=0;
	
	for(i=0;i<100;i++)
	{
		for(j=0;j<400;j++)
		{
			temp_pak[i][j]='\0';
		}
	}
	for(i=0;i<no_pak;i++)
	{
	
		//printf("i is %d check",i);	
         	pak_len=strlen(arra[i]);
		//strcpy(temp,"");
		m=0;
		n=0;
 		for(j=0;j<pak_len;j++)
		{
		
				if((arra[i][j] == '\t') || (arra[i][j] == ' ') || (arra[i][j] == '\n'))			
				{	

					temp_pak[m][n]='\0';
			//		printf("-%s-",temp_pak[m]);		
					m++;
					n=0;	
				}
				else
				{

					temp_pak[m][n]=arra[i][j];
					n++;
			
				}				
			
			
		}  
		int i_last=0;
		if(m > 23)		
		{
		//	printf("here");
			for(i_last=24 ;i_last <= m; i_last ++)
			{
		
				strcat(temp_pak[23]," "); 
				strcat(temp_pak[23],temp_pak[i_last]);		 
			}		
			strcat(temp_pak[23],"\0");
		
			for(i_last=24;i_last <=m;i_last ++)
			{
				strcpy(temp_pak[i_last],"");
			}
			m=23;			
		}
	//	printf("\n m is = %s = \n",temp_pak[m]);
		
		
		//----> create the data structure from the delim packet in temp_pak
		create_datastruct();
		
		
		for(ii=0;ii<100;ii++)
		{
			for(jj=0;jj<100;jj++)
			{
				temp_pak[ii][jj]='\0';
			}
		}
		
		
	}	
		
	



}


void create_datastruct()
{
	unsigned temp_val=0;	
	
	struct stream *current;
	struct packet *current_pak;
	int p=0 , counter=0 ,tempo=0 ;
	for( p=0 ;p<=21;p++)
	{
			//printf(" -%s-  ", temp_pak[p]);     	
	}
//	printf("\n next \n");	

	tempo=atoi(temp_pak[0]);
		
	////		printf ("inside if node count is %d ans tem is %d\n",node_count,tempo);
	//return;		
	if (node_count == tempo)
	{
	
			
			
				current=stream_head;
			
	
				while(1)
				{	
					if(current->snext == NULL)
					{	
											
							
							break;
					}
	
					current = current->snext;
				}

	
			 
			//printf("stream number is %d\n",current->st_no);
			//return;	
	
			
			
			//create the new packet
			struct packet *pak_node = ((struct packet*)malloc(sizeof(struct packet)));	
			size=size+sizeof(struct packet);	
				

				if(!strcmp(current->src_ip,temp_pak[19]))				
				{
					strcpy(pak_node->rx_num,"client");
				}
				else
					strcpy(pak_node->rx_num,"server");
				temp_val=atoi(temp_pak[7]);
				pak_node->seq_no=temp_val;
				temp_val=0;
			
															 

				temp_val=atoi(temp_pak[8]);	
				pak_node->acq_no=temp_val;
				temp_val=0;

									
				temp_val=atoi(temp_pak[9]);
				pak_node->hdr_len=temp_val;
				temp_val=0;

				if(!strcmp(temp_pak[10],"0x0002"))
				{
					temp_val=0;
					temp_val=atoi(temp_pak[17]);
					current->ws_val_cl=temp_val;
					temp_val=0;
					temp_val=atoi(temp_pak[20]);
					current->mss_val_cl=temp_val;
					temp_val=0;
								
				}
				else if (!strcmp(temp_pak[10],"0x0012"))
				{
					temp_val=atoi(temp_pak[17]);
					current->ws_val_svr=temp_val;
					temp_val=0;
					temp_val=atoi(temp_pak[20]);
					current->mss_val_svr=temp_val;
					temp_val=0;
				}							
				strcpy(pak_node->flags,temp_pak[10]);
				
								
				temp_val=atoi(temp_pak[11]);
				pak_node->win_size=temp_val;
				temp_val=0;
				
				
				
				temp_val=atoi(temp_pak[12]);
				pak_node->win_size_cal=temp_val;
				temp_val=0;
				
				
				temp_val=atoi(temp_pak[13]);
				pak_node->win_scale=temp_val;
				temp_val=0;
				
				
				strcpy(pak_node->chksum,temp_pak[14]);
				
				temp_val=atoi(temp_pak[15]);
				pak_node->dup_ack=temp_val;
				temp_val=0;
				
				temp_val=atoi(temp_pak[16]);
				pak_node->dup_ack_num=temp_val;
				temp_val=0;
				
				strcpy(pak_node->timestamp,temp_pak[21]);
				
				temp_val=atoi(temp_pak[22]);
				pak_node->nxt_seq=temp_val;
				temp_val=0;
						
				strcpy(pak_node->expert_msg,temp_pak[23]);
				
				strcpy(pak_node->lpcb_no,temp_pak[5]);
				current_pak = packet_head;
	
				pak_node->next=NULL;
				pak_node->prev=NULL;
				
				while(1)
				{	
					if(current_pak->next == NULL)
					{	
											
						current_pak->next=pak_node;
                                                size=size+sizeof(struct packet);
						pak_node->prev=current_pak;					
			//			printf("added\n");	
							break;
					}
	
					current_pak = current_pak->next;
				}

				 
 			//	printf (" end of if count is %d ans tem is %d\n",node_count,tempo);
		}		
		else if(node_count < tempo )
		{
			//1st packet of the stream so create the stream and and the head packet of the packet linked list				
		//	printf ("inside else else node count is %d ans tem is %d\n",node_count,tempo);
		//	return;			
			// create the stream packet			
			struct stream *newNode = ((struct stream*)malloc(sizeof(struct stream)));	
			size=size+sizeof(struct stream);

			temp_val=atoi(temp_pak[0]);
			newNode->st_no=temp_val;
			temp_val=0;
				
			
			
			strcpy(newNode->src_ip,temp_pak[19]);
			
			strcpy(newNode->dst_ip,temp_pak[2]);
			
			temp_val=atoi(temp_pak[1]);
			newNode->src_port=temp_val;
			temp_val=0;
				
			//temp_val=atoi(temp_pak[17]);
			//newNode->ws_val=temp_val;
			//temp_val=0;
			//temp_val=atoi(temp_pak[20]);
			//newNode->mss_val=temp_val;
			temp_val=0;
			temp_val=atoi(temp_pak[18]);
			newNode->ws_en=temp_val;
			temp_val=0;
			
			
			temp_val=atoi(temp_pak[3]);
			newNode->dst_port=temp_val;
			temp_val=0;
						
			
			
			strcpy(newNode->pcb_no,temp_pak[4]);
					
			
			
	
				// create the head of the packet of each of the stream
				struct packet *pak_new = ((struct packet*)malloc(sizeof(struct packet)));	
				size=size+sizeof(struct packet);	
		
				
				
				strcpy(pak_new->rx_num,temp_pak[6]);
				strcpy(pak_new->rx_num,"client");
		
				temp_val=atoi(temp_pak[7]);
				pak_new->seq_no=temp_val;
				temp_val=0;
			
															 

				temp_val=atoi(temp_pak[8]);	
				pak_new->acq_no=temp_val;
				temp_val=0;

									
				temp_val=atoi(temp_pak[9]);
				pak_new->hdr_len=temp_val;
				temp_val=0;

				if(!strcmp(temp_pak[10],"0x0002"))
				{
					temp_val=0;					
					temp_val=atoi(temp_pak[17]);
					newNode->ws_val_cl=temp_val;
					temp_val=0;
					temp_val=atoi(temp_pak[20]);
					newNode->mss_val_cl=temp_val;
					temp_val=0;
								
				}
				else if (!strcmp(temp_pak[10],"0x0012"))
				{
					temp_val=atoi(temp_pak[17]);
					newNode->ws_val_svr=temp_val;
					temp_val=0;
					temp_val=atoi(temp_pak[20]);
					newNode->mss_val_svr=temp_val;
					temp_val=0;
				}				
				strcpy(pak_new->flags,temp_pak[10]);
				
								
				temp_val=atoi(temp_pak[11]);
				pak_new->win_size=temp_val;
				temp_val=0;
				
				
				
				temp_val=atoi(temp_pak[12]);
				pak_new->win_size_cal=temp_val;
				temp_val=0;
				
				
				temp_val=atoi(temp_pak[13]);
				pak_new->win_scale=temp_val;
				temp_val=0;
				
			
				
				strcpy(pak_new->chksum,temp_pak[14]);
				
				temp_val=atoi(temp_pak[15]);
				pak_new->dup_ack=temp_val;
				temp_val=0;
				
			
				
				temp_val=atoi(temp_pak[16]);
				pak_new->dup_ack_num=temp_val;
				temp_val=0;
							
			
				strcpy(pak_new->timestamp,temp_pak[21]);
				
				temp_val=atoi(temp_pak[22]);
				pak_new->nxt_seq=temp_val;
				temp_val=0;
					
				strcpy(pak_new->expert_msg,temp_pak[23]);
				
				strcpy(pak_new->lpcb_no,temp_pak[5]);
				current_pak = packet_head;
	


			newNode->sprev=NULL;
			newNode->snext=NULL;		
			newNode->link=pak_new;
			
			pak_new->next=NULL;
			pak_new->prev=NULL;
			//printf("\nam here \n");
			//make it as head node
			packet_head=pak_new;
			
			//insert stream to the end

			if (stream_head == NULL)
				stream_head=newNode;
			else
			{
				current = stream_head;
	
				while(1)
				{	
					if(current->snext == NULL)
					{	
											
						current->snext=newNode;
						newNode->sprev=current;					
						//printf("added\n");	
							break;
					}
	
					current = current->snext;
				}

			 }
	
												
				
			//increase the node count
			node_count++;
		//printf("tempo is %d",node_count);
		
		}
		
		
		
//printf("over");

}
void printdata()
{
	int fi=0 , fj=0;			
	struct stream *stream_print;
	struct packet *packet_print;
	stream_print=stream_head;
	while(stream_print != NULL)
	{
		//printf("indise printdata");		
		printf("\n\nst_no=%d ",stream_print->st_no);
		printf("\tsrc_ip=%s ",stream_print->src_ip);
		printf("\tsrc_port=%d ",stream_print->src_port);
		printf("\t dest_ip=%s ",stream_print->dst_ip);	
		printf("\tdest_port=%d \n",stream_print->dst_port);
	

	if(d_value!=0)
	{
		packet_print=stream_print->link;
		while(packet_print != NULL )
		{

			printf(" %s ",packet_print->timestamp);				
			
			//strcpy(f,packet_print->flags)
			fi=0 , fj=0;			
			for(fi=3;fi<6;fi++)
			{
				s[fj]=packet_print->flags[fi];
				fj++;
			}
			s[fj]='\0';
			//fi=atoi(f)						
//			printf("f %cis %c ds%cf",s[0] ,s[1],s[2]);			
			printflags();
			printf("seq=%d  ",packet_print->seq_no);
			printf("acq=%d ",packet_print->acq_no);
			printf("len=%d  ",packet_print->hdr_len);
			//printf("flags=%s ",packet_print->flags);
			printf("win=%d  ",packet_print->win_size);
			//printf("win_size_cal=%d ",packet_print->win_size_cal);
			printf("scale=%d ",packet_print->win_scale);
			printf("nxt_seq=%d  ",packet_print->nxt_seq);
			//printf("dup_ack=%d  ",packet_print->dup_ack);
			//printf("dup_ack_num=%d ",packet_print->dup_ack_num);
		//	printf(" %s   ",packet_print->expert_msg);
			//printf(" %s   ",packet_print->timestamp);				
			if(!strcmp(packet_print->rx_num,"client"))			
			{
				printf("==>> ");			
			}
			else if(!strcmp(packet_print->rx_num,"server"))			
			{
				printf("<<== ");			
			}
						
			printf("\n");
			//printf("lpcb no=%s \n",packet_print->lpcb_no);
				
			packet_print=packet_print->next;
		}
		
	}	stream_print=stream_print->snext;
		
	}

}	


int check_f(int size)
{
// to check any filter is present or nt
	int i=0 ,n=0;
	n=strlen(input_arra);	
 //       printf("n is %s we %d sdas",input_arra,n);
	for(i=0;i<=size;i++)
	{

		if(!(strcmp(input_arra[i],"-f")))
		{
//			printf("inside n f is dr");

			return (i+1);
		}
	}
	return (-1);

}

int check_F(int size)
{
// to check any filter is present or nt
	int i=0 ,n=0;
	n=strlen(input_arra);	
 //       printf("n is %s we %d sdas",input_arra,n);
	for(i=0;i<=size;i++)
	{

		if(!(strcmp(input_arra[i],"-F")))
		{
//			printf("inside n f is dr");

			return (i+1);
		}
	}
	return (-1);

}

int check_t(int size)
{
// to check if any testcase is checkde for or not
        int i=0 ,n=0;
	//n=st"rlen(input_arra);	
        //printf("insdei t");
	for(i=0;i<=size;i++)
        {
		if(!(strcmp(input_arra[i],"-t")))
		{
	//		printf("returning %d dsf",i+1);
		     return (i+1);
		}
        }
//	printf("insdei t");	 
	   return -1;

}
int check_s(int start , int size)
{
// to check if any testcase is checkde for or not
        int i=0 ,n=0;
	//n=st"rlen(input_arra);	
        //printf("insdei t");
	for(i=start;i<size;i++)
        {
		if(!(strcmp(input_arra[i],"-s")))
                return (i+1);
        }
	    return -1;

}
int check_ip(int size)
{
// to check if any testcase is checkde for or not
        int i=0 ,n=0;
	//n=st"rlen(input_arra);	
        //printf("insdei t");
	for(i=0;i<size;i++)
        {
		if(!(strcmp(input_arra[i],"-ip")))
                return (i+1);
        }
	    return -1;

}

int check_delta(int size)
{
// to check if any testcase is checkde for or not
        int i=0 ,n=0;
	//n=st"rlen(input_arra);	
        //printf("insdei t");
	for(i=0;i<size;i++)
        {
		if(!(strcmp(input_arra[i],"-delta")))
                return (i+1);
        }
	    return -1;

}

int check_h(int size)
{
// to check if any testcase is checkde for or not
        int i=0 ,n=0;
	//printf("h mainmila");		 
	//n=strlen(input_arra);	
        for(i=0;i<=size;i++)
        {
		if(!(strcmp(input_arra[i],"-h")))
		{           
	//		printf("h mila");		 
		    return (1);
		}        

	}
	    return 0;

}
int check_d(int size)
{
// to check if any testcase is checkde for or not
        int i=0 ,n=0;
	//printf("h mainmila");		 
	//n=strlen(input_arra);	
        for(i=0;i<=size;i++)
        {
		if(!(strcmp(input_arra[i],"-d")))
		{           
		//	printf("h mila");		 
		    return (i+1);
		}        

	}
	    return -1;

}

void execution(int argc,char* argv[])
{

	int in=0,flag_F=-1 ,io=0,jo=0 ,copy_flag=0 , flag_fname=0;
		char f[6];			
	in_len=argc;
	flag_h=0;
	flag_d=-1;	
	d_value=0;
	flag_f=-1;
	
	for(in=0; in< in_len ;in++)
	{
			strcpy(input_arra[in],argv[in]);
	}
	//	printf("val of srgasdc is %d \n",in_len);
	flag_f=check_f(in_len);
	flag_F=check_F(in_len);
	flag_h=check_h(in_len);
	flag_d=check_d(in_len);
//	printf("h is %d\n",flag_h);		
	if(flag_h == 1)
	{
		printf("help karo\n");
		return ;
	}			
	if(in_len < 2)
	{
		printf("\n usage ./a.out inputfile<test.cap>\n");
			return ;
	}
	if(flag_d != -1)
	{
		d_value=atoi(argv[flag_d]);
		//strcpy(inputfile,argv[flag_d]);
		
	}
	if(flag_F != -1)
	{

		//d_value=atoi(argv[flag_F]);
		strcpy(inputfile,argv[flag_F]);
	//	printf("d_value is %s \n\n",inputfile);
	//	return;	
	}
	else
	{
		printf("no input file \n -F <filename.cap>");
		return;

	}
	//check filename exists or not	
	//printf("filename is %s",inputfile);
	 flag_fname=check_filename();	
	if(flag_fname == 1 )
	{
		printf("\n input file name  format is wrong ...<*.cap>\n");
		return;

	}

		strcpy(runtimecmd," ");
	cmd_flag=0;
	int len=0;
	//printf("number is %d \n\n",in_len);
	//if(flag_d==1)
	//	len=in_len-3;
	//else
	//	len=in_len-1;
	if(flag_f != -1)
	{
			
		
		cmd_flag=1;		
	//	
		io=0;
		jo=0;
		strcpy(runtimecmd,input_arra[flag_f]);
	//	printf("%she%sre",runtimecmd,input_arra[flag_f]);
			//for(io=0;io<strlen(input_arra[flag_f]);io++)
			//{

			//	printf("%c",input_arra[flag_f][io]);
				//if(input_arra[flag_f][io] == ' ')				
				//	jo++;								
				//strcpy(runtimecmd[jo][io],input_arra[flag_f][io]);
				
			//}
			//return;		
	/*					for(io=0;io<strlen(runtimecmd);io++)
			printf("cmd is jgjnade %d us %s jhkj \n",flag_f,runtimecmd[io]);	*/					
	}		
	
	int ret, check_ret=0;
	check_ret=get_data();
	//return 1;
	if(check_ret==1)
		return;
	int checkt =-1, checkf=0;
	int checkfst=0;	
	
	//number of words in input
	int inputsize=in_len;

	strcpy(user_input,input_arra[1]);
	printdata();
	while(1)
	{
		//printf("inside while");
		checkt=-1;
		checkf=0;
		

		//checkf=check_f(inputsize);		

		if(checkfst==1)
		{
			strcpy(user_input,"");
			//checkfst=1;	


			printf(" \n enter the new commnad  \n ");
			//scanf(" %s ",input_value);
			int j=0,m=0;
			for(m=0;m<100;m++)
			{		
  				for(j=0;j<100;j++)
    					input_arra[m][j]='\0';
			}			
 			char c; 
       			for (m=0;m<100;)
            		{     
                 		for(j=0;j<100;j++)
                    		{	
                            		scanf("%c",&c);
                             		if(c==' ') 
					{
						 m++; break;
					}
                             		if(c=='\n') 
						break;
                             		input_arra[m][j]=c; 
                     		}
         			 
                		 if(c=='\n')break;
              

           		}	
			inputsize=m;
			//for( j=0;j<=m;j++)			
			  //    printf("in put is %s \n",input_arra[j]); 
                        strcpy(user_input,input_arra[0]);
		}
		checkt=check_t(inputsize);
		if(!strcmp(user_input,"exit"))
			break;			
		
		else if(!strcmp(user_input,"help"))
		{

			printf("\n am in help \n");

		}			
		else if(checkt !=-1 && checkfst == 1)
		{

	//		printf("t is present at pos %ddsf and in put size is %d \n",checkt , inputsize);			
			testcase(checkt,inputsize);
			
				
		}
		else
		{
			if(checkfst==1)
			{			
			printf("wrong command entered \n");
			}

		}
		checkfst=1;	
		


	}
	




}

int check_filename()
{

	int i=0 ,n=0;
	n=strlen(inputfile);	
 	char checkcmd[30];
//	printf("check the nema %d \n",n);
	for(i=0;i<n;i++)
	{

		if(inputfile[i] == '.' && !(inputfile[i+1] == 'c' && inputfile[i+2] == 'a' && inputfile[i+3] == 'p')  )
		{
			//printf("right format %c \n",inputfile[i]);
			//break;
			return (1);
		}
	}
	for(i=0;i<30;i++)
		checkcmd[i]='\0';	
	strcpy(checkcmd,"ls  ");
	strcat(checkcmd,inputfile);
	n=system(checkcmd);
	if(n !=0)
		return 1;
	//printf("checkcmd is %s ans %d",checkcmd,n);		
return 0;
}
void printflags()
{
	//printf("%d[%c %c  %c",strlen(s),s[0],s[1],s[2]);
	printf("[ ");	
	int num;
	num=s[2];
	switch(num)
	{
		case '0':
			printf("");
			break;
		case '1':
			printf("FIN ");
			break;
		case '2':
			printf("SYN ");
			break;
		case '3':
			printf("FIN SYN ");
			break;
		case '4':
			printf("RST ");		
			break;
		case '5':
			printf("RST SYN ");
			break;
		case '6':
			printf("RST FIN ");
			break;
		case '7':
			printf("RST FIN SYN ");
			break;
		case '8':
			printf("PUSH ");
			break;
		case '9':
			printf("PUSH SYN ");
			break;
		case 'a':
		case 'A':
			printf("PUSH FIN ");
			break;
		case 'b':
		case 'B':
			printf("PUSH SYN FIN ");
			break;
		case 'c':
		case 'C':
			printf("PUSH RST ");
			break;
		case 'd':
			case 'D':
			printf("PUSH RST FIN ");
			break;
		case 'e':
		case 'E':
			printf("PUSH RST SYN ");
			break;
		case 'f':
		case 'F':
			printf("PUSH RST SYN FIN ");
			break;
	}
	num=(s[1]);
	switch(num)
	{
		case '0':
			printf("");
			break;
		case '1':
			printf("ACK ");
			break;
		case '2':
			printf("U ");
			break;
		case '3':
			printf("ACK U ");
			break;
		case '4':
			printf("ECHO ");		
			break;
		case '5':
			printf("ECHO ACK ");
			break;
		case '6':
			printf("ECHO U ");
			break;
		case '7':
			printf("ECHO U ACK ");
			break;
		case '8':
			printf("CWR ");
			break;
		case '9':
			printf("CWR ACK ");
			break;
		case 'a':
		case 'A':
			printf("CWR U ");
			break;
		case 'b':
		case 'B':
			printf("CWR U ACK ");
			break;
		case 'c':
		case 'C':
			printf("CWR ECHO ");
			break;
		case 'd':
			case 'D':
			printf("CWR ECHO ACK ");
			break;
		case 'e':
		case 'E':
			printf("CWR ECHO U ");
			break;
		case 'f':
		case 'F':
			printf("CWR ECHO U ACK ");
			break;
	}
	
	if(s[0] == '1')
	{
			printf("NONCE ");
	}
	else if(s[0] > '0')
	{
			printf("RSVD ");
	}

		printf("] ");
}


void testcase(int index , int size)
{
	//printf("inside testcase");	
	int checkip=0 , checkdel =0 ,checkd ;
	strcpy(testname,input_arra[index]);
	checkip=check_ip(size);
	checkd=check_d(size);
	checkdel=check_delta(size);
	if(checkdel != -1)
	{
		//strcpy(ip," ");
		delta=0;		
		delta=atof(input_arra[checkdel]);
		//printf("delta is %f  \n",delta);	
	}
	else
	{
		delta=0.10;
		//printf("delta is %f we\n",delta);	
	}	
	if(checkd != -1)
	{
		//strcpy(ip," ");
		d_value=0;		
		d_value=atof(input_arra[checkd]);
		//printf("delta is %f  \n",delta);	
	}
	else
	{
		d_value=2;
		//printf("delta is %f we\n",delta);	
	}	

	if(checkip != 0)
	{
				
		strcpy(ip," ");
		strcpy(ip,input_arra[checkip]);
	}
	//printf("testcase name %s is  checking on ip = %s and ",testname, ip);	
	int checks=-1;
	checks=check_s(index,size);	
	if(checks != -1)
	{
		teststream=atoi(input_arra[checks]);
		//printf("stream number is %d  \n",teststream);	
		checks=teststream;	
		if(checks>node_count)
		{
			printf(" \t stream number entered is out of range ! \n ");
			return;
		}
	}
	
	if( !strcmp(testname,"FR") || !strcmp(testname,"fr"))	
	{
		
		 tc_fr(checks , checkip );

	}
	else if( !strcmp(testname,"RT") || !strcmp(testname,"rt"))
	{
			
				 tc_rt(checks , checkip);
	}
	else
	{

		printf("wrong test case name \n");
	}		

}

void tc_fr(int stm , int checkip )
{
	//printf("checking for %d nodecount %d \n",stm,node_count);
	int ni=1;
	char type[10];	
	if(stm == -1)
	{
		printf("checking on all the sreams \n");
		for(ni=1;ni<=node_count;ni++)
		{
				printf("\t\tstream number = %d \n",ni);
				printf("\tclient side FR \n");
				strcpy(type,"client");
				dofr(ni,type);				
				printf("\n\tserver sidee FR \n");				
				strcpy(type,"server");
				dofr(ni,type);				


		}
	}
	else
	{
				
		struct stream *stream_tst;	
		stream_tst=stream_head;
		while(stream_tst != NULL && stream_tst->st_no != stm)
		{
		//	printf("inside %d val%d or\n",stream_tst->st_no,stm);
			stream_tst=stream_tst->snext;
		}
	
		if(checkip >0)		
		{
			if(!strcmp(stream_tst->src_ip,ip))
			{
				printf("\t\tchecking for client side FR \n");		
				strcpy(type,"client");
				dofr(stm,type);				
			
			}			
			else
			{
				
				strcpy(type,"");							
				strcpy(type,"server");
			//	printf("inside %d val%d or\n",stream_head->st_no,stm);
				
				dofr(stm,type);
			}
		}
		else if(checkip < 0)
		{
				printf("\t\tchecking for server sidee FR \n\n\n");				
				strcpy(type,"server");
			
				//printf("inside %d val or\n",stream_head->st_no);				
				dofr(stm,type);				

				printf("\t\tchecking for client side FR \n");
				strcpy(type,"client");
				dofr(stm,type);				
				
		}					

	}	
	
}


void dofr(int stm, char* type[])
{
//	printf("checking for %d fr \n",stm);
	struct stream *stream_tst;
	struct packet *packet_tst;
	struct packet *packet_tst_print;
	int af_i=0 ,ch_i=0, found=0,i , countpaks=0 , flagprint;
	float fr_time=0;		
	for(i=0;i<200;i++)
	{			
		af_array[i].seq_no=0;
		af_array[i].ack_no=0;
		af_array[af_i].fre=0;				

	}
		//		printf("\ncheck\n");	
	
		stream_tst=stream_head;
		
		while(stream_tst != NULL && stream_tst->st_no != stm)
		{
		//	
			stream_tst=stream_tst->snext;
		}
		packet_tst=stream_tst->link;
		packet_tst_print=stream_tst->link;
		while(packet_tst != NULL )
		{
			found=0;
		
		//		printf("flgno is = %s and type is %s and rx is %s\n",packet_tst->flags,type,packet_tst->rx_num);		
			if((!strcmp(type,packet_tst->rx_num))&&(packet_tst->flags[4] == '1' || packet_tst->flags[4] == '3' || packet_tst->flags[4] == '7' || packet_tst->flags[4] == '9' || packet_tst->flags[4] == 'b' || packet_tst->flags[4] == 'B' || packet_tst->flags[4] == 'd' || packet_tst->flags[4] == 'D' || packet_tst->flags[4] == 'f' || packet_tst->flags[4] == 'F' )&&(packet_tst->flags[5] == '0' || packet_tst->flags[5] == '4' || packet_tst->flags[5] == '8' || packet_tst->flags[5] == 'c' ||packet_tst->flags[5] == 'C') )		
			{				
					//it is an ack			
				for(ch_i=0;ch_i<af_i;ch_i++)
				{
					if((af_array[ch_i].ack_no == packet_tst->acq_no)&&(af_array[ch_i].seq_no == packet_tst->seq_no))
					{
							
						//printf("updating  %d",af_array[ch_i].ack_no);
						if(af_array[ch_i].fre == 2)
						{
						
							strcpy(af_array[ch_i].ack3t,packet_tst->timestamp);
						}						
						af_array[ch_i].fre=af_array[ch_i].fre+1;
						found=1;
					}
				}
				if(found==0)
				{				
					strcpy(af_array[ch_i].ack1t,packet_tst->timestamp);
					af_array[af_i].seq_no=packet_tst->seq_no;		
					af_array[af_i].ack_no=packet_tst->acq_no;
					af_array[af_i].fre=1;				
		//	printf("ack= %d seq = %d and fre = %d \n",af_i,af_array[af_i].seq_no,af_array[af_i].fre);				
		
					af_i++;				
				}			
			}	
			packet_tst=packet_tst->next;		
		}
//		if(af_i>0)
		
		
		//printf("frqency are \n");
		for(ch_i=0;ch_i<af_i;ch_i++)
		{
//			printf("ack = %d seq + %dand fre = %d \n",af_array[ch_i].ack_no,af_array[ch_i].seq_no,af_array[ch_i].fre);
			int 	countpak=0;
			if(af_array[ch_i].fre >2)
			{
				if(d_value == 2)
				{	printf("\n\n\nack = %d seq = %dand fre = %d ",af_array[ch_i].ack_no,af_array[ch_i].seq_no,af_array[ch_i].fre);
					if(d_value ==2)
						printf("\n \t\t\t DupAcks \n");				
				}
				packet_tst_print=stream_tst->link;
//printing the dupacks			
	while(packet_tst_print != NULL )
				{

		if((af_array[ch_i].ack_no == packet_tst_print->acq_no)&&(af_array[ch_i].seq_no == packet_tst_print->seq_no))
		{
						if(d_value ==2)
						{
							printf("\t%s  ",packet_tst_print->timestamp);
							printf("seq=%d  ",packet_tst_print->seq_no);
							printf("acq=%d ",packet_tst_print->acq_no);
							printf("len=%d  ",packet_tst_print->hdr_len);
					
							printf("win=%d  ",packet_tst_print->win_size);
				
							//printf("scale=%d ",packet_tst->win_scale);
							//printf("nxt_seq=%d  ",packet_tst->nxt_seq);
							if(!strcmp(packet_tst_print->rx_num,"client"))			
							{
								printf("==>> ");			
							}	
							else if(!strcmp(packet_tst_print->rx_num,"server"))					{
							
								printf("<<== ");			
							}
								printf("\n");	
							}


		}
				packet_tst_print=packet_tst_print->next;

				}	
				flagprint=0;			
	//check for the packets with the next frequency ..shd b two packets
				//display 2 packets n all the acks
				packet_tst=stream_tst->link;
				while(packet_tst != NULL )
				{	
					if((packet_tst->seq_no == af_array[ch_i].ack_no)&&(packet_tst->acq_no == af_array[ch_i].seq_no)&&((atof(packet_tst->timestamp)>atof(af_array[ch_i].ack3t))))
					{	
						
						if(d_value == 2)
						{
							if(flagprint == 0)
							{	
								printf("\t\t\tTimestamp of 3rd DupAck : %s \n",af_array[ch_i].ack3t);
								flagprint=1;
							}				
							fr_time=atof(packet_tst->timestamp);
							printf("\tFR packe\n");						
							printf("\t%s  ",packet_tst->timestamp);
							printf("seq=%d  ",packet_tst->seq_no);
							printf("acq=%d ",packet_tst->acq_no);
							printf("len=%d  ",packet_tst->hdr_len);
					
							printf("win=%d  ",packet_tst->win_size);
				
							//printf("scale=%d ",packet_tst->win_scale);
							//printf("nxt_seq=%d  ",packet_tst->nxt_seq);
							if(!strcmp(packet_tst->rx_num,"client"))			
							{
								printf("==>> ");			
							}	
							else if(!strcmp(packet_tst->rx_num,"server"))					{
						
								printf("<<== ");			
							}
					  	}	
						countpak++;
															
					}
						packet_tst=packet_tst->next;
				
			}
					if(countpak == 1)
					{
						
						if(fr_time-atof(af_array[ch_i].ack3t)<0.01 && d_value == 2)
							printf("\n\tPASSED\n");
											
					}
					else if(countpak != 1)
					{
						
						if(d_value == 3)
						{
			
						
						printf("\n\n\nack = %d seq = %dand fre = %d \n",af_array[ch_i].ack_no,af_array[ch_i].seq_no,af_array[ch_i].fre);
						
						packet_tst_print=stream_tst->link;
						while(packet_tst_print != NULL )
						{
							
							if((af_array[ch_i].ack_no == packet_tst_print->acq_no)&&(af_array[ch_i].seq_no == packet_tst_print->seq_no))
							{
							printf("\t%s  ",packet_tst_print->timestamp);
							printf("seq=%d  ",packet_tst_print->seq_no);
							printf("acq=%d ",packet_tst_print->acq_no);
							printf("len=%d  ",packet_tst_print->hdr_len);
					
							printf("win=%d  ",packet_tst_print->win_size);
				
							//printf("scale=%d ",packet_tst->win_scale);
							//printf("nxt_seq=%d  ",packet_tst->nxt_seq);
							if(!strcmp(packet_tst_print->rx_num,"client"))			
							{
								printf("==>> ");			
							}	
							else if(!strcmp(packet_tst_print->rx_num,"server"))					{
							
								printf("<<== ");			
							}
								printf("\n");	
							
					}	

							packet_tst_print=packet_tst_print->next;
	
							
				

					}

						}
						printf("\n\t\FAILED\n");
						//printf("\n\t\t\t\tPASSED\n");
						
					}
		}				
	}
		
}

void tc_rt(int stm , int checkip)
{
	//printf("inside");	
	int ni=1;
	char type[10];	
	if(stm == -1)
	{
		printf("\n\t\t\tchecking on all the sreams\n");
		for(ni=0;ni<=node_count;ni++)
		{
				printf("\t\tstream number = %d \n",ni);
				printf("\tclient side RT \n");
				strcpy(type,"client");
				dort(ni,type,delta);				
				printf("\n\tserver sidee RT \n");				
				strcpy(type,"server");
				dort(ni,type,delta);				


		}
	}
	else
	{
				
		struct stream *stream_tst;	
		stream_tst=stream_head;
		while(stream_tst != NULL && stream_tst->st_no != stm)
		{
		//	printf("inside %d val%d or\n",stream_tst->st_no,stm);
			stream_tst=stream_tst->snext;
		}
	
		if(checkip >0)		
		{
			if(!strcmp(stream_tst->src_ip,ip))
			{
				printf("\t\tchecking for client side RT \n\n");		
				strcpy(type,"client");
				dort(stm,type,delta);				
			
			}			
			else
			{
					printf("\t\tchecking for client side RT \n");	
				strcpy(type,"");							
				strcpy(type,"server");
			//	printf("inside %d val%d or\n",stream_head->st_no,stm);
				
				dort(stm,type,delta);
			}
		}
		else if(checkip < 0)
		{
				printf("\t\tchecking for server sidee RT \n\n\n");				
				strcpy(type,"server");
			
				//printf("inside %d val or\n",stream_head->st_no);				
				dort(stm,type,delta);				

				printf("\t\tchecking for client side RT \n");
				strcpy(type,"client");
				dort(stm,type,delta);				
				
		}					

	}	
	


}

void dort(int stm, char* type[] , float delta)
{

	printf("\t\t\t\t\tdelta  %f \n",delta);	
	struct stream *stream_tst;
	struct packet *packet_tst1;
	struct packet *packet_tst2;
	int seq1 =0 ,seq2=0 , is=0 , ack1=0 , ack2 =0;
	float ts1=0 ,ts2=0;
	
	stream_tst=stream_head;
	while(stream_tst->st_no != stm)
	{
	//	
		stream_tst=stream_tst->snext;
	}
	
	packet_tst1=stream_tst->link;

	//printf("insdei %ddort \n",stream_tst->st_no);						
	//return;
	//char dir[20];
	int flag_pass=0;
	while(packet_tst1 != NULL && packet_tst1->next != NULL )	
	{
	
	//	strcpy(dir,"");			
		if(!strcmp(type,packet_tst1->rx_num))
		{
			seq1=packet_tst1->seq_no;
			ack1=packet_tst1->acq_no;
			if(packet_tst1->timestamp[0] == '-' )
			{
						
				for(is=0;is<(strlen(packet_tst1->timestamp)-2);is++)
					packet_tst1->timestamp[is]=packet_tst1->timestamp[is+1];
				ts1=atof(packet_tst1->timestamp);
				ts1=ts1*(-1);	
			}
			else			
				ts1=atof(packet_tst1->timestamp);
			
			packet_tst2=packet_tst1->next;
			//strcpy(dir,);
			flag_pass=0;	
			while(packet_tst2 != NULL && flag_pass == 0 )	
			{
				seq2=packet_tst2->seq_no;
				ack2=packet_tst2->acq_no;
				if(packet_tst2->timestamp[0] == '-' )
				{
					for(is=0;is<(strlen(packet_tst2->timestamp)-1);is++)
						packet_tst2->timestamp[is]=packet_tst2->timestamp[is+1];
					ts2=atof(packet_tst2->timestamp);
					ts2=ts2*(-1);	
				}
				else			
					ts2=atof(packet_tst2->timestamp);
				//	printf()
				if((ack1 == ack2)&&(seq1 == seq2) && ((ts2-ts1) >= delta) && !strcmp(type,packet_tst2->rx_num))			{						
																
							flag_pass=1;					
							printf("\n\t RTO t1= %f t2= %f \n  ",ts1,ts2);
							printf("\t%s  ",packet_tst1->timestamp);
							printf("seq=%d  ",packet_tst1->seq_no);
							printf("acq=%d ",packet_tst1->acq_no);
							printf("len=%d  ",packet_tst1->hdr_len);
						
							printf("win=%d  ",packet_tst1->win_size);
					
					//		printf("scale=%f and delta is %f",ts1,ts2);
							//printf("nxt_seq=%d  ",packet_tst->nxt_seq);
	
						if(!strcmp(packet_tst1->rx_num,"client"))			
							{
								printf("==>> ");			
							}	
					else if(!strcmp(packet_tst1->rx_num,"server"))				
					{
							
								printf("<<== ");			
							}
								
								printf("\n");
	
						
							printf("\t%s  ",packet_tst2->timestamp);
							printf("seq=%d  ",packet_tst2->seq_no);
							printf("acq=%d ",packet_tst2->acq_no);
							printf("len=%d  ",packet_tst2->hdr_len);
						
							printf("win=%d  ",packet_tst2->win_size);
					
							//printf("scale=%d ",packet_tst->win_scale);
							//printf("nxt_seq=%d  ",packet_tst->nxt_seq);
	
						if(!strcmp(packet_tst2->rx_num,"client"))			
							{
								printf("==>> ");			
							}	
					else if(!strcmp(packet_tst2->rx_num,"server"))				
					{
							
								printf("<<== ");			
					}
								
								printf("\n");
				
	
				}
				//if(flag_pass == 1)
				//	break;
				packet_tst2=packet_tst2->next;		
			}
		}
		packet_tst1=packet_tst1->next;
	}

}	
