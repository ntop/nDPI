# Relazione 

My work focused on modifying the ndpireader file so that it would print an addition of statistics on the flows collected by the program. To do this I first of all created the hashStats.c file where I implemented the basic hash operations. The insert function where harvesting is done is very important: 
if (table->count==table->size){
      		int j=0;
      		int i=0;
      		while(i<=table->size){
      			if(table->items[i]!=NULL){
      				if(table->items[i]->value<min)
				free_item(table->items[i]);
				table->items[i] = NULL;
				j++;
				if (j>=10)
					break;
			}				
			i++;
		} 
 }

that is, the less frequent elements in the table are eliminated. 

As for the ndpiReader file, I first included the file myhash.h header file for the hashStats.c file. 
#include "myhash.h"

Finally I modified the printFlowStats () function, where I added this code

if(verbose == 4){
      HashTable* table;
      table = create_table(CAPACITY);
      if (table == NULL)
	        printf("errore tabella\n");
      
      for(i = 0; i< num_flows; i++){
	      if(all_flows[i].flow->ssh_tls.server_info[0] != '0'){
	          ht_insert(table,all_flows[i].flow->ssh_tls.server_info);
	       }

	       if(all_flows[i].flow->host_server_name[0] != '0'){
	           ht_insert(table,all_flows[i].flow->host_server_name);
	       }
      }   
      ht_order(table);
    
      print_table(table);
      free_table(table);

}


I added option 4 to the -v argument to see the results of the hash table, as well as the statistics printed by the printRiskStats function.
After compiling the hashStats file, to run ndpiReader I ran the terminal command ./nDPI/example/ndpiReader -i ../tests/pcap/KakaoTalk_chat.pcap -v 4 
