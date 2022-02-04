#include <string.h>
#include <stdlib.h>
#include <stdio.h>


#define CAPACITY 1000



typedef struct Ht_item {
  char* key;
  int value;
}Ht_item;

typedef struct HashTable{
  Ht_item** items;
  int size;
  int count;
}HashTable;

unsigned long hash_function(char* str){
  unsigned long i = 0;
  for(int j=0; str[j];j++)
    i += str[j];
  return i % CAPACITY; 
}

Ht_item* create_item(char* key){
  Ht_item* item = (Ht_item*) malloc (sizeof(Ht_item));
  item->key = (char*) malloc (strlen(key)+1);
  item->value = 1;
  strcpy(item->key, key);
  return item;
}

HashTable* create_table(int size){
  HashTable* table = (HashTable*) malloc (sizeof(HashTable));
  table->size = size;
  table->count = 0;
  table->items = (Ht_item**) calloc (table->size, sizeof(Ht_item*));
  for (int i=0; i<table->size;i++)
    table->items[i] = NULL;
  return table;
}

void free_item(Ht_item* item){
  free(item->key);
  free(item);
}

void free_table(HashTable* table){
  for(int i=0; i<table->size;i++){
    Ht_item* item = table->items[i];
    if(item != NULL)
    free_item(item);
  }
  free(table->items);
  free(table);
}

void ht_order(HashTable* table){
  Ht_item* x = NULL;
  Ht_item* y = NULL;

  for(int i = 0; i<=table->size;i++){
  	x = table->items[i];
  	for(int j=0;j<=table->size;j++){
 		y = table->items[j];
  		if(x!=NULL && y!=NULL){
 			if(x->value>y->value){
  				Ht_item* item = table->items[i];
  				table->items[i] = table->items[j];
  				table->items[j] = item;
  					
  			}
 		}
  	}
    
  }	
}

void ht_insert(HashTable* table, char* key){
  Ht_item* item = create_item(key);
  unsigned long index = hash_function(key);
  Ht_item* current_item = table->items[index];
  int min = 1;
  if (current_item != NULL){
 	if(strcmp(current_item->key,key)==0){
      		table->items[index]->value++;
      	}
      	else{
      		while(table->items[index] != NULL){         //wrap around the table
      			++index;
      			index %= table->size;
      		}
      	}
    	if (table->count==table->size){
      		int j=0;
      		int i=0;
      		while(i<=table->size){                     //remove elements with less occurrences
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
    	
    	
  }
  else{
    while(table->items[index] != NULL){              //wrap around the table
      			++index;
      			index %= table->size;
 	}	
  	if (table->count==table->size){
      		int j=0;
      		int i=0;
      		while(i<=table->size){               //remove elements with less occurrences
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
    	table->items[index] = item;
    	table->count++;
    	
    	}
 	for (int i=0; i<table->size;i++)
 		if(table->items[i]!=NULL)
    			if(table->items[i]->value)
    				min = table->items[i]->value;
}



void print_table(HashTable* table){
  for(int i=0; i<table->size;i++){
    if(table->items[i])
      printf("%s    %d\n",table->items[i]->key, table->items[i]->value);
    
  }
}



