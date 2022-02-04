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

unsigned long hash_function(char* str);
  
Ht_item* create_item(char* key);

HashTable* create_table(int size);

void free_item(Ht_item* item);

void free_table(HashTable* table);

void ht_order(HashTable* table);
  

void handle_collision(HashTable* table, Ht_item* item);

void ht_insert(HashTable* table, char* key);

int ht_search(HashTable* table, char* key);

void print_table(HashTable* table);
