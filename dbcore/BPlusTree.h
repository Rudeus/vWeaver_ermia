#ifndef __BPlusTree_H__
#define __BPlusTree_H__

#include "sm-common.h"

#define MAX_CHILD_NUMBER 129 //default 3200

#if defined(offsetof)
  #undef offsetof
  #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#else
  #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)

typedef struct BPlusTreeNode {
	int isRoot, isLeaf;
	int key_num;
	uint64_t key[MAX_CHILD_NUMBER];
	ermia::fat_ptr child[MAX_CHILD_NUMBER];
	struct BPlusTreeNode* father;
	struct BPlusTreeNode* next;
	struct BPlusTreeNode* last;
} BPlusTreeNode;

typedef struct BPlusTreeRoot {
	struct BplusTreeNode* node;
  bool lock;
} BPlusTreeRoot;

extern uint64_t TotalNodes;

void BPlusTree_SetMaxChildNumber(int);
void BPlusTree_Init();
void BPlusTree_Destroy();
int BPlusTree_Insert(BPlusTreeRoot*, uint64_t, ermia::fat_ptr);
int BPlusTree_GetTotalNodes();
void BPlusTree_Query_Key(int);
void BPlusTree_Query_Range(int, int);
void BPlusTree_Modify(int, void*);
void BPlusTree_Delete(int);

#endif
