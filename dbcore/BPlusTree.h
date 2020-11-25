#ifndef __BPlusTree_H__
#define __BPlusTree_H__

#include "sm-common.h"

#define MAX_CHILD_NUMBER 128 //default 3200

#if defined(offsetof)
  #undef offsetof
  #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#else
  #define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

typedef struct BPlusTreeNode {
	int isRoot, isLeaf;
	int key_num;
	uint64_t key[MAX_CHILD_NUMBER]; // key: snapshot
	ermia::fat_ptr child[MAX_CHILD_NUMBER]; // value: object pointer
	struct BPlusTreeNode* father;
	struct BPlusTreeNode* next;
	struct BPlusTreeNode* last;
} BPlusTreeNode;

typedef struct BPlusTreeRoot {
	struct BPlusTreeNode* node;
  bool bpt_lock;

  inline void BPTreeLockAcquire() {
    while (__sync_lock_test_and_set(&bpt_lock, true)) {
      pthread_yield();
    }
  }
  inline void BPTreeLockRelease() {
    bpt_lock = false;
    __sync_synchronize();
  }
} BPlusTreeRoot;

extern uint64_t TotalNodes;
extern void BPT_deallocate(void *p);
void BPlusTree_SetMaxChildNumber(int);
BPlusTreeRoot *BPlusTree_Init();
void BPlusTree_Destroy();
int BPlusTree_Insert(BPlusTreeRoot*, uint64_t, ermia::fat_ptr);
int BPlusTree_GetTotalNodes();
void BPlusTree_Query_Key(int);
void BPlusTree_Query_Range(int, int);
void BPlusTree_Modify(int, void*);
void BPlusTree_Delete(int);

#endif
