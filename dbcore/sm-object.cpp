#include "sm-object.h"
#include "../tuple.h"
#include "sm-alloc.h"
#include "sm-chkpt.h"
#include "sm-log-recover.h"
#include "sm-log.h"

namespace ermia {

#ifdef HYU_RBTREE /* HYU_RBTREE */
/*
 * =============================================================================
 *
 *       Filename:  rbtree.c
 *
 *    Description:  rbtree(Red-Black tree) implementation adapted from linux
 *                  kernel thus can be used in userspace c program.
 *
 *        Created:  09/02/2012 11:38:12 PM
 *
 *         Author:  Fu Haiping (forhappy), haipingf@gmail.com
 *        Company:  ICT ( Institute Of Computing Technology, CAS )
 *
 * =============================================================================
 */

/*
  Red Black Trees
  (C) 1999  Andrea Arcangeli <andrea@suse.de>
  (C) 2002  David Woodhouse <dwmw2@infradead.org>
  
  This program is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  This program is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, write to the Free Software
  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

  linux/lib/rbtree.c
*/

static void __rb_rotate_left(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *right = node->rb_right;
	struct rb_node *parent = rb_parent(node);

	if ((node->rb_right = right->rb_left))
		rb_set_parent(right->rb_left, node);
	right->rb_left = node;

	rb_set_parent(right, parent);

	if (parent)
	{
		if (node == parent->rb_left)
			parent->rb_left = right;
		else
			parent->rb_right = right;
	}
	else
		root->rb_node = right;
	rb_set_parent(node, right);
}

static void __rb_rotate_right(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *left = node->rb_left;
	struct rb_node *parent = rb_parent(node);

	if ((node->rb_left = left->rb_right))
		rb_set_parent(left->rb_right, node);
	left->rb_right = node;

	rb_set_parent(left, parent);

	if (parent)
	{
		if (node == parent->rb_right)
			parent->rb_right = left;
		else
			parent->rb_left = left;
	}
	else
		root->rb_node = left;
	rb_set_parent(node, left);
}

void rb_insert_color(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *parent, *gparent;

	while ((parent = rb_parent(node)) && rb_is_red(parent))
	{
		gparent = rb_parent(parent);

		if (parent == gparent->rb_left)
		{
			{
				register struct rb_node *uncle = gparent->rb_right;
				if (uncle && rb_is_red(uncle))
				{
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}

			if (parent->rb_right == node)
			{
				register struct rb_node *tmp;
				__rb_rotate_left(parent, root);
				tmp = parent;
				parent = node;
				node = tmp;
			}

			rb_set_black(parent);
			rb_set_red(gparent);
			__rb_rotate_right(gparent, root);
		} else {
			{
				register struct rb_node *uncle = gparent->rb_left;
				if (uncle && rb_is_red(uncle))
				{
					rb_set_black(uncle);
					rb_set_black(parent);
					rb_set_red(gparent);
					node = gparent;
					continue;
				}
			}

			if (parent->rb_left == node)
			{
				register struct rb_node *tmp;
				__rb_rotate_right(parent, root);
				tmp = parent;
				parent = node;
				node = tmp;
			}

			rb_set_black(parent);
			rb_set_red(gparent);
			__rb_rotate_left(gparent, root);
		}
	}

	rb_set_black(root->rb_node);
}

static void __rb_erase_color(struct rb_node *node, struct rb_node *parent,
			     struct rb_root *root)
{
	struct rb_node *other;

	while ((!node || rb_is_black(node)) && node != root->rb_node)
	{
		if (parent->rb_left == node)
		{
			other = parent->rb_right;
			if (rb_is_red(other))
			{
				rb_set_black(other);
				rb_set_red(parent);
				__rb_rotate_left(parent, root);
				other = parent->rb_right;
			}
			if ((!other->rb_left || rb_is_black(other->rb_left)) &&
			    (!other->rb_right || rb_is_black(other->rb_right)))
			{
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else
			{
				if (!other->rb_right || rb_is_black(other->rb_right))
				{
					rb_set_black(other->rb_left);
					rb_set_red(other);
					__rb_rotate_right(other, root);
					other = parent->rb_right;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->rb_right);
				__rb_rotate_left(parent, root);
				node = root->rb_node;
				break;
			}
		}
		else
		{
			other = parent->rb_left;
			if (rb_is_red(other))
			{
				rb_set_black(other);
				rb_set_red(parent);
				__rb_rotate_right(parent, root);
				other = parent->rb_left;
			}
			if ((!other->rb_left || rb_is_black(other->rb_left)) &&
			    (!other->rb_right || rb_is_black(other->rb_right)))
			{
				rb_set_red(other);
				node = parent;
				parent = rb_parent(node);
			}
			else
			{
				if (!other->rb_left || rb_is_black(other->rb_left))
				{
					rb_set_black(other->rb_right);
					rb_set_red(other);
					__rb_rotate_left(other, root);
					other = parent->rb_left;
				}
				rb_set_color(other, rb_color(parent));
				rb_set_black(parent);
				rb_set_black(other->rb_left);
				__rb_rotate_right(parent, root);
				node = root->rb_node;
				break;
			}
		}
	}
	if (node)
		rb_set_black(node);
}

void rb_erase(struct rb_node *node, struct rb_root *root)
{
	struct rb_node *child, *parent;
	int color;

	if (!node->rb_left)
		child = node->rb_right;
	else if (!node->rb_right)
		child = node->rb_left;
	else
	{
		struct rb_node *old = node, *left;

		node = node->rb_right;
		while ((left = node->rb_left) != NULL)
			node = left;

		if (rb_parent(old)) {
			if (rb_parent(old)->rb_left == old)
				rb_parent(old)->rb_left = node;
			else
				rb_parent(old)->rb_right = node;
		} else
			root->rb_node = node;

		child = node->rb_right;
		parent = rb_parent(node);
		color = rb_color(node);

		if (parent == old) {
			parent = node;
		} else {
			if (child)
				rb_set_parent(child, parent);
			parent->rb_left = child;

			node->rb_right = old->rb_right;
			rb_set_parent(old->rb_right, node);
		}

		node->rb_parent_color = old->rb_parent_color;
		node->rb_left = old->rb_left;
		rb_set_parent(old->rb_left, node);

		goto color;
	}

	parent = rb_parent(node);
	color = rb_color(node);

	if (child)
		rb_set_parent(child, parent);
	if (parent)
	{
		if (parent->rb_left == node)
			parent->rb_left = child;
		else
			parent->rb_right = child;
	}
	else
		root->rb_node = child;

 color:
	if (color == RB_BLACK)
		__rb_erase_color(child, parent, root);
}

static void rb_augment_path(struct rb_node *node, rb_augment_f func, void *data)
{
	struct rb_node *parent;

up:
	func(node, data);
	parent = rb_parent(node);
	if (!parent)
		return;

	if (node == parent->rb_left && parent->rb_right)
		func(parent->rb_right, data);
	else if (parent->rb_left)
		func(parent->rb_left, data);

	node = parent;
	goto up;
}

/*
 * after inserting @node into the tree, update the tree to account for
 * both the new entry and any damage done by rebalance
 */
void rb_augment_insert(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node->rb_left)
		node = node->rb_left;
	else if (node->rb_right)
		node = node->rb_right;

	rb_augment_path(node, func, data);
}

/*
 * before removing the node, find the deepest node on the rebalance path
 * that will still be there after @node gets removed
 */
struct rb_node *rb_augment_erase_begin(struct rb_node *node)
{
	struct rb_node *deepest;

	if (!node->rb_right && !node->rb_left)
		deepest = rb_parent(node);
	else if (!node->rb_right)
		deepest = node->rb_left;
	else if (!node->rb_left)
		deepest = node->rb_right;
	else {
		deepest = rb_next(node);
		if (deepest->rb_right)
			deepest = deepest->rb_right;
		else if (rb_parent(deepest) != node)
			deepest = rb_parent(deepest);
	}

	return deepest;
}

/*
 * after removal, update the tree to account for the removed entry
 * and any rebalance damage.
 */
void rb_augment_erase_end(struct rb_node *node, rb_augment_f func, void *data)
{
	if (node)
		rb_augment_path(node, func, data);
}

/*
 * This function returns the first node (in sort order) of the tree.
 */
struct rb_node *rb_first(const struct rb_root *root)
{
	struct rb_node	*n;

	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_left)
		n = n->rb_left;
	return n;
}

struct rb_node *rb_last(const struct rb_root *root)
{
	struct rb_node	*n;

	n = root->rb_node;
	if (!n)
		return NULL;
	while (n->rb_right)
		n = n->rb_right;
	return n;
}

struct rb_node *rb_next(const struct rb_node *node)
{
	struct rb_node *parent;

	if (rb_parent(node) == node)
		return NULL;

	/* If we have a right-hand child, go down and then left as far
	   as we can. */
	if (node->rb_right) {
		node = node->rb_right; 
		while (node->rb_left)
			node=node->rb_left;
		return (struct rb_node *)node;
	}

	/* No right-hand children.  Everything down and left is
	   smaller than us, so any 'next' node must be in the general
	   direction of our parent. Go up the tree; any time the
	   ancestor is a right-hand child of its parent, keep going
	   up. First time it's a left-hand child of its parent, said
	   parent is our 'next' node. */
	while ((parent = rb_parent(node)) && node == parent->rb_right)
		node = parent;

	return parent;
}

struct rb_node *rb_prev(const struct rb_node *node)
{
	struct rb_node *parent;

	if (rb_parent(node) == node)
		return NULL;

	/* If we have a left-hand child, go down and then right as far
	   as we can. */
	if (node->rb_left) {
		node = node->rb_left; 
		while (node->rb_right)
			node=node->rb_right;
		return (struct rb_node *)node;
	}

	/* No left-hand children. Go up till we find an ancestor which
	   is a right-hand child of its parent */
	while ((parent = rb_parent(node)) && node == parent->rb_left)
		node = parent;

	return parent;
}

void rb_replace_node(struct rb_node *victim, struct rb_node *new_node,
		     struct rb_root *root)
{
	struct rb_node *parent = rb_parent(victim);

	/* Set the surrounding nodes to point to the replacement */
	if (parent) {
		if (victim == parent->rb_left)
			parent->rb_left = new_node;
		else
			parent->rb_right = new_node;
	} else {
		root->rb_node = new_node;
	}
	if (victim->rb_left)
		rb_set_parent(victim->rb_left, new_node);
	if (victim->rb_right)
		rb_set_parent(victim->rb_right, new_node);

	/* Copy the pointers/colour from the victim to the replacement */
	*new_node = *victim;
}
#endif /* HYU_RBTREE */

#ifdef HYU_BPTREE /* HYU_BPTREE */
#define true 1
#define false 0

int MaxChildNumber = 128;
uint64_t TotalNodes;

int QueryAnsNum;

/** Create a new B+tree Node */
BPlusTreeNode* New_BPlusTreeNode() {
  size_t size_node = sizeof(BPlusTreeNode);
	BPlusTreeNode* p = (BPlusTreeNode*)MM::allocate(size_node);
	p->isRoot = false;
	p->isLeaf = false;
	p->key_num = 0;
	p->child[0] = NULL_PTR;
	p->father = NULL;
	p->next = NULL;
	p->last = NULL;
	TotalNodes++;
	return p;
}

/** Create a new B+tree Root */
BPlusTreeRoot* New_BPlusTreeRoot() {
  size_t size_root = sizeof(BPlusTreeRoot);
	BPlusTreeRoot* r = (BPlusTreeRoot*)MM::allocate(size_root);
	size_t size_node = sizeof(BPlusTreeNode);
	BPlusTreeNode* p = (BPlusTreeNode*)MM::allocate(size_node);
	p->isRoot = false;
	p->isLeaf = false;
	p->key_num = 0;
	p->child[0] = NULL_PTR;
	p->father = NULL;
	p->next = NULL;
	p->last = NULL;
	r->node = p;
	r->bpt_lock = false;
	TotalNodes++;
	return r;
}

void BPT_deallocate(void *p) {
  size_t size = sizeof(struct BPlusTreeNode);
  size_t size_code = encode_size_aligned(size);
  MM::deallocate_bpt(fat_ptr::make(p, size_code));
}

/** Binary search to find the biggest child l that Cur->key[l] <= key */
int Binary_Search(BPlusTreeNode* Cur, uint64_t key) {
	int l = 0, r = Cur->key_num;
	if (key < Cur->key[l]) return l;
	if (Cur->key[r - 1] <= key) return r - 1;
	while (l < r - 1) {
		int mid = (l + r) >> 1;
		if (Cur->key[mid] > key)
			r = mid;
		else
			l = mid;
	}
	return l;
}

/**
 * Cur(MaxChildNumber) split into two part:
 *	(1) Cur(0 .. Mid - 1) with original key
 *	(2) Temp(Mid .. MaxChildNumber) with key[Mid]
 * where Mid = MaxChildNumber / 2
 * Note that only when Split() is called, a new Node is created
 */
//void Insert(BPlusTreeNode*, int64_t, fat_ptr, BPlusTreeRoot*);
void Split(BPlusTreeNode* Cur, BPlusTreeRoot* Root) {
	// copy Cur(Mid .. MaxChildNumber) -> Temp(0 .. Temp->key_num)
	BPlusTreeNode* Temp = New_BPlusTreeNode();
	BPlusTreeNode* ch;
	int Mid = MaxChildNumber >> 1;
	Temp->isLeaf = Cur->isLeaf; // Temp's depth == Cur's depth
	Temp->key_num = MaxChildNumber - Mid;
	int i;
	for (i = Mid; i < MaxChildNumber; i++) {
		Temp->child[i - Mid] = Cur->child[i];
		Temp->key[i - Mid] = Cur->key[i];
		if (Temp->isLeaf) {
			//Temp->pos[i - Mid] = Cur->pos[i];
		} else {
			ch = (BPlusTreeNode*)Temp->child[i - Mid].offset();
			ch->father = Temp;
		}
	}
	// Change Cur
	Cur->key_num = Mid;
	// Insert Temp
	if (Cur->isRoot) {
		// Create a new Root, the depth of Tree is increased
		BPlusTreeNode *new_root = New_BPlusTreeNode();
    size_t size_node = sizeof(BPlusTreeNode);
    size_t size_code = encode_size_aligned(size_node);
		new_root->key_num = 2;
		new_root->isRoot = true;
		new_root->key[0] = Cur->key[0];
		new_root->child[0] = fat_ptr::make(Cur, size_code, 0);
		new_root->key[1] = Temp->key[0];
		new_root->child[1] = fat_ptr::make(Temp, size_code, 0);
		Cur->father = Temp->father = new_root;
		Cur->isRoot = false;
		Root->node = new_root;

		if (Cur->isLeaf) {
			Cur->next = Temp;
			Temp->last = Cur;
		}
	} else {
		// Try to insert Temp to Cur->father
		Temp->father = Cur->father;
    size_t size_node = sizeof(BPlusTreeNode);
    size_t size_code = encode_size_aligned(size_node);
		Insert(Cur->father, Cur->key[Mid], fat_ptr::make(Temp, size_code, 0), Root);
	}
}

/** Insert (key, value) into Cur, if Cur is full, then split it to fit the definition of B+tree */
void Insert(BPlusTreeNode* Cur, uint64_t key, fat_ptr value, BPlusTreeRoot* Root) {
	int i, ins;
	//if (key < Cur->key[0]) ins = 0; else ins = Binary_Search(Cur, key) + 1;
	//for (i = Cur->key_num; i > ins; i--) {
		//Cur->key[i] = Cur->key[i - 1];
		//Cur->child[i] = Cur->child[i - 1];
	//}
	ins = Cur->key_num;
	Cur->key_num++;
	Cur->key[ins] = key;
	Cur->child[ins] = value;
	if (Cur->isLeaf == false) { // make links on leaves
		BPlusTreeNode* firstChild = (BPlusTreeNode*)(Cur->child[0].offset());
		if (firstChild->isLeaf == true) { // which means value is also a leaf as child[0]	
			BPlusTreeNode* temp = (BPlusTreeNode*)(value.offset());
			if (ins > 0) {
				BPlusTreeNode* prevChild;
				BPlusTreeNode* succChild;
				prevChild = (BPlusTreeNode*)Cur->child[ins - 1].offset();
				succChild = prevChild->next;
				prevChild->next = temp;
				temp->next = succChild;
				temp->last = prevChild;
				if (succChild != NULL) succChild->last = temp;
			} else {
				// do not have a prevChild, then refer next directly
				// updated: the very first record on B+tree, and will not come to this case
				temp->next = (BPlusTreeNode *)Cur->child[1].offset();
				//printf("this happens\n");
			}
		}
	}
	if (Cur->key_num == MaxChildNumber) // children is full
		Split(Cur, Root);
}

/** Resort(Give, Get) make their no. of children average */
void Resort(BPlusTreeNode* Left, BPlusTreeNode* Right) {
	int total = Left->key_num + Right->key_num;
	BPlusTreeNode* temp;
	if (Left->key_num < Right->key_num) {
		int leftSize = total >> 1;
		int i = 0, j = 0;
		while (Left->key_num < leftSize) {
			Left->key[Left->key_num] = Right->key[i];
			Left->child[Left->key_num] = Right->child[i];
			if (!Left->isLeaf) {
				temp = (BPlusTreeNode*)Right->child[i].offset();
				temp->father = Left;
			}
			Left->key_num++;
			i++;
		}
		while (i < Right->key_num) {
			Right->key[j] = Right->key[i];
			Right->child[j] = Right->child[i];
			i++;
			j++;
		}
		Right->key_num = j; 
	} else {
		int leftSize = total >> 1;
		int i, move = Left->key_num - leftSize, j = 0;
		for (i = Right->key_num - 1; i >= 0; i--) {
			Right->key[i + move] = Right->key[i];
			Right->child[i + move] = Right->child[i];
		}
		for (i = leftSize; i < Left->key_num; i++) {
			Right->key[j] = Left->key[i];
			Right->child[j] = Left->child[i];
			if (!Right->isLeaf) {
				temp = (BPlusTreeNode*)Left->child[i].offset();
				temp->father = Right;
			}
			j++;
		}
		Left->key_num = leftSize;
		Right->key_num = total - leftSize;
	}
}

/**
 * Redistribute Cur, using following strategy:
 * (1) resort with right brother
 * (2) resort with left brother
 * (3) merge with right brother
 * (4) merge with left brother
 * in that case root has only one child, set this chil to be root
 */
void Redistribute(BPlusTreeRoot* Root, BPlusTreeNode* Cur) {
	if (Cur->isRoot) {
		if (Cur->key_num == 1 && !Cur->isLeaf) {
			Root->node = Cur->child[0];
			Root->node->isRoot = true;
			BPT_deallocate(Cur);
			//free(Cur);
		}
		return;
	}
	BPlusTreeNode* Father = Cur->father;
	BPlusTreeNode* prevChild;
	BPlusTreeNode* succChild;
	BPlusTreeNode* temp;
	int my_index = Binary_Search(Father, Cur->key[0]);
	if (my_index + 1 < Father->key_num) {
		succChild = (BPlusTreeNode *)Father->child[my_index + 1].offset();
		if ((succChild->key_num - 1) * 2 >= MaxChildNumber) { // at least can move one child to Cur
			Resort(Cur, succChild); // (1) resort with right child
			Father->key[my_index + 1] = succChild->key[0];
			return;
		}
	}
	if (my_index - 1 >= 0) {
		prevChild = (BPlusTreeNode *)Father->child[my_index - 1].offset();
		if ((prevChild->key_num - 1) * 2 >= MaxChildNumber) {
			Resort(prevChild, Cur); // (2) resort with left child
			Father->key[my_index] = Cur->key[0];
			return;
		}
	}
	if (my_index + 1 < Father->key_num) { // (3) merge with right child
		int i = 0;
		while (i < succChild->key_num) {
			Cur->key[Cur->key_num] = succChild->key[i];
			Cur->child[Cur->key_num] = succChild->child[i];
			if (!Cur->isLeaf) {
				temp = (BPlusTreeNode*)succChild->child[i].offset();
				temp->father = Cur;
			}
			Cur->key_num++;
			i++;
		}
		Delete(Root, Father, succChild->key[0]); // delete right child
		return;
	}
	if (my_index - 1 >= 0) { // (4) merge with left child
		int i = 0;
		while (i < Cur->key_num) {
			prevChild->key[prevChild->key_num] = Cur->key[i];
			prevChild->child[prevChild->key_num] = Cur->child[i];
			if (!Cur->isLeaf) {
				temp = (BPlusTreeNode*)Cur->child[i].offset();
				temp->father = prevChild;
			}
			prevChild->key_num++;
			i++;
		}
		Delete(Root, Father, Cur->key[0]); // delete left child
		return;
	}
	printf("What?! you're the only child???\n"); // this won't happen
}

/** Delete Rightmost key */
void Delete_Rightmost(BPlusTreeRoot* Root) {
  // find code start
  BPlusTreeNode* Cur = Root->node;
  fat_ptr temp_cur = NULL_PTR;
  while (1) {
    if (Cur->isLeaf == true)
      break;
    temp_cur = Cur->child[Cur->key_num - 1];
    Cur = (BPlusTreeNode *)temp_cur.offset();
  }
	// find code end

  int del = Cur->key_num - 1;
  int i;
	fat_ptr delChild_fat = Cur->child[del];
  BPlusTreeNode* delChild = (BPlusTreeNode *)delChild_fat.offset();
	for (i = del; i < Cur->key_num - 1; i++) {
		Cur->key[i] = Cur->key[i + 1];
		Cur->child[i] = Cur->child[i + 1];
	}
	Cur->key_num--;
	if (Cur->isLeaf == false) { // make links on leaves
		BPlusTreeNode* firstChild = (BPlusTreeNode*)(Cur->child[0].offset());
		if (firstChild->isLeaf == true) { // which means delChild is also a leaf
			BPlusTreeNode* temp = delChild;
			BPlusTreeNode* prevChild = temp->last;
			BPlusTreeNode* succChild = temp->next;
			if (prevChild != NULL) prevChild->next = succChild;
			if (succChild != NULL) succChild->last = prevChild;
		}
	}
	if (del == 0 && !Cur->isRoot) { // some fathers' key should be changed
		BPlusTreeNode* temp = Cur;
		while (!temp->isRoot && temp == (BPlusTreeNode *)temp->father->child[0].offset()) {
			temp->father->key[0] = Cur->key[0];
			temp = temp->father;
		}
		if (!temp->isRoot) {
			temp = temp->father;
			int i = Binary_Search(temp, Cur->key[0]);
			temp->key[i] = Cur->key[0];
		}
	}
	BPT_deallocate(delChild);
	//free(delChild);
	if (Cur->key_num * 2 < MaxChildNumber)
		Redistribute(Root, Cur);
}

/** Delete key from Cur, if no. of children < MaxChildNUmber / 2, resort or merge it with brothers */
void Delete(BPlusTreeRoot* Root, BPlusTreeNode* Cur, uint64_t key) {
	int i, del = Binary_Search(Cur, key);
	BPlusTreeNode* delChild = (BPlusTreeNode *)Cur->child[del].offset();
	for (i = del; i < Cur->key_num - 1; i++) {
		Cur->key[i] = Cur->key[i + 1];
		Cur->child[i] = Cur->child[i + 1];
	}
	Cur->key_num--;
	if (Cur->isLeaf == false) { // make links on leaves
		BPlusTreeNode* firstChild = (BPlusTreeNode*)Cur->child[0].offset();
		if (firstChild->isLeaf == true) { // which means delChild is also a leaf
			BPlusTreeNode* temp = (BPlusTreeNode*)delChild;
			BPlusTreeNode* prevChild = temp->last;
			BPlusTreeNode* succChild = temp->next;
			if (prevChild != NULL) prevChild->next = succChild;
			if (succChild != NULL) succChild->last = prevChild;
		}
	}
	if (del == 0 && !Cur->isRoot) { // some fathers' key should be changed
		BPlusTreeNode* temp = Cur;
		while (!temp->isRoot && temp == (BPlusTreeNode *)temp->father->child[0].offset()) {
			temp->father->key[0] = Cur->key[0];
			temp = temp->father;
		}
		if (!temp->isRoot) {
			temp = temp->father;
			int i = Binary_Search(temp, key);
			temp->key[i] = Cur->key[0];
		}
	}
	BPT_deallocate(delChild);
	//free(delChild);
	if (Cur->key_num * 2 < MaxChildNumber)
		Redistribute(Root, Cur);
}


/** Find a leaf node that key lays in it
 *	modify indicates whether key should affect the tree
 */
BPlusTreeNode* Find(BPlusTreeRoot *Root, uint64_t key, int modify) {
	BPlusTreeNode* Cur = Root->node;
  fat_ptr temp_cur = NULL_PTR;
	while (1) {
		if (Cur->isLeaf == true)
			break;
		if (key < Cur->key[0]) {
			if (modify == true) Cur->key[0] = key;
			temp_cur = Cur->child[0];
			Cur = (BPlusTreeNode *)temp_cur.offset();
		} else {
			int i = Binary_Search(Cur, key);
			temp_cur = Cur->child[i];
			Cur = (BPlusTreeNode *)temp_cur.offset();
		}
	}
	return Cur;
}

/** Destroy subtree whose root is Cur, By recursion */
void Destroy(BPlusTreeNode* Cur) {
	if (Cur->isLeaf == true) {
		//int i;
		//for (i = 0; i < Cur->key_num; i++)
			//free(Cur->child[i]);
	} else {
		int i;
		for (i = 0; i < Cur->key_num; i++)
			Destroy(Cur->child[i]);
	}
	BPT_deallocate(Cur);
	//free(Cur);
}

/** Interface: Insert (key, value) into B+tree */
int BPlusTree_Insert(BPlusTreeRoot *Root, uint64_t key, fat_ptr value) {
	BPlusTreeNode* Leaf = Find(Root, key, true);
	//int i = Binary_Search(Leaf, key);
	//if (Leaf->key[i] == key) return false;
	Insert(Leaf, key, value, Root);
	return true;
}

/** Interface: Initialize */
BPlusTreeRoot *BPlusTree_Init() {
	//BPlusTree_Destroy();
	BPlusTreeRoot *Root = New_BPlusTreeRoot();
	Root->node->isRoot = true;
	Root->node->isLeaf = true;
	TotalNodes = 0;

	return Root;
}

#endif /* HYU_BPTREE */

// Dig out the payload from the durable log
// ptr should point to some position in the log and its size_code should refer
// to only data size (i.e., the size of the payload of dbtuple rounded up).
// Returns a fat_ptr to the object created
void Object::Pin(bool load_from_logbuf) {
  uint32_t status = volatile_read(status_);
  if (status != kStatusStorage) {
    if (status == kStatusLoading) {
      while (volatile_read(status_) != kStatusMemory) {
      }
    }
    ALWAYS_ASSERT(volatile_read(status_) == kStatusMemory ||
                  volatile_read(status_) == kStatusDeleted);
    return;
  }

  // Try to 'lock' the status
  // TODO(tzwang): have the thread do something else while waiting?
  uint32_t val =
      __sync_val_compare_and_swap(&status_, kStatusStorage, kStatusLoading);
  if (val == kStatusMemory) {
    return;
  } else if (val == kStatusLoading) {
    while (volatile_read(status_) != kStatusMemory) {
    }
    return;
  } else {
    ASSERT(val == kStatusStorage);
    ASSERT(volatile_read(status_) == kStatusLoading);
  }

  uint32_t final_status = kStatusMemory;

  // Now we can load it from the durable log
  ALWAYS_ASSERT(pdest_.offset());
  uint16_t where = pdest_.asi_type();
  ALWAYS_ASSERT(where == fat_ptr::ASI_LOG || where == fat_ptr::ASI_CHK);

  // Already pre-allocated space when creating the object
  dbtuple *tuple = (dbtuple *)GetPayload();
  new (tuple) dbtuple(0);  // set the correct size later

  size_t data_sz = decode_size_aligned(pdest_.size_code());
  if (where == fat_ptr::ASI_LOG) {
    ASSERT(logmgr);
    // Not safe to dig out from the log buffer as it might be receiving a
    // new batch from the primary, unless we have NVRAM as log buffer.
    // XXX(tzwang): for now we can't flush - need coordinate with backup daemon
    if (config::is_backup_srv() && !config::nvram_log_buffer) {
      while (pdest_.offset() >= logmgr->durable_flushed_lsn().offset()) {
      }
    }

    // Load tuple varstr from the log
    if (load_from_logbuf) {
      logmgr->load_object_from_logbuf((char *)tuple->get_value_start(), data_sz,
                                      pdest_);
    } else {
      logmgr->load_object((char *)tuple->get_value_start(), data_sz, pdest_);
    }
    // Strip out the varstr stuff
    tuple->size = ((varstr *)tuple->get_value_start())->size();
    // Fill in the overwritten version's pdest if needed
    if (config::is_backup_srv() && next_pdest_ == NULL_PTR) {
      next_pdest_ = ((varstr *)tuple->get_value_start())->ptr;
    }
    // Could be a delete
    ASSERT(tuple->size < data_sz);
    if (tuple->size == 0) {
      final_status = kStatusDeleted;
      ASSERT(next_pdest_.offset());
    }
    memmove(tuple->get_value_start(),
            (char *)tuple->get_value_start() + sizeof(varstr), tuple->size);
    SetClsn(LSN::make(pdest_.offset(), 0).to_log_ptr());
    ALWAYS_ASSERT(pdest_.offset() == clsn_.offset());
  } else {
    // Load tuple data form the chkpt file
    ASSERT(sm_chkpt_mgr::base_chkpt_fd);
    ALWAYS_ASSERT(pdest_.offset());
    ASSERT(volatile_read(status_) == kStatusLoading);
    // Skip the status_ and alloc_epoch_ fields
    static const uint32_t skip = sizeof(status_) + sizeof(alloc_epoch_);
    uint32_t read_size = data_sz - skip;
    auto n = os_pread(sm_chkpt_mgr::base_chkpt_fd, (char *)this + skip,
                      read_size, pdest_.offset() + skip);
    ALWAYS_ASSERT(n == read_size);
    ASSERT(tuple->size <= read_size - sizeof(dbtuple));
    next_pdest_ = NULL_PTR;
  }
  ASSERT(clsn_.asi_type() == fat_ptr::ASI_LOG);
  ALWAYS_ASSERT(pdest_.offset());
  ALWAYS_ASSERT(clsn_.offset());
  ASSERT(volatile_read(status_) == kStatusLoading);
  SetStatus(final_status);
}

#ifdef HYU_SKIPLIST /* HYU_SKIPLIST */
void Object::AllocLvPointer() {
  if (this->GetLv() == 1) {
    lv_pointer_ = NULL_PTR;
  } else {
    size_t size = sizeof(fat_ptr) * (this->GetLv() - 1);
    fat_ptr *lv_pointer = (fat_ptr *)MM::allocate(size);
    size_t size_code = encode_size_aligned(size);
    ASSERT(size_code != INVALID_SIZE_CODE);
    this->lv_pointer_ = fat_ptr::make(lv_pointer, size_code, 0);
  }
}
#endif /* HYU_SKIPLIST */

fat_ptr Object::Create(const varstr *tuple_value, bool do_write,
                       epoch_num epoch) {
  if (tuple_value) {
    do_write = true;
  }

  // Calculate tuple size
  const uint32_t data_sz = tuple_value ? tuple_value->size() : 0;
  /*uint32_t data_sz = tuple_value ? tuple_value->size() : 0;
#ifdef HYU_MOTIVATION
        if (tuple_value && (tuple_value->data() == (uint8_t*)0x4 ||
                                tuple_value->data() == (uint8_t*)0x8)) {
                data_sz = 0;
                do_write = false;
        }
#endif*/
  size_t alloc_sz = sizeof(dbtuple) + sizeof(Object) + data_sz;

  // Allocate a version
  Object *obj = new (MM::allocate(alloc_sz)) Object();
  // In case we got it from the tls reuse pool
  ASSERT(obj->GetAllocateEpoch() <= epoch - 4);
  obj->SetAllocateEpoch(epoch);
#ifdef HYU_VWEAVER /* HYU_VWEAVER */
  obj->SetVRidgy(NULL_PTR);
  obj->SetVRidgyClsn(NULL_PTR);
  obj->SetKRidgy(NULL_PTR);
  obj->SetLevel(1);
  obj->SetVRidgyLevel(0);
#endif /* HYU_VWEAVER */

  // Tuple setup
  dbtuple *tuple = (dbtuple *)obj->GetPayload();
  new (tuple) dbtuple(data_sz);
  ASSERT(tuple->pvalue == NULL);
  /*#ifdef HYU_MOTIVATION
          if (tuple_value && (tuple_value->data() == (uint8_t*)0x4 ||
                                  tuple_value->data() == (uint8_t*)0x8)) {
                  tuple->pvalue = NULL;
          } else {
                  tuple->pvalue = (varstr *)tuple_value;
          }
  #else
    tuple->pvalue = (varstr *)tuple_value;
  #endif*/
  tuple->pvalue = (varstr *)tuple_value;
  if (do_write) {
    tuple->DoWrite();
  }

  size_t size_code = encode_size_aligned(alloc_sz);
  ASSERT(size_code != INVALID_SIZE_CODE);
  return fat_ptr::make(obj, size_code, 0 /* 0: in-memory */);
}

// Make sure the object has a valid clsn/pdest
fat_ptr Object::GenerateClsnPtr(uint64_t clsn) {
  fat_ptr clsn_ptr = NULL_PTR;
  uint64_t tuple_off = GetPersistentAddress().offset();
  if (tuple_off == 0) {
    // Must be a delete record
    ASSERT(GetPinnedTuple()->size == 0);
    ASSERT(GetPersistentAddress() == NULL_PTR);
    tuple_off = clsn;
    clsn_ptr = LSN::make(tuple_off, 0).to_log_ptr();
    // Set pdest here which wasn't set by log_delete
    pdest_ = clsn_ptr;
  } else {
    clsn_ptr = LSN::make(tuple_off, 0).to_log_ptr();
  }
  return clsn_ptr;
}
}  // namespace ermia
