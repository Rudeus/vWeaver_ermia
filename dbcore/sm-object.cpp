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
