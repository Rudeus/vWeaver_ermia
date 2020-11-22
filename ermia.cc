#include "dbcore/rcu.h"
#include "dbcore/sm-chkpt.h"
#include "dbcore/sm-cmd-log.h"
#include "dbcore/sm-rep.h"

#include "ermia.h"
#include "txn.h"

namespace ermia {

// Engine initialization, including creating the OID, log, and checkpoint
// managers and recovery if needed.
Engine::Engine() {
  config::sanity_check();

  if (!config::is_backup_srv()) {
    if (!RCU::rcu_is_registered()) {
      RCU::rcu_register();
    }
    RCU::rcu_enter();

    ALWAYS_ASSERT(config::log_dir.size());
    ALWAYS_ASSERT(not logmgr);
    ALWAYS_ASSERT(not oidmgr);
    sm_log::allocate_log_buffer();
    logmgr = sm_log::new_log(config::recover_functor, nullptr);
    sm_oid_mgr::create();
    if (config::command_log) {
      CommandLog::cmd_log = new CommandLog::CommandLogManager();
    }
    ALWAYS_ASSERT(logmgr);
    ALWAYS_ASSERT(oidmgr);

    LSN chkpt_lsn = logmgr->get_chkpt_start();
    if (config::enable_chkpt) {
      chkptmgr = new sm_chkpt_mgr(chkpt_lsn);
    }

    // The backup will want to recover in another thread
    if (sm_log::need_recovery) {
      logmgr->recover();
    }
    RCU::rcu_exit();
  }
}

void Engine::CreateTable(uint16_t index_type, const char *name,
                         const char *primary_name) {
  IndexDescriptor *index_desc = nullptr;

  switch (index_type) {
  case kIndexConcurrentMasstree:
    index_desc =
        (new ConcurrentMasstreeIndex(name, primary_name))->GetDescriptor();
    break;
  default:
    LOG(FATAL) << "Wrong index type: " << index_type;
    break;
  }

  if (!sm_log::need_recovery && !config::is_backup_srv()) {
    ASSERT(ermia::logmgr);
    auto create_file = [=](char *) {
      ermia::RCU::rcu_enter();
      DEFER(ermia::RCU::rcu_exit());
      ermia::sm_tx_log *log = ermia::logmgr->new_tx_log();

      index_desc->Initialize();
      log->log_index(index_desc->GetTupleFid(), index_desc->GetKeyFid(),
                     index_desc->GetName());

      log->commit(nullptr);
    };

    // Note: this will insert to the log and therefore affect min_flush_lsn,
    // so must be done in an sm-thread.
    ermia::thread::Thread *thread = ermia::thread::GetThread(true);
    ALWAYS_ASSERT(thread);
    thread->StartTask(create_file);
    thread->Join();
    ermia::thread::PutThread(thread);
  }
}

#ifdef HYU_EVAL_2 /* HYU_EVAL_2 */
rc_t ConcurrentMasstreeIndex::Scan_eval(transaction *t, const varstr &start_key,
                                        const varstr *end_key,
                                        ScanCallback &callback,
                                        str_arena *arena, const int scan_flag) {
  MARK_REFERENCED(arena);
  SearchRangeCallback c(callback);

  ASSERT(c.return_code._val == RC_FALSE);

  t->ensure_active();
  if (end_key) {
    VERBOSE(std::cerr << "txn_btree(0x" << util::hexify(intptr_t(this))
                      << ")::search_range_call [" << util::hexify(start_key)
                      << ", " << util::hexify(*end_key) << ")" << std::endl);
  } else {
    VERBOSE(std::cerr << "txn_btree(0x" << util::hexify(intptr_t(this))
                      << ")::search_range_call [" << util::hexify(start_key)
                      << ", +inf)" << std::endl);
  }

  if (!unlikely(end_key && *end_key <= start_key)) {
    XctSearchRangeCallback cb(t, &c);

    varstr uppervk;
    if (end_key) {
      uppervk = *end_key;
    }
    masstree_.search_range_call_eval(start_key, end_key ? &uppervk : nullptr,
                                     cb, t->xc, scan_flag);
  }
  return c.return_code;
}
#endif /* HYU_EVAL_2 */
rc_t ConcurrentMasstreeIndex::Scan(transaction *t, const varstr &start_key,
                                   const varstr *end_key,
                                   ScanCallback &callback, str_arena *arena) {
  MARK_REFERENCED(arena);
  SearchRangeCallback c(callback);

  ASSERT(c.return_code._val == RC_FALSE);

  t->ensure_active();
  if (end_key) {
    VERBOSE(std::cerr << "txn_btree(0x" << util::hexify(intptr_t(this))
                      << ")::search_range_call [" << util::hexify(start_key)
                      << ", " << util::hexify(*end_key) << ")" << std::endl);
  } else {
    VERBOSE(std::cerr << "txn_btree(0x" << util::hexify(intptr_t(this))
                      << ")::search_range_call [" << util::hexify(start_key)
                      << ", +inf)" << std::endl);
  }

  if (!unlikely(end_key && *end_key <= start_key)) {
    XctSearchRangeCallback cb(t, &c);

    varstr uppervk;
    if (end_key) {
      uppervk = *end_key;
    }

    masstree_.search_range_call(start_key, end_key ? &uppervk : nullptr, cb,
                                t->xc);
  }
  return c.return_code;
}

rc_t ConcurrentMasstreeIndex::ReverseScan(transaction *t,
                                          const varstr &start_key,
                                          const varstr *end_key,
                                          ScanCallback &callback,
                                          str_arena *arena) {
  MARK_REFERENCED(arena);
  SearchRangeCallback c(callback);
  ASSERT(c.return_code._val == RC_FALSE);

  t->ensure_active();
  if (!unlikely(end_key && start_key <= *end_key)) {
    XctSearchRangeCallback cb(t, &c);

    varstr lowervk;
    if (end_key) {
      lowervk = *end_key;
    }
    masstree_.rsearch_range_call(start_key, end_key ? &lowervk : nullptr, cb,
                                 t->xc);
  }
  return c.return_code;
}

std::map<std::string, uint64_t> ConcurrentMasstreeIndex::Clear() {
  PurgeTreeWalker w;
  masstree_.tree_walk(w);
  masstree_.clear();
  return std::map<std::string, uint64_t>();
}

#if defined(HYU_EVAL_2) || defined(HYU_EVAL_OBJ) /* HYU_EVAL_2 */
void ConcurrentMasstreeIndex::Get_eval(transaction *t, rc_t &rc,
                                       const varstr &key, varstr &value,
                                       int flag, OID *out_oid) {
  OID oid = 0;
  rc = {RC_INVALID};
  ConcurrentMasstree::versioned_node_t sinfo;

  if (!t) {
    auto e = MM::epoch_enter();
    rc._val = masstree_.search(key, oid, e, &sinfo) ? RC_TRUE : RC_FALSE;
    MM::epoch_exit(0, e);
  } else {
    t->ensure_active();
    bool found = masstree_.search(key, oid, t->xc->begin_epoch, &sinfo);

    dbtuple *tuple = nullptr;
    if (found) {
      // Key-OID mapping exists, now try to get the actual tuple to be sure
      if (config::is_backup_srv()) {
        tuple = oidmgr->BackupGetVersion(
            descriptor_->GetTupleArray(),
            descriptor_->GetPersistentAddressArray(), oid, t->xc);
      } else {
        if (flag == 0) {  // vanilla
          tuple = oidmgr->oid_get_version_eval_stack(
              descriptor_->GetTupleArray(), oid, t->xc);
        } else {
#if defined(HYU_EVAL_OBJ)
          if (flag == 1) { //original skiplist
            tuple = oidmgr->oid_get_version_skiplist_eval(descriptor_->GetTupleArray(),
                                                 oid, t->xc); 
          } else { //vweaver
            tuple = oidmgr->oid_get_version_eval(descriptor_->GetTupleArray(),
                                                 oid, t->xc);
          }
#else
          tuple = oidmgr->oid_get_version_eval(descriptor_->GetTupleArray(),
                                               oid, t->xc);
#endif
        }
      }
      if (!tuple) {
        found = false;
      }
    }

    if (found) {
      if (out_oid) {
        *out_oid = oid;
      }
      volatile_write(rc._val, t->DoTupleRead(tuple, &value)._val);
    } else if (config::phantom_prot) {
      volatile_write(rc._val, DoNodeRead(t, sinfo.first, sinfo.second)._val);
    } else {
      volatile_write(rc._val, RC_FALSE);
    }
    ASSERT(rc._val == RC_FALSE || rc._val == RC_TRUE);
  }

  if (out_oid) {
    *out_oid = oid;
  }
}

#endif /* HYU_EVAL_2 */

void ConcurrentMasstreeIndex::Get(transaction *t, rc_t &rc, const varstr &key,
                                  varstr &value, OID *out_oid) {
  OID oid = 0;
  rc = {RC_INVALID};
  ConcurrentMasstree::versioned_node_t sinfo;

  if (!t) {
    auto e = MM::epoch_enter();
    rc._val = masstree_.search(key, oid, e, &sinfo) ? RC_TRUE : RC_FALSE;
    MM::epoch_exit(0, e);
  } else {
    t->ensure_active();
    bool found = masstree_.search(key, oid, t->xc->begin_epoch, &sinfo);

    dbtuple *tuple = nullptr;
#ifdef HYU_VWEAVER /* HYU_VWEAVER */
                   // dbtuple *zigzag_tuple = nullptr;
#endif             /* HYU_VWEAVER */
    if (found) {
      // Key-OID mapping exists, now try to get the actual tuple to be sure
      if (config::is_backup_srv()) {
        tuple = oidmgr->BackupGetVersion(
            descriptor_->GetTupleArray(),
            descriptor_->GetPersistentAddressArray(), oid, t->xc);
      } else {
      retry_get:
        uint64_t point_cnt = 0;
        uint64_t zigzag_cnt = 0;
#ifdef HYU_VWEAVER /* HYU_VWEAVER */
        tuple =
#ifdef HYU_DEBUG /* HYU_DEBUG */
            oidmgr->oid_get_version_zigzag_debug(descriptor_->GetTupleArray(),
                                                 oid, t->xc, &zigzag_cnt);
#else  /* HYU_DEBUG */
            oidmgr->oid_get_version_zigzag(descriptor_->GetTupleArray(), oid,
                                           t->xc);
#endif /* HYU_DEBUG */

#else            /* HYU_VWEAVER */
        tuple =
#ifdef HYU_DEBUG /* HYU_DEBUG */
            oidmgr->oid_get_version_debug(descriptor_->GetTupleArray(), oid,
                                          t->xc, &point_cnt);
#else            /* HYU_DEBUG */
#if defined (HYU_SKIPLIST) /* HYU_SKIPLIST */
            oidmgr->oid_get_version_skiplist(descriptor_->GetTupleArray(), oid,
                                             t->xc);
        //for debug
				/*dbtuple *debug = oidmgr->oid_get_version(descriptor_->GetTupleArray(), oid, t->xc);
				if (debug != tuple) {
          Object *debug_obj = debug->GetObject();
          Object *tuple_obj = tuple->GetObject();
          //LSN::from_ptr(debug_obj->GetClsn()).offset();
          printf("consistency error!\n");
          printf("skiplist: %lu, list: %lu\n",
             LSN::from_ptr(tuple_obj->GetClsn()).offset(),
             LSN::from_ptr(debug_obj->GetClsn()).offset());
        }*/
#elif defined (HYU_RBTREE)
            oidmgr->oid_get_version_rbtree(descriptor_->GetTupleArray(), oid,
                                           t->xc);
				//for debug
				/*dbtuple *debug = oidmgr->oid_get_version(descriptor_->GetTupleArray(), oid, t->xc);
				if (debug != tuple) {
          Object *debug_obj = debug->GetObject();
          Object *tuple_obj = tuple->GetObject();
          LSN::from_ptr(debug_obj->GetClsn()).offset();
          printf("consistency error!\n");
          printf("rbtree: %lu, list: %lu\n",
             LSN::from_ptr(tuple_obj->GetClsn()).offset(),
             LSN::from_ptr(debug_obj->GetClsn()).offset());
        }*/
#else /* HYU_SKIPLIST */
            oidmgr->oid_get_version(descriptor_->GetTupleArray(), oid, t->xc);
#endif /* HYU_SKIPLIST */
#endif           /* HYU_DEBUG */
        // if (tuple != zigzag_tuple) {
        //	printf("[HYU] scan fail in GET\n");
        //	goto retry_get;
        //}
#endif           /* HYU_VWEAVER */
      }
      if (!tuple) {
        found = false;
      }
    }

    if (found) {
      if (out_oid) {
        *out_oid = oid;
      }
      volatile_write(rc._val, t->DoTupleRead(tuple, &value)._val);
    } else if (config::phantom_prot) {
      volatile_write(rc._val, DoNodeRead(t, sinfo.first, sinfo.second)._val);
    } else {
      volatile_write(rc._val, RC_FALSE);
    }
    ASSERT(rc._val == RC_FALSE || rc._val == RC_TRUE);
  }

  if (out_oid) {
    *out_oid = oid;
  }
}

void ConcurrentMasstreeIndex::PurgeTreeWalker::on_node_begin(
    const typename ConcurrentMasstree::node_opaque_t *n) {
  ASSERT(spec_values.empty());
  spec_values = ConcurrentMasstree::ExtractValues(n);
}

void ConcurrentMasstreeIndex::PurgeTreeWalker::on_node_success() {
  spec_values.clear();
}

void ConcurrentMasstreeIndex::PurgeTreeWalker::on_node_failure() {
  spec_values.clear();
}

bool ConcurrentMasstreeIndex::InsertIfAbsent(transaction *t, const varstr &key,
                                             OID oid) {
  typename ConcurrentMasstree::insert_info_t ins_info;
  bool inserted = masstree_.insert_if_absent(key, oid, t->xc, &ins_info);

  if (!inserted) {
    return false;
  }

  if (config::phantom_prot && !t->masstree_absent_set.empty()) {
    // Update node version number
    ASSERT(ins_info.node);
    auto it = t->masstree_absent_set.find(ins_info.node);
    if (it != t->masstree_absent_set.end()) {
      if (unlikely(it->second != ins_info.old_version)) {
        // Important: caller should unlink the version, otherwise we risk
        // leaving a dead version at chain head -> infinite loop or segfault...
        return false;
      }
      // otherwise, bump the version
      it->second = ins_info.new_version;
    }
  }
  return true;
}

rc_t OrderedIndex::TryInsert(transaction &t, const varstr *k, varstr *v,
                             bool upsert, OID *inserted_oid) {
  if (t.TryInsertNewTuple(this, k, v, inserted_oid)) {
    return rc_t{RC_TRUE};
  } else if (!upsert) {
    return rc_t{RC_ABORT_INTERNAL};
  } else {
    return rc_t{RC_FALSE};
  }
}

rc_t ConcurrentMasstreeIndex::DoTreePut(transaction &t, const varstr *k,
                                        varstr *v, bool expect_new, bool upsert,
                                        OID *inserted_oid) {
  ASSERT(k);
  ASSERT((char *)k->data() == (char *)k + sizeof(varstr));
  ASSERT(!expect_new || v);
  t.ensure_active();

  if (expect_new) {
    rc_t rc = TryInsert(t, k, v, upsert, inserted_oid);
    if (rc._val != RC_FALSE) {
      return rc;
    }
    return rc_t{RC_ABORT_INTERNAL};
  }

  // do regular search
  OID oid = 0;
  rc_t rc = {RC_INVALID};
#ifdef HYU_VWEAVER /* HYU_VWEAVER */

  next_key_info_t next_key_info;
  GetOID(*k, rc, t.xc, oid, next_key_info);

  if (rc._val == RC_TRUE) {
    return t.Update(descriptor_, oid, k, v, next_key_info);
  } else {
    return rc_t{RC_ABORT_INTERNAL};
  }
#else  /* HYU_VWEAVER */
  GetOID(*k, rc, t.xc, oid);

  if (rc._val == RC_TRUE) {
    return t.Update(descriptor_, oid, k, v);
  } else {
    return rc_t{RC_ABORT_INTERNAL};
  }
#endif /* HYU_VWEAVER */
}

rc_t ConcurrentMasstreeIndex::DoNodeRead(
    transaction *t, const ConcurrentMasstree::node_opaque_t *node,
    uint64_t version) {
  ALWAYS_ASSERT(config::phantom_prot);
  ASSERT(node);
  auto it = t->masstree_absent_set.find(node);
  if (it == t->masstree_absent_set.end()) {
    t->masstree_absent_set[node] = version;
  } else if (it->second != version) {
    return rc_t{RC_ABORT_PHANTOM};
  }
  return rc_t{RC_TRUE};
}

void ConcurrentMasstreeIndex::XctSearchRangeCallback::on_resp_node(
    const typename ConcurrentMasstree::node_opaque_t *n, uint64_t version) {
  VERBOSE(std::cerr << "on_resp_node(): <node=0x" << util::hexify(intptr_t(n))
                    << ", version=" << version << ">" << std::endl);
  VERBOSE(std::cerr << "  " << ConcurrentMasstree::NodeStringify(n)
                    << std::endl);
  if (config::phantom_prot) {
#ifdef SSN
    if (t->flags & transaction::TXN_FLAG_READ_ONLY) {
      return;
    }
#endif
    rc_t rc = DoNodeRead(t, n, version);
    if (rc.IsAbort()) {
      caller_callback->return_code = rc;
    }
  }
}

bool ConcurrentMasstreeIndex::XctSearchRangeCallback::invoke(
    const ConcurrentMasstree *btr_ptr,
    const typename ConcurrentMasstree::string_type &k, dbtuple *v,
    const typename ConcurrentMasstree::node_opaque_t *n, uint64_t version) {
  MARK_REFERENCED(btr_ptr);
  MARK_REFERENCED(n);
  MARK_REFERENCED(version);
  t->ensure_active();
  VERBOSE(std::cerr << "search range k: " << util::hexify(k) << " from <node=0x"
                    << util::hexify(n) << ", version=" << version << ">"
                    << std::endl
                    << "  " << *((dbtuple *)v) << std::endl);
  varstr vv;
  caller_callback->return_code = t->DoTupleRead(v, &vv);
  if (caller_callback->return_code._val == RC_TRUE) {
    return caller_callback->Invoke(k, vv);
  } else if (caller_callback->return_code.IsAbort()) {
    // don't continue the read if the tx should abort
    // ^^^^^ note: see masstree_scan.hh, whose scan() calls
    // visit_value(), which calls this function to determine
    // if it should stop reading.
    return false;  // don't continue the read if the tx should abort
  }
  return true;
}
}  // namespace ermia
