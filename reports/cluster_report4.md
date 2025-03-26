# Cluster 4 Report

## Function 1
```
Function: static inline void get_inotify_handle(struct inotify_handle *ih)
{
	atomic_inc(&ih->count);
}
```
## Message
Fix inotify watch removal/umount races

Inotify watch removals suck violently.

To kick the watch out we need (in this order) inode->inotify_mutex and
ih->mutex.  That's fine if we have a hold on inode; however, for all
other cases we need to make damn sure we don't race with umount.  We can
*NOT* just grab a reference to a watch - inotify_unmount_inodes() will
happily sail past it and we'll end with reference to inode potentially
outliving its superblock.

Ideally we just want to grab an active reference to superblock if we
can; that will make sure we won't go into inotify_umount_inodes() until
we are done.  Cleanup is just deactivate_super().

However, that leaves a messy case - what if we *are* racing with
umount() and active references to superblock can't be acquired anymore?
We can bump ->s_count, grab ->s_umount, which will almost certainly wait
until the superblock is shut down and the watch in question is pining
for fjords.  That's fine, but there is a problem - we might have hit the
window between ->s_active getting to 0 / ->s_count - below S_BIAS (i.e.
the moment when superblock is past the point of no return and is heading
for shutdown) and the moment when deactivate_super() acquires
->s_umount.

We could just do drop_super() yield() and retry, but that's rather
antisocial and this stuff is luser-triggerable.  OTOH, having grabbed
->s_umount and having found that we'd got there first (i.e.  that
->s_root is non-NULL) we know that we won't race with
inotify_umount_inodes().

So we could grab a reference to watch and do the rest as above, just
with drop_super() instead of deactivate_super(), right? Wrong.  We had
to drop ih->mutex before we could grab ->s_umount.  So the watch
could've been gone already.

That still can be dealt with - we need to save watch->wd, do idr_find()
and compare its result with our pointer.  If they match, we either have
the damn thing still alive or we'd lost not one but two races at once,
the watch had been killed and a new one got created with the same ->wd
at the same address.  That couldn't have happened in inotify_destroy(),
but inotify_rm_wd() could run into that.  Still, "new one got created"
is not a problem - we have every right to kill it or leave it alone,
whatever's more convenient.

So we can use idr_find(...) == watch && watch->inode->i_sb == sb as
"grab it and kill it" check.  If it's been our original watch, we are
fine, if it's a newcomer - nevermind, just pretend that we'd won the
race and kill the fscker anyway; we are safe since we know that its
superblock won't be going away.

And yes, this is far beyond mere "not very pretty"; so's the entire
concept of inotify to start with.

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
Acked-by: Greg KH <greg@kroah.com>
Signed-off-by: Linus Torvalds <torvalds@linux-foundation.org>
## CWE: `['CWE-362']`

---
## Function 2
```
Function: static inline unsigned dx_get_hash(struct dx_entry *entry)
{
	return le32_to_cpu(entry->hash);
}
```
## Message
ext4: Add sanity check to make_indexed_dir

Make sure the rec_len field in the '..' entry is sane, lest we overrun
the directory block and cause a kernel oops on a purposefully
corrupted filesystem.

Thanks to Sami Liedes for reporting this bug.

http://bugzilla.kernel.org/show_bug.cgi?id=12430

Signed-off-by: "Theodore Ts'o" <tytso@mit.edu>
Cc: stable@kernel.org
## CWE: `['CWE-20']`

---
## Function 3
```
Function: static void sdma_put(struct sdma_state *ss)
{
	kref_put(&ss->kref, sdma_complete);
}
```
## Message
RDMA/hfi1: Prevent memory leak in sdma_init

In sdma_init if rhashtable_init fails the allocated memory for
tmp_sdma_rht should be released.

Fixes: 5a52a7acf7e2 ("IB/hfi1: NULL pointer dereference when freeing rhashtable")
Link: https://lore.kernel.org/r/20190925144543.10141-1-navid.emamdoost@gmail.com
Signed-off-by: Navid Emamdoost <navid.emamdoost@gmail.com>
Acked-by: Dennis Dalessandro <dennis.dalessandro@intel.com>
Signed-off-by: Jason Gunthorpe <jgg@mellanox.com>
## CWE: `['CWE-400', 'CWE-401']`

---
## Function 4
```
Function: void __iscsi_get_task(struct iscsi_task *task)
{
	refcount_inc(&task->refcount);
}
```
## Message
scsi: iscsi: Ensure sysfs attributes are limited to PAGE_SIZE

As the iSCSI parameters are exported back through sysfs, it should be
enforcing that they never are more than PAGE_SIZE (which should be more
than enough) before accepting updates through netlink.

Change all iSCSI sysfs attributes to use sysfs_emit().

Cc: stable@vger.kernel.org
Reported-by: Adam Nichols <adam@grimm-co.com>
Reviewed-by: Lee Duncan <lduncan@suse.com>
Reviewed-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
Reviewed-by: Mike Christie <michael.christie@oracle.com>
Signed-off-by: Chris Leech <cleech@redhat.com>
Signed-off-by: Martin K. Petersen <martin.petersen@oracle.com>
## CWE: `['CWE-787']`

---
## Function 5
```
Function: void imap_parser_enable_literal_minus(struct imap_parser *parser)
{
	parser->literal_minus = TRUE;
}
```
## Message
lib-imap: Don't accept strings with NULs

IMAP doesn't allow NULs except in binary literals. We'll still allow them
in regular literals as well, but just not in strings.

This fixes a bug with unescaping a string with NULs: str_unescape() could
have been called for memory that points outside the allocated string,
causing heap corruption. This could cause crashes or theoretically even
result in remote code execution exploit.

Found by Nick Roessler and Rafi Rubin
## CWE: `['CWE-787']`

---