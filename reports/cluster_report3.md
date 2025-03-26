# Cluster 3 Report

## Function 1
```
Function: ssize_t __splice_from_pipe(struct pipe_inode_info *pipe, struct splice_desc *sd,
			   splice_actor *actor)
{
	int ret;

	splice_from_pipe_begin(sd);
	do {
		ret = splice_from_pipe_next(pipe, sd);
		if (ret > 0)
			ret = splice_from_pipe_feed(pipe, sd, actor);
	} while (ret > 0);
	splice_from_pipe_end(pipe, sd);

	return sd->num_spliced ? sd->num_spliced : ret;
}
```
## Message
->splice_write() via ->write_iter()

iter_file_splice_write() - a ->splice_write() instance that gathers the
pipe buffers, builds a bio_vec-based iov_iter covering those and feeds
it to ->write_iter().  A bunch of simple cases coverted to that...

[AV: fixed the braino spotted by Cyrill]

Signed-off-by: Al Viro <viro@zeniv.linux.org.uk>
## CWE: `['CWE-284', 'CWE-264']`

---
## Function 2
```
Function: static int clear_qf_name(struct super_block *sb, int qtype)
{

	struct ext4_sb_info *sbi = EXT4_SB(sb);

	if (sb_any_quota_loaded(sb) &&
		sbi->s_qf_names[qtype]) {
		ext4_msg(sb, KERN_ERR, "Cannot change journaled quota options"
			" when quota turned on");
		return -1;
	}
	kfree(sbi->s_qf_names[qtype]);
	sbi->s_qf_names[qtype] = NULL;
	return 1;
}
```
## Message
ext4: fix races between page faults and hole punching

Currently, page faults and hole punching are completely unsynchronized.
This can result in page fault faulting in a page into a range that we
are punching after truncate_pagecache_range() has been called and thus
we can end up with a page mapped to disk blocks that will be shortly
freed. Filesystem corruption will shortly follow. Note that the same
race is avoided for truncate by checking page fault offset against
i_size but there isn't similar mechanism available for punching holes.

Fix the problem by creating new rw semaphore i_mmap_sem in inode and
grab it for writing over truncate, hole punching, and other functions
removing blocks from extent tree and for read over page faults. We
cannot easily use i_data_sem for this since that ranks below transaction
start and we need something ranking above it so that it can be held over
the whole truncate / hole punching operation. Also remove various
workarounds we had in the code to reduce race window when page fault
could have created pages with stale mapping information.

Signed-off-by: Jan Kara <jack@suse.com>
Signed-off-by: Theodore Ts'o <tytso@mit.edu>
## CWE: `['CWE-362']`

---
## Function 3
```
Function: static int vbg_misc_device_user_open(struct inode *inode, struct file *filp)
{
	struct vbg_session *session;
	struct vbg_dev *gdev;

	/* misc_open sets filp->private_data to our misc device */
	gdev = container_of(filp->private_data, struct vbg_dev,
			    misc_device_user);

	session = vbg_core_open_session(gdev, false);
	if (IS_ERR(session))
		return PTR_ERR(session);

	filp->private_data = session;
	return 0;
}
```
## Message
virt: vbox: Only copy_from_user the request-header once

In vbg_misc_device_ioctl(), the header of the ioctl argument is copied from
the userspace pointer 'arg' and saved to the kernel object 'hdr'. Then the
'version', 'size_in', and 'size_out' fields of 'hdr' are verified.

Before this commit, after the checks a buffer for the entire request would
be allocated and then all data including the verified header would be
copied from the userspace 'arg' pointer again.

Given that the 'arg' pointer resides in userspace, a malicious userspace
process can race to change the data pointed to by 'arg' between the two
copies. By doing so, the user can bypass the verifications on the ioctl
argument.

This commit fixes this by using the already checked copy of the header
to fill the header part of the allocated buffer and only copying the
remainder of the data from userspace.

Signed-off-by: Wenwen Wang <wang6495@umn.edu>
Reviewed-by: Hans de Goede <hdegoede@redhat.com>
Signed-off-by: Greg Kroah-Hartman <gregkh@linuxfoundation.org>
## CWE: `['CWE-362']`

---
## Function 4
```
Function: vips_giflib_buffer_read( GifFileType *file, GifByteType *buf, int n )
{
	VipsForeignLoadGif *gif = (VipsForeignLoadGif *) file->UserData;
	VipsForeignLoadGifBuffer *buffer = (VipsForeignLoadGifBuffer *) gif;
	size_t will_read = VIPS_MIN( n, buffer->bytes_to_go );

	memcpy( buf, buffer->p, will_read );
	buffer->p += will_read;
	buffer->bytes_to_go -= will_read;

	if( will_read == 0 )
		gif->eof = TRUE;

	return( will_read ); 
}
```
## Message
fetch map after DGifGetImageDesc()

Earlier refactoring broke GIF map fetch.
## CWE: `['CWE-416']`

---
## Function 5
```
Function: int io_wq_cpu_affinity(struct io_wq *wq, cpumask_var_t mask)
{
	int i;

	rcu_read_lock();
	for_each_node(i) {
		struct io_wqe *wqe = wq->wqes[i];

		if (mask)
			cpumask_copy(wqe->cpu_mask, mask);
		else
			cpumask_copy(wqe->cpu_mask, cpumask_of_node(i));
	}
	rcu_read_unlock();
	return 0;
}
```
## Message
io-wq: fix cancellation on create-worker failure

WARNING: CPU: 0 PID: 10392 at fs/io_uring.c:1151 req_ref_put_and_test
fs/io_uring.c:1151 [inline]
WARNING: CPU: 0 PID: 10392 at fs/io_uring.c:1151 req_ref_put_and_test
fs/io_uring.c:1146 [inline]
WARNING: CPU: 0 PID: 10392 at fs/io_uring.c:1151
io_req_complete_post+0xf5b/0x1190 fs/io_uring.c:1794
Modules linked in:
Call Trace:
 tctx_task_work+0x1e5/0x570 fs/io_uring.c:2158
 task_work_run+0xe0/0x1a0 kernel/task_work.c:164
 tracehook_notify_signal include/linux/tracehook.h:212 [inline]
 handle_signal_work kernel/entry/common.c:146 [inline]
 exit_to_user_mode_loop kernel/entry/common.c:172 [inline]
 exit_to_user_mode_prepare+0x232/0x2a0 kernel/entry/common.c:209
 __syscall_exit_to_user_mode_work kernel/entry/common.c:291 [inline]
 syscall_exit_to_user_mode+0x19/0x60 kernel/entry/common.c:302
 do_syscall_64+0x42/0xb0 arch/x86/entry/common.c:86
 entry_SYSCALL_64_after_hwframe+0x44/0xae

When io_wqe_enqueue() -> io_wqe_create_worker() fails, we can't just
call io_run_cancel() to clean up the request, it's already enqueued via
io_wqe_insert_work() and will be executed either by some other worker
during cancellation (e.g. in io_wq_put_and_exit()).

Reported-by: Hao Sun <sunhao.th@gmail.com>
Fixes: 3146cba99aa28 ("io-wq: make worker creation resilient against signals")
Signed-off-by: Pavel Begunkov <asml.silence@gmail.com>
Link: https://lore.kernel.org/r/93b9de0fcf657affab0acfd675d4abcd273ee863.1631092071.git.asml.silence@gmail.com
Signed-off-by: Jens Axboe <axboe@kernel.dk>
## CWE: `['CWE-200']`

---