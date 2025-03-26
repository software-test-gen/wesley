# Cluster 5 Report

## Function 1
```
Function: static int mlookup(const char *name, char **server, char **aclp, void *tid)
{
    struct mboxlist_entry mbentry;
    int r;
    
    r = mboxlist_lookup(name, &mbentry, tid);
    if (r == IMAP_MAILBOX_NONEXISTENT && config_mupdate_server) {
	kick_mupdate();
	r = mboxlist_lookup(name, &mbentry, tid);
    }

    if (aclp) *aclp = mbentry.acl;

    if (server) {
	*server = NULL;
	if (mbentry.mbtype & MBTYPE_REMOTE) {
	    char *c;
	    *server = mbentry.partition;
	    c = strchr(*server, '!');
	    if(c) *c = '\0';
	}
    }

    return r;
}
```
## Message
Secunia SA46093 - make sure nntp authentication completes

Discovered by Stefan Cornelius, Secunia Research

The vulnerability is caused due to the access restriction for certain
commands only checking whether or not variable "nntp_userid" is non-NULL,
without performing additional checks to verify that a complete, successful
authentication actually took place. The variable "nntp_userid" can be set to
point to a string holding the username (changing it to a non-NULL, thus
allowing attackers to bypass the checks) by sending an "AUTHINFO USER"
command. The variable is not reset to NULL until e.g. a wrong "AUTHINFO
PASS" command is received. This can be exploited to bypass the
authentication mechanism and allows access to e.g. the "NEWNEWS" or the
"LIST NEWSGROUPS" commands by sending an "AUTHINFO USER" command without a
following "AUTHINFO PASS" command.
## CWE: `['CWE-287']`

---
## Function 2
```
Function: xt_hook_ops_alloc(const struct xt_table *table, nf_hookfn *fn)
{
	unsigned int hook_mask = table->valid_hooks;
	uint8_t i, num_hooks = hweight32(hook_mask);
	uint8_t hooknum;
	struct nf_hook_ops *ops;

	ops = kmalloc(sizeof(*ops) * num_hooks, GFP_KERNEL);
	if (ops == NULL)
		return ERR_PTR(-ENOMEM);

	for (i = 0, hooknum = 0; i < num_hooks && hook_mask != 0;
	     hook_mask >>= 1, ++hooknum) {
		if (!(hook_mask & 1))
			continue;
		ops[i].hook     = fn;
		ops[i].pf       = table->af;
		ops[i].hooknum  = hooknum;
		ops[i].priority = table->priority;
		++i;
	}

	return ops;
}
```
## Message
netfilter: x_tables: introduce and use xt_copy_counters_from_user

The three variants use same copy&pasted code, condense this into a
helper and use that.

Make sure info.name is 0-terminated.

Signed-off-by: Florian Westphal <fw@strlen.de>
Signed-off-by: Pablo Neira Ayuso <pablo@netfilter.org>
## CWE: `['CWE-119']`

---
## Function 3
```
Function: void __init old_map_region(efi_memory_desc_t *md)
{
	u64 start_pfn, end_pfn, end;
	unsigned long size;
	void *va;

	start_pfn = PFN_DOWN(md->phys_addr);
	size	  = md->num_pages << PAGE_SHIFT;
	end	  = md->phys_addr + size;
	end_pfn   = PFN_UP(end);

	if (pfn_range_is_mapped(start_pfn, end_pfn)) {
		va = __va(md->phys_addr);

		if (!(md->attribute & EFI_MEMORY_WB))
			efi_memory_uc((u64)(unsigned long)va, size);
	} else
		va = efi_ioremap(md->phys_addr, size,
				 md->type, md->attribute);

	md->virt_addr = (u64) (unsigned long) va;
	if (!va)
		pr_err("ioremap of 0x%llX failed!\n",
		       (unsigned long long)md->phys_addr);
}
```
## Message
efi/x86/Add missing error handling to old_memmap 1:1 mapping code

The old_memmap flow in efi_call_phys_prolog() performs numerous memory
allocations, and either does not check for failure at all, or it does
but fails to propagate it back to the caller, which may end up calling
into the firmware with an incomplete 1:1 mapping.

So let's fix this by returning NULL from efi_call_phys_prolog() on
memory allocation failures only, and by handling this condition in the
caller. Also, clean up any half baked sets of page tables that we may
have created before returning with a NULL return value.

Note that any failure at this level will trigger a panic() two levels
up, so none of this makes a huge difference, but it is a nice cleanup
nonetheless.

[ardb: update commit log, add efi_call_phys_epilog() call on error path]

Signed-off-by: Gen Zhang <blackgod016574@gmail.com>
Signed-off-by: Ard Biesheuvel <ard.biesheuvel@linaro.org>
Cc: Linus Torvalds <torvalds@linux-foundation.org>
Cc: Peter Zijlstra <peterz@infradead.org>
Cc: Rob Bradford <robert.bradford@intel.com>
Cc: Thomas Gleixner <tglx@linutronix.de>
Cc: linux-efi@vger.kernel.org
Link: http://lkml.kernel.org/r/20190525112559.7917-2-ard.biesheuvel@linaro.org
Signed-off-by: Ingo Molnar <mingo@kernel.org>
## CWE: `['CWE-388']`

---
## Function 4
```
Function: mm_answer_authpassword(int sock, Buffer *m)
{
	static int call_count;
	char *passwd;
	int authenticated;
	u_int plen;

	passwd = buffer_get_string(m, &plen);
	/* Only authenticate if the context is valid */
	authenticated = options.password_authentication &&
	    auth_password(authctxt, passwd);
	explicit_bzero(passwd, strlen(passwd));
	free(passwd);

	buffer_clear(m);
	buffer_put_int(m, authenticated);

	debug3("%s: sending result %d", __func__, authenticated);
	mm_request_send(sock, MONITOR_ANS_AUTHPASSWORD, m);

	call_count++;
	if (plen == 0 && call_count == 1)
		auth_method = "none";
	else
		auth_method = "password";

	/* Causes monitor loop to terminate if authenticated */
	return (authenticated);
}
```
## Message
Don't resend username to PAM; it already has it.

Pointed out by Moritz Jodeit; ok dtucker@
## CWE: `['CWE-20', 'CWE-200']`

---
## Function 5
```
Function: int kvm_write_guest_cached(struct kvm *kvm, struct gfn_to_hva_cache *ghc,
			   void *data, unsigned long len)
{
	struct kvm_memslots *slots = kvm_memslots(kvm);
	int r;

	BUG_ON(len > ghc->len);

	if (slots->generation != ghc->generation)
		kvm_gfn_to_hva_cache_init(kvm, ghc, ghc->gpa, ghc->len);

	if (unlikely(!ghc->memslot))
		return kvm_write_guest(kvm, ghc->gpa, data, len);

	if (kvm_is_error_hva(ghc->hva))
		return -EFAULT;

	r = __copy_to_user((void __user *)ghc->hva, data, len);
	if (r)
		return -EFAULT;
	mark_page_dirty_in_slot(kvm, ghc->memslot, ghc->gpa >> PAGE_SHIFT);

	return 0;
}
```
## Message
KVM: Improve create VCPU parameter (CVE-2013-4587)

In multiple functions the vcpu_id is used as an offset into a bitfield.  Ag
malicious user could specify a vcpu_id greater than 255 in order to set or
clear bits in kernel memory.  This could be used to elevate priveges in the
kernel.  This patch verifies that the vcpu_id provided is less than 255.
The api documentation already specifies that the vcpu_id must be less than
max_vcpus, but this is currently not checked.

Reported-by: Andrew Honig <ahonig@google.com>
Cc: stable@vger.kernel.org
Signed-off-by: Andrew Honig <ahonig@google.com>
Signed-off-by: Paolo Bonzini <pbonzini@redhat.com>
## CWE: `['CWE-20']`

---