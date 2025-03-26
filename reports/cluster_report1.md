# Cluster 1 Report

## Function 1
```
Function: void mark_page_dirty(struct kvm *kvm, gfn_t gfn)
{
	struct kvm_memory_slot *memslot;

	memslot = gfn_to_memslot(kvm, gfn);
	mark_page_dirty_in_slot(kvm, memslot, gfn);
}
```
## Message
KVM: Ensure all vcpus are consistent with in-kernel irqchip settings

If some vcpus are created before KVM_CREATE_IRQCHIP, then
irqchip_in_kernel() and vcpu->arch.apic will be inconsistent, leading
to potential NULL pointer dereferences.

Fix by:
- ensuring that no vcpus are installed when KVM_CREATE_IRQCHIP is called
- ensuring that a vcpu has an apic if it is installed after KVM_CREATE_IRQCHIP

This is somewhat long winded because vcpu->arch.apic is created without
kvm->lock held.

Based on earlier patch by Michael Ellerman.

Signed-off-by: Michael Ellerman <michael@ellerman.id.au>
Signed-off-by: Avi Kivity <avi@redhat.com>
## CWE: `['CWE-399']`

---
## Function 2
```
Function: int snd_timer_continue(struct snd_timer_instance *timeri)
{
	if (timeri->flags & SNDRV_TIMER_IFLG_SLAVE)
		return snd_timer_start_slave(timeri, false);
	else
		return snd_timer_start1(timeri, false, 0);
}
```
## Message
ALSA: timer: Fix leak in SNDRV_TIMER_IOCTL_PARAMS

The stack object “tread” has a total size of 32 bytes. Its field
“event” and “val” both contain 4 bytes padding. These 8 bytes
padding bytes are sent to user without being initialized.

Signed-off-by: Kangjie Lu <kjlu@gatech.edu>
Signed-off-by: Takashi Iwai <tiwai@suse.de>
## CWE: `['CWE-200']`

---
## Function 3
```
Function: static int muscle_card_verified_pins(sc_card_t *card, sc_cardctl_muscle_verified_pins_info_t *info)
{
	muscle_private_t* priv = MUSCLE_DATA(card);
	info->verifiedPins = priv->verifiedPins;
	return 0;
}
```
## Message
fixed out of bounds writes

Thanks to Eric Sesterhenn from X41 D-SEC GmbH
for reporting the problems.
## CWE: `['CWE-415', 'CWE-119']`

---
## Function 4
```
Function: static void deferred_dec_badcount(struct clone_struct *cs)
{
	if (!cs->save_dup_cluster)
		return;
	decrement_badcount(cs->ctx, cs->save_blocknr, cs->save_dup_cluster);
	cs->save_dup_cluster = NULL;
}
```
## Message
e2fsck: don't try to rehash a deleted directory

If directory has been deleted in pass1[bcd] processing, then we
shouldn't try to rehash the directory in pass 3a when we try to
rehash/reoptimize directories.

Signed-off-by: Theodore Ts'o <tytso@mit.edu>
## CWE: `['CWE-787']`

---
## Function 5
```
Function: tr_variant* tr_variantListAddRaw(tr_variant* list, void const* val, size_t len)
{
    tr_variant* child = tr_variantListAdd(list);
    tr_variantInitRaw(child, val, len);
    return child;
}
```
## Message
CVE-2018-10756: Fix heap-use-after-free in tr_variantWalk

In libtransmission/variant.c, function tr_variantWalk, when the variant
stack is reallocated, a pointer to the previously allocated memory
region is kept. This address is later accessed (heap use-after-free)
while walking back down the stack, causing the application to crash.
The application can be any application which uses libtransmission, such
as transmission-daemon, transmission-gtk, transmission-show, etc.

Reported-by: Tom Richards <tom@tomrichards.net>
## CWE: `['CWE-416', 'CWE-284']`

---