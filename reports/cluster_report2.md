# Cluster 2 Report

## Function 1
```
Function: static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct dp_upcall_info *upcall_info)
{
	struct ovs_header *upcall;
	struct sk_buff *nskb = NULL;
	struct sk_buff *user_skb; /* to be queued to userspace */
	struct nlattr *nla;
	struct genl_info info = {
		.dst_sk = ovs_dp_get_net(dp)->genl_sock,
		.snd_portid = upcall_info->portid,
	};
	size_t len;
	unsigned int hlen;
	int err, dp_ifindex;

	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	if (vlan_tx_tag_present(skb)) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return -ENOMEM;

		nskb = __vlan_put_tag(nskb, nskb->vlan_proto, vlan_tx_tag_get(nskb));
		if (!nskb)
			return -ENOMEM;

		nskb->vlan_tci = 0;
		skb = nskb;
	}

	if (nla_attr_size(skb->len) > USHRT_MAX) {
		err = -EFBIG;
		goto out;
	}

	/* Complete checksum if needed */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto out;

	/* Older versions of OVS user space enforce alignment of the last
	 * Netlink attribute to NLA_ALIGNTO which would require extensive
	 * padding logic. Only perform zerocopy if padding is not required.
	 */
	if (dp->user_features & OVS_DP_F_UNALIGNED)
		hlen = skb_zerocopy_headlen(skb);
	else
		hlen = skb->len;

	len = upcall_msg_size(upcall_info->userdata, hlen);
	user_skb = genlmsg_new_unicast(len, &info, GFP_ATOMIC);
	if (!user_skb) {
		err = -ENOMEM;
		goto out;
	}

	upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);
	upcall->dp_ifindex = dp_ifindex;

	nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_KEY);
	ovs_nla_put_flow(upcall_info->key, upcall_info->key, user_skb);
	nla_nest_end(user_skb, nla);

	if (upcall_info->userdata)
		__nla_put(user_skb, OVS_PACKET_ATTR_USERDATA,
			  nla_len(upcall_info->userdata),
			  nla_data(upcall_info->userdata));

	/* Only reserve room for attribute header, packet data is added
	 * in skb_zerocopy() */
	if (!(nla = nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, 0))) {
		err = -ENOBUFS;
		goto out;
	}
	nla->nla_len = nla_attr_size(skb->len);

	skb_zerocopy(user_skb, skb, skb->len, hlen);

	/* Pad OVS_PACKET_ATTR_PACKET if linear copy was performed */
	if (!(dp->user_features & OVS_DP_F_UNALIGNED)) {
		size_t plen = NLA_ALIGN(user_skb->len) - user_skb->len;

		if (plen > 0)
			memset(skb_put(user_skb, plen), 0, plen);
	}

	((struct nlmsghdr *) user_skb->data)->nlmsg_len = user_skb->len;

	err = genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);
out:
	kfree_skb(nskb);
	return err;
}
```
## Message
core, nfqueue, openvswitch: Orphan frags in skb_zerocopy and handle errors

skb_zerocopy can copy elements of the frags array between skbs, but it doesn't
orphan them. Also, it doesn't handle errors, so this patch takes care of that
as well, and modify the callers accordingly. skb_tx_error() is also added to
the callers so they will signal the failed delivery towards the creator of the
skb.

Signed-off-by: Zoltan Kiss <zoltan.kiss@citrix.com>
Signed-off-by: David S. Miller <davem@davemloft.net>
## CWE: `['CWE-416']`

---
## Function 2
```
Function: static int queue_userspace_packet(struct datapath *dp, struct sk_buff *skb,
				  const struct dp_upcall_info *upcall_info)
{
	struct ovs_header *upcall;
	struct sk_buff *nskb = NULL;
	struct sk_buff *user_skb; /* to be queued to userspace */
	struct nlattr *nla;
	struct genl_info info = {
		.dst_sk = ovs_dp_get_net(dp)->genl_sock,
		.snd_portid = upcall_info->portid,
	};
	size_t len;
	unsigned int hlen;
	int err, dp_ifindex;

	dp_ifindex = get_dpifindex(dp);
	if (!dp_ifindex)
		return -ENODEV;

	if (vlan_tx_tag_present(skb)) {
		nskb = skb_clone(skb, GFP_ATOMIC);
		if (!nskb)
			return -ENOMEM;

		nskb = __vlan_put_tag(nskb, nskb->vlan_proto, vlan_tx_tag_get(nskb));
		if (!nskb)
			return -ENOMEM;

		nskb->vlan_tci = 0;
		skb = nskb;
	}

	if (nla_attr_size(skb->len) > USHRT_MAX) {
		err = -EFBIG;
		goto out;
	}

	/* Complete checksum if needed */
	if (skb->ip_summed == CHECKSUM_PARTIAL &&
	    (err = skb_checksum_help(skb)))
		goto out;

	/* Older versions of OVS user space enforce alignment of the last
	 * Netlink attribute to NLA_ALIGNTO which would require extensive
	 * padding logic. Only perform zerocopy if padding is not required.
	 */
	if (dp->user_features & OVS_DP_F_UNALIGNED)
		hlen = skb_zerocopy_headlen(skb);
	else
		hlen = skb->len;

	len = upcall_msg_size(upcall_info->userdata, hlen);
	user_skb = genlmsg_new_unicast(len, &info, GFP_ATOMIC);
	if (!user_skb) {
		err = -ENOMEM;
		goto out;
	}

	upcall = genlmsg_put(user_skb, 0, 0, &dp_packet_genl_family,
			     0, upcall_info->cmd);
	upcall->dp_ifindex = dp_ifindex;

	nla = nla_nest_start(user_skb, OVS_PACKET_ATTR_KEY);
	ovs_nla_put_flow(upcall_info->key, upcall_info->key, user_skb);
	nla_nest_end(user_skb, nla);

	if (upcall_info->userdata)
		__nla_put(user_skb, OVS_PACKET_ATTR_USERDATA,
			  nla_len(upcall_info->userdata),
			  nla_data(upcall_info->userdata));

	/* Only reserve room for attribute header, packet data is added
	 * in skb_zerocopy() */
	if (!(nla = nla_reserve(user_skb, OVS_PACKET_ATTR_PACKET, 0))) {
		err = -ENOBUFS;
		goto out;
	}
	nla->nla_len = nla_attr_size(skb->len);

	err = skb_zerocopy(user_skb, skb, skb->len, hlen);
	if (err)
		goto out;

	/* Pad OVS_PACKET_ATTR_PACKET if linear copy was performed */
	if (!(dp->user_features & OVS_DP_F_UNALIGNED)) {
		size_t plen = NLA_ALIGN(user_skb->len) - user_skb->len;

		if (plen > 0)
			memset(skb_put(user_skb, plen), 0, plen);
	}

	((struct nlmsghdr *) user_skb->data)->nlmsg_len = user_skb->len;

	err = genlmsg_unicast(ovs_dp_get_net(dp), user_skb, upcall_info->portid);
out:
	if (err)
		skb_tx_error(skb);
	kfree_skb(nskb);
	return err;
}
```
## Message
core, nfqueue, openvswitch: Orphan frags in skb_zerocopy and handle errors

skb_zerocopy can copy elements of the frags array between skbs, but it doesn't
orphan them. Also, it doesn't handle errors, so this patch takes care of that
as well, and modify the callers accordingly. skb_tx_error() is also added to
the callers so they will signal the failed delivery towards the creator of the
skb.

Signed-off-by: Zoltan Kiss <zoltan.kiss@citrix.com>
Signed-off-by: David S. Miller <davem@davemloft.net>
## CWE: `['CWE-416']`

---
## Function 3
```
Function: static int __ip6mr_fill_mroute(struct mr6_table *mrt, struct sk_buff *skb,
			       struct mfc6_cache *c, struct rtmsg *rtm)
{
	struct rta_mfc_stats mfcs;
	struct nlattr *mp_attr;
	struct rtnexthop *nhp;
	unsigned long lastuse;
	int ct;

	/* If cache is unresolved, don't try to parse IIF and OIF */
	if (c->mf6c_parent >= MAXMIFS) {
		rtm->rtm_flags |= RTNH_F_UNRESOLVED;
		return -ENOENT;
	}

	if (MIF_EXISTS(mrt, c->mf6c_parent) &&
	    nla_put_u32(skb, RTA_IIF, mrt->vif6_table[c->mf6c_parent].dev->ifindex) < 0)
		return -EMSGSIZE;
	mp_attr = nla_nest_start(skb, RTA_MULTIPATH);
	if (!mp_attr)
		return -EMSGSIZE;

	for (ct = c->mfc_un.res.minvif; ct < c->mfc_un.res.maxvif; ct++) {
		if (MIF_EXISTS(mrt, ct) && c->mfc_un.res.ttls[ct] < 255) {
			nhp = nla_reserve_nohdr(skb, sizeof(*nhp));
			if (!nhp) {
				nla_nest_cancel(skb, mp_attr);
				return -EMSGSIZE;
			}

			nhp->rtnh_flags = 0;
			nhp->rtnh_hops = c->mfc_un.res.ttls[ct];
			nhp->rtnh_ifindex = mrt->vif6_table[ct].dev->ifindex;
			nhp->rtnh_len = sizeof(*nhp);
		}
	}

	nla_nest_end(skb, mp_attr);

	lastuse = READ_ONCE(c->mfc_un.res.lastuse);
	lastuse = time_after_eq(jiffies, lastuse) ? jiffies - lastuse : 0;

	mfcs.mfcs_packets = c->mfc_un.res.pkt;
	mfcs.mfcs_bytes = c->mfc_un.res.bytes;
	mfcs.mfcs_wrong_if = c->mfc_un.res.wrong_if;
	if (nla_put_64bit(skb, RTA_MFC_STATS, sizeof(mfcs), &mfcs, RTA_PAD) ||
	    nla_put_u64_64bit(skb, RTA_EXPIRES, jiffies_to_clock_t(lastuse),
			      RTA_PAD))
		return -EMSGSIZE;

	rtm->rtm_type = RTN_MULTICAST;
	return 1;
}
```
## Message
ipv6: check sk sk_type and protocol early in ip_mroute_set/getsockopt

Commit 5e1859fbcc3c ("ipv4: ipmr: various fixes and cleanups") fixed
the issue for ipv4 ipmr:

  ip_mroute_setsockopt() & ip_mroute_getsockopt() should not
  access/set raw_sk(sk)->ipmr_table before making sure the socket
  is a raw socket, and protocol is IGMP

The same fix should be done for ipv6 ipmr as well.

This patch can fix the panic caused by overwriting the same offset
as ipmr_table as in raw_sk(sk) when accessing other type's socket
by ip_mroute_setsockopt().

Signed-off-by: Xin Long <lucien.xin@gmail.com>
Signed-off-by: David S. Miller <davem@davemloft.net>
## CWE: `['CWE-20']`

---
## Function 4
```
Function: static int inode_doinit_use_xattr(struct inode *inode, struct dentry *dentry,
				  u32 def_sid, u32 *sid)
{
#define INITCONTEXTLEN 255
	char *context;
	unsigned int len;
	int rc;

	len = INITCONTEXTLEN;
	context = kmalloc(len + 1, GFP_NOFS);
	if (!context)
		return -ENOMEM;

	context[len] = '\0';
	rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SELINUX, context, len);
	if (rc == -ERANGE) {
		kfree(context);

		/* Need a larger buffer.  Query for the right size. */
		rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SELINUX, NULL, 0);
		if (rc < 0)
			return rc;

		len = rc;
		context = kmalloc(len + 1, GFP_NOFS);
		if (!context)
			return -ENOMEM;

		context[len] = '\0';
		rc = __vfs_getxattr(dentry, inode, XATTR_NAME_SELINUX,
				    context, len);
	}
	if (rc < 0) {
		kfree(context);
		if (rc != -ENODATA) {
			pr_warn("SELinux: %s:  getxattr returned %d for dev=%s ino=%ld\n",
				__func__, -rc, inode->i_sb->s_id, inode->i_ino);
			return rc;
		}
		*sid = def_sid;
		return 0;
	}

	rc = security_context_to_sid_default(&selinux_state, context, rc, sid,
					     def_sid, GFP_NOFS);
	if (rc) {
		char *dev = inode->i_sb->s_id;
		unsigned long ino = inode->i_ino;

		if (rc == -EINVAL) {
			pr_notice_ratelimited("SELinux: inode=%lu on dev=%s was found to have an invalid context=%s.  This indicates you may need to relabel the inode or the filesystem in question.\n",
					      ino, dev, context);
		} else {
			pr_warn("SELinux: %s:  context_to_sid(%s) returned %d for dev=%s ino=%ld\n",
				__func__, context, -rc, dev, ino);
		}
	}
	kfree(context);
	return 0;
}
```
## Message
selinux: properly handle multiple messages in selinux_netlink_send()

Fix the SELinux netlink_send hook to properly handle multiple netlink
messages in a single sk_buff; each message is parsed and subject to
SELinux access control.  Prior to this patch, SELinux only inspected
the first message in the sk_buff.

Cc: stable@vger.kernel.org
Reported-by: Dmitry Vyukov <dvyukov@google.com>
Reviewed-by: Stephen Smalley <stephen.smalley.work@gmail.com>
Signed-off-by: Paul Moore <paul@paul-moore.com>
## CWE: `['CWE-349']`

---
## Function 5
```
Function: static int sev_asid_new(struct kvm_sev_info *sev)
{
	int asid, min_asid, max_asid, ret;
	bool retry = true;

	WARN_ON(sev->misc_cg);
	sev->misc_cg = get_current_misc_cg();
	ret = sev_misc_cg_try_charge(sev);
	if (ret) {
		put_misc_cg(sev->misc_cg);
		sev->misc_cg = NULL;
		return ret;
	}

	mutex_lock(&sev_bitmap_lock);

	/*
	 * SEV-enabled guests must use asid from min_sev_asid to max_sev_asid.
	 * SEV-ES-enabled guest can use from 1 to min_sev_asid - 1.
	 */
	min_asid = sev->es_active ? 1 : min_sev_asid;
	max_asid = sev->es_active ? min_sev_asid - 1 : max_sev_asid;
again:
	asid = find_next_zero_bit(sev_asid_bitmap, max_asid + 1, min_asid);
	if (asid > max_asid) {
		if (retry && __sev_recycle_asids(min_asid, max_asid)) {
			retry = false;
			goto again;
		}
		mutex_unlock(&sev_bitmap_lock);
		ret = -EBUSY;
		goto e_uncharge;
	}

	__set_bit(asid, sev_asid_bitmap);

	mutex_unlock(&sev_bitmap_lock);

	return asid;
e_uncharge:
	sev_misc_cg_uncharge(sev);
	put_misc_cg(sev->misc_cg);
	sev->misc_cg = NULL;
	return ret;
}
```
## Message
KVM: SEV: add cache flush to solve SEV cache incoherency issues

Flush the CPU caches when memory is reclaimed from an SEV guest (where
reclaim also includes it being unmapped from KVM's memslots).  Due to lack
of coherency for SEV encrypted memory, failure to flush results in silent
data corruption if userspace is malicious/broken and doesn't ensure SEV
guest memory is properly pinned and unpinned.

Cache coherency is not enforced across the VM boundary in SEV (AMD APM
vol.2 Section 15.34.7). Confidential cachelines, generated by confidential
VM guests have to be explicitly flushed on the host side. If a memory page
containing dirty confidential cachelines was released by VM and reallocated
to another user, the cachelines may corrupt the new user at a later time.

KVM takes a shortcut by assuming all confidential memory remain pinned
until the end of VM lifetime. Therefore, KVM does not flush cache at
mmu_notifier invalidation events. Because of this incorrect assumption and
the lack of cache flushing, malicous userspace can crash the host kernel:
creating a malicious VM and continuously allocates/releases unpinned
confidential memory pages when the VM is running.

Add cache flush operations to mmu_notifier operations to ensure that any
physical memory leaving the guest VM get flushed. In particular, hook
mmu_notifier_invalidate_range_start and mmu_notifier_release events and
flush cache accordingly. The hook after releasing the mmu lock to avoid
contention with other vCPUs.

Cc: stable@vger.kernel.org
Suggested-by: Sean Christpherson <seanjc@google.com>
Reported-by: Mingwei Zhang <mizhang@google.com>
Signed-off-by: Mingwei Zhang <mizhang@google.com>
Message-Id: <20220421031407.2516575-4-mizhang@google.com>
Signed-off-by: Paolo Bonzini <pbonzini@redhat.com>
## CWE: `['CWE-459']`

---