
/* audit_fsnotify.c */
static const struct fsnotify_ops audit_mark_fsnotify_ops = {
	.handle_event =	audit_mark_handle_event,
	.free_mark = audit_fsnotify_free_mark,
};

/* audit_tree.c */
static const struct fsnotify_ops audit_tree_ops = {
	.handle_event = audit_tree_handle_event,
	.freeing_mark = audit_tree_freeing_mark,
	.free_mark = audit_tree_destroy_watch,
};

/* audit_watch.c */
static const struct fsnotify_ops audit_watch_fsnotify_ops = {
	.handle_event = 	audit_watch_handle_event,
	.free_mark =		audit_watch_free_mark,
};

/* btf.c */
static const struct btf_kind_operations int_ops = {
	.check_meta = btf_int_check_meta,
	.resolve = btf_df_resolve,
	.check_member = btf_int_check_member,
	.log_details = btf_int_log,
	.seq_show = btf_int_seq_show,
};

/* btf.c */
static const struct btf_kind_operations * const kind_ops[NR_BTF_KINDS] = {
	[BTF_KIND_INT] = &int_ops,
	[BTF_KIND_PTR] = &ptr_ops,
	[BTF_KIND_ARRAY] = &array_ops,
	[BTF_KIND_STRUCT] = &struct_ops,
	[BTF_KIND_UNION] = &struct_ops,
	[BTF_KIND_ENUM] = &enum_ops,
	[BTF_KIND_FWD] = &fwd_ops,
	[BTF_KIND_TYPEDEF] = &modifier_ops,
	[BTF_KIND_VOLATILE] = &modifier_ops,
	[BTF_KIND_CONST] = &modifier_ops,
	[BTF_KIND_RESTRICT] = &modifier_ops,
};

/* core.c */
static const struct latch_tree_ops bpf_tree_ops = {
	.less	= bpf_tree_less,
	.comp	= bpf_tree_comp,
};

/* inode.c */
static const struct seq_operations bpffs_map_seq_ops = {
	.start	= map_seq_start,
	.next	= map_seq_next,
	.show	= map_seq_show,
	.stop	= map_seq_stop,
};

/* inode.c */
static const struct file_operations bpffs_map_fops = {
	.open		= bpffs_map_open,
	.read		= seq_read,
	.release	= bpffs_map_release,
};

/* inode.c */
static const struct file_operations bpffs_obj_fops = {
	.open		= bpffs_obj_open,
};

/* inode.c */
static const struct inode_operations bpf_dir_iops = {
	.lookup		= bpf_lookup,
	.mkdir		= bpf_mkdir,
	.symlink	= bpf_symlink,
	.rmdir		= simple_rmdir,
	.rename		= simple_rename,
	.link		= simple_link,
	.unlink		= simple_unlink,
};

/* inode.c */
static const struct super_operations bpf_super_ops = {
	.statfs		= simple_statfs,
	.drop_inode	= generic_delete_inode,
	.show_options	= bpf_show_options,
	.evict_inode	= bpf_evict_inode,
};

/* inode.c */
static struct file_system_type bpf_fs_type = {
	.owner		= THIS_MODULE,
	.name		= "bpf",
	.mount		= bpf_mount,
	.kill_sb	= kill_litter_super,
};

/* sockmap.c */
static int smap_init_sock(struct smap_psock *psock,
			  struct sock *sk)
{
	static const struct strp_callbacks cb = {
		.rcv_msg = smap_read_sock_strparser,
		.parse_msg = smap_parse_func_strparser,
		.read_sock_done = smap_read_sock_done,
	};

	return strp_init(&psock->strp, sk, &cb);
}

/* syscall.c */
static const struct file_operations bpf_raw_tp_fops = {
	.release	= bpf_raw_tracepoint_release,
	.read		= bpf_dummy_read,
	.write		= bpf_dummy_write,
};

/* cgroup.c */
static const struct attribute_group cgroup_sysfs_attr_group = {
	.attrs = cgroup_sysfs_attrs,
	.name = "cgroup",
};

/* configs.c */
static const struct file_operations ikconfig_file_ops = {
	.owner = THIS_MODULE,
	.read = ikconfig_read_current,
	.llseek = default_llseek,
};

/* cpu.c */
static const struct attribute_group cpuhp_cpu_attr_group = {
	.attrs = cpuhp_cpu_attrs,
	.name = "hotplug",
	NULL
};

/* coherent.c */
static const struct reserved_mem_ops rmem_dma_ops = {
	.device_init	= rmem_dma_device_init,
	.device_release	= rmem_dma_device_release,
};

/* contiguous.c */
static const struct reserved_mem_ops rmem_cma_ops = {
	.device_init	= rmem_cma_device_init,
	.device_release = rmem_cma_device_release,
};

/* debug.c */
static const struct file_operations filter_fops = {
	.read  = filter_read,
	.write = filter_write,
	.llseek = default_llseek,
};

/* core.c */
static const struct vm_operations_struct perf_mmap_vmops = {
	.open		= perf_mmap_open,
	.close		= perf_mmap_close, /* non mergable */
	.fault		= perf_mmap_fault,
	.page_mkwrite	= perf_mmap_fault,
};

/* core.c */
static const struct file_operations perf_fops = {
	.llseek			= no_llseek,
	.release		= perf_release,
	.read			= perf_read,
	.poll			= perf_poll,
	.unlocked_ioctl		= perf_ioctl,
	.compat_ioctl		= perf_compat_ioctl,
	.mmap			= perf_mmap,
	.fasync			= perf_fasync,
};

/* core.c */
static struct pmu perf_kprobe = {
	.task_ctx_nr	= perf_sw_context,
	.event_init	= perf_kprobe_event_init,
	.add		= perf_trace_add,
	.del		= perf_trace_del,
	.start		= perf_swevent_start,
	.stop		= perf_swevent_stop,
	.read		= perf_swevent_read,
	.attr_groups	= probe_attr_groups,
};

/* fail_function.c */
static const struct seq_operations fei_seq_ops = {
	.start	= fei_seq_start,
	.next	= fei_seq_next,
	.stop	= fei_seq_stop,
	.show	= fei_seq_show,
};

/* fail_function.c */ 
static const struct file_operations fei_ops = {
	.open =		fei_open,
	.read =		seq_read,
	.write =	fei_write,
	.llseek =	seq_lseek,
	.release =	seq_release,
};

/* futex.c */
static const struct futex_q futex_q_init = {
	/* list gets initialized in queue_me()*/
	.key = FUTEX_KEY_INIT,
	.bitset = FUTEX_BITSET_MATCH_ANY
};

/* fs.c */
static const struct seq_operations gcov_seq_ops = {
	.start	= gcov_seq_start,
	.next	= gcov_seq_next,
	.show	= gcov_seq_show,
	.stop	= gcov_seq_stop,
};

/* fs.c */
static const struct file_operations gcov_data_fops = {
	.open		= gcov_seq_open,
	.release	= gcov_seq_release,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.write		= gcov_seq_write,
};

/* fs.c */
static const struct file_operations gcov_reset_fops = {
	.write	= reset_write,
	.read	= reset_read,
	.llseek = noop_llseek,
};

/* debugfs.c */
static const struct file_operations dfs_irq_ops = {
	.open		= irq_debug_open,
	.write		= irq_debug_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* msi.c */
static const struct irq_domain_ops msi_domain_ops = {
	.alloc		= msi_domain_alloc,
	.free		= msi_domain_free,
	.activate	= msi_domain_activate,
	.deactivate	= msi_domain_deactivate,
};

/* proc.c */
static const struct file_operations irq_affinity_proc_fops = {
	.open		= irq_affinity_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= irq_affinity_proc_write,
};

/* proc.c */
static const struct file_operations irq_affinity_list_proc_fops = {
	.open		= irq_affinity_list_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= irq_affinity_list_proc_write,
};

/* proc.c */
static const struct file_operations default_affinity_proc_fops = {
	.open		= default_affinity_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= default_affinity_write,
};

/* kallsym.c */
static const struct seq_operations kallsyms_op = {
	.start = s_start,
	.next = s_next,
	.stop = s_stop,
	.show = s_show
};

/* kallsym.c */
static const struct file_operations kallsyms_operations = {
	.open = kallsyms_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

/* kcov.c */
static const struct file_operations kcov_fops = {
	.open		= kcov_open,
	.unlocked_ioctl	= kcov_ioctl,
	.compat_ioctl	= kcov_ioctl,
	.mmap		= kcov_mmap,
	.release        = kcov_close,
};

/* kprobes.c */
static const struct seq_operations kprobes_seq_ops = {
	.start = kprobe_seq_start,
	.next  = kprobe_seq_next,
	.stop  = kprobe_seq_stop,
	.show  = show_kprobe_addr
};

/* kprobes.c */
static const struct file_operations debugfs_kprobes_operations = {
	.open           = kprobes_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

/* kprobes.c */
static const struct seq_operations kprobe_blacklist_seq_ops = {
	.start = kprobe_blacklist_seq_start,
	.next  = kprobe_blacklist_seq_next,
	.stop  = kprobe_seq_stop,	/* Reuse void function */
	.show  = kprobe_blacklist_seq_show,
};

/* kprobes.c */
static const struct file_operations debugfs_kprobe_blacklist_ops = {
	.open           = kprobe_blacklist_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

/* kprobes.c */
static const struct file_operations fops_kp = {
	.read =         read_enabled_file_bool,
	.write =        write_enabled_file_bool,
	.llseek =	default_llseek,
};

/* latencytop.c */
static const struct file_operations lstats_fops = {
	.open		= lstats_open,
	.read		= seq_read,
	.write		= lstats_write,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* lockdep_proc.c */
static const struct seq_operations lockdep_ops = {
	.start	= l_start,
	.next	= l_next,
	.stop	= l_stop,
	.show	= l_show,
};

/* lockdep_proc.c */
static const struct seq_operations lockdep_chains_ops = {
	.start	= lc_start,
	.next	= lc_next,
	.stop	= lc_stop,
	.show	= lc_show,
};

/* lockdep_proc.c */
static const struct seq_operations lockstat_ops = {
	.start	= ls_start,
	.next	= ls_next,
	.stop	= ls_stop,
	.show	= ls_show,
};

/* lockdep_proc.c */
static const struct file_operations proc_lock_stat_operations = {
	.open		= lock_stat_open,
	.write		= lock_stat_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= lock_stat_release,
};

/* qspinlock_stat.h */
static const struct file_operations fops_qstat = {
	.read = qstat_read,
	.write = qstat_write,
	.llseek = default_llseek,
};

/* module.c */
static const struct latch_tree_ops mod_tree_ops = {
	.less = mod_tree_less,
	.comp = mod_tree_comp,
};

/* module.c */
static const struct seq_operations modules_op = {
	.start	= m_start,
	.next	= m_next,
	.stop	= m_stop,
	.show	= m_show
};

/* module.c */
static const struct file_operations proc_modules_operations = {
	.open		= modules_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* padata.c */
static const struct sysfs_ops padata_sysfs_ops = {
	.show = padata_sysfs_show,
	.store = padata_sysfs_store,
};

/* padata.c */
static struct kobj_type padata_attr_type = {
	.sysfs_ops = &padata_sysfs_ops,
	.default_attrs = padata_default_attrs,
	.release = padata_sysfs_release,
};

/* params.c */
static const struct sysfs_ops module_sysfs_ops = {
	.show = module_attr_show,
	.store = module_attr_store,
};

/* params.c */
struct kobj_type module_ktype = {
	.release   =	module_kobj_release,
	.sysfs_ops =	&module_sysfs_ops,
};

/* main.c */
static const struct file_operations suspend_stats_operations = {
	.open           = suspend_stats_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

/* qos.c */
static struct pm_qos_constraints cpu_dma_constraints = {
	.list = PLIST_HEAD_INIT(cpu_dma_constraints.list),
	.target_value = PM_QOS_CPU_DMA_LAT_DEFAULT_VALUE,
	.default_value = PM_QOS_CPU_DMA_LAT_DEFAULT_VALUE,
	.no_constraint_value = PM_QOS_CPU_DMA_LAT_DEFAULT_VALUE,
	.type = PM_QOS_MIN,
	.notifiers = &cpu_dma_lat_notifier,
};

/* qos.c */
static struct pm_qos_object cpu_dma_pm_qos = {
	.constraints = &cpu_dma_constraints,
	.name = "cpu_dma_latency",
};

/* qos.c */
static struct pm_qos_constraints network_lat_constraints = {
	.list = PLIST_HEAD_INIT(network_lat_constraints.list),
	.target_value = PM_QOS_NETWORK_LAT_DEFAULT_VALUE,
	.default_value = PM_QOS_NETWORK_LAT_DEFAULT_VALUE,
	.no_constraint_value = PM_QOS_NETWORK_LAT_DEFAULT_VALUE,
	.type = PM_QOS_MIN,
	.notifiers = &network_lat_notifier,
};

/* qos.c */
static struct pm_qos_object network_lat_pm_qos = {
	.constraints = &network_lat_constraints,
	.name = "network_latency",
};

/* qos.c */
static struct pm_qos_constraints network_tput_constraints = {
	.list = PLIST_HEAD_INIT(network_tput_constraints.list),
	.target_value = PM_QOS_NETWORK_THROUGHPUT_DEFAULT_VALUE,
	.default_value = PM_QOS_NETWORK_THROUGHPUT_DEFAULT_VALUE,
	.no_constraint_value = PM_QOS_NETWORK_THROUGHPUT_DEFAULT_VALUE,
	.type = PM_QOS_MAX,
	.notifiers = &network_throughput_notifier,
};

/* qos.c */
static struct pm_qos_object network_throughput_pm_qos = {
	.constraints = &network_tput_constraints,
	.name = "network_throughput",
};

/* qos.c */
static struct pm_qos_constraints memory_bw_constraints = {
	.list = PLIST_HEAD_INIT(memory_bw_constraints.list),
	.target_value = PM_QOS_MEMORY_BANDWIDTH_DEFAULT_VALUE,
	.default_value = PM_QOS_MEMORY_BANDWIDTH_DEFAULT_VALUE,
	.no_constraint_value = PM_QOS_MEMORY_BANDWIDTH_DEFAULT_VALUE,
	.type = PM_QOS_SUM,
	.notifiers = &memory_bandwidth_notifier,
};

/* qos.c */
static struct pm_qos_object memory_bandwidth_pm_qos = {
	.constraints = &memory_bw_constraints,
	.name = "memory_bandwidth",
};

/* qos.c */
static const struct file_operations pm_qos_power_fops = {
	.write = pm_qos_power_write,
	.read = pm_qos_power_read,
	.open = pm_qos_power_open,
	.release = pm_qos_power_release,
	.llseek = noop_llseek,
};

/* qos.c */
static const struct file_operations pm_qos_debug_fops = {
	.open           = pm_qos_dbg_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = single_release,
};

/* user.c */
static const struct file_operations snapshot_fops = {
	.open = snapshot_open,
	.release = snapshot_release,
	.read = snapshot_read,
	.write = snapshot_write,
	.llseek = no_llseek,
	.unlocked_ioctl = snapshot_ioctl,
#ifdef CONFIG_COMPAT
	.compat_ioctl = snapshot_compat_ioctl,
#endif
};

/* user.c */
static struct miscdevice snapshot_device = {
	.minor = SNAPSHOT_MINOR,
	.name = "snapshot",
	.fops = &snapshot_fops,
};

/* profile.c */
static const struct file_operations prof_cpu_mask_proc_fops = {
	.open		= prof_cpu_mask_proc_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
	.write		= prof_cpu_mask_proc_write,
};

/* profile.c */
static const struct file_operations proc_profile_operations = {
	.read		= read_profile,
	.write		= write_profile,
	.llseek		= default_llseek,
};

/* relay.c */
static const struct vm_operations_struct relay_file_mmap_ops = {
	.fault = relay_buf_fault,
	.close = relay_file_mmap_close,
};

/* relay.c */
static const struct pipe_buf_operations relay_pipe_buf_ops = {
	.can_merge = 0,
	.confirm = generic_pipe_buf_confirm,
	.release = relay_pipe_buf_release,
	.steal = generic_pipe_buf_steal,
	.get = generic_pipe_buf_get,
};

/* resource.c */
static const struct seq_operations resource_op = {
	.start	= r_start,
	.next	= r_next,
	.stop	= r_stop,
	.show	= r_show,
};

/* debug.c */
static const struct file_operations sched_feat_fops = {
	.open		= sched_feat_open,
	.write		= sched_feat_write,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* debug.c */
static const struct seq_operations sched_debug_sops = {
	.start		= sched_debug_start,
	.next		= sched_debug_next,
	.stop		= sched_debug_stop,
	.show		= sched_debug_show,
};

/* stats.c */
static const struct seq_operations schedstat_sops = {
	.start = schedstat_start,
	.next  = schedstat_next,
	.stop  = schedstat_stop,
	.show  = show_schedstat,
};

/* sysctl_binary.c */
struct bin_table {
	bin_convert_t		*convert;
	int			ctl_name;
	const char		*procname;
	const struct bin_table	*child;
};

/* sysctl_binary.c */
static const struct bin_table bin_random_table[] = {
	{ CTL_INT,	RANDOM_POOLSIZE,	"poolsize" },
	{ CTL_INT,	RANDOM_ENTROPY_COUNT,	"entropy_avail" },
	{ CTL_INT,	RANDOM_READ_THRESH,	"read_wakeup_threshold" },
	{ CTL_INT,	RANDOM_WRITE_THRESH,	"write_wakeup_threshold" },
	{ CTL_UUID,	RANDOM_BOOT_ID,		"boot_id" },
	{ CTL_UUID,	RANDOM_UUID,		"uuid" },
	{}
};

/* sysctl_binary.c */
static const struct bin_table bin_vm_table[] = {
	{ CTL_INT,	VM_OVERCOMMIT_MEMORY,		"overcommit_memory" },
	{ CTL_INT,	VM_PAGE_CLUSTER,		"page-cluster" },
	{ CTL_INT,	VM_DIRTY_BACKGROUND,		"dirty_background_ratio" },
	{ CTL_INT,	VM_DIRTY_RATIO,			"dirty_ratio" },
	/* VM_DIRTY_WB_CS "dirty_writeback_centisecs" no longer used */
	/* VM_DIRTY_EXPIRE_CS "dirty_expire_centisecs" no longer used */
	/* VM_NR_PDFLUSH_THREADS "nr_pdflush_threads" no longer used */
	{ CTL_INT,	VM_OVERCOMMIT_RATIO,		"overcommit_ratio" },
	/* VM_PAGEBUF unused */
	/* VM_HUGETLB_PAGES "nr_hugepages" no longer used */
	{ CTL_INT,	VM_SWAPPINESS,			"swappiness" },
	{ CTL_INT,	VM_LOWMEM_RESERVE_RATIO,	"lowmem_reserve_ratio" },
	{ CTL_INT,	VM_MIN_FREE_KBYTES,		"min_free_kbytes" },
	{ CTL_INT,	VM_MAX_MAP_COUNT,		"max_map_count" },
	{ CTL_INT,	VM_LAPTOP_MODE,			"laptop_mode" },
	{ CTL_INT,	VM_BLOCK_DUMP,			"block_dump" },
	{ CTL_INT,	VM_HUGETLB_GROUP,		"hugetlb_shm_group" },
	{ CTL_INT,	VM_VFS_CACHE_PRESSURE,	"vfs_cache_pressure" },
	{ CTL_INT,	VM_LEGACY_VA_LAYOUT,		"legacy_va_layout" },
	/* VM_SWAP_TOKEN_TIMEOUT unused */
	{ CTL_INT,	VM_DROP_PAGECACHE,		"drop_caches" },
	{ CTL_INT,	VM_PERCPU_PAGELIST_FRACTION,	"percpu_pagelist_fraction" },
	{ CTL_INT,	VM_ZONE_RECLAIM_MODE,		"zone_reclaim_mode" },
	{ CTL_INT,	VM_MIN_UNMAPPED,		"min_unmapped_ratio" },
	{ CTL_INT,	VM_PANIC_ON_OOM,		"panic_on_oom" },
	{ CTL_INT,	VM_VDSO_ENABLED,		"vdso_enabled" },
	{ CTL_INT,	VM_MIN_SLAB,			"min_slab_ratio" },

	{}
};

/* taskstats.c */
static const struct nla_policy taskstats_cmd_get_policy[TASKSTATS_CMD_ATTR_MAX+1] = {
	[TASKSTATS_CMD_ATTR_PID]  = { .type = NLA_U32 },
	[TASKSTATS_CMD_ATTR_TGID] = { .type = NLA_U32 },
	[TASKSTATS_CMD_ATTR_REGISTER_CPUMASK] = { .type = NLA_STRING },
	[TASKSTATS_CMD_ATTR_DEREGISTER_CPUMASK] = { .type = NLA_STRING },};

/* taskstats.c */
static const struct nla_policy cgroupstats_cmd_get_policy[TASKSTATS_CMD_ATTR_MAX+1] = {
	[CGROUPSTATS_CMD_ATTR_FD] = { .type = NLA_U32 },
};

/* taskstats.c */
static const struct genl_ops taskstats_ops[] = {
	{
		.cmd		= TASKSTATS_CMD_GET,
		.doit		= taskstats_user_cmd,
		.policy		= taskstats_cmd_get_policy,
		.flags		= GENL_ADMIN_PERM,
	},
	{
		.cmd		= CGROUPSTATS_CMD_GET,
		.doit		= cgroupstats_user_cmd,
		.policy		= cgroupstats_cmd_get_policy,
	},
};

/* taskstats.c */
static struct genl_family family __ro_after_init = {
	.name		= TASKSTATS_GENL_NAME,
	.version	= TASKSTATS_GENL_VERSION,
	.maxattr	= TASKSTATS_CMD_ATTR_MAX,
	.module		= THIS_MODULE,
	.ops		= taskstats_ops,
	.n_ops		= ARRAY_SIZE(taskstats_ops),
};

/* alarmtimer.c */
const struct k_clock alarm_clock = {
	.clock_getres		= alarm_clock_getres,
	.clock_get		= alarm_clock_get,
	.timer_create		= alarm_timer_create,
	.timer_set		= common_timer_set,
	.timer_del		= common_timer_del,
	.timer_get		= common_timer_get,
	.timer_arm		= alarm_timer_arm,
	.timer_rearm		= alarm_timer_rearm,
	.timer_forward		= alarm_timer_forward,
	.timer_remaining	= alarm_timer_remaining,
	.timer_try_to_cancel	= alarm_timer_try_to_cancel,
	.nsleep			= alarm_timer_nsleep,
};

/* alarmtimer.c */
static const struct dev_pm_ops alarmtimer_pm_ops = {
	.suspend = alarmtimer_suspend,
	.resume = alarmtimer_resume,
};

/* posix-clock.c */
static const struct file_operations posix_clock_file_operations = {
	.owner		= THIS_MODULE,
	.llseek		= no_llseek,
	.read		= posix_clock_read,
	.poll		= posix_clock_poll,
	.unlocked_ioctl	= posix_clock_ioctl,
	.open		= posix_clock_open,
	.release	= posix_clock_release,
#ifdef CONFIG_COMPAT
	.compat_ioctl	= posix_clock_compat_ioctl,
#endif
};

/* posix-timers.c */
static const struct k_clock clock_realtime = {
	.clock_getres		= posix_get_hrtimer_res,
	.clock_get		= posix_clock_realtime_get,
	.clock_set		= posix_clock_realtime_set,
	.clock_adj		= posix_clock_realtime_adj,
	.nsleep			= common_nsleep,
	.timer_create		= common_timer_create,
	.timer_set		= common_timer_set,
	.timer_get		= common_timer_get,
	.timer_del		= common_timer_del,
	.timer_rearm		= common_hrtimer_rearm,
	.timer_forward		= common_hrtimer_forward,
	.timer_remaining	= common_hrtimer_remaining,
	.timer_try_to_cancel	= common_hrtimer_try_to_cancel,
	.timer_arm		= common_hrtimer_arm,
};

/* posix-timers.c */
static const struct k_clock clock_monotonic = {
	.clock_getres		= posix_get_hrtimer_res,
	.clock_get		= posix_ktime_get_ts,
	.nsleep			= common_nsleep,
	.timer_create		= common_timer_create,
	.timer_set		= common_timer_set,
	.timer_get		= common_timer_get,
	.timer_del		= common_timer_del,
	.timer_rearm		= common_hrtimer_rearm,
	.timer_forward		= common_hrtimer_forward,
	.timer_remaining	= common_hrtimer_remaining,
	.timer_try_to_cancel	= common_hrtimer_try_to_cancel,
	.timer_arm		= common_hrtimer_arm,
};

/* posix-timers.c */
static const struct k_clock clock_monotonic_raw = {
	.clock_getres		= posix_get_hrtimer_res,
	.clock_get		= posix_get_monotonic_raw,
};

/* posix-timers.c */
static const struct k_clock clock_realtime_coarse = {
	.clock_getres		= posix_get_coarse_res,
	.clock_get		= posix_get_realtime_coarse,
};

/* posix-timers.c */
static const struct k_clock clock_monotonic_coarse = {
	.clock_getres		= posix_get_coarse_res,
	.clock_get		= posix_get_monotonic_coarse,
};

/* posix-timers.c */
static const struct k_clock clock_tai = {
	.clock_getres		= posix_get_hrtimer_res,
	.clock_get		= posix_get_tai,
	.nsleep			= common_nsleep,
	.timer_create		= common_timer_create,
	.timer_set		= common_timer_set,
	.timer_get		= common_timer_get,
	.timer_del		= common_timer_del,
	.timer_rearm		= common_hrtimer_rearm,
	.timer_forward		= common_hrtimer_forward,
	.timer_remaining	= common_hrtimer_remaining,
	.timer_try_to_cancel	= common_hrtimer_try_to_cancel,
	.timer_arm		= common_hrtimer_arm,
};

/* posix-timers.c */
static const struct k_clock clock_boottime = {
	.clock_getres		= posix_get_hrtimer_res,
	.clock_get		= posix_get_boottime,
	.nsleep			= common_nsleep,
	.timer_create		= common_timer_create,
	.timer_set		= common_timer_set,
	.timer_get		= common_timer_get,
	.timer_del		= common_timer_del,
	.timer_rearm		= common_hrtimer_rearm,
	.timer_forward		= common_hrtimer_forward,
	.timer_remaining	= common_hrtimer_remaining,
	.timer_try_to_cancel	= common_hrtimer_try_to_cancel,
	.timer_arm		= common_hrtimer_arm,
};

/* posix-timers.c */
static const struct k_clock * const posix_clocks[] = {
	[CLOCK_REALTIME]		= &clock_realtime,
	[CLOCK_MONOTONIC]		= &clock_monotonic,
	[CLOCK_PROCESS_CPUTIME_ID]	= &clock_process,
	[CLOCK_THREAD_CPUTIME_ID]	= &clock_thread,
	[CLOCK_MONOTONIC_RAW]		= &clock_monotonic_raw,
	[CLOCK_REALTIME_COARSE]		= &clock_realtime_coarse,
	[CLOCK_MONOTONIC_COARSE]	= &clock_monotonic_coarse,
	[CLOCK_BOOTTIME]		= &clock_boottime,
	[CLOCK_REALTIME_ALARM]		= &alarm_clock,
	[CLOCK_BOOTTIME_ALARM]		= &alarm_clock,
	[CLOCK_TAI]			= &clock_tai,
};

/* test_udelay.c */
static const struct file_operations udelay_test_debugfs_ops = {
	.owner = THIS_MODULE,
	.open = udelay_test_open,
	.read = seq_read,
	.write = udelay_test_write,
	.llseek = seq_lseek,
	.release = single_release,
};

/* timekeeping_debug.c */
static const struct file_operations tk_debug_sleep_time_fops = {
	.open		= tk_debug_sleep_time_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= single_release,
};

/* timer_list.c */
static const struct seq_operations timer_list_sops = {
	.start = timer_list_start,
	.next = timer_list_next,
	.stop = timer_list_stop,
	.show = timer_list_show,
};

/* blktrace.c */
static const struct file_operations blk_dropped_fops = {
	.owner =	THIS_MODULE,
	.open =		simple_open,
	.read =		blk_dropped_read,
	.llseek =	default_llseek,
};

/* blktrace.c */
static const struct file_operations blk_msg_fops = {
	.owner =	THIS_MODULE,
	.open =		simple_open,
	.write =	blk_msg_write,
	.llseek =	noop_llseek,
};

/* blktrace.c */
static const struct {
	int mask;
	const char *str;
} mask_maps[] = {
	{ BLK_TC_READ,		"read"		},
	{ BLK_TC_WRITE,		"write"		},
	{ BLK_TC_FLUSH,		"flush"		},
	{ BLK_TC_SYNC,		"sync"		},
	{ BLK_TC_QUEUE,		"queue"		},
	{ BLK_TC_REQUEUE,	"requeue"	},
	{ BLK_TC_ISSUE,		"issue"		},
	{ BLK_TC_COMPLETE,	"complete"	},
	{ BLK_TC_FS,		"fs"		},
	{ BLK_TC_PC,		"pc"		},
	{ BLK_TC_NOTIFY,	"notify"	},
	{ BLK_TC_AHEAD,		"ahead"		},
	{ BLK_TC_META,		"meta"		},
	{ BLK_TC_DISCARD,	"discard"	},
	{ BLK_TC_DRV_DATA,	"drv_data"	},
	{ BLK_TC_FUA,		"fua"		},
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_override_return_proto = {
	.func		= bpf_override_return,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_probe_read_proto = {
	.func		= bpf_probe_read,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_probe_write_user_proto = {
	.func		= bpf_probe_write_user,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_ANYTHING,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_trace_printk_proto = {
	.func		= bpf_trace_printk,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_MEM,
	.arg2_type	= ARG_CONST_SIZE,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_perf_event_read_proto = {
	.func		= bpf_perf_event_read,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_perf_event_read_value_proto = {
	.func		= bpf_perf_event_read_value,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_CONST_MAP_PTR,
	.arg2_type	= ARG_ANYTHING,
	.arg3_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg4_type	= ARG_CONST_SIZE,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_perf_event_output_proto = {
	.func		= bpf_perf_event_output,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_get_current_task_proto = {
	.func		= bpf_get_current_task,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_current_task_under_cgroup_proto = {
	.func           = bpf_current_task_under_cgroup,
	.gpl_only       = false,
	.ret_type       = RET_INTEGER,
	.arg1_type      = ARG_CONST_MAP_PTR,
	.arg2_type      = ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_probe_read_str_proto = {
	.func		= bpf_probe_read_str,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg2_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg3_type	= ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_perf_event_output_proto_tp = {
	.func		= bpf_perf_event_output_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_get_stackid_proto_tp = {
	.func		= bpf_get_stackid_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_get_stack_proto_tp = {
	.func		= bpf_get_stack_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_UNINIT_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_perf_prog_read_value_proto = {
         .func           = bpf_perf_prog_read_value,
         .gpl_only       = true,
         .ret_type       = RET_INTEGER,
         .arg1_type      = ARG_PTR_TO_CTX,
         .arg2_type      = ARG_PTR_TO_UNINIT_MEM,
         .arg3_type      = ARG_CONST_SIZE,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_perf_event_output_proto_raw_tp = {
	.func		= bpf_perf_event_output_raw_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
	.arg4_type	= ARG_PTR_TO_MEM,
	.arg5_type	= ARG_CONST_SIZE_OR_ZERO,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_get_stackid_proto_raw_tp = {
	.func		= bpf_get_stackid_raw_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_CONST_MAP_PTR,
	.arg3_type	= ARG_ANYTHING,
};

/* bpf_trace.c */
static const struct bpf_func_proto bpf_get_stack_proto_raw_tp = {
	.func		= bpf_get_stack_raw_tp,
	.gpl_only	= true,
	.ret_type	= RET_INTEGER,
	.arg1_type	= ARG_PTR_TO_CTX,
	.arg2_type	= ARG_PTR_TO_MEM,
	.arg3_type	= ARG_CONST_SIZE_OR_ZERO,
	.arg4_type	= ARG_ANYTHING,
};

/* ftrace.c */
static const struct file_operations ftrace_profile_fops = {
	.open		= tracing_open_generic,
	.read		= ftrace_profile_read,
	.write		= ftrace_profile_write,
	.llseek		= default_llseek,
};

/* ftrace.c */
static struct tracer_stat function_stats __initdata = {
	.name		= "functions",
	.stat_start	= function_stat_start,
	.stat_next	= function_stat_next,
	.stat_cmp	= function_stat_cmp,
	.stat_headers	= function_stat_headers,
	.stat_show	= function_stat_show
};

/* ftrace.c */
static const struct seq_operations show_ftrace_seq_ops = {
	.start = t_start,
	.next = t_next,
	.stop = t_stop,
	.show = t_show,
};

/* ftrace.c */
static const struct file_operations ftrace_avail_fops = {
	.open = ftrace_avail_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

/* ftrace.c */
static const struct file_operations ftrace_enabled_fops = {
	.open = ftrace_enabled_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
};

/* ftrace.c */
static const struct file_operations ftrace_filter_fops = {
	.open = ftrace_filter_open,
	.read = seq_read,
	.write = ftrace_filter_write,
	.llseek = tracing_lseek,
	.release = ftrace_regex_release,
};

/* ftrace.c */
static const struct file_operations ftrace_notrace_fops = {
	.open = ftrace_notrace_open,
	.read = seq_read,
	.write = ftrace_notrace_write,
	.llseek = tracing_lseek,
	.release = ftrace_regex_release,
};

/* ftrace.c */
static const struct seq_operations ftrace_graph_seq_ops = {
	.start = g_start,
	.next = g_next,
	.stop = g_stop,
	.show = g_show,
};

/* ftrace.c */
static const struct file_operations ftrace_graph_fops = {
	.open		= ftrace_graph_open,
	.read		= seq_read,
	.write		= ftrace_graph_write,
	.llseek		= tracing_lseek,
	.release	= ftrace_graph_release,
};

/* ftrace.c */
static const struct file_operations ftrace_graph_notrace_fops = {
	.open		= ftrace_graph_notrace_open,
	.read		= seq_read,
	.write		= ftrace_graph_write,
	.llseek		= tracing_lseek,
	.release	= ftrace_graph_release,
};

/* ftrace.c */
static const struct seq_operations ftrace_pid_sops = {
	.start = fpid_start,
	.next = fpid_next,
	.stop = fpid_stop,
	.show = fpid_show,
};

/* ftrace.c */
static const struct file_operations ftrace_pid_fops = {
	.open		= ftrace_pid_open,
	.write		= ftrace_pid_write,
	.read		= seq_read,
	.llseek		= tracing_lseek,
	.release	= ftrace_pid_release,
};

/* trace_events_hist.c */
static const struct seq_operations synth_events_seq_op = {
	.start  = synth_events_seq_start,
	.next   = synth_events_seq_next,
	.stop   = synth_events_seq_stop,
	.show   = synth_events_seq_show
};

/* trace_events_hist.c */
static const struct file_operations synth_events_fops = {
	.open           = synth_events_open,
	.write		= synth_events_write,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

/* trace_events_hist.c */
static const struct tracing_map_ops hist_trigger_elt_data_ops = {
	.elt_alloc	= hist_trigger_elt_data_alloc,
	.elt_free	= hist_trigger_elt_data_free,
	.elt_init	= hist_trigger_elt_data_init,
};

/* trace_events_trigger.c */
static const struct seq_operations event_triggers_seq_ops = {
	.start = trigger_start,
	.next = trigger_next,
	.stop = trigger_stop,
	.show = trigger_show,
};

/* trace_events.c */
static const struct seq_operations trace_format_seq_ops = {
	.start		= f_start,
	.next		= f_next,
	.stop		= f_stop,
	.show		= f_show,
};

/* trace_events.c */
static const struct seq_operations show_event_seq_ops = {
	.start = t_start,
	.next = t_next,
	.show = t_show,
	.stop = t_stop,
};

/* trace_events.c */
static const struct seq_operations show_set_event_seq_ops = {
	.start = s_start,
	.next = s_next,
	.show = t_show,
	.stop = t_stop,
};

/* trace_events.c */
static const struct seq_operations show_set_pid_seq_ops = {
	.start = p_start,
	.next = p_next,
	.show = trace_pid_show,
	.stop = p_stop,
};

/* trace_events.c */
static const struct file_operations ftrace_avail_fops = {
	.open = ftrace_event_avail_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/* trace_events.c */
static const struct file_operations ftrace_set_event_fops = {
	.open = ftrace_event_set_open,
	.read = seq_read,
	.write = ftrace_event_write,
	.llseek = seq_lseek,
	.release = ftrace_event_release,
};

/* trace_events.c */
static const struct file_operations ftrace_set_event_pid_fops = {
	.open = ftrace_event_set_pid_open,
	.read = seq_read,
	.write = ftrace_event_pid_write,
	.llseek = seq_lseek,
	.release = ftrace_event_release,
};

/* trace_events.c */
static const struct file_operations ftrace_enable_fops = {
	.open = tracing_open_generic,
	.read = event_enable_read,
	.write = event_enable_write,
	.llseek = default_llseek,
};

/* trace_events.c */
static const struct file_operations ftrace_event_format_fops = {
	.open = trace_format_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/* trace_events.c */
static const struct file_operations ftrace_event_id_fops = {
	.read = event_id_read,
	.llseek = default_llseek,
};

/* trace_events.c */
static const struct file_operations ftrace_event_filter_fops = {
	.open = tracing_open_generic,
	.read = event_filter_read,
	.write = event_filter_write,
	.llseek = default_llseek,
};

/* trace_events.c */
static const struct file_operations ftrace_subsystem_filter_fops = {
	.open = subsystem_open,
	.read = subsystem_filter_read,
	.write = subsystem_filter_write,
	.llseek = default_llseek,
	.release = subsystem_release,
};

/* trace_events.c */
static const struct file_operations ftrace_system_enable_fops = {
	.open = subsystem_open,
	.read = system_enable_read,
	.write = system_enable_write,
	.llseek = default_llseek,
	.release = subsystem_release,
};

/* trace_events.c */
static const struct file_operations ftrace_tr_enable_fops = {
	.open = system_tr_open,
	.read = system_enable_read,
	.write = system_enable_write,
	.llseek = default_llseek,
	.release = subsystem_release,
};

/* trace_events.c */
static const struct file_operations ftrace_show_header_fops = {
	.open = tracing_open_generic,
	.read = show_header,
	.llseek = default_llseek,
};

/* trace_functions_graph.c */
static const struct file_operations graph_depth_fops = {
	.open		= tracing_open_generic,
	.write		= graph_depth_write,
	.read		= graph_depth_read,
	.llseek		= generic_file_llseek,
};

/* trace_hwlat.c */
static const struct file_operations width_fops = {
	.open		= tracing_open_generic,
	.read		= hwlat_read,
	.write		= hwlat_width_write,
};

/* trace_hwlat.c */
static const struct file_operations window_fops = {
	.open		= tracing_open_generic,
	.read		= hwlat_read,
	.write		= hwlat_window_write,
};

/* trace_kprobe.c */
static const struct seq_operations probes_seq_op = {
	.start  = probes_seq_start,
	.next   = probes_seq_next,
	.stop   = probes_seq_stop,
	.show   = probes_seq_show
};

/* trace_kprobe.c */
static const struct file_operations kprobe_events_ops = {
	.owner          = THIS_MODULE,
	.open           = probes_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
	.write		= probes_write,
};

/* trace_kprobe.c */
static const struct seq_operations profile_seq_op = {
	.start  = probes_seq_start,
	.next   = probes_seq_next,
	.stop   = probes_seq_stop,
	.show   = probes_profile_seq_show
};

/* trace_kprobe.c */
static const struct file_operations kprobe_profile_ops = {
	.owner          = THIS_MODULE,
	.open           = profile_open,
	.read           = seq_read,
	.llseek         = seq_lseek,
	.release        = seq_release,
};

/* trace_output.c */
static const struct trace_mark {
	unsigned long long	val; /* unit: nsec */
	char			sym;
} mark[] = {
	MARK(1000000000ULL	, '$'), /* 1 sec */
	MARK(100000000ULL	, '@'), /* 100 msec */
	MARK(10000000ULL	, '*'), /* 10 msec */
	MARK(1000000ULL		, '#'), /* 1000 usecs */
	MARK(100000ULL		, '!'), /* 100 usecs */
	MARK(10000ULL		, '+'), /* 10 usecs */
};

/* trace_printk.c */
static const struct seq_operations show_format_seq_ops = {
	.start = t_start,
	.next = t_next,
	.show = t_show,
	.stop = t_stop,
};

/* trace_printk.c */
static const struct file_operations ftrace_formats_fops = {
	.open = ftrace_formats_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release,
};

/* trace_stack.c */
static const struct file_operations stack_max_size_fops = {
	.open		= tracing_open_generic,
	.read		= stack_max_size_read,
	.write		= stack_max_size_write,
	.llseek		= default_llseek,
};

/* trace_stack.c */
static const struct seq_operations stack_trace_seq_ops = {
	.start		= t_start,
	.next		= t_next,
	.stop		= t_stop,
	.show		= t_show,
};

/* trace_stack.c */
static const struct file_operations stack_trace_fops = {
	.open		= stack_trace_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* trace_stack.c */
static const struct file_operations stack_trace_filter_fops = {
	.open = stack_trace_filter_open,
	.read = seq_read,
	.write = ftrace_filter_write,
	.llseek = tracing_lseek,
	.release = ftrace_regex_release,
};

/* trace_stat.c */
static const struct seq_operations trace_stat_seq_ops = {
	.start		= stat_seq_start,
	.next		= stat_seq_next,
	.stop		= stat_seq_stop,
	.show		= stat_seq_show
};

/* trace_stat.c */
static const struct file_operations tracing_stat_fops = {
	.open		= tracing_stat_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= tracing_stat_release
};

/* trace_uprobe.c */
static const struct seq_operations probes_seq_op = {
	.start	= probes_seq_start,
	.next	= probes_seq_next,
	.stop	= probes_seq_stop,
	.show	= probes_seq_show
};

/* trace_uprobe.c */
static const struct file_operations uprobe_events_ops = {
	.owner		= THIS_MODULE,
	.open		= probes_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
	.write		= probes_write,
};

/* trace_uprobe.c */
static const struct seq_operations profile_seq_op = {
	.start	= probes_seq_start,
	.next	= probes_seq_next,
	.stop	= probes_seq_stop,
	.show	= probes_profile_seq_show
};

/* trace_uprobe.c */
static const struct file_operations uprobe_profile_ops = {
	.owner		= THIS_MODULE,
	.open		= profile_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* trace.c */
static const struct seq_operations tracer_seq_ops = {
	.start		= s_start,
	.next		= s_next,
	.stop		= s_stop,
	.show		= s_show,
};

/* trace.c */
static const struct seq_operations show_traces_seq_ops = {
	.start		= t_start,
	.next		= t_next,
	.stop		= t_stop,
	.show		= t_show,
};

/* trace.c */
static const struct file_operations tracing_fops = {
	.open		= tracing_open,
	.read		= seq_read,
	.write		= tracing_write_stub,
	.llseek		= tracing_lseek,
	.release	= tracing_release,
};

/* trace.c */
static const struct file_operations show_traces_fops = {
	.open		= show_traces_open,
	.read		= seq_read,
	.release	= seq_release,
	.llseek		= seq_lseek,
};

/* trace.c */
static const struct file_operations tracing_cpumask_fops = {
	.open		= tracing_open_generic_tr,
	.read		= tracing_cpumask_read,
	.write		= tracing_cpumask_write,
	.release	= tracing_release_generic_tr,
	.llseek		= generic_file_llseek,
};

/* trace.c */
static const struct file_operations tracing_iter_fops = {
	.open		= tracing_trace_options_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= tracing_single_release_tr,
	.write		= tracing_trace_options_write,
};

/* trace.c */
static const struct file_operations tracing_readme_fops = {
	.open		= tracing_open_generic,
	.read		= tracing_readme_read,
	.llseek		= generic_file_llseek,
};

/* trace.c */
static const struct seq_operations tracing_saved_tgids_seq_ops = {
	.start		= saved_tgids_start,
	.stop		= saved_tgids_stop,
	.next		= saved_tgids_next,
	.show		= saved_tgids_show,
};

/* trace.c */
static const struct file_operations tracing_saved_tgids_fops = {
	.open		= tracing_saved_tgids_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* trace.c */
static const struct seq_operations tracing_saved_cmdlines_seq_ops = {
	.start		= saved_cmdlines_start,
	.next		= saved_cmdlines_next,
	.stop		= saved_cmdlines_stop,
	.show		= saved_cmdlines_show,
};

/* trace.c */
static const struct file_operations tracing_saved_cmdlines_fops = {
	.open		= tracing_saved_cmdlines_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* trace.c */
static const struct file_operations tracing_saved_cmdlines_size_fops = {
	.open		= tracing_open_generic,
	.read		= tracing_saved_cmdlines_size_read,
	.write		= tracing_saved_cmdlines_size_write,
};

/* trace.c */
static const struct seq_operations tracing_eval_map_seq_ops = {
	.start		= eval_map_start,
	.next		= eval_map_next,
	.stop		= eval_map_stop,
	.show		= eval_map_show,
};

/* trace.c */
static const struct file_operations tracing_eval_map_fops = {
	.open		= tracing_eval_map_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= seq_release,
};

/* trace.c */
static const struct pipe_buf_operations tracing_pipe_buf_ops = {
	.can_merge		= 0,
	.confirm		= generic_pipe_buf_confirm,
	.release		= generic_pipe_buf_release,
	.steal			= generic_pipe_buf_steal,
	.get			= generic_pipe_buf_get,
};

/* trace.c */
static const struct file_operations tracing_thresh_fops = {
	.open		= tracing_open_generic,
	.read		= tracing_thresh_read,
	.write		= tracing_thresh_write,
	.llseek		= generic_file_llseek,
};

/* trace.c */
static const struct file_operations tracing_max_lat_fops = {
	.open		= tracing_open_generic,
	.read		= tracing_max_lat_read,
	.write		= tracing_max_lat_write,
	.llseek		= generic_file_llseek,
};

/* trace.c */
static const struct file_operations set_tracer_fops = {
	.open		= tracing_open_generic,
	.read		= tracing_set_trace_read,
	.write		= tracing_set_trace_write,
	.llseek		= generic_file_llseek,
};

/* trace.c */
static const struct file_operations tracing_pipe_fops = {
	.open		= tracing_open_pipe,
	.poll		= tracing_poll_pipe,
	.read		= tracing_read_pipe,
	.splice_read	= tracing_splice_read_pipe,
	.release	= tracing_release_pipe,
	.llseek		= no_llseek,
};

/* trace.c */
static const struct file_operations tracing_entries_fops = {
	.open		= tracing_open_generic_tr,
	.read		= tracing_entries_read,
	.write		= tracing_entries_write,
	.llseek		= generic_file_llseek,
	.release	= tracing_release_generic_tr,
};

/* trace.c */
static const struct file_operations tracing_total_entries_fops = {
	.open		= tracing_open_generic_tr,
	.read		= tracing_total_entries_read,
	.llseek		= generic_file_llseek,
	.release	= tracing_release_generic_tr,
};

/* trace.c */
static const struct file_operations tracing_free_buffer_fops = {
	.open		= tracing_open_generic_tr,
	.write		= tracing_free_buffer_write,
	.release	= tracing_free_buffer_release,
};

/* trace.c */
static const struct file_operations tracing_mark_fops = {
	.open		= tracing_open_generic_tr,
	.write		= tracing_mark_write,
	.llseek		= generic_file_llseek,
	.release	= tracing_release_generic_tr,
};

/* trace.c */
static const struct file_operations tracing_mark_raw_fops = {
	.open		= tracing_open_generic_tr,
	.write		= tracing_mark_raw_write,
	.llseek		= generic_file_llseek,
	.release	= tracing_release_generic_tr,
};

/* trace.c */
static const struct file_operations trace_clock_fops = {
	.open		= tracing_clock_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= tracing_single_release_tr,
	.write		= tracing_clock_write,
};

/* trace.c */
static const struct file_operations trace_time_stamp_mode_fops = {
	.open		= tracing_time_stamp_mode_open,
	.read		= seq_read,
	.llseek		= seq_lseek,
	.release	= tracing_single_release_tr,
};

/* trace.c */
static const struct file_operations snapshot_fops = {
	.open		= tracing_snapshot_open,
	.read		= seq_read,
	.write		= tracing_snapshot_write,
	.llseek		= tracing_lseek,
	.release	= tracing_snapshot_release,
};

/* trace.c */
static const struct file_operations snapshot_raw_fops = {
	.open		= snapshot_raw_open,
	.read		= tracing_buffers_read,
	.release	= tracing_buffers_release,
	.splice_read	= tracing_buffers_splice_read,
	.llseek		= no_llseek,
};

/* trace.c */
static const struct pipe_buf_operations buffer_pipe_buf_ops = {
	.can_merge		= 0,
	.confirm		= generic_pipe_buf_confirm,
	.release		= buffer_pipe_buf_release,
	.steal			= generic_pipe_buf_steal,
	.get			= buffer_pipe_buf_get,
};

/* trace.c */
static const struct file_operations tracing_buffers_fops = {
	.open		= tracing_buffers_open,
	.read		= tracing_buffers_read,
	.poll		= tracing_buffers_poll,
	.release	= tracing_buffers_release,
	.splice_read	= tracing_buffers_splice_read,
	.llseek		= no_llseek,
};

/* trace.c */
static const struct file_operations tracing_stats_fops = {
	.open		= tracing_open_generic_tr,
	.read		= tracing_stats_read,
	.llseek		= generic_file_llseek,
	.release	= tracing_release_generic_tr,
};

/* trace.c */
static const struct file_operations tracing_dyn_info_fops = {
	.open		= tracing_open_generic,
	.read		= tracing_read_dyn_info,
	.llseek		= generic_file_llseek,
};

/* trace.c */
static const struct file_operations trace_options_fops = {
	.open = tracing_open_generic,
	.read = trace_options_read,
	.write = trace_options_write,
	.llseek	= generic_file_llseek,
};

/* trace.c */
static const struct file_operations trace_options_core_fops = {
	.open = tracing_open_generic,
	.read = trace_options_core_read,
	.write = trace_options_core_write,
	.llseek = generic_file_llseek,
};

/* trace.c */
static const struct file_operations rb_simple_fops = {
	.open		= tracing_open_generic_tr,
	.read		= rb_simple_read,
	.write		= rb_simple_write,
	.release	= tracing_release_generic_tr,
	.llseek		= default_llseek,
};

/* workqueue.c */
static const struct kernel_param_ops wq_watchdog_thresh_ops = {
	.set	= wq_watchdog_param_set_thresh,
	.get	= param_get_ulong,
};
