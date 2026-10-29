"""Prepare the pinned kernel's privileged platform-notifier experiment on a copy.

Application filters run first, preserving their original action semantics. A
separate, privileged ALLOW/USER_NOTIF domain then services the platform profile
without occupying the application's notification-listener slot.
"""
import argparse
import difflib
import hashlib
import json
from pathlib import Path

SOURCE_SHA256 = "dbaa4efdab114c9a2a081f672bc1d354cfb519f99d1c1a5689422fa37e2ed072"


def change(source, before, after):
    if source.count(before) != 1:
        raise ValueError(f"Unexpected pinned source shape: {before[:90]!r}")
    return source.replace(before, after)


def prepare(source):
    original = source
    if hashlib.sha256(source.encode()).hexdigest() != SOURCE_SHA256:
        raise ValueError("The kernel seccomp source differs from the pinned baseline")
    source = change(source, '#include <linux/seccomp.h>', '''#include <linux/seccomp.h>
#include <linux/user_namespace.h>

/* Private laboratory ABI; never granted through no_new_privs alone. */
#define SECCOMP_FILTER_FLAG_PLATFORM_SUPERVISOR (1U << 31)

struct seccomp_platform_info {
\t__u64 flags;
\t__u64 program_length;
};
#define SECCOMP_IOCTL_PLATFORM_INFO \\
\t_IOR(SECCOMP_IOC_MAGIC, 0x7f, struct seccomp_platform_info)''')
    source = change(source, '\tbool wait_killable_recv;\n', '''\tbool wait_killable_recv;
\tbool platform_supervisor;
\tbool has_platform_supervisor;
''')
    source = change(source, '''static u32 seccomp_run_filters(const struct seccomp_data *sd,
\t\t\t       struct seccomp_filter **match)''', '''static u32 seccomp_run_filters(const struct seccomp_data *sd,
\t\t\t       struct seccomp_filter **match,
\t\t\t       bool platform_supervisor)''')
    source = change(source, '''\tfor (; f; f = f->prev) {
\t\tu32 cur_ret = bpf_prog_run_pin_on_cpu(f->prog, sd);
''', '''\tfor (; f; f = f->prev) {
\t\tu32 cur_ret;

\t\tif (f->platform_supervisor != platform_supervisor)
\t\t\tcontinue;
\t\tcur_ret = bpf_prog_run_pin_on_cpu(f->prog, sd);
''')
    source = change(source, '''/**
 * seccomp_prepare_filter: Prepares a seccomp filter for use.
 * @fprog: BPF program to install
 *
 * Returns filter on success or an ERR_PTR on failure.
 */
static struct seccomp_filter *seccomp_prepare_filter(struct sock_fprog *fprog)''', '''/* Platform mediation cannot introduce application security actions. */
static bool seccomp_platform_program_valid(struct bpf_prog *prog)
{
\tconst struct sock_fprog_kern *original = prog->orig_prog;
\tunsigned int i;

\tif (!original)
\t\treturn false;
\tfor (i = 0; i < original->len; i++) {
\t\tconst struct sock_filter *instruction = &original->filter[i];

\t\tif (BPF_CLASS(instruction->code) != BPF_RET)
\t\t\tcontinue;
\t\tif (instruction->code != (BPF_RET | BPF_K) ||
\t\t    (instruction->k != SECCOMP_RET_ALLOW &&
\t\t     instruction->k != SECCOMP_RET_USER_NOTIF))
\t\t\treturn false;
\t}
\treturn true;
}

/**
 * seccomp_prepare_filter: Prepares a seccomp filter for use.
 * @fprog: BPF program to install
 * @platform_supervisor: privileged, separate notification domain
 *
 * Returns filter on success or an ERR_PTR on failure.
 */
static struct seccomp_filter *seccomp_prepare_filter(struct sock_fprog *fprog,
\t\t\t\t\t\t  bool platform_supervisor)''')
    source = change(source, '''\t\t\t\t\tseccomp_check_filter, save_orig);''', '''\t\t\t\t\tseccomp_check_filter,
\t\t\t\t\tsave_orig || platform_supervisor);''')
    source = change(source, '''\trefcount_set(&sfilter->refs, 1);''', '''\tif (platform_supervisor && !seccomp_platform_program_valid(sfilter->prog)) {
\t\tbpf_prog_destroy(sfilter->prog);
\t\tkfree(sfilter);
\t\treturn ERR_PTR(-EINVAL);
\t}
\tsfilter->platform_supervisor = platform_supervisor;
\trefcount_set(&sfilter->refs, 1);''')
    source = change(source, '''seccomp_prepare_user_filter(const char __user *user_filter)''', '''seccomp_prepare_user_filter(const char __user *user_filter,
\t\t\t    bool platform_supervisor)''')
    source = change(source, '''\tfilter = seccomp_prepare_filter(&fprog);''', '''\tfilter = seccomp_prepare_filter(&fprog, platform_supervisor);''')
    source = change(source, '''\tfilter->prev = current->seccomp.filter;
\tseccomp_cache_prepare(filter);''', '''\tfilter->prev = current->seccomp.filter;
\tfilter->has_platform_supervisor = filter->platform_supervisor ||
\t\t(filter->prev && filter->prev->has_platform_supervisor);
\tseccomp_cache_prepare(filter);''')
    source = change(source, '''static int __seccomp_filter(int this_syscall, const struct seccomp_data *sd,
\t\t\t    const bool recheck_after_trace)
{
\tu32 filter_ret, action;''', '''static int __seccomp_filter_domain(int this_syscall,
\t\t\t\t   const struct seccomp_data *sd,
\t\t\t\t   const bool recheck_after_trace,
\t\t\t\t   bool platform_supervisor)
{
\tu32 filter_ret, action;''')
    source = change(source, '''\tfilter_ret = seccomp_run_filters(sd, &match);''', '''\tfilter_ret = seccomp_run_filters(sd, &match, platform_supervisor);''')
    source = change(source, '''\t\tif (__seccomp_filter(this_syscall, NULL, true))''', '''\t\tif (__seccomp_filter_domain(this_syscall, NULL, true,
\t\t\t\t\t    platform_supervisor))''')
    source = change(source, '''\tseccomp_log(this_syscall, 0, action, match ? match->log : false);
\treturn -1;
}
#else''', '''\tseccomp_log(this_syscall, 0, action, match ? match->log : false);
\treturn -1;
}

static int __seccomp_filter(int this_syscall, const struct seccomp_data *sd,
\t\t\t    const bool recheck_after_trace)
{
\tstruct seccomp_filter *head;

\t/* Application denials and synthetic returns always take precedence. */
\tif (__seccomp_filter_domain(this_syscall, sd, recheck_after_trace, false))
\t\treturn -1;
\thead = READ_ONCE(current->seccomp.filter);
\tif (!head->has_platform_supervisor)
\t\treturn 0;

\t/* Reload registers after TRACE or a notification's CONTINUE response. */
\tthis_syscall = syscall_get_nr(current, current_pt_regs());
\treturn __seccomp_filter_domain(this_syscall, NULL, false, true);
}
#else''')
    source = change(source, '''\t\tif (cur->notif)
\t\t\treturn true;''', '''\t\tif (cur->notif && cur->platform_supervisor == new_child->platform_supervisor)
\t\t\treturn true;''')
    source = change(source, '''\tstruct seccomp_filter *filter = file->private_data;
\tvoid __user *buf = (void __user *)arg;

\t/* Fixed-size ioctls */''', '''\tstruct seccomp_filter *filter = file->private_data;
\tvoid __user *buf = (void __user *)arg;

\tif (filter->platform_supervisor &&
\t    !ns_capable_noaudit(&init_user_ns, CAP_SYS_ADMIN))
\t\treturn -EINVAL;
\tif (cmd == SECCOMP_IOCTL_PLATFORM_INFO) {
\t\tstruct seccomp_platform_info info = {};

\t\t/* Ordinary listener descriptors retain their unknown-ioctl result. */
\t\tif (!filter->platform_supervisor)
\t\t\treturn -EINVAL;
\t\tinfo.flags = SECCOMP_FILTER_FLAG_PLATFORM_SUPERVISOR;
\t\tinfo.program_length = filter->prog->orig_prog->len;
\t\treturn copy_to_user(buf, &info, sizeof(info)) ? -EFAULT : 0;
\t}

\t/* Fixed-size ioctls */''')
    source = change(source, '''\t/* Validate flags. */
\tif (flags & ~SECCOMP_FILTER_FLAG_MASK)
\t\treturn -EINVAL;''', '''\t/* The private domain is available only to an initial-namespace admin. */
\tif (flags & ~(SECCOMP_FILTER_FLAG_MASK |
\t\t      SECCOMP_FILTER_FLAG_PLATFORM_SUPERVISOR))
\t\treturn -EINVAL;
\tif ((flags & SECCOMP_FILTER_FLAG_PLATFORM_SUPERVISOR) &&
\t    (task_no_new_privs(current) ||
\t     !ns_capable_noaudit(&init_user_ns, CAP_SYS_ADMIN) ||
\t     !(flags & SECCOMP_FILTER_FLAG_NEW_LISTENER)))
\t\treturn -EINVAL;''')
    source = change(source, '''\tprepared = seccomp_prepare_user_filter(filter);''', '''\tprepared = seccomp_prepare_user_filter(filter,
\t\tflags & SECCOMP_FILTER_FLAG_PLATFORM_SUPERVISOR);''')
    source = change(source, '''\tif (filter->log)
\t\tkmd.flags |= SECCOMP_FILTER_FLAG_LOG;
''', '''\tif (filter->log)
\t\tkmd.flags |= SECCOMP_FILTER_FLAG_LOG;
\tif (filter->platform_supervisor)
\t\tkmd.flags |= SECCOMP_FILTER_FLAG_PLATFORM_SUPERVISOR;
''')
    return original, source


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--patch', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    before, after = prepare(args.source.read_text(encoding='utf-8-sig'))
    args.output.write_text(after, encoding='utf-8', newline='\n')
    args.patch.write_text(''.join(difflib.unified_diff(before.splitlines(True), after.splitlines(True), fromfile='a/kernel/seccomp.c', tofile='b/kernel/seccomp.c')), encoding='utf-8', newline='\n')
    report = {'original_normalized_sha256':SOURCE_SHA256,'modified_sha256':hashlib.sha256(after.encode()).hexdigest(),'private_flag':'0x80000000','platform_info_ioctl':'0x8010217f','initial_namespace_admin_required':True,'no_new_privs_not_sufficient':True,'platform_descriptor_ioctls_require_admin':True,'application_filters_evaluated_first':True,'normal_duplicate_listener_rule_preserved':True,'platform_return_actions':['ALLOW','USER_NOTIF'],'all_filters_remain_counted_and_root_metadata_reports_domain':True,'runtime_verified':False}
    args.report.write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report))


if __name__ == '__main__':
    main()
