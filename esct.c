#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kprobes.h>
#include <linux/kobject.h>
#include <linux/sysfs.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/mutex.h>

static struct jprobe esct_probe;
static pid_t pid_to_track;

struct trace_struct {
	char data[PAGE_SIZE];
	size_t size;
	struct mutex tlock;
};

static struct trace_struct tinfo;

static ssize_t pid_read(struct kobject *kobj, struct kobj_attribute *attr,
		                char *buf)
{
	return sprintf(buf, "%d", pid_to_track);
}

static ssize_t pid_write(struct kobject *kobj, struct kobj_attribute *attr,
		                const char *buf, size_t count)
{
	long n;

	if (kstrtol(buf, 10, &n) == 0)
		pid_to_track = n;

	return count;
}

static ssize_t trace_read(struct kobject *kobj, struct kobj_attribute *attr,
				char *buf)
{
	size_t sz;

	mutex_lock(&tinfo.tlock);

	sz = tinfo.size;
	memcpy(buf, tinfo.data, sz);
	tinfo.size = 0;

	mutex_unlock(&tinfo.tlock);

	return sz;
}

static struct kobj_attribute pid_attribute = __ATTR(pid, 0644, pid_read, pid_write);
/* NOTE: consider using netlink socket instead */
static struct kobj_attribute trace_attribute = __ATTR(trace, 0444, trace_read, NULL);

static struct attribute *attrs[] = {
        &pid_attribute.attr,
	&trace_attribute.attr,
        NULL,
};

static struct attribute_group attr_group = {
        .attrs = attrs,
};

long esct_sys_open(const char __user *filename, int flags, umode_t mode)
{
	char fn[256];

	copy_from_user(fn, filename, strnlen_user(filename, 256));
	if (task_pid_nr(current) == pid_to_track) {
		mutex_lock(&tinfo.tlock);
		if (tinfo.size < PAGE_SIZE - 1)
			tinfo.size += snprintf(tinfo.data + tinfo.size, PAGE_SIZE - tinfo.size - 1,
				"%d|sys_open(%s)\n", task_pid_nr(current), fn);
		mutex_unlock(&tinfo.tlock);
	}

	jprobe_return();
}

static struct kobject *esct_kobj;

int __init esct_init(void)
{
	int retval;

	mutex_init(&tinfo.tlock);
	esct_probe.kp.addr = (kprobe_opcode_t *)kallsyms_lookup_name("sys_open");
	esct_probe.entry = (kprobe_opcode_t *)esct_sys_open;
	register_jprobe(&esct_probe);

	esct_kobj = kobject_create_and_add("esct", kernel_kobj);
        if (!esct_kobj)
                return -ENOMEM;

        retval = sysfs_create_group(esct_kobj, &attr_group);
        if (retval)
                kobject_put(esct_kobj);

        return retval;
}
 
void __exit esct_exit(void)
{
	kobject_put(esct_kobj);
	unregister_jprobe(&esct_probe);
}
 
module_init(esct_init);
module_exit(esct_exit);
 
MODULE_AUTHOR("Okash Khawaja");
MODULE_DESCRIPTION("Experimental System Call Tracer");
MODULE_LICENSE("GPL");
