// cc -lprocstat
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

#include <sys/user.h>
#include <sys/stat.h>
#include <sys/sysctl.h>

#include <err.h>
#include <libprocstat.h>
#include <limits.h>
#include <pwd.h>
#include <dirent.h>

static int	checkfile; /* restrict to particular files or filesystems */
static int	mflg;	/* include memory-mapped files */

uint64_t	fsid;
uint64_t	ino;
char		*name;

static char *memf, *nlistf;

int getfname(char *filename);
pid_t dofiles(struct procstat *procstat, struct kinfo_proc *p);
pid_t print_file_info(struct procstat *procstat,
    struct filestat *fst, const char *uname, const char *cmd, int pid);

pid_t
dofiles(struct procstat *procstat, struct kinfo_proc *kp)
{
	const char *cmd;
	const char *uname;
	struct filestat *fst = NULL;
	struct filestat_list *head;
	pid_t pid = 0;
	pid_t vm_pid = 0;

	uname = user_from_uid(kp->ki_uid, 0);
	pid = kp->ki_pid;
	cmd = kp->ki_comm;

	head = procstat_getfiles(procstat, kp, mflg);
	if (head == NULL)
		return -1;
	STAILQ_FOREACH(fst, head, next) {
		//processing only for bhyve command
		if (!strcmp(cmd,"bhyve")) {
			vm_pid = print_file_info(procstat, fst, uname, cmd, pid);
			if (vm_pid > 0) break;
		}
		if (vm_pid > 0) break;
	}
	procstat_freefiles(procstat, head);
	return vm_pid;
}


pid_t print_file_info(struct procstat *procstat, struct filestat *fst,
    const char *uname, const char *cmd, int pid)
{
	struct vnstat vn;
	char *filename;
	int error, fsmatch = 0;
	char errbuf[_POSIX2_LINE_MAX];

	filename = NULL;
	if (checkfile != 0) {
		if (fst->fs_type != PS_FST_TYPE_VNODE &&
		    fst->fs_type != PS_FST_TYPE_FIFO)
			return -1;
		error = procstat_get_vnode_info(procstat, fst, &vn, errbuf);
		if (error != 0)
			return -1;

		if (fsid == vn.vn_fsid) {
			if (ino == vn.vn_fileid) {
				return pid;
			}
		}
	}
	return 0;
}

// store filename data (inode, fsid)
int getfname(char *filename)
{
	struct stat statbuf;

	if (stat(filename, &statbuf)) {
		warn("%s", filename);
		return (0);
	}

	ino = statbuf.st_ino;
	fsid = statbuf.st_dev;
	name = filename;

	return (1);
}


pid_t get_vm_pid(char *vmpath)
{
	struct kinfo_proc *p;
	struct passwd *passwd;
	struct procstat *procstat;
	int arg, ch, what;
	int i;
	unsigned int cnt;
	pid_t vmpid;

	arg = 0;
	what = KERN_PROC_PROC;
	nlistf = memf = NULL;

	if (getfname(vmpath))
		checkfile = 1;

	if (!checkfile)	/* file(s) specified, but none accessible */
		return -1;

	procstat = procstat_open_sysctl();
	if (procstat == NULL)
		errx(1, "procstat_open()");
	p = procstat_getprocs(procstat, what, arg, &cnt);
	if (p == NULL)
		errx(1, "procstat_getprocs()");

	/*
	 * Go through the process list.
	 */
	for (i = 0; i < cnt; i++) {
		if (p[i].ki_stat == SZOMB)
			continue;
		vmpid = dofiles(procstat, &p[i]);
		if (vmpid > 0) break;
	}
	procstat_freeprocs(procstat, p);
	procstat_close(procstat);
	return vmpid;
}

int main(int argc, char *argv[])
{
	DIR *dirp;

	struct dirent *dp;
	char vmname[1024];
	char vmpath[1024];
	pid_t vmpid;

	dirp = opendir("/dev/vmm");
	if (dirp == NULL)
		return (1);

	while ((dp = readdir(dirp)) != NULL) {
		if (dp->d_name[0]=='.') continue;
		memset(vmname,0,sizeof(vmname));
		memset(vmpath,0,sizeof(vmpath));
		sprintf(vmpath,"/dev/vmm/%s",dp->d_name);
		printf("Search pid for %s: ", dp->d_name);
		vmpid = get_vm_pid(vmpath);
		printf("%d\n", vmpid);
	}

	(void)closedir(dirp);
	return 0;
}
