/* Minimal initramfs /init: squashfs root + tmpfs overlay, then switch_root.
 *
 * Freestanding on purpose -- no libc, so nothing can drag in string routines
 * built for ISA extensions the emulator may not have.  rv64gc only.
 */
typedef unsigned long ul;
typedef long sl;

static sl sys(sl n, sl a, sl b, sl c, sl d, sl e)
{
	register sl a7 __asm__("a7") = n;
	register sl a0 __asm__("a0") = a;
	register sl a1 __asm__("a1") = b;
	register sl a2 __asm__("a2") = c;
	register sl a3 __asm__("a3") = d;
	register sl a4 __asm__("a4") = e;
	__asm__ volatile("ecall" : "+r"(a0)
			 : "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4)
			 : "memory");
	return a0;
}

#define NR_write     64
#define NR_exit      93
#define NR_execve   221
#define NR_chdir     49
#define NR_chroot    51
#define NR_mount     40
#define NR_mkdirat   34
#define NR_nanosleep 101

#define AT_FDCWD  (-100)
#define MS_RDONLY 1
#define MS_MOVE   8192

static void out(const char *s)
{
	ul n = 0;
	while (s[n])
		n++;
	sys(NR_write, 1, (sl)s, (sl)n, 0, 0);
}

static void mkdir(const char *p) { sys(NR_mkdirat, AT_FDCWD, (sl)p, 0755, 0, 0); }

static sl mount(const char *src, const char *tgt, const char *fs, ul flags, const char *data)
{
	return sys(NR_mount, (sl)src, (sl)tgt, (sl)fs, (sl)flags, (sl)data);
}

static void die(const char *msg, sl err)
{
	out("initramfs: FAILED ");
	out(msg);
	out(" errno=");
	{
		char b[8];
		int i = 7;
		ul u = (ul)(-err);
		b[i--] = 0;
		b[i--] = '\n';
		if (!u)
			b[i--] = '0';
		while (u) {
			b[i--] = '0' + (u % 10);
			u /= 10;
		}
		out(&b[i + 1]);
	}
	sys(NR_exit, 1, 0, 0, 0, 0);
}

void _start(void)
{
	sl r;

	out("initramfs: starting\n");
	mkdir("/proc");
	mkdir("/sys");
	mkdir("/dev");
	mkdir("/lower");
	mkdir("/over");
	mkdir("/merged");

	if ((r = mount("proc", "/proc", "proc", 0, 0)) < 0)
		die("mount /proc", r);
	if ((r = mount("sysfs", "/sys", "sysfs", 0, 0)) < 0)
		die("mount /sys", r);
	if ((r = mount("devtmpfs", "/dev", "devtmpfs", 0, 0)) < 0)
		die("mount /dev", r);

	/* virtio-blk probing may not have created /dev/vda yet. */
	for (int i = 0; i < 200; i++) {
		r = mount("/dev/vda", "/lower", "squashfs", MS_RDONLY, 0);
		if (r >= 0)
			break;
		{
			struct { sl sec, nsec; } ts = { 0, 10000000 }; /* 10ms */
			sys(NR_nanosleep, (sl)&ts, 0, 0, 0, 0);
		}
	}
	if (r < 0)
		die("mount squashfs /dev/vda", r);
	out("initramfs: squashfs mounted\n");

	if ((r = mount("tmpfs", "/over", "tmpfs", 0, "size=75%")) < 0)
		die("mount tmpfs", r);
	mkdir("/over/up");
	mkdir("/over/work");

	if ((r = mount("overlay", "/merged", "overlay", 0,
		       "lowerdir=/lower,upperdir=/over/up,workdir=/over/work")) < 0)
		die("mount overlay", r);
	out("initramfs: overlay mounted, switching root\n");

	/* Carry the API filesystems across rather than remounting them. */
	mount("/proc", "/merged/proc", 0, MS_MOVE, 0);
	mount("/sys", "/merged/sys", 0, MS_MOVE, 0);
	mount("/dev", "/merged/dev", 0, MS_MOVE, 0);

	if ((r = sys(NR_chdir, (sl)"/merged", 0, 0, 0, 0)) < 0)
		die("chdir /merged", r);
	if ((r = mount(".", "/", 0, MS_MOVE, 0)) < 0)
		die("move mount to /", r);
	if ((r = sys(NR_chroot, (sl)".", 0, 0, 0, 0)) < 0)
		die("chroot", r);
	sys(NR_chdir, (sl)"/", 0, 0, 0, 0);

	{
		static const char *cands[] = { "/sbin/init", "/usr/lib/systemd/systemd",
					       "/bin/sh", "/usr/bin/sh", 0 };
		char *argv[2], *envp[2];
		envp[0] = (char *)"TERM=linux";
		envp[1] = 0;
		argv[1] = 0;
		for (int i = 0; cands[i]; i++) {
			argv[0] = (char *)cands[i];
			r = sys(NR_execve, (sl)cands[i], (sl)argv, (sl)envp, 0, 0);
			out("initramfs: execve ");
			out(cands[i]);
			out(" -> ");
			{
				char b[8];
				int k = 7;
				ul u = (ul)(-r);
				b[k--] = 0;
				b[k--] = '\n';
				if (!u) b[k--] = '0';
				while (u) { b[k--] = '0' + (u % 10); u /= 10; }
				out(&b[k + 1]);
			}
		}
	}
	die("no init could be executed", 0);
}
