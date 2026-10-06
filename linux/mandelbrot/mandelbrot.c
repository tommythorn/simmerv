/* Mandelbrot zoom on /dev/fb0, for the --graphics framebuffer.
 *
 * Endlessly zooms into Seahorse Valley until double precision runs out, then
 * starts over.  Ctrl-C stops it and gives the console back.  The framebuffer
 * is simmerv's RGB565; the
 * 24-bit palette is brought down to it with an 8x8 ordered dither, which
 * hides the 565 banding and, unlike error diffusion, is a fixed function of
 * (x, y) that stays put on screen as the zoom moves.
 *
 * Freestanding on purpose, like ../demo/init.c -- no libc, so nothing can drag
 * in string routines built for ISA extensions the emulator may not have.
 * No V; see build.sh for the -march.
 */
typedef unsigned long ul;
typedef long sl;
typedef unsigned int u32;
typedef unsigned short u16;

static sl sys(sl n, sl a, sl b, sl c, sl d, sl e, sl f)
{
	register sl a7 __asm__("a7") = n;
	register sl a0 __asm__("a0") = a;
	register sl a1 __asm__("a1") = b;
	register sl a2 __asm__("a2") = c;
	register sl a3 __asm__("a3") = d;
	register sl a4 __asm__("a4") = e;
	register sl a5 __asm__("a5") = f;
	__asm__ volatile("ecall" : "+r"(a0)
			 : "r"(a7), "r"(a1), "r"(a2), "r"(a3), "r"(a4), "r"(a5)
			 : "memory");
	return a0;
}

#define NR_ioctl      29
#define NR_openat     56
#define NR_write      64
#define NR_exit       93
#define NR_exit_group 94
#define NR_rt_sigaction 134
#define NR_mmap      222

#define AT_FDCWD   (-100)
#define O_RDWR     2
#define PROT_RW    3
#define MAP_SHARED 1

#define FBIOGET_VSCREENINFO 0x4600
#define FBIOGET_FSCREENINFO 0x4602
#define KDSETMODE           0x4B3A
#define KD_TEXT             0
#define KD_GRAPHICS         1

#define SIGHUP  1
#define SIGINT  2
#define SIGTERM 15

struct fb_bitfield { u32 offset, length, msb_right; };

struct fb_var_screeninfo {
	u32 xres, yres, xres_virtual, yres_virtual, xoffset, yoffset;
	u32 bits_per_pixel, grayscale;
	struct fb_bitfield red, green, blue, transp;
	u32 nonstd, activate, height, width, accel_flags;
	u32 pixclock, left_margin, right_margin, upper_margin, lower_margin;
	u32 hsync_len, vsync_len, sync, vmode, rotate, colorspace;
	u32 reserved[4];
};

struct fb_fix_screeninfo {
	char id[16];
	ul smem_start;
	u32 smem_len, type, type_aux, visual;
	u16 xpanstep, ypanstep, ywrapstep;
	u32 line_length;
	ul mmio_start;
	u32 mmio_len, accel;
	u16 capabilities, reserved[2];
};

/* gcc may emit calls to these for struct copies and clears. */
void *memset(void *d, int c, ul n)
{
	char *p = d;
	while (n--)
		*p++ = (char)c;
	return d;
}

void *memcpy(void *d, const void *s, ul n)
{
	char *p = d;
	const char *q = s;
	while (n--)
		*p++ = *q++;
	return d;
}

static void out(const char *s)
{
	ul n = 0;
	while (s[n])
		n++;
	sys(NR_write, 1, (sl)s, (sl)n, 0, 0, 0);
}

static void outnum(ul u)
{
	char b[24];
	int i = 23;
	b[i] = 0;
	do {
		b[--i] = '0' + (u % 10);
		u /= 10;
	} while (u);
	out(&b[i]);
}

static sl tty = -1;

/* riscv has no SA_RESTORER; the kernel returns through the vDSO. */
struct k_sigaction { void (*handler)(int); ul flags, mask; };

/* Give the console back: KD_TEXT unblanks the VT and redraws it. */
static void quit(int sig)
{
	if (tty >= 0)
		sys(NR_ioctl, tty, KDSETMODE, KD_TEXT, 0, 0, 0);
	sys(NR_exit_group, 128 + sig, 0, 0, 0, 0, 0);
}

static void fail(const char *msg, sl err)
{
	out("mandelbrot: ");
	out(msg);
	out(" failed, errno ");
	outnum((ul)-err);
	out("\n");
	sys(NR_exit, 1, 0, 0, 0, 0, 0);
}

/* Palette: a cyclic gradient through these, the familiar blue-gold-white. */
#define PAL 256
static u32 palette[PAL];
static const unsigned char stops[][3] = {
	{   0,   7, 100 }, {  32, 107, 203 }, { 237, 255, 255 },
	{ 255, 170,   0 }, {   0,   2,   0 },
};
#define NSTOPS (sizeof stops / sizeof stops[0])

/* Bayer thresholds 0..63, scaled to 2..254 below so that a channel of 255
 * still rounds to full scale and 0 stays 0. */
static const unsigned char bayer[8][8] = {
	{  0, 32,  8, 40,  2, 34, 10, 42 }, { 48, 16, 56, 24, 50, 18, 58, 26 },
	{ 12, 44,  4, 36, 14, 46,  6, 38 }, { 60, 28, 52, 20, 62, 30, 54, 22 },
	{  3, 35, 11, 43,  1, 33,  9, 41 }, { 51, 19, 59, 27, 49, 17, 57, 25 },
	{ 15, 47,  7, 39, 13, 45,  5, 37 }, { 63, 31, 55, 23, 61, 29, 53, 21 },
};

/* 0xRRGGBB to RGB565, rounding each channel up or down by threshold t. */
static u16 dither565(u32 rgb, u32 t)
{
	u32 r = rgb >> 16, g = rgb >> 8 & 255, b = rgb & 255;
	return (u16)((r * 31 + t) / 255 << 11 | (g * 63 + t) / 255 << 5 |
		     (b * 31 + t) / 255);
}

static void make_palette(void)
{
	for (u32 i = 0; i < PAL; i++) {
		u32 seg = i * NSTOPS / PAL, t = i * NSTOPS % PAL; /* t/PAL into seg */
		const unsigned char *a = stops[seg], *b = stops[(seg + 1) % NSTOPS];
		u32 c[3];
		for (int k = 0; k < 3; k++)
			c[k] = (a[k] * (PAL - t) + b[k] * t) / PAL;
		palette[i] = c[0] << 16 | c[1] << 8 | c[2];
	}
}

/* Iterations before |z| > 2, or maxit if it never escapes. */
static u32 escape(double cr, double ci, u32 maxit)
{
	/* Main cardioid and period-2 bulb: interior, skip the full count. */
	double q = (cr - 0.25) * (cr - 0.25) + ci * ci;
	if (q * (q + (cr - 0.25)) <= 0.25 * ci * ci ||
	    (cr + 1) * (cr + 1) + ci * ci <= 0.0625)
		return maxit;

	double zr = 0, zi = 0, zr2 = 0, zi2 = 0;
	u32 n = 0;
	while (n < maxit && zr2 + zi2 <= 4.0) {
		zi = 2 * zr * zi + ci;
		zr = zr2 - zi2 + cr;
		zr2 = zr * zr;
		zi2 = zi * zi;
		n++;
	}
	return n;
}

void _start(void)
{
	sl r, fd;

	fd = sys(NR_openat, AT_FDCWD, (sl)"/dev/fb0", O_RDWR, 0, 0, 0);
	if (fd < 0)
		fail("open /dev/fb0 (was the sim started with --graphics WxH?)", fd);

	struct fb_var_screeninfo v;
	struct fb_fix_screeninfo f;
	if ((r = sys(NR_ioctl, fd, FBIOGET_VSCREENINFO, (sl)&v, 0, 0, 0)) < 0)
		fail("FBIOGET_VSCREENINFO", r);
	if ((r = sys(NR_ioctl, fd, FBIOGET_FSCREENINFO, (sl)&f, 0, 0, 0)) < 0)
		fail("FBIOGET_FSCREENINFO", r);
	if (v.bits_per_pixel != 16)
		fail("unsupported depth (want RGB565)", -22);

	char *fb = (char *)sys(NR_mmap, 0, f.smem_len, PROT_RW, MAP_SHARED, fd, 0);
	if ((ul)fb > -4096UL)
		fail("mmap /dev/fb0", (sl)fb);

	/* Keep fbcon's cursor and kernel messages off the picture. */
	tty = sys(NR_openat, AT_FDCWD, (sl)"/dev/tty0", O_RDWR, 0, 0, 0);
	if (tty >= 0) {
		static const int sigs[] = { SIGHUP, SIGINT, SIGTERM };
		struct k_sigaction sa = { quit, 0, 0 };
		for (int i = 0; i < 3; i++)
			sys(NR_rt_sigaction, sigs[i], (sl)&sa, 0, 8, 0, 0);
		sys(NR_ioctl, tty, KDSETMODE, KD_GRAPHICS, 0, 0, 0);
	}

	out("mandelbrot: ");
	outnum(v.xres);
	out("x");
	outnum(v.yres);
	out(" RGB565\n");

	make_palette();

	const double cx = -0.743643887037158704752191506114774;
	const double cy = 0.131825904205311970493132056385139;
	const u32 w = v.xres, h = v.yres;
	const ul pitch = f.line_length;

	for (;;) {
		double scale = 3.0 / w; /* complex units per pixel */
		for (u32 frame = 0; scale * w > 1e-12; frame++, scale *= 0.92) {
			/* Deeper views need more iterations to resolve. */
			u32 maxit = 64 + frame * 6;
			/* Screen y grows down, the imaginary axis up. */
			double y0 = cy + scale * h / 2, x0 = cx - scale * w / 2;
			for (u32 y = 0; y < h; y++) {
				u16 *row = (u16 *)(fb + (y + v.yoffset) * pitch) + v.xoffset;
				const unsigned char *thr = bayer[y & 7];
				double ci = y0 - y * scale;
				for (u32 x = 0; x < w; x++) {
					u32 n = escape(x0 + x * scale, ci, maxit);
					row[x] = n == maxit ? 0 :
						 dither565(palette[(n * 4) % PAL],
							   thr[x & 7] * 4 + 2);
				}
			}
		}
	}
}
