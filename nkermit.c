#include <stdio.h>
#include <sys/stat.h>
#include <errno.h>

#include "nkermit.h"

struct nkermit_header_s {
	unsigned char code;
	unsigned char len;
	unsigned char seq;
	unsigned char type;
};

struct nkermit_header_b {
	unsigned char code;
	unsigned char len;
	unsigned char seq;
	unsigned char type;
	unsigned char lenh;
	unsigned char lenl;
	unsigned char sum;
};

struct nkermit_header_ack {
	unsigned char code;
	unsigned char len;
	unsigned char seq;
	unsigned char type;
	unsigned char sum;
	unsigned char eol;
};

#define translate_char(x)   ((unsigned char)(x) + 0x20)
#define translate_sum(s)    translate_char(((s) + (((s) >> 6) & 3)) & 0x3f)
#define min(a, b)           ((a) < (b) ? (a) : (b))

#define MAX_RETRY           5
#define MAX_PACK            500

unsigned char escape_need_table[] = {
	1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,0,0,0,1,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,
	1,1,1,1,1,1,1,1,0,0,0,1,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,
	0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,
};

unsigned char escape_char_table[] = {
	0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,
	0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,
	0x5e,0x5f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,
	0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,
	0x3c,0x3d,0x3e,0x3f,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,
	0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,
	0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,
	0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,
	0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x3f,0xc0,0xc1,0xc2,0xc3,0xc4,0xc5,0xc6,
	0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,0xd0,0xd1,0xd2,0xd3,0xd4,0xd5,
	0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,0xa0,0xa1,0xa2,0xa3,0xa4,
	0xa5,0xa6,0xa7,0xa8,0xa9,0xaa,0xab,0xac,0xad,0xae,0xaf,0xb0,0xb1,0xb2,0xb3,
	0xb4,0xb5,0xb6,0xb7,0xb8,0xb9,0xba,0xbb,0xbc,0xbd,0xbe,0xbf,0xc0,0xc1,0xc2,
	0xc3,0xc4,0xc5,0xc6,0xc7,0xc8,0xc9,0xca,0xcb,0xcc,0xcd,0xce,0xcf,0xd0,0xd1,
	0xd2,0xd3,0xd4,0xd5,0xd6,0xd7,0xd8,0xd9,0xda,0xdb,0xdc,0xdd,0xde,0xdf,0xe0,
	0xe1,0xe2,0xe3,0xe4,0xe5,0xe6,0xe7,0xe8,0xe9,0xea,0xeb,0xec,0xed,0xee,0xef,
	0xf0,0xf1,0xf2,0xf3,0xf4,0xf5,0xf6,0xf7,0xf8,0xf9,0xfa,0xfb,0xfc,0xfd,0xfe,
	0xbf,
};

int escape_buffer(unsigned char *in, int is, unsigned char *out, int *os)
{
	int sum = 0, i, used = 0;

	for (i = 0; i < is; i++) {
		if (escape_need_table[in[i]]) {
			out[used] = '#';
			sum += out[used++];
		}

		out[used] = escape_char_table[in[i]];
		sum += out[used++];
	}
	*os = used;

	return sum;
}

void send_package_b(struct nkermit *n, unsigned char *buf, int size)
{
	unsigned char data[0x400] = {0};
	int used, sum, sumh;
	struct nkermit_header_b header;

	sum = escape_buffer(buf, size, data, &used);

	header.code = 0x01;
	header.len = translate_char(0);
	header.seq = translate_char(n->seq);
	header.type = 'D';
	header.lenh = translate_char((used + 1) / 95);
	header.lenl = translate_char((used + 1) % 95);
	sumh = header.len + header.seq + header.type + header.lenh + header.lenl;
	header.sum = translate_sum(sumh);

	sum += sumh + header.sum;
	data[used++] = translate_sum(sum);
	data[used++] = 0x0d;

	n->ops.write_dev(n, (char *)&header, sizeof(struct nkermit_header_b));
	n->ops.write_dev(n, (char *)data, used);
}

int check_ack(struct nkermit *n)
{
	int sum;
	struct nkermit_header_ack header;

	n->ops.read_dev(n, (char *)&header, sizeof(struct nkermit_header_ack));
	sum = header.len + header.seq + header.type;
	if (translate_sum(sum) != header.sum)
		return 0;

	if (header.seq != translate_char(n->seq))
		return 0;

	if (header.type != 'Y')
		return 0;

	return 1;
}

static int send_package(struct nkermit *n, unsigned char *buf, int size)
{
	int retry = 0;

	while (retry < MAX_RETRY) {
		send_package_b(n, buf, size);

		if (check_ack(n))
			break;

		retry++;
	}

	if (retry >= MAX_RETRY)
		return 0;

	if (n->ops.process)
		n->ops.process(n);
	return 1;
}

int send_end_package(struct nkermit *n)
{
	char end[] = {0x01, 0x22, 0x00, 'B', 0x00, 0x0d};
	int sum = end[1] + end[3];
	end[2] = translate_char(n->seq);
	end[4] = translate_sum(sum + end[2]);
	n->ops.write_dev(n, end, sizeof(end));
	if (n->ops.process)
		n->ops.process(n);
	return check_ack(n);
}

int nkermit_send(struct nkermit *n, char *buf, int size)
{
	n->seq = 0;
	n->cur = 0;
	n->total = size;

	while (n->cur < n->total) {
		int size = min(n->total - n->cur, MAX_PACK);
		if (!send_package(n, (unsigned char *)buf + n->cur, size))
			break;

		n->cur += size;
		if (++n->seq > 0x7f)
			n->seq = 0;
	}
	if (n->cur == n->total)
		send_end_package(n);

	return n->cur;
}

int nkermit_send_file(struct nkermit *n, char *path)
{
	FILE *fp;
	char buf[MAX_PACK];
	struct stat st;

	if (stat(path, &st) < 0)
		return -ENOENT;

	n->seq = 0;
	n->cur = 0;
	n->total = st.st_size;

	fp = fopen(path, "rb");
	if (fp == NULL)
		return -ENOENT;

	while(1) {
		int size = fread(buf, 1, MAX_PACK, fp);
		if (size <= 0)
			break;

		if (!send_package(n, (unsigned char *)buf, size))
			break;

		n->cur += size;
		if (++n->seq > 0x7f)
			n->seq = 0;
	}
	if (n->cur == n->total)
		send_end_package(n);

	fclose(fp);
	return n->cur;
}
