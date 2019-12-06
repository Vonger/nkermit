#ifndef NKERMIT_H
#define NKERMIT_H

struct nkermit {
    struct nkermit_ops {
	int (*read_dev)(struct nkermit *, char *buf, int size);
	int (*write_dev)(struct nkermit *, const char *buf, int size);
	void (*process)(struct nkermit *);
    } ops;

    unsigned char seq;
    int cur, total;
    void *priv, *user;
};

int nkermit_send(struct nkermit *, char *buf, int size);
int nkermit_send_file(struct nkermit *, char *path);

#endif /* NKERMIT_H */
