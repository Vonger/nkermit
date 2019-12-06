#include <stdio.h>
#include <string.h>

#include "libserialport.h"
#include "nkermit.h"

struct sp_port * gd32_init_serial(const char *name)
{
    struct sp_port *port;

    if (SP_OK != sp_get_port_by_name(name, &port))
	return NULL;

    if (SP_OK != sp_open(port, SP_MODE_READ_WRITE))
	return NULL;

    // clear input/output buffer.
    sp_flush(port, SP_BUF_BOTH);

    sp_set_baudrate(port, 115200);
    sp_set_bits(port, 8);
    sp_set_parity(port, SP_PARITY_NONE);
    sp_set_stopbits(port, 1);

    return port;
}

void gd32_uninit_serial(struct sp_port *port)
{
    sp_close(port);
    sp_free_port(port);
}

int sp_write(struct nkermit *n, const char *buf, int size)
{
    return sp_blocking_write((struct sp_port *)n->user, buf, size, 600);
}

int sp_read(struct nkermit *n, char *buf, int size)
{
    return sp_blocking_read((struct sp_port *)n->user, buf, size, 600);
}

void process(struct nkermit *n)
{
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    printf("\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b\b");
    printf("%9dB / %9dB [%3.1f%%]", n->cur, n->total, (float)n->cur / n->total * 100);
    fflush(stdout);
}

int main(int argc, char *argv[])
{
    struct nkermit n;
    struct sp_port *port;

    if (argc != 3) {
	printf("usage: nkermit [port] [file]\n");
	return 0;
    }

    port = gd32_init_serial(argv[1]);

    bzero(&n, sizeof(struct nkermit));
    n.user = port;
    n.ops.read_dev = sp_read;
    n.ops.write_dev = sp_write;
    n.ops.process = process;

    printf("OK, we are ready.\n");
    if (!nkermit_send_file(&n, argv[2]))
	printf("error: can not finish the upload.\n");
    return 0;
}
