#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <hex.h>
#include <lq/io.h>
#include <lq/msg.h>
#include <lq/cert.h>

/**
 *
 * \todo stat file and alloc buffers large enough for the work.
 */
int main(int argc, char **argv) {
	int f;
	int r;
	size_t c;
	size_t mx;
	char in[4096];
	char pubk_b[LQ_PUBKEY_LEN];
	char sig_b[LQ_SIGN_LEN];
	char out[4096];
	char sum[LQ_DIGEST_LEN * 2 + 1];
	char *p;
	LQCert *cert;
	LQMsg *msg;

	if (argc < 2) {
		return 1;
	}
	r = h2b((const char*)(*(argv+1)), (unsigned char*)pubk_b);
	if (r == 0) {
		return 1;
	}

	if (argc == 3) {
		r = h2b((const char*)(*(argv+2)), (unsigned char*)sig_b);
		if (r == 0) {
			return 1;
		}
	}

	r = lq_init();
	if (r) {
		return 1;
	}

	cert = lq_certificate_new(NULL);
	lq_certificate_set_domain(cert, "foobarbaz");

	msg = lq_msg_new("inkypinky", 10);
	msg->pubkey = lq_publickey_new(pubk_b);
	if (msg->pubkey == NULL) {
		return 1;
	}

	r = lq_certificate_request(cert, msg, NULL);
	if (r) {
		return 1;
	}

	if (argc == 3) {
		cert->request_sig = lq_signature_from_bytes(sig_b, LQ_SIGN_LEN, msg->pubkey);
		if (cert->request_sig == NULL) {
			return 1;
		}

		r = lq_certificate_verify(cert, NULL, NULL);
		if (r) {
			return r;
		}

		c = 4096;
		r = lq_certificate_serialize(cert, NULL, in, &c);
		if (r) {
			return r;
		}
		b2h((unsigned char*)in, c, (unsigned char*)out);
		printf(out);
	} else {
		p = lq_certificate_mat(cert, msg->pubkey, out);
		b2h((unsigned char*)p, LQ_DIGEST_LEN, (unsigned char*)sum);
		printf(sum);
	}

	lq_certificate_free(cert);
	lq_finish();

	return 0;
}
