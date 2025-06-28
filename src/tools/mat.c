#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <hex.h>
#include <lq/io.h>
#include <lq/msg.h>
#include <lq/cert.h>

// 40f7c950cf393e61a3e7ceeef2e2d25f7b5adc1f93ff059d350a3b0f873fa26ca1
// 49ba0f2518f543d871a3525c0b0ae5411b20d949667da5e34a5f0ae8d5fbacccf61dd75db0b8c2524bb598a1a3c0d93f1baccf21937edbc7f44751dd0b80860c

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
	char pubk_b[LQ_PUBKEY_LEN + 1];
	char sig_b[LQ_SIGN_LEN + 1];
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
	r = lq_certificate_request(cert, msg, NULL);
	if (r) {
		return 1;
	}

	msg->pubkey = lq_publickey_new(pubk_b);
	if (msg->pubkey == NULL) {
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
	} else {
		p = lq_certificate_mat(cert, msg->pubkey, out);
		b2h((unsigned char*)p, LQ_DIGEST_LEN, (unsigned char*)sum);
		printf(sum);
	}

	lq_certificate_free(cert);
	lq_finish();

	return 0;
}
