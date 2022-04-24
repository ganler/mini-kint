// http://www.openssh.com/txt/preauth.adv

#include <sys/types.h>
#include <stddef.h>

void     fatal(const char *, ...) __attribute__((format(printf, 1, 2))) __attribute__((noreturn));
u_int    packet_get_int(void);
void    *packet_get_string(u_int *length_ptr);
void    *xmalloc(size_t);

char **input_userauth_info_response()
{
	int i;
	u_int nresp;
	char **response = NULL;
	nresp = packet_get_int();

	if (nresp > 0) {
		response = (char **)xmalloc(nresp * sizeof(char*)); // multiplication may overflow
		for (i = 0; i < nresp; i++)
			response[i] = (char *)packet_get_string(NULL);
	}
	return response;
}
