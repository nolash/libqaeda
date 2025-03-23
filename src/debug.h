#ifndef MORGEL_H_
#define MORGEL_H_

enum debug_typ_e {
	MORGEL_TYP_BIN,
	MORGEL_TYP_NUM,
	MORGEL_TYP_STR,
};

void debug_dbg(const char *ns, const char *msg);
void debug_dbg_x(const char *ns, const char *msg, int argc, ...);

#endif // MOREGELLONS_H_
