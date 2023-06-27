#ifndef _DEF_FUNC_H
#define _DEF_FUNC_H

#include "prio.h"

#define declare_nop_prio(name)						\
int name (struct prio *p)						\
{									\
	return 0;							\
}
#endif /* _DEF_FUNC_H */
