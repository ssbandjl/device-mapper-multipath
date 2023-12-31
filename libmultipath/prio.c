#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <dlfcn.h>
#include <sys/stat.h>

#include "debug.h"
#include "prio.h"
#include "config.h"

static LIST_HEAD(prioritizers);

unsigned int get_prio_timeout(unsigned int default_timeout)
{
	if (conf->checker_timeout)
		return conf->checker_timeout * 1000;
	return default_timeout;
}

int init_prio (void)
{
	if (!add_prio(DEFAULT_PRIO))
		return 1;
	return 0;
}

static struct prio * alloc_prio (void)
{
	struct prio *p;

	p = MALLOC(sizeof(struct prio));
	if (p) {
		INIT_LIST_HEAD(&p->node);
		p->refcount = 1;
	}
	return p;
}

void free_prio (struct prio * p)
{
	if (!p)
		return;
	p->refcount--;
	if (p->refcount) {
		condlog(3, "%s prioritizer refcount %d",
			p->name, p->refcount);
		return;
	}
	condlog(3, "unloading %s prioritizer", p->name);
	list_del(&p->node);
	if (p->handle) {
		if (dlclose(p->handle) != 0) {
			condlog(0, "Cannot unload prioritizer %s: %s",
				p->name, dlerror());
		}
	}
	FREE(p);
}

void cleanup_prio(void)
{
	struct prio * prio_loop;
	struct prio * prio_temp;

	list_for_each_entry_safe(prio_loop, prio_temp, &prioritizers, node) {
		free_prio(prio_loop);
	}
}

struct prio * prio_lookup (char * name)
{
	struct prio * p;

	list_for_each_entry(p, &prioritizers, node) {
		if (!strncmp(name, p->name, PRIO_NAME_LEN))
			return p;
	}
	return add_prio(name);
}

int prio_set_args (struct prio * p, char * args)
{
	return snprintf(p->args, PRIO_ARGS_LEN, "%s", args);
}

struct prio * add_prio (char * name)
{
	char libname[LIB_PRIO_NAMELEN];
	struct stat stbuf;
	struct prio * p;
	char *errstr;

	p = alloc_prio();
	if (!p)
		return NULL;
	snprintf(p->name, PRIO_NAME_LEN, "%s", name);
	snprintf(libname, LIB_PRIO_NAMELEN, "%s/libprio%s.so",
		 conf->multipath_dir, name);
	if (stat(libname,&stbuf) < 0) {
		condlog(0,"Prioritizer '%s' not found in %s",
			name, conf->multipath_dir);
		goto out;
	}
	condlog(3, "loading %s prioritizer", libname);
	p->handle = dlopen(libname, RTLD_NOW);
	if (!p->handle) {
		if ((errstr = dlerror()) != NULL)
			condlog(0, "A dynamic linking error occurred: (%s)",
				errstr);
		goto out;
	}
	p->getprio = (int (*)(struct path *, char *)) dlsym(p->handle, "getprio");
	errstr = dlerror();
	if (errstr != NULL)
		condlog(0, "A dynamic linking error occurred with getprio: (%s)", errstr);
	if (!p->getprio)
		goto out;

	p->initprio = (int (*)(struct prio *)) dlsym(p->handle, "initprio");
	errstr = dlerror();
	if (errstr != NULL)
		condlog(0, "A dynamic linking error occurred with initprio: (%s)", errstr);
	if (!p->initprio)
		goto out;

	p->freeprio = (int (*)(struct prio *)) dlsym(p->handle, "freeprio");
	errstr = dlerror();
	if (errstr != NULL)
		condlog(0, "A dynamic linking error occurred with freeprio: (%s)", errstr);
	if (!p->freeprio)
		goto out;

	list_add(&p->node, &prioritizers);
	return p;
out:
	free_prio(p);
	return NULL;
}

int prio_init (struct prio * p)
{
	if (!p || !p->initprio)
		return 1;
	return p->initprio(p);
}

int prio_getprio (struct prio * p, struct path * pp)
{
	return p->getprio(pp, p->args);
}

int prio_selected (struct prio * p)
{
	if (!p || !p->getprio)
		return 0;
	return (p->getprio) ? 1 : 0;
}

char * prio_name (struct prio * p)
{
	return p->name;
}

char * prio_args (struct prio * p)
{
	return p->args;
}

void prio_get (struct prio * dst, char * name, char * args)
{
	struct prio * src = prio_lookup(name);

	if (!src) {
		dst->getprio = NULL;
		return;
	}

	strncpy(dst->name, src->name, PRIO_NAME_LEN);
	if (args)
		strncpy(dst->args, args, PRIO_ARGS_LEN);
	dst->initprio = src->initprio;
	dst->getprio = src->getprio;
	dst->freeprio = src->freeprio;
	dst->handle = NULL;
	dst->context = NULL;

	if (dst->initprio(dst) != 0){
		memset(dst, 0x0, sizeof(struct prio));
		return;
	}

	src->refcount++;
}

void prio_put (struct prio * dst)
{
	struct prio * src;

	if (!dst)
		return;

	if (!strlen(dst->name))
		src = NULL;
	else
		src = prio_lookup(dst->name);
	if (dst->freeprio)
		dst->freeprio(dst);
	memset(dst, 0x0, sizeof(struct prio));
	free_prio(src);
}
