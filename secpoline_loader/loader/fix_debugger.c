#include <assert.h>
#include <sys/auxv.h>
#include "dso.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <err.h>
#include <stdlib.h>
#include <link.h>

#include <string.h>

__attribute__((visibility("hidden")))
void populate_dt_debug(Elf64_Dyn *d, uintptr_t inferior_load_addr, uintptr_t inferior_dynamic_vaddr, uintptr_t inferior_r_debug_vaddr, char* name);
__attribute__((visibility("hidden")))
Elf64_Dyn *find_or_create_dt_debug(uintptr_t inferior_load_addr, uintptr_t inferior_dynamic_vaddr, size_t our_dynamic_size, uintptr_t inferior_r_debug_vaddr);


int fix_debugger(dso_t * dso, Elf64_Phdr* our_phdrs, int our_phnum){

/* To find the _r_debug symbol, we use a simple but slow linear search
	 * rather than the hash table. */
	Elf64_Dyn *dt_debug = NULL;
	Elf64_Sym *symtab = NULL;
	Elf64_Sym *symtab_end = NULL;
	const unsigned char *strtab = NULL;
	for (Elf64_Dyn *dyn = dso->dyn; dyn->d_tag != DT_NULL; ++dyn)
	{
		switch (dyn->d_tag)
		{
			case DT_SYMTAB:
				symtab = (Elf64_Sym *)(dso->base + dyn->d_un.d_ptr);
				break;
			case DT_STRTAB:
				strtab = (const unsigned char *)(dso->base + dyn->d_un.d_ptr);
				symtab_end = (Elf64_Sym *)strtab;
				break;
			default: break;
		}
	}
	Elf64_Sym *found_r_debug_sym = NULL;
	for (Elf64_Sym *p_sym = &symtab[0]; p_sym && p_sym <= symtab_end; ++p_sym)
	{
		if (0 == strcmp((const char*) &strtab[p_sym->st_name], "_r_debug"))
		{
			/* match */
			found_r_debug_sym = p_sym;
			break;
		}
	}

    if (found_r_debug_sym)
	{
		assert(our_phdrs);
		size_t our_dynamic_size = 0;
		for (Elf64_Phdr *phdr = our_phdrs; phdr != our_phdrs + our_phnum; ++phdr)
		{
			if (phdr->p_type == PT_DYNAMIC) { our_dynamic_size = phdr->p_memsz; break; }
		}

        uintptr_t dynamic_vaddr = 0;
        for (Elf64_Phdr *phdr = dso->phdr; phdr != dso->phdr + dso->phdr_length; ++phdr)
		{
			if (phdr->p_type == PT_DYNAMIC) { dynamic_vaddr = phdr->p_vaddr; break; }
		}
		dt_debug = find_or_create_dt_debug((uintptr_t) dso->base, dynamic_vaddr, our_dynamic_size, found_r_debug_sym->st_value);
	    if (dt_debug) populate_dt_debug(dt_debug, (uintptr_t) dso->base, dynamic_vaddr, found_r_debug_sym->st_value, dso->path);
	}

    return 1;
}


Elf64_Dyn *find_or_create_dt_debug(uintptr_t inferior_load_addr, uintptr_t inferior_dynamic_vaddr,
	size_t our_dynamic_size, uintptr_t inferior_r_debug_vaddr)
{
	/* This used to say:
	 * PROBLEM: can't use _DYNAMIC because there is no way to
	 * --export-dynamic it. Instead we use PT_DYNAMIC.
	 * BUT shouldn't the linker let us reference our own _DYNAMIC at link time?
	 * This seems to work. */
	Elf64_Dyn *d = &_DYNAMIC[0];
	// seek forwards until we see the null terminator OR existing DT_DEBUG
	for (; (uintptr_t) d - (uintptr_t) &_DYNAMIC[0] < our_dynamic_size && d->d_tag != DT_NULL
			&& d->d_tag != DT_DEBUG; ++d);
	// do we have spare space?
	if ((intptr_t) d + sizeof (ElfW(Dyn)) - (intptr_t) &_DYNAMIC[0] >= our_dynamic_size)
	{
		// no space!
		return NULL;
	}
	else if (d->d_tag == DT_NULL)
	{
		/* Need to create the DT_DEBUG */
		*d = (Elf64_Dyn) { .d_tag = DT_DEBUG };
		/* Ensure _DYNAMIC still has a terminator. */
		*(d+1) = (Elf64_Dyn) { .d_tag = DT_NULL, .d_un = { .d_ptr = 0x0 } };
	}
	assert(d->d_tag == DT_DEBUG);
	struct r_debug *r = (struct r_debug *)(inferior_load_addr + inferior_r_debug_vaddr);
	// make *our* _DYNAMIC point to the *inferior*'s _r_debug
	d->d_un.d_ptr = (uintptr_t) r;
	return d;
}

// other client code may want this
__attribute__((visibility("hidden")))
struct link_map fake_ld_so_link_map;

void populate_dt_debug(Elf64_Dyn *d, uintptr_t inferior_load_addr, uintptr_t inferior_dynamic_vaddr, uintptr_t inferior_r_debug_vaddr, char* name)
{
	struct r_debug *r = (struct r_debug *)(inferior_load_addr + inferior_r_debug_vaddr);
	/* What about the contents of the inferior's r_debug? To enable
	 * debugging early in the ld.so, we could create a fake entry. Let's try it. */
	fake_ld_so_link_map = (struct link_map) {
		.l_addr = 0 /* inferior_load_addr */,
		.l_name = name,
		.l_ld = 0 /* (ElfW(Dyn) *) inferior_dynamic_vaddr */,
		.l_prev = NULL,
		.l_next = NULL
	};
	extern void _dl_debug_state(void) __attribute__((weak));
	fake_ld_so_link_map.l_addr = inferior_load_addr;
	fake_ld_so_link_map.l_ld = (Elf64_Dyn *) (inferior_load_addr + inferior_dynamic_vaddr);

	if (_dl_debug_state) _dl_debug_state(); // trigger the attached debugger, if any
}