#include <stddef.h>
#include <mach-o/reloc.h>
#include "../Application/Dopamine/Exploits/weightBufs/exploit/aneProgram.h"

typedef __typeof__(*(((struct relocation_entries *)0)->relocs)) ANERelocation;

_Static_assert(sizeof(ANERelocation) == 8, "ANE relocation size must remain unchanged");
_Static_assert(offsetof(ANERelocation, r_address) == 0, "ANE address offset must remain unchanged");
_Static_assert(offsetof(ANERelocation, r_symbolnum) == 4, "ANE symbol offset must remain unchanged");
_Static_assert(sizeof(((ANERelocation *)0)->r_symbolnum) == 4, "ANE symbol must remain a full-width field");
