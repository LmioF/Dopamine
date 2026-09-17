#include <sys/syslimits.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/getsect.h>
#include <dlfcn.h>
#include <sys/stat.h>
#include <paths.h>
#include <util.h>
#include <ptrauth.h>
#include <pthread.h>
#include <errno.h>
#include <stdlib.h>
#include <os/log.h>
#include <libjailbreak/jbroot.h>
#include <substrate.h>
#include "common.h"
#include "litehook.h"
#include "hookd_external.h"
#include "private.h"

// Modify external libraries to use hookd instead of whatever they ship with
// Currently this is relevant for:
// Ellekit, normally uses inline syscall, contains EKHookMemoryRaw variable that can be replaced by a custom function to do the hooking instead
// Frida, uses inline syscalls, we have no other option than to apply hooks to frida-agent.dylib to redirect the inline syscalls to our own flow

uint64_t gShellcodeCurIdx = 0;

uint32_t arm64_gen_b(vm_address_t origin, vm_address_t target)
{
	int64_t displacement = (int64_t)target - (int64_t)origin;
	if ((displacement & 3) != 0) return 0;
	int64_t offset = displacement / 4;
	if (offset < -(1LL << 25) || offset >= (1LL << 25)) return 0;
	return 0x14000000U | ((uint32_t)offset & 0x03FFFFFFU);
}

uint32_t arm64_gen_bl(vm_address_t origin, vm_address_t target)
{
	int64_t displacement = (int64_t)target - (int64_t)origin;
	if ((displacement & 3) != 0) return 0;
	int64_t offset = displacement / 4;
	if (offset < -(1LL << 25) || offset >= (1LL << 25)) return 0;
	return 0x94000000U | ((uint32_t)offset & 0x03FFFFFFU);
}

int emit_hookd_svc_trampoline(uint32_t *patchpoint, uint32_t *shellcode, size_t *emittedSize)
{
	size_t oneShcSize = (size_t)(hook_trampoline_template_end - hook_trampoline_template);

	uint32_t curShc[oneShcSize];

	memcpy(curShc, hook_trampoline_template, oneShcSize * sizeof(uint32_t));

	uint32_t replacementInsn = arm64_gen_b((vm_address_t)patchpoint, (vm_address_t)shellcode);
	size_t callIdx    = hook_trampoline_template_call    - hook_trampoline_template;
	size_t jmpbackIdx = hook_trampoline_template_jmpback - hook_trampoline_template;

	curShc[callIdx]    = arm64_gen_bl((vm_address_t)&shellcode[callIdx],    (vm_address_t)hookd_intercept_syscall);
	curShc[jmpbackIdx] = arm64_gen_b ((vm_address_t)&shellcode[jmpbackIdx], (vm_address_t)&patchpoint[1]);

	if (!replacementInsn || !curShc[callIdx] || !curShc[jmpbackIdx]) return -1;

	int r = litehook_hook_memory(shellcode, curShc, sizeof(curShc));
	if (r != 0) return r;
	r = litehook_hook_memory(patchpoint, &replacementInsn, sizeof(replacementInsn));
	if (r != 0) return r;

	if (emittedSize) *emittedSize = oneShcSize;
	return 0;
}

int apply_hookd_syscall_patches(uint32_t *textPtr, size_t textSize)
{
	const size_t shcPageSize = 0x4000;
	const size_t oneShcWords = (size_t)(hook_trampoline_template_end - hook_trampoline_template);
	if (oneShcWords == 0 || oneShcWords > (shcPageSize / sizeof(uint32_t))) return -1;

	size_t siteCount = 0;
	for (uint64_t i = 0; i < (textSize / sizeof(uint32_t)); i++) {
		if (textPtr[i] == 0xd4001001) siteCount++;
	}
	if (siteCount > (shcPageSize / (oneShcWords * sizeof(uint32_t)))) return -1;
	if (siteCount == 0) return 0;

	vm_address_t shcPage = 0;
	uint64_t off = 0;

	for (uint64_t i = 0; i < (textSize / sizeof(uint32_t)); i++) {
		if (textPtr[i] == 0xd4001001) /* svc 0x80 */ {
			if (shcPage == 0) {
					kern_return_t kr = vm_allocate_nearby(mach_task_self(), (vm_address_t)textPtr, (vm_size_t)textSize, &shcPage, shcPageSize, (1ULL << 21));
				if (kr != KERN_SUCCESS) {
					return -1;
				}
			}
				size_t emittedSize = 0;
				int r = emit_hookd_svc_trampoline(&textPtr[i], &((uint32_t *)shcPage)[off], &emittedSize);
				if (r != 0) return r;
				if (emittedSize != oneShcWords || off > (shcPageSize / sizeof(uint32_t)) - emittedSize) return -1;
				off += emittedSize;
			}
		}

	return 0;
}

static bool hookd_prologue_is_pc_independent(const uint32_t *instructions, size_t count)
{
	for (size_t i = 0; i < count; i++) {
		uint32_t insn = instructions[i];
		if ((insn & 0x1F000000U) == 0x10000000U || /* ADR/ADRP */
			(insn & 0x7C000000U) == 0x14000000U || /* B/BL */
			(insn & 0xFF000010U) == 0x54000000U || /* B.cond */
			(insn & 0x7E000000U) == 0x34000000U || /* CBZ/CBNZ */
			(insn & 0x7E000000U) == 0x36000000U || /* TBZ/TBNZ */
			(insn & 0x3B000000U) == 0x18000000U) { /* literal load/prefetch */
			return false;
		}
	}
	return true;
}

static void image_loaded(const struct mach_header* mh, intptr_t vmaddr_slide)
{
	Dl_info imageInfo;
	if (dladdr(mh, &imageInfo) == 0) return;

	if (_dyld_shared_cache_contains_path(imageInfo.dli_fname)) return;

	void *handle = dlopen(imageInfo.dli_fname, RTLD_NOLOAD);
	if (!handle) return;

	const char *paths_to_hook[] = {
		"/usr/lib/frida/frida-agent.dylib",
	};

	void **EKHookMemoryRaw_ptr = dlsym(handle, "EKHookMemoryRaw");
	if (EKHookMemoryRaw_ptr) {
		*EKHookMemoryRaw_ptr = litehook_hook_memory_hookd;
	}
	else {
		for (int k = 0; k < sizeof(paths_to_hook) / sizeof(*paths_to_hook); k++) {
			if (string_has_suffix(imageInfo.dli_fname, paths_to_hook[k])) {
				const struct section_64 *textSect = getsectbynamefromheader_64((const struct mach_header_64 *)mh, "__TEXT", "__text");
				uint32_t *textPtr = (uint32_t *)(textSect->addr + vmaddr_slide);
				apply_hookd_syscall_patches(textPtr, textSect->size);
				break;
			}
		}
	}
}


int find_frida_text(void (^foundHandler)(uint32_t *ptr, size_t size))
{
	int r = 0;
	mach_port_t task = mach_task_self();
	mach_vm_address_t start = 0x0;
	mach_vm_address_t end = -1;
	int depth = 0;
	for (bool first = true;; first = false) {
		mach_vm_address_t address = start;
		mach_vm_size_t size = 0;
		uint32_t depth0 = depth;
		vm_region_submap_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse(task, &address, &size, &depth0, (vm_region_recurse_info_t)&info, &count);
		if (kr != KERN_SUCCESS || address > end) {
			break;
		}
		if (info.protection & VM_PROT_EXECUTE) {
			// If dyld knows about this region, we can skip it...
			// frida's region is unknown to dyld (hence we even need to find it in the first place)
			Dl_info info;
			if (dladdr((void *)address, &info) == 0) {
				// An easy way to figure out whether what we have is fridas text is to check whether the string "FridaAgent" appears within the first two pages
				if (size >= 0x8000) {
					const char *needle = "FridaAgent";
					if (memmem((const void *)address, size, needle, sizeof(needle)) != NULL) {
						foundHandler((uint32_t *)address, size);
					}
				}
			}
		}
		start = address + size;
	}
	return r;
}



typedef struct {
	void *(*routine)(void *);
	void *argument;
} ThreadStartContext;

void *pthread_handler_hook(void *arg)
{
	ThreadStartContext context = *(ThreadStartContext *)arg;
	free(arg);
	find_frida_text(^(uint32_t *fridaTextPtr, size_t fridaSize){
		apply_hookd_syscall_patches(fridaTextPtr, fridaSize);
	});

	return context.routine(context.argument);
}

int (*_pthread_create_orig)(pthread_t *restrict thread,
						  const pthread_attr_t *restrict attr,
						  typeof(void *(void *)) *start_routine,
						  void *restrict arg, uint32_t whatever);

int _pthread_create_hook(pthread_t *restrict thread,
						  const pthread_attr_t *restrict attr,
						  typeof(void *(void *)) *start_routine,
						  void *restrict arg, uint32_t whatever)
{
	if (!get_tpidrr0_el0()) {
		// When frida calls it, it will always be from a thread that doesn't have TPIDRRO_EL0 set
		ThreadStartContext *context = malloc(sizeof(*context));
		if (!context) return ENOMEM;
		*context = (ThreadStartContext){ .routine = start_routine, .argument = arg };
		int result = _pthread_create_orig(thread, attr, pthread_handler_hook, context, whatever);
		if (result != 0) free(context);
		return result;
	}

	return _pthread_create_orig(thread, attr, start_routine, arg, whatever);
}

int init_hookd_external_support(void)
{
	_dyld_register_func_for_add_image(image_loaded);

	// Frida iOS 26 hackfix
	// Frida bundles it's own linker
	// It will remotely map it's agent in via a task port and then at some point invoke pthread_create to spawn a thread that will jump into the agent code
	// At this point we need to intervene by hooking pthread_create and scanning for the agent in memory
	// If we find it, we need to manually apply the hooks to inline syscalls to make it work on iOS 26

	void *_pthread_create_ptr = litehook_find_dsc_symbol("/usr/lib/system/libsystem_pthread.dylib", "__pthread_create");
	if (!_pthread_create_ptr) return ENOENT;

	void *_pthread_create_ptr_unsigned = ptrauth_strip((void *)_pthread_create_ptr, ptrauth_key_function_pointer);

	vm_address_t shcPage = 0;
	kern_return_t kr = vm_allocate(mach_task_self(), &shcPage, 0x4000, VM_FLAGS_ANYWHERE);
	if (kr != KERN_SUCCESS) return EIO;

	// We cannot get an allocation within 2^21 of _pthread_create, so we cannot use direct branches
	// Our only option is to use 4 mov's into x16 and a br x16
	// This orig trampoline assumes that the first 5 instructions of _pthread_create are PC-independent
	uint32_t *fridaHookOrigShc = (uint32_t *)shcPage;
	if (!hookd_prologue_is_pc_independent((const uint32_t *)_pthread_create_ptr_unsigned, 5)) {
		vm_deallocate(mach_task_self(), shcPage, 0x4000);
		return ENOTSUP;
	}
	memcpy(fridaHookOrigShc, _pthread_create_ptr_unsigned, sizeof(uint32_t) * 5);
	kr = litehook_hook_function(ptrauth_sign_unauthenticated(&fridaHookOrigShc[5], ptrauth_key_function_pointer, 0), ptrauth_sign_unauthenticated((void *)((uintptr_t)_pthread_create_ptr_unsigned + sizeof(uint32_t) * 5), ptrauth_key_function_pointer, 0));
	if (kr != KERN_SUCCESS) {
		vm_deallocate(mach_task_self(), shcPage, 0x4000);
		return EIO;
	}
	_pthread_create_orig = (void *)ptrauth_sign_unauthenticated(fridaHookOrigShc, ptrauth_key_function_pointer, 0);

	kr = litehook_hook_function(_pthread_create_ptr, _pthread_create_hook);
	if (kr != KERN_SUCCESS) {
		_pthread_create_orig = NULL;
		vm_deallocate(mach_task_self(), shcPage, 0x4000);
		return EIO;
	}
	return 0;
}
