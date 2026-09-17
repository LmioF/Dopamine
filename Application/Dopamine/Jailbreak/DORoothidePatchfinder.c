#include "DORoothidePatchfinder.h"
#include <xpf/xpf.h>
#include <stdlib.h>
#include <string.h>

static PFSection *roothide_section(const char *entry, const char *segment, const char *section)
{
    PFSection *result = pfsec_init_from_macho(gXPF.kernel, gXPF.kernelIsFileset ? entry : NULL, segment, section);
    if (result) {
        pfsec_set_cached(result, true);
        pfsec_set_pointer_decoder(result, xpfsec_decode_pointer);
    }
    return result;
}

static int find_namecache(uint64_t *table, uint64_t *mask)
{
    uint32_t instructions[2], masks[2];
    arm64_gen_mov_imm('z', ARM64_REG_ANY, OPT_UINT64(0x1db7), OPT_UINT64_NONE, &instructions[0], &masks[0]);
    arm64_gen_mov_imm('k', ARM64_REG_ANY, OPT_UINT64(0x4c1), OPT_UINT64(16), &instructions[1], &masks[1]);
    PFPatternMetric *crcMetric = pfmetric_pattern_init(instructions, masks, sizeof(instructions), 4);
    __block uint64_t foundTable = 0, foundMask = 0;
    __block bool ambiguous = false;
    pfmetric_run(gXPF.kernelTextSection, crcMetric, ^(uint64_t address, bool *stop) {
        uint32_t call, callMask;
        arm64_gen_b_l(OPT_BOOL(true), OPT_UINT64_NONE, OPT_UINT64_NONE, &call, &callMask);
        uint64_t hashInit = pfsec_find_next_inst(gXPF.kernelTextSection, address, 100, call, callMask);
        if (!hashInit) return;
        uint64_t candidates[2] = {0};
        unsigned count = 0;
        for (uint64_t pc = hashInit + 4; pc < hashInit + 80 && count < 2; pc += 4) {
            if (!pfsec_contains_vmaddr(gXPF.kernelTextSection, pc + 4)) break;
            uint64_t page, displacement;
            arm64_register pageRegister, baseRegister, sourceRegister;
            bool isPage;
            if (arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, pc), pc, &page, &pageRegister, &isPage) != 0 || !isPage) continue;
            if (arm64_dec_str_imm(pfsec_read32(gXPF.kernelTextSection, pc + 4), &sourceRegister, &baseRegister, &displacement, NULL, NULL) != 0) continue;
            if (ARM64_REG_GET_NUM(pageRegister) != ARM64_REG_GET_NUM(baseRegister) || !ARM64_REG_IS_X(sourceRegister) || (count == 0 && ARM64_REG_GET_NUM(sourceRegister) != 0)) continue;
            uint64_t target = page + displacement;
            if (target < gXPF.kernelBase || (target & 7)) continue;
            candidates[count++] = target;
        }
        if (count != 2 || candidates[0] == candidates[1]) return;
        if (foundTable && (foundTable != candidates[0] || foundMask != candidates[1])) {
            ambiguous = true;
            *stop = true;
            return;
        }
        foundTable = candidates[0];
        foundMask = candidates[1];
    });
    pfmetric_free(crcMetric);
    if (!foundTable || !foundMask || ambiguous) {
        xpf_set_error("Roothide: name-cache globals were not uniquely resolved");
        return -1;
    }
    *table = foundTable;
    *mask = foundMask;
    return 0;
}

static uint64_t find_unique_kernel_function_for_string(const char *string)
{
    if (!gXPF.kernelStringSection || !string) return 0;

    __block uint64_t stringAddress = 0;
    __block bool ambiguousString = false;
    PFStringMetric *stringMetric = pfmetric_string_init(string);
    pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t address, bool *stop) {
        if (stringAddress && stringAddress != address) ambiguousString = true;
        stringAddress = address;
    });
    pfmetric_free(stringMetric);
    if (!stringAddress || ambiguousString) return 0;

    __block uint64_t function = 0;
    __block bool ambiguousFunction = false;
    PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddress, XREF_TYPE_MASK_REFERENCE);
    pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t reference, bool *stop) {
        uint64_t candidate = pfsec_find_function_start(gXPF.kernelTextSection, reference);
        if (!candidate) return;
        if (function && function != candidate) ambiguousFunction = true;
        function = candidate;
    });
    pfmetric_free(xrefMetric);
    return ambiguousFunction ? 0 : function;
}

static int find_vnode_reference_primitives(uint64_t *vnodeRefExtOut, uint64_t *vnodeReleExtOut)
{
    static const char *refString = "vnode_ref_ext: vp %p has no valid reference %d, %d @%s:%d";
    static const char *releString = "vnode_rele_ext: vp %p usecount -ve : %d.  v_tag = %d, v_type = %d, v_flag = %x. @%s:%d";
    uint64_t vnodeRefExt = find_unique_kernel_function_for_string(refString);
    uint64_t vnodeReleExt = find_unique_kernel_function_for_string(releString);
    if (!vnodeRefExt || !vnodeReleExt || vnodeRefExt == vnodeReleExt) {
        xpf_set_error("Roothide: vnode reference primitives were not uniquely resolved");
        return -1;
    }
    *vnodeRefExtOut = vnodeRefExt;
    *vnodeReleExtOut = vnodeReleExt;
    return 0;
}

static size_t find_kernel_functions_for_string(const char *string, uint64_t *functions, size_t capacity)
{
    if (!gXPF.kernelStringSection || !string || !functions || !capacity) return 0;

    __block uint64_t stringAddress = 0;
    PFStringMetric *stringMetric = pfmetric_string_init(string);
    pfmetric_run(gXPF.kernelStringSection, stringMetric, ^(uint64_t address, bool *stop) {
        if (!stringAddress) stringAddress = address;
    });
    pfmetric_free(stringMetric);
    if (!stringAddress) return 0;

    __block size_t count = 0;
    PFXrefMetric *xrefMetric = pfmetric_xref_init(stringAddress, XREF_TYPE_MASK_REFERENCE);
    pfmetric_run(gXPF.kernelTextSection, xrefMetric, ^(uint64_t reference, bool *stop) {
        uint64_t candidate = pfsec_find_function_start(gXPF.kernelTextSection, reference);
        if (!candidate) return;
        for (size_t i = 0; i < count; i++) {
            if (functions[i] == candidate) return;
        }
        if (count >= capacity) {
            count = capacity + 1;
            *stop = true;
            return;
        }
        functions[count++] = candidate;
    });
    pfmetric_free(xrefMetric);
    return count;
}

static uint64_t resolve_x0_address_before_call(uint64_t callAddress)
{
    for (unsigned addDistance = 1; addDistance <= 5; addDistance++) {
        uint64_t addAddress = callAddress - addDistance * sizeof(uint32_t);
        arm64_register destination, source;
        uint16_t immediate = 0;
        if (arm64_dec_add_imm(pfsec_read32(gXPF.kernelTextSection, addAddress),
                              &destination, &source, &immediate) != 0 ||
            ARM64_REG_GET_NUM(destination) != 0) continue;

        for (unsigned pageDistance = addDistance + 1; pageDistance <= addDistance + 5; pageDistance++) {
            uint64_t pageAddress = callAddress - pageDistance * sizeof(uint32_t);
            uint64_t page = 0;
            arm64_register pageRegister;
            bool isPage = false;
            if (arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, pageAddress), pageAddress,
                                &page, &pageRegister, &isPage) == 0 && isPage &&
                ARM64_REG_GET_NUM(pageRegister) == ARM64_REG_GET_NUM(source)) {
                return page + immediate;
            }
        }
    }

    for (unsigned distance = 1; distance <= 5; distance++) {
        uint64_t address = callAddress - distance * sizeof(uint32_t);
        uint64_t target = 0;
        arm64_register destination;
        bool isPage = false;
        if (arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, address), address,
                            &target, &destination, &isPage) == 0 && !isPage &&
            ARM64_REG_GET_NUM(destination) == 0) {
            return target;
        }
    }
    return 0;
}

static bool reference_window_writes_address(uint64_t reference, uint64_t target)
{
    uint64_t begin = reference >= 2 * sizeof(uint32_t) ? reference - 2 * sizeof(uint32_t) : reference;
    for (uint64_t pageAddress = begin; pageAddress <= reference + 2 * sizeof(uint32_t); pageAddress += sizeof(uint32_t)) {
        uint64_t page = 0;
        arm64_register pageRegister;
        bool isPage = false;
        if (arm64_dec_adr_p(pfsec_read32(gXPF.kernelTextSection, pageAddress), pageAddress,
                            &page, &pageRegister, &isPage) != 0 || !isPage) continue;

        for (unsigned distance = 1; distance <= 4; distance++) {
            uint64_t storeAddress = pageAddress + distance * sizeof(uint32_t);
            arm64_register sourceRegister, baseRegister;
            uint64_t displacement = 0;
            if (arm64_dec_str_imm(pfsec_read32(gXPF.kernelTextSection, storeAddress),
                                  &sourceRegister, &baseRegister, &displacement, NULL, NULL) == 0 &&
                ARM64_REG_GET_NUM(baseRegister) == ARM64_REG_GET_NUM(pageRegister) &&
                page + displacement == target) {
                return true;
            }
        }
    }
    return false;
}

static size_t find_functions_writing_address(uint64_t target, uint64_t *writers, size_t capacity)
{
    if (!writers || !capacity) return 0;
    __block size_t count = 0;
    PFXrefMetric *metric = pfmetric_xref_init(target, XREF_TYPE_MASK_REFERENCE);
    pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t reference, bool *stop) {
        if (!reference_window_writes_address(reference, target)) return;
        uint64_t candidate = pfsec_find_function_start(gXPF.kernelTextSection, reference);
        if (!candidate) return;
        for (size_t i = 0; i < count; i++) {
            if (writers[i] == candidate) return;
        }
        if (count >= capacity) {
            count = capacity + 1;
            *stop = true;
            return;
        }
        writers[count++] = candidate;
    });
    pfmetric_free(metric);
    return count;
}

static uint64_t find_first_call_from_function(uint64_t caller, uint64_t callee)
{
    __block uint64_t call = 0;
    PFXrefMetric *metric = pfmetric_xref_init(callee, XREF_TYPE_MASK_CALL);
    pfmetric_run(gXPF.kernelTextSection, metric, ^(uint64_t reference, bool *stop) {
        if (pfsec_find_function_start(gXPF.kernelTextSection, reference) != caller) return;
        call = reference;
        *stop = true;
    });
    pfmetric_free(metric);
    return call;
}

static int find_namecache_synchronization(uint64_t table,
                                          uint64_t *lockOut,
                                          uint64_t *lockExclusiveOut,
                                          uint64_t *lockDoneOut)
{
    static const char *lockString = "Taking non-sleepable RW lock with preemption enabled @%s:%d";
    static const char *unlockString = "Releasing non-exclusive RW lock without a reader refcount! @%s:%d";

    uint64_t lockDone = find_unique_kernel_function_for_string(unlockString);
    uint64_t lockFunctions[32] = {0};
    size_t lockFunctionCount = find_kernel_functions_for_string(lockString, lockFunctions,
                                                                sizeof(lockFunctions) / sizeof(lockFunctions[0]));
    if (!lockFunctionCount || lockFunctionCount > sizeof(lockFunctions) / sizeof(lockFunctions[0]) || !lockDone) {
        xpf_set_error("Roothide: name-cache lock primitives were not uniquely resolved");
        return -1;
    }

    uint64_t tableWriters[16] = {0};
    size_t tableWriterCount = find_functions_writing_address(table, tableWriters,
                                                             sizeof(tableWriters) / sizeof(tableWriters[0]));
    if (!tableWriterCount || tableWriterCount > sizeof(tableWriters) / sizeof(tableWriters[0])) {
        xpf_set_error("Roothide: name-cache table writers were not resolved");
        return -1;
    }

    uint64_t lockExclusive = 0;
    uint64_t resolvedLock = 0;
    for (size_t writerIndex = 0; writerIndex < tableWriterCount; writerIndex++) {
        uint64_t tableWriter = tableWriters[writerIndex];
        if (!find_first_call_from_function(tableWriter, lockDone)) continue;

        uint64_t writerLockFunction = 0;
        uint64_t writerLockObject = 0;
        for (size_t i = 0; i < lockFunctionCount; i++) {
            uint64_t call = find_first_call_from_function(tableWriter, lockFunctions[i]);
            if (!call) continue;
            uint64_t candidateLock = resolve_x0_address_before_call(call);
            if (!candidateLock) continue;
            if (writerLockFunction && (writerLockFunction != lockFunctions[i] || writerLockObject != candidateLock)) {
                xpf_set_error("Roothide: name-cache writer uses multiple RW-lock acquisition modes");
                return -1;
            }
            writerLockFunction = lockFunctions[i];
            writerLockObject = candidateLock;
        }
        if (!writerLockFunction || !writerLockObject) continue;

        if (lockExclusive && (lockExclusive != writerLockFunction || resolvedLock != writerLockObject)) {
            xpf_set_error("Roothide: name-cache writer lock acquisition was ambiguous");
            return -1;
        }
        lockExclusive = writerLockFunction;
        resolvedLock = writerLockObject;
    }

    if (!lockExclusive || !resolvedLock || lockExclusive == lockDone) {
        xpf_set_error("Roothide: name-cache writer lock was not uniquely resolved");
        return -1;
    }

    *lockOut = resolvedLock;
    *lockExclusiveOut = lockExclusive;
    *lockDoneOut = lockDone;
    return 0;
}

static uint64_t find_oid(PFSection *data, PFSection *strings, const char *name, const char *description)
{
    if (!data || !strings) return 0;
    __block uint64_t result = 0;
    __block bool ambiguous = false;
    PFStringMetric *descriptionMetric = pfmetric_string_init(description);
    pfmetric_run(strings, descriptionMetric, ^(uint64_t address, bool *stop) {
        PFXrefMetric *referenceMetric = pfmetric_xref_init(address, XREF_TYPE_MASK_POINTER);
        pfmetric_run(data, referenceMetric, ^(uint64_t reference, bool *stopReference) {
            if (reference < 0x18 || !pfsec_contains_vmaddr(data, reference - 0x18)) return;
            uint64_t nameField = reference - 0x18;
            uint64_t nameAddress = pfsec_read_pointer(data, nameField);
            if (!pfsec_contains_vmaddr(strings, nameAddress)) return;
            char *resolvedName = NULL;
            if (pfsec_read_string(strings, nameAddress, &resolvedName) != 0 || !resolvedName) return;
            bool matches = strcmp(resolvedName, name) == 0;
            free(resolvedName);
            if (!matches) return;
            if (result && result != nameField) ambiguous = true;
            result = nameField;
        });
        pfmetric_free(referenceMetric);
    });
    pfmetric_free(descriptionMetric);
    return ambiguous ? 0 : result;
}

int roothide_add_kernel_offsets(xpc_object_t offsets)
{
    if (!offsets || !gXPF.kernel || !gXPF.kernelTextSection) return -1;
    uint64_t table = 0, mask = 0;
    if (find_namecache(&table, &mask) != 0) return -1;

    uint64_t namecacheLock = 0, lockExclusive = 0, lockDone = 0;
    if (find_namecache_synchronization(table, &namecacheLock, &lockExclusive, &lockDone) != 0) return -1;

    uint64_t vnodeRefExt = 0, vnodeReleExt = 0;
    if (find_vnode_reference_primitives(&vnodeRefExt, &vnodeReleExt) != 0) return -1;

    uint64_t launchLogging = 0, developerMode = 0;
    if (strtod(gXPF.darwinVersion, NULL) >= 22.0) {
        PFSection *strings = gXPF.kernelAMFIStringSection ?: gXPF.kernelStringSection;
        const char *entry = gXPF.kernelIsFileset ? "com.apple.driver.AppleMobileFileIntegrity" : NULL;
        PFSection *data = roothide_section(entry, "__DATA", "__data");
        if (!gXPF.kernelIsArm64e && !gXPF.kernelIsFileset) {
            if (data) pfsec_free(data);
            data = roothide_section(NULL, "__PRELINK_DATA", "__data");
            strings = gXPF.kernelPrelinkTextSection;
        }
        launchLogging = find_oid(data, strings, "launch_env_logging", "launch environment logging");
        developerMode = find_oid(data, strings, "developer_mode_status", "developer mode status");
        if (data) pfsec_free(data);
        if (!launchLogging || !developerMode || launchLogging == developerMode) {
            xpf_set_error("Roothide: AMFI sysctl objects were not uniquely resolved");
            return -1;
        }
    }
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.nchashtbl", table);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.nchashmask", mask);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.namecache_rw_lock", namecacheLock);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.lck_rw_lock_exclusive", lockExclusive);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.lck_rw_done", lockDone);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.vnode_ref_ext", vnodeRefExt);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.vnode_rele_ext", vnodeReleExt);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.launch_env_logging", launchLogging);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.developer_mode_status", developerMode);
    return 0;
}
