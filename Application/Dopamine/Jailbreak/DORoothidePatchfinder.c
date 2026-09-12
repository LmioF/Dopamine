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
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.launch_env_logging", launchLogging);
    xpc_dictionary_set_uint64(offsets, "kernelSymbol.developer_mode_status", developerMode);
    return 0;
}
