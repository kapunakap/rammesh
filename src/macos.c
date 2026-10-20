#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <sys/sysctl.h>
#include <stdint.h>
#include <string.h>

struct memory_info {
    uint64_t physical, page_size, free_bytes, inactive_bytes, wired_bytes, compressed_bytes;
    uint32_t pressure, pressure_known;
};

int rammesh_memory_info(struct memory_info *out) {
    memset(out, 0, sizeof(*out));
    size_t n = sizeof(out->physical);
    if (sysctlbyname("hw.memsize", &out->physical, &n, NULL, 0)) return -1;
    vm_size_t page;
    mach_port_t host = mach_host_self();
    vm_statistics64_data_t s = {0};
    mach_msg_type_number_t count = HOST_VM_INFO64_COUNT;
    kern_return_t a = host_page_size(host, &page);
    kern_return_t b = host_statistics64(host, HOST_VM_INFO64, (host_info64_t)&s, &count);
    mach_port_deallocate(mach_task_self(), host);
    if (a != KERN_SUCCESS || b != KERN_SUCCESS) return -1;
    out->page_size = page;
    /* free_count already includes speculative_count: do not double count it. */
    out->free_bytes = (uint64_t)s.free_count * page;
    out->inactive_bytes = (uint64_t)s.inactive_count * page;
    out->wired_bytes = (uint64_t)s.wire_count * page;
    out->compressed_bytes = (uint64_t)s.compressor_page_count * page;
    n = sizeof(out->pressure);
    out->pressure_known = !sysctlbyname("kern.memorystatus_vm_pressure_level", &out->pressure, &n, NULL, 0);
    return 0;
}

/* Independent VM query, in addition to mincore and the successful mlock call. */
int rammesh_region_info(uint64_t address, uint64_t *size, uint64_t *resident,
                        uint64_t *swapped, uint32_t *external, uint32_t *wired) {
    mach_vm_address_t start = address;
    mach_vm_size_t len = 0;
    natural_t depth = 0;
    vm_region_submap_info_data_64_t info = {0};
    mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
    kern_return_t k = mach_vm_region_recurse(mach_task_self(), &start, &len, &depth,
                                            (vm_region_recurse_info_t)&info, &count);
    if (k != KERN_SUCCESS || start != address || info.is_submap) return -1;
    *size = len;
    *resident = info.pages_resident;
    *swapped = info.pages_swapped_out;
    *external = info.external_pager;
    *wired = info.user_wired_count;
    return 0;
}
