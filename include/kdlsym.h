#pragma once
#ifndef KDLSYM_H
#define KDLSYM_H

typedef enum {
    KERNEL_SYM_DMPML4I,
    KERNEL_SYM_DMPDPI,
    KERNEL_SYM_PML4PML4I,
    KERNEL_SYM_PMAP_STORE,
    KERNEL_SYM_DATA_CAVE,
    KERNEL_SYM_MAX
} ksym_t;

typedef enum {
    KERNEL_PATCH_HAS_MMAP_SELF_CAPABILITY,
    KERNEL_PATCH_IS_ALLOWED_TO_MMAP_SELF,
    KERNEL_PATCH_MMAP_SELF_CALL_IS_LOADABLE,
    KERNEL_PATCH_SYS_GETGID,
    KERNEL_PATCH_MAX
} kpatch_t;

uint64_t kdlsym(ksym_t sym);
uint64_t kdlpatch(kpatch_t patch);
uint64_t ktext(uint64_t offset);

#endif // KDLSYM_H