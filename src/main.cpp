#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

extern "C" {
#include <ps5/kernel.h>
}

#include "config.h"
#include "debug_log.h"
#include "hen.h"
#include "kdlsym.h"
#include "kexec.h"
#include "mirror.h"
#include "paging.h"
#include "patching.h"
#include "self.h"
#include "util.h"

int g_debug_sock = -1;

extern "C"
{
    int sceKernelSleep(int secs);
    int sceKernelLoadStartModule(char *name, size_t argc, const void *argv, uint32_t flags, void *unk, int *res);
    int __sys_is_development_mode();
    int sceSystemStateMgrEnterStandby(void);
}

void dump_kernel_to_client(int client)
{
    int write_ret;
    char data_buf[0x4000];
    uint64_t qword;

    SOCK_LOG("[+] Dumping kernel to client\n");

    // Write firmware version
    qword = kernel_get_fw_version() & 0xFFFF0000;
    if (write(client, &qword, sizeof(qword)) != sizeof(qword)) {
        SOCK_LOG("[!] Failed to send FW version\n");
        close(client);
        return;
    }

    // Write kernel base address
    qword = ktext(0);
    if (write(client, &qword, sizeof(qword)) != sizeof(qword)) {
        SOCK_LOG("[!] Failed to send kernel base\n");
        close(client);
        return;
    }

    // Write kernel .text + data
    for (uint64_t addr = ktext(0); ; addr += sizeof(data_buf)) {
        kernel_copyout(addr, &data_buf, sizeof(data_buf));
        write_ret = write(client, &data_buf, sizeof(data_buf));
        if (write_ret < 0)
            break;
    }

    // We shouldn't reach here, we should crash
    close(client);
    SOCK_LOG("[+] Done\n");
}

int main()
{
    int ret;
    int debug_sock = -1;
    struct sockaddr_in addr;
    uint64_t kernel_pmap;
    uint64_t pte_addr;
    uint64_t pde_addr;
    uint64_t pte;
    uint64_t pde;

    // Set shellcore auth ID
    kernel_set_ucred_authid(getpid(), 0x4800000000000007);

    // Open a debug socket if enabled
    if (PC_DEBUG_ENABLED) {
        debug_sock = socket(AF_INET, SOCK_STREAM, 0);
        if (debug_sock < 0) {
            return 0xDEAD0001;
        }

        inet_pton(AF_INET, PC_DEBUG_IP, &addr.sin_addr);
        addr.sin_family = AF_INET;
        addr.sin_len    = sizeof(addr);
        addr.sin_port   = htons(PC_DEBUG_PORT);

        ret = connect(debug_sock, (const struct sockaddr *) &addr, sizeof(addr));
        if (ret < 0) {
            return 0xDEAD0002;
        }

        SOCK_LOG("[!] debug socket connected\n");
        g_debug_sock = debug_sock;
    }

    // Jailbreak
    kernel_set_proc_rootdir(getpid(), kernel_get_root_vnode());

    kernel_pmap = kdlsym(KERNEL_SYM_PMAP_STORE);
    SOCK_LOG("[+] Kernel pmap = 0x%lx\n", kernel_pmap);

    // Disable xotext + enable write  on kernel .text pages
    SOCK_LOG("[+] Disabling xotext + enabling write\n");
    for (uint64_t addr = ktext(0); addr < KERNEL_ADDRESS_DATA_BASE; addr += 0x1000) {
        pde_addr = find_pde(kernel_pmap, addr, &pde);
        if (pde_addr != 0xFFFFFFFFFFFFFFFFull) {
            CLEAR_PDE_BIT(pde, XOTEXT);
            SET_PDE_BIT(pde, RW);
            kernel_copyin(&pde, pde_addr, sizeof(pde));
        }

        pte_addr = find_pte(kernel_pmap, addr, &pte);
        if (pte_addr != 0xFFFFFFFFFFFFFFFFull) {
            CLEAR_PDE_BIT(pte, XOTEXT);
            SET_PDE_BIT(pte, RW);
            kernel_copyin(&pte, pte_addr, sizeof(pte));
        }
    }

    // auto suspend
    sceSystemStateMgrEnterStandby();

    // Check if this is a resume state or not, if it's not, prompt for restart and exit
    if (kernel_read4(kdlsym(KERNEL_SYM_DATA_CAVE)) != 0x1337) {
        // Notify the user that they have to suspend/resume their console
        SOCK_LOG("[+] System needs to be suspended and resumed...\n");
        flash_notification("Byepervisor\nEnter rest mode & resume");
        kernel_write4(kdlsym(KERNEL_SYM_DATA_CAVE), 0x1337);

        return 0;
    }

    // Print out the kernel base
    SOCK_LOG("[+] Kernel base = 0x%lx\n", ktext(0));

    // Apply patches
    if (apply_kernel_patches() != 0) {
        SOCK_LOG("[!] Applying kernel patches failed, firmware likely not supported\n");
        return -1;
    }

    // Calculate the remaining blocks after 0x1000 segments
    uint64_t KELF_REMAINING = KELF_SZ % 0x1000;

    // Calculate the number of blocks to copy
    uint64_t KELF_BLOCK_COPIES = KELF_SZ / 0x1000;

    // Calculate the offset of the remaining data
    uint64_t KELF_REMAINING_START_OFFSET = KELF_BLOCK_COPIES * 0x1000;

    // Copy hen into kernel code cave
    for (uint32_t i = 0; i < KELF_SZ; i += 0x1000) {
        kernel_copyin(&KELF[i], kdlsym(KERNEL_SYM_CODE_CAVE) + i, 0x1000);
    }
    if (KELF_REMAINING != 0)
        kernel_copyin(&KELF[KELF_REMAINING_START_OFFSET], kdlsym(KERNEL_SYM_CODE_CAVE) + KELF_REMAINING_START_OFFSET, KELF_REMAINING);

    // Install kexec syscall
    SOCK_LOG("[+] Installing kexec syscall\n");
    install_kexec();

    // Print out the development mode before and after jailbreak
    SOCK_LOG("[+] Bef. hook is_development_mode = 0x%x\n", __sys_is_development_mode());

    // Run hen from the code cave
    int test_ret = kexec(kdlsym(KERNEL_SYM_CODE_CAVE));
    SOCK_LOG("[+] kexec returned: 0x%x\n", test_ret);

    SOCK_LOG("[+] Aft. hook is_development_mode = 0x%x\n", __sys_is_development_mode());

    run_self_server(9004);
    // run_dump_server(9003);
    reset_mirrors();
    return 0;
}
