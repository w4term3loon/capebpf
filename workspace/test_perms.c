#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <cheri/cheric.h>

static void print_cap(const char *label, void * __capability cap) {
    cheri_perms_t perms = cheri_perms_get(cap);
    size_t addr = cheri_address_get(cap);
    size_t base = cheri_base_get(cap);
    size_t len = cheri_length_get(cap);
    _Bool tag = cheri_tag_get(cap);
    _Bool sealed = cheri_getsealed(cap);

    printf("%s:\n", label);
    printf("  tag=%d sealed=%d addr=0x%llx base=0x%llx len=0x%llx\n",
           (int)tag, (int)sealed, (unsigned long long)addr,
           (unsigned long long)base, (unsigned long long)len);
    printf("  perms=0x%x:", perms);
    if (perms & 0x20000) printf(" LOAD");
    if (perms & 0x10000) printf(" STORE");
    if (perms & 0x8000) printf(" EXEC");
    if (perms & 0x4000) printf(" LOAD_CAP");
    if (perms & 0x2000) printf(" STORE_CAP");
    if (perms & 0x1000) printf(" STORE_LOCAL");
    if (perms & 0x0800) printf(" SYSREGS");
    if (perms & 0x0001) printf(" GLOBAL");
    printf("\n");
}

void compiled_fn(void) { }

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);

    void * __capability ddc = cheri_ddc_get();
    print_cap("DDC", ddc);

    void * __capability pcc = cheri_pcc_get();
    print_cap("PCC", pcc);

    void * __capability fn = (void * __capability)(void*)compiled_fn;
    print_cap("compiled_fn (.text)", fn);

    void *mmap_rwx = mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                          MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mmap_rwx == (void*)-1) { perror("mmap rwx"); return 1; }
    print_cap("mmap RWX", (void * __capability)mmap_rwx);

    void *mmap_rw = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    print_cap("mmap RW (data)", (void * __capability)mmap_rw);

    void *mmap_rx = mmap(NULL, 4096, PROT_READ|PROT_WRITE,
                         MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    if (mmap_rx != (void*)-1) {
        if (mprotect(mmap_rx, 4096, PROT_READ|PROT_EXEC) == 0)
            print_cap("mprotect RW->RX", (void * __capability)mmap_rx);
        else
            printf("mprotect RW->RX: FAILED (%s)\n", strerror(errno));
    }

    printf("\nAttempting cheri_perms_and on mmap RWX...\n");
    void * __capability enhanced = cheri_perms_and((void * __capability)mmap_rwx,
        0x20000 | 0x10000 | 0x4000 | 0x2000 | 0x1000 | 0x8000);
    print_cap("enhanced mmap RWX", enhanced);

    return 0;
}
