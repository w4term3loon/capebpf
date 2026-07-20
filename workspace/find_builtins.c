#include <cheri/cheri.h>
#include <stdio.h>
int main(void) {
    void * __capability ddc = cheri_ddc_get();
    void * __capability csp = cheri_stack_get();
    uint64_t perms = cheri_perms_get(ddc);
    printf("DDC perms: 0x%llx\n", (unsigned long long)perms);
    printf("DDC addr: 0x%llx\n", (unsigned long long)cheri_address_get(ddc));
    perms = cheri_perms_get(csp);
    printf("CSP perms: 0x%llx\n", (unsigned long long)perms);
    return 0;
}
