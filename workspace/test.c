#include <stdio.h>

int
main(void)
{
    int arr[5] = {1, 2, 3, 4, 5};
    int *ptr = arr;
    volatile int index = 10;

    printf("about to read arr[%d]\n", (int)index);

    int value = ptr[index];

    printf("unexpectedly survived, value=%d\n", value);
    return 1;
}
