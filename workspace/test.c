
int main() {
    int arr[5] = {1, 2, 3, 4, 5};
    int *ptr = arr;

    int oob = ptr[10];

    return 0;
}
