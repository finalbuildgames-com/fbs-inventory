#include <fbs/inventory.h>
#include <stdio.h>
int main(void) {
    fbs_inv_config config = fbs_inv_config_default();
    fbs_inv_store *context = NULL;
    if (fbs_inv_store_create(&config, NULL, &context) != 0) return 1;
    printf("API version: %u\n", fbs_inv_version());
    fbs_inv_store_destroy(context);
    return 0;
}
