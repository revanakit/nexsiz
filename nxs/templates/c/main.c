/* NXS C template — honour nxs/CONTRACT.md */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    int has_crash = 0, has_meta = 0, has_target = 0;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            fprintf(stderr, "nxs-c-template — custom NXS skeleton\n");
            return 0;
        }
        if (strcmp(argv[i], "--version") == 0) {
            printf("nxs-c-template 0.1.0 (id=custom/c-template)\n");
            return 0;
        }
        if (strcmp(argv[i], "--crash") == 0) has_crash = 1;
        if (strcmp(argv[i], "--meta") == 0) has_meta = 1;
        if (strcmp(argv[i], "--target") == 0) has_target = 1;
    }

    if (!has_crash && !has_meta) {
        fprintf(stderr, "error: at least one of --crash or --meta required\n");
        return 1;
    }
    if (!has_target && !has_meta) {
        fprintf(stderr, "error: --target required when --meta is absent\n");
        return 1;
    }

    fprintf(stderr, "[nxs-c-template] skeleton — replace with real logic\n");
    return 0;
}
