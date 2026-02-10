#ifndef MPT_TEST_UTILS_H
#define MPT_TEST_UTILS_H

#include <stdio.h>
#include <stdlib.h>

/* --- Macro: Persistent Assertion --- */
/* Ensures checks run in both Debug and Release modes */
#define EXPECT(condition) do { \
    if (!(condition)) { \
        fprintf(stderr, "TEST FAILED: %s at line %d\n", #condition, __LINE__); \
        abort(); \
    } \
} while(0)

#endif // MPT_TEST_UTILS_H
