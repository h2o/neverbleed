#include <check.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>

// Include the actual neverbleed.c header or declare the function
// Assuming the vulnerable function is process_tempdir() that takes a tempdir argument
extern void process_tempdir(const char *tempdir);

START_TEST(test_tempdir_double_free_invariant)
{
    // Invariant: Memory management operations on 'tempdir' must maintain single ownership semantics
    const char *payloads[] = {
        // Exact exploit case: Path that triggers double free in original vulnerability
        "/tmp/exploit\0hidden",
        // Boundary case: Empty string (edge case for allocation)
        "",
        // Valid input: Normal temporary directory path
        "/tmp/valid_dir",
        // Adversarial case: Path with maximum length to test buffer boundaries
        "/tmp/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        // Adversarial case: Path with special characters
        "/tmp/../../etc/passwd"
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        // Create a copy to pass to the function since it may modify/free the argument
        char *tempdir_copy = strdup(payloads[i]);
        if (tempdir_copy == NULL) {
            ck_abort_msg("Failed to allocate memory for test payload");
        }
        
        // Call the actual production function - this must not cause double free
        process_tempdir(tempdir_copy);
        
        // The invariant: If the function frees tempdir_copy, it must set it to NULL
        // or ensure it's not accessed again. We can't directly test freed memory,
        // but we can verify the program didn't crash (test runs to completion).
        // In practice, we'd use tools like AddressSanitizer, but for unit test:
        // Simply reaching here means no immediate crash from double free.
        
        // Note: We don't free tempdir_copy here since process_tempdir may have taken ownership
        // This mimics real usage patterns
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_tempdir_double_free_invariant);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}