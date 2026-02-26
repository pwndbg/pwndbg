/* Binary for testing backtrace frame label alignment.
 * Provides two entry points:
 *   break_shallow  - reached from main() with ~2 frames (tests single-digit
 * labels) break_deep     - reached via 12 nested calls (tests 10+ frame label
 * width padding)
 */
#include <stdio.h>

__attribute__((noinline)) void break_shallow(void) {}

__attribute__((noinline)) void break_deep(void) {}

__attribute__((noinline)) static void f11(void) { break_deep(); }
__attribute__((noinline)) static void f10(void) { f11(); }
__attribute__((noinline)) static void f9(void) { f10(); }
__attribute__((noinline)) static void f8(void) { f9(); }
__attribute__((noinline)) static void f7(void) { f8(); }
__attribute__((noinline)) static void f6(void) { f7(); }
__attribute__((noinline)) static void f5(void) { f6(); }
__attribute__((noinline)) static void f4(void) { f5(); }
__attribute__((noinline)) static void f3(void) { f4(); }
__attribute__((noinline)) static void f2(void) { f3(); }
__attribute__((noinline)) static void f1(void) { f2(); }

int main(void) {
  break_shallow();
  f1();
  return 0;
}
