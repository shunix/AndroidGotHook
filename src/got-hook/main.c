#include "config.h"
#include "elf_utils.h"
#include "injector.h"
#include "ptrace.h"
#include "utils.h"

int main(int argc, char const *argv[]) {
  if (argc < 4) {
    return -1;
  }
  const char* process_name = argv[1];
  const char* hook_library_path = argv[2];
  const char* target_library_path = argv[3];
  pid_t pid = GetPid(process_name);
  long so_handle = InjectLibrary(pid, hook_library_path);
  PtraceAttach(pid);
  long hook_fuction_addr = CallDlsym(pid, so_handle, "my_printf");
  PtraceDetach(pid);
  long original_function_addr = GetRemoteFuctionAddr(pid, LIBC_PATH, (long)printf);
  if (DEBUG) {
    printf("hook_fuction_addr: %lx, original_function_addr: %lx\n", hook_fuction_addr, original_function_addr);
  }
  PatchRemoteGot(pid, target_library_path, original_function_addr, hook_fuction_addr);
  return 0;
}
