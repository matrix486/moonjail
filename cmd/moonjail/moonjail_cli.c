#include "moonbit.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#if defined(__linux__)
#include <sys/socket.h>
#include <unistd.h>
#endif

MOONBIT_FFI_EXPORT void moonjail_cli_exit(int32_t code) { exit(code); }

MOONBIT_FFI_EXPORT void moonjail_cli_error(moonbit_bytes_t message) {
  fwrite(message, 1, (size_t)Moonbit_array_length(message), stderr);
  fputc('\n', stderr);
}

MOONBIT_FFI_EXPORT int32_t moonjail_cli_probe_socket(void) {
#if defined(__linux__)
  int fd = socket(AF_INET, SOCK_STREAM, 0);
  if (fd < 0) {
    return errno;
  }
  close(fd);
  return 0;
#else
  return -1;
#endif
}
