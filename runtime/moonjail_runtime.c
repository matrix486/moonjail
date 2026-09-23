#if defined(__linux__)
#define _GNU_SOURCE
#endif

#include "moonbit.h"

#include <stdint.h>

#if defined(__linux__)
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/seccomp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif

#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

#ifndef CLOSE_RANGE_CLOEXEC
#define CLOSE_RANGE_CLOEXEC (1U << 2)
#endif

static int set_one_limit(int resource, int64_t value) {
  if (value < 0) {
    return 0;
  }
  struct rlimit limit = {(rlim_t)value, (rlim_t)value};
  return setrlimit(resource, &limit);
}

static int add_landlock_path(int ruleset_fd, uint64_t rights,
                             const char *path) {
  int path_fd = open(path, O_PATH | O_CLOEXEC);
  if (path_fd < 0) {
    return -1;
  }
  struct landlock_path_beneath_attr rule = {
      .allowed_access = rights,
      .parent_fd = path_fd,
  };
  int result = (int)syscall(__NR_landlock_add_rule, ruleset_fd,
                            LANDLOCK_RULE_PATH_BENEATH, &rule, 0);
  int saved = errno;
  close(path_fd);
  errno = saved;
  return result;
}

static int apply_landlock(const uint8_t *blob, int32_t length,
                          int required) {
  if (length == 0 && !required) {
    return 0;
  }
  uint64_t handled = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
                     LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_DIR |
                     LANDLOCK_ACCESS_FS_REMOVE_FILE |
                     LANDLOCK_ACCESS_FS_MAKE_CHAR |
                     LANDLOCK_ACCESS_FS_MAKE_DIR |
                     LANDLOCK_ACCESS_FS_MAKE_REG |
                     LANDLOCK_ACCESS_FS_MAKE_SOCK |
                     LANDLOCK_ACCESS_FS_MAKE_FIFO |
                     LANDLOCK_ACCESS_FS_MAKE_BLOCK |
                     LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
                     LANDLOCK_ACCESS_FS_TRUNCATE;
  struct landlock_ruleset_attr attr = {.handled_access_fs = handled};
  int ruleset_fd = (int)syscall(__NR_landlock_create_ruleset, &attr,
                                sizeof(attr), 0);
  if (ruleset_fd < 0) {
    return -1;
  }

  char *copy = (char *)malloc((size_t)length + 1);
  if (copy == NULL) {
    close(ruleset_fd);
    errno = ENOMEM;
    return -1;
  }
  memcpy(copy, blob, (size_t)length);
  copy[length] = '\0';
  char *save_line = NULL;
  for (char *line = strtok_r(copy, "\n", &save_line); line != NULL;
       line = strtok_r(NULL, "\n", &save_line)) {
    char *tab = strchr(line, '\t');
    if (tab == NULL) {
      free(copy);
      close(ruleset_fd);
      errno = EINVAL;
      return -1;
    }
    *tab = '\0';
    uint64_t rights = strtoull(line, NULL, 10) & handled;
    if (add_landlock_path(ruleset_fd, rights, tab + 1) < 0) {
      int saved = errno;
      free(copy);
      close(ruleset_fd);
      errno = saved;
      return -1;
    }
  }
  free(copy);
  if (syscall(__NR_landlock_restrict_self, ruleset_fd, 0) < 0) {
    int saved = errno;
    close(ruleset_fd);
    errno = saved;
    return -1;
  }
  close(ruleset_fd);
  return 0;
}

static int apply_seccomp(const uint32_t *words, int32_t word_count) {
  if (word_count <= 0 || word_count % 4 != 0) {
    errno = EINVAL;
    return -1;
  }
  int32_t count = word_count / 4;
  struct sock_filter *filters =
      (struct sock_filter *)calloc((size_t)count, sizeof(struct sock_filter));
  if (filters == NULL) {
    errno = ENOMEM;
    return -1;
  }
  for (int32_t index = 0; index < count; index++) {
    filters[index].code = (uint16_t)words[index * 4];
    filters[index].jt = (uint8_t)words[index * 4 + 1];
    filters[index].jf = (uint8_t)words[index * 4 + 2];
    filters[index].k = words[index * 4 + 3];
  }
  struct sock_fprog program = {
      .len = (unsigned short)count,
      .filter = filters,
  };
  int result = (int)syscall(__NR_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program);
  int saved = errno;
  free(filters);
  errno = saved;
  return result;
}

static char **decode_argv(const uint8_t *blob, int32_t length) {
  int count = 0;
  for (int32_t index = 0; index < length; index++) {
    if (blob[index] == 0) {
      count++;
    }
  }
  if (count == 0 || blob[length - 1] != 0) {
    errno = EINVAL;
    return NULL;
  }
  char **argv = (char **)calloc((size_t)count + 1, sizeof(char *));
  char *copy = (char *)malloc((size_t)length);
  if (argv == NULL || copy == NULL) {
    free(argv);
    free(copy);
    errno = ENOMEM;
    return NULL;
  }
  memcpy(copy, blob, (size_t)length);
  int arg = 0;
  argv[arg++] = copy;
  for (int32_t index = 0; index < length - 1; index++) {
    if (copy[index] == '\0') {
      argv[arg++] = copy + index + 1;
    }
  }
  argv[count] = NULL;
  return argv;
}

static void report_setup_failure(int fd, int stage) {
  int data[2] = {stage, errno};
  ssize_t ignored = write(fd, data, sizeof(data));
  (void)ignored;
  _exit(125);
}

static int isolate_inherited_fds(void) {
#if defined(__NR_close_range)
  // The setup pipe is already O_CLOEXEC. Marking the full range preserves it
  // for pre-exec error reporting while keeping inherited handles out of the
  // untrusted program. Do not fall back to an incomplete descriptor scan.
  return (int)syscall(__NR_close_range, 3U, ~0U, CLOSE_RANGE_CLOEXEC);
#else
  errno = ENOSYS;
  return -1;
#endif
}

static int64_t monotonic_millis(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
    return -1;
  }
  return (int64_t)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}

MOONBIT_FFI_EXPORT int32_t moonjail_platform(void) { return 1; }

MOONBIT_FFI_EXPORT int32_t moonjail_architecture(void) {
#if defined(__x86_64__)
  return 1;
#elif defined(__aarch64__)
  return 2;
#else
  return 0;
#endif
}

MOONBIT_FFI_EXPORT int32_t moonjail_landlock_abi(void) {
  int result = (int)syscall(__NR_landlock_create_ruleset, NULL, 0,
                            LANDLOCK_CREATE_RULESET_VERSION);
  if (result >= 0) {
    return result;
  }
  if (errno == ENOSYS || errno == EOPNOTSUPP) {
    return 0;
  }
  return -errno;
}

MOONBIT_FFI_EXPORT int64_t moonjail_run(
    uint32_t *words, moonbit_bytes_t argv_blob, moonbit_bytes_t paths_blob,
    int32_t require_landlock, int32_t cpu_seconds,
    int64_t address_space_bytes, int64_t file_size_bytes, int32_t open_files,
    int32_t processes, int32_t timeout_ms) {
  int32_t word_count = Moonbit_array_length(words);
  int32_t argv_length = Moonbit_array_length(argv_blob);
  int32_t paths_length = Moonbit_array_length(paths_blob);
  char **argv = decode_argv(argv_blob, argv_length);
  if (argv == NULL) {
    return -errno;
  }
  int setup_pipe[2];
  if (pipe2(setup_pipe, O_CLOEXEC | O_NONBLOCK) < 0) {
    free(argv[0]);
    free(argv);
    return -errno;
  }
  fflush(NULL);
  pid_t child = fork();
  if (child < 0) {
    int saved = errno;
    close(setup_pipe[0]);
    close(setup_pipe[1]);
    free(argv[0]);
    free(argv);
    return -saved;
  }
  if (child == 0) {
    close(setup_pipe[0]);
    if (setpgid(0, 0) < 0) {
      report_setup_failure(setup_pipe[1], 6);
    }
    if (isolate_inherited_fds() < 0) {
      report_setup_failure(setup_pipe[1], 7);
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
      report_setup_failure(setup_pipe[1], 1);
    }
    if (apply_landlock(paths_blob, paths_length, require_landlock) < 0) {
      report_setup_failure(setup_pipe[1], 2);
    }
    if (set_one_limit(RLIMIT_CPU, cpu_seconds) < 0 ||
        set_one_limit(RLIMIT_AS, address_space_bytes) < 0 ||
        set_one_limit(RLIMIT_FSIZE, file_size_bytes) < 0 ||
        set_one_limit(RLIMIT_NOFILE, open_files) < 0 ||
        set_one_limit(RLIMIT_NPROC, processes) < 0) {
      report_setup_failure(setup_pipe[1], 3);
    }
    if (apply_seccomp(words, word_count) < 0) {
      report_setup_failure(setup_pipe[1], 4);
    }
    execvp(argv[0], argv);
    report_setup_failure(setup_pipe[1], 5);
  }
  close(setup_pipe[1]);
  (void)setpgid(child, child);
  int64_t started = monotonic_millis();
  if (started < 0) {
    int saved = errno;
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    waitpid(child, NULL, 0);
    close(setup_pipe[0]);
    free(argv[0]);
    free(argv);
    return -saved;
  }
  int setup[2] = {0, 0};
  ssize_t setup_bytes = -1;
  int status = 0;
  int failure = 0;
  int timed_out = 0;
  while (1) {
    if (setup_bytes < 0) {
      ssize_t read_bytes = read(setup_pipe[0], setup, sizeof(setup));
      if (read_bytes >= 0) {
        setup_bytes = read_bytes;
      } else if (errno != EAGAIN && errno != EINTR) {
        failure = errno;
        break;
      }
    }
    pid_t waited = waitpid(child, &status, WNOHANG);
    if (waited == child) {
      if (setup_bytes < 0) {
        setup_bytes = read(setup_pipe[0], setup, sizeof(setup));
      }
      break;
    }
    if (waited < 0 && errno != EINTR) {
      failure = errno;
      break;
    }
    int64_t now = monotonic_millis();
    if (now < 0) {
      failure = errno;
      break;
    }
    if (now - started >= timeout_ms) {
      timed_out = 1;
      break;
    }
    struct timespec pause = {.tv_sec = 0, .tv_nsec = 10000000};
    nanosleep(&pause, NULL);
  }
  if (timed_out || failure) {
    kill(-child, SIGKILL);
    kill(child, SIGKILL);
    while (waitpid(child, NULL, 0) < 0 && errno == EINTR) {
    }
  }
  close(setup_pipe[0]);
  free(argv[0]);
  free(argv);
  if (failure) {
    return -failure;
  }
  if (timed_out) {
    return 3000000LL;
  }
  if (setup_bytes == (ssize_t)sizeof(setup)) {
    return 2000000LL + (int64_t)setup[0] * 1000LL + setup[1];
  }
  if (WIFEXITED(status)) {
    return (int64_t)WEXITSTATUS(status);
  }
  if (WIFSIGNALED(status)) {
    return 1000000LL + (int64_t)WTERMSIG(status);
  }
  return -ECHILD;
}

#else

MOONBIT_FFI_EXPORT int32_t moonjail_platform(void) { return 0; }
MOONBIT_FFI_EXPORT int32_t moonjail_architecture(void) { return 0; }
MOONBIT_FFI_EXPORT int32_t moonjail_landlock_abi(void) { return 0; }
MOONBIT_FFI_EXPORT int64_t moonjail_run(
    uint32_t *words, moonbit_bytes_t argv_blob, moonbit_bytes_t paths_blob,
    int32_t require_landlock, int32_t cpu_seconds,
    int64_t address_space_bytes, int64_t file_size_bytes, int32_t open_files,
    int32_t processes, int32_t timeout_ms) {
  (void)words;
  (void)argv_blob;
  (void)paths_blob;
  (void)require_landlock;
  (void)cpu_seconds;
  (void)address_space_bytes;
  (void)file_size_bytes;
  (void)open_files;
  (void)processes;
  (void)timeout_ms;
  return -1;
}

#endif
