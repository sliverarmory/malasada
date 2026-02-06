#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static void die(const char *msg) {
  perror(msg);
  exit(1);
}

int main(int argc, char **argv) {
  if (argc != 2) {
    fprintf(stderr, "usage: runner <payload.bin>\n");
    return 2;
  }

  const char *path = argv[1];
  int fd = open(path, O_RDONLY);
  if (fd < 0) die("open");

  struct stat st;
  if (fstat(fd, &st) != 0) die("fstat");
  if (st.st_size <= 0) {
    fprintf(stderr, "empty payload\n");
    return 3;
  }

  void *file_map = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
  if (file_map == MAP_FAILED) die("mmap(file)");
  close(fd);

  // Copy into an anonymous mapping so we can mark it executable.
  void *buf = mmap(NULL, (size_t)st.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  if (buf == MAP_FAILED) die("mmap(anon)");
  memcpy(buf, file_map, (size_t)st.st_size);
  munmap(file_map, (size_t)st.st_size);

  if (mprotect(buf, (size_t)st.st_size, PROT_READ | PROT_EXEC) != 0) die("mprotect");

  // Execute stage0 shellcode. It does not return (exec-like).
  void (*entry)(void) = (void (*)(void))buf;
  entry();

  // Unreachable in success case.
  fprintf(stderr, "payload returned unexpectedly\n");
  return 4;
}

