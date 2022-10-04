#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
	char buf[16] = {0};

	// read 0 bytes so it won't block
	read(STDOUT_FILENO, buf, 0);

	int fd = open(argv[0], 0);

	read(fd, buf, sizeof(buf));

	close(fd);
}
