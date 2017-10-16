#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>

#define BUF_SIZE 512

int main()
{
	pid_t child = fork();

	if (child) {
		int readfd, writefd, readsz;
		char buf[BUF_SIZE];

		printf("> parent\n");
		/* 
		 * NOTE: parent should be a separate daemon reading the sysfs
		 * file. Or better, a daemon listening to netlink socket, as
		 * noted in kernel module code
		 */
		usleep(2000); 
		
		readfd = open("/sys/kernel/esct/trace", O_RDONLY);
		writefd = open("/tmp/syscall.trace", O_WRONLY | O_CREAT, 0644);

		while ((readsz = read(readfd, buf, BUF_SIZE)) > 0)
			write(writefd, buf, (ssize_t) readsz);

		close(readfd);
		close(writefd);
	} else {
		pid_t curr = getpid();
		int fd;
		char str[16];
		
		sprintf(str, "%d", curr);
		printf("> child pid = %d\n", curr);
		fd = open("/sys/kernel/esct/pid", O_WRONLY);
		write(fd, str, strlen(str));
		close(fd);
		execl("/usr/bin/ls", "/usr/bin/ls", "-lh", NULL);
	}

	return 0;
}

