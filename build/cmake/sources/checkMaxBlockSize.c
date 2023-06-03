#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
	int result = sysconf(_SC_PAGESIZE);
	if (result < 0)
		return 1;
	printf("%d", result);
	return 0;
}
