#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <dlfcn.h>
#include <os/log.h>
#include <poll.h>
#include <errno.h>
#include <util.h>
#include "syscall.h"
#include "litehook.h"
#include <libjailbreak/jbclient_mach.h>

extern void __fork(void);

int childToParentPipe[2];
int parentToChildPipe[2];

static int close_pipe_end(int *fd)
{
	if (*fd < 0) return 0;
	int ret = ffsys_close(*fd);
	*fd = -1;
	return ret;
}

static int wait_for_pipe(int fd, short events)
{
	struct pollfd pollfd = {
		.fd = fd,
		.events = events,
	};

	for (;;) {
		pollfd.revents = 0;
		int ret = ffsys_poll(&pollfd, 1, 5000);
		if (ret == EINTR) continue;
		if (ret != 1 || !(pollfd.revents & events)) return -1;
		return 0;
	}
}

static int read_protocol_byte(int fd, char *value)
{
	for (;;) {
		if (wait_for_pipe(fd, POLLIN) != 0) return -1;
		ssize_t ret = ffsys_read(fd, value, sizeof(*value));
		if (ret == sizeof(*value)) return 0;
		if (ret == EINTR) continue;
		return -1;
	}
}

static int write_protocol_byte(int fd, char value)
{
	for (;;) {
		ssize_t ret = ffsys_write(fd, &value, sizeof(value));
		if (ret == sizeof(value)) return 0;
		if (ret == EINTR) continue;
		return -1;
	}
}

static void open_pipes(void)
{
	parentToChildPipe[0] = parentToChildPipe[1] = -1;
	childToParentPipe[0] = childToParentPipe[1] = -1;
	if (pipe(parentToChildPipe) < 0 || pipe(childToParentPipe) < 0) {
		close_pipe_end(&parentToChildPipe[0]);
		close_pipe_end(&parentToChildPipe[1]);
		abort();
	}
}
static void close_pipes(void)
{
	int ret = 0;
	ret |= close_pipe_end(&parentToChildPipe[0]);
	ret |= close_pipe_end(&parentToChildPipe[1]);
	ret |= close_pipe_end(&childToParentPipe[0]);
	ret |= close_pipe_end(&childToParentPipe[1]);
	if (ret != 0) {
		abort();
	}
}

void child_fixup(void)
{
	// Tell parent we are waiting for fixup now
	char msg = ' ';
	if (write_protocol_byte(childToParentPipe[1], msg) != 0) abort();

	// Wait until parent completes fixup
	if (read_protocol_byte(parentToChildPipe[0], &msg) != 0) abort();
}

void parent_fixup(pid_t childPid)
{
	// Wait until the child is ready and waiting
	char msg = ' ';
	if (read_protocol_byte(childToParentPipe[0], &msg) != 0) {
		kill(childPid, SIGKILL);
		abort();
	}

	// Child is waiting for wx_allowed + permission fixups now
	// Apply fixup
	int64_t fix_ret = jbclient_mach_fork_fix(childPid);
	if (fix_ret != 0) {
		kill(childPid, SIGKILL);
		abort();
	}

	// Tell child we are done, this will make it resume
	if (write_protocol_byte(parentToChildPipe[1], msg) != 0) {
		kill(childPid, SIGKILL);
		abort();
	}
}

__attribute__((visibility ("default"))) pid_t forkfix___fork(void)
{
	open_pipes();

	pid_t pid = ffsys_fork();
	if (pid < 0) {
		close_pipes();
		return pid;
	}

	if (pid == 0) {
		if (close_pipe_end(&parentToChildPipe[1]) != 0 || close_pipe_end(&childToParentPipe[0]) != 0) abort();
		child_fixup();
	}
	else {
		if (close_pipe_end(&parentToChildPipe[0]) != 0 || close_pipe_end(&childToParentPipe[1]) != 0) {
			kill(pid, SIGKILL);
			abort();
		}
		parent_fixup(pid);
	}

	close_pipes();
	return pid;
}

void apply_fork_hook(void)
{
	static dispatch_once_t onceToken;
	dispatch_once (&onceToken, ^{


/************************* roothide specific **********************/
// find systemhook using <install-name>
void *systemhookHandle = dlopen("systemhook.dylib", RTLD_NOLOAD);
assert(systemhookHandle != NULL);
kern_return_t (*litehook_hook_function)(void *source, void *target) = dlsym(systemhookHandle, "litehook_hook_function");
assert(litehook_hook_function != NULL);
/************************* roothide specific **********************/


		litehook_hook_function((void *)__fork, (void *)forkfix___fork);
	});
}

__attribute__((constructor)) static void initializer(void)
{
	apply_fork_hook();
}
