#include <spawn.h>
#include <libjailbreak/libjailbreak.h>
#include <libjailbreak/jbserver.h>
#include <libjailbreak/jbserver_boomerang.h>
#include <libjailbreak/physrw.h>
#include <libjailbreak/physrw_pte.h>
#include <libjailbreak/primitives_IOSurface.h>
#include <libjailbreak/kcall_Fugu14.h>
#include <libjailbreak/kcall_arm64.h>
#include <libjailbreak/stock_fixes.h>
#include <libjailbreak/roothider/bootlog.h>
#include <unistd.h>
#include <signal.h>

int posix_spawnattr_set_registered_ports_np(posix_spawnattr_t *__restrict attr, mach_port_t portarray[], uint32_t count);

#define JB_DOMAIN_PRIMITIVE_STORAGE 10

#define JB_PRIMITIVE_STORAGE_RETRIEVE_PHYSRW 1
#define JB_PRIMITIVE_STORAGE_RETRIEVE_KCALL 2

int boomerang_stashPrimitives()
{
	roothide_bootlog("launchd: stashing primitives begin");
	dispatch_semaphore_t boomerangDone = dispatch_semaphore_create(0);
	if (!boomerangDone) return ENOMEM;

	mach_port_t serverPort = MACH_PORT_NULL;
	kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &serverPort);
	if (kr != KERN_SUCCESS) return EIO;
	kr = mach_port_insert_right(mach_task_self(), serverPort, serverPort, MACH_MSG_TYPE_MAKE_SEND);
	if (kr != KERN_SUCCESS) {
		mach_port_deallocate(mach_task_self(), serverPort);
		return EIO;
	}

	// Small server provided to boomerang to obtain exploit primitives
	dispatch_source_t serverSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_MACH_RECV, (uintptr_t)serverPort, 0, dispatch_get_main_queue());
	if (!serverSource) {
		mach_port_deallocate(mach_task_self(), serverPort);
		return ENOMEM;
	}
	dispatch_source_set_event_handler(serverSource, ^{
		xpc_object_t xdict = NULL;
		if (!xpc_pipe_receive(serverPort, &xdict)) {
			if (jbserver_received_boomerang_xpc_message(&gBoomerangServer, xdict) == JBS_BOOMERANG_DONE) {
				dispatch_semaphore_signal(boomerangDone);
			}
			xpc_release(xdict);
		}
	});
	dispatch_resume(serverSource);

	// Spawn boomerang process
	pid_t boomerangPid = 0;
	posix_spawnattr_t attr = NULL;
	int ret = posix_spawnattr_init(&attr);
	if (ret != 0) {
		dispatch_source_cancel(serverSource);
		mach_port_deallocate(mach_task_self(), serverPort);
		return ret;
	}
	ret = posix_spawnattr_set_registered_ports_np(&attr, (mach_port_t[]){ MACH_PORT_NULL, MACH_PORT_NULL, serverPort }, 3);
	if (ret != 0) {
		posix_spawnattr_destroy(&attr);
		dispatch_source_cancel(serverSource);
		mach_port_deallocate(mach_task_self(), serverPort);
		return ret;
	}
	ret = posix_spawn(&boomerangPid, JBROOT_PATH("/basebin/boomerang"), NULL, &attr, NULL, NULL);
	posix_spawnattr_destroy(&attr);
	roothide_bootlog(ret == 0 ? "launchd: boomerang spawned" : "launchd: boomerang spawn failed");
	if (ret != 0) {
		dispatch_source_cancel(serverSource);
		mach_port_deallocate(mach_task_self(), serverPort);
		return ret;
	}

	// Wait for boomerang to retrieve the primitives from launchd (handled in server above)
	long waitResult = dispatch_semaphore_wait(boomerangDone, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC));
	if (waitResult != 0) {
		roothide_bootlog("launchd: boomerang primitive handoff timed out");
		if (waitpid(boomerangPid, NULL, WNOHANG) == 0) {
			kill(boomerangPid, SIGKILL);
			waitpid(boomerangPid, NULL, 0);
		}
		dispatch_source_cancel(serverSource);
		mach_port_deallocate(mach_task_self(), serverPort);
		return ETIMEDOUT;
	}
	roothide_bootlog("launchd: boomerang received primitives");
	dispatch_source_cancel(serverSource);
	mach_port_deallocate(mach_task_self(), serverPort);

	// Stash boomerang pid in environment to later be able to call waitpid on it
	char pidBuf[10];
	snprintf(pidBuf, 10, "%d", boomerangPid);
	if (setenv("BOOMERANG_PID", pidBuf, 1) != 0) return errno ?: EIO;
	return 0;
}

int boomerang_recoverPrimitives(bool firstRetrieval, bool shouldEndBoomerang)
{
	roothide_bootlog(firstRetrieval ? "launchd: first primitive recovery begin" : "launchd: reboot primitive recovery begin");
	// Mach port to boomerang should be stored in our registeredPorts[2]
	// Use it to recover primitives, afterwards replace it with MACH_PORT_NULL to make launchd happy
	mach_port_t *registeredPorts;
	mach_msg_type_number_t registeredPortsCount = 0;
	if (mach_ports_lookup(mach_task_self(), &registeredPorts, &registeredPortsCount) != 0 || registeredPortsCount < 3) return -1;
	mach_port_t boomerangPort = registeredPorts[2];
	if (boomerangPort == MACH_PORT_NULL) return -2;
	jbclient_xpc_set_custom_port(boomerangPort);
	registeredPorts[2] = MACH_PORT_NULL;
	mach_ports_register(mach_task_self(), registeredPorts, registeredPortsCount);

	// Recover boomerang pid from environment
	pid_t boomerangPid = 0;
	const char *pidBuf = getenv("BOOMERANG_PID");
	if (pidBuf) {
		boomerangPid = atoi(pidBuf);
		unsetenv("BOOMERANG_PID");
	}

	// Retrieve primitives
	// For performance reasons we only use physrw_pte until the first userspace reboot
	// Handing off full physrw from the app is really slow and causes watchdog timeouts
	// But from launchd it's generally fine, no clue why
	bool physrwPTE = firstRetrieval && !is_kcall_available();
		if (jbclient_initialize_primitives_internal(physrwPTE) != 0) {
			roothide_bootlog("launchd: primitive recovery failed");
			return -3;
		}
		roothide_bootlog("launchd: recovery RPC returned");

		if (shouldEndBoomerang) {
			// Send done message to boomerang
			if (jbclient_boomerang_done() != 0) {
				roothide_bootlog("launchd: failed to send boomerang completion");
				return -4;
			}
		roothide_bootlog("launchd: sent boomerang completion");

		// Remove boomerang zombie proc if needed
		if (boomerangPid != 0) {
			int boomerangStatus;
			waitpid(boomerangPid, &boomerangStatus, WEXITED);
			waitpid(boomerangPid, &boomerangStatus, 0);
		}
	}

	return 0;
}
