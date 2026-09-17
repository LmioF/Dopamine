#include "hookd.h"

#include "libjailbreak.h"
#include <spawn.h>
#include <xpc_private.h>
#include "inline_svc.h"
#include <limits.h>

#include "jbclient_mach.h"
int (*hookd_send_msg)(struct hookd_mach_msg *msg, struct hookd_mach_msg_reply *reply) = jbclient_mach_hookd_send_msg;

size_t hookd_sizeof_encoded_hook(struct hookd_hook *hook)
{
	if (!hook || !hook->data || !hook->dataSize ||
		hook->dataSize > HOOKD_MSG_MAX_SIZE - sizeof(struct hookd_encoded_hook)) return 0;
	return sizeof(struct hookd_encoded_hook) + hook->dataSize;
}

int hook_encode_hook(void *encodedHook, struct hookd_hook *hook)
{
	if (!encodedHook || !hookd_sizeof_encoded_hook(hook)) return -1;
	struct hookd_encoded_hook header = {
		.address = hook->address,
		.dataSize = hook->dataSize,
	};
	memcpy(encodedHook, &header, sizeof(header));
	memcpy((uint8_t *)encodedHook + sizeof(header), hook->data, hook->dataSize);
	return 0;
}

int hookd_encode_msg(struct hookd_mach_msg *msg, int clientPid, task_port_t taskPort, struct hookd_hook *hooks, int hooksCount, struct hookd_encoded_fixup *fixups, int fixupsCount)
{
	if (!msg || hooksCount < 0 || fixupsCount < 0 ||
		(hooksCount && !hooks) || (fixupsCount && !fixups)) return -1;
	size_t payloadCapacity = HOOKD_MSG_MAX_SIZE - sizeof(*msg);
	if ((size_t)hooksCount > payloadCapacity / sizeof(struct hookd_encoded_hook) ||
		(size_t)fixupsCount > payloadCapacity / sizeof(struct hookd_encoded_fixup)) return -1;
	size_t fixupsSize = sizeof(struct hookd_encoded_fixup) * (size_t)fixupsCount;
	size_t remaining = payloadCapacity - fixupsSize;

	size_t hooksSize = 0;
	for (int i = 0; i < hooksCount; i++) {
		size_t hookSize = hookd_sizeof_encoded_hook(&hooks[i]);
		if (!hookSize || hookSize > remaining) return -1;
		hooksSize += hookSize;
		remaining -= hookSize;
	}
	msg->hdr.msgh_size = (mach_msg_size_t)(sizeof(*msg) + hooksSize + fixupsSize);

	msg->clientPid = clientPid;
	msg->taskPortInClient = taskPort == mach_task_self() ? -1 : taskPort;

	msg->hooksStartOff  = 0;
	msg->fixupsStartOff = hooksSize;

	size_t off = 0;
	for (int i = 0; i < hooksCount; i++) {
		size_t hookSize = hookd_sizeof_encoded_hook(&hooks[i]);
		hook_encode_hook(&msg->data[off], &hooks[i]);
		off += hookSize;
	}

	if (fixupsSize) memcpy(&msg->data[msg->fixupsStartOff], fixups, fixupsSize);

	return 0;
}

static int hookd_decode_reply(struct hookd_mach_msg_reply *reply, int hooksCount, int *hookResultsOut, int fixupsCount, int *fixupResultsOut)
{
	if (!reply || hooksCount < 0 || fixupsCount < 0 ||
		(hooksCount && !hookResultsOut) || (fixupsCount && !fixupResultsOut)) return -1;
	size_t replySize = reply->hdr.msgh_size;
	if (replySize < sizeof(*reply) || replySize > HOOKD_MSG_MAX_SIZE) return -1;
	size_t resultCapacity = (replySize - sizeof(*reply)) / sizeof(int64_t);
	if ((size_t)hooksCount > resultCapacity ||
		(size_t)fixupsCount > resultCapacity - (size_t)hooksCount) return -1;
	if (reply->hookResultsCount != (uint64_t)hooksCount ||
		reply->fixupResultsCount != (uint64_t)fixupsCount) return -1;
	size_t resultCount = (size_t)hooksCount + (size_t)fixupsCount;
	if (replySize != sizeof(*reply) + resultCount * sizeof(int64_t)) return -1;
	for (size_t i = 0; i < resultCount; i++) {
		int64_t result;
		memcpy(&result, &reply->data[i * sizeof(result)], sizeof(result));
		if (result < INT_MIN || result > INT_MAX) return -1;
	}
	for (size_t i = 0; i < resultCount; i++) {
		int64_t result;
		memcpy(&result, &reply->data[i * sizeof(result)], sizeof(result));
		if (i < (size_t)hooksCount) hookResultsOut[i] = (int)result;
		else fixupResultsOut[i - (size_t)hooksCount] = (int)result;
	}

	return 0;
}

int hookd_send_requests(task_port_t taskPort, struct hookd_hook *hooks, int hooksCount, int *hookResultsOut, struct hookd_encoded_fixup *fixups, int fixupsCount, int *fixupResultsOut)
{
	if (!hookd_send_msg || hooksCount < 0 || fixupsCount < 0 ||
		(hooksCount && !hookResultsOut) || (fixupsCount && !fixupResultsOut)) return -1;

	int r = 0;

	_Alignas(struct hookd_mach_msg) uint8_t msgBuf[HOOKD_MSG_MAX_SIZE];
	memset(msgBuf, 0, HOOKD_MSG_MAX_SIZE);
	struct hookd_mach_msg *msg = (struct hookd_mach_msg *)msgBuf;
	r = hookd_encode_msg(msg, getpid_inline(), taskPort, hooks, hooksCount, fixups, fixupsCount);
	if (r != 0) return r;

	_Alignas(struct hookd_mach_msg_reply) uint8_t replyBuf[HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE];
	memset(replyBuf, 0, HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE);
	struct hookd_mach_msg_reply *reply = (struct hookd_mach_msg_reply *)replyBuf;
	reply->hdr.msgh_size = HOOKD_MSG_MAX_SIZE + MAX_TRAILER_SIZE;
	r = hookd_send_msg(msg, reply);
	if (r != 0) return r;

	if (hookd_decode_reply(reply, hooksCount, hookResultsOut, fixupsCount, fixupResultsOut) != 0) return -44;

	return 0;
}

kern_return_t hookd_vm_protect(mach_port_t taskPort, vm_address_t address, vm_size_t size, bool set_maximum, vm_prot_t new_protection)
{
	struct hookd_encoded_fixup fixup;
	fixup.address = address;
	fixup.size = size;
	fixup.set_maximum = set_maximum;
	fixup.prot = new_protection;

	int result = 0;
	int ret = hookd_send_requests(taskPort, NULL, 0, NULL, &fixup, 1, &result);
	if (ret != 0) return ret;
	return result;
}

kern_return_t hookd_hook(mach_port_t taskPort, uint64_t address, uint8_t *data, size_t dataSize)
{
	struct hookd_hook hook;
	hook.address = address;
	hook.data = data;
	hook.dataSize = dataSize;

	int result = 0;
	int ret = hookd_send_requests(taskPort, &hook, 1, &result, NULL, 0, NULL);
	if (ret != 0) return ret;
	return result;
}
