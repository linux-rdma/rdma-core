// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/*
 * Copyright 2026 Hewlett Packard Enterprise Development LP
 *
 * List-entry encoding for RU QPs. No hardware needed: entries are checked
 * field by field and against a model of how a matching PTE selects them.
 */
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ccan/array_size.h>

#include "../cxi.h"
#include "../cxi_le.h"
#include "../cxidv.h"
#include "../cxidv_telem.h"

static int test_destroy_qp_command(struct ibv_qp *qp);
#define ibv_cmd_destroy_qp test_destroy_qp_command
#include "../verbs.c"
#undef ibv_cmd_destroy_qp

bool is_cxi_dev(struct ibv_device *device)
{
	const struct verbs_device *provider = verbs_get_device(device);

	return provider->ops->name && !strcmp(provider->ops->name, "cxiverbs");
}

static bool fail_destroy_qp_command;

static int test_destroy_qp_command(struct ibv_qp *qp)
{
	return fail_destroy_qp_command ? EBUSY : ibv_cmd_destroy_qp(qp);
}

static int failed_tests;

#define EXPECT_EQ(expected, actual)                                                                \
	({                                                                                         \
		unsigned long long _e = (unsigned long long)(expected);                            \
		unsigned long long _a = (unsigned long long)(actual);                              \
		if (_e != _a) {                                                                    \
			printf("  FAIL at line %d: %s != %s (0x%llx != 0x%llx)\n", __LINE__,       \
			       #expected, #actual, _e, _a);                                        \
			failed_tests++;                                                            \
		}                                                                                  \
	})

#define EXPECT_TRUE(actual) EXPECT_EQ(1, !!(actual))
#define EXPECT_FALSE(actual) EXPECT_EQ(0, !!(actual))

static void correctness_result(const char *name, int before)
{
	printf("%s correctness: %s\n", failed_tests == before ? "PASS" : "FAIL", name);
}

struct address_test {
	struct cxi_context context;
	struct cxi_qp qp;
	struct cxi_ibv_cq cq;
	struct ibv_job job;
	pthread_mutex_t lock;
	struct ibv_ah_attr_ex address;
	unsigned int capacity;
	unsigned int queries;
	unsigned int failures;
	unsigned int submitted;
	bool present;
	bool check_lock;
};

static struct ibv_job *mock_alloc_job(struct ibv_context *context, struct ibv_job_attr *attr,
				      void *user_context)
{
	struct address_test *test =
		container_of(context, struct address_test, context.verbs_ctx.context);

	(void)user_context;
	test->capacity =
		attr->comp_mask & IBV_JOB_ATTR_MAX_ADDR_ENTRIES ? attr->max_addr_entries : 0;
	return &test->job;
}

static int mock_query_addr(struct ibv_job *job, unsigned int index, struct ibv_ah_attr_ex *address)
{
	struct address_test *test = container_of(job, struct address_test, job);
	int ret = 0;

	if (test->check_lock) {
		ret = pthread_spin_trylock(&test->qp.sq_lock);
		if (ret)
			return EDEADLK;
		pthread_spin_unlock(&test->qp.sq_lock);
	}
	pthread_mutex_lock(&test->lock);
	test->queries++;
	if (index >= test->capacity)
		ret = EINVAL;
	else if (!test->present)
		ret = ENOENT;
	else
		*address = test->address;
	pthread_mutex_unlock(&test->lock);
	return ret;
}

static int mock_insert_addr(struct ibv_job *job, struct ibv_ah_attr_ex *address, unsigned int index)
{
	struct address_test *test = container_of(job, struct address_test, job);
	int ret = 0;

	pthread_mutex_lock(&test->lock);
	if (index >= test->capacity) {
		ret = EINVAL;
	} else if (test->present) {
		ret = EBUSY;
	} else {
		test->address = *address;
		test->present = true;
	}
	pthread_mutex_unlock(&test->lock);
	return ret;
}

static int mock_remove_addr(struct ibv_job *job, unsigned int index)
{
	struct address_test *test = container_of(job, struct address_test, job);
	int ret = 0;

	pthread_mutex_lock(&test->lock);
	if (index >= test->capacity)
		ret = EINVAL;
	else if (!test->present)
		ret = ENOENT;
	else
		test->present = false;
	pthread_mutex_unlock(&test->lock);
	return ret;
}

static void *mock_update_addresses(void *opaque)
{
	struct address_test *test = opaque;

	for (unsigned int index = 0; index < 1000; index++) {
		pthread_mutex_lock(&test->lock);
		test->present = index & 1;
		test->address.remote_qpn = index;
		pthread_mutex_unlock(&test->lock);
	}
	return NULL;
}

static void *mock_submit_indexed(void *opaque)
{
	struct address_test *test = opaque;
	unsigned int failures = 0;
	unsigned int submitted = 0;

	for (unsigned int index = 0; index < 1000; index++) {
		struct ibv_send_wr request = {
			.opcode = IBV_WR_SEND,
		};
		struct ibv_sge sge = { .addr = 0x1000, .length = 64, .lkey = 1 };
		struct ibv_send_wr *bad = NULL;
		int ret;

		request.sg_list = &sge;
		request.num_sge = 1;
		if (index & 1) {
			struct ibv_qp_ex *extended = &test->qp.vqp.qp_ex;

			cxi_wr_start(extended);
			cxi_wr_send(extended);
			cxi_wr_set_ru_addr(extended, NULL, 0);
			cxi_wr_set_sge32(extended, 1, 0x1000, 64);
			ret = cxi_wr_complete(extended);
		} else {
			ret = cxi_post_send(&test->qp.vqp.qp, &request, &bad);
		}
		if (!ret)
			submitted++;
		else if ((ret != ENOENT && ret != ENOSPC) || (!(index & 1) && bad != &request))
			failures++;
	}
	pthread_mutex_lock(&test->lock);
	test->failures += failures;
	test->submitted += submitted;
	pthread_mutex_unlock(&test->lock);
	return NULL;
}

static void cxi_test_clear_cookie(void *buffer, size_t bytes_size, uint64_t cookie)
{
	uint8_t *bytes = buffer;

	for (size_t offset = 0; offset + sizeof(cookie) <= bytes_size; offset += sizeof(cookie)) {
		uint64_t value;

		memcpy(&value, bytes + offset, sizeof(value));
		if (value == cookie) {
			memset(bytes + offset, 0, sizeof(cookie));
			return;
		}
	}

	EXPECT_TRUE(false);
}

static void test_address_command_equivalence(struct address_test *test)
{
	struct cxi_cmd64 commands[32] = {}, explicit_commands[32];
	uint64_t doorbell = 0, wrids[8], cookies[8];
	uint32_t job_ids[8];
	uint8_t opcodes[8];
	bool slot_valid[8] = {};
	struct cxi_mr mr = {
		.va = 0x1000,
		.iova = 0x1000,
		.len = 64,
	};
	struct ibv_sge sge = { .addr = 0x1000, .length = 64, .lkey = 1 };
	struct ibv_qp_ex *extended = &test->qp.vqp.qp_ex;
	const enum ibv_wr_opcode operations[] = {
		IBV_WR_SEND,
		IBV_WR_RDMA_WRITE,
		IBV_WR_RDMA_READ,
	};
	struct cxi_ah address = { .ah_ex.remote_qpn = 1 };

	mr.vmr.ibv_mr.lkey = 1;
	test->context.mr_list = &mr;
	pthread_spin_init(&test->context.mr_list_lock, PTHREAD_PROCESS_PRIVATE);
	test->qp.sq_size = ARRAY_SIZE(wrids);
	test->qp.send_wrids = wrids;
	test->qp.send_opcodes = opcodes;
	test->qp.send_job_ids = job_ids;
	test->qp.send_cookies = cookies;
	test->qp.send_slot_valid = slot_valid;
	test->context.pid_bits = C_DFA_PID_BITS_MAX;
	test->address.remote_qpn = 1;

	for (size_t operation = 0; operation < ARRAY_SIZE(operations); operation++) {
		for (unsigned int api = 0; api < 2; api++) {
			for (unsigned int indexed = 0; indexed < 2; indexed++) {
				struct ibv_send_wr request = {
					.opcode = operations[operation],
					.sg_list = &sge,
					.num_sge = 1,
				};
				struct ibv_send_wr *bad = NULL;

				memset(commands, 0, sizeof(commands));
				cxi_cq_init(&test->qp.hw_txq, commands, ARRAY_SIZE(commands),
					    &doorbell, 0);
				test->qp.send_count = 0;
				test->qp.send_tail = 0;
				memset(cookies, 0, sizeof(cookies));
				memset(slot_valid, 0, sizeof(slot_valid));
				if (!api) {
					if (operations[operation] == IBV_WR_SEND) {
						request.wr.ru.ah = indexed ? NULL : &address.ah_ex;
						request.wr.ru.addr_idx = 1;
					} else {
						request.wr.ru_rdma.ah =
							indexed ? NULL : &address.ah_ex;
						request.wr.ru_rdma.addr_idx = 1;
						request.wr.ru_rdma.rkey64 = 1;
						request.wr.ru_rdma.remote_addr = 0x2000;
					}
					EXPECT_EQ(0,
						  cxi_post_send(&test->qp.vqp.qp, &request, &bad));
				} else {
					cxi_wr_start(extended);
					if (operations[operation] == IBV_WR_SEND)
						cxi_wr_send(extended);
					else if (operations[operation] == IBV_WR_RDMA_WRITE)
						cxi_wr_rdma_write64(extended, 1, 0x2000);
					else
						cxi_wr_rdma_read64(extended, 1, 0x2000);
					cxi_wr_set_ru_addr(extended,
							   indexed ? NULL : &address.ah_ex, 1);
					cxi_wr_set_sge32(extended, 1, 0x1000, 64);
					EXPECT_EQ(0, cxi_wr_complete(extended));
				}
				EXPECT_EQ(1, test->qp.send_count);
				{
					uint64_t cookie = test->qp.send_cookies[0];

					cxi_test_clear_cookie(commands, sizeof(commands), cookie);
				}
				if (!indexed)
					memcpy(explicit_commands, commands, sizeof(commands));
				else
					EXPECT_EQ(0, memcmp(explicit_commands, commands,
							    sizeof(commands)));
			}
		}
	}
	test->qp.sq_size = 0;
	test->qp.send_count = 0;
	test->qp.send_tail = 0;
	test->context.mr_list = NULL;
	pthread_spin_destroy(&test->context.mr_list_lock);
}

static void test_indexed_submission_locking(void)
{
	struct address_test test = {};
	struct cxi_cmd64 *commands = calloc(4096, sizeof(*commands));
	uint64_t doorbell = 0;
	struct cxi_mr mr = { .va = 0x1000, .iova = 0x1000, .len = 64 };
	uint64_t *wrids = calloc(2048, sizeof(*wrids));
	uint64_t *cookies = calloc(2048, sizeof(*cookies));
	uint32_t *job_ids = calloc(2048, sizeof(*job_ids));
	uint8_t *opcodes = calloc(2048, sizeof(*opcodes));
	bool *slot_valid = calloc(2048, sizeof(*slot_valid));
	struct ibv_context *context = &test.context.verbs_ctx.context;
	struct ibv_job_attr attr = {};
	struct ibv_ah_attr_ex table_address = { .remote_qpn = 1 };
	struct ibv_ah_attr_ex queried_address = {};
	struct ibv_send_wr request = { .opcode = IBV_WR_SEND };
	struct ibv_send_wr *bad = NULL;
	struct ibv_qp_ex *extended = &test.qp.vqp.qp_ex;
	struct cxi_ah explicit = {};
	pthread_t updater, submitters[2];
	unsigned int queries;
	int before = failed_tests;
	int ret;

	EXPECT_TRUE(commands && wrids && cookies && job_ids && opcodes && slot_valid);
	if (!commands || !wrids || !cookies || !job_ids || !opcodes || !slot_valid) {
		free(commands);
		free(wrids);
		free(cookies);
		free(job_ids);
		free(opcodes);
		free(slot_valid);
		return;
	}
	test.context.verbs_ctx.sz = sizeof(test.context.verbs_ctx);
	context->abi_compat = __VERBS_ABI_IS_EXTENDED;
	test.context.verbs_ctx.alloc_job = mock_alloc_job;
	test.context.verbs_ctx.insert_addr = mock_insert_addr;
	test.context.verbs_ctx.remove_addr = mock_remove_addr;
	test.context.verbs_ctx.query_addr = mock_query_addr;
	test.qp.vqp.qp.context = context;
	test.qp.vqp.qp.send_cq = &test.cq.verbs_cq.cq;
	test.qp.job = &test.job;
	test.qp.qp_slot = 0;
	test.qp.send_cookies = cookies;
	test.qp.send_slot_valid = slot_valid;
	test.job.context = context;
	atomic_init(&test.context.send_cookie_seq, 0);
	test.check_lock = true;
	pthread_mutex_init(&test.lock, NULL);
	pthread_mutex_init(&test.qp.builder_lock, NULL);
	pthread_spin_init(&test.qp.sq_lock, PTHREAD_PROCESS_PRIVATE);

	EXPECT_TRUE(ibv_alloc_job(context, &attr, NULL) == &test.job);
	EXPECT_EQ(0, test.capacity);
	EXPECT_EQ(EINVAL, ibv_insert_addr(&test.job, &table_address, 0));
	EXPECT_EQ(EINVAL, ibv_query_addr(&test.job, 0, &queried_address));
	EXPECT_EQ(EINVAL, ibv_remove_addr(&test.job, 0));
	attr.comp_mask = IBV_JOB_ATTR_MAX_ADDR_ENTRIES;
	EXPECT_TRUE(ibv_alloc_job(context, &attr, NULL) == &test.job);
	EXPECT_EQ(0, test.capacity);
	attr.max_addr_entries = 2;
	EXPECT_TRUE(ibv_alloc_job(context, &attr, NULL) == &test.job);
	EXPECT_EQ(2, test.capacity);
	EXPECT_EQ(ENOENT, ibv_query_addr(&test.job, 0, &queried_address));
	EXPECT_EQ(ENOENT, ibv_remove_addr(&test.job, 0));
	EXPECT_EQ(0, ibv_insert_addr(&test.job, &table_address, 0));
	EXPECT_EQ(EBUSY, ibv_insert_addr(&test.job, &table_address, 0));
	EXPECT_EQ(0, ibv_query_addr(&test.job, 0, &queried_address));
	EXPECT_EQ(table_address.remote_qpn, queried_address.remote_qpn);
	EXPECT_EQ(EINVAL, ibv_insert_addr(&test.job, &table_address, 2));
	EXPECT_EQ(EINVAL, ibv_query_addr(&test.job, UINT_MAX, &queried_address));
	EXPECT_EQ(EINVAL, ibv_remove_addr(&test.job, 2));
	EXPECT_EQ(0, ibv_remove_addr(&test.job, 0));
	EXPECT_EQ(ENOENT, ibv_query_addr(&test.job, 0, &queried_address));

	EXPECT_EQ(ENOENT, cxi_post_send(&test.qp.vqp.qp, &request, &bad));
	EXPECT_TRUE(bad == &request);
	test.present = true;
	EXPECT_EQ(ENOSPC, cxi_post_send(&test.qp.vqp.qp, &request, &bad));
	request.wr.ru.addr_idx = 2;
	EXPECT_EQ(EINVAL, cxi_post_send(&test.qp.vqp.qp, &request, &bad));
	request.wr.ru.addr_idx = 1;
	request.opcode = IBV_WR_RDMA_WRITE;
	EXPECT_EQ(ENOSPC, cxi_post_send(&test.qp.vqp.qp, &request, &bad));
	request.opcode = IBV_WR_RDMA_READ;
	EXPECT_EQ(ENOSPC, cxi_post_send(&test.qp.vqp.qp, &request, &bad));
	queries = test.queries;
	request.opcode = IBV_WR_SEND;
	request.wr.ru.ah = &explicit.ah_ex;
	EXPECT_EQ(ENOSPC, cxi_post_send(&test.qp.vqp.qp, &request, &bad));
	EXPECT_EQ(queries, test.queries);

	cxi_wr_start(extended);
	cxi_wr_send(extended);
	cxi_wr_set_ru_addr(extended, NULL, 1);
	EXPECT_EQ(0, test.qp.wr_build.err);
	EXPECT_EQ(0, pthread_spin_trylock(&test.qp.sq_lock));
	pthread_spin_unlock(&test.qp.sq_lock);
	cxi_wr_send(extended);
	EXPECT_EQ(1, test.qp.pending_count);
	cxi_wr_abort(extended);
	EXPECT_EQ(0, test.qp.pending_count);
	EXPECT_EQ(0, test.qp.send_count);
	cxi_wr_start(extended);
	cxi_wr_rdma_read64(extended, 1, 0);
	cxi_wr_set_ru_addr(extended, NULL, 1);
	EXPECT_EQ(0, test.qp.wr_build.err);
	EXPECT_EQ(ENOSPC, cxi_wr_complete(extended));
	EXPECT_EQ(0, test.qp.send_count);
	cxi_wr_start(extended);
	cxi_wr_send(extended);
	cxi_wr_set_ru_addr(extended, NULL, 2);
	EXPECT_EQ(EINVAL, cxi_wr_complete(extended));

	test_address_command_equivalence(&test);
	memset(slot_valid, 0, 2048 * sizeof(*slot_valid));
	mr.vmr.ibv_mr.lkey = 1;
	test.context.mr_list = &mr;
	pthread_spin_init(&test.context.mr_list_lock, PTHREAD_PROCESS_PRIVATE);
	test.qp.sq_size = 2048;
	test.qp.send_wrids = wrids;
	test.qp.send_job_ids = job_ids;
	test.qp.send_opcodes = opcodes;
	test.qp.send_cookies = cookies;
	test.qp.send_slot_valid = slot_valid;
	cxi_cq_init(&test.qp.hw_txq, commands, 4096, &doorbell, 0);
	test.check_lock = false;
	ret = pthread_create(&updater, NULL, mock_update_addresses, &test);
	EXPECT_EQ(0, ret);
	if (!ret) {
		for (size_t index = 0; index < ARRAY_SIZE(submitters); index++) {
			ret = pthread_create(&submitters[index], NULL, mock_submit_indexed, &test);
			EXPECT_EQ(0, ret);
			if (ret) {
				for (size_t previous = 0; previous < index; previous++)
					pthread_join(submitters[previous], NULL);
				break;
			}
			if (index + 1 == ARRAY_SIZE(submitters))
				for (size_t thread = 0; thread < ARRAY_SIZE(submitters); thread++)
					pthread_join(submitters[thread], NULL);
		}
		pthread_join(updater, NULL);
	}
	EXPECT_EQ(0, test.failures);
	EXPECT_EQ(test.submitted, test.qp.send_count);
	pthread_spin_destroy(&test.context.mr_list_lock);
	free(test.qp.pending_wrs);
	free(commands);
	free(wrids);
	free(cookies);
	free(job_ids);
	free(opcodes);
	free(slot_valid);
	pthread_spin_destroy(&test.qp.sq_lock);
	pthread_mutex_destroy(&test.qp.builder_lock);
	pthread_mutex_destroy(&test.lock);
	correctness_result("indexed-submission-locking", before);
}

static void set_test_initiator_event(struct cxi_eq *eq, unsigned int index,
				     uint8_t event_type, uint64_t user_ptr)
{
	struct c_event_initiator_short *event =
		(void *)(eq->events + C_EE_CFG_ECB_SIZE + index * sizeof(*event));

	*event = (struct c_event_initiator_short){
		.user_ptr = user_ptr,
		.mlength = 64,
		.event_size = C_EVENT_SIZE_16_BYTE,
		.event_type = event_type,
		.return_code = C_RC_OK,
	};
}

static void test_out_of_order_send_completions(void)
{
	struct cxi_context context = {};
	struct cxi_qp qp = {};
	struct cxi_qp *cookie_qp;
	struct cxi_ibv_cq cq = {};
	struct cxi_eq eq = {
		.byte_size = 256,
		.rd_offset = C_EE_CFG_ECB_SIZE,
		.prev_rd_offset = C_EE_CFG_ECB_SIZE,
	};
	union {
		uint64_t alignment;
		uint8_t bytes[256];
	} event_buffer = {};
	uint64_t wrids[] = { 100, 101, 102 };
	uint64_t cookies[ARRAY_SIZE(wrids)] = {};
	uint32_t job_ids[] = { 10, 11, 12 };
	uint8_t opcodes[] = { IBV_WR_SEND, IBV_WR_RDMA_WRITE, IBV_WR_RDMA_READ };
	bool slot_valid[] = { true, true, true };
	struct ibv_wc wc = {};
	uint64_t eq_state = 0;
	uint64_t stale_cookie = 0;
	uint64_t replacement_cookie = 0;
	uint32_t free_slot = 2;
	uint32_t cookie_slot = UINT32_MAX;
	int before = failed_tests;
	int ret;

	eq.events = event_buffer.bytes;
	eq.sw_state_addr = &eq_state;
	cq.hw_eq = eq;
	context.qp_slots[0] = &qp;
	context.qp_by_pte[0] = &qp;
	context.qp_count = 1;
	qp.qp_slot = 0;
	qp.pte_index = 1;
	qp.vqp.qp.context = &context.verbs_ctx.context;
	qp.vqp.qp.qp_num = 0x1234;
	qp.send_cq = &cq;
	qp.send_wrids = wrids;
	qp.send_opcodes = opcodes;
	qp.send_job_ids = job_ids;
	qp.send_cookies = cookies;
	qp.send_slot_valid = slot_valid;
	qp.sq_size = ARRAY_SIZE(wrids);
	qp.send_count = ARRAY_SIZE(wrids);
	qp.job_id = 10;
	cq.verbs_cq.cq.context = &context.verbs_ctx.context;

	EXPECT_EQ(0, pthread_spin_init(&context.qp_table_lock, PTHREAD_PROCESS_PRIVATE));
	EXPECT_EQ(0, pthread_spin_init(&qp.sq_lock, PTHREAD_PROCESS_PRIVATE));
	EXPECT_EQ(0, pthread_spin_init(&cq.lock, PTHREAD_PROCESS_PRIVATE));
	atomic_init(&context.send_cookie_seq, 0);
	for (uint32_t slot = 0; slot < ARRAY_SIZE(wrids); slot++)
		EXPECT_EQ(0, cxi_sq_make_cookie(&qp, slot, &cookies[slot]));
	stale_cookie = cookies[2];
	cookie_qp = cxi_sq_cookie_qp(&context, cookies[2], &cookie_slot);
	EXPECT_EQ((uintptr_t)&qp, (uintptr_t)cookie_qp);
	EXPECT_EQ(2, cookie_slot);
	set_test_initiator_event(&cq.hw_eq, 0, C_EVENT_ACK, 0);
	set_test_initiator_event(&cq.hw_eq, 1, C_EVENT_ACK, cookies[2]);
	set_test_initiator_event(&cq.hw_eq, 2, C_EVENT_SEND, cookies[0]);
	set_test_initiator_event(&cq.hw_eq, 3, C_EVENT_REPLY, cookies[1]);

	ret = cxi_poll_cq(&cq.verbs_cq.cq, 1, &wc);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(102, wc.wr_id);
	EXPECT_EQ(IBV_WC_RDMA_READ, wc.opcode);
	EXPECT_EQ(IBV_WC_SUCCESS, wc.status);
	EXPECT_EQ(0x1234, wc.qp_num);
	EXPECT_EQ(12, cq.cur_job_id);
	EXPECT_EQ(2, qp.send_count);
	EXPECT_FALSE(slot_valid[2]);
	EXPECT_TRUE(cxi_sq_find_free_slot(&qp, &free_slot));
	EXPECT_EQ(2, free_slot);

	ret = cxi_poll_cq(&cq.verbs_cq.cq, 1, &wc);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(100, wc.wr_id);
	EXPECT_EQ(IBV_WC_SEND, wc.opcode);
	EXPECT_EQ(10, cq.cur_job_id);
	EXPECT_EQ(1, qp.send_count);

	ret = cxi_poll_cq(&cq.verbs_cq.cq, 1, &wc);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(101, wc.wr_id);
	EXPECT_EQ(IBV_WC_RDMA_WRITE, wc.opcode);
	EXPECT_EQ(11, cq.cur_job_id);
	EXPECT_EQ(0, qp.send_count);
	EXPECT_FALSE(slot_valid[0]);
	EXPECT_FALSE(slot_valid[1]);

	/* Reuse the out-of-order hole and verify its new completion metadata. */
	EXPECT_EQ(0, cxi_sq_make_cookie(&qp, free_slot, &replacement_cookie));
	cxi_sq_record_send(&qp, free_slot, replacement_cookie, 202, IBV_WR_SEND, 22);
	set_test_initiator_event(&cq.hw_eq, 4, C_EVENT_ACK, stale_cookie);
	ret = cxi_poll_cq(&cq.verbs_cq.cq, 1, &wc);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, qp.send_count);
	EXPECT_TRUE(slot_valid[2]);

	set_test_initiator_event(&cq.hw_eq, 5, C_EVENT_ACK, replacement_cookie);
	ret = cxi_poll_cq(&cq.verbs_cq.cq, 1, &wc);
	EXPECT_EQ(1, ret);
	EXPECT_EQ(202, wc.wr_id);
	EXPECT_EQ(22, cq.cur_job_id);
	EXPECT_EQ(0, qp.send_count);

	/* A completion for a free slot is consumed, never returned as a WR ID. */
	set_test_initiator_event(&cq.hw_eq, 6, C_EVENT_ACK, replacement_cookie);
	ret = cxi_poll_cq(&cq.verbs_cq.cq, 1, &wc);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(0, qp.send_count);

	pthread_spin_destroy(&qp.sq_lock);
	pthread_spin_destroy(&context.qp_table_lock);
	pthread_spin_destroy(&cq.lock);
	correctness_result("out-of-order-send-completions", before);
}

static void test_qp_lookup_indexes(void)
{
	struct cxi_context context = {};
	struct cxi_qp qps[4] = {};
	const int initial_ptes[] = { 20, 4, 11 };
	int before = failed_tests;
	int ret;

	ret = pthread_spin_init(&context.qp_table_lock, PTHREAD_PROCESS_PRIVATE);
	EXPECT_EQ(0, ret);
	if (ret)
		return;

	pthread_spin_lock(&context.qp_table_lock);
	for (size_t index = 0; index < ARRAY_SIZE(initial_ptes); index++) {
		qps[index].qp_slot = UINT32_MAX;
		qps[index].pte_index = initial_ptes[index];
		ret = cxi_qp_register_locked(&context, &qps[index]);
		EXPECT_EQ(0, ret);
		if (ret)
			goto out_unlock;
	}
	EXPECT_EQ(3, context.qp_count);
	EXPECT_EQ((uintptr_t)&qps[1], (uintptr_t)context.qp_by_pte[0]);
	EXPECT_EQ((uintptr_t)&qps[2], (uintptr_t)context.qp_by_pte[1]);
	EXPECT_EQ((uintptr_t)&qps[0], (uintptr_t)context.qp_by_pte[2]);
	EXPECT_EQ((uintptr_t)&qps[0], (uintptr_t)cxi_qp_find_pte_locked(&context, 20));
	EXPECT_EQ((uintptr_t)&qps[1], (uintptr_t)cxi_qp_find_pte_locked(&context, 4));
	EXPECT_EQ((uintptr_t)&qps[2], (uintptr_t)cxi_qp_find_pte_locked(&context, 11));
	EXPECT_EQ(0, (uintptr_t)cxi_qp_find_pte_locked(&context, 12));

	ret = cxi_qp_update_pte_locked(&context, &qps[1], 15);
	EXPECT_EQ(0, ret);
	EXPECT_EQ((uintptr_t)&qps[2], (uintptr_t)context.qp_by_pte[0]);
	EXPECT_EQ((uintptr_t)&qps[1], (uintptr_t)context.qp_by_pte[1]);
	EXPECT_EQ((uintptr_t)&qps[0], (uintptr_t)context.qp_by_pte[2]);
	ret = cxi_qp_update_pte_locked(&context, &qps[1], 20);
	EXPECT_EQ(EEXIST, ret);
	EXPECT_EQ(15, qps[1].pte_index);
	EXPECT_EQ((uintptr_t)&qps[1], (uintptr_t)cxi_qp_find_pte_locked(&context, 15));

	cxi_qp_unregister_locked(&context, &qps[1]);
	EXPECT_EQ(2, context.qp_count);
	EXPECT_EQ(0, (uintptr_t)context.qp_slots[1]);
	EXPECT_EQ(0, (uintptr_t)cxi_qp_find_pte_locked(&context, 15));
	qps[3].qp_slot = UINT32_MAX;
	qps[3].pte_index = 6;
	ret = cxi_qp_register_locked(&context, &qps[3]);
	EXPECT_EQ(0, ret);
	EXPECT_EQ(1, qps[3].qp_slot);
	EXPECT_EQ((uintptr_t)&qps[3], (uintptr_t)context.qp_slots[1]);
	EXPECT_EQ((uintptr_t)&qps[3], (uintptr_t)context.qp_by_pte[0]);

	cxi_qp_unregister_locked(&context, &qps[0]);
	cxi_qp_unregister_locked(&context, &qps[2]);
	cxi_qp_unregister_locked(&context, &qps[3]);
	EXPECT_EQ(0, context.qp_count);

out_unlock:
	pthread_spin_unlock(&context.qp_table_lock);
	pthread_spin_destroy(&context.qp_table_lock);
	correctness_result("qp-lookup-indexes", before);
}

enum op { OP_PUT, OP_GET };

/*
 * How a matching PTE selects a priority-list entry: the incoming match bits
 * must equal the entry's outside ignore_bits, the initiator must fall within
 * the entry's match_id, where an all-ones PID or endpoint field is a
 * wildcard, and the entry must permit the operation.
 */
static bool le_selects(const struct c_target_cmd *le, uint64_t match_bits, uint32_t initiator,
		       enum op op)
{
	const unsigned int bits = C_DFA_PID_BITS_MAX;
	uint32_t le_pid = CXI_MATCH_ID_PID(bits, le->match_id);
	uint32_t le_ep = CXI_MATCH_ID_EP(bits, le->match_id);

	if ((match_bits ^ le->match_bits) & ~le->ignore_bits)
		return false;
	if (le_pid != C_PID_ANY && le_pid != CXI_MATCH_ID_PID(bits, initiator))
		return false;
	if (le_ep != C_RANK_ANY && le_ep != CXI_MATCH_ID_EP(bits, initiator))
		return false;
	return op == OP_GET ? le->op_get : le->op_put;
}

/* Includes the initiator a live two-node SEND actually carried. */
static const uint32_t initiators[] = {
	0x00000000,
	0x00000001,
	0x36080000,
	0x00000807,
	0x00000836,
	CXI_MATCH_ID(C_DFA_PID_BITS_MAX, 10, 0x807),
	CXI_MATCH_ID(C_DFA_PID_BITS_MAX, 511, 0xfffff),
	0xffffffff,
};

#define NUM_INITIATORS ARRAY_SIZE(initiators)

static const uint64_t rkeys[] = {
	0x1, 0x1234, 0xabcd0001, 0x00000001deadbeefULL, 0x8000000000000001ULL,
};

#define NUM_RKEYS ARRAY_SIZE(rkeys)

static void test_model_enforces_match_id(void)
{
	union c_cmdu cmd;

	/* A zeroed match_id admits only initiator 0; the model must say so. */
	cxi_le_recv(&cmd, 10, 1, 0x1000, 4096);
	cmd.target.match_id = 0;
	EXPECT_FALSE(le_selects(&cmd.target, 0, 0x36080000, OP_PUT));
}

static void test_vni_key_encoding(void)
{
	union c_cmdu cmd;
	uint64_t wire_key = 0;
	const uint64_t keys[] = { 0, 1, 0xffffffffULL, CXI_LE_RKEY_MAX };

	for (size_t index = 0; index < ARRAY_SIZE(keys); index++) {
		cxi_le_recv(&cmd, 10, 1, 0x1000, 4096);
		EXPECT_EQ(0, cxi_le_wire_key(keys[index], &wire_key));
		EXPECT_EQ(keys[index], wire_key >> 16);
		EXPECT_EQ(0, wire_key & CXI_LE_VNI_MASK);
		EXPECT_EQ(0, cxi_le_set_vni(&cmd, keys[index], 0x7e01));
		EXPECT_TRUE(le_selects(&cmd.target, wire_key | 0x7e01, 0, OP_PUT));
		EXPECT_FALSE(le_selects(&cmd.target, wire_key | 0x7e00, 0, OP_PUT));
	}
	EXPECT_EQ(-EOPNOTSUPP, cxi_le_wire_key(1ULL << 48, &wire_key));
	EXPECT_EQ(-EOPNOTSUPP, cxi_le_wire_key(UINT64_MAX, &wire_key));
}

static void test_recv_fields(void)
{
	union c_cmdu cmd;

	cxi_le_recv(&cmd, 10, 5, 0x7f0000001000ULL, 4096);
	EXPECT_EQ(C_CMD_TGT_APPEND, cmd.command.opcode);
	EXPECT_EQ(10, cmd.target.ptlte_index);
	EXPECT_EQ(C_PTL_LIST_PRIORITY, cmd.target.ptl_list);
	EXPECT_EQ(5, cmd.target.lac);
	EXPECT_EQ(0x7f0000001000ULL, cmd.target.start);
	EXPECT_EQ(4096, cmd.target.length);
	EXPECT_EQ(CXI_MATCH_ID_ANY, cmd.target.match_id);
	EXPECT_EQ(CXI_LE_RECV_MATCH_BITS, cmd.target.match_bits);
	EXPECT_EQ(0, cmd.target.ignore_bits);
	EXPECT_EQ(1, cmd.target.op_put);
	EXPECT_EQ(0, cmd.target.op_get);
	EXPECT_EQ(1, cmd.target.use_once);
}

static void test_recv_selection(void)
{
	union c_cmdu cmd;
	size_t i, k;

	cxi_le_recv(&cmd, 10, 1, 0x1000, 4096);
	for (i = 0; i < NUM_INITIATORS; i++) {
		EXPECT_TRUE(le_selects(&cmd.target, 0, initiators[i], OP_PUT));
		EXPECT_FALSE(le_selects(&cmd.target, 0, initiators[i], OP_GET));
		for (k = 0; k < NUM_RKEYS; k++)
			EXPECT_FALSE(le_selects(&cmd.target, rkeys[k], initiators[i], OP_PUT));
	}
}

static void test_region_fields(void)
{
	union c_cmdu cmd;
	size_t k;

	for (k = 0; k < NUM_RKEYS; k++) {
		cxi_le_region(&cmd, 12, 0xabc0 | 6, rkeys[k], 0x2000, 8192);
		EXPECT_EQ(C_CMD_TGT_APPEND, cmd.command.opcode);
		EXPECT_EQ(12, cmd.target.ptlte_index);
		EXPECT_EQ(C_PTL_LIST_PRIORITY, cmd.target.ptl_list);
		EXPECT_EQ(6, cmd.target.lac);
		EXPECT_EQ(0x2000, cmd.target.start);
		EXPECT_EQ(8192, cmd.target.length);
		EXPECT_EQ(CXI_MATCH_ID_ANY, cmd.target.match_id);
		EXPECT_EQ(rkeys[k], cmd.target.match_bits);
		EXPECT_EQ(0, cmd.target.ignore_bits);
		EXPECT_EQ(1, cmd.target.op_put);
		EXPECT_EQ(1, cmd.target.op_get);
		EXPECT_EQ(0, cmd.target.use_once);
		EXPECT_EQ(rkeys[k] & 0xffff, cmd.target.buffer_id);
	}
}

static void test_region_selection(void)
{
	union c_cmdu cmd;
	size_t i, k, j;

	for (k = 0; k < NUM_RKEYS; k++) {
		cxi_le_region(&cmd, 12, 0, rkeys[k], 0x2000, 8192);
		for (i = 0; i < NUM_INITIATORS; i++) {
			uint32_t init = initiators[i];
			uint64_t wrong_rkey = rkeys[k] ^ (1ULL << 63);

			EXPECT_TRUE(le_selects(&cmd.target, rkeys[k], init, OP_PUT));
			EXPECT_TRUE(le_selects(&cmd.target, rkeys[k], init, OP_GET));
			/* A SEND must never land in a region. */
			EXPECT_FALSE(le_selects(&cmd.target, 0, init, OP_PUT));
			/* Exact: a key differing only in its high half is another key. */
			EXPECT_FALSE(le_selects(&cmd.target, wrong_rkey, init, OP_PUT));
			for (j = 0; j < NUM_RKEYS; j++) {
				if (j == k)
					continue;
				EXPECT_FALSE(le_selects(&cmd.target, rkeys[j], init, OP_PUT));
			}
		}
	}
}

static void test_region_unlink(void)
{
	union c_cmdu append, unlink;
	size_t k;

	for (k = 0; k < NUM_RKEYS; k++) {
		cxi_le_region(&append, 12, 0, rkeys[k], 0x2000, 8192);
		cxi_le_region_unlink(&unlink, 12, rkeys[k]);
		EXPECT_EQ(C_CMD_TGT_UNLINK, unlink.command.opcode);
		EXPECT_EQ(12, unlink.target.ptlte_index);
		EXPECT_EQ(C_PTL_LIST_PRIORITY, unlink.target.ptl_list);
		EXPECT_EQ(append.target.buffer_id, unlink.target.buffer_id);
	}
}

/* The provider's create-QP response layout is ABI shared with the kernel. */
static void test_create_qp_resp_abi(void)
{
	EXPECT_EQ(1, CXI_IB_UVERBS_ABI_VERSION);
	EXPECT_EQ(88, sizeof(struct cxi_ibv_create_qp_resp));
	EXPECT_EQ(72, offsetof(struct cxi_ibv_create_qp_resp, tgq_idx));
	EXPECT_EQ(76, offsetof(struct cxi_ibv_create_qp_resp, job_id));
	EXPECT_EQ(80, offsetof(struct cxi_ibv_create_qp_resp, pte_index));
}

static bool resource_ok(const char *operation, int ret)
{
	if (!ret)
		return true;
	fprintf(stderr, "%s: %s\n", operation, strerror(ret));
	failed_tests++;
	return false;
}

static bool test_exact_vni_service(struct ibv_context *context, const uint16_t *vnis,
				   uint32_t vni_count)
{
	struct cxidv_svc_attr config = {
		.vni_count = vni_count,
		.tc_mask = 1U << CXIDV_TC_BEST_EFFORT,
		.flags = CXIDV_SVC_CREATE_TC,
		.uid = geteuid(),
	};
	struct cxidv_svc_attr queried;
	uint32_t svc_id = 0;
	uint32_t index;
	int before = failed_tests;

	if (!vnis || !vni_count || vni_count > CXIDV_SVC_MAX_VNIS)
		return false;
	memcpy(config.vnis, vnis, vni_count * sizeof(config.vnis[0]));
	if (!resource_ok("allocate exact-VNI service", cxidv_alloc_svc(context, &config, &svc_id)))
		return false;
	if (!resource_ok("query exact-VNI service", cxidv_query_svc(context, svc_id, &queried)))
		goto out;
	if (queried.vni_count != config.vni_count || queried.is_range || queried.is_system_svc ||
	    queried.vni_min || queried.vni_max) {
		fprintf(stderr, "exact-VNI service query changed the granted set\n");
		failed_tests++;
		goto out;
	}
	for (index = 0; index < vni_count; index++) {
		if (queried.vnis[index] != config.vnis[index]) {
			fprintf(stderr, "exact-VNI service query changed the granted set\n");
			failed_tests++;
			goto out;
		}
	}
	if (!resource_ok("destroy exact-VNI service", cxidv_destroy_svc(context, svc_id)))
		return false;
	return failed_tests == before;
out:
	if (svc_id)
		resource_ok("cleanup exact-VNI service", cxidv_destroy_svc(context, svc_id));
	return false;
}

static bool test_retry_system_service(struct ibv_context *context)
{
	struct cxidv_svc_attr config = {
		.is_system_svc = 1,
		.flags = CXIDV_SVC_LIMITS,
		.uid = geteuid(),
		.maximum = {
			[CXIDV_SVC_EQS] = 1,
			[CXIDV_SVC_ACS] = 1,
		},
		.reserved = {
			[CXIDV_SVC_EQS] = 1,
			[CXIDV_SVC_ACS] = 1,
		},
	};
	struct cxidv_svc_attr queried;
	uint32_t svc_id = 0;
	uint32_t lpr;
	int before = failed_tests;

	if (!resource_ok("allocate retry system service",
			 cxidv_alloc_svc(context, &config, &svc_id)))
		return false;
	if (!resource_ok("query retry system service", cxidv_query_svc(context, svc_id, &queried)))
		goto out;
	if (!queried.is_system_svc || queried.is_range || queried.vni_count || queried.vni_min ||
	    queried.vni_max || queried.tc_mask || queried.vnis[0] || queried.vnis[1] ||
	    queried.vnis[2] || queried.vnis[3]) {
		fprintf(stderr, "retry system service query changed restricted-empty policy\n");
		failed_tests++;
		goto out;
	}
	if (!resource_ok("query retry system service LPR",
			 cxidv_get_svc_lpr(context, svc_id, &lpr)))
		goto out;
	if (lpr != 1) {
		fprintf(stderr, "retry system service LPR is %u, expected 1\n", lpr);
		failed_tests++;
		goto out;
	}
	if (!resource_ok("destroy retry system service", cxidv_destroy_svc(context, svc_id)))
		return false;
	return failed_tests == before;
out:
	if (svc_id)
		resource_ok("cleanup retry system service", cxidv_destroy_svc(context, svc_id));
	return false;
}

static void test_hardware_resources(const char *name)
{
	static const uint16_t one_vni[] = { 0x7e00 };
	static const uint16_t two_vnis[] = { 0x7e00, 0x7e03 };
	static const uint16_t four_vnis[] = { 0x7e00, 0x7e03, 0x7e07, 0x7e0b };
	struct ibv_device **devices = ibv_get_device_list(NULL);
	struct ibv_context *context = NULL;
	struct ibv_context *bare = NULL;
	struct cxidv_lni *lni = NULL;
	struct ibv_pd *first = NULL;
	struct ibv_pd *second = NULL;
	struct ibv_mr *mr = NULL;
	struct ibv_mr *receive_mr = NULL;
	struct ibv_ah *destination = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_job *job = NULL;
	struct ibv_job *alternate_job = NULL;
	struct ibv_job *retired_job = NULL;
	struct ibv_job_key *first_key = NULL;
	struct ibv_job_key *second_key = NULL;
	struct ibv_job_key *alternate_key = NULL;
	struct ibv_job_key *retired_grant = NULL;
	struct ibv_qp *first_qp = NULL;
	struct ibv_qp *second_qp = NULL;
	struct cxidv_svc_attr config = {
		.is_range = 1,
		.vnis = { 0x7e00, 0x7e03 },
		.tc_mask = 1U << CXIDV_TC_BEST_EFFORT,
		.flags = CXIDV_SVC_CREATE_TC,
	};
	struct cxidv_svc_attr queried;
	struct ibv_device_attr device_attr;
	uint32_t svc_id = 0;
	uint32_t first_pid, second_pid, queried_pid;
	char buffer[4096];
	char receive_buffer[4096];
	int default_enabled = 0;
	bool restore_default = false;
	bool indexed = getenv("CXI_TEST_INDEXED");
	int index;
	int ret;

	if (!devices) {
		failed_tests++;
		return;
	}
	for (index = 0; devices[index]; index++)
		if (!strcmp(ibv_get_device_name(devices[index]), name))
			break;
	if (!devices[index]) {
		fprintf(stderr, "missing device %s\n", name);
		failed_tests++;
		goto out;
	}
	context = ibv_open_device(devices[index]);
	if (!context) {
		resource_ok("open device", errno);
		goto out;
	}
	config.uid = geteuid();
	if (!test_exact_vni_service(context, one_vni, ARRAY_SIZE(one_vni)) ||
	    !test_exact_vni_service(context, two_vnis, ARRAY_SIZE(two_vnis)) ||
	    !test_exact_vni_service(context, four_vnis, ARRAY_SIZE(four_vnis)) ||
	    !test_retry_system_service(context))
		goto out;
	if (!resource_ok("allocate service", cxidv_alloc_svc(context, &config, &svc_id)))
		goto out;
	if (!resource_ok("query service", cxidv_query_svc(context, svc_id, &queried)))
		goto out;
	EXPECT_EQ(0, queried.vni_count);
	EXPECT_EQ(1, queried.is_range);
	EXPECT_EQ(0, queried.vni_min);
	EXPECT_EQ(0, queried.vni_max);
	EXPECT_EQ(config.vnis[0], queried.vnis[0]);
	EXPECT_EQ(config.vnis[1], queried.vnis[1]);
	EXPECT_EQ(config.tc_mask, queried.tc_mask);
	if (!resource_ok("query default service state",
			 cxidv_svc_is_enabled(context, 1, &default_enabled)))
		goto out;
	if (!resource_ok("disable default service", cxidv_enable_svc(context, 1, 0)))
		goto out;
	restore_default = true;
	bare = ibv_open_device(devices[index]);
	if (!bare) {
		resource_ok("open without default service", errno);
		goto out;
	}
	if (!resource_ok("query without default service", ibv_query_device(bare, &device_attr)))
		goto out;
	first = ibv_alloc_pd(bare);
	EXPECT_FALSE(first);
	if (first)
		goto out;
	if (!resource_ok("allocate explicit LNI", cxidv_alloc_lni(bare, svc_id, &lni)))
		goto out;
	first = cxidv_alloc_pd(lni);
	second = cxidv_alloc_pd(lni);
	if (!first || !second) {
		resource_ok("allocate explicit PDs", errno);
		goto out;
	}
	if (!resource_ok("allocate first PID", cxidv_alloc_pid(first, 0, &first_pid)) ||
	    !resource_ok("allocate second PID", cxidv_alloc_pid(second, 0, &second_pid)))
		goto out;
	EXPECT_TRUE(first_pid != second_pid);
	if (!resource_ok("query first PID", cxidv_query_pid(first, &queried_pid)))
		goto out;
	EXPECT_EQ(first_pid, queried_pid);
	EXPECT_EQ(EBUSY, cxidv_alloc_pid(first, 0, &queried_pid));
	ret = cxidv_destroy_lni(lni);
	EXPECT_EQ(EBUSY, ret);
	if (!ret) {
		lni = NULL;
		goto out;
	}
	mr = ibv_reg_mr(first, buffer, sizeof(buffer), IBV_ACCESS_LOCAL_WRITE);
	if (!mr) {
		resource_ok("register memory", errno);
		goto out;
	}
	EXPECT_EQ((uint32_t)mr->lkey64, mr->lkey);
	EXPECT_TRUE(mr->lkey != 0);
	{
		struct cxidv_mr_info info;

		if (!resource_ok("query native memory descriptor", cxidv_mr_from_ibv_mr(mr, &info)))
			goto out;
		EXPECT_TRUE(info.va <= (uintptr_t)buffer);
		EXPECT_TRUE(info.length >= sizeof(buffer));
		EXPECT_TRUE((uintptr_t)buffer - info.va <= info.length - sizeof(buffer));
		EXPECT_EQ(mr->lkey64 & CXI_LKEY64_LAC_MASK, info.lac);
		EXPECT_EQ((mr->lkey64 >> CXI_LKEY64_MD_SHIFT) & CXI_LKEY64_MD_MASK, info.id);
		EXPECT_EQ(to_cxi_mr(mr)->iova, info.iova + (uintptr_t)buffer - info.va);
		EXPECT_TRUE(info.page_shift > 0);
	}
	{
		struct ibv_mr_init_attr zero_key_attr = {
			.comp_mask = IBV_REG_MR_MASK_ADDR | IBV_REG_MR_MASK_RKEY,
			.addr = buffer,
			.length = sizeof(buffer),
		};
		struct ibv_mr *zero_key_mr;

		errno = 0;
		zero_key_mr = ibv_reg_mr_ex(first, &zero_key_attr);
		EXPECT_FALSE(zero_key_mr);
		EXPECT_EQ(EINVAL, errno);
		if (zero_key_mr)
			resource_ok("deregister invalid zero-key MR", ibv_dereg_mr(zero_key_mr));
	}
	cq = ibv_create_cq(bare, 64, NULL, NULL, 0);
	if (!cq) {
		resource_ok("create CQ", errno);
		goto out;
	}
	{
		struct ibv_job_attr attr = {
			.comp_mask =
				IBV_JOB_ATTR_ID | IBV_JOB_ATTR_PORT_NUM | IBV_JOB_ATTR_SGID_INDEX,
			.id = config.vnis[0],
			.port_num = 1,
		};
		struct ibv_qp_init_attr_ex qp_attr = {
			.send_cq = cq,
			.recv_cq = cq,
			.cap = {
				.max_send_wr = 16,
				.max_recv_wr = 16,
				.max_send_sge = 1,
				.max_recv_sge = 1,
			},
			.qp_type = IBV_QPT_RU,
			.comp_mask = IBV_QP_INIT_ATTR_PD |
				IBV_QP_INIT_ATTR_JKEY | IBV_QP_INIT_ATTR_CREATE_FLAGS |
				IBV_QP_INIT_ATTR_SEND_OPS_FLAGS,
			.create_flags = IBV_QP_CREATE_SOURCE_QPN,
			.send_ops_flags = IBV_QP_EX_WITH_SEND,
		};
		struct ibv_qp *duplicate;
		struct ibv_job *imported = NULL;
		struct ibv_job_attr queried_job = {};
		int job_fd = -1;

		if (indexed) {
			attr.comp_mask |= IBV_JOB_ATTR_MAX_ADDR_ENTRIES;
			attr.max_addr_entries = 2;
		}
		job = ibv_alloc_job(bare, &attr, NULL);
		if (!job) {
			resource_ok("allocate generic job", errno);
			goto out;
		}
		if (!resource_ok("query job", ibv_query_job(job, &queried_job)))
			goto out;
		EXPECT_EQ(config.vnis[0], queried_job.id);
		EXPECT_EQ(indexed ? 2 : 0, queried_job.max_addr_entries);
		if (!indexed) {
			struct ibv_ah_attr_ex address = {};

			EXPECT_EQ(EINVAL, ibv_insert_addr(job, &address, 0));
			EXPECT_EQ(EINVAL, ibv_query_addr(job, 0, &address));
			EXPECT_EQ(EINVAL, ibv_remove_addr(job, 0));
		}
		if (!resource_ok("export job", ibv_export_job(job, &job_fd)))
			goto out;
		ret = ibv_import_job(context, job_fd, &imported);
		close(job_fd);
		if (!resource_ok("import job into bare context", ret))
			goto out;
		resource_ok("query imported job", ibv_query_job(imported, &queried_job));
		EXPECT_EQ(config.vnis[0], queried_job.id);
		resource_ok("close imported job", ibv_dealloc_job(imported));
		attr.id++;
		attr.comp_mask &= ~IBV_JOB_ATTR_MAX_ADDR_ENTRIES;
		attr.max_addr_entries = 0;
		alternate_job = ibv_alloc_job(bare, &attr, NULL);
		if (!alternate_job) {
			resource_ok("allocate alternate job", errno);
			goto out;
		}
		first_key = ibv_create_jkey(first, job);
		second_key = ibv_create_jkey(second, alternate_job);
		alternate_key = ibv_create_jkey(first, alternate_job);
		if (!first_key || !second_key || !alternate_key) {
			resource_ok("create job keys", errno);
			goto out;
		}
		errno = 0;
		EXPECT_EQ(-1, ibv_dealloc_job(alternate_job));
		EXPECT_EQ(EBUSY, errno);
		qp_attr.pd = first;
		qp_attr.job_key = first_key;
		qp_attr.source_qpn = first_pid | (7U << IBV_QPN_UET_RI_SHIFT);
		{
			struct ibv_qp_attr initial_attr = {
				.path_mtu = IBV_MTU_2048,
			};

			qp_attr.comp_mask |= IBV_QP_INIT_ATTR_QP_ATTR;
			qp_attr.qp_attr = &initial_attr;
			qp_attr.qp_attr_mask = IBV_QP_PATH_MTU;
			errno = 0;
			duplicate = ibv_create_qp_ex(bare, &qp_attr);
			EXPECT_FALSE(duplicate);
			EXPECT_EQ(EOPNOTSUPP, errno);
			if (duplicate)
				resource_ok("destroy unsupported MTU QP",
					    ibv_destroy_qp(duplicate));
			qp_attr.comp_mask &= ~IBV_QP_INIT_ATTR_QP_ATTR;
			qp_attr.qp_attr = NULL;
			qp_attr.qp_attr_mask = 0;
		}
		first_qp = ibv_create_qp_ex(bare, &qp_attr);
		if (!first_qp) {
			resource_ok("create first QP", errno);
			goto out;
		}
		EXPECT_EQ(qp_attr.source_qpn, first_qp->qp_num);
		EXPECT_EQ(IBV_QPS_RTS, first_qp->state);
		{
			struct ibv_qp_attr queried_qp = {};
			struct ibv_qp_init_attr initialized = {};
			struct ibv_qp_attr invalid = {
				.qp_state = IBV_QPS_INIT,
			};

			if (resource_ok("query kernel RTS state",
					ibv_query_qp(first_qp, &queried_qp,
						     IBV_QP_STATE | IBV_QP_PATH_MTU,
						     &initialized))) {
				EXPECT_EQ(IBV_QPS_RTS, queried_qp.qp_state);
				EXPECT_EQ(IBV_MTU_4096, queried_qp.path_mtu);
			}
			EXPECT_EQ(EINVAL, ibv_modify_qp(first_qp, &invalid, IBV_QP_STATE));
		}
		{
			struct ibv_qp_ex *extended = ibv_qp_to_qp_ex(first_qp);
			struct cxi_qp *provider_qp = to_cxi_qp(first_qp);

			EXPECT_TRUE(extended);
			if (!extended)
				goto out;
			ibv_wr_start(extended);
			ibv_wr_set_job_key(extended, first_key->jkey);
			EXPECT_EQ(EINVAL, ibv_wr_complete(extended));
			ibv_wr_start(extended);
			ibv_wr_send(extended);
			ibv_wr_set_job_key(extended, UINT32_MAX);
			EXPECT_EQ(EINVAL, provider_qp->wr_build.err);
			EXPECT_EQ(EINVAL, ibv_wr_complete(extended));
			ibv_wr_start(extended);
			ibv_wr_send(extended);
			ibv_wr_set_job_key(extended, first_key->jkey);
			EXPECT_EQ(0, provider_qp->wr_build.err);
			ibv_wr_abort(extended);
		}
		duplicate = ibv_create_qp_ex(bare, &qp_attr);
		EXPECT_FALSE(duplicate);
		if (duplicate)
			resource_ok("destroy invalid duplicate", ibv_destroy_qp(duplicate));
		qp_attr.pd = second;
		qp_attr.job_key = second_key;
		qp_attr.source_qpn = second_pid | (7U << IBV_QPN_UET_RI_SHIFT);
		second_qp = ibv_create_qp_ex(bare, &qp_attr);
		if (!second_qp) {
			resource_ok("create second QP with same SI", errno);
			goto out;
		}
		EXPECT_TRUE(first_qp->qp_num != second_qp->qp_num);
		receive_mr = ibv_reg_mr(second, receive_buffer, sizeof(receive_buffer),
					IBV_ACCESS_LOCAL_WRITE);
		if (!receive_mr) {
			resource_ok("register alternate-job receive memory", errno);
			goto out;
		}
		for (int pass = 0; pass < (getenv("CXI_TEST_WRONG_VNI") ? 4 : 2); pass++) {
			int before = failed_tests;
			uint64_t receive_id = pass == 3 ? 102 : 100 + pass;
			uint32_t expected_job = config.vnis[0] + (pass == 1 || pass == 2 ? 0 : 1);
			struct ibv_qp *target = pass == 1 ? first_qp : second_qp;
			struct ibv_mr *target_mr = pass == 1 ? mr : receive_mr;
			struct ibv_ah_attr_ex address = {
				.ah_attr = {
					.is_global = 1,
					.port_num = 1,
					.grh.hop_limit = 1,
				},
				.remote_qpn = target->qp_num,
			};
			struct ibv_sge receive = {
				.addr = (uintptr_t)(pass == 1 ? buffer : receive_buffer),
				.length = 64,
				.lkey = target_mr->lkey,
			};
			struct ibv_recv_wr request = {
				.wr_id = 100 + pass,
				.sg_list = &receive,
				.num_sge = 1,
			};
			struct ibv_recv_wr *bad;
			struct ibv_qp_ex *extended = ibv_qp_to_qp_ex(first_qp);
			struct timespec started, now;
			bool sent = false, received = false;
			bool send_rejected = false;

			memset(buffer, 0x5a, 64);
			memset(receive_buffer, 0, 64);
			if (!resource_ok("query local GID",
					 ibv_query_gid(bare, 1, 0, &address.ah_attr.grh.dgid)))
				goto out;
			if (indexed) {
				struct ibv_ah_attr_ex result = {};

				EXPECT_EQ(ENOENT, ibv_query_addr(job, 1, &result));
				EXPECT_EQ(ENOENT, ibv_remove_addr(job, 1));
				EXPECT_EQ(EINVAL, ibv_insert_addr(job, &address, 2));
				EXPECT_EQ(EINVAL, ibv_query_addr(job, UINT_MAX, &result));
				EXPECT_EQ(EINVAL, ibv_remove_addr(job, 2));
				if (!resource_ok("insert indexed address",
						 ibv_insert_addr(job, &address, 1)))
					goto out;
				EXPECT_EQ(EBUSY, ibv_insert_addr(job, &address, 1));
				EXPECT_EQ(0, ibv_query_addr(job, 1, &result));
				EXPECT_EQ(address.remote_qpn, result.remote_qpn);
				EXPECT_EQ(0, memcmp(address.ah_attr.grh.dgid.raw,
						    result.ah_attr.grh.dgid.raw, 16));
				EXPECT_EQ(0, ibv_remove_addr(job, 1));
				EXPECT_EQ(ENOENT, ibv_query_addr(job, 1, &result));
				if (!resource_ok("reinsert indexed address",
						 ibv_insert_addr(job, &address, 1)))
					goto out;
			}
			destination = ibv_create_ah_ex(first, &address);
			if (!destination) {
				resource_ok("create loopback address", errno);
				goto out;
			}
			if (pass != 3 && !resource_ok("post job-selected receive",
						      ibv_post_recv(target, &request, &bad)))
				goto out;
			ibv_wr_start(extended);
			extended->wr_id = 200 + pass;
			ibv_wr_send(extended);
			if (!pass || pass == 3)
				ibv_wr_set_job_key(extended, alternate_key->jkey);
			ibv_wr_set_ru_addr(extended, indexed ? NULL : ibv_ah_to_ah_ex(destination),
					   indexed ? 1 : 0);
			ibv_wr_set_sge(extended, mr->lkey, (uintptr_t)buffer, 64);
			if (!resource_ok("send selected job", ibv_wr_complete(extended)))
				goto out;
			clock_gettime(CLOCK_MONOTONIC, &started);
			do {
				struct ibv_wc completion;

				ret = ibv_poll_cq(cq, 1, &completion);
				if (ret < 0) {
					resource_ok("poll selected-job CQ", EIO);
					goto out;
				}
				if (ret) {
					if (completion.wr_id == (uint64_t)(200 + pass))
						send_rejected = completion.status != IBV_WC_SUCCESS;
					if (pass != 2)
						EXPECT_EQ(IBV_WC_SUCCESS, completion.status);
					if (completion.wr_id == receive_id ||
					    completion.wr_id == (uint64_t)(200 + pass)) {
						EXPECT_EQ(expected_job,
							  to_cxi_ibv_cq(cq)->cur_job_id);
					}
					sent |= completion.wr_id == (uint64_t)(200 + pass);
					received |= completion.wr_id == receive_id &&
						    completion.status == IBV_WC_SUCCESS;
				}
				clock_gettime(CLOCK_MONOTONIC, &now);
			} while ((pass == 2 ? !sent : !(sent && received)) &&
				 now.tv_sec - started.tv_sec < 10);
			if (pass == 2) {
				EXPECT_TRUE(sent && send_rejected);
				EXPECT_TRUE(!received);
				if (received)
					fprintf(stderr, "relative endpoint accepted wrong VNI\n");
				correctness_result("unconfigured-job-receive", before);
			} else {
				EXPECT_TRUE(sent && received);
			}
			if (!pass || pass == 3)
				EXPECT_EQ(0, memcmp(buffer, receive_buffer, 64));
			if (!pass) {
				correctness_result("multi-job-send", before);
				correctness_result("multi-job-receive", before);
			}
			if (pass == 1)
				correctness_result("default-job-restoration", before);
			if (pass == 3)
				correctness_result("receive-after-job-rejection", before);
			if (pass != 2 && !(sent && received))
				goto out;
			if (!resource_ok("destroy loopback address", ibv_destroy_ah(destination)))
				goto out;
			destination = NULL;
			if (indexed)
				EXPECT_EQ(0, ibv_remove_addr(job, 1));
		}
		{
			struct ibv_qp_ex *extended = ibv_qp_to_qp_ex(first_qp);
			uint32_t retired_key = alternate_key->jkey;
			uint64_t before = to_cxi_qp(first_qp)->hw_txq.wp32;
			int failures_before = failed_tests;

			if (!resource_ok("destroy alternate key", ibv_destroy_jkey(alternate_key)))
				goto out;
			alternate_key = NULL;
			ibv_wr_start(extended);
			ibv_wr_send(extended);
			ibv_wr_set_job_key(extended, retired_key);
			EXPECT_EQ(EINVAL, ibv_wr_complete(extended));
			EXPECT_EQ(before, to_cxi_qp(first_qp)->hw_txq.wp32);
			correctness_result("retired-job-grant-send", failures_before);
		}
		{
			struct ibv_job_attr retired_attr = attr;
			struct ibv_qp_ex *extended = ibv_qp_to_qp_ex(first_qp);
			uint32_t retired_value;
			uint64_t before = to_cxi_qp(first_qp)->hw_txq.wp32;
			int failures_before = failed_tests;

			retired_attr.id = config.vnis[0] + 2;
			retired_job = ibv_alloc_job(bare, &retired_attr, NULL);
			if (!retired_job) {
				resource_ok("allocate retirement-test job", errno);
				goto out;
			}
			retired_grant = ibv_create_jkey(first, retired_job);
			if (!retired_grant) {
				resource_ok("create retirement-test grant", errno);
				goto out;
			}
			retired_value = retired_grant->jkey;
			if (!resource_ok("destroy last job grant", ibv_destroy_jkey(retired_grant)))
				goto out;
			retired_grant = NULL;
			if (!resource_ok("deallocate unreferenced job",
					 ibv_dealloc_job(retired_job)))
				goto out;
			retired_job = NULL;
			ibv_wr_start(extended);
			ibv_wr_send(extended);
			ibv_wr_set_job_key(extended, retired_value);
			EXPECT_EQ(EINVAL, ibv_wr_complete(extended));
			EXPECT_EQ(before, to_cxi_qp(first_qp)->hw_txq.wp32);
			correctness_result("deallocated-job-send", failures_before);
		}
		{
			struct ibv_sge64 sge = {
				.addr = (uintptr_t)buffer,
				.length = sizeof(buffer),
				.lkey64 = mr->lkey64,
			};
			struct ibv_recv_wr64 wr = {
				.wr_id = 7,
				.sg_list = &sge,
				.num_sge = 1,
			};
			struct ibv_recv_wr64 *bad = NULL;

			resource_ok("post receive64", ibv_post_recv64(first_qp, &wr, &bad));
			sge.lkey64 ^= 1ULL << 63;
			EXPECT_EQ(EINVAL, ibv_post_recv64(first_qp, &wr, &bad));
			EXPECT_TRUE(bad == &wr);
			sge.lkey64 = mr->lkey64;
			EXPECT_EQ(EINVAL, ibv_post_recv64(second_qp, &wr, &bad));
		}
	}
out:
	if (retired_grant)
		resource_ok("destroy retirement-test grant", ibv_destroy_jkey(retired_grant));
	if (retired_job)
		resource_ok("destroy retirement-test job", ibv_dealloc_job(retired_job));
	if (destination)
		resource_ok("destroy loopback address", ibv_destroy_ah(destination));
	if (second_qp)
		resource_ok("destroy second QP", ibv_destroy_qp(second_qp));
	if (first_qp)
		resource_ok("destroy first QP", ibv_destroy_qp(first_qp));
	if (second_key)
		resource_ok("destroy second key", ibv_destroy_jkey(second_key));
	if (first_key)
		resource_ok("destroy first key", ibv_destroy_jkey(first_key));
	if (alternate_key)
		resource_ok("destroy alternate key", ibv_destroy_jkey(alternate_key));
	if (alternate_job)
		resource_ok("destroy alternate job", ibv_dealloc_job(alternate_job));
	if (job)
		resource_ok("destroy job", ibv_dealloc_job(job));
	if (cq)
		resource_ok("destroy CQ", ibv_destroy_cq(cq));
	if (mr)
		resource_ok("deregister memory", ibv_dereg_mr(mr));
	if (receive_mr)
		resource_ok("deregister receive memory", ibv_dereg_mr(receive_mr));
	if (second)
		resource_ok("destroy second PD", ibv_dealloc_pd(second));
	if (first)
		resource_ok("destroy first PD", ibv_dealloc_pd(first));
	if (lni)
		resource_ok("destroy LNI", cxidv_destroy_lni(lni));
	if (bare)
		resource_ok("close bare context", ibv_close_device(bare));
	if (restore_default)
		resource_ok("restore default service",
			    cxidv_enable_svc(context, 1, default_enabled));
	if (svc_id)
		resource_ok("destroy service", cxidv_destroy_svc(context, svc_id));
	if (context)
		resource_ok("close context", ibv_close_device(context));
	ibv_free_device_list(devices);
}

static void test_csr_mapping(const char *device_name)
{
	struct ibv_device **devices = ibv_get_device_list(NULL);
	struct ibv_context *context = NULL;
	struct cxidv_csr *csr = NULL;
	long page_size = sysconf(_SC_PAGESIZE);
	unsigned int iteration;
	void *invalid;
	uint64_t offset;
	size_t length;
	int index;
	int ret;

	EXPECT_TRUE(devices);
	if (!devices)
		return;
	for (index = 0; devices[index]; index++) {
		if (!strcmp(ibv_get_device_name(devices[index]), device_name)) {
			context = ibv_open_device(devices[index]);
			break;
		}
	}
	EXPECT_TRUE(context);
	if (!context)
		goto out;
	EXPECT_TRUE(page_size > 0);
	if (page_size <= 0)
		goto out;
	EXPECT_EQ(EINVAL, cxidv_map_csrs(NULL, &csr));
	EXPECT_EQ(EINVAL, cxidv_map_csrs(context, NULL));
	EXPECT_EQ(EINVAL, cxidv_unmap_csrs(NULL));
	if (geteuid() != 0) {
		EXPECT_EQ(EPERM, cxidv_map_csrs(context, &csr));
		EXPECT_FALSE(csr);
		goto out;
	}
	for (iteration = 0; iteration < 16; iteration++) {
		ret = cxidv_map_csrs(context, &csr);
		if (!resource_ok("map CSR aperture", ret))
			goto out;
		EXPECT_TRUE(csr->address);
		EXPECT_TRUE(page_size > 0 && csr->length >= (size_t)page_size);
		EXPECT_EQ(0, csr->length % page_size);
		length = csr->length;
		offset = csr->mmap_offset;
		errno = 0;
		invalid = mmap(NULL, length + page_size, PROT_READ | PROT_WRITE, MAP_SHARED,
			       context->cmd_fd, offset);
		EXPECT_TRUE(invalid == MAP_FAILED);
		EXPECT_EQ(EINVAL, errno);
		if (invalid != MAP_FAILED)
			munmap(invalid, length + page_size);
		ret = cxidv_unmap_csrs(csr);
		if (!resource_ok("unmap CSR aperture", ret))
			goto out;
		csr = NULL;
		errno = 0;
		invalid = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_SHARED, context->cmd_fd,
			       offset);
		EXPECT_TRUE(invalid == MAP_FAILED);
		EXPECT_EQ(EINVAL, errno);
		if (invalid != MAP_FAILED)
			munmap(invalid, length);
	}
out:
	if (csr)
		resource_ok("cleanup CSR aperture", cxidv_unmap_csrs(csr));
	if (context)
		resource_ok("close CSR context", ibv_close_device(context));
	ibv_free_device_list(devices);
}

static void test_csr_accessors(void)
{
	uint64_t backing[4] = {};
	uint64_t input[] = { 0x123456789abcdef0ULL, 0xfedcba9876543210ULL };
	uint64_t output[2] = {};
	unsigned char unaligned[sizeof(input) + 1];
	struct cxidv_csr csr = {
		.address = backing,
		.length = sizeof(backing),
	};

	EXPECT_EQ(EINVAL, cxidv_read_csr(NULL, 0, output, sizeof(output)));
	EXPECT_EQ(EINVAL, cxidv_read_csr(&csr, 0, NULL, sizeof(output)));
	EXPECT_EQ(EINVAL, cxidv_read_csr(&csr, 0, output, 0));
	EXPECT_EQ(EINVAL, cxidv_read_csr(&csr, 1, output, sizeof(output)));
	EXPECT_EQ(EINVAL, cxidv_read_csr(&csr, 0, output, 1));
	EXPECT_EQ(EINVAL, cxidv_read_csr(&csr, UINT64_MAX, output, 8));
	EXPECT_EQ(EINVAL, cxidv_read_csr(&csr, 0, output, SIZE_MAX));
	EXPECT_EQ(EINVAL, cxidv_write_csr(NULL, 0, input, sizeof(input)));
	EXPECT_EQ(EINVAL, cxidv_write_csr(&csr, 0, NULL, sizeof(input)));
	EXPECT_EQ(EINVAL, cxidv_write_csr(&csr, 1, input, sizeof(input)));
	EXPECT_EQ(EINVAL, cxidv_write_csr(&csr, 24, input, sizeof(input)));
	EXPECT_EQ(EINVAL, cxidv_write8_csr(NULL, 0, 1));
	EXPECT_EQ(EINVAL, cxidv_write8_csr(&csr, sizeof(backing), 1));
	EXPECT_EQ(0, backing[0]);
	EXPECT_EQ(0, backing[3]);
	memcpy(unaligned + 1, input, sizeof(input));
	EXPECT_EQ(0, cxidv_write_csr(&csr, 8, unaligned + 1, sizeof(input)));
	EXPECT_EQ(input[0], le64toh(backing[1]));
	EXPECT_EQ(input[1], le64toh(backing[2]));
	EXPECT_EQ(0, backing[0]);
	EXPECT_EQ(0, backing[3]);
	memset(unaligned, 0, sizeof(unaligned));
	EXPECT_EQ(0, cxidv_read_csr(&csr, 8, unaligned + 1, sizeof(input)));
	EXPECT_EQ(0, memcmp(unaligned + 1, input, sizeof(input)));
	EXPECT_EQ(0, cxidv_write8_csr(&csr, 11, 0x5a));
	EXPECT_EQ(0x5a, ((unsigned char *)backing)[11]);
	EXPECT_EQ(0, ((unsigned char *)backing)[0]);
	csr.address = NULL;
	EXPECT_EQ(EINVAL, cxidv_read_csr(&csr, 0, output, sizeof(output)));
	EXPECT_EQ(EINVAL, cxidv_write8_csr(&csr, 0, 1));
}

static void test_command_ring_bounds(void)
{
	struct {
		struct cxi_cmd64 commands[16];
		uint64_t canary;
	} storage = {};
	const unsigned int count = ARRAY_SIZE(storage.commands);
	struct cxi_cq queue = {};
	unsigned int size;
	unsigned int position;
	int before = failed_tests;

	storage.canary = UINT64_C(0x123456789abcdef0);
	for (size = 0; size < ARRAY_SIZE(__cxi_cmd_slots); size++) {
		for (position = C_CQ_FIRST_WR_PTR_32; position < 2 * count; position++) {
			cxi_cq_init(&queue, storage.commands, count, NULL, 0);
			queue.wp32 = position;
			queue.rp32 = position;
			queue.status->rd_ptr = position / 2;
			EXPECT_EQ(0, cxi_cq_align_for_cmd(&queue, size));
			EXPECT_EQ(UINT64_C(0x123456789abcdef0), storage.canary);
		}
	}
	cxi_cq_init(&queue, storage.commands, count, NULL, 0);
	EXPECT_EQ(-EINVAL, cxi_cq_align_for_cmd(&queue, (enum c_cmd_size)-1));
	EXPECT_EQ(-EINVAL, cxi_cq_align_for_cmd(&queue, ARRAY_SIZE(__cxi_cmd_slots)));
	queue.size32--;
	EXPECT_EQ(-EINVAL, cxi_cq_align_for_cmd(&queue, C_CMD_SIZE_64B));
	correctness_result("command-ring-bounds", before);
}

static void test_queue_full_errno(void)
{
	struct cxi_context context = {};
	struct cxi_qp qp = {};
	struct cxi_ibv_cq cq = {};
	struct cxi_cmd64 commands[8] = {};
	struct cxi_mr mr = { .va = 0x1000, .iova = 0x1000, .len = 64 };
	struct ibv_sge sge = { .addr = 0x1000, .length = 64, .lkey = 1 };
	struct cxi_ah address = { .ah_ex.remote_qpn = 1, .nid = 0x807 };
	struct ibv_send_wr send = { .opcode = IBV_WR_SEND, .sg_list = &sge, .num_sge = 1 };
	struct ibv_recv_wr receive = { .sg_list = &sge, .num_sge = 1 };
	struct ibv_send_wr *bad_send = NULL;
	struct ibv_recv_wr *bad_receive = NULL;
	int before = failed_tests;
	int ret;

	context.verbs_ctx.sz = sizeof(context.verbs_ctx);
	context.verbs_ctx.context.abi_compat = __VERBS_ABI_IS_EXTENDED;
	context.pid_bits = 9;
	mr.vmr.ibv_mr.lkey = 1;
	context.mr_list = &mr;
	ret = pthread_spin_init(&context.mr_list_lock, PTHREAD_PROCESS_PRIVATE);
	EXPECT_EQ(0, ret);
	if (ret)
		return;
	ret = cxi_qp_init_locks(&qp);
	EXPECT_EQ(0, ret);
	if (ret) {
		pthread_spin_destroy(&context.mr_list_lock);
		return;
	}
	qp.vqp.qp.context = &context.verbs_ctx.context;
	qp.vqp.qp.send_cq = &cq.verbs_cq.cq;
	qp.sq_size = 1;
	qp.rq_size = 1;
	qp.job_id = 1;
	cxi_cq_init(&qp.hw_txq, commands, ARRAY_SIZE(commands), NULL, 0);
	qp.hw_txq.wp32 = qp.hw_txq.size32 - 2;
	qp.hw_tgq = qp.hw_txq;
	send.wr.ru.ah = &address.ah_ex;
	EXPECT_EQ(ENOSPC, cxi_post_send(&qp.vqp.qp, &send, &bad_send));
	EXPECT_EQ((uintptr_t)&send, (uintptr_t)bad_send);
	EXPECT_EQ(ENOSPC, cxi_post_recv(&qp.vqp.qp, &receive, &bad_receive));
	EXPECT_EQ((uintptr_t)&receive, (uintptr_t)bad_receive);
	pthread_mutex_destroy(&qp.builder_lock);
	pthread_spin_destroy(&qp.sq_lock);
	pthread_spin_destroy(&qp.rq_lock);
	pthread_spin_destroy(&context.mr_list_lock);
	correctness_result("queue-full-positive-errno", before);
}

static void test_telemetry_api_bounds(void)
{
	const uint64_t *items = NULL;
	uint32_t count = 0;
	int before = failed_tests;

	EXPECT_EQ(EINVAL, cxidv_telem_get_set((enum cxidv_telem_set)-1, &items, &count));
	EXPECT_EQ(EINVAL, cxidv_telem_get_set(CXIDV_TELEM_SET_COUNT, &items, &count));
	EXPECT_EQ(0, cxidv_telem_lookup("UNDEFINED"));
	EXPECT_EQ(-1, cxidv_telem_lookup(NULL));
	EXPECT_EQ(CXI_IBV_TC_ENTRY_F_CREATED_BY_RDMA, CXIDV_TC_ENTRY_F_CREATED_BY_RDMA);
	correctness_result("telemetry-api-bounds", before);
}

struct tc_cache_stress {
	struct cxi_context context;
	unsigned int failures;
};

static void *update_tc_cache(void *opaque)
{
	struct tc_cache_stress *test = opaque;

	for (unsigned int iteration = 0; iteration < 100000; iteration++) {
		uint32_t tc = iteration % CXI_IBV_TC_MAX;

		cxi_tc_cache_update(&test->context, tc, tc + 1000, true);
	}

	return NULL;
}

static void *read_tc_cache(void *opaque)
{
	struct tc_cache_stress *test = opaque;

	for (unsigned int iteration = 0; iteration < 100000; iteration++) {
		uint32_t tc, svc_id;

		if (!cxi_tc_cache_read(&test->context, &tc, &svc_id) ||
		    tc >= CXI_IBV_TC_MAX || svc_id != tc + 1000)
			test->failures++;
	}

	return NULL;
}

static void test_tc_cache_concurrency(void)
{
	struct tc_cache_stress test = {};
	pthread_t updater, reader;
	int before = failed_tests;
	int ret;

	ret = pthread_mutex_init(&test.context.tc_lock, NULL);
	EXPECT_EQ(0, ret);
	if (ret)
		return;
	cxi_tc_cache_update(&test.context, 0, 1000, true);
	ret = pthread_create(&updater, NULL, update_tc_cache, &test);
	EXPECT_EQ(0, ret);
	if (ret) {
		pthread_mutex_destroy(&test.context.tc_lock);
		return;
	}
	ret = pthread_create(&reader, NULL, read_tc_cache, &test);
	EXPECT_EQ(0, ret);
	if (ret) {
		pthread_join(updater, NULL);
		pthread_mutex_destroy(&test.context.tc_lock);
		return;
	}
	pthread_join(updater, NULL);
	pthread_join(reader, NULL);
	EXPECT_EQ(0, test.failures);
	pthread_mutex_destroy(&test.context.tc_lock);
	correctness_result("tc-cache-concurrency", before);
}

struct wait_hold_test {
	struct cxidv_wait *wait;
	pthread_mutex_t lock;
	pthread_cond_t cond;
	bool held;
	bool release;
	int get_ret;
};

static void *hold_wait_reference(void *opaque)
{
	struct wait_hold_test *test = opaque;

	pthread_mutex_lock(&test->lock);
	test->get_ret = cxi_wait_ref_get(test->wait);
	test->held = true;
	pthread_cond_signal(&test->cond);
	while (!test->release)
		pthread_cond_wait(&test->cond, &test->lock);
	if (!test->get_ret)
		cxi_wait_ref_put(test->wait);
	pthread_mutex_unlock(&test->lock);

	return NULL;
}

static void test_wait_lifetime_contract(void)
{
	struct cxidv_lni lni = {};
	struct cxidv_wait *wait = NULL;
	struct wait_hold_test hold = {};
	pthread_t thread;
	int pipe_fds[2] = { -1, -1 };
	bool read_fd_open = false;
	int before = failed_tests;
	int ret;

	EXPECT_EQ(EINVAL, cxidv_destroy_wait(NULL));
	ret = pipe(pipe_fds);
	EXPECT_EQ(0, ret);
	if (ret)
		goto out;
	read_fd_open = true;
	wait = calloc(1, sizeof(*wait));
	EXPECT_TRUE(wait);
	if (!wait)
		goto out;
	wait->lni = &lni;
	wait->fd = pipe_fds[0];
	ret = pthread_mutex_init(&hold.lock, NULL);
	EXPECT_EQ(0, ret);
	if (ret)
		goto out;
	ret = pthread_cond_init(&hold.cond, NULL);
	EXPECT_EQ(0, ret);
	if (ret) {
		pthread_mutex_destroy(&hold.lock);
		goto out;
	}
	hold.wait = wait;
	ret = pthread_create(&thread, NULL, hold_wait_reference, &hold);
	EXPECT_EQ(0, ret);
	if (ret) {
		pthread_cond_destroy(&hold.cond);
		pthread_mutex_destroy(&hold.lock);
		goto out;
	}
	pthread_mutex_lock(&hold.lock);
	while (!hold.held)
		pthread_cond_wait(&hold.cond, &hold.lock);
	EXPECT_EQ(0, hold.get_ret);
	if (!hold.get_ret)
		EXPECT_EQ(EBUSY, cxidv_destroy_wait(wait));
	hold.release = true;
	pthread_cond_signal(&hold.cond);
	pthread_mutex_unlock(&hold.lock);
	pthread_join(thread, NULL);
	pthread_cond_destroy(&hold.cond);
	pthread_mutex_destroy(&hold.lock);
	if (!hold.get_ret) {
		EXPECT_EQ(0, cxi_wait_ref_get(wait));
		EXPECT_EQ(0, cxi_wait_ref_get(wait));
		EXPECT_EQ(EBUSY, cxidv_destroy_wait(wait));
		cxi_wait_ref_put(wait);
		cxi_wait_ref_put(wait);
		ret = cxidv_destroy_wait(wait);
		EXPECT_EQ(0, ret);
		if (!ret) {
			read_fd_open = false;
			wait = NULL;
		}
	}
out:
	if (read_fd_open)
		close(pipe_fds[0]);
	if (wait)
		free(wait);
	if (pipe_fds[1] >= 0)
		close(pipe_fds[1]);
	correctness_result("wait-lifetime-contract", before);
}

static void test_failed_qp_destroy(void)
{
	struct cxi_context context = {};
	struct cxi_qp qp = {};
	int before = failed_tests;
	int ret;

	ret = pthread_spin_init(&context.qp_table_lock, PTHREAD_PROCESS_PRIVATE);
	EXPECT_EQ(0, ret);
	if (ret)
		return;
	qp.pte_index = 12;
	qp.qp_slot = UINT32_MAX;
	pthread_spin_lock(&context.qp_table_lock);
	ret = cxi_qp_register_locked(&context, &qp);
	pthread_spin_unlock(&context.qp_table_lock);
	EXPECT_EQ(0, ret);
	if (ret) {
		pthread_spin_destroy(&context.qp_table_lock);
		correctness_result("failed-qp-destroy-retains-lookup", before);
		return;
	}
	qp.vqp.qp.context = &context.verbs_ctx.context;
	fail_destroy_qp_command = true;
	EXPECT_EQ(EBUSY, cxi_destroy_qp(&qp.vqp.qp));
	pthread_spin_lock(&context.qp_table_lock);
	EXPECT_EQ((uintptr_t)&qp, (uintptr_t)context.qp_slots[qp.qp_slot]);
	EXPECT_EQ((uintptr_t)&qp,
		  (uintptr_t)cxi_qp_find_pte_locked(&context, qp.pte_index));
	pthread_spin_unlock(&context.qp_table_lock);
	fail_destroy_qp_command = false;
	pthread_spin_lock(&context.qp_table_lock);
	cxi_qp_unregister_locked(&context, &qp);
	pthread_spin_unlock(&context.qp_table_lock);
	pthread_spin_destroy(&context.qp_table_lock);
	correctness_result("failed-qp-destroy-retains-lookup", before);
}

static void test_sge_bounds(void)
{
	struct cxi_context context = {};
	struct cxi_mr mr = {
		.vmr.ibv_mr.lkey = 7,
		.lkey64 = 3,
		.va = 0x1000,
		.iova = 0x8000,
		.len = 0x100,
	};
	struct ibv_sge sge = { .addr = 0x1080, .length = 0x80, .lkey = 7 };
	uint64_t iova = 0;
	uint8_t lac = 0;
	int before = failed_tests;
	int ret;

	ret = pthread_spin_init(&context.mr_list_lock, PTHREAD_PROCESS_PRIVATE);
	EXPECT_EQ(0, ret);
	if (ret)
		return;
	context.mr_list = &mr;
	EXPECT_TRUE(cxi_sge_resolve(&context, &sge, &iova, &lac));
	EXPECT_EQ(0x8080, iova);
	EXPECT_EQ(3, lac);
	sge.length++;
	EXPECT_FALSE(cxi_sge_resolve(&context, &sge, &iova, &lac));
	sge.addr = UINT64_MAX - 15;
	sge.length = 32;
	EXPECT_FALSE(cxi_sge_resolve(&context, &sge, &iova, &lac));
	mr.va = UINT64_MAX - 31;
	mr.len = 64;
	EXPECT_FALSE(cxi_sge_resolve(&context, &sge, &iova, &lac));
	mr.va = 0x1000;
	mr.len = 0x100;
	mr.iova = UINT64_MAX - 7;
	sge.addr = 0x1010;
	sge.length = 1;
	EXPECT_FALSE(cxi_sge_resolve(&context, &sge, &iova, &lac));
	mr.iova = 0x8000;
	sge.addr = 0x1100;
	sge.length = 0;
	EXPECT_TRUE(cxi_sge_resolve(&context, &sge, &iova, &lac));
	sge.lkey++;
	EXPECT_FALSE(cxi_sge_resolve(&context, &sge, &iova, &lac));
	pthread_spin_destroy(&context.mr_list_lock);
	correctness_result("sge-bounds", before);
}

int main(int argc, char **argv)
{
	test_command_ring_bounds();
	test_queue_full_errno();
	test_telemetry_api_bounds();
	test_tc_cache_concurrency();
	test_wait_lifetime_contract();
	test_failed_qp_destroy();
	test_qp_lookup_indexes();
	test_sge_bounds();
	test_indexed_submission_locking();
	test_out_of_order_send_completions();
	test_model_enforces_match_id();
	test_recv_fields();
	test_recv_selection();
	test_region_fields();
	test_region_selection();
	test_region_unlink();
	test_create_qp_resp_abi();
	test_vni_key_encoding();
	test_csr_accessors();
	if (argc == 3 && !strcmp(argv[1], "--resources")) {
		test_hardware_resources(argv[2]);
	} else if (argc == 3 && !strcmp(argv[1], "--csr")) {
		test_csr_mapping(argv[2]);
	} else if (argc != 1) {
		fprintf(stderr, "usage: %s [--resources DEVICE | --csr DEVICE]\n", argv[0]);
		return 2;
	}

	if (failed_tests) {
		printf("cxi_le_test: %d check(s) FAILED\n", failed_tests);
		return 1;
	}
	printf("cxi_le_test: all checks passed\n");
	return 0;
}
