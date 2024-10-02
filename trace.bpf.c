#include <uapi/linux/ptrace.h>

struct data_t {
	char buf[100];
};

BPF_HASH(buf_addr, u32, u64); //local var no addr hozon
BPF_PERF_OUTPUT(events);

int encrypt_update_enter(struct pt_regs *ctx, const void *evpctx, unsigned char *out, int *outl, unsigned char *in, int inl) {
	if (!PT_REGS_PARM4(ctx)) // in
		return 0;
	
	struct data_t data = {};
	//bpf_probe_read_user();
	//bpf_probe_read(&data.buf, sizeof(data.buf), (void *)PT_REGS_PARM2(ctx));
	bpf_probe_read(&data.buf, sizeof(data.buf), in);
	//bpf_probe_read(&data.buf, inl > 100 ? 100 : inl, in);
	//bpf_trace_printk("%s", data.buf);
	events.perf_submit(ctx, &data, sizeof(data));

	u32 pid = bpf_get_current_pid_tgid();
	u64 param_addr = PT_REGS_PARM2(ctx);
	buf_addr.update(&pid, &param_addr);
	bpf_trace_printk("encrypt_in: %d", pid);

	return 0;
};

int encrypt_update_exit(struct pt_regs *ctx) {
	struct data_t data = {};
	u32 pid = bpf_get_current_pid_tgid();
	u64 *param_addr = buf_addr.lookup(&pid);
	if (param_addr == 0)
		return 0;
	bpf_probe_read_user(&data.buf, sizeof(data.buf), (void *)*param_addr);
	events.perf_submit(ctx, &data, sizeof(data));

	buf_addr.delete(&pid);
	bpf_trace_printk("encrypt_out: %d", pid);
	return 0;
}

int decrypt_update_enter(struct pt_regs *ctx, const void *evpctx, unsigned char *out, int *outl, unsigned char *in, int inl) {
	if (!PT_REGS_PARM4(ctx)) // in
		return 0;
	struct data_t data = {0};
	bpf_probe_read(&data.buf, sizeof(data.buf), in);
	events.perf_submit(ctx, &data, sizeof(data));

	u32 pid = bpf_get_current_pid_tgid();
	u64 param_addr = PT_REGS_PARM2(ctx);
	buf_addr.update(&pid, &param_addr);
	bpf_trace_printk("decrypt_in: %d", pid);
	return 0;
}

int decrypt_update_exit(struct pt_regs *ctx) {
	struct data_t data = {0};
	u32 pid = bpf_get_current_pid_tgid();
	u64 *param_addr = buf_addr.lookup(&pid);
	if (param_addr == 0)
		return 0;
	bpf_probe_read_user(&data.buf, sizeof(data.buf), (void *)*param_addr);
	events.perf_submit(ctx, &data, sizeof(data));
	//data.buf[99] = '\0';	
	buf_addr.delete(&pid);
	bpf_trace_printk("decrypt_out: %d", pid);
	return 0;
}

int decrypt_finalex_enter(struct pt_regs *ctx, const void *evpctx, unsigned char *outm, int *outl) {
	if (!PT_REGS_PARM2(ctx)) // buf mada encrypt
		return 0;
	struct data_t data = {0};
	bpf_probe_read(&data.buf, sizeof(data.buf), outm);
	events.perf_submit(ctx, &data, sizeof(data));

	u32 pid = bpf_get_current_pid_tgid();
	u64 param_addr = PT_REGS_PARM2(ctx);
	buf_addr.update(&pid, &param_addr);
	bpf_trace_printk("decrypt_finalin: %d", pid);
	return 0;
}

int decrypt_finalex_exit(struct pt_regs *ctx) {
	struct data_t data = {0};
	u32 pid = bpf_get_current_pid_tgid();
	u64 *param_addr = buf_addr.lookup(&pid);
	if (param_addr == 0)
		return 0;
	bpf_probe_read_user(&data.buf, sizeof(data.buf), (void *)*param_addr);
	events.perf_submit(ctx, &data, sizeof(data));
	//data.buf[99] = '\0';	
	buf_addr.delete(&pid);
	bpf_trace_printk("decrypt_finalout: %d", pid);
	return 0;
}

