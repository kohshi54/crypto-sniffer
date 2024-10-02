from bcc import BPF
from bcc.utils import printb

def print_event(cpu, data, size):
	#event = ct.cast(data, ct.POINTER(Data)).contents
	event = b["events"].event(data)
	#print(f"{event.buf}")
	if event.cipher_type == 0:
		print("encryption")
		printb(b"before: %s" % event.plain)
		printb(b"after: %s" % event.encrypted)
	if event.cipher_type == 1:
		print("decryption")
		printb(b"before: %s" % event.encrypted)
		printb(b"after: %s" % event.plain)

#path="../openssl_evp_test/encrypt_test"
path="/lib/x86_64-linux-gnu/libcrypto.so.3"

b = BPF(src_file="trace.bpf.c")
b.attach_uprobe(name=path, sym="EVP_EncryptUpdate", fn_name="encrypt_update_enter")
#b.attach_uretprobe(name=path, sym="EVP_EncryptUpdate", fn_name="encrypt_update_exit")
b.attach_uretprobe(name=path, sym="EVP_EncryptFinal_ex", fn_name="encrypt_update_exit")
b.attach_uprobe(name=path, sym="EVP_DecryptUpdate", fn_name="decrypt_update_enter") # decryptupdateの段階でアドレス取っとく
#b.attach_uretprobe(name=path, sym="EVP_DecryptUpdate", fn_name="decrypt_update_exit")
b.attach_uretprobe(name=path, sym="EVP_DecryptFinal_ex", fn_name="decrypt_finalex_exit")
#b.attach_uprobe(name="/usr/local/ssl/lib/libcrypto.so", sym="EVP_EncryptUpdate", fn_name="read_buf")
b["events"].open_perf_buffer(print_event)
while 1:
	try:
		b.perf_buffer_poll()
		#b.trace_print()
	except KeyboardInterrupt:
		break

