/*
 * macOS vmnet.framework wrapper.
 *
 * Presents a simple synchronous/polling API to Rust FFI, hiding the
 * GCD-block-based completion handlers that vmnet normally requires.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <dispatch/dispatch.h>
#include <vmnet/vmnet.h>

typedef struct {
    interface_ref  iface;
    uint64_t       max_packet_size;
} VmnetHandle;

/*
 * Open vmnet in shared (NAT) mode.  The caller needs CAP_NET_ADMIN
 * equivalent on macOS — root or the com.apple.vm.networking entitlement.
 * Returns NULL on failure.
 */
VmnetHandle *simmerv_vmnet_open(void)
{
    dispatch_queue_t q =
        dispatch_queue_create("simmerv.vmnet.init", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);

    __block vmnet_return_t result    = VMNET_FAILURE;
    __block interface_ref  iface     = NULL;
    __block uint64_t       max_pkt   = 1514;

    xpc_object_t desc = xpc_dictionary_create(NULL, NULL, 0);
    xpc_dictionary_set_uint64(desc, vmnet_operation_mode_key, VMNET_SHARED_MODE);

    iface = vmnet_start_interface(desc, q,
        ^(vmnet_return_t status, xpc_object_t params) {
            result = status;
            if (status == VMNET_SUCCESS)
                max_pkt = xpc_dictionary_get_uint64(
                              params, vmnet_max_packet_size_key);
            dispatch_semaphore_signal(sem);
        });

    xpc_release(desc);
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    dispatch_release(sem);
    dispatch_release(q);

    if (result != VMNET_SUCCESS || iface == NULL)
        return NULL;

    VmnetHandle *h = (VmnetHandle *)malloc(sizeof(VmnetHandle));
    if (!h) return NULL;
    h->iface           = iface;
    h->max_packet_size = max_pkt;
    return h;
}

/*
 * Non-blocking read.  Returns the number of bytes in the received packet,
 * or 0 if no packet is currently available.
 */
int simmerv_vmnet_read(VmnetHandle *h, uint8_t *buf, int cap)
{
    struct iovec iov    = { buf, (size_t)cap };
    struct vmpktdesc pk = { (size_t)cap, &iov, 1, 0 };
    int pktcnt = 1;
    vmnet_return_t r = vmnet_read(h->iface, &pk, &pktcnt);
    if (r != VMNET_SUCCESS || pktcnt == 0) return 0;
    return (int)pk.vm_pkt_size;
}

/*
 * Write one ethernet frame.  Returns 0 on success, non-zero on failure.
 */
int simmerv_vmnet_write(VmnetHandle *h, const uint8_t *buf, int len)
{
    /* iov_base is void*, not const void* — vmnet doesn't modify the buffer */
    struct iovec iov    = { (void *)(uintptr_t)buf, (size_t)len };
    struct vmpktdesc pk = { (size_t)len, &iov, 1, 0 };
    int pktcnt = 1;
    return vmnet_write(h->iface, &pk, &pktcnt) != VMNET_SUCCESS;
}

/* Synchronously stop the interface and free the handle. */
void simmerv_vmnet_close(VmnetHandle *h)
{
    if (!h) return;
    dispatch_queue_t q =
        dispatch_queue_create("simmerv.vmnet.close", DISPATCH_QUEUE_SERIAL);
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    vmnet_stop_interface(h->iface, q, ^(vmnet_return_t status) {
        (void)status;
        dispatch_semaphore_signal(sem);
    });
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    dispatch_release(sem);
    dispatch_release(q);
    free(h);
}
