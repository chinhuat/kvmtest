#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include "linux/kvm.h"
#include <stddef.h>
#include <err.h>
#include <sys/mman.h>
#include <string.h>
#include <stdio.h>

int main(void) {

/*
(Source: https://lwn.net/Articles/658511/)

Using the KVM API

Many developers, users, and entire industries rely on virtualization, as provided by software like Xen, QEMU/KVM, or kvmtool. While QEMU can run a software-based virtual machine, and Xen can run cooperating paravirtualized OSes without hardware support, most current uses and deployments of virtualization rely on hardware-accelerated virtualization, as provided on many modern hardware platforms. Linux supports hardware virtualization via the Kernel Virtual Machine (KVM) API. In this article, we'll take a closer look at the KVM API, using it to directly set up a virtual machine without using any existing virtual machine implementation.

A virtual machine using KVM need not run a complete operating system or emulate a full suite of hardware devices. Using the KVM API, a program can run code inside a sandbox and provide arbitrary virtual hardware interfaces to that sandbox. If you want to emulate anything other than standard hardware, or run anything other than a standard operating system, you'll need to work with the KVM API used by virtual machine implementations. As a demonstration that KVM can run more (or less) than just a complete operating system, we'll instead run a small handful of instructions that simply compute 2+2 and print the result to an emulated serial port.

The KVM API provides an abstraction over the hardware-virtualization features of various platforms. However, any software making use of the KVM API still needs to handle certain machine-specific details, such as processor registers and expected hardware devices. For the purposes of this article, we'll set up an x86 virtual machine using Intel VT. For another platform, you'd need to handle different registers, different virtual hardware, and different expectations about memory layout and initial state.

The Linux kernel includes documentation of the KVM API in Documentation/virtual/kvm/api.txt and other files in the Documentation/virtual/kvm/ directory.

This article includes snippets of sample code from a fully functional sample program (MIT licensed). The program makes extensive use of the err() and errx() functions for error handling; however, the snippets quoted in the article only include non-trivial error handling.

Definition of the sample virtual machine
A full virtual machine using KVM typically emulates a variety of virtual hardware devices and firmware functionality, as well as a potentially complex initial state and initial memory contents. For our sample virtual machine, we'll run the following 16-bit x86 code:

    mov $0x3f8, %dx
    add %bl, %al
    add $'0', %al
    out %al, (%dx)
    mov $'\n', %al
    out %al, (%dx)
    hlt
These instructions will add the initial contents of the al and bl registers (which we will pre-initialize to 2), convert the resulting sum (4) to ASCII by adding '0', output it to a serial port at 0x3f8 followed by a newline, and then halt.

Rather than reading code from an object file or executable, we'll pre-assemble these instructions (via gcc and objdump) into machine code stored in a static array:
*/

    const uint8_t code[] = {
	0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
	0x00, 0xd8,       /* add %bl, %al */
	0x04, '0',        /* add $'0', %al */
	0xee,             /* out %al, (%dx) */
	0xb0, '\n',       /* mov $'\n', %al */
	0xee,             /* out %al, (%dx) */
	0xf4,             /* hlt */
    };

/*
For our initial state, we will preload this code into the second page of guest "physical" memory (to avoid conflicting with a non-existent real-mode interrupt descriptor table at address 0). al and bl will contain 2, the code segment (cs) will have a base of 0, and the instruction pointer (ip) will point to the start of the second page at 0x1000.

Rather than the extensive set of virtual hardware typically provided by a virtual machine, we'll emulate only a trivial serial port on port 0x3f8.

Finally, note that running 16-bit real-mode code with hardware VT support requires a processor with "unrestricted guest" support. The original VT implementations only supported protected mode with paging enabled; emulators like QEMU thus had to handle virtualization in software until reaching a paged protected mode (typically after OS boot), then feed the virtual system state into KVM to start doing hardware emulation. However, processors from the "Westmere" generation and newer support "unrestricted guest" mode, which adds hardware support for emulating 16-bit real mode, "big real mode", and protected mode without paging. The Linux KVM subsystem has supported the "unrestricted guest" feature since Linux 2.6.32 in June 2009.

Building a virtual machine
First, we'll need to open /dev/kvm:
*/

    int kvm = open("/dev/kvm", O_RDWR | O_CLOEXEC);

/*
We need read-write access to the device to set up a virtual machine, and all opens not explicitly intended for inheritance across exec should use O_CLOEXEC.

Depending on your system, you likely have access to /dev/kvm either via a group named "kvm" or via an access control list (ACL) granting access to users logged in at the console.

Before you use the KVM API, you should make sure you have a version you can work with. Early versions of KVM had an unstable API with an increasing version number, but the KVM_API_VERSION last changed to 12 with Linux 2.6.22 in April 2007, and got locked to that as a stable interface in 2.6.24; since then, KVM API changes occur only via backward-compatible extensions (like all other kernel APIs). So, your application should first confirm that it has version 12, via the KVM_GET_API_VERSION ioctl():
*/

    int ret = ioctl(kvm, KVM_GET_API_VERSION, NULL);
    if (ret == -1)
	err(1, "KVM_GET_API_VERSION");
    if (ret != 12)
	errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

/*
After checking the version, you may want to check for any extensions you use, using the KVM_CHECK_EXTENSION ioctl(). However, for extensions that add new ioctl() calls, you can generally just call the ioctl(), which will fail with an error (ENOTTY) if it does not exist.

If we wanted to check for the one extension we use in this sample program, KVM_CAP_USER_MEM (required to set up guest memory via the KVM_SET_USER_MEMORY_REGION ioctl()), that check would look like this:
*/

    ret = ioctl(kvm, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    if (ret == -1)
	err(1, "KVM_CHECK_EXTENSION");
    if (!ret)
	errx(1, "Required extension KVM_CAP_USER_MEM not available");

/*
Next, we need to create a virtual machine (VM), which represents everything associated with one emulated system, including memory and one or more CPUs. KVM gives us a handle to this VM in the form of a file descriptor:
*/

    int vmfd = ioctl(kvm, KVM_CREATE_VM, (unsigned long)0);

/*
The VM will need some memory, which we provide in pages. This corresponds to the "physical" address space as seen by the VM. For performance, we wouldn't want to trap every memory access and emulate it by returning the corresponding data; instead, when a virtual CPU attempts to access memory, the hardware virtualization for that CPU will first try to satisfy that access via the memory pages we've configured. If that fails (due to the VM accessing a "physical" address without memory mapped to it), the kernel will then let the user of the KVM API handle the access, such as by emulating a memory-mapped I/O device or generating a fault.

For our simple example, we'll allocate a single page of memory to hold our code, using mmap() directly to obtain page-aligned zero-initialized memory:
*/
    void *mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);

/*
We then need to copy our machine code into it:
*/

    memcpy(mem, code, sizeof(code));

/*
And finally tell the KVM virtual machine about its spacious new 4096-byte memory:
*/
    struct kvm_userspace_memory_region region = {
	.slot = 0,
	.guest_phys_addr = 0x1000,
	.memory_size = 0x1000,
	.userspace_addr = (uint64_t)mem,
    };
    ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &region);

/*
The slot field provides an integer index identifying each region of memory we hand to KVM; calling KVM_SET_USER_MEMORY_REGION again with the same slot will replace this mapping, while calling it with a new slot will create a separate mapping. guest_phys_addr specifies the base "physical" address as seen from the guest, and userspace_addr points to the backing memory in our process that we allocated with mmap(); note that these always use 64-bit values, even on 32-bit platforms. memory_size specifies how much memory to map: one page, 0x1000 bytes.

Now that we have a VM, with memory containing code to run, we need to create a virtual CPU to run that code. A KVM virtual CPU represents the state of one emulated CPU, including processor registers and other execution state. Again, KVM gives us a handle to this VCPU in the form of a file descriptor:
*/

    int vcpufd = ioctl(vmfd, KVM_CREATE_VCPU, (unsigned long)0);

/*
The 0 here represents a sequential virtual CPU index. A VM with multiple CPUs would assign a series of small identifiers here, from 0 to a system-specific limit (obtainable by checking the KVM_CAP_MAX_VCPUS capability with KVM_CHECK_EXTENSION).

Each virtual CPU has an associated struct kvm_run data structure, used to communicate information about the CPU between the kernel and user space. In particular, whenever hardware virtualization stops (called a "vmexit"), such as to emulate some virtual hardware, the kvm_run structure will contain information about why it stopped. We map this structure into user space using mmap(), but first, we need to know how much memory to map, which KVM tells us with the KVM_GET_VCPU_MMAP_SIZE ioctl():
*/

    int mmap_size = ioctl(kvm, KVM_GET_VCPU_MMAP_SIZE, NULL);

/*
Note that the mmap size typically exceeds that of the kvm_run structure, as the kernel will also use that space to store other transient structures that kvm_run may point to.

Now that we have the size, we can mmap() the kvm_run structure:
*/

    struct kvm_run *run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);

/*
The VCPU also includes the processor's register state, broken into two sets of registers: standard registers and "special" registers. These correspond to two architecture-specific data structures: struct kvm_regs and struct kvm_sregs, respectively. On x86, the standard registers include general-purpose registers, as well as the instruction pointer and flags; the "special" registers primarily include segment registers and control registers.

Before we can run code, we need to set up the initial states of these sets of registers. Of the "special" registers, we only need to change the code segment (cs); its default state (along with the initial instruction pointer) points to the reset vector at 16 bytes below the top of memory, but we want cs to point to 0 instead. Each segment in kvm_sregs includes a full segment descriptor; we don't need to change the various flags or the limit, but we zero the base and selector fields which together determine what address in memory the segment points to. To avoid changing any of the other initial "special" register states, we read them out, change cs, and write them back:
*/
    struct kvm_sregs sregs;
    ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    ioctl(vcpufd, KVM_SET_SREGS, &sregs);

/*
For the standard registers, we set most of them to 0, other than our initial instruction pointer (pointing to our code at 0x1000, relative to cs at 0), our addends (2 and 2), and the initial state of the flags (specified as 0x2 by the x86 architecture; starting the VM will fail with this not set):
*/
    struct kvm_regs regs = {
	.rip = 0x1000,
	.rax = 2,
	.rbx = 2,
	.rflags = 0x2,
    };
    ioctl(vcpufd, KVM_SET_REGS, &regs);
/*
With our VM and VCPU created, our memory mapped and initialized, and our initial register states set, we can now start running instructions with the VCPU, using the KVM_RUN ioctl(). That will return successfully each time virtualization stops, such as for us to emulate hardware, so we'll run it in a loop:
*/
    while (1) {
	ioctl(vcpufd, KVM_RUN, NULL);
	switch (run->exit_reason) {
	/* Handle exit */

/*
Note that KVM_RUN runs the VM in the context of the current thread and doesn't return until emulation stops. To run a multi-CPU VM, the user-space process must spawn multiple threads, and call KVM_RUN for different virtual CPUs in different threads.

To handle the exit, we check run->exit_reason to see why we exited. This can contain any of several dozen exit reasons, which correspond to different branches of the union in kvm_run. For this simple VM, we'll just handle a few of them, and treat any other exit_reason as an error.

We treat a hlt instruction as a sign that we're done, since we have nothing to ever wake us back up:
*/
	case KVM_EXIT_HLT:
	    puts("KVM_EXIT_HLT");
	    return 0;

/*
To let the virtualized code output its result, we emulate a serial port on I/O port 0x3f8. Fields in run->io indicate the direction (input or output), the size (1, 2, or 4), the port, and the number of values. To pass the actual data, the kernel uses a buffer mapped after the kvm_run structure, and run->io.data_offset provides the offset from the start of that mapping.
*/
	case KVM_EXIT_IO:
	    if (run->io.direction == KVM_EXIT_IO_OUT &&
		    run->io.size == 1 &&
		    run->io.port == 0x3f8 &&
		    run->io.count == 1)
		putchar(*(((char *)run) + run->io.data_offset));
	    else
		errx(1, "unhandled KVM_EXIT_IO");
	    break;

/*
To make it easier to debug the process of setting up and running the VM, we handle a few common kinds of errors. KVM_EXIT_FAIL_ENTRY, in particular, shows up often when changing the initial conditions of the VM; it indicates that the underlying hardware virtualization mechanism (VT in this case) can't start the VM because the initial conditions don't match its requirements. (Among other reasons, this error will occur if the flags register does not have bit 0x2 set, or if the initial values of the segment or task-switching registers fail various setup criteria.) The hardware_entry_failure_reason does not actually distinguish many of those cases, so an error of this type typically requires a careful read through the hardware documentation.
*/

	case KVM_EXIT_FAIL_ENTRY:
	    errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
		 (unsigned long long)run->fail_entry.hardware_entry_failure_reason);

/*
KVM_EXIT_INTERNAL_ERROR indicates an error from the Linux KVM subsystem rather than from the hardware. In particular, under various circumstances, the KVM subsystem will emulate one or more instructions in the kernel rather than via hardware, such as for performance reasons (to coalesce a series of vmexits for I/O). The run->internal.suberror value KVM_INTERNAL_ERROR_EMULATION indicates that the VM encountered an instruction it doesn't know how to emulate, which most commonly indicates an invalid instruction.
*/
	case KVM_EXIT_INTERNAL_ERROR:
	    errx(1, "KVM_EXIT_INTERNAL_ERROR: suberror = 0x%x",
	         run->internal.suberror);
	}
    }
}

/*
When we put all of this together into the sample code, build it, and run it, we get the following:

    $ ./kvmtest
    4
    KVM_EXIT_HLT
Success! We ran our machine code, which added 2+2, turned it into an ASCII 4, and wrote it to port 0x3f8. This caused the KVM_RUN ioctl() to stop with KVM_EXIT_IO, which we emulated by printing the 4. We then looped and re-entered KVM_RUN, which stops with KVM_EXIT_IO again for the \n. On the third and final loop, KVM_RUN stops with KVM_EXIT_HLT, so we print a message and quit.

Additional KVM API features
This sample virtual machine demonstrates the core of the KVM API, but ignores several other major areas that many non-trivial virtual machines will care about.

Prospective implementers of memory-mapped I/O devices will want to look at the exit_reason KVM_EXIT_MMIO, as well as the KVM_CAP_COALESCED_MMIO extension to reduce vmexits, and the ioeventfd mechanism to process I/O asynchronously without a vmexit.

For hardware interrupts, see the irqfd mechanism, using the KVM_CAP_IRQFD extension capability. This provides a file descriptor that can inject a hardware interrupt into the KVM virtual machine without stopping it first. A virtual machine may thus write to this from a separate event loop or device-handling thread, and threads running KVM_RUN for a virtual CPU will process that interrupt at the next available opportunity.

x86 virtual machines will likely want to support CPUID and model-specific registers (MSRs), both of which have architecture-specific ioctl()s that minimize vmexits.

Applications of the KVM API
Other than learning, debugging a virtual machine implementation, or as a party trick, why use /dev/kvm directly?

Virtual machines like qemu-kvm or kvmtool typically emulate the standard hardware of the target architecture; for instance, a standard x86 PC. While they can support other devices and virtio hardware, if you want to emulate a completely different type of system that shares little more than the instruction set architecture, you might want to implement a new VM instead. And even within an existing virtual machine implementation, authors of a new class of virtio hardware device will want a clear understanding of the KVM API.

Efforts like novm and kvmtool use the KVM API to construct a lightweight VM, dedicated to running Linux rather than an arbitrary OS. More recently, the Clear Containers project uses kvmtool to run containers using hardware virtualization.

Alternatively, a VM need not run an OS at all. A KVM-based VM could instead implement a hardware-assisted sandbox with no virtual hardware devices and no OS, providing arbitrary virtual "hardware" devices as the API between the sandbox and the sandboxing VM.

While running a full virtual machine remains the primary use case for hardware virtualization, we've seen many innovative uses of the KVM API recently, and we can certainly expect more in the future.
*/
