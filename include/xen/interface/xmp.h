#ifndef __XEN_PUBLIC_XMP_H__
#define __XEN_PUBLIC_XMP_H__

#include <linux/module.h>
#include <linux/siphash.h>
#include <linux/gfp.h>

#include <uapi/linux/const.h>

#include <xen/interface/altp2m.h>

/*
 * Use this macro instead of VMX_VMFUNC_EPTP_SWITCHING.
 *
 * The macro defined in arch/x86/include/asm/vmx.h holds
 * the wrong value for EPTP switching.
 */
#define XMP_VMFUNC_EPTP_SWITCHING       0

/*
 * XMP_DEBUG
 */

#ifdef CONFIG_XMP_DEBUG
#define xmp_pr_info(msg, ...)   pr_info("[ xMP ] %s: " msg "\n", __FUNCTION__, ##__VA_ARGS__)
#else
#define xmp_pr_info(msg, ...)
#endif

/*
 * xMP domains
 */

#define XMP_MAX_PDOMAINS	XEN_ALTP2M_MAX_VIEWS

#define XMP_INVALID_PDOMAIN	0xffff

#define XMP_PRIVILEGED_PDOMAIN		0
#define XMP_RESTRICTED_PDOMAIN		1

#define XMP_RESTRICTED_PDOMAIN_PT	2

/*
 * xMP allocation flags
 */

#define XMP_GFP_SHIFT(domain)		(domain) << __GFP_BITS_SHIFT
#define XMP_GFP_FLAGS(domain, flags)	XMP_GFP_SHIFT(domain) | flags
#define XMP_GFP_FVIEW(flags)		(flags) >> __GFP_BITS_SHIFT

/*
 * xMP structures
 */

typedef enum {
	XMP_VCPU_STATUS_DOWN,
	XMP_VCPU_STATUS_UP
} xmp_vcpu_status_t;

struct vea_struct {
	uint32_t exit_reason;

	/*
	 * Indel SDM, Section 25.5.6.1
	 */
	uint32_t lock;
	uint64_t exit_qualification;
	uint64_t gva;
	uint64_t gpa;
	uint16_t altp2m_id;
};

struct xmp_vcpu {
	int nr;
	int status;
	struct vea_struct *vea;
};

struct xmp_vcpu_info {
	unsigned int num_vcpus;
	struct xmp_vcpu *vcpus;
};

/*
 * xMP primitives
 */

#ifdef CONFIG_XMP

struct xmp_vcpu *xmp_vcpu_ptr(unsigned int cpu);

struct vea_struct *xmp_vcpu_vea(unsigned int cpu);

struct xmp_vcpu *xmp_current_vcpu(void);

struct vea_struct *xmp_current_vea(void);

uint8_t xmp_vmfunc(uint16_t pdomain);

/*
 * xMP primitive B - Isolation of xMP domains
 */

int xmp_isolate_pages(uint16_t altp2m_id, struct page *page, unsigned int num_pages,
	xenmem_access_t r_access, xenmem_access_t p_access);

int xmp_isolate_page(uint16_t altp2m_id, struct page *page,
	xenmem_access_t r_access, xenmem_access_t p_access);

int xmp_release_pages(struct page *page, unsigned int num_pages);

#define xmp_isolate_addr(altp2m_id, addr, num_pages, r_access, p_access)		\
	xmp_isolate_pages(altp2m_id, virt_to_page(addr), num_pages, r_access, p_access)

/*
 * xMP primitive A - Memory partitioning through xMP Domains
 */

uint16_t xmp_alloc_pdomain(void);

void xmp_free_pdomain(uint16_t altp2m_id);

int __init xmp_init_late(void);

int __init xmp_init(void);

#endif /* CONFIG_XMP */

#ifdef CONFIG_XMP_PT

#define xmp_isolate_pt(altp2m_id, page)							\
	xmp_isolate_page(altp2m_id, page, XENMEM_access_r, XENMEM_access_rwx)

#endif /* CONFIG_XMP_PT */

#endif /* __XEN_PUBLIC_XMP_H__ */
