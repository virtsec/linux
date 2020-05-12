#include <linux/mm.h>
#include <linux/errno.h>
#include <linux/random.h>
#include <linux/bootmem.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/smp.h>
#include <linux/types.h>
#include <linux/siphash.h>
#include <linux/bitmap.h>
#include <linux/topology.h>
#include <linux/percpu-defs.h>

#include <xen/interface/xmp.h>
#include <xen/interface/xen.h>
#include <xen/interface/altp2m.h>

#include <asm/bitops.h>
#include <asm/unaligned.h>
#include <asm/fpu/api.h>
#include <asm/processor-flags.h>
#include <asm/sections.h>

#include <asm/xen/page.h>

DECLARE_BITMAP(xmp_pdomain_bitmap, XMP_MAX_PDOMAINS);
DEFINE_SPINLOCK(xmp_pdomain_bitmap_lock);

/*
 * Pointers to xMP siphash key
 *
 * Each view is assigned a xMP siphash key which is only visible to the specific
 * view it was allocated for. Thus, we need a page for each key to reside in. To
 * make sure the key appears to be at the same address for each domain, we use
 * Xens altp2m_change_gfn hypercall to remap the GFN of the secret key page.
 */
static siphash_key_t *xmp_key = NULL;

/*
 * xMP vCPU information structure
 */
static struct xmp_vcpu_info xmp_vcpu_info = { 0 };

/*
 * xMP utilities
 */

struct xmp_vcpu *xmp_vcpu_ptr(unsigned int cpu)
{
        if (cpu >= xmp_vcpu_info.num_vcpus)
                return NULL;

        return &xmp_vcpu_info.vcpus[cpu];
}

struct vea_struct *xmp_vcpu_vea(unsigned int cpu)
{
        struct xmp_vcpu *vcpu = xmp_vcpu_ptr(cpu);

        return (vcpu ? vcpu->vea : NULL);
}

struct xmp_vcpu *xmp_current_vcpu(void)
{
        unsigned int cpu = smp_processor_id();

        return xmp_vcpu_ptr(cpu);
}

struct vea_struct *xmp_current_vea(void)
{
        unsigned int cpu = smp_processor_id();

        return xmp_vcpu_vea(cpu);
}

/*
 * xMP primitives
 */

static uint8_t __xmp_vmfunc(uint16_t pdomain)
{
        uint8_t ret;

        asm volatile("vmfunc;"
                     : "=a"(ret)
                     : "a"(XMP_VMFUNC_EPTP_SWITCHING), "c"(pdomain)
                     : "cc");

        return ret;
}

uint8_t xmp_vmfunc(uint16_t pdomain)
{
        struct xmp_vcpu *vcpu = xmp_current_vcpu();

	if (!vcpu) {
		xmp_pr_info("Could not find current vCPU!");
		return 0;
	}

        /*
         * This branch prediction only misses during the early stage
         * when VMFUNC has not been enabled on the current vCPU.
         */

        if (unlikely(vcpu->status != XMP_VCPU_STATUS_UP))
                return 0;

        return __xmp_vmfunc(pdomain);
}
EXPORT_SYMBOL(xmp_vmfunc);

/*
 * xMP primitive C: Context-bound Pointer Integrity
 *
 * The following paragraphs briefly describe the correct usage of the signing
 * and authenticating functions and their behavior.
 *
 * Every pointer to an isolated structure has to be signed. That is, the devs
 * are responsible for using xmp_sign_ptr() on this particular pointer. We do
 * pass the altp2m_id as an argument to the function which tells for which id
 * the pointer is signed for.
 *
 * Every usage of the same structure pointer is to be autheticated by calling
 * xmp_auth_ptr() with the same altp2m_id in which the structure was isolated
 * in.
 *
 * If a pointer is signed by using either ap2m[0] or ap2m[1] the pointers are
 * returned unmodified as ap2m[0] and ap2m[1] both are not used for isolation
 * purposes.
 *
 * However, if a pointer is authenticated with either one of those altp2m_ids
 * we will crash, because those views are, as explained, not valid for either
 * isolation or authentication.
 *
 * That means, an attacker trying to modify an index to a unprotected ap2m_id
 * will ultimately cause a crash, simply because the altp2m_id is invalid for
 * any protected domain and its isolated objects.
 */

static uint16_t xmp_siphash(void *ptr, void *ctx, uint16_t altp2m_id)
{
	uint16_t view;
	uint64_t hash, data;

	view = XMP_VIEW_MASK(current->xmp_kernel_index);
	data = ((uint64_t)ptr ^ (uint64_t)ctx);

	xmp_vmfunc(altp2m_id);

	/*
	 * This will crash if the altp2m view we just switched to does not
	 * have a key generated when the domain was allocated.
	 */
	hash = siphash(&data, sizeof(data), xmp_key);
	xmp_vmfunc(view);

	return hash & 0x7fff;
}

void *xmp_sign_ptr(void *ptr, void *ctx, uint16_t altp2m_id)
{
	uint64_t hmac, pval;

	if (altp2m_id <= XMP_RESTRICTED_PDOMAIN)
		return ptr;

	hmac  = xmp_siphash(ptr, ctx, altp2m_id);
	pval  = (uint64_t)ptr & ~XMP_PAC_MASK;
	pval |= (hmac << 48)  &  XMP_PAC_MASK;

	return (void *)pval;
}

void *xmp_auth_ptr(void *ptr, void *ctx, uint16_t altp2m_id)
{
	uint64_t hmac, pval;

	if (altp2m_id <= XMP_RESTRICTED_PDOMAIN)
		BUG_ON(true);

	pval = (uint64_t)ptr & ~XMP_PAC_MASK;
	if (pval & (1ULL << 63))
		pval |= XMP_PAC_MASK;

	/*
	 * If the HMAC in the pointer does not match the calculated HMAC
	 * then we deliberately cause a crash.
	 */
	hmac = xmp_siphash((void *)pval, ctx, altp2m_id);
	if (hmac != XMP_PTR_HMAC(ptr))
		BUG_ON(true);

	return (void *)pval;
}

uint64_t xmp_sign_val(void *ctx, uint16_t altp2m_id)
{
	uint64_t hmac, ival;

	if (altp2m_id <= XMP_RESTRICTED_PDOMAIN)
		return altp2m_id;

	hmac = xmp_siphash(NULL, ctx, altp2m_id);
	ival = XMP_INDEX(altp2m_id, hmac);

	return ival;
}

uint64_t xmp_auth_val(uint64_t ival, void *ctx)
{
	uint16_t altp2m_id;
	uint64_t hmac;

	altp2m_id = XMP_VIEW_MASK(ival);
	if (altp2m_id <= XMP_RESTRICTED_PDOMAIN)
		return 0;

	hmac = xmp_siphash(NULL, ctx, altp2m_id);
	if (hmac != XMP_VAL_HMAC(ival))
		BUG_ON(true);

	return 0;
}

/*
 * Protecting and unprotecting
 */

int xmp_unprotect(uint16_t altp2m_id)
{
	uint64_t data, hash;

	if (!xmp_key)
		return XMP_RESTRICTED_PDOMAIN;

	/*
	 * To reduce the number of switches, we call vmfunc once to access
	 * the xmp_key for the specified view and continue execution while
	 * staying in this view.
	 *
	 * This may drastically reduce the numbers of switches in frequent
	 * locations such as in the #VE handler, when CPUs try to write to
	 * isolated page table structures.
	 */
	xmp_vmfunc(altp2m_id);

	data = (uint64_t)current;
	hash = siphash(&data, sizeof(data), xmp_key) & 0x7fff;

	current->xmp_kernel_index = XMP_INDEX(altp2m_id, hash);

	return altp2m_id;
}

int xmp_protect(void)
{
	uint16_t altp2m_id = XMP_RESTRICTED_PDOMAIN;

	if (!xmp_key)
		return altp2m_id;

	xmp_vmfunc(altp2m_id);

	current->xmp_kernel_index = XMP_INDEX(altp2m_id, 0);

	return altp2m_id;
}

void xmp_context_switch(struct task_struct *task)
{
	if (xmp_auth_val(task->xmp_kernel_index, task))
		BUG_ON(true);
}

/*
 * xMP primitive A: Memory Partitioning through xMP Domains
 *
 * Allocating and freeing domains. All altp2m views have been created during
 * the initialization phase. We simply look over the bitmap and check, which
 * domain has not been allocated.
 *
 * When freeing a domain we keep the altp2m view active but clear the bit in
 * the allocation bitmap.
 */

static uint16_t xmp_create_pdomain(void)
{
	uint16_t altp2m_id = 0;

	spin_lock(&xmp_pdomain_bitmap_lock);

	altp2m_id = find_first_zero_bit(xmp_pdomain_bitmap, XMP_MAX_PDOMAINS);
	if (altp2m_id == XMP_MAX_PDOMAINS) {
		spin_unlock(&xmp_pdomain_bitmap_lock);
		return altp2m_id;
	}

	bitmap_set(xmp_pdomain_bitmap, altp2m_id, 1);

	spin_unlock(&xmp_pdomain_bitmap_lock);

	return altp2m_id;
}

static int xmp_destroy_pdomain(uint16_t altp2m_id)
{
	int set;

	spin_lock(&xmp_pdomain_bitmap_lock);
	set = test_and_clear_bit(altp2m_id, xmp_pdomain_bitmap);
	spin_unlock(&xmp_pdomain_bitmap_lock);

	return set;
}

/*
 * xMP primitive B: Isolation of xMP Domains
 *
 * Core function for isolating page-sized chunks of memory in individual views.
 */

static int __xmp_isolate_pages(uint16_t altp2m_id, struct page *page,
	unsigned int num_pages, xenmem_access_t r_access,
	xenmem_access_t p_access, bool release)
{
	int ret;
	unsigned int i;
	xen_pfn_t gfn;
	struct page *pgp;

	for (i = 0; i < num_pages; i++) {
		pgp = page + i;
		gfn = page_to_pfn(pgp);

		/*
		 * Sanity check before performing isolation or release of pages
		 *
		 * We check whether the pages have already been isolated before
		 * trying to release them. The same goes for the isolation with
		 * the PG_xmp bit not being set.
		 */
		if (!release)
			goto isolate_pages;

		if (pgp->flags & (1UL << PG_xmp))
			__clear_bit(PG_xmp, &pgp->flags);
		else {
			xmp_pr_info("Trying to release a non-isolated page, skip...");
			continue;
		}

isolate_pages:
		/*
		 * When isolating a page, we only check whether the PG_xmp bit
		 * is cleared and if it is, we set it.
		 *
		 * If it is set, then the page is already isolated and the call
		 * is simply to alter the permissions for this page.
		 */
		if (!release && !(pgp->flags & (1UL << PG_xmp)))
			__set_bit(PG_xmp, &pgp->flags);

		ret = altp2m_isolate_pdomain(altp2m_id, gfn, r_access, p_access, release);
		if (ret)
			return -EFAULT;
	}

	return 0;
}

/*
 * xmp_isolate_pages: Isolate <num_pages> continuous pages in the given pdomain.
 *
 * @altp2m_id: The pdomain in which to isolate the given page
 * @page: The page to isolate
 * @num_pages: The number of pages to isolate
 * @r_access: The permissions in the restricted views
 * @p_access: The permissions in the "private" (relaxed) view
 */
int xmp_isolate_pages(uint16_t altp2m_id, struct page *page, unsigned int num_pages,
	xenmem_access_t r_access, xenmem_access_t p_access)
{
	return __xmp_isolate_pages(altp2m_id, page, num_pages, r_access, p_access, false);
}
EXPORT_SYMBOL(xmp_isolate_pages);

/*
 * xmp_isolate_page: Isolate a given page in the given pdomain.
 *
 * @altp2m_id: The pdomain in which to isolate the given page
 * @page: The page to isolate
 * @r_access: The permissions in the restricted views
 * @p_access: The permissions in the "private" (relaxed) view
 */
int xmp_isolate_page(uint16_t altp2m_id, struct page *page, xenmem_access_t r_access,
	xenmem_access_t p_access)
{
	return __xmp_isolate_pages(altp2m_id, page, 1, r_access, p_access, false);
}
EXPORT_SYMBOL(xmp_isolate_page);

/*
 * xmp_release_pages: Release the given pages from all pdomains.
 *
 * @page: The page or compound page head to release.
 * @num_pages: The number of continuous pages.
 */
int xmp_release_pages(struct page *page, unsigned int num_pages)
{
	return __xmp_isolate_pages(XMP_RESTRICTED_PDOMAIN, page, num_pages,
		XENMEM_access_rwx, XENMEM_access_rwx, true);
}
EXPORT_SYMBOL(xmp_release_pages);

static int xmp_initialize_pdomain(uint16_t altp2m_id, siphash_key_t *key)
{
	int ret;
	xenmem_access_t p_access;

	p_access = XENMEM_access_r;

	if (altp2m_id == XMP_RESTRICTED_PDOMAIN) {

		/*
		 * If an altp2m view does not use a secret key, then we mark
		 * the page as non-readable, which will lead to crashes when
		 * trying to sign pointers for this pdomain.
		 */
		p_access = XENMEM_access_n;
	} else
		get_random_bytes(key, sizeof(*key));

	/*
	 * Isolate the page containing the domain-specific key in the given
	 * pdomain. If this is successful, the key can only be read from in
	 * the view the key was generated for.
	 */
	ret = xmp_isolate_addr(altp2m_id, key, 1, XENMEM_access_n, p_access);
	if (ret)
		return -EFAULT;

	/*
	 * Remap the GFN of the new key page to the general GFN in which all
	 * keys are accessible from their own pdomain.
	 */
	return altp2m_change_gfn(altp2m_id, virt_to_pfn(xmp_key), virt_to_pfn(key));
}

uint16_t xmp_alloc_pdomain(void)
{
	uint16_t altp2m_id;
	siphash_key_t *key;

	altp2m_id = xmp_create_pdomain();
	if (altp2m_id == XMP_MAX_PDOMAINS)
		return altp2m_id;

	key = (void *)get_zeroed_page(GFP_KERNEL);
	if (!key)
		goto xmp_alloc_destroy_pdomain;

	if (xmp_initialize_pdomain(altp2m_id, key))
		goto xmp_alloc_free_key;

	xmp_pr_info("Created pdomain %u", altp2m_id);

	return altp2m_id;

xmp_alloc_free_key:
	free_page((unsigned long)key);

xmp_alloc_destroy_pdomain:
	xmp_destroy_pdomain(altp2m_id);

	return XMP_MAX_PDOMAINS;
}
EXPORT_SYMBOL(xmp_alloc_pdomain);

void xmp_free_pdomain(uint16_t altp2m_id)
{
	if (!xmp_destroy_pdomain(altp2m_id))
		return;

	altp2m_destroy_view(altp2m_id);
}
EXPORT_SYMBOL(xmp_free_pdomain);

/*
 * Initialization
 */

static uint16_t __init xmp_early_alloc_pdomain(void)
{
	uint16_t altp2m_id;
	siphash_key_t *key;

	altp2m_id = xmp_create_pdomain();
	if (altp2m_id == XMP_MAX_PDOMAINS)
		return altp2m_id;

	key = memblock_virt_alloc_node(PAGE_SIZE, NUMA_NO_NODE);
	if (!key)
		goto xmp_early_alloc_destroy_pdomain;

	if (xmp_initialize_pdomain(altp2m_id, key))
		goto xmp_early_alloc_free_key;

	xmp_pr_info("Created early pdomain %u", altp2m_id);

	return altp2m_id;

xmp_early_alloc_free_key:
	memblock_free_early(__pa(key), PAGE_SIZE);

xmp_early_alloc_destroy_pdomain:
	xmp_destroy_pdomain(altp2m_id);

	return XMP_INVALID_PDOMAIN;
}

static void __init xmp_set_vcpu_enable_notify(struct xmp_vcpu *vcpu)
{
        xen_pfn_t gfn = virt_to_pfn(vcpu->vea);

        if (altp2m_set_vcpu_enable_notify(vcpu->nr, gfn)) {
                xmp_pr_info("Failed to set VEA on vCPU %d", vcpu->nr);
                return;
        }

        vcpu->status = XMP_VCPU_STATUS_UP;

        if (xmp_vmfunc(XMP_RESTRICTED_PDOMAIN))
                xmp_pr_info("Failed to run VMFUNC on vCPU %d", vcpu->nr);
        else
                xmp_pr_info("Enabled VMFUNC on vCPU %d (%d/%u)",
                            vcpu->nr, vcpu->nr + 1, num_possible_cpus());
}

static void __init xmp_init_vcpu(void *info)
{
        struct xmp_vcpu *vcpu = xmp_current_vcpu();

        /*
         * The first vCPU has already been initialized at this
         * point. Initialize the other vCPUs here.
         */

        if (vcpu->status == XMP_VCPU_STATUS_UP)
                return;

        xmp_set_vcpu_enable_notify(vcpu);
}

static int __init xmp_init_vcpus(void)
{
        return on_each_cpu(xmp_init_vcpu, NULL, 1);
}

static int __init xmp_alloc_vcpu_vea(void)
{
        unsigned int cpu;
        struct xmp_vcpu *vcpu;

        for_each_possible_cpu(cpu) {
                vcpu = xmp_vcpu_ptr(cpu);

                vcpu->vea = memblock_virt_alloc_node(PAGE_SIZE, cpu_to_node(cpu));
                if (!vcpu->vea)
                        return -ENOMEM;

                vcpu->status = XMP_VCPU_STATUS_DOWN;
                vcpu->nr = cpu;
        }

        return 0;
}

static int __init xmp_alloc_vcpus(void)
{
        unsigned int cpus, size;

        cpus = num_possible_cpus();
        size = sizeof(struct xmp_vcpu) * cpus;

        xmp_vcpu_info.vcpus = memblock_virt_alloc_node(size, NUMA_NO_NODE);
        if (!xmp_vcpu_info.vcpus)
                return -ENOMEM;

        xmp_vcpu_info.num_vcpus = cpus;

        return xmp_alloc_vcpu_vea();
}

static int __init xmp_init_pdomains(void)
{
	uint16_t altp2m_id = 0;

	memset(xmp_pdomain_bitmap, 0, sizeof(xmp_pdomain_bitmap));
	bitmap_set(xmp_pdomain_bitmap, XMP_PRIVILEGED_PDOMAIN, 1);

        if (altp2m_set_domain_state(true)) {
                xmp_pr_info("Failed to set altp2m state");
                return -EFAULT;
        }

	while (altp2m_id < (XMP_MAX_PDOMAINS - 1)) {
		if (altp2m_create_view(XENMEM_access_default, &altp2m_id))
			return -EFAULT;

		xmp_pr_info("Created view %u", altp2m_id);
	}

	/*
	 * Alocate a random page which is going to be the base page used for
	 * the GFN remapping mechanism.
	 */
	xmp_key = memblock_virt_alloc_node(PAGE_SIZE, NUMA_NO_NODE);
	if (!xmp_key)
		return -EFAULT;

	/*
	 * Allocate the first xMP protection domain for the restricted (a.k.a.
	 * acummulated restrictions) view. This is the view the kernel usually
	 * resides in.
	 */
	altp2m_id = xmp_early_alloc_pdomain();
	if (altp2m_id != XMP_RESTRICTED_PDOMAIN)
		return -EFAULT;

#ifdef CONFIG_XMP_PT

	/*
	 * Allocate restricted view for page tables (XMP_RESTRICTED_PDOMAIN_PT)
	 * This view is designed for isolating page tables.
	 */
	altp2m_id = xmp_early_alloc_pdomain();
	if (altp2m_id != XMP_RESTRICTED_PDOMAIN_PT)
		return -EFAULT;
#endif

        return 0;
}

int __init xmp_init_late(void)
{
	/*
	 * Initialize all other vCPUs. The first vCPU has already been set up
	 * in the xmp_init function.
	 */
	xmp_init_vcpus();

	return 0;
}

int __init xmp_init(void)
{
	if (xmp_init_pdomains())
		return -EFAULT;

	if (xmp_alloc_vcpus())
		return -EFAULT;

	/*
	 * To protect as many structures as early as possible, we initialize
	 * the first vCPU now so that we can isolate them in the early stage
	 * already.
	 */
	xmp_init_vcpu(NULL);

	return 0;
}
