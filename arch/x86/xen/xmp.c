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
 * Each view is assigned axMP siphash key which is only visible to the specific
 * view it was allocated for. Thus, we need a page for each key to reside in.
 */
static siphash_key_t *xmp_keys[XMP_MAX_PDOMAINS] = { 0 };

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

        /*
         * This branch prediction only misses during the early stage
         * when VMFUNC has not been enabled on the current vCPU.
         */

        if (unlikely(vcpu->status != XMP_VCPU_STATUS_UP))
                return 0;

        return __xmp_vmfunc(pdomain);
}
EXPORT_SYMBOL(xmp_vmfunc);

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

static int __xmp_isolate_pages(uint16_t altp2m_id, struct page *page,
	unsigned int num_pages, xenmem_access_t r_access,
	xenmem_access_t p_access, bool release)
{
	int ret;
	unsigned int i, j;
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
		if (release && pgp->flags & (1UL << PG_xmp))
			__clear_bit(PG_xmp, &pgp->flags);
		else {
			xmp_pr_info("Trying to release a non-isolated page, skip...");
			continue;
		}

		/*
		 * When isolating a page, we only check whether the PG_xmp bit
		 * is cleared and if it is, we set it.
		 *
		 * If it is set, then the page is already isolated and the call
		 * is simply to alter the permissions for this page.
		 */
		if (!release && !(pgp->flags & (1UL << PG_xmp)))
			__set_bit(PG_xmp, &pgp->flags);

		ret = altp2m_isolate_pdomain(altp2m_id, gfn, r_access, p_access);
		if (ret)
			return -EFAULT;

		/*
		 * TODO CRO: Incorporate this in the actual Xen hypercall
		 *
		 * This should happen in Xen. To deal with the suppress_ve bit
		 * issue, which is set for newer Xen versions, we also have to
		 * pass an additional parameter  to the altp2m_isolate_pdomain
		 * function which states whether the suppress_ve bit should be
		 * set or cleared.
		 *
		 * On isolations, the bit should be cleared to trigger the #VE
		 * for this page. Upon releasing, we set the bit again.
		 */
		for (j = 1; j < (XMP_MAX_PDOMAINS - 1); j++) {
			ret = altp2m_set_suppress_ve(altp2m_id, gfn, false);
			if (ret)
				return -EFAULT;
		}
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

static int xmp_initialize_pdomain(uint16_t altp2m_id)
{
	get_random_bytes(xmp_keys[altp2m_id], sizeof(siphash_key_t));

	/*
	 * Isolate the page containing the domain-specific key in the given
	 * pdomain. If this is successful, the key can only be read from in
	 * the view the key was generated for.
	 */
	return xmp_isolate_addr(altp2m_id, xmp_keys[altp2m_id], 1,
		XENMEM_access_n, XENMEM_access_r);
}

uint16_t xmp_alloc_pdomain(void)
{
	uint16_t altp2m_id;

	altp2m_id = xmp_create_pdomain();
	if (altp2m_id == XMP_MAX_PDOMAINS)
		return altp2m_id;

	xmp_keys[altp2m_id] = (void *)get_zeroed_page(GFP_KERNEL);
	if (!xmp_keys[altp2m_id])
		goto xmp_alloc_destroy_pdomain;

	if (xmp_initialize_pdomain(altp2m_id))
		goto xmp_alloc_free_key;

	xmp_pr_info("Created pdomain %u", altp2m_id);

	return altp2m_id;

xmp_alloc_free_key:
	free_page((unsigned long)xmp_keys[altp2m_id]);

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

	altp2m_id = xmp_create_pdomain();
	if (altp2m_id == XMP_MAX_PDOMAINS)
		return altp2m_id;

	xmp_keys[altp2m_id] = memblock_virt_alloc_node(PAGE_SIZE, NUMA_NO_NODE);
	if (!xmp_keys[altp2m_id])
		goto xmp_early_alloc_destroy_pdomain;

	if (xmp_initialize_pdomain(altp2m_id))
		goto xmp_early_alloc_free_key;

	xmp_pr_info("Created early pdomain %u", altp2m_id);

	return altp2m_id;

xmp_early_alloc_free_key:
	memblock_free_early(__pa(xmp_keys[altp2m_id]), PAGE_SIZE);

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
	 * Allocate the first xMP protection domain for the restricted (a.k.a.
	 * acummulated restrictions) view. This is the view the kernel usually
	 * resides in.
	 */
	xmp_early_alloc_pdomain();

	/*
	 * Allocate restricted view for page tables (XMP_RESTRICTED_PDOMAIN_PT)
	 * This view is designed for isolating page tables.
	 */
	xmp_early_alloc_pdomain();

        return 0;
}

int __init xmp_init_late(void)
{
	/*
	 * Initialize all other vCPUs. The first vCPU has already been set up
	 * in the xmp_init function.
	 */
	xmp_init_vcpus();

	alloc_pages(XMP_GFP_FLAGS(XMP_RESTRICTED_PDOMAIN_PT, GFP_KERNEL), 2);

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
