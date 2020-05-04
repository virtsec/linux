#ifndef __XEN_PUBLIC_ALTP2M_H__
#define __XEN_PUBLIC_ALTP2M_H__

#include <xen/interface/xen.h>

#define XEN_ALTP2M_MAX_VIEWS    10
#define XEN_ALTP2M_DEFAULT_VIEW  0

typedef enum {
        XENMEM_access_n,
        XENMEM_access_r,
        XENMEM_access_w,
        XENMEM_access_rw,
        XENMEM_access_x,
        XENMEM_access_rx,
        XENMEM_access_wx,
        XENMEM_access_rwx,
        /*
         * Page starts off as r-x, but automatically
         * change to r-w on a write
         */
        XENMEM_access_rx2rw,
        /*
         * Log access: starts off as n, automatically
         * goes to rwx, generating an event without
         * pausing the vcpu
         */
        XENMEM_access_n2rwx,
        /* Take the domain default */
        XENMEM_access_default
} xenmem_access_t;

int altp2m_get_domain_state(bool *state);
int altp2m_set_domain_state(bool state);
int altp2m_set_vcpu_enable_notify(uint32_t vcpuid, xen_pfn_t gfn);
int altp2m_create_view(xenmem_access_t default_access, uint16_t *view_id);
int altp2m_destroy_view(uint16_t view_id);
int altp2m_switch_to_view(uint16_t view_id);
int altp2m_get_suppress_ve(uint16_t view_id, xen_pfn_t gfn, bool *sve);
int altp2m_set_suppress_ve(uint16_t view_id, xen_pfn_t gfn, bool sve);
int altp2m_set_mem_access(uint16_t view_id, xen_pfn_t gfn, xenmem_access_t access);
int altp2m_change_gfn(uint16_t view_id, xen_pfn_t old_gfn, xen_pfn_t new_gfn);
int altp2m_get_mem_access(uint16_t view_id, xen_pfn_t gfn, xenmem_access_t *access);
int altp2m_get_vcpu_p2m_idx(uint32_t vcpuid, uint16_t *altp2m_idx);
int altp2m_isolate_pdomain(uint16_t altp2m_id, xen_pfn_t gfn,
        xenmem_access_t restr_access, xenmem_access_t priv_access,
	bool suppress_ve);

#endif /* __XEN_PUBLIC_ALTP2M_H__ */
