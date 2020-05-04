#include <linux/types.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/kallsyms.h>

#include <xen/hvm.h>
#include <xen/interface/xen.h>
#include <xen/interface/hvm/hvm_op.h>
#include <xen/interface/altp2m.h>

#include <asm/xen/interface.h>

int altp2m_get_domain_state(bool *state)
{
        int rc;
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_get_domain_state;
        arg.domain = DOMID_SELF;

        rc = HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);

        if ( !rc )
                *state = arg.u.domain_state.state;

        return rc;
}

int altp2m_set_domain_state(bool state)
{
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_set_domain_state;
        arg.domain = DOMID_SELF;
        arg.u.domain_state.state = state;

        return HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);
}

int altp2m_set_vcpu_enable_notify(uint32_t vcpuid, xen_pfn_t gfn)
{
	int rc;
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_vcpu_enable_notify;
        arg.domain = DOMID_SELF;
        arg.u.enable_notify.vcpu_id = vcpuid;
        arg.u.enable_notify.gfn = gfn;

        rc = HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);

	return rc;
}

int altp2m_create_view(xenmem_access_t default_access, uint16_t *view_id)
{
        int rc;
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_create_p2m;
        arg.domain = DOMID_SELF;
        arg.u.view.view = -1;
        arg.u.view.hvmmem_default_access = default_access;

        rc = HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);

        if ( !rc )
                *view_id = arg.u.view.view;

        return rc;
}

int altp2m_destroy_view(uint16_t view_id)
{
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_destroy_p2m;
        arg.domain = DOMID_SELF;
        arg.u.view.view = view_id;

        return HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);
}

/* Switch all vCPUs of the domain to the specified altp2m view */
int altp2m_switch_to_view(uint16_t view_id)
{
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_switch_p2m;
        arg.domain = DOMID_SELF;
        arg.u.view.view = view_id;

        return HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);
}

int altp2m_get_suppress_ve(uint16_t view_id, xen_pfn_t gfn, bool *sve)
{
        int rc;
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_get_suppress_ve;
        arg.domain = DOMID_SELF;
        arg.u.suppress_ve.view = view_id;
        arg.u.suppress_ve.gfn = gfn;

        rc = HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);

        if ( !rc )
                *sve = arg.u.suppress_ve.suppress_ve;

        return rc;
}

int altp2m_set_suppress_ve(uint16_t view_id, xen_pfn_t gfn, bool sve)
{
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_set_suppress_ve;
        arg.domain = DOMID_SELF;
        arg.u.suppress_ve.view = view_id;
        arg.u.suppress_ve.gfn = gfn;
        arg.u.suppress_ve.suppress_ve = sve;

        return HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);
}
EXPORT_SYMBOL(altp2m_set_suppress_ve);

int altp2m_set_mem_access(uint16_t view_id,
                xen_pfn_t gfn, xenmem_access_t access)
{
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_set_mem_access;
        arg.domain = DOMID_SELF;
        arg.u.mem_access.view = view_id;
        arg.u.mem_access.access = access;
        arg.u.mem_access.gfn = gfn;

        return HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);
}
EXPORT_SYMBOL(altp2m_set_mem_access);

int altp2m_change_gfn(uint16_t view_id, xen_pfn_t old_gfn, xen_pfn_t new_gfn)
{
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_change_gfn;
        arg.domain = DOMID_SELF;
        arg.u.change_gfn.view = view_id;
        arg.u.change_gfn.old_gfn = old_gfn;
        arg.u.change_gfn.new_gfn = new_gfn;

        return HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);
}

int altp2m_get_mem_access(uint16_t view_id, xen_pfn_t gfn, xenmem_access_t *access)
{
        int rc;
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_get_mem_access;
        arg.domain = DOMID_SELF;
        arg.u.mem_access.view = view_id;
        arg.u.mem_access.gfn = gfn;

        rc = HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);

        if ( !rc )
                *access = arg.u.mem_access.access;

        return rc;
}

int altp2m_get_vcpu_p2m_idx(uint32_t vcpuid, uint16_t *altp2m_idx)
{
        int rc;
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_get_p2m_idx;
        arg.domain = DOMID_SELF;
        arg.u.get_vcpu_p2m_idx.vcpu_id = vcpuid;

        rc = HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);

        if ( !rc )
                *altp2m_idx = arg.u.get_vcpu_p2m_idx.altp2m_idx;

        return rc;
}

int altp2m_isolate_pdomain(uint16_t altp2m_id, xen_pfn_t gfn,
        xenmem_access_t restr_access, xenmem_access_t priv_access,
	bool suppress_ve)
{
        xen_hvm_altp2m_op_t arg = { 0 };

        arg.version = HVMOP_ALTP2M_INTERFACE_VERSION;
        arg.cmd = HVMOP_altp2m_isolate_pdomain;
        arg.domain = DOMID_SELF;
        arg.u.isolate_pdomain.view = altp2m_id;
        arg.u.isolate_pdomain.restr_access = restr_access;
        arg.u.isolate_pdomain.priv_access = priv_access;
        arg.u.isolate_pdomain.gfn = gfn;
	arg.u.isolate_pdomain.suppress_ve = suppress_ve;

        return HYPERVISOR_hvm_op(HVMOP_altp2m, &arg);
}
