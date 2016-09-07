/*
 * xen/arch/arm/vgic-v3-its.c
 *
 * ARM Interrupt Translation Service (ITS) emulation
 *
 * Andre Przywara <andre.przywara@arm.com>
 * Copyright (c) 2016,2017 ARM Ltd.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; under version 2 of the License.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; If not, see <http://www.gnu.org/licenses/>.
 */

#include <xen/bitops.h>
#include <xen/config.h>
#include <xen/domain_page.h>
#include <xen/lib.h>
#include <xen/init.h>
#include <xen/softirq.h>
#include <xen/irq.h>
#include <xen/sched.h>
#include <xen/sizes.h>
#include <asm/current.h>
#include <asm/mmio.h>
#include <asm/gic_v3_defs.h>
#include <asm/gic_v3_its.h>
#include <asm/vgic.h>
#include <asm/vgic-emul.h>

/*
 * Data structure to describe a virtual ITS.
 * If both the vcmd_lock and the its_lock are required, the vcmd_lock must
 * be taken first.
 */
struct virt_its {
    struct domain *d;
    unsigned int devid_bits;
    unsigned int intid_bits;
    spinlock_t vcmd_lock;       /* Protects the virtual command buffer, which */
    uint64_t cwriter;           /* consists of CBASER and CWRITER and those   */
    uint64_t creadr;            /* shadow variables cwriter and creadr. */
    /* Protects the rest of this structure, including the ITS tables. */
    spinlock_t its_lock;
    uint64_t cbaser;
    uint64_t baser_dev, baser_coll;     /* BASER0 and BASER1 for the guest */
    unsigned int max_collections;
    unsigned int max_devices;
    bool enabled;
};

/*
 * An Interrupt Translation Table Entry: this is indexed by a
 * DeviceID/EventID pair and is located in guest memory.
 */
struct vits_itte
{
    uint32_t vlpi;
    uint16_t collection;
    uint16_t pad;
};

#define UNMAPPED_COLLECTION      ((uint16_t)~0)

void vgic_v3_its_init_domain(struct domain *d)
{
    spin_lock_init(&d->arch.vgic.its_devices_lock);
    d->arch.vgic.its_devices = RB_ROOT;
}

void vgic_v3_its_free_domain(struct domain *d)
{
    ASSERT(RB_EMPTY_ROOT(&d->arch.vgic.its_devices));
}

/*
 * The physical address is encoded slightly differently depending on
 * the used page size: the highest four bits are stored in the lowest
 * four bits of the field for 64K pages.
 */
static paddr_t get_baser_phys_addr(uint64_t reg)
{
    if ( reg & BIT(9) )
        return (reg & GENMASK_ULL(47, 16)) |
                ((reg & GENMASK_ULL(15, 12)) << 36);
    else
        return reg & GENMASK_ULL(47, 12);
}

/* Must be called with the ITS lock held. */
static int its_set_collection(struct virt_its *its, uint16_t collid,
                              uint16_t vcpu_id)
{
    paddr_t addr = get_baser_phys_addr(its->baser_coll);

    ASSERT(spin_is_locked(&its->its_lock));

    if ( collid >= its->max_collections )
        return -ENOENT;

    return vgic_access_guest_memory(its->d, addr + collid * sizeof(uint16_t),
                                    &vcpu_id, sizeof(vcpu_id), true);
}

/* Must be called with the ITS lock held. */
static struct vcpu *get_vcpu_from_collection(struct virt_its *its,
                                             uint16_t collid)
{
    paddr_t addr = get_baser_phys_addr(its->baser_coll);
    uint16_t vcpu_id;
    int ret;

    ASSERT(spin_is_locked(&its->its_lock));

    if ( collid >= its->max_collections )
        return NULL;

    ret = vgic_access_guest_memory(its->d, addr + collid * sizeof(uint16_t),
                                   &vcpu_id, sizeof(vcpu_id), false);
    if ( ret )
        return NULL;

    if ( vcpu_id == UNMAPPED_COLLECTION || vcpu_id >= its->d->max_vcpus )
        return NULL;

    return its->d->vcpu[vcpu_id];
}

/*
 * Our device table encodings:
 * Contains the guest physical address of the Interrupt Translation Table in
 * bits [51:8], and the size of it is encoded as the number of bits minus one
 * in the lowest 8 bits of the word.
 */
#define DEV_TABLE_ITT_ADDR(x) ((x) & GENMASK_ULL(51, 8))
#define DEV_TABLE_ITT_SIZE(x) (BIT(((x) & GENMASK_ULL(7, 0)) + 1))
#define DEV_TABLE_ENTRY(addr, bits)                     \
        (((addr) & GENMASK_ULL(51, 8)) | (((bits) - 1) & GENMASK_ULL(7, 0)))

/*
 * Lookup the address of the Interrupt Translation Table associated with
 * a device ID and return the address of the ITTE belonging to the event ID
 * (which is an index into that table).
 */
static paddr_t its_get_itte_address(struct virt_its *its,
                                    uint32_t devid, uint32_t evid)
{
    paddr_t addr = get_baser_phys_addr(its->baser_dev);
    uint64_t itt;

    if ( devid >= its->max_devices )
        return INVALID_PADDR;

    if ( vgic_access_guest_memory(its->d, addr + devid * sizeof(uint64_t),
                                  &itt, sizeof(itt), false) )
        return INVALID_PADDR;

    if ( evid >= DEV_TABLE_ITT_SIZE(itt) ||
         DEV_TABLE_ITT_ADDR(itt) == INVALID_PADDR )
        return INVALID_PADDR;

    return DEV_TABLE_ITT_ADDR(itt) + evid * sizeof(struct vits_itte);
}

/*
 * Queries the collection and device tables to get the vCPU and virtual
 * LPI number for a given guest event. This first accesses the guest memory
 * to resolve the address of the ITTE, then reads the ITTE entry at this
 * address and puts the result in vcpu_ptr and vlpi_ptr.
 * Requires the ITS lock to be held.
 */
static bool read_itte_locked(struct virt_its *its, uint32_t devid,
                             uint32_t evid, struct vcpu **vcpu_ptr,
                             uint32_t *vlpi_ptr)
{
    paddr_t addr;
    struct vits_itte itte;
    struct vcpu *vcpu;

    ASSERT(spin_is_locked(&its->its_lock));

    addr = its_get_itte_address(its, devid, evid);
    if ( addr == INVALID_PADDR )
        return false;

    if ( vgic_access_guest_memory(its->d, addr, &itte, sizeof(itte), false) )
        return false;

    vcpu = get_vcpu_from_collection(its, itte.collection);
    if ( !vcpu )
        return false;

    *vcpu_ptr = vcpu;
    *vlpi_ptr = itte.vlpi;
    return true;
}

/*
 * This function takes care of the locking by taking the its_lock itself, so
 * a caller shall not hold this. Before returning, the lock is dropped again.
 */
static bool read_itte(struct virt_its *its, uint32_t devid, uint32_t evid,
                      struct vcpu **vcpu_ptr, uint32_t *vlpi_ptr)
{
    bool ret;

    spin_lock(&its->its_lock);
    ret = read_itte_locked(its, devid, evid, vcpu_ptr, vlpi_ptr);
    spin_unlock(&its->its_lock);

    return ret;
}

/*
 * Queries the collection and device tables to translate the device ID and
 * event ID and find the appropriate ITTE. The given collection ID and the
 * virtual LPI number are then stored into that entry.
 * If vcpu_ptr is provided, returns the VCPU belonging to that collection.
 * Requires the ITS lock to be held.
 */
static bool write_itte_locked(struct virt_its *its, uint32_t devid,
                              uint32_t evid, uint32_t collid, uint32_t vlpi,
                              struct vcpu **vcpu_ptr)
{
    paddr_t addr;
    struct vits_itte itte;

    ASSERT(spin_is_locked(&its->its_lock));

    if ( collid >= its->max_collections )
        return false;

    if ( vlpi >= its->d->arch.vgic.nr_lpis )
        return false;

    addr = its_get_itte_address(its, devid, evid);
    if ( addr == INVALID_PADDR )
        return false;

    itte.collection = collid;
    itte.vlpi = vlpi;

    if ( vgic_access_guest_memory(its->d, addr, &itte, sizeof(itte), true) )
        return false;

    if ( vcpu_ptr )
        *vcpu_ptr = get_vcpu_from_collection(its, collid);

    return true;
}

/*
 * This function takes care of the locking by taking the its_lock itself, so
 * a caller shall not hold this. Before returning, the lock is dropped again.
 */
bool write_itte(struct virt_its *its, uint32_t devid, uint32_t evid,
                uint32_t collid, uint32_t vlpi, struct vcpu **vcpu_ptr)
{
    bool ret;

    spin_lock(&its->its_lock);
    ret = write_itte_locked(its, devid, evid, collid, vlpi, vcpu_ptr);
    spin_unlock(&its->its_lock);

    return ret;
}

/**************************************
 * Functions that handle ITS commands *
 **************************************/

static uint64_t its_cmd_mask_field(uint64_t *its_cmd, unsigned int word,
                                   unsigned int shift, unsigned int size)
{
    return (le64_to_cpu(its_cmd[word]) >> shift) & (BIT(size) - 1);
}

#define its_cmd_get_command(cmd)        its_cmd_mask_field(cmd, 0,  0,  8)
#define its_cmd_get_deviceid(cmd)       its_cmd_mask_field(cmd, 0, 32, 32)
#define its_cmd_get_size(cmd)           its_cmd_mask_field(cmd, 1,  0,  5)
#define its_cmd_get_id(cmd)             its_cmd_mask_field(cmd, 1,  0, 32)
#define its_cmd_get_physical_id(cmd)    its_cmd_mask_field(cmd, 1, 32, 32)
#define its_cmd_get_collection(cmd)     its_cmd_mask_field(cmd, 2,  0, 16)
#define its_cmd_get_target_addr(cmd)    its_cmd_mask_field(cmd, 2, 16, 32)
#define its_cmd_get_validbit(cmd)       its_cmd_mask_field(cmd, 2, 63,  1)
#define its_cmd_get_ittaddr(cmd)        (its_cmd_mask_field(cmd, 2, 8, 44) << 8)

/*
 * CLEAR removes the pending state from an LPI. */
static int its_handle_clear(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct pending_irq *p;
    struct vcpu *vcpu;
    uint32_t vlpi;
    unsigned long flags;

    /* Translate the DevID/EvID pair into a vCPU/vLPI pair. */
    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        return -1;

    p = its->d->arch.vgic.handler->lpi_to_pending(its->d, vlpi);
    if ( !p )
        return -1;

    spin_lock_irqsave(&vcpu->arch.vgic.lock, flags);

    /* We store the pending bit for LPIs in our struct pending_irq. */
    clear_bit(GIC_IRQ_GUEST_LPI_PENDING, &p->status);

    /*
     * If the LPI is already visible on the guest, it is too late to
     * clear the pending state. However this is a benign race that can
     * happen on real hardware, too: If the LPI has already been forwarded
     * to a CPU interface, a CLEAR request reaching the redistributor has
     * no effect on that LPI anymore. Since LPIs are edge triggered and
     * have no active state, we don't need to care about this here.
     */
    if ( !test_bit(GIC_IRQ_GUEST_VISIBLE, &p->status) )
    {
        /* Remove a pending, but not yet injected guest IRQ. */
        clear_bit(GIC_IRQ_GUEST_QUEUED, &p->status);
        gic_remove_from_queues(vcpu, vlpi);
    }

    return 0;
}

static int its_handle_int(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t devid = its_cmd_get_deviceid(cmdptr);
    uint32_t eventid = its_cmd_get_id(cmdptr);
    struct pending_irq *p;
    struct vcpu *vcpu;
    uint32_t vlpi;

    if ( !read_itte(its, devid, eventid, &vcpu, &vlpi) )
        return -1;

    p = its->d->arch.vgic.handler->lpi_to_pending(its->d, vlpi);
    if ( !p )
        return -1;

    /*
     * If the LPI is enabled, inject it.
     * If not, store the pending state to inject it once it gets enabled later.
     */
    if ( test_bit(GIC_IRQ_GUEST_ENABLED, &p->status) )
        vgic_vcpu_inject_irq(vcpu, vlpi);
    else
        set_bit(GIC_IRQ_GUEST_LPI_PENDING, &p->status);

    return 0;
}

static int its_handle_mapc(struct virt_its *its, uint64_t *cmdptr)
{
    uint32_t collid = its_cmd_get_collection(cmdptr);
    uint64_t rdbase = its_cmd_mask_field(cmdptr, 2, 16, 44);

    if ( collid >= its->max_collections )
        return -1;

    if ( rdbase >= its->d->max_vcpus )
        return -1;

    spin_lock(&its->its_lock);

    if ( its_cmd_get_validbit(cmdptr) )
        its_set_collection(its, collid, rdbase);
    else
        its_set_collection(its, collid, UNMAPPED_COLLECTION);

    spin_unlock(&its->its_lock);

    return 0;
}

#define ITS_CMD_BUFFER_SIZE(baser)      ((((baser) & 0xff) + 1) << 12)

/*
 * Requires the vcmd_lock to be held.
 * TODO: Investigate whether we can be smarter here and don't need to hold
 * the lock all of the time.
 */
static int vgic_its_handle_cmds(struct domain *d, struct virt_its *its)
{
    paddr_t addr = its->cbaser & GENMASK_ULL(51, 12);
    uint64_t command[4];

    ASSERT(spin_is_locked(&its->vcmd_lock));

    if ( its->cwriter >= ITS_CMD_BUFFER_SIZE(its->cbaser) )
        return -1;

    while ( its->creadr != its->cwriter )
    {
        int ret;

        ret = vgic_access_guest_memory(d, addr + its->creadr,
                                       command, sizeof(command), false);
        if ( ret )
            return ret;

        switch ( its_cmd_get_command(command) )
        {
        case GITS_CMD_CLEAR:
            ret = its_handle_clear(its, command);
            break;
        case GITS_CMD_INT:
            ret = its_handle_int(its, command);
            break;
        case GITS_CMD_MAPC:
            ret = its_handle_mapc(its, command);
            break;
        case GITS_CMD_SYNC:
            /* We handle ITS commands synchronously, so we ignore SYNC. */
            break;
        default:
            gdprintk(XENLOG_WARNING, "ITS: unhandled ITS command %lu\n",
                     its_cmd_get_command(command));
            break;
        }

        its->creadr += ITS_CMD_SIZE;
        if ( its->creadr == ITS_CMD_BUFFER_SIZE(its->cbaser) )
            its->creadr = 0;

        if ( ret )
            gdprintk(XENLOG_WARNING,
                     "ITS: ITS command error %d while handling command %lu\n",
                     ret, its_cmd_get_command(command));
    }

    return 0;
}

/*****************************
 * ITS registers read access *
 *****************************/

static int vgic_v3_its_mmio_read(struct vcpu *v, mmio_info_t *info,
                                 register_t *r, void *priv)
{
    struct virt_its *its = priv;
    uint64_t reg;

    switch ( info->gpa & 0xffff )
    {
    case VREG32(GITS_CTLR):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;

        spin_lock(&its->vcmd_lock);
        spin_lock(&its->its_lock);
        if ( its->enabled )
            reg = GITS_CTLR_ENABLE;
        else
            reg = 0;

        if ( its->cwriter == its->creadr )
            reg |= GITS_CTLR_QUIESCENT;
        spin_unlock(&its->its_lock);
        spin_unlock(&its->vcmd_lock);

        *r = vgic_reg32_extract(reg, info);
        break;
    case VREG32(GITS_IIDR):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GITS_IIDR_VALUE, info);
        break;
    case VREG64(GITS_TYPER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        reg = GITS_TYPER_PHYSICAL;
        reg |= (sizeof(struct vits_itte) - 1) << GITS_TYPER_ITT_SIZE_SHIFT;
        reg |= (its->intid_bits - 1) << GITS_TYPER_IDBITS_SHIFT;
        reg |= (its->devid_bits - 1) << GITS_TYPER_DEVIDS_SHIFT;
        *r = vgic_reg64_extract(reg, info);
        break;
    case VREG64(GITS_CBASER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->its_lock);
        *r = vgic_reg64_extract(its->cbaser, info);
        spin_unlock(&its->its_lock);
        break;
    case VREG64(GITS_CWRITER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->vcmd_lock);
        *r = vgic_reg64_extract(its->cwriter, info);
        spin_unlock(&its->vcmd_lock);
        break;
    case VREG64(GITS_CREADR):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->vcmd_lock);
        *r = vgic_reg64_extract(its->creadr, info);
        spin_unlock(&its->vcmd_lock);
        break;
    case VREG64(GITS_BASER0):           /* device table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->its_lock);
        *r = vgic_reg64_extract(its->baser_dev, info);
        spin_unlock(&its->its_lock);
        break;
    case VREG64(GITS_BASER1):           /* collection table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        spin_lock(&its->its_lock);
        *r = vgic_reg64_extract(its->baser_coll, info);
        spin_unlock(&its->its_lock);
        break;
    case VRANGE64(GITS_BASER2, GITS_BASER7):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
        *r = vgic_reg64_extract(0, info);
        break;
    case VREG32(GITS_PIDR2):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;
        *r = vgic_reg32_extract(GIC_PIDR2_ARCH_GICv3, info);
        break;
    }

    return 1;

bad_width:
    printk(XENLOG_G_ERR "vGIIS: bad read width %d r%d offset %#08lx\n",
           info->dabt.size, info->dabt.reg, (unsigned long)info->gpa & 0xffff);
    domain_crash_synchronous();

    return 0;
}

/******************************
 * ITS registers write access *
 ******************************/

static unsigned int its_baser_table_size(uint64_t baser)
{
    unsigned int ret, page_size[4] = {SZ_4K, SZ_16K, SZ_64K, SZ_64K};

    ret = page_size[(baser >> GITS_BASER_PAGE_SIZE_SHIFT) & 3];

    return ret * ((baser & GITS_BASER_SIZE_MASK) + 1);
}

static int its_baser_nr_entries(uint64_t baser)
{
    int entry_size = GITS_BASER_ENTRY_SIZE(baser);

    return its_baser_table_size(baser) / entry_size;
}

/* Must be called with the ITS lock held. */
static bool vgic_v3_verify_its_status(struct virt_its *its, bool status)
{
    ASSERT(spin_is_locked(&its->its_lock));

    if ( !status )
        return false;

    if ( !(its->cbaser & GITS_VALID_BIT) ||
         !(its->baser_dev & GITS_VALID_BIT) ||
         !(its->baser_coll & GITS_VALID_BIT) )
        return false;

    return true;
}

static void sanitize_its_base_reg(uint64_t *reg)
{
    uint64_t r = *reg;

    /* Avoid outer shareable. */
    switch ( (r >> GITS_BASER_SHAREABILITY_SHIFT) & 0x03 )
    {
    case GIC_BASER_OuterShareable:
        r = r & ~GITS_BASER_SHAREABILITY_MASK;
        r |= GIC_BASER_InnerShareable << GITS_BASER_SHAREABILITY_SHIFT;
        break;
    default:
        break;
    }

    /* Avoid any inner non-cacheable mapping. */
    switch ( (r >> GITS_BASER_INNER_CACHEABILITY_SHIFT) & 0x07 )
    {
    case GIC_BASER_CACHE_nCnB:
    case GIC_BASER_CACHE_nC:
        r = r & ~GITS_BASER_INNER_CACHEABILITY_MASK;
        r |= GIC_BASER_CACHE_RaWb << GITS_BASER_INNER_CACHEABILITY_SHIFT;
        break;
    default:
        break;
    }

    /* Only allow non-cacheable or same-as-inner. */
    switch ( (r >> GITS_BASER_OUTER_CACHEABILITY_SHIFT) & 0x07 )
    {
    case GIC_BASER_CACHE_SameAsInner:
    case GIC_BASER_CACHE_nC:
        break;
    default:
        r = r & ~GITS_BASER_OUTER_CACHEABILITY_MASK;
        r |= GIC_BASER_CACHE_nC << GITS_BASER_OUTER_CACHEABILITY_SHIFT;
        break;
    }

    *reg = r;
}

static int vgic_v3_its_mmio_write(struct vcpu *v, mmio_info_t *info,
                                  register_t r, void *priv)
{
    struct domain *d = v->domain;
    struct virt_its *its = priv;
    uint64_t reg;
    uint32_t reg32, ctlr;

    switch ( info->gpa & 0xffff )
    {
    case VREG32(GITS_CTLR):
        if ( info->dabt.size != DABT_WORD ) goto bad_width;

        spin_lock(&its->vcmd_lock);
        spin_lock(&its->its_lock);
        ctlr = its->enabled ? GITS_CTLR_ENABLE : 0;
        reg32 = ctlr;
        vgic_reg32_update(&reg32, r, info);

        if ( ctlr ^ reg32 )
            its->enabled = vgic_v3_verify_its_status(its,
                                                     reg32 & GITS_CTLR_ENABLE);
        spin_unlock(&its->its_lock);
        spin_unlock(&its->vcmd_lock);
        return 1;

    case VREG32(GITS_IIDR):
        goto write_ignore_32;
    case VREG32(GITS_TYPER):
        goto write_ignore_32;
    case VREG64(GITS_CBASER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->vcmd_lock);
        spin_lock(&its->its_lock);
        /* Changing base registers with the ITS enabled is UNPREDICTABLE. */
        if ( its->enabled )
        {
            spin_unlock(&its->its_lock);
            spin_unlock(&its->vcmd_lock);
            gdprintk(XENLOG_WARNING,
                     "ITS: tried to change CBASER with the ITS enabled.\n");
            return 1;
        }

        reg = its->cbaser;
        vgic_reg64_update(&reg, r, info);
        sanitize_its_base_reg(&reg);

        its->cbaser = reg;
        its->creadr = 0;
        spin_unlock(&its->its_lock);
        spin_unlock(&its->vcmd_lock);

        return 1;

    case VREG64(GITS_CWRITER):
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->vcmd_lock);
        reg = its->cwriter & 0xfffe0;
        vgic_reg64_update(&reg, r, info);
        its->cwriter = reg & 0xfffe0;

        if ( its->enabled )
        {
            int ret = vgic_its_handle_cmds(d, its);

            if ( ret )
                printk(XENLOG_G_WARNING "error handling ITS commands\n");
        }
        spin_unlock(&its->vcmd_lock);

        return 1;

    case VREG64(GITS_CREADR):
        goto write_ignore_64;
    case VREG64(GITS_BASER0):           /* device table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->its_lock);

        /*
         * Changing base registers with the ITS enabled is UNPREDICTABLE,
         * we choose to ignore it, but warn.
         */
        if ( its->enabled )
        {
            spin_unlock(&its->its_lock);
            gdprintk(XENLOG_WARNING, "ITS: tried to change BASER with the ITS enabled.\n");

            return 1;
        }

        reg = its->baser_dev;
        vgic_reg64_update(&reg, r, info);

        reg &= ~GITS_BASER_RO_MASK;
        reg |= (sizeof(uint64_t) - 1) << GITS_BASER_ENTRY_SIZE_SHIFT;
        reg |= GITS_BASER_TYPE_DEVICE << GITS_BASER_TYPE_SHIFT;
        sanitize_its_base_reg(&reg);

        if ( reg & GITS_VALID_BIT )
            its->max_devices = its_baser_nr_entries(reg);
        else
            its->max_devices = 0;

        its->baser_dev = reg;
        spin_unlock(&its->its_lock);
        return 1;
    case VREG64(GITS_BASER1):           /* collection table */
        if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;

        spin_lock(&its->its_lock);
        /*
         * Changing base registers with the ITS enabled is UNPREDICTABLE,
         * we choose to ignore it, but warn.
         */
        if ( its->enabled )
        {
            spin_unlock(&its->its_lock);
            gdprintk(XENLOG_INFO, "ITS: tried to change BASER with the ITS enabled.\n");
            return 1;
        }

        reg = its->baser_coll;
        vgic_reg64_update(&reg, r, info);
        reg &= ~GITS_BASER_RO_MASK;
        reg |= (sizeof(uint16_t) - 1) << GITS_BASER_ENTRY_SIZE_SHIFT;
        reg |= GITS_BASER_TYPE_COLLECTION << GITS_BASER_TYPE_SHIFT;
        sanitize_its_base_reg(&reg);

        if ( reg & GITS_VALID_BIT )
            its->max_collections = its_baser_nr_entries(reg);
        else
            its->max_collections = 0;
        its->baser_coll = reg;
        spin_unlock(&its->its_lock);
        return 1;
    case VRANGE64(GITS_BASER2, GITS_BASER7):
        goto write_ignore_64;
    default:
        gdprintk(XENLOG_G_WARNING, "ITS: unhandled ITS register 0x%lx\n",
                 info->gpa & 0xffff);
        return 0;
    }

    return 1;

write_ignore_64:
    if ( !vgic_reg64_check_access(info->dabt) ) goto bad_width;
    return 1;

write_ignore_32:
    if ( info->dabt.size != DABT_WORD ) goto bad_width;
    return 1;

bad_width:
    printk(XENLOG_G_ERR "vGITS: bad write width %d r%d offset %#08lx\n",
           info->dabt.size, info->dabt.reg, (unsigned long)info->gpa & 0xffff);

    domain_crash_synchronous();

    return 0;
}

static const struct mmio_handler_ops vgic_its_mmio_handler = {
    .read  = vgic_v3_its_mmio_read,
    .write = vgic_v3_its_mmio_write,
};

/*
 * Local variables:
 * mode: C
 * c-file-style: "BSD"
 * c-basic-offset: 4
 * indent-tabs-mode: nil
 * End:
 */
