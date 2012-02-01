
extern const struct fw_address_region sbp_register_region;

static inline u64 sbp2_pointer_to_addr(const struct sbp2_pointer *ptr)
{
	return (u64)(be32_to_cpu(ptr->high) & 0x0000ffff) << 32 |
		(be32_to_cpu(ptr->low) & 0xfffffffc);
}

static inline void addr_to_sbp2_pointer(u64 addr, struct sbp2_pointer *ptr)
{
	ptr->high = cpu_to_be32(addr >> 32);
	ptr->low = cpu_to_be32(addr);
}

