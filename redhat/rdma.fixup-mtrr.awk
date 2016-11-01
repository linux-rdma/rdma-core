# This is a simple script that checks the contents of /proc/mtrr to see if
# the BIOS maker for the computer took the easy way out in terms of
# specifying memory regions when there is a hole below 4GB for PCI access
# and the machine has 4GB or more of RAM.  When the contents of /proc/mtrr
# show a 4GB mapping of write-back cached RAM, minus punch out hole(s) of
# uncacheable regions (the area reserved for PCI access), then it becomes
# impossible for the ib_ipath driver to set write_combining on its PIO
# buffers.  To correct the problem, remap the lower memory region in various
# chunks up to the start of the punch out hole(s), then delete the punch out
# hole(s) entirely as they aren't needed any more.  That way, ib_ipath will
# be able to set write_combining on its PIO memory access region.

BEGIN {
	regs = 0
}

function check_base(mem)
{
	printf "Base memory data: base=0x%08x, size=0x%x\n", base[mem], size[mem] > "/dev/stderr"
	if (size[mem] < (512 * 1024 * 1024))
		return 0
	if (type[mem] != "write-back")
		return 0
	if (base[mem] >= (4 * 1024 * 1024 * 1024))
		return 0
	return 1
}

function check_hole(hole)
{
	printf "Hole data: base=0x%08x, size=0x%x\n", base[hole], size[hole] > "/dev/stderr"
	if (size[hole] > (1 * 1024 * 1024 * 1024))
		return 0
	if (type[hole] != "uncachable")
		return 0
	if ((base[hole] + size[hole]) > (4 * 1024 * 1024 * 1024))
		return 0
	return 1
}

function build_entries(start, end,     new_base, new_size, tmp_base)
{
	# mtrr registers require alignment of blocks, so a 256MB chunk must
	# be 256MB aligned.  Additionally, all blocks must be a power of 2
	# in size.  So, do the largest power of two size that we can and
	# still have start + block <= end, rinse and repeat.
	tmp_base = start
	do {
		new_base = tmp_base
		new_size = 4096
		while (((new_base + new_size) < end) &&
		       ((new_base % new_size) == 0))
			new_size = lshift(new_size, 1)
		if (((new_base + new_size) > end) ||
		    ((new_base % new_size) != 0))
			new_size = rshift(new_size, 1)
		printf "base=0x%x size=0x%x type=%s\n",
			new_base, new_size, type[mem] > "/dev/stderr"
		printf "base=0x%x size=0x%x type=%s\n",
			new_base, new_size, type[mem] > "/proc/mtrr"
		fflush("")
		tmp_base = new_base + new_size
	} while (tmp_base < end)
}

{
	gsub("^reg", "")
	gsub(": base=", " ")
	gsub(" [(].*), size=", " ")
	gsub(": ", " ")
	gsub(", count=.*$", "")
	register[regs] = strtonum($1)
	base[regs] = strtonum($2)
	size[regs] = strtonum($3)
	human_size[regs] = size[regs]
	if (match($3, "MB")) { size[regs] *= 1024*1024; mult[regs] = "MB" }
	else { size[regs] *= 1024; mult[regs] = "KB" }
	type[regs] = $4
	enabled[regs] = 1
	end[regs] = base[regs] + size[regs]
	regs++
}

END {
	# First we need to find our base memory region.  We only care about
	# the memory register that starts at base 0.  This is the only one
	# that we can reliably know is our global memory region, and the
	# only one that we can reliably check against overlaps.  It's entirely
	# possible that any memory region not starting at 0 and having an
	# overlap with another memory region is in fact intentional and we
	# shouldn't touch it.
	for(i=0; i<regs; i++)
		if (base[i] == 0)
			break
	# Did we get a valid base register?
	if (i == regs)
		exit 1
	mem = i
	if (!check_base(mem))
		exit 1

	cur_hole = 0
	for(i=0; i<regs; i++) {
		if (i == mem)
			continue
		if (base[i] < end[mem] && check_hole(i))
			holes[cur_hole++] = i
	}
	if (cur_hole == 0) {
		print "Nothing to do" > "/dev/stderr"
		exit 1
	}
	printf "Found %d punch-out holes\n", cur_hole > "/dev/stderr"

	# We need to sort the holes according to base address
	for(j = 0; j < cur_hole - 1; j++) {
		for(i = cur_hole - 1; i > j; i--) {
			if(base[holes[i]] < base[holes[i-1]]) {
				tmp = holes[i]
				holes[i] = holes[i-1]
				holes[i-1] = tmp
			}
		}
	}
	# OK, the common case would be that the BIOS is mapping holes out
	# of the 4GB memory range, and that our hole(s) are consecutive and
	# that our holes and our memory region end at the same place.  However,
	# things like machines with 8GB of RAM or more can foul up these
	# common traits.
	#
	# So, our modus operandi is to disable all of the memory/hole regions
	# to start, then build new base memory zones that in the end add
	# up to the same as our original zone minus the holes.  We know that
	# we will never have a hole listed here that belongs to a valid
	# hole punched in a write-combining memory region because you can't
	# overlay write-combining on top of write-back and we know our base
	# memory region is write-back, so in order for this hole to overlap
	# our base memory region it can't be also overlapping a write-combining
	# region.
	printf "disable=%d\n", register[mem] > "/dev/stderr"
	printf "disable=%d\n", register[mem] > "/proc/mtrr"
	fflush("")
	enabled[mem] = 0
	for(i=0; i < cur_hole; i++) {
		printf "disable=%d\n", register[holes[i]] > "/dev/stderr"
		printf "disable=%d\n", register[holes[i]] > "/proc/mtrr"
		fflush("")
		enabled[holes[i]] = 0
	}
	build_entries(base[mem], base[holes[0]])
	for(i=0; i < cur_hole - 1; i++)
		if (base[holes[i+1]] > end[holes[i]])
			build_entries(end[holes[i]], base[holes[i+1]])
	if (end[mem] > end[holes[i]])
		build_entries(end[holes[i]], end[mem])
	# We changed up the mtrr regs, so signal to the rdma script to
	# reload modules that need the mtrr regs to be right.
	exit 0
}

