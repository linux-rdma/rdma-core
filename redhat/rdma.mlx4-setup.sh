#!/bin/bash
dir="/sys/bus/pci/drivers/mlx4_core"
[ ! -d $dir ] && exit 1
pushd $dir >/dev/null

function set_dual_port() {
	device=$1
	port1=$2
	port2=$3
	pushd $device >/dev/null
	cur_p1=`cat mlx4_port1`
	cur_p2=`cat mlx4_port2`

	# special case the "eth eth" mode as we need port2 to
	# actually switch to eth before the driver will let us
	# switch port1 to eth as well
	if [ "$port1" == "eth" ]; then
		if [ "$port2" != "eth" ]; then
			echo "In order for port1 to be eth, port2 to must also be eth"
			popd >/dev/null
			return
		fi
		if [ "$cur_p2" != "eth" -a "$cur_p2" != "auto (eth)" ]; then
			tries=0
			echo "$port2" > mlx4_port2 2>/dev/null
			sleep .25
			cur_p2=`cat mlx4_port2`
			while [ "$cur_p2" != "eth" -a "$cur_p2" != "auto (eth)" -a $tries -lt 10 ]; do
				sleep .25
				let tries++
				cur_p2=`cat mlx4_port2`
			done
			if [ "$cur_p2" != "eth" -a "$cur_p2" != "auto (eth)" ]; then
				echo "Failed to set port2 to eth mode"
				popd >/dev/null
				return
			fi
		fi
		if [ "$cur_p1" != "eth" -a "$cur_p1" != "auto (eth)" ]; then
			tries=0
			echo "$port1" > mlx4_port1 2>/dev/null
			sleep .25
			cur_p1=`cat mlx4_port1`
			while [ "$cur_p1" != "eth" -a "$cur_p1" != "auto (eth)" -a $tries -lt 10 ]; do
				sleep .25
				let tries++
				cur_p1=`cat mlx4_port1`
			done
			if [ "$cur_p1" != "eth" -a "$cur_p1" != "auto (eth)" ]; then
				echo "Failed to set port1 to eth mode"
			fi
		fi
		popd >/dev/null
		return
	fi

	# our mode is not eth <anything> as that is covered above
	# so we should be able to successfully set the ports in
	# port1 then port2 order
	if [ "$cur_p1" != "$port1" -o "$cur_p2" != "$port2" ]; then
		# Try setting the ports in order first
		echo "$port1" > mlx4_port1 2>/dev/null ; sleep .1
		echo "$port2" > mlx4_port2 2>/dev/null ; sleep .1
		cur_p1=`cat mlx4_port1`
		cur_p2=`cat mlx4_port2`
	fi

	if [ "$cur_p1" != "$port1" -o "$cur_p2" != "$port2" ]; then
		# Try reverse order this time
		echo "$port2" > mlx4_port2 2>/dev/null ; sleep .1
		echo "$port1" > mlx4_port1 2>/dev/null ; sleep .1
		cur_p1=`cat mlx4_port1`
		cur_p2=`cat mlx4_port2`
	fi

	if [ "$cur_p1" != "$port1" -o "$cur_p2" != "$port2" ]; then
		echo "Error setting port type on mlx4 device $device"
	fi

	popd >/dev/null
	return
}


while read device port1 port2 ; do
	[ -d "$device" ] || continue
	[ -z "$port1" ] && continue
	[ -f "$device/mlx4_port2" -a -z "$port2" ] && continue
	[ -f "$device/mlx4_port2" ] && set_dual_port $device $port1 $port2 || echo "$port1" > "$device/mlx4_port1"
done
popd 2&>/dev/null
