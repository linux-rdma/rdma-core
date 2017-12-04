# Kernel Module Loading

The RDMA subsystem relies on the kernel, udev and systemd to load modules on
demand when RDMA hardware is present. The RDMA subsystem is unique since it
does not do not load the optional RDMA hardware modules unless the system has
the rdma-core package installed.

This is to avoid exposing systems not using RDMA from having RDMA enabled, for
instance if a system has a multi-protocol ethernet adapter, but is only using
the net stack interface.

## Boot ordering with systemd

systemd assumes everything is hot pluggable and runs in an event driven
manner. This creates a chain of hot plug events as each part of the system
autoloads based on earlier parts. The first step in the process is udev
loading the physical hardware driver.

This can happen in several spots along the bootup:

 - From the initrd or built into the kernel. If hardware modules are present
   in the initrd then they are loaded into the kernel before booting the
   system. This is done largely synchronously with the boot process.

 - From udev when it auto detects PCI hardware or otherwise.
   This happens asynchronously in the boot process, systemd does not wait for
   udev to finish loading modules before it continues on.

   This path makes it very likely the system will experience a RDMA 'hot plug'
   scenario.

 - From systemd's fixed module loader systemd-modules-load.service, e.g. from
   the list in /etc/modules-load.d/. In this case the modules load happens
   synchronously within systemd and it will hold off sysinit.target until
   modules are loaded

Once the hardware module is loaded it may be necessary to load a protocol
module, e.g. to enable RDMA support on an ethernet device.

This is triggered automatically by udev rules that match the master devices
and load the protocol module with udev's module loader. This happens
asynchronously to the rest of the systemd startup.

Once a RDMA device is created by the kernel then udev will cause systemd to
schedule ULP module loading services (e.g. rdma-load-modules@.service) specific
to the plugged hardware. If sysinit.target has not yet been passed then these
loaders will defer sysinit.target until they complete, otherwise this is a hot
plug event and things will load asynchronously to the boot up process.

Finally udev will cause systemd to start RDMA specific daemons like
srp_daemon, rdma-ndd and iwpmd. These starts are linked to the detection of
the first RDMA hardware, and the daemons internally handle hot plug events for
other hardware.

## Hot Plug compatible services

Services using RDMA need to have device specific systemd dependencies in their
unit files, either created by hand by the admin or by using udev rules.

For instance, a service that uses /dev/infiniband/umad0 requires:

```
After=dev-infiniband-umad0.device
BindsTo=dev-infiniband-umad0.device
```

Which will ensure the service will not run until the required umad device
appears, and will be stopped if the umad device is unplugged.

This is similar to how systemd handles mounting filesystems and configuring
ethernet devices.

## Interaction with legacy non-hotplug services

Services that cannot handle hot plug must be ordered after
systemd-udev-settle.service, which will wait for udev to complete loading
modules and scheduling systemd services. This ensures that all RDMA hardware
present at boot is setup before proceeding to run the legacy service.

Admins using legacy services can also place their RDMA hardware modules
(e.g.  mlx4_ib) directly in /etc/modules-load.d/ or in their initrd which will
cause systemd to defer passing to sysinit.target until all RDMA hardware is
setup, this is usually sufficient for legacy services. This is probably the
default behavior in many configurations.

# Systemd Ordering

Within rdma-core we have a series of units which run in the pre `basic.target`
world to setup kernel services:

 - `iwpmd`
 - `rdma-ndd`
 - `rdma-load-modules@.service`
 - `ibacmd.socket`

These special units use DefaultDependencies=no and order before any other unit that
uses DefaultDependencies=yes. This will happen even in the case of hotplug.

Units for normal rdma-using daemons should use DefaultDependencies=yes, and
either this pattern for 'any RDMA device':

```
[Unit]
# Order after rdma-hw.target has become active and setup the kernel services
Requires=rdma-hw.target
After=rdma-hw.target

[Install]
# Autostart when RDMA hardware is present
WantedBy=rdma-hw.target
```

Or this pattern for a specific RDMA device:

```
[Unit]
# Order after RDMA services are setup
After=rdma-hw.target
# Run only while a specific umad device is present
After=dev-infiniband-umad0.device
BindsTo=dev-infiniband-umad0.device

[Install]
# Schedual the unit to be runnable when RDMA hardware is present, but
# it will only start once the requested device actuall appears.
WantedBy=rdma-hw.target
```

Note, the above does explicitly reference `After=rdma-hw.target` even though
all the current constituents of that target order before
`sysinit.target`. This is to provide greater flexibility in the future.

## rdma-hw.target

This target is Wanted automatically by udev as soon as any RDMA hardware is
plugged in or becomes available at boot.

This may be used to pull in rdma management daemons dynamically when RDMA
hardware is found. Such daemons should use:

```
[Install]
WantedBy=rdma-hw.target
```

In their unit files.

`rdma-hw.target` is also a synchronization point that orders after the low level,
pre `sysinit.target` RDMA related units have been started.
