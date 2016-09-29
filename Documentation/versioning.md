# Overall Package Version

This version number is set in the top level CMakeLists.txt:

```sh
set(PACKAGE_VERSION "11")
````

For upstream releases this is a single integer showing the release
ordering. We do not attempt to encode any 'ABI' information in this version.

Branched stabled releases can append an additional counter eg `11.2`.

Unofficial releases should include a distributor tag, eg '11.vendor2'.

When the PACKAGE_VERSION is changed, the packaging files should be updated:

```diff
diff --git a/CMakeLists.txt b/CMakeLists.txt
index 389feee1e0f9..63854fe8f07f 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -26,7 +26,7 @@ project(RDMA C)
 set(PACKAGE_NAME "RDMA")
 
 # See Documentation/versioning.md
-set(PACKAGE_VERSION "11")
+set(PACKAGE_VERSION "12")
 
 #-------------------------
 # Basic standard paths
```

# Shared Library Versions

The shared libraries use the typical semantic versioning scheme, eg
*libibumad* has a version like `3.1.11`.

The version number is broken up into three fields:
- '3' is called the SONAME and is embedded into the ELF:
   ```sh
   $ readelf -ds build/lib/libibumad.so.3.1.11
    0x000000000000000e (SONAME)             Library soname: [libibumad.so.3]
   ```

   We do not expect this value to ever change for our libraries. It indicates
   the overall ABI, changing it means the library will not dynamically to old
   programs link anymore.

- '1' is called the ABI level and is used within the ELF as the last component
   symbol version tag.  This version must be changed every time a new symbol
   is introduced. It allows the user to see what version of the ABI the
   library provides.

- '11' is the overall release number and is copied from `PACKAGE_VERSION` This
  version increases with every package release, even if the library code did
  not change. It allows the user to see what upstream source was used to build
  the library.

This version is encoded into the filename `build/lib/libibumad.so.3.1.11` and
a symlink from `libibumad.so.3` to `build/lib/libibumad.so.3.1.11` is created.

## Shared Library Symbol Versions

Symbol versions are a linker technique that lets the library author provide
two symbols with different ABIs that have the same API name. The linker
differentiates the two cases internally. This allows the library author to
change the ABI that the API uses. This project typically does not make use of
this feature.

As a secondary feature, the symbol version is also used by package managers
like RPM to manage the ABI level. To make this work properly the ABI level
must be correctly encoded into the symbol version.

## Adding a new symbol

First, increase the ABI level of the library. It is safe to re-use the ABI
level for multiple new functions within a single release, but once a release
is tagged the ABI level becomes *immutable*. The maintainer can provide
guidence on what ABI level to use for each series.

```diff
 rdma_library(ibumad libibumad.map
   # See Documentation/versioning.md
-  3 3.1.${PACKAGE_VERSION}
+  3 3.2.${PACKAGE_VERSION}
```

Next, add your new symbol to the symbol version file:

```diff
+ IBUMAD_3.2 {
+ 	global:
+ 		umad_new_symbol;
+ } IBUMAD_1.0;
```

NOTE: Once a release is made the stanzas in the map file are *immutable* and
cannot be changed. Do not add your new symbol to old stanzas.

The new symbol should appear in the ELF:

```sh
$ readelf -s build/lib/libibumad.so.3.1.11
 35: 00000000000031e0   450 FUNC    GLOBAL DEFAULT   12 umad_new_symbol@@IBUMAD_3.2
```

Finally update the `debian/libibumad3.symbols` file.
