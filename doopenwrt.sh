set -ex
zz build

cd ~/proj/captif/openwrt/
make V=s CONFIG_DEBUG=y -j20 package/devguard/carrier/{clean,compile}
scp ~/proj/captif/openwrt/build_dir/target-mips_24kc_musl/carrier-0.13/carrier root@192.168.0.83:/tmp/carrier

