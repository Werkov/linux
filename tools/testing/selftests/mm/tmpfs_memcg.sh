#!/bin/sh
# SPDX-License-Identifier: GPL-2.0

CGROUP_PATH=/dev/cgroup/memory/tmpfs-memcg-test

function cleanup() {
  rm -rf /mnt/tmpfs/*
  umount /mnt/tmpfs
  rm -rf /mnt/tmpfs

  rmdir $CGROUP_PATH

  echo CLEANUP DONE
}

function setup() {
  mkdir -p $CGROUP_PATH
  echo $((10 * 1024 * 1024)) > $CGROUP_PATH/memory.limit_in_bytes
  echo 0 > $CGROUP_PATH/cpuset.cpus
  echo 0 > $CGROUP_PATH/cpuset.mems

  mkdir -p /mnt/tmpfs

  echo SETUP DONE
}

function expect_equal() {
  local expected="$1"
  local actual="$2"
  local error="$3"

  if [[ "$actual" != "$expected" ]]; then
    echo "expected ($expected) != actual ($actual): $3" >&2
    cleanup
    exit 1
  fi
}

function expect_ge() {
  local expected="$1"
  local actual="$2"
  local error="$3"

  if [[ "$actual" -lt "$expected" ]]; then
    echo "expected ($expected) < actual ($actual): $3" >&2
    cleanup
    exit 1
  fi
}

cleanup
setup

mount -t tmpfs -o nomemcg tmpfs /mnt/tmpfs
check=$(cat /proc/mounts | grep -i remount-memcg-test)
if [ -z "$check" ]; then
  echo "tmpfs nomemcg was not mounted correctly:"
  echo $check
  echo "FAILED"
  cleanup
  exit 1
fi

if mount -t tmpfs -o remount tmpfs /mnt/tmpfs; then
  echo "tmpfs nomemcg was not remounted correctly:"
  echo $check
  echo "FAILED"
  cleanup
  exit 1
fi

TARGET_MEMCG_USAGE=$(cat $CGROUP_PATH/memory.usage_in_bytes)
# XXX take snapshot
expect_equal 0 "$TARGET_MEMCG_USAGE" "Before echo, memcg usage should be 0"

# Echo to allocate a page in the tmpfs
echo
echo
echo hello > /mnt/tmpfs/test
TARGET_MEMCG_USAGE=$(cat $CGROUP_PATH/memory.usage_in_bytes)
# XXX negation
expect_ge 4096 "$TARGET_MEMCG_USAGE" "After echo, memcg usage should be greater than 4096"
echo "Echo test succeeded"

echo
echo
tools/testing/selftests/vm/mmap_write -p /mnt/tmpfs/test -s $((1 * 1024 * 1024))
TARGET_MEMCG_USAGE=$(cat $CGROUP_PATH/memory.usage_in_bytes)
# XXX negation
expect_ge $((1 * 1024 * 1024)) "$TARGET_MEMCG_USAGE" "After mmap_write, memcg usage should greater than 1MB"
echo "WRITE TEST SUCCEEDED"

cleanup
echo TEST PASSED
