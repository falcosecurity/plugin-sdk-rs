#!/usr/bin/env bash

cd "$(dirname "$0")/.." || exit 1

EVENT_TABLE="api/flags_table.c"

(cat << EOF
use falco_schema_derive::event_flags;

event_flags! {
EOF

cat api/flag_types

echo

sed -n '/ppm_name_value/,$p' < $EVENT_TABLE | grep -v '^#' | uniq | sed 's@, ANON_INODE_FD_TYPE@, anon_inode_fd_type_ANON_INODE_FD_TYPE@'

echo '}') > src/fields/event_flags.rs

rustfmt src/fields/event_flags.rs
