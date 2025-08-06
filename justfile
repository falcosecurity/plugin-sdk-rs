default:
    just --list

[working-directory('falco_plugin_api')]
pull_api version:
    wget https://raw.githubusercontent.com/falcosecurity/libs/{{ version }}/userspace/plugin/plugin_types.h -O plugin/plugin_types.h
    wget https://raw.githubusercontent.com/falcosecurity/libs/{{ version }}/userspace/plugin/plugin_api.h -O plugin/plugin_api.h

[working-directory('falco_plugin_api')]
regen_api:
    bindgen plugin/plugin_api.h \
        --new-type-alias ss_plugin_table_t --no-copy ss_plugin_table_t \
        --new-type-alias ss_plugin_table_entry_t --no-copy ss_plugin_table_entry_t \
        --new-type-alias ss_plugin_table_field_t --no-copy ss_plugin_table_field_t \
        --new-type-alias ss_plugin_owner_t --no-copy ss_plugin_owner_t \
        --new-type-alias ss_plugin_t --no-copy ss_plugin_t \
        --new-type-alias ss_instance_t --no-copy ss_instance_t \
        --new-type-alias ss_plugin_table_iterator_state_t --no-copy ss_plugin_table_iterator_state_t \
        --new-type-alias ss_plugin_routine_t --no-copy ss_plugin_routine_t \
        --new-type-alias ss_plugin_routine_state_t --no-copy ss_plugin_routine_state_t \
        --no-debug 'ss_plugin_table_info|ss_plugin_table_fieldinfo' \
        --override-abi '.*=C-unwind' \
        --blocklist-item imaxdiv_t \
        --blocklist-item imaxdiv \
        -- -I. > src/ffi.rs

update_api version: (pull_api version) regen_api

[working-directory('falco_event')]
pull_events version:
    wget https://raw.githubusercontent.com/falcosecurity/libs/{{ version }}/driver/ppm_fillers.h -O api/ppm_fillers.h
    wget https://raw.githubusercontent.com/falcosecurity/libs/{{ version }}/driver/ppm_events_public.h -O - | sed 's@\<long\>@int64_t@' > api/ppm_events_public.h
    wget https://raw.githubusercontent.com/falcosecurity/libs/{{ version }}/driver/event_table.c -O api/event_table.c
    wget https://raw.githubusercontent.com/falcosecurity/libs/{{ version }}/driver/flags_table.c -O api/flags_table.c
    wget https://raw.githubusercontent.com/falcosecurity/libs/{{ version }}/driver/dynamic_params_table.c -O api/dynamic_params_table.c
    > api/feature_gates.h

[working-directory('falco_event')]
regen_events:
    bindgen api/ppm_events_public.h -- -I. > src/ffi.rs
    ./tools/generate_event_table.sh
    ./tools/generate_dynamic_param_table.sh
    ./tools/generate_flags_table.sh

update_events version: (pull_events version) regen_events

pull version: (pull_api version) (pull_events version)

regen: regen_api regen_events

update version: (pull version) regen

presubmit:
    cargo clippy --all-targets --all-features -- -D warnings
    cargo test --all-features
    RUSTDOCFLAGS="--cfg docsrs" cargo doc --all-features --no-deps
    cargo fmt --check || cargo fmt

presubmit-pr base:
    git rebase --exec "just presubmit" {{ base }}
