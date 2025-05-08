This crate provides a framework for writing [Falco](https://github.com/falcosecurity/falco)
plugins. There are several types of plugins available. Learn more about Falco plugins
and plugin types in the [Falco plugin documentation](https://falco.org/docs/plugins/).

All plugins must implement the base plugin trait (see [`base::Plugin`]) and at least one of the plugin
capabilities.

# Building a Falco plugin

The typical way to distribute a Falco plugin is to build a shared library. To build a plugin as a shared
library, you need to:

1. Specify `crate_type = ["cdylib"]` in the `[lib]` section of `Cargo.toml`,
2. Invoke [`plugin!`] and all the macros corresponding to the capabilities your plugin implements.

The most basic `Cargo.toml` file for a dynamically linked plugin without any dependencies could be:

```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
falco_plugin = "0.4.0"
```

The general layout of your plugin code would be:

```ignore
struct MyPlugin { /* ... */ }

impl Plugin for MyPlugin { /* ... */ }

// one or more of the plugin capabilities:
impl SourcePlugin for MyPlugin { /* ... */ }

// generate actual plugin functions for Falco to use:
plugin!(MyPlugin);
// use the macros corresponding to the capabilities your plugin implements:
source_plugin!(MyPlugin);

// now you can call sinsp::register_plugin("/path/to/your.so")
// or get Falco to do it via the configuration file
```

# Loading and configuring plugins in Falco

To load a plugin in Falco, you need to add them to the `plugins` and `load_plugins` sections in the config
file, for example:

```yaml
plugins:
  - name: my_plugin
    library_path: /path/to/libmyplugin.so
    init_config: ...
load_plugins:
  - my_plugin
```

The plugin name in `plugins.name` and in `load_plugins` must match [`base::Plugin::NAME`]. `init_config` is optional
and may contain either a string or a YAML object (which will be converted to JSON before passing it to your plugin).
In any case, the configuration must match [`base::Plugin::ConfigType`].

# Statically linked plugins

In some circumstances, you might prefer to link plugins statically into your application. This changes
the interface somewhat (instead of using predefined symbol names, you register your plugin by directly
passing a [`falco_plugin_api::plugin_api`] struct to `sinsp::register_plugin`).

This is only relevant if you're building your own application that uses libsinsp, not when building plugins
to use with Falco, so feel free to skip this section.

<details><summary>How to build statically linked plugins</summary>

For a statically linked plugin, you need to:

1. Specify `crate_type = ["staticlib"]` in the `[lib]` section of `Cargo.toml`,
2. Invoke the [`static_plugin!`] macro. You do not need to handle individual capabilities.

The most basic `Cargo.toml` file for a statically linked plugin without any dependencies could be:

```toml
[package]
name = "my-plugin"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["staticlib"]

[dependencies]
falco_plugin = "0.4.0"
```

The outline of the plugin code would look like:

```ignore
struct MyPlugin { /* ... */ }

impl Plugin for MyPlugin { /* ... */ }

// one or more of the plugin capabilities:
impl SourcePlugin for MyPlugin { /* ... */ }

// generate the API structure for the plugin:
static_plugin!(MY_PLUGIN_API = MyPlugin);

// now you can call sinsp::register_plugin(&MY_PLUGIN_API) on the C++ side
```

Loading and configuring a statically linked plugin entirely depends on the application you're linking it into.

## Building static and dynamic plugins from a single codebase

This is a more complex problem, but still doable. As the SDK has validation to ensure the required macros
are invoked, we cannot split the plugin `impl`s from the export macros. We also cannot conditionally compile
one set or the other based on the crate type we're building, so we need another approach.

First, add a lints setting to your `Cargo.toml` and make sure you're building a `cdylib`:

```toml
[lib]
crate-type = ["cdylib"]

[lints.rust]
unexpected_cfgs = { level = "allow", check-cfg = ['cfg(linkage, values("static"))'] }
```

This lets us configure the build either with or without `linkage="static"` and check the value of this
setting inside the code.

Then, conditionally invoke the right macros, based on the setting:

```ignore
// static linking
#[cfg(linkage = "static")]
use falco_plugin::static_plugin;

#[cfg(linkage = "static")]
static_plugin!(MY_PLUGIN = MyPlugin);

// dynamic linking
#[cfg(not(linkage = "static"))]
use falco_plugin::{plugin, source_plugin};

#[cfg(not(linkage = "static"))]
plugin!(MyPlugin);

#[cfg(not(linkage = "static"))]
source_plugin!(MyPlugin);
```

(explicitly importing the macros seems necessary for some reason)

Finally, build both variants:

```shell
# build the shared plugin library (default)
cargo build --release

# override crate type and the linkage setting to build a static library
# note we're using `cargo rustc` here, not `cargo build`
RUSTFLAGS='--cfg linkage="static"' cargo rustc --crate-type=staticlib --release
```

</details>

# Plugin capabilities

Plugin functionality is split across several independent capabilities. You will want to implement at least one,
otherwise your plugin won't do anything at all (and will be rejected by Falco when trying to load it).

Capabilities are added by implementing the corresponding trait on your plugin type and invoking the matching
capability export macro (see individual capabilities for details).

The SDK will check that all the capabilities your plugin does support are exported to the plugin API.
This happens automatically with statically linked plugins, but with dynamically linked plugins you need to invoke
one macro per capability yourself. If you forget to do this, you will get a compile error pointing you to the right
macro.

The SDK will also check that your plugin supports at least one capability. During initial development, you might want to
build a plugin with no capabilities, so this check can be disabled by using the `#[no_capabilities]` attribute:

```ignore
// dynamically linked plugin:
plugin!(#[no_capabilities] MyPlugin);

// statically linked plugin
static_plugin!(#[no_capabilities] MY_PLUGIN = MyPlugin);
```

## Event sourcing plugins

Source plugins are used to generate events. The implementation comes in two parts:

1. An implementation of [`source::SourcePlugin`] on the plugin type, which mostly serves
   to create a plugin instance
2. A type implementing [`source::SourcePluginInstance`], which does the actual event generation

To register your plugin's event sourcing capability, pass it to the [`source_plugin!`] macro.

To create rules matching against events coming from your plugin, set the `source` field on a rule
to the value of [`source::SourcePlugin::EVENT_SOURCE`], for example (in `falco_rules.yaml`):

```yaml
- rule: match first 100 events from `my_plugin`
  desc: match first 100 events from `my_plugin`
  condition: evt.num <= 100
  output: %evt.plugininfo # evt.plugininfo comes from event_to_string()
  priority: CRITICAL
  source: my_plugin
```

## Field extraction plugins

Field extraction plugins add extra fields to be used in rule matching and rule output. Each
field has a name, type and a function or method that returns the actual extracted data.

Extraction plugins are created by implementing the [`extract::ExtractPlugin`] trait and calling
[`extract_plugin!`] with the plugin type.

Rules involving fields from extract plugins must match against the correct source (one of [
`extract::ExtractPlugin::EVENT_SOURCES`]).

## Event parsing plugins

Event parsing plugins are invoked on every event (modulo some filtering) and can be used to
maintain some state across events, e.g. for extraction plugins to return later.

Event parsing plugins are created by implementing [`parse::ParsePlugin`] and calling [`parse_plugin!`]
with the plugin type.

## Asynchronous event plugins

Asynchronous event plugins can be used to inject events outside the flow of the main event loop,
for example from a separate thread.

They are created by implementing [`async_event::AsyncEventPlugin`] and calling [`async_event_plugin!`]
with the plugin type.

## Capture listening plugins

Plugins with this capability provide `capture_open` and `capture_close` callbacks that are called
when the capture is started/stopped, respectively. Note this is *not* equivalent to plugin init/shutdown
as the capture may be stopped/restarted several times over the lifetime of a plugin.

They are created by implementing [`listen::CaptureListenPlugin`] and calling [`capture_listen_plugin!`]
with the plugin type.

# Logging in plugins

The SDK uses the [`log`] crate for logging, redirecting all messages to the Falco libs logger, so you can use
e.g. `log::info!` in your plugin without any explicit initialization. The log level defaults to `Trace`
in debug builds and to `Info` in release builds, but can be overridden by calling [`log::set_max_level`]
in your [plugin init method](`base::Plugin::new`).

# Versioning and MSRV

The SDK consists of several crates, some are more coupled to each other, some are mostly independent. However,
to keep packaging manageable, all the crates are versioned together, i.e. a version bump in one causes
a corresponding version bump in all the other crates, even if it's not strictly necessary. This may change
in the future.

While we're in the 0.x version range, the Minimum Supported Rust Version is defined as "latest stable".
