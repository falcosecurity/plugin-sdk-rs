use crate::plugin::base::metrics::Metric;
use crate::plugin::error::last_error::LastError;
use crate::plugin::schema::ConfigSchema;
use crate::plugin::tables::vtable::TablesInput;
use crate::strings::cstring_writer::WriteIntoCString;
use falco_plugin_api::ss_plugin_metric;
use std::ffi::{CStr, CString};
use std::fmt::Display;
use std::io::Write;

mod logger;
pub mod metrics;
#[doc(hidden)]
pub mod wrappers;

pub(crate) struct ActualPlugin<P: Plugin> {
    pub(crate) plugin: P,
    pub(crate) last_error: LastError,
}

// TODO(sdk): convert this into traits?
//       this may make it hard to make the lifetimes line up
//       (will end up with multiple mutable references)
#[doc(hidden)]
pub struct PluginWrapper<P: Plugin> {
    pub(crate) plugin: Option<ActualPlugin<P>>,
    pub(crate) error_buf: CString,
    pub(crate) field_storage: bumpalo::Bump,
    pub(crate) string_storage: CString,
    pub(crate) metric_storage: Vec<ss_plugin_metric>,
}

impl<P: Plugin> PluginWrapper<P> {
    pub fn new(plugin: P, last_error: LastError) -> Self {
        Self {
            plugin: Some(ActualPlugin { plugin, last_error }),
            error_buf: Default::default(),
            field_storage: bumpalo::Bump::new(),
            string_storage: Default::default(),
            metric_storage: Default::default(),
        }
    }

    pub fn new_error(err: impl Display) -> Self {
        let mut plugin = Self {
            plugin: None,
            error_buf: Default::default(),
            field_storage: bumpalo::Bump::new(),
            string_storage: Default::default(),
            metric_storage: vec![],
        };

        plugin
            .error_buf
            .write_into(|buf| write!(buf, "{}", err))
            .unwrap_or_else(|err| panic!("Failed to write error message (was: {})", err));

        plugin
    }
}

/// # A base trait for implementing Falco plugins
///
/// There are several constants you need to set to describe the metadata for your plugin, described
/// below. All the constants are C-style strings: you can initialize the fields with `c"foo"`.
///
/// For example, a plugin that doesn't support any capabilities (which is
/// useless and would fail to load, but is a necessary step to building an actually useful plugin)
/// might look like:
///
/// ```
/// use std::ffi::CStr;
/// use falco_plugin::base::{Metric, Plugin};
/// use falco_plugin::plugin;
/// use falco_plugin::FailureReason;
/// use falco_plugin::tables::TablesInput;
///
/// // define the type holding the plugin state
/// struct NoOpPlugin;
///
/// // implement the base::Plugin trait
/// impl Plugin for NoOpPlugin {
///     const NAME: &'static CStr = c"sample-plugin-rs";
///     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
///     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
///     const CONTACT: &'static CStr = c"you@example.com";
///     type ConfigType = ();
///
///     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
///         -> Result<Self, anyhow::Error> {
///         Ok(NoOpPlugin)
///     }
/// }
///
/// // generate the actual plugin wrapper code
/// plugin!(NoOpPlugin);
/// ```
pub trait Plugin: Sized {
    /// the name of your plugin, must match the plugin name in the Falco config file
    const NAME: &'static CStr;
    /// the version of your plugin
    const PLUGIN_VERSION: &'static CStr;
    /// a free-form description of what your plugin does
    const DESCRIPTION: &'static CStr;
    /// a way to contact you with issues regarding the plugin, be it email or a website
    const CONTACT: &'static CStr;

    /// The plugin can be configured in three different ways. In all cases, an instance of the type
    /// you specify will be passed to the [`Plugin::new`] method.
    ///
    /// See <https://falco.org/docs/plugins/usage/> for more information about plugin configuration
    /// in Falco.
    ///
    /// ### No configuration
    ///
    /// If your plugin does not need any configuration, set the `ConfigType` to an empty tuple.
    ///
    /// ### Configuration as a string
    ///
    /// If you set the `ConfigType` to [`String`], your plugin will receive the configuration
    /// as a string, read directly from the Falco config file.
    ///
    /// ### Configuration as JSON
    ///
    /// Plugins can also be configured using a JSON object. This will be parsed by the SDK and your
    /// plugin will receive a data structure containing all the parsed fields. In order to use JSON
    /// configuration, set the `ConfigType` to `Json<T>`, where the [`Json`](`crate::base::Json`)
    /// type is provided by this crate and the type `T` must implement [`serde::de::DeserializeOwned`]
    /// and [`schemars::JsonSchema`].
    ///
    /// You will also need to provide a JSON schema for the plugin API to validate the configuration.
    ///
    /// Please note that you can use the reexports (`falco_plugin::serde` and `falco_plugin::schemars`)
    /// to ensure you're using the same version of serde and schemars as the SDK.
    ///
    /// Your config struct might look like:
    ///
    /// ```
    /// use falco_plugin::schemars::JsonSchema;
    /// use falco_plugin::serde::Deserialize;
    ///
    /// #[derive(JsonSchema, Deserialize)]
    /// #[schemars(crate = "falco_plugin::schemars")]
    /// #[serde(crate = "falco_plugin::serde")]
    /// struct MyConfig {
    ///     /* ... */
    /// }
    /// ```
    ///
    /// You can use irrefutable patterns in your `new` and `set_config` methods to make JSON configs
    /// a little more ergonomic:
    ///
    /// ```
    /// use std::ffi::CStr;
    /// use anyhow::Error;
    /// use falco_plugin::base::{Json, Metric, Plugin};
    /// use falco_plugin::schemars::JsonSchema;
    /// use falco_plugin::serde::Deserialize;
    ///
    /// use falco_plugin::tables::TablesInput;
    ///
    /// #[derive(JsonSchema, Deserialize)]
    /// #[schemars(crate = "falco_plugin::schemars")]
    /// #[serde(crate = "falco_plugin::serde")]
    /// struct MyConfig {
    ///     debug: bool,
    /// }
    ///
    /// struct MyPlugin;
    ///
    /// impl Plugin for MyPlugin {
    ///     // ...
    ///#    const NAME: &'static CStr = c"";
    ///#    const PLUGIN_VERSION: &'static CStr = c"";
    ///#    const DESCRIPTION: &'static CStr = c"";
    ///#    const CONTACT: &'static CStr = c"";
    ///
    ///     type ConfigType = Json<MyConfig>;
    ///
    ///     fn new(input: Option<&TablesInput>, Json(config): Json<MyConfig>) -> Result<Self, Error> {
    ///     //                                  ^^^^^^^^^^^^
    ///         if config.debug { /* ... */ }
    ///
    ///         // ...
    ///#        todo!()
    ///     }
    ///
    ///     fn set_config(&mut self, Json(config): Json<MyConfig>) -> Result<(), Error> {
    ///     //                       ^^^^^^^^^^^^
    ///         if config.debug { /* ... */ }
    ///
    ///         // ...
    ///#        todo!()
    ///     }
    ///
    ///#    fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
    ///#        []
    ///#    }
    ///
    ///     // ...
    /// }
    /// ```
    type ConfigType: ConfigSchema;

    /// This method takes a [`TablesInput`](`crate::tables::TablesInput`) instance, which lets you
    /// access tables exposed by other plugins (and Falco core).
    ///
    /// It should return a new instance of `Self`
    fn new(input: Option<&TablesInput>, config: Self::ConfigType) -> Result<Self, anyhow::Error>;

    /// Update the configuration of a running plugin
    ///
    /// The default implementation does nothing
    fn set_config(&mut self, _config: Self::ConfigType) -> Result<(), anyhow::Error> {
        Ok(())
    }

    /// Return the plugin metrics
    ///
    /// Metrics are described by:
    /// - a name (just a string)
    /// - a type (monotonic vs non-monotonic: [`crate::base::MetricType`])
    /// - a value of one of the supported types ([`crate::base::MetricValue`])
    ///
    /// **Note**: The plugin name is prepended to the metric name, so a metric called `foo`
    /// in a plugin called `bar` will be emitted by the plugin framework as `bar.foo`.
    ///
    /// **Note**: Metrics aren't registered in the framework in any way and there is no
    /// requirement to report the same metrics on each call to `get_metrics`. However, it's
    /// probably a good idea to do so, or at least not to change the type of metric or the type
    /// of its value from call to call.
    ///
    /// There are two general patterns to use when emitting metrics from a plugin:
    ///
    /// 1. Predefined metrics
    /// ```
    ///# use std::ffi::CStr;
    ///# use falco_plugin::base::{Metric, MetricLabel, MetricType, MetricValue, Plugin};
    ///# use falco_plugin::plugin;
    ///# use falco_plugin::FailureReason;
    ///# use falco_plugin::tables::TablesInput;
    ///#
    ///# // define the type holding the plugin state
    ///struct MyPlugin {
    ///    // ...
    ///    my_metric: MetricLabel,
    ///}
    ///#
    ///# // implement the base::Plugin trait
    ///# impl Plugin for MyPlugin {
    ///#     const NAME: &'static CStr = c"sample-plugin-rs";
    ///#     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    ///#     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
    ///#     const CONTACT: &'static CStr = c"you@example.com";
    ///#     type ConfigType = ();
    ///#
    ///     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
    ///         -> Result<Self, anyhow::Error> {
    ///         Ok(MyPlugin {
    ///             // ...
    ///             my_metric: MetricLabel::new(c"my_metric", MetricType::Monotonic),
    ///         })
    ///     }
    ///
    ///#     fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
    ///#         Ok(())
    ///#     }
    ///#
    ///     fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
    ///         [self.my_metric.with_value(MetricValue::U64(10u64))]
    ///     }
    ///# }
    /// ```
    ///
    /// 2. Inline metrics
    /// ```
    ///# use std::ffi::CStr;
    ///# use falco_plugin::base::{Metric, MetricLabel, MetricType, MetricValue, Plugin};
    ///# use falco_plugin::plugin;
    ///# use falco_plugin::FailureReason;
    ///# use falco_plugin::tables::TablesInput;
    ///#
    ///# // define the type holding the plugin state
    ///# struct NoOpPlugin;
    ///#
    ///# // implement the base::Plugin trait
    ///# impl Plugin for NoOpPlugin {
    ///#     const NAME: &'static CStr = c"sample-plugin-rs";
    ///#     const PLUGIN_VERSION: &'static CStr = c"0.0.1";
    ///#     const DESCRIPTION: &'static CStr = c"A sample Falco plugin that does nothing";
    ///#     const CONTACT: &'static CStr = c"you@example.com";
    ///#     type ConfigType = ();
    ///#
    ///#     fn new(input: Option<&TablesInput>, config: Self::ConfigType)
    ///#         -> Result<Self, anyhow::Error> {
    ///#         Ok(NoOpPlugin)
    ///#     }
    ///#
    ///#     fn set_config(&mut self, config: Self::ConfigType) -> Result<(), anyhow::Error> {
    ///#         Ok(())
    ///#     }
    ///#
    ///     fn get_metrics(&mut self) -> impl IntoIterator<Item=Metric> {
    ///         [Metric::new(
    ///             MetricLabel::new(c"my_metric", MetricType::Monotonic),
    ///             MetricValue::U64(10u64),
    ///         )]
    ///     }
    ///# }
    /// ```
    fn get_metrics(&mut self) -> impl IntoIterator<Item = Metric> {
        []
    }
}
