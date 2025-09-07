use falco_plugin_api::{
    ss_plugin_metric, ss_plugin_metric_type, ss_plugin_metric_type_SS_PLUGIN_METRIC_TYPE_MONOTONIC,
    ss_plugin_metric_type_SS_PLUGIN_METRIC_TYPE_NON_MONOTONIC, ss_plugin_metric_value,
    ss_plugin_metric_value_type, ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_D,
    ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_F,
    ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_I,
    ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_S32,
    ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_S64,
    ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_U32,
    ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_U64,
};
use std::ffi::CStr;

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(missing_docs)]
pub enum MetricType {
    Monotonic,
    NonMonotonic,
}

impl MetricType {
    fn as_raw(&self) -> ss_plugin_metric_type {
        match self {
            Self::Monotonic => ss_plugin_metric_type_SS_PLUGIN_METRIC_TYPE_MONOTONIC,
            Self::NonMonotonic => ss_plugin_metric_type_SS_PLUGIN_METRIC_TYPE_NON_MONOTONIC,
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq)]
#[allow(missing_docs)]
pub enum MetricValue {
    U32(u32),
    S32(i32),
    U64(u64),
    I64(i64),
    Double(f64),
    Float(f32),
    Int(i32),
}

impl MetricValue {
    fn as_raw(&self) -> (ss_plugin_metric_value_type, ss_plugin_metric_value) {
        match self {
            MetricValue::U32(v) => (
                ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_U32,
                ss_plugin_metric_value { u32_: *v },
            ),
            MetricValue::S32(v) => (
                ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_S32,
                ss_plugin_metric_value { s32: *v },
            ),
            MetricValue::U64(v) => (
                ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_U64,
                ss_plugin_metric_value { u64_: *v },
            ),
            MetricValue::I64(v) => (
                ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_S64,
                ss_plugin_metric_value { s64: *v },
            ),
            MetricValue::Double(v) => (
                ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_D,
                ss_plugin_metric_value { d: *v },
            ),
            MetricValue::Float(v) => (
                ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_F,
                ss_plugin_metric_value { f: *v },
            ),
            MetricValue::Int(v) => (
                ss_plugin_metric_value_type_SS_PLUGIN_METRIC_VALUE_TYPE_I,
                ss_plugin_metric_value { i: *v },
            ),
        }
    }
}

/// A descriptor for a metric
///
/// It contains the metric name and the type (monotonic/non-monotonic) but does not
/// contain a specific value
#[derive(Debug, Clone)]
pub struct MetricLabel {
    name: &'static CStr,
    metric_type: MetricType,
}

impl MetricLabel {
    /// Create a new metric label
    pub fn new(name: &'static CStr, metric_type: MetricType) -> Self {
        Self { name, metric_type }
    }

    /// Create a [`Metric`], assigning a specific value to a label
    pub fn with_value(&self, value: MetricValue) -> Metric {
        Metric {
            label: self.clone(),
            value,
        }
    }
}

/// A metric with a value
///
/// This is what gets emitted to the Falco Plugin API (after a conversion to the required format)
#[derive(Debug)]
pub struct Metric {
    label: MetricLabel,
    value: MetricValue,
}

impl Metric {
    /// Create a new metric, combining a label with a corresponding value
    pub fn new(label: MetricLabel, value: MetricValue) -> Self {
        Self { label, value }
    }

    pub(crate) fn as_raw(&self) -> ss_plugin_metric {
        let (value_type, value) = self.value.as_raw();
        let metric_type = self.label.metric_type.as_raw();

        ss_plugin_metric {
            name: self.label.name.as_ptr(),
            type_: metric_type,
            value_type,
            value,
        }
    }
}
