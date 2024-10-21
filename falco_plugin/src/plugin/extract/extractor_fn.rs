use crate::extract::{ExtractPlugin, ExtractRequest};
use crate::plugin::extract::fields::Extract;
use crate::plugin::extract::schema::ExtractArgType;
use crate::plugin::extract::{ExtractField, ExtractFieldRequestArg};
use anyhow::Error;
use falco_plugin_api::ss_plugin_extract_field;
use std::ffi::CStr;

#[derive(Debug)]
pub struct ExtractLambda<P: ExtractPlugin> {
    pub(in crate::plugin::extract) obj: *const (),

    #[allow(clippy::type_complexity)]
    pub(in crate::plugin::extract) func: fn(
        obj: *const (),
        plugin: &mut P,
        field: &mut ss_plugin_extract_field,
        request: ExtractRequest<'_, '_, '_, P>,
        storage: &mut bumpalo::Bump,
    ) -> Result<(), Error>,
}

impl<P: ExtractPlugin> ExtractLambda<P> {
    pub(in crate::plugin::extract) fn call(
        &self,
        plugin: &mut P,
        field: &mut ss_plugin_extract_field,
        request: ExtractRequest<'_, '_, '_, P>,
        storage: &mut bumpalo::Bump,
    ) -> Result<(), Error> {
        (self.func)(self.obj, plugin, field, request, storage)
    }
}

#[derive(Debug)]
pub struct NoArg;

#[derive(Debug)]
pub struct IntArg;

#[derive(Debug)]
pub struct StringArg;

#[derive(Debug)]
pub struct OptIntArg;

#[derive(Debug)]
pub struct OptStringArg;

pub trait ExtractorFn<P, R, A>
where
    P: ExtractPlugin,
    R: Extract,
{
    const ARG_TYPE: ExtractArgType;

    fn call(
        obj: *const (),
        plugin: &mut P,
        req: ExtractRequest<P>,
        arg: ExtractFieldRequestArg,
    ) -> Result<R, Error>;

    fn extract<'a>(
        obj: *const (),
        plugin: &'a mut P,
        field: &mut ss_plugin_extract_field,
        request: ExtractRequest<'a, '_, '_, P>,
        storage: &mut bumpalo::Bump,
    ) -> Result<(), Error> {
        let result = Self::call(obj, plugin, request, unsafe { field.key_unchecked() })?;
        Ok(result.extract_to(field, storage)?)
    }
}

impl<P, R, F> ExtractorFn<P, R, NoArg> for F
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(&mut P, ExtractRequest<P>) -> Result<R, Error> + 'static,
{
    const ARG_TYPE: ExtractArgType = ExtractArgType::None;

    fn call(
        obj: *const (),
        plugin: &mut P,
        req: ExtractRequest<P>,
        arg: ExtractFieldRequestArg,
    ) -> Result<R, Error> {
        anyhow::ensure!(matches!(arg, ExtractFieldRequestArg::None));

        let func = obj as *const F;
        unsafe { (*func)(plugin, req) }
    }
}

impl<P, R, F> ExtractorFn<P, R, IntArg> for F
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(&mut P, ExtractRequest<P>, u64) -> Result<R, Error> + 'static,
{
    const ARG_TYPE: ExtractArgType = ExtractArgType::RequiredIndex;

    fn call(
        obj: *const (),
        plugin: &mut P,
        req: ExtractRequest<P>,
        arg: ExtractFieldRequestArg,
    ) -> Result<R, Error> {
        let ExtractFieldRequestArg::Int(arg) = arg else {
            anyhow::bail!("Expected index argument, got {:?}", arg);
        };

        let func = obj as *const F;
        unsafe { (*func)(plugin, req, arg) }
    }
}

impl<P, R, F> ExtractorFn<P, R, OptIntArg> for F
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(&mut P, ExtractRequest<P>, Option<u64>) -> Result<R, Error> + 'static,
{
    const ARG_TYPE: ExtractArgType = ExtractArgType::OptionalIndex;

    fn call(
        obj: *const (),
        plugin: &mut P,
        req: ExtractRequest<P>,
        arg: ExtractFieldRequestArg,
    ) -> Result<R, Error> {
        let arg = match arg {
            ExtractFieldRequestArg::Int(arg) => Some(arg),
            ExtractFieldRequestArg::None => None,
            _ => anyhow::bail!("Expected index argument, got {:?}", arg),
        };

        let func = obj as *const F;
        unsafe { (*func)(plugin, req, arg) }
    }
}

impl<P, R, F> ExtractorFn<P, R, StringArg> for F
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(&mut P, ExtractRequest<P>, &CStr) -> Result<R, Error> + 'static,
{
    const ARG_TYPE: ExtractArgType = ExtractArgType::RequiredKey;

    fn call(
        obj: *const (),
        plugin: &mut P,
        req: ExtractRequest<P>,
        arg: ExtractFieldRequestArg,
    ) -> Result<R, Error> {
        let ExtractFieldRequestArg::String(arg) = arg else {
            anyhow::bail!("Expected key argument, got {:?}", arg);
        };

        let func = obj as *const F;
        unsafe { (*func)(plugin, req, arg) }
    }
}

impl<P, R, F> ExtractorFn<P, R, OptStringArg> for F
where
    P: ExtractPlugin,
    R: Extract,
    F: Fn(&mut P, ExtractRequest<P>, Option<&CStr>) -> Result<R, Error> + 'static,
{
    const ARG_TYPE: ExtractArgType = ExtractArgType::OptionalKey;

    fn call(
        obj: *const (),
        plugin: &mut P,
        req: ExtractRequest<P>,
        arg: ExtractFieldRequestArg,
    ) -> Result<R, Error> {
        let arg = match arg {
            ExtractFieldRequestArg::String(arg) => Some(arg),
            ExtractFieldRequestArg::None => None,
            _ => anyhow::bail!("Expected key argument, got {:?}", arg),
        };

        let func = obj as *const F;
        unsafe { (*func)(plugin, req, arg) }
    }
}
