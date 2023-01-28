// Code originally thanks to https://github.com/rust-bitcoin/rust-bitcoincore-rpc
use crate::rpc_helper::*;

pub(crate) fn handle_defaults<'a, 'b>(
    args: &'a mut [serde_json::Value],
    defaults: &'b [serde_json::Value],
) -> &'a [serde_json::Value] {
    assert!(args.len() >= defaults.len());

    // Pass over the optional arguments in backwards order, filling in defaults after the first
    // non-null optional argument has been observed.
    let mut first_non_null_optional_idx = None;
    for i in 0..defaults.len() {
        let args_i = args.len() - 1 - i;
        let defaults_i = defaults.len() - 1 - i;
        if args[args_i] == serde_json::Value::Null {
            if first_non_null_optional_idx.is_some() {
                if defaults[defaults_i] == serde_json::Value::Null {
                    panic!("Missing `default` for argument idx {}", args_i);
                }
                args[args_i] = defaults[defaults_i].clone();
            }
        } else if first_non_null_optional_idx.is_none() {
            first_non_null_optional_idx = Some(args_i);
        }
    }

    let required_num = args.len() - defaults.len();

    if let Some(i) = first_non_null_optional_idx {
        &args[..i + 1]
    } else {
        &args[..required_num]
    }
}


pub(crate) fn into_json<T>(val: T) -> Result<serde_json::Value, RpcError>
where
    T: serde::ser::Serialize,
{
    Ok(serde_json::to_value(val)?)
}

pub(crate) fn opt_into_json<T>(opt: Option<T>) -> Result<serde_json::Value, RpcError>
where
    T: serde::ser::Serialize,
{
    Ok(into_json(Some(opt))?)
}
