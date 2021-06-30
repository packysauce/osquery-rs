use maplit::btreemap;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::marker::PhantomData;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use thrift::protocol::TBinaryInputProtocol;
use thrift::protocol::TBinaryOutputProtocol;
use thrift::server::{TProcessor};
use thrift::transport::{TBufferedReadTransport, TBufferedWriteTransport};
use thrift::{ApplicationError, ProtocolError, TransportError, TransportErrorKind};
use tracing::{debug, error, info, instrument, warn};

pub use anyhow::Error as AnyError;
pub use thiserror::Error;
pub use thrift;

pub mod gen;
pub use gen::osquery::ExtensionPluginRequest as PluginRequest;
pub use gen::osquery::ExtensionPluginResponse as PluginResponse;
pub use gen::osquery::*;
pub use gen::table::{Column, QueryContext};
pub use ExtensionCode as Code;
pub use ExtensionResponse as Response;
pub use ExtensionStatus as Status;

use self::gen::table::ColumnType;

mod util;

#[derive(Debug, Error)]
pub enum Error {}

macro_rules! column_types {
    ($($variant:ident : $kind:ty,)+) => { column_types!($( $variant : $kind ),+ ); };
    ($($variant:ident : $kind:ty),+) => {
        #[derive(PartialEq, PartialOrd, Debug)]
        pub enum ColumnValue {
            $($variant($kind),)+
        }

        impl ColumnValue {
            $(
            ::paste::paste! {
                pub fn [< $variant:snake >]<T: Into<$kind>>(v: T) -> Self {
                    Self::from(v.into())
                }
            }
            )+

            fn to_string(&self) -> String {
                match self {
                    $(Self::$variant(v) => v.to_string(),)+
                }
            }
        }

        $(
        impl From<$kind> for ColumnValue {
            fn from(value: $kind) -> Self {
                ColumnValue::$variant(value)
            }
        }

        impl From<$kind> for ColumnType {
            fn from(_: $kind) -> Self {
                ColumnType::$variant
            }
        }
        )+

        impl From<ColumnValue> for ColumnType {
            fn from(value: ColumnValue) -> Self {
                match value {
                    $(ColumnValue::$variant(_) => ColumnType::$variant),+
                }
            }
        }

        impl Column {
            $(
            ::paste::paste! {
                pub const fn [< $variant:snake >](name: &'static str) -> Column {
                    Column {
                        name,
                        kind: ColumnType::[< $variant:camel >]
                    }
                }
            }
            )+
        }
    };
}

column_types!(Text: String, Integer: i32, BigInt: i64, Double: f64,);

pub type TableColumns = Vec<Column>;
pub type TableRows = Vec<BTreeMap<String, ColumnValue>>;

pub trait TablePlugin {
    const NAME: &'static str;
    const COLUMNS: &'static [Column];
    fn generate(&self, query: &QueryContext) -> Result<TableRows, thrift::Error>;
    fn shutdown(&self) {}
}

pub trait Routes: TablePlugin {
    fn routes() -> ExtensionPluginResponse {
        Self::COLUMNS
            .iter()
            .map(|col| {
                serde_json::from_value(serde_json::json!({
                    "id": "column",
                    "name": col.name,
                    "type": col.kind,
                    "op": "0",
                }))
                .unwrap()
            })
            .collect()
    }
}

impl<T> Routes for T where T: TablePlugin {}

impl ExtensionStatus {
    pub fn ok(self) -> Result<Option<String>, thrift::Error> {
        if self.code == Some(Code::ExtSuccess as i32) {
            return Ok(self.message);
        }
        let e = thrift::ApplicationError::new(
            thrift::ApplicationErrorKind::InternalError,
            self.message
                .unwrap_or_else(|| "Unknown error occurred!".to_string()),
        );
        Err(e.into())
    }
}

type BinaryIn = TBinaryInputProtocol<UnixStream>;
type BinaryOut = TBinaryOutputProtocol<UnixStream>;

pub struct Handle<T> {
    socket_path: PathBuf,
    uuid: i64,
    _marker: PhantomData<T>,
}

// do i need this shit?
pub trait Plugin: Default {
    fn new() -> Self {
        Self::default()
    }
}
impl<T> Plugin for T where T: TablePlugin + Default {}

impl<T> Handle<T>
where
    T: Plugin,
{
    fn new<P: AsRef<Path>>(path: P, uuid: i64) -> Self {
        Handle {
            socket_path: path.as_ref().into(),
            uuid,
            _marker: Default::default(),
        }
    }
}

#[instrument]
fn run_metaserver<T: Default + ExtensionSyncHandler + Send + Sync + 'static>(
    uuid: i64,
    mut socket_path: PathBuf,
) -> Result<(), thrift::Error> {
    let mut name = socket_path
        .file_name()
        .ok_or_else(|| {
            thrift::Error::Transport(TransportError::new(
                thrift::TransportErrorKind::NotOpen,
                format!("Invalid osquery socket path `{:?}`", socket_path),
            ))
        })?
        .to_os_string();
    name.push(&format!(".{}", uuid));
    socket_path.set_file_name(name);

    // stand up the sync processor (the thing that knows how to go from thrift -> Plugin)
    let processor = Arc::new(ExtensionSyncProcessor::new(T::default()));
    // listen on the unix socket we got back from osquery
    let unix_listener = UnixListener::bind(&socket_path)?;
    info!("Listening at {:?}", socket_path);

    for sock in unix_listener.incoming() {
        match sock {
            Ok(stream) => {
                // every time we get a connection, grab a copy of the processor and get to steppin
                let processor = processor.clone();
                std::thread::spawn(move || {
                    debug!(?stream, "new connection");
                    let i_trans = TBufferedReadTransport::new(stream.try_clone()?);
                    let o_trans = TBufferedWriteTransport::new(stream);
                    let mut i_prot = TBinaryInputProtocol::new(i_trans, true);
                    let mut o_prot = TBinaryOutputProtocol::new(o_trans, true);
                    loop {
                        match processor.process(&mut i_prot, &mut o_prot) {
                            Ok(_) => {}
                            Err(thrift::Error::Transport(TransportError {
                                kind: TransportErrorKind::EndOfFile,
                                ..
                            })) => break,
                            Err(e) => {
                                warn!(error=%e, "processor completed with error");
                                break;
                            }
                        }
                    }
                    Ok::<_, thrift::Error>(())
                });
            }
            Err(e) => {
                error!("incoming connection had a problem! {}", e);
                return Err(e.into());
            }
        }
    }
    info!("listener shut down");
    Ok(())
}

impl<T: 'static> Handle<T>
where
    T: TablePlugin + Default + Send + Sync,
{
    #[tracing::instrument(skip(self), fields(T = "std::any::type_name::<T>()"))]
    pub fn start(&self) -> JoinHandle<Result<(), thrift::Error>> {
        let uuid = self.uuid;
        let socket_path = self.socket_path.clone();
        std::thread::spawn(move || run_metaserver::<T>(uuid, socket_path))
    }
}

#[derive(derive_more::Deref, derive_more::DerefMut)]
pub struct Client {
    socket_path: std::path::PathBuf,
    #[deref]
    #[deref_mut]
    server: ExtensionManagerSyncClient<BinaryIn, BinaryOut>,
}

impl Client {
    pub fn connect<P: AsRef<Path>>(path: P) -> Result<Self, thrift::Error> {
        let reader = UnixStream::connect(&path)?;
        let writer = reader.try_clone()?;
        let input_protocol = TBinaryInputProtocol::new(reader, false);
        let output_protocol = TBinaryOutputProtocol::new(writer, false);
        Ok(Self {
            socket_path: path.as_ref().into(),
            server: ExtensionManagerSyncClient::new(input_protocol, output_protocol),
        })
    }

    pub fn register_table<T: TablePlugin + Default + Send>(
        &mut self,
    ) -> Result<Handle<T>, thrift::Error> {
        let info = InternalExtensionInfo::new(
            Some(T::NAME.to_string()),
            env!("CARGO_PKG_VERSION").to_string(),
            None,
            None,
        );
        let registry = serde_json::from_value(json!({
            "table": {
                "example_plugin": T::routes(),
            }
        }))
        .map_err(|e| {
            ApplicationError::new(
                thrift::ApplicationErrorKind::InternalError,
                format!("Failed to generate routes: {}", e),
            )
        })?;
        let status = self.register_extension(info, registry)?;
        debug!(
            "registered extension from {}, got back {:?}",
            std::any::type_name::<T>(),
            &status
        );
        let uuid = status.uuid.ok_or_else(|| {
            ApplicationError::new(
                thrift::ApplicationErrorKind::ProtocolError,
                "Got no UUID from osquery",
            )
        })?;
        Ok(Handle::new(&self.socket_path, uuid))
    }
}

impl<T> ExtensionSyncHandler for T
where
    T: TablePlugin,
{
    fn handle_ping(&self) -> thrift::Result<ExtensionStatus> {
        Ok(ExtensionStatus {
            code: Some(Code::ExtSuccess as i32),
            message: Some("OK".to_string()),
            uuid: None,
        })
    }

    fn handle_call(
        &self,
        _registry: String,
        _item: String,
        mut request: ExtensionPluginRequest,
    ) -> thrift::Result<Response> {
        debug!("handling call with request {:?}", &request);
        let mut get_field = |key| {
            request.remove(key).ok_or_else(|| {
                thrift::Error::Application(ApplicationError::new(
                    thrift::ApplicationErrorKind::ProtocolError,
                    format!(
                        "request to `{}` missing required field `{}`",
                        Self::NAME,
                        key,
                    ),
                ))
            })
        };
        let action = get_field("action")?;
        let context_data = get_field("context")?;
        debug!("handling call with context {}", &context_data);
        let query = serde_json::from_str::<QueryContext>(&context_data).map_err(|e| {
            thrift::Error::Application(ApplicationError::new(
                thrift::ApplicationErrorKind::ProtocolError,
                format!("got error deserializing context: {}\n{}", e, context_data),
            ))
        })?;

        let output = match action.as_str() {
            "generate" => self
                .generate(&query)?
                .into_iter()
                .map(|v| {
                    v.into_iter()
                        .map(|(k, v)| (k, v.to_string()))
                        .collect::<BTreeMap<_, _>>()
                })
                .collect(),
            "columns" => Self::COLUMNS
                .iter()
                .cloned()
                .map(|c| btreemap! { c.name.to_string() => c.kind.to_string() })
                .collect::<Vec<_>>(),
            other => {
                return Err(thrift::Error::Protocol(ProtocolError::new(
                    thrift::ProtocolErrorKind::NotImplemented,
                    format!("action `{}` not supported on plugin type `table`", other),
                )))
            }
        };
        let response = Response {
            status: Some(Status {
                code: Some(Code::ExtSuccess as i32),
                message: None,
                uuid: None,
            }),
            response: Some(output),
        };

        Ok(response)
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        let _ = self.shutdown();
        Ok(())
    }
}
