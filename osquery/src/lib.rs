use maplit::btreemap;
use serde_json::json;
use std::collections::BTreeMap;
use std::fmt::Debug;
use std::io::ErrorKind;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;
use thrift::protocol::TBinaryInputProtocol;
use thrift::protocol::TBinaryOutputProtocol;
use thrift::server::TProcessor;
use thrift::transport::{TBufferedReadTransport, TBufferedWriteTransport};
use thrift::{ApplicationError, ProtocolError, TransportError, TransportErrorKind};
use tracing::{debug, error, info, info_span, instrument, trace, warn};

pub use anyhow::{anyhow, Error};
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
                pub fn [< $variant:snake >](name: &str) -> Column {
                    Column {
                        name: name.to_string(),
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

pub trait TablePlugin: Plugin {
    fn generate(&self, query: &QueryContext) -> Result<TableRows, Self::Error>;
    fn columns(&self) -> Result<Vec<Column>, Self::Error>;
    fn shutdown(&self);
}

pub trait Routes {
    fn routes(&self) -> ExtensionPluginResponse;
}

impl<T> Routes for T
where
    T: TablePlugin,
{
    fn routes(&self) -> ExtensionPluginResponse {
        let columns = match self.columns() {
            Ok(col) => col,
            Err(error) => {
                error!(table=std::any::type_name::<Self>(), %error, "problem getting columns for routes");
                return vec![];
            }
        };

        columns
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

#[derive(Debug)]
pub struct Handle<T> {
    socket_path: PathBuf,
    server: T,
}

pub trait Plugin: Routes + Sized {
    type Error: std::error::Error + Send + Sync + 'static;
    const NAME: &'static str;
    fn new() -> Self;
    fn install(self, client: &mut Client) -> Result<Handle<Self>, thrift::Error> {
        let info = InternalExtensionInfo::new(
            Some(Self::NAME.to_string()),
            env!("CARGO_PKG_VERSION").to_string(),
            None,
            None,
        );
        let registry = serde_json::from_value(json!({
            "table": {
                (Self::NAME) : self.routes(),
            }
        }))
        .map_err(|e| {
            ApplicationError::new(
                thrift::ApplicationErrorKind::InternalError,
                format!("Failed to generate routes: {}", e),
            )
        })?;
        let status = client.register_extension(info, registry)?;
        debug!(
            "registered extension from {}, got back {:?}",
            std::any::type_name::<Self>(),
            &status
        );
        let uuid = status.uuid.ok_or_else(|| {
            ApplicationError::new(
                thrift::ApplicationErrorKind::ProtocolError,
                "Got no UUID from osquery",
            )
        })?;
        Ok(Handle::new(client.socket_path(uuid)?, self))
    }
}

impl<T> Handle<T>
where
    T: Plugin,
{
    pub fn new<P: AsRef<Path>>(path: P, server: T) -> Self {
        Handle {
            socket_path: path.as_ref().into(),
            server,
        }
    }
}

impl<T: 'static> Handle<T>
where
    T: TablePlugin + Debug + Send + Sync,
{
    #[tracing::instrument(skip(self), fields(T = "std::any::type_name::<T>()"))]
    pub fn start(self) -> Result<JoinHandle<Result<(), thrift::Error>>, Error> {
        let socket_path = self.socket_path;

        // stand up the sync processor (the thing that knows how to go from thrift -> Plugin)
        let processor = Arc::new(ExtensionSyncProcessor::new(self.server));
        // listen on the unix socket we got back from osquery
        let unix_listener = UnixListener::bind(&socket_path)?;
        info!("Listening at {:?}", socket_path);

        let _span = info_span!("listening").entered();
        let handle = std::thread::spawn(move || {
            for sock in unix_listener.incoming() {
                match sock {
                    Ok(stream) => {
                        // every time we get a connection, grab a copy of the processor and get to steppin
                        let processor = processor.clone();
                        std::thread::spawn(move || {
                            let _span = info_span!("new connection", ?stream).entered();
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
                                    })) => {
                                        break;
                                    }
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
        });
        Ok(handle)
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

    pub fn socket_path(&self, uuid: ExtensionRouteUUID) -> Result<PathBuf, std::io::Error> {
        let mut socket_path = self.socket_path.clone();
        let mut name = socket_path
            .file_name()
            .ok_or_else(|| {
                std::io::Error::new(ErrorKind::InvalidData, socket_path.to_string_lossy())
            })?
            .to_os_string();
        name.push(&format!(".{}", uuid));
        socket_path.set_file_name(name);
        Ok(socket_path)
    }


    pub fn connect<P: AsRef<Path>>(path: P, timeout: Duration) -> Result<Self, thrift::Error> {
        let reader = UnixStream::connect(&path)?;
        debug!(?timeout, "set timeout on read and write streams");
        reader.set_read_timeout(Some(timeout))?;
        reader.set_write_timeout(Some(timeout))?;
        let writer = reader.try_clone()?;
        let input_protocol = TBinaryInputProtocol::new(reader, false);
        let output_protocol = TBinaryOutputProtocol::new(writer, false);
        Ok(Self {
            socket_path: path.as_ref().into(),
            server: ExtensionManagerSyncClient::new(input_protocol, output_protocol),
        })
    }

    /// Convenience function for registering a table
    pub fn register_table<T>(&mut self, table: T) -> Result<Handle<T>, thrift::Error>
    where
        T: Plugin,
        thrift::Error: From<T::Error>,
    {
        table.install(self)
    }
}

impl<T> ExtensionSyncHandler for T
where
    T: TablePlugin + Debug,
{
    #[instrument(target = "osquery::ping", level = "trace")]
    fn handle_ping(&self) -> thrift::Result<ExtensionStatus> {
        trace!(target = "osquery::ping", "pong");
        Ok(ExtensionStatus {
            code: Some(Code::ExtSuccess as i32),
            message: Some("OK".to_string()),
            uuid: None,
        })
    }

    #[instrument(level = "trace")]
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
                .generate(&query)
                .map_err(|e| {
                    thrift::Error::Application(ApplicationError::new(
                        thrift::ApplicationErrorKind::InternalError,
                        e.to_string(),
                    ))
                })?
                .into_iter()
                .map(|v| {
                    v.into_iter()
                        .map(|(k, v)| (k, v.to_string()))
                        .collect::<BTreeMap<_, _>>()
                })
                .collect(),
            "columns" => self
                .columns()
                .map_err(|e| {
                    thrift::Error::Application(ApplicationError::new(
                        thrift::ApplicationErrorKind::InternalError,
                        e.to_string(),
                    ))
                })?
                .iter()
                .map(|c| {
                    let (key, val) = c.to_pair();
                    btreemap! {
                        "name".to_string() => key,
                        "type".to_string() => val.to_string(),
                    }
                })
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

    #[instrument(level = "trace")]
    fn handle_shutdown(&self) -> thrift::Result<()> {
        let _ = self.shutdown();
        Ok(())
    }
}
