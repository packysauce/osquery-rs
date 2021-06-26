use log::{debug, error, info};
use maplit::btreemap;
use serde_json::json;
use std::collections::BTreeMap;
use std::marker::PhantomData;
use std::net::TcpStream;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use thrift::protocol::TBinaryOutputProtocol;
use thrift::protocol::{
    TBinaryInputProtocol, TBinaryInputProtocolFactory, TBinaryOutputProtocolFactory,
};
use thrift::server::TServer;
use thrift::transport::{TFramedReadTransportFactory, TFramedWriteTransportFactory};
use thrift::{ApplicationError, TransportError};

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
    fn generate(&self, query: &QueryContext) -> Result<TableRows, Error>;
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

#[derive(Default)]
pub struct ExampleTable;

impl TablePlugin for ExampleTable {
    const NAME: &'static str = "example_table";
    const COLUMNS: &'static [Column] = &[
        Column::text("text"),
        Column::integer("integer"),
        Column::big_int("big_int"),
        Column::double("double"),
    ];

    fn generate(&self, _query: &QueryContext) -> Result<TableRows, Error> {
        Ok(vec![btreemap! {
            "text".to_string() => ColumnValue::text("hello_world"),
            "integer".to_string() => ColumnValue::integer(123),
            "big_int".to_string() => ColumnValue::big_int(-123456789),
            "double".to_string() => ColumnValue::double(std::f64::consts::PI),
        }])
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

pub struct Handle<T> {
    socket_path: PathBuf,
    uuid: i64,
    port: u16,
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
    fn new<P: AsRef<Path>>(path: P, port: u16, uuid: i64) -> Self {
        Handle {
            socket_path: path.as_ref().into(),
            uuid,
            port,
            _marker: Default::default(),
        }
    }
}

impl<T: 'static> Handle<T>
where
    T: TablePlugin + Default + Send + Sync,
{
    pub fn start(&self) -> JoinHandle<Result<(), thrift::Error>> {
        let uuid = self.uuid;
        let port = self.port;
        let mut socket_path = self.socket_path.clone();
        std::thread::spawn(move || {
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
            info!("Listening at {:?}", socket_path);
            /* get rando local listener */
            let processor = ExtensionSyncProcessor::new(T::new());

            let mut server = TServer::new(
                TFramedReadTransportFactory::default(),
                TBinaryInputProtocolFactory::default(),
                TFramedWriteTransportFactory::default(),
                TBinaryOutputProtocolFactory::default(),
                processor,
                10,
            );

            let totally_strong_address = format!("localhost:{}", port);
            let addr = totally_strong_address.clone();
            let _tcp_listener = std::thread::spawn(move || server.listen(&addr));

            /* set up unix listener */
            let unix_listener = UnixListener::bind(socket_path)?;
            for sock in unix_listener.incoming() {
                match sock {
                    Ok(mut writer) => {
                        let mut tcp_writer = TcpStream::connect(&totally_strong_address)?;
                        let mut tcp_reader = tcp_writer.try_clone()?;
                        let mut reader = writer.try_clone()?;
                        std::thread::spawn(move || std::io::copy(&mut reader, &mut tcp_writer));
                        std::thread::spawn(move || std::io::copy(&mut tcp_reader, &mut writer));
                    }
                    Err(e) => {
                        error!("incoming connection had a problem! {}", e);
                    }
                }
            }
            /* start std::io::copy thread(s) */
            /* feed to TServer! */

            Ok(())
        })
    }
}

#[derive(derive_more::Deref, derive_more::DerefMut)]
pub struct Client {
    port: u16,
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
            port: 8080,
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
        Ok(Handle::new(&self.socket_path, self.port, uuid))
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
        let data = request.remove("context").ok_or_else(|| {
            thrift::Error::Application(ApplicationError::new(
                thrift::ApplicationErrorKind::ProtocolError,
                format!(
                    "request to `{}` missing required field `context`",
                    Self::NAME
                ),
            ))
        })?;
        let _context = serde_json::from_str::<QueryContext>(&data).map_err(|e| {
            thrift::Error::Application(ApplicationError::new(
                thrift::ApplicationErrorKind::ProtocolError,
                format!("PluginRequest failed to deserialize QueryContext: {}", e),
            ))
        });
        todo!()
    }

    fn handle_shutdown(&self) -> thrift::Result<()> {
        todo!()
    }
}
