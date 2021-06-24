
pub use osquery_thrift::InternalExtensionInfo;
pub use osquery_thrift::InternalExtensionList;
pub use osquery_thrift::InternalOptionInfo;
pub use osquery_thrift::InternalOptionList;

macro_rules! make_rename {
    ($id:ident) => {
        ::paste::paste! {
            pub use osquery_thrift::[< Extension $id >] as $id;
        }
    };
}

pub mod extension {
    make_rename!(Code);
    make_rename!(ManagerSyncClient);
    make_rename!(ManagerSyncHandler);
    make_rename!(ManagerSyncProcessor);
    make_rename!(PluginRequest);
    make_rename!(PluginResponse);
    make_rename!(Registry);
    make_rename!(Response);
    make_rename!(RouteTable);
    make_rename!(RouteUUID);
    make_rename!(Status);
    make_rename!(SyncClient);
    make_rename!(SyncHandler);
    make_rename!(SyncProcessor);
}