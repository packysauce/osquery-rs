use std::{thread::sleep, time::Duration};

use maplit::btreemap;
use osquery::{
    Client, Column, ColumnValue, QueryContext, TExtensionManagerSyncClient, TablePlugin, TableRows,
};
use tracing::{debug, error, info};

#[derive(Debug, Default)]
pub struct ExampleTable;

impl TablePlugin for ExampleTable {
    const NAME: &'static str = "example_table";
    const COLUMNS: &'static [Column] = &[
        Column::text("text"),
        Column::integer("integer"),
        Column::big_int("big_int"),
        Column::double("double"),
    ];

    fn generate(&self, _query: &QueryContext) -> Result<TableRows, thrift::Error> {
        Ok(vec![btreemap! {
            "text".to_string() => ColumnValue::text("hello_world"),
            "integer".to_string() => ColumnValue::integer(123),
            "big_int".to_string() => ColumnValue::big_int(-123456789),
            "double".to_string() => ColumnValue::double(std::f64::consts::PI),
        }])
    }
}

fn main() -> Result<(), Box<dyn (std::error::Error)>> {
    tracing_subscriber::fmt()
        .with_env_filter("tester=trace,osquery=trace,info")
        .pretty()
        .init();
    info!("Getting a client put together");
    let mut home = dirs::home_dir().expect("no home dir?");
    home.extend(&[".osquery", "shell.em"]);
    let mut client = Client::connect(&home)?;
    debug!("ostensibly connected");
    let table = client.register_table::<ExampleTable>()?;
    let handle = table.start();
    let stfu = handle.join().unwrap();
    if let Err(e) = stfu {
        error!("shit broke: {}", e);
    }

    info!("ext. {:#?}", client.extensions()?);
    //info!("opt. {:#?}", client.options()?);
    sleep(Duration::from_secs(30));
    Ok(())
}
