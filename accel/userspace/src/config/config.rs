use serde::{Serialize, Deserialize};
use super::super::handler::handler;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct Config{
    pub programs: Vec<handler::Program>, 
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Interface{
    pub queues: Vec<u32>,
    pub name: String,
    pub role: Role,
    pub zero_copy: Option<bool>,
    pub idx: Option<u32>,
    pub order: Option<bool>
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub enum Role{
    Fabric,
    Access,
}


#[derive(Serialize, Deserialize, PartialEq, Debug)]
#[serde(rename_all = "camelCase")]
pub struct LoadBalancer{
    pub flowlet_size: u8,
}


