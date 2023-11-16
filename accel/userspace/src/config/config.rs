use serde::{Serialize, Deserialize};
use super::super::handler::handler;

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Config{
    pub programs: Vec<handler::Program>, 
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub struct Interface{
    pub queues: Vec<u32>,
    pub name: String,
    pub role: Role,
    pub zero_copy: Option<bool>,
    pub idx: Option<u32>,
}

#[derive(Serialize, Deserialize, PartialEq, Debug, Clone)]
pub enum Role{
    Fabric,
    Access,
}


#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct LoadBalancer{
    pub flowlet_size: u8,
    pub interfaces: Vec<Interface>,
}


