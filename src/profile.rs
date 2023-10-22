use std::fs;
use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct Profile {
    pub allowed_ips: Vec<String>,
}

impl Profile {
    pub fn load_from_path(path: Option<PathBuf>) -> Self {
        match path {
            Some(p) => {
                let contents = fs::read_to_string(p).expect("Failed to read YAML file");
                serde_yaml::from_str(&contents).expect("Failed to parse YAML file")
            }
            None => Profile {
                allowed_ips: vec!["127.0.0.1".to_string()],
            },
        }
    }
}