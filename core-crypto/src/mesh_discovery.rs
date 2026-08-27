use std::net::{UdpSocket, SocketAddr};
use std::time::Duration;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct MeshBeacon {
    pub magic: String,
    pub node_id: String,
    pub username: String,
    pub port: u16,
    pub timestamp: u64,
}

pub struct MeshBeaconManager {
    pub socket: UdpSocket,
    pub node_id: String,
    pub username: String,
}

impl MeshBeaconManager {
    pub fn new(node_id: String, username: String) -> Result<Self, std::io::Error> {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.set_broadcast(true)?;
        socket.set_read_timeout(Some(Duration::from_millis(200)))?;
        Ok(Self { socket, node_id, username })
    }

    pub fn broadcast_presence(&self, target_port: u16) -> Result<(), std::io::Error> {
        let beacon = MeshBeacon {
            magic: "AEGIS_MESH_V1".to_string(),
            node_id: self.node_id.clone(),
            username: self.username.clone(),
            port: target_port,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        let data = serde_json::to_vec(&beacon).unwrap_or_default();
        let target_addr: SocketAddr = format!("255.255.255.255:{}", target_port).parse().unwrap();
        let _ = self.socket.send_to(&data, target_addr);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mesh_beacon_serialization() {
        let beacon = MeshBeacon {
            magic: "AEGIS_MESH_V1".to_string(),
            node_id: "node_abc123".to_string(),
            username: "Alice".to_string(),
            port: 42424,
            timestamp: 1720000000,
        };

        let serialized = serde_json::to_string(&beacon).unwrap();
        let deserialized: MeshBeacon = serde_json::from_str(&serialized).unwrap();
        assert_eq!(beacon, deserialized);
        assert_eq!(deserialized.magic, "AEGIS_MESH_V1");
    }
}
