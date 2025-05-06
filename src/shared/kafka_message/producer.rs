use super::{payload::KafkaPayload, topics::KafkaTopic};
use anyhow::Result;
use rdkafka::config::ClientConfig;
use rdkafka::producer::{FutureProducer, FutureRecord};
use serde_json;
use std::time::Duration;

pub struct KafkaProducer {
    producer: FutureProducer,
}

impl KafkaProducer {
    /// Create a new KafkaProducer instance with the broker URL.
    pub fn new(broker_url: &str) -> Result<Self> {
        let producer = ClientConfig::new()
            .set("bootstrap.servers", broker_url) // Using broker URL from main.rs
            .create()
            .expect("Failed to create Kafka producer");

        Ok(KafkaProducer { producer })
    }

    /// Sends a Kafka event to the specified topic with given key and payload.
    pub async fn send_event(
        &self,
        topic: KafkaTopic,
        key: &str,
        payload: KafkaPayload,
    ) -> Result<()> {
        let serialized = serde_json::to_string(&payload)?;

        let record = FutureRecord::to(topic.as_str())
            .key(key)
            .payload(&serialized);

        let delivery_status = self.producer.send(record, Duration::from_secs(0)).await;

        match delivery_status {
            Ok(delivery) => {
                println!("✅ Delivered to '{}': {:?}", topic.as_str(), delivery);
                Ok(())
            }
            Err((e, _)) => {
                eprintln!("❌ Kafka error: {:?}", e);
                Err(anyhow::anyhow!(e.to_string()))
            }
        }
    }
}
