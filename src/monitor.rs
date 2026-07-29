use std::time::Duration;

pub async fn monitor_task(port: u16, poll_interval: u16) {
    tokio::spawn(async move {
        loop {
            let client = reqwest::Client::new();
            if let Err(error) = client
                .post(format!("http://localhost:{port}/request_scan",))
                .send()
                .await
            {
                log::warn!("Failed to request wallet scan: {error}");
            }

            tokio::time::sleep(Duration::from_secs(poll_interval as u64)).await;
        }
    });
}
