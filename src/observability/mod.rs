pub mod metrics;

#[cfg(feature = "admin")]
pub mod dashboard;
#[cfg(any(feature = "prometheus", feature = "admin"))]
pub mod http;

/// Initialize the Prometheus metrics recorder and return a handle for rendering.
///
/// Only available when the `prometheus` or `admin` feature is enabled.
#[cfg(any(feature = "prometheus", feature = "admin"))]
pub fn init() -> metrics_exporter_prometheus::PrometheusHandle {
    let builder = metrics_exporter_prometheus::PrometheusBuilder::new();
    let handle = builder
        .install_recorder()
        .expect("Failed to install Prometheus metrics recorder");

    metrics::describe_metrics();

    handle
}
