use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use axum::{
    body::Body,
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use tower_http::services::fs::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> anyhow::Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    info!("Serving {:?} on port {}", path, addr);
    let state = HttpServeState { path: path.clone() };

    let router = Router::new()
        .route("/", get(root_processor))
        .route("/*path", get(file_handler))
        .nest_service("/tower", ServeDir::new(path))
        .with_state(Arc::new(state));

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, router).await?;
    Ok(())
}

async fn root_processor(State(state): State<Arc<HttpServeState>>) -> impl IntoResponse {
    let root_dir = state.path.as_path();
    let entries = std::fs::read_dir(root_dir).unwrap();
    let mut lines = vec![];
    for entry in entries {
        let entry = entry.unwrap();
        let filename = entry.file_name().to_str().unwrap().to_string();
        lines.push(format!("<a href='{}'>{}</a>", &filename, &filename));
    }
    Html(lines.join("<br/>"))
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    let p = std::path::Path::new(state.path.as_path()).join(path.clone());
    info!("Reading file {:?}", p);
    if !p.exists() {
        (
            StatusCode::NOT_FOUND,
            Body::from(format!("File {} not found", p.display())),
        )
    } else {
        // if it is a directory list all files/subdirectories
        // as <li><a href="/path/to/file">file</a></li>
        // <html><body><ul>...</ul></body></html>
        if p.is_file() {
            match tokio::fs::read_to_string(p).await {
                Ok(content) => {
                    info!("Read {} bytes", content.len());
                    (StatusCode::OK, Body::from(content))
                }
                Err(e) => {
                    warn!("Error reading file: {}", e);
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Body::from(format!("Error reading file: {}", e)),
                    )
                }
            }
        } else {
            let entries = std::fs::read_dir(p).unwrap();
            let mut lines = vec!["<html><body><ul>".to_string()];
            for entry in entries {
                let entry = entry.unwrap();
                let filename = entry.file_name().to_str().unwrap().to_string();
                lines.push(format!(
                    r#"<li><a href="/{}/{}">{}</a></li>"#,
                    &path, &filename, &filename
                ));
            }
            lines.push("</ul></body></html>".to_string());
            let res_content = lines.join("<br/>");
            (StatusCode::OK, Body::from(res_content))
        }
    }
}

// #[cfg(test)]
// mod tests {
//     use super::*;

//     #[tokio::test]
//     async fn test_file_handler() {
//         let state = Arc::new(HttpServeState {
//             path: PathBuf::from("."),
//         });
//         let path = Path("Cargo.toml".to_string());
//         let (status, content) = file_handler(State(state), path).await;
//         assert_eq!(status, StatusCode::OK);
//         assert!(content.trim().starts_with("[package]"));
//     }
// }
