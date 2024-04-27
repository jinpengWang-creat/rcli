use anyhow::Result;
use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::fs;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Debug)]
struct HttpServeState {
    path: PathBuf,
}

pub async fn process_http_serve(path: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Serving {:?} on port {}", path, port);

    let dir_serve = ServeDir::new(path.clone())
        .append_index_html_on_directories(true)
        .precompressed_gzip()
        .precompressed_br()
        .precompressed_deflate()
        .precompressed_zstd();
    let state = HttpServeState { path };
    let route = Router::new()
        .nest_service("/tower", dir_serve)
        .route("/", get(file_handler))
        .route("/*path", get(file_handler))
        .with_state(Arc::new(state));
    axum::serve(listener, route).await?;
    Ok(())
}

async fn file_handler(
    State(state): State<Arc<HttpServeState>>,
    path_opt: Option<Path<String>>,
) -> Response {
    let mut path = state.path.clone();
    if let Some(sub_path) = path_opt {
        path = path.join(sub_path.0);
    }
    if path.is_dir() {
        process_dir(path).await
    } else {
        process_file(path).await
    }
}

async fn process_dir(path: PathBuf) -> Response {
    match fs::read_dir(path.clone()).await {
        Ok(mut dir) => {
            let mut file_names = vec![];
            while let Ok(Some(entry)) = dir.next_entry().await {
                if let Some(file_name) = entry.path().file_name() {
                    file_names.push(
                        format!(
                            "<a href={:?}>{}</a>",
                            path.join(file_name),
                            file_name.to_str().unwrap()
                        )
                        .replace("\\\\", "/"),
                    );
                }
            }

            let mut result = String::new();
            result.push_str("<ul>");
            if !path.as_os_str().eq(".") {
                result.push_str("<li><a href='..'>..</a></li>");
            }
            for ele in file_names {
                result.push_str("<li>");
                result.push_str(&ele);
                result.push_str("</li>");
            }
            result.push_str("</ul>");
            Html(result).into_response()
        }
        Err(e) => {
            warn!("Error reading file: {:?}", e);
            (StatusCode::NOT_FOUND, e.to_string()).into_response()
        }
    }
}

async fn process_file(path: PathBuf) -> Response {
    if !path.exists() {
        warn!("File {:?} not fount!", path);
        (
            StatusCode::NOT_FOUND,
            format!("File {} not fount!", path.display()),
        )
            .into_response()
    } else {
        match tokio::fs::read_to_string(path).await {
            Ok(content) => {
                info!("Read {} bytes", content.len());
                (StatusCode::OK, content).into_response()
            }
            Err(e) => {
                warn!("Error reading file: {:?}", e);
                (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response()
            }
        }
    }
}
