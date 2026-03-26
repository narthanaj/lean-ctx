use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

const DEFAULT_PORT: u16 = 3333;
const DASHBOARD_HTML: &str = include_str!("dashboard.html");

pub async fn start(port: Option<u16>) {
    let port = port.unwrap_or_else(|| {
        std::env::var("LEAN_CTX_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(DEFAULT_PORT)
    });

    let addr = format!("127.0.0.1:{port}");

    let listener = match TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("Failed to bind to {addr}: {e}");
            std::process::exit(1);
        }
    };

    let stats_path = dirs::home_dir()
        .map(|h| h.join(".lean-ctx/stats.json"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.lean-ctx/stats.json".to_string());

    println!("\n  lean-ctx dashboard → http://localhost:{port}");
    println!("  Stats file: {stats_path}");
    println!("  Press Ctrl+C to stop\n");

    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open")
            .arg(format!("http://localhost:{port}"))
            .spawn();
    }

    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("xdg-open")
            .arg(format!("http://localhost:{port}"))
            .spawn();
    }

    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("cmd")
            .args(["/C", "start", &format!("http://localhost:{port}")])
            .spawn();
    }

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(handle_request(stream));
        }
    }
}

async fn handle_request(mut stream: tokio::net::TcpStream) {
    let mut buf = vec![0u8; 4096];
    let n = match stream.read(&mut buf).await {
        Ok(n) if n > 0 => n,
        _ => return,
    };

    let request = String::from_utf8_lossy(&buf[..n]);
    let path = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .unwrap_or("/");

    let (status, content_type, body) = match path {
        "/api/stats" => {
            let store = crate::core::stats::load();
            let json = serde_json::to_string(&store).unwrap_or_else(|_| "{}".to_string());
            ("200 OK", "application/json", json)
        }
        "/api/mcp" => {
            let mcp_path = dirs::home_dir()
                .map(|h| h.join(".lean-ctx").join("mcp-live.json"))
                .unwrap_or_default();
            let json = std::fs::read_to_string(&mcp_path).unwrap_or_else(|_| "{}".to_string());
            ("200 OK", "application/json", json)
        }
        "/" | "/index.html" => (
            "200 OK",
            "text/html; charset=utf-8",
            DASHBOARD_HTML.to_string(),
        ),
        "/favicon.ico" => ("204 No Content", "text/plain", String::new()),
        _ => ("404 Not Found", "text/plain", "Not Found".to_string()),
    };

    let cache_header = if content_type.starts_with("application/json") {
        "Cache-Control: no-cache, no-store, must-revalidate\r\nPragma: no-cache\r\n"
    } else {
        ""
    };

    let response = format!(
        "HTTP/1.1 {status}\r\n\
         Content-Type: {content_type}\r\n\
         Content-Length: {}\r\n\
         {cache_header}\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\
         \r\n\
         {body}",
        body.len()
    );

    let _ = stream.write_all(response.as_bytes()).await;
}
