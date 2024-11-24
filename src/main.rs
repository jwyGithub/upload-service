use actix_multipart::Multipart;
use actix_web::{guard::Guard, http::header, web, App, Error, HttpResponse, HttpServer};
use futures::{StreamExt, TryStreamExt};
use log::{debug, error, info, warn};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile::{certs, pkcs8_private_keys};
use serde::Deserialize;
use serde_json::{self, Map, Value};
use std::{fs::File, io::BufReader, io::Write, path::Path};

const MAX_FILE_SIZE: usize = 30 * 1024 * 1024; // 30MB

#[derive(Deserialize, Clone)]
struct Config {
    upload_dir: String,
    cert_dir: String,
}

async fn upload(mut payload: Multipart, config: web::Data<Config>) -> Result<HttpResponse, Error> {
    // 校验Content-Type
    debug!("Starting file upload process");

    // 确保上传目录存在
    if let Err(e) = std::fs::create_dir_all(&config.upload_dir) {
        error!("Failed to create upload directory: {}", e);
        return Ok(HttpResponse::InternalServerError().body("Failed to create upload directory"));
    }

    let mut total_size = 0usize;
    let mut file_count = 0;

    while let Ok(Some(mut field)) = payload.try_next().await {
        file_count += 1;
        debug!("Processing file #{}", file_count);

        // 获取文件名
        let content_disposition = match field.content_disposition() {
            Some(cd) => cd,
            None => {
                warn!("Missing content disposition");
                return Ok(HttpResponse::BadRequest().body("Missing content disposition"));
            }
        };

        let filename = match content_disposition.get_filename() {
            Some(name) => name.to_owned(),
            None => {
                warn!("Missing filename");
                return Ok(HttpResponse::BadRequest().body("Missing filename"));
            }
        };

        info!("Processing upload for file: {}", filename);

        // 保存文件名和上传目录，用于后续创建路径
        let filename_clone = filename.clone();
        let upload_dir = config.upload_dir.clone();

        let filepath = Path::new(&upload_dir).join(&filename);

        // 如果文件已经存在，则删除
        if filepath.exists() {
            info!("File {} already exists, removing it", filename);
            if let Err(e) = std::fs::remove_file(&filepath) {
                error!("Failed to remove existing file: {}", e);
                return Ok(
                    HttpResponse::InternalServerError().body("Failed to remove existing file")
                );
            }
        }

        // 创建新文件
        let mut f = match web::block(move || std::fs::File::create(&filepath)).await {
            Ok(file) => file,
            Err(e) => {
                error!("Failed to create file {}: {}", filename, e);
                return Ok(HttpResponse::InternalServerError().body("Failed to create file"));
            }
        };

        // 处理文件内容
        while let Some(chunk) = field.next().await {
            let data = match chunk {
                Ok(data) => data,
                Err(e) => {
                    error!("Error reading chunk: {}", e);
                    return Ok(HttpResponse::InternalServerError().body("Error reading file chunk"));
                }
            };

            total_size += data.len();
            if total_size > MAX_FILE_SIZE {
                error!("File size exceeds maximum allowed size");
                // 重新创建路径用于删除文件
                let filepath_to_remove = Path::new(&upload_dir).join(&filename_clone);
                if let Err(e) = std::fs::remove_file(&filepath_to_remove) {
                    error!("Failed to remove partial file: {}", e);
                }
                return Ok(HttpResponse::BadRequest().body("File size too large"));
            }

            f = match web::block(move || {
                let mut file = f?;
                file.write_all(&data)?;
                Ok(file)
            })
            .await
            {
                Ok(file) => file,
                Err(e) => {
                    error!("Failed to write file chunk: {}", e);
                    return Ok(HttpResponse::InternalServerError().body("Failed to write file"));
                }
            };
        }
    }

    if file_count == 0 {
        warn!("No files were uploaded");
        return Ok(HttpResponse::BadRequest().body("No files were uploaded"));
    }

    if total_size == 0 {
        warn!("Uploaded file is empty");
        return Ok(HttpResponse::BadRequest().body("Uploaded file is empty"));
    }

    info!(
        "File upload completed successfully. Total size: {} bytes",
        total_size
    );
    Ok(HttpResponse::Ok().json({
        let mut response = Map::new();
        response.insert("total_size".to_string(), Value::Number(total_size.into()));
        response.insert("file_count".to_string(), Value::Number(file_count.into()));
        response.insert("code".to_string(), Value::Number(200.into()));
        Value::Object(response)
    }))
}

struct MultipartGuard;

impl Guard for MultipartGuard {
    fn check(&self, ctx: &actix_web::guard::GuardContext) -> bool {
        ctx.header::<header::ContentType>()
            .map(|ct| ct.essence_str().starts_with("multipart/form-data"))
            .unwrap_or(false)
    }
}

fn load_rustls_config(cert_dir: &str) -> Result<ServerConfig, std::io::Error> {
    // 证书文件路径
    let cert_path = Path::new(cert_dir).join("fullchain.cer");
    let key_path = Path::new(cert_dir).join("private_pkcs8.key");

    // 读取证书文件
    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let mut cert_reader = BufReader::new(cert_file);
    let mut key_reader = BufReader::new(key_file);

    // 解析证书
    let cert_chain = certs(&mut cert_reader)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "无效的证书"))?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();

    // 解析私钥
    let keys = pkcs8_private_keys(&mut key_reader)
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "无效的私钥"))?;

    let private_key = keys
        .first()
        .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::NotFound, "没有找到私钥"))?
        .clone();

    // 配置 TLS
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(cert_chain, PrivateKey(private_key))
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;

    Ok(config)
}

async fn start_server(config: Config) -> std::io::Result<()> {
    // 加载 TLS 配置
    let tls_config = load_rustls_config(&config.cert_dir)?;

    let factory = move || {
        App::new().app_data(web::Data::new(config.clone())).service(
            web::resource("/upload")
                .guard(actix_web::guard::Post())
                .guard(MultipartGuard)
                .to(upload),
        )
    };

    info!("Starting HTTPS server on 0.0.0.0:9443");
    HttpServer::new(factory)
        .bind_rustls("0.0.0.0:9443", tls_config)? // 注意这里使用 bind_rustls_0_22
        .run()
        .await
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // 初始化日志系统
    env_logger::init_from_env(env_logger::Env::default().default_filter_or("info"));

    let cert_dir = std::env::var("CERT_DIR").unwrap_or_else(|_| "./cert".to_string());
    let upload_dir = std::env::var("UPLOAD_DIR").unwrap_or_else(|_| "./uploads".to_string());

    let config = Config {
        upload_dir,
        cert_dir,
    };

    info!("Server starting on port 9443");
    info!("Upload directory: {}", config.upload_dir);
    info!("Certificates directory: {}", config.cert_dir);

    start_server(config).await
}
