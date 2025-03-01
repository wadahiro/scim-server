use axum::extract::Path;
use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc}; // Import chrono
use rusqlite::Connection;
use scim_v2::models::user::{Email, Name, User}; // Import Email
use scim_v2::models::{
    scim_schema::Meta,
    service_provider_config::{
        AuthenticationScheme, Bulk, Filter, ServiceProviderConfig, Supported,
    },
};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use uuid::Uuid;

async fn service_provider_config() -> (StatusCode, Json<ServiceProviderConfig>) {
    let config = ServiceProviderConfig {
        documentation_uri: Some("https://example.com/scim/docs".to_string()),
        patch: Supported { supported: true },
        bulk: Bulk {
            supported: true,
            max_operations: 1000,
            max_payload_size: 1048576,
        },
        filter: Filter {
            supported: true,
            max_results: 100,
        },
        change_password: Supported { supported: true },
        sort: Supported { supported: true },
        etag: Supported { supported: true },
        authentication_schemes: vec![AuthenticationScheme {
            name: "OAuth Bearer Token".to_string(),
            type_: "oauthbearertoken".to_string(),
            description: "Authentication scheme using the OAuth Bearer Token standard".to_string(),
            spec_uri: "https://datatracker.ietf.org/doc/html/rfc6750".to_string(),
            documentation_uri: Some("https://example.com/scim/docs".to_string()),
            primary: Some(true),
        }],
        meta: Some(Meta {
            resource_type: Some("ServiceProviderConfig".to_string()),
            created: None,
            last_modified: None,
            version: None,
            location: None,
        }),
    };
    (StatusCode::OK, Json(config))
}

async fn create_user(
    State(state): State<Arc<Mutex<Connection>>>,
    Json(payload): Json<User>,
) -> Result<(StatusCode, Json<User>), (StatusCode, String)> {
    // Basic validation (only userName is required)
    if payload.user_name.is_empty() {
        return Err((
            StatusCode::BAD_REQUEST,
            "Invalid user data: userName is required".to_string(),
        ));
    }

    // Generate UUID
    let user_id = Uuid::new_v4().to_string();

    // Create Meta
    let meta = Meta {
        resource_type: Some("User".to_string()),
        created: Some(Utc::now().to_rfc3339()),
        last_modified: Some(Utc::now().to_rfc3339()),
        version: Some("W/\"1\"".to_string()), // Assuming versioning
        location: Some(format!("/Users/{}", user_id)),
    };

    // Create a new User object with the ID and meta
    let created_user = User {
        id: Some(user_id.clone()),
        meta: Some(meta),
        ..payload
    };

    // Serialize the user to JSON
    let json_string = serde_json::to_string(&created_user).map_err(|e| {
        eprintln!("Error serializing user to JSON: {}", e);
        (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    })?;

    println!("Received user payload: {:?}", created_user); // Add this line

    let result = {
        let mut conn = state.lock().map_err(|e| {
            eprintln!("Error locking database connection: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
        let mut tx = conn.transaction().map_err(|e| {
            eprintln!("Error starting transaction: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
        })?;
        let result = tx.execute(
            "INSERT INTO users (id, data) VALUES (?1, ?2)",
            [&user_id, &json_string],
        );
        match result {
            Ok(result) => {
                tx.commit().map_err(|e| {
                    eprintln!("Error committing transaction: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                })?;
                result
            }
            Err(e) => {
                tx.rollback().map_err(|e| {
                    eprintln!("Error rolling back transaction: {}", e);
                    (StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
                })?;
                return Err((StatusCode::INTERNAL_SERVER_ERROR, e.to_string()));
            }
        }
    };

    if result > 0 {
        Ok((StatusCode::CREATED, Json(created_user)))
    } else {
        Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to create user".to_string(),
        ))
    }
}

async fn get_user(
    State(state): State<Arc<Mutex<Connection>>>,
    Path(id): Path<String>, // Assuming id is a String (UUID)
) -> Result<(StatusCode, Json<User>), (StatusCode, Json<serde_json::Value>)> {
    let state_lock = state.lock().map_err(|e| {
        eprintln!("Error locking database connection: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string()})),
        )
    })?;

    let mut stmt = state_lock
        .prepare("SELECT data FROM users WHERE id = ?1")
        .map_err(|e| {
            eprintln!("Error preparing SQL statement: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string() })),
            )
        })?;

    let mut rows = stmt.query(rusqlite::params![id]).map_err(|e| {
        eprintln!("Error executing SQL query: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string() })),
        )
    })?;

    if let Some(row) = rows.next().map_err(|e| {
        eprintln!("Error getting next row: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"error": e.to_string() })),
        )
    })? {
        let data: String = row.get(0).map_err(|e| {
            eprintln!("Error getting data from row: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string() })),
            )
        })?;
        let user: User = serde_json::from_str(&data).map_err(|e| {
            eprintln!("Error deserializing JSON: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"error": e.to_string() })),
            )
        })?;
        Ok((StatusCode::OK, Json(user)))
    } else {
        // User not found
        Err((
            StatusCode::NOT_FOUND,
            Json(json!({"message": "User not found"})),
        ))
    }
}

#[tokio::main]
async fn main() {
    // initialize tracing
    // tracing_subscriber::fmt::init();

    let db_path = "scim.db";
    let conn = Connection::open(db_path).unwrap();
    let shared_conn = Arc::new(Mutex::new(conn));

    shared_conn
        .lock()
        .unwrap()
        .execute(
            "CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, data TEXT)",
            [],
        )
        .unwrap();

    let app = Router::new()
        .route("/scim/v2/ServiceProvider", get(service_provider_config))
        .route("/Users", post(create_user))
        .route("/Users/:id", get(get_user))
        .with_state(shared_conn.clone());

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    println!("listening on {}", addr);
    let listener = TcpListener::bind(&addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
