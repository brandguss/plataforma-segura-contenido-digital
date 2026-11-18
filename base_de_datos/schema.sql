-- =====================================================================
-- Plataforma Segura de Venta y Distribución de Contenido Digital
-- Esquema de base de datos relacional (SQLite 3)
--
-- Notas de diseño:
--   * Los importes (price, total, amount) se guardan en CENTAVOS (INTEGER)
--     para evitar errores de redondeo de punto flotante.
--   * No existe ninguna columna con la contraseña original: solo password_hash
--     (Argon2id, la sal va incluida en el propio hash).
--   * Los tokens de sesión y de recuperación se guardan como SHA-256,
--     nunca en claro: si alguien roba la BD no puede reutilizarlos.
--   * security_events es de solo inserción (triggers bloquean UPDATE/DELETE).
-- =====================================================================

PRAGMA foreign_keys = ON;

-- ---------------------------------------------------------------------
-- Usuarios
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    email           TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash   TEXT    NOT NULL,                 -- Argon2id ($argon2id$v=19$...)
    name            TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'CLIENTE'
                    CHECK (role IN ('CLIENTE', 'OPERADOR', 'ADMINISTRADOR')),
    status          TEXT    NOT NULL DEFAULT 'ACTIVO'
                    CHECK (status IN ('ACTIVO', 'INACTIVO')),
    failed_attempts INTEGER NOT NULL DEFAULT 0,       -- intentos fallidos consecutivos
    locked_until    TEXT,                             -- bloqueo temporal por fuerza bruta
    created_at      TEXT    NOT NULL,
    last_login      TEXT
);

-- ---------------------------------------------------------------------
-- Productos digitales
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS products (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    NOT NULL,
    description TEXT    NOT NULL,
    price       INTEGER NOT NULL CHECK (price > 0),   -- centavos MXN
    file_name   TEXT    NOT NULL UNIQUE,              -- nombre interno en productos/
    file_hash   TEXT    NOT NULL,                     -- SHA-256 del archivo original
    status      TEXT    NOT NULL DEFAULT 'ACTIVO'
                CHECK (status IN ('ACTIVO', 'INACTIVO')),
    created_at  TEXT    NOT NULL,
    updated_at  TEXT
);

-- ---------------------------------------------------------------------
-- Carrito (persistente por usuario)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS cart_items (
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id),
    added_at   TEXT    NOT NULL,
    PRIMARY KEY (user_id, product_id)
);

-- ---------------------------------------------------------------------
-- Órdenes
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS orders (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    total      INTEGER NOT NULL CHECK (total >= 0),   -- centavos
    status     TEXT    NOT NULL DEFAULT 'PENDIENTE'
               CHECK (status IN ('PENDIENTE', 'PAGADA', 'RECHAZADA', 'COMPLETADA', 'CANCELADA')),
    created_at TEXT    NOT NULL,
    updated_at TEXT
);

-- El precio se copia aquí: las órdenes históricas conservan el precio
-- del momento de la compra aunque cambie el precio actual del producto.
CREATE TABLE IF NOT EXISTS order_items (
    order_id   INTEGER NOT NULL REFERENCES orders(id) ON DELETE CASCADE,
    product_id INTEGER NOT NULL REFERENCES products(id),
    price      INTEGER NOT NULL CHECK (price > 0),    -- centavos
    PRIMARY KEY (order_id, product_id)
);

-- ---------------------------------------------------------------------
-- Pagos simulados (sin tarjetas, CVV ni cuentas reales)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS payments (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id              INTEGER NOT NULL REFERENCES orders(id),
    transaction_reference TEXT    NOT NULL UNIQUE,
    amount                INTEGER NOT NULL,           -- centavos
    status                TEXT    NOT NULL CHECK (status IN ('APROBADO', 'RECHAZADO')),
    created_at            TEXT    NOT NULL
);

-- ---------------------------------------------------------------------
-- Comprobantes firmados digitalmente (RSA-PSS + SHA-256)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS receipts (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    order_id   INTEGER NOT NULL UNIQUE REFERENCES orders(id),
    content    TEXT    NOT NULL,                      -- JSON canónico firmado
    signature  TEXT    NOT NULL,                      -- firma en Base64
    algorithm  TEXT    NOT NULL,
    key_id     TEXT    NOT NULL,                      -- huella SHA-256 de la clave pública
    created_at TEXT    NOT NULL
);

-- ---------------------------------------------------------------------
-- Descargas con fingerprint
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS downloads (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    order_id    INTEGER NOT NULL REFERENCES orders(id),
    product_id  INTEGER NOT NULL REFERENCES products(id),
    fingerprint TEXT    NOT NULL UNIQUE,              -- identificador insertado en el PDF
    copy_hash   TEXT    NOT NULL,                     -- SHA-256 de la copia personalizada
    source_ip   TEXT,
    created_at  TEXT    NOT NULL
);

-- ---------------------------------------------------------------------
-- Eventos de seguridad (bitácora de solo inserción)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER,                               -- NULL si el usuario es anónimo
    email      TEXT,                                  -- usuario involucrado (o intentado)
    event      TEXT    NOT NULL,                      -- LOGIN_SUCCESS, DOWNLOAD, ...
    result     TEXT    NOT NULL CHECK (result IN ('EXITO', 'FALLO', 'DENEGADO')),
    source     TEXT,                                  -- IP de origen
    details    TEXT,
    created_at TEXT    NOT NULL
);

CREATE TRIGGER IF NOT EXISTS security_events_no_update
BEFORE UPDATE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'La bitacora de seguridad es de solo insercion');
END;

CREATE TRIGGER IF NOT EXISTS security_events_no_delete
BEFORE DELETE ON security_events
BEGIN
    SELECT RAISE(ABORT, 'La bitacora de seguridad es de solo insercion');
END;

-- ---------------------------------------------------------------------
-- Sesiones del lado del servidor (permiten revocación)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS sessions (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash TEXT    NOT NULL UNIQUE,               -- SHA-256 del token de la cookie
    user_id    INTEGER NOT NULL REFERENCES users(id),
    csrf_token TEXT    NOT NULL,
    ip         TEXT,
    user_agent TEXT,
    created_at TEXT    NOT NULL,
    last_seen  TEXT    NOT NULL,
    expires_at TEXT    NOT NULL,
    revoked    INTEGER NOT NULL DEFAULT 0
);

-- ---------------------------------------------------------------------
-- Tokens de recuperación de contraseña (temporales y de un solo uso)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    token_hash TEXT    NOT NULL UNIQUE,
    expires_at TEXT    NOT NULL,
    used_at    TEXT,
    created_at TEXT    NOT NULL
);

-- ---------------------------------------------------------------------
-- Configuración general de seguridad (administrada por ADMINISTRADOR)
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS settings (
    key        TEXT PRIMARY KEY,
    value      TEXT NOT NULL,
    updated_at TEXT,
    updated_by INTEGER REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_orders_user     ON orders(user_id);
CREATE INDEX IF NOT EXISTS idx_downloads_user  ON downloads(user_id);
CREATE INDEX IF NOT EXISTS idx_events_created  ON security_events(created_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user   ON sessions(user_id);
