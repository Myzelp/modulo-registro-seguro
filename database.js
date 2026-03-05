const sqlite3 = require('sqlite3').verbose();

// 1. Crear o abrir el archivo de la base de datos
const db = new sqlite3.Database('./usuarios.db');

db.serialize(() => {

    // Tabla: usuarios
    db.run(`CREATE TABLE IF NOT EXISTS usuarios (
        id       INTEGER PRIMARY KEY AUTOINCREMENT,
        email    TEXT NOT NULL UNIQUE, 
        password TEXT NOT NULL, 
        role     TEXT DEFAULT 'cliente'
    )`, (err) => {
        if (err) console.error("Error al crear tabla usuarios:", err.message);
        else console.log("Tabla 'usuarios' creada o ya existente.");
    });

    // Tabla: productos
    db.run(`CREATE TABLE IF NOT EXISTS productos (
        id     INTEGER PRIMARY KEY AUTOINCREMENT,
        nombre TEXT NOT NULL,
        precio REAL NOT NULL CHECK(precio > 0),
        stock  INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0)
    )`, (err) => {
        if (err) console.error("Error al crear tabla productos:", err.message);
        else console.log("Tabla 'productos' creada o ya existente.");
    });

    // Tabla: compras
    db.run(`CREATE TABLE IF NOT EXISTS compras (
        id          INTEGER PRIMARY KEY AUTOINCREMENT,
        usuario_id  INTEGER NOT NULL,
        producto_id INTEGER NOT NULL,
        cantidad    INTEGER NOT NULL CHECK(cantidad > 0),
        total       REAL NOT NULL,
        fecha       TEXT NOT NULL,
        FOREIGN KEY (usuario_id)  REFERENCES usuarios(id),
        FOREIGN KEY (producto_id) REFERENCES productos(id)
    )`, (err) => {
        if (err) console.error("Error al crear tabla compras:", err.message);
        else console.log("Tabla 'compras' creada o ya existente.");
    });

});

// 3. Cerrar la conexión
db.close();