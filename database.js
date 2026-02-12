const sqlite3 = require('sqlite3').verbose();

// 1. Crear o abrir el archivo de la base de datos
const db = new sqlite3.Database('./usuarios.db');

db.serialize(() => {
  // 2. Ejecutar el script CREATE TABLE que te dieron
  db.run(`CREATE TABLE IF NOT EXISTS usuarios (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE, 
    password TEXT NOT NULL, 
    role TEXT DEFAULT 'cliente'
  )`, (err) => {
    if (err) {
      console.error("Error al crear la tabla:", err.message);
    } else {
      console.log("¡Éxito! Tabla 'usuarios' creada o ya existente.");
    }
  });
});

// 3. Cerrar la conexión
db.close();