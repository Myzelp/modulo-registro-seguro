const sqlite3 = require('sqlite3').verbose();

const db = new sqlite3.Database('./usuarios.db', (err) => {
    if (err) {
        console.error('Error al crear la base de datos:', err.message);
        process.exit(1);
    }
    console.log('Base de datos "usuarios.db" creada correctamente.');
});

db.serialize(() => {

    // Tabla: usuarios
    db.run(`
        CREATE TABLE IF NOT EXISTS usuarios (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            email    TEXT    NOT NULL UNIQUE,
            password TEXT    NOT NULL,
            role     TEXT    NOT NULL DEFAULT 'cliente'
        )
    `, (err) => {
        if (err) console.error('Error creando tabla usuarios:', err.message);
        else console.log('Tabla "usuarios" lista.');
    });

    // Tabla: productos
    db.run(`
        CREATE TABLE IF NOT EXISTS productos (
            id     INTEGER PRIMARY KEY AUTOINCREMENT,
            nombre TEXT    NOT NULL,
            precio REAL    NOT NULL CHECK(precio > 0),
            stock  INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0)
        )
    `, (err) => {
        if (err) console.error('Error creando tabla productos:', err.message);
        else console.log('Tabla "productos" lista.');
    });

    // Tabla: compras
    db.run(`
        CREATE TABLE IF NOT EXISTS compras (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            usuario_id  INTEGER NOT NULL,
            producto_id INTEGER NOT NULL,
            cantidad    INTEGER NOT NULL CHECK(cantidad > 0),
            total       REAL    NOT NULL,
            fecha       TEXT    NOT NULL,
            FOREIGN KEY (usuario_id)  REFERENCES usuarios(id),
            FOREIGN KEY (producto_id) REFERENCES productos(id)
        )
    `, (err) => {
        if (err) console.error('Error creando tabla compras:', err.message);
        else console.log('Tabla "compras" lista.');
    });

    // Datos de prueba: productos
    db.run(`
        INSERT OR IGNORE INTO productos (id, nombre, precio, stock) VALUES
            (1, 'Laptop Gamer Pro',      1299.99, 10),
            (2, 'Mouse Inalámbrico',       25.50, 50),
            (3, 'Teclado Mecánico',        89.99, 30),
            (4, 'Monitor 4K 27"',         399.00, 15),
            (5, 'Auriculares Bluetooth',   59.99, 25)
    `, (err) => {
        if (err) console.error('Error insertando productos:', err.message);
        else console.log('Productos de prueba insertados.');
    });

});

db.close((err) => {
    if (err) console.error('Error cerrando BD:', err.message);
    else console.log('\nBase de datos inicializada correctamente.');
});