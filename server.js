const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');

const app = express();
const PORT = 3000;

// Middleware para que el servidor pueda leer el JSON que envíes desde Postman
app.use(express.json());

// Conexión a la base de datos
const db = new sqlite3.Database('./usuarios.db');

// ENDPOINT: POST /registro
app.post('/registro', async (req, res) => {
    const { email, password } = req.body;

    // 1. Validar datos de entrada (Password mayor a 8 y menor a 10)
    if (!email || !password || password.length <= 8 || password.length >= 10) {
        return res.status(400).send("Error 400: Credenciales Invalidas");
    }

    // 2. Verificar duplicados (Email existente)
    const sqlCheck = `SELECT * FROM usuarios WHERE email = ?`;
    
    db.get(sqlCheck, [email], async (err, row) => {
        if (err) return res.status(500).send("Error en el servidor");
        
        if (row) {
            return res.status(409).send("ERROR 409: El usuario ya existe");
        }


    });
});

// Levantar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log(`Listo para recibir peticiones POST en /registro`);
});