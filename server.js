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

        // 3. Si no es duplicado, cifrar la contraseña con bcrypt
        try {
            const saltRounds = 10;
            const hashedPassword = await bcrypt.hash(password, saltRounds);

            // 4. Guardar en la base de datos
            const sqlInsert = `INSERT INTO usuarios (email, password) VALUES (?, ?)`;
            
            db.run(sqlInsert, [email, hashedPassword], function(err) {
                if (err) return res.status(500).send("Error al guardar usuario");
                
                // 5. Éxito
                res.status(201).send("Success 201: Usuario Registrado");
            });

        } catch (error) {
            res.status(500).send("Error al cifrar contraseña");
        }
    });
});

// ENDPOINT PUT /cambiar-rol/:email
app.put('/cambiar-rol/:email', (req, res) => {
    //Obtenemos el email de la URL y el nuevo rol del cuerpo
    const userEmail = req.params.email;
    const { newRole } = req.body;

    //Validación básica
    if (!newRole) {
        return res.status(400).json({ error: "Debes proporcionar el nuevo rol (newRole)." });
    }

    //Primero verificamos si el usuario existe
    const sqlSearch = "SELECT * FROM usuarios WHERE email = ?";

    db.get(sqlSearch, [userEmail], (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: "Usuario no encontrado." });

        //SI EXISTE, entonces ejecutamos el UPDATE (dentro del callback)
        const sqlUpdate = "UPDATE usuarios SET role = ? WHERE email = ?";
        
        db.run(sqlUpdate, [newRole, userEmail], function(err) {
            if (err) return res.status(500).json({ error: err.message });
            
            res.status(200).json({ 
                message: `Rol de ${userEmail} actualizado a ${newRole}.`,
                cambios: this.changes 
            });
        });
    });
});

//ENDPOINT PUT /cambiar-password
app.put('/usuarios/cambiar-password/:email', (req, res) => {
    
    // Extraemos el email de los parámetros
    const userEmail = req.params.email;
    const { oldPassword, newPassword } = req.body;

    if (!oldPassword || !newPassword) {
        return res.status(400).json({ error: "Datos incompletos." });
    }

    // Buscamos por EMAIL en la base de datos
    const sqlSearch = "SELECT password FROM usuarios WHERE email = ?";
    
    db.get(sqlSearch, [userEmail], async (err, user) => {
        if (err) return res.status(500).json({ error: err.message });
        if (!user) return res.status(404).json({ error: "Usuario no encontrado con ese correo." });

        try {
            const match = await bcrypt.compare(oldPassword, user.password);
            
            if (!match) {
                return res.status(401).json({ error: "La contraseña antigua no coincide." });
            }

            const saltRounds = 10;
            const hashedNewPassword = await bcrypt.hash(newPassword, saltRounds);

            //Actualizamos usando el EMAIL como condición
            const sqlUpdate = "UPDATE usuarios SET password = ? WHERE email = ?";
            db.run(sqlUpdate, [hashedNewPassword, userEmail], function(err) {
                if (err) return res.status(500).json({ error: err.message });
                
                res.status(200).json({ 
                    message: `Contraseña de ${userEmail} actualizada.`,
                    cambios: this.changes 
                });
            });

        } catch (error) {
            res.status(500).json({ error: "Error en el proceso de cifrado." });
        }
    });
});


// Levantar el servidor
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
    console.log(`Listo para recibir peticiones POST en /registro`);
});

