const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { exec } = require('child_process'); 
const util = require('util');
const fs = require('fs').promises;
const path = require('path');
const crypto = require('crypto');



const execPromise = util.promisify(exec);


const app = express();
const PORT = 3000;

// Middleware para que el servidor pueda leer el JSON que envíes desde Postman
app.use(express.json());

// Conexión a la base de datos
const db = new sqlite3.Database('./usuarios.db');

// Función para generar JWT usando Python (versión con archivo temporal)
async function generarJWT(payload) {
    let tempFile = null;
    
    try {
        console.log('1. Iniciando generación de JWT');
        console.log('2. Payload recibido:', payload);
        
        // Crear un nombre de archivo temporal único
        const tempFileName = `temp_${crypto.randomBytes(16).toString('hex')}.json`;
        tempFile = path.join(__dirname, tempFileName);
        console.log('3. Archivo temporal:', tempFile);
        
        // Preparar los datos para Python
        const pythonInput = {
            action: 'generar',
            payload: payload
        };
        
        // Escribir los datos al archivo temporal
        await fs.writeFile(tempFile, JSON.stringify(pythonInput));
        console.log('4. Datos escritos en archivo temporal');
        
        // Ejecutar Python con el archivo temporal
        const comando = `python "${path.join(__dirname, 'jwt_handler.py')}" "${tempFile}"`;
        console.log('5. Comando a ejecutar:', comando);
        
        const { stdout, stderr } = await execPromise(comando);
        
        console.log('6. stdout (salida de Python - TOKEN):', stdout ? stdout.substring(0, 50) + '...' : 'vacío');
        
        if (stderr) {
            // Solo mostramos stderr como información, NO como error
            console.log('7. stderr (información de Python):', stderr);
        }
        
        // Verificar si obtuvimos algo en stdout
        if (!stdout || stdout.trim() === '') {
            throw new Error('Python no devolvió ningún token');
        }
        
        const token = stdout.trim();
        console.log('8. Token generado exitosamente, longitud:', token.length);
        console.log('9. Token (primeros 20 chars):', token.substring(0, 20));
        
        return token;
        
    } catch (error) {
        console.error('ERROR DETALLADO en generarJWT:');
        console.error('- Mensaje:', error.message);
        console.error('- Stack:', error.stack);
        throw new Error('Error al generar token JWT: ' + error.message);
    } finally {
        // Limpiar el archivo temporal si existe
        if (tempFile) {
            try {
                // Verificar si el archivo existe antes de eliminarlo
                try {
                    await fs.access(tempFile);
                    await fs.unlink(tempFile);
                    console.log('10. Archivo temporal eliminado');
                } catch (e) {
                    // El archivo ya no existe o no se puede acceder
                    console.log('Archivo temporal ya no existe o no accesible');
                }
            } catch (e) {
                console.error('Error eliminando archivo temporal:', e);
            }
        }
    }
}

// Función para verificar JWT usando Python
async function verificarJWT(token) {
    try {
        const { stdout, stderr } = await execPromise(`python jwt_handler.py verificar '${token}'`);
        
        if (stderr) {
            console.error('Error en Python (stderr):', stderr);
            throw new Error(stderr);
        }
        
        return JSON.parse(stdout); // El resultado viene como JSON
    } catch (error) {
        console.error('Error al verificar token:', error);
        return { valido: false, error: 'Error al verificar token' };
    }
}

// ENDPOINT: POST /login
app.post('/login', async (req, res) => {
    const { email, password } = req.body;

    console.log('=== INTENTO DE LOGIN ===');
    console.log('Email:', email);

    if (!email || !password) {
        return res.status(400).json({ error: "Email y contraseña son requeridos" });
    }

    const sqlSearch = "SELECT * FROM usuarios WHERE email = ?";
    
    db.get(sqlSearch, [email], async (err, user) => {
        if (err) {
            console.error('Error en BD:', err);
            return res.status(500).json({ error: "Error en el servidor" });
        }
        
        if (!user) {
            return res.status(401).json({ error: "Credenciales inválidas" });
        }

        try {
            const match = await bcrypt.compare(password, user.password);
            
            if (match) {
                console.log('Login exitoso, generando token...');
                
                const payload = {
                    user_id: user.id,
                    email: user.email,
                    role: user.role || 'user'
                };
                
                try {
                    const token = await generarJWT(payload);
                    
                    console.log('Token generado correctamente');
                    
                    res.status(200).json({ 
                        message: "Login exitoso",
                        token: token,
                        email: user.email,
                        role: user.role 
                    });
                    
                } catch (jwtError) {
                    console.error('ERROR generando JWT:', jwtError);
                    res.status(500).json({ 
                        error: "Error al generar token de autenticación",
                        detalle: jwtError.message 
                    });
                }
            } else {
                res.status(401).json({ error: "Credenciales inválidas" });
            }
        } catch (error) {
            console.error('Error en bcrypt:', error);
            res.status(500).json({ error: "Error al verificar la contraseña" });
        }
    });
});


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

